//! Level 10: the admin plane — `/metrics` and `/health` on their own listener.
//!
//! # Why a second socket and not two reserved paths
//!
//! `/metrics` leaks route names, backend addresses, and error rates —
//! reconnaissance gold — and the main listener faces the internet. Binding
//! the admin plane to its own address (the docs recommend `127.0.0.1:9100`)
//! makes exposure an explicit operator choice instead of a default; a
//! backend that legitimately serves `/metrics` is never shadowed; and the
//! main listener's routing logic stays untouched. This is Envoy's admin
//! port and HAProxy's stats socket — "the admin plane is a different
//! socket" *is* the production lesson.
//!
//! # Deliberately tiny
//!
//! This server reuses `http::read_head`/`parse_request_head` (the parser is
//! battle-tested; a second hand-written one would just be a second bug
//! surface) and NOTHING else from the proxy machinery: no routing, no
//! middleware, no keep-alive, no pooling. One request per connection,
//! `Connection: close`, done. A scraper hits it every ~15 s — everything
//! keep-alive buys is rounding error here, and everything it costs
//! (drain-before-reuse discipline, poolability analysis) is complexity this
//! endpoint exists to observe, not participate in.
//!
//! It is not exempt from slowloris thinking, though: a 5 s deadline covers
//! the whole exchange. `ConnLimiter` would be overkill for a
//! localhost-default socket, but an unbounded read deadline would be the
//! same mistake Level 8 spent a level killing.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::balancer::Upstream;
use crate::http;
use crate::metrics::Metrics;
use crate::proxy::Conn;
use crate::router::RouteTable;
use std::sync::RwLock;

/// Whole-exchange deadline: read the request head, write the response. On a
/// localhost socket a healthy scraper finishes in microseconds; anything
/// approaching seconds is wedged and gets cut.
const ADMIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Bind the admin listener and serve it forever. Called from `main` AFTER the
/// bind succeeds — the bind itself happens in `main` so a bad `--admin`
/// address is a startup failure (exit 1, no service announced), the same
/// guardrail posture as Level 8's TLS config checks.
pub async fn serve(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    cache: Arc<crate::cache::Cache>,
    routes: Arc<RwLock<Arc<RouteTable>>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let metrics = Arc::clone(&metrics);
                let cache = Arc::clone(&cache);
                // Level 12: resolve the upstream list PER REQUEST through the
                // shared handle. Capturing a Vec<Arc<Upstream>> at boot (the
                // pre-reload design) would have made this task a permanent
                // strong ref to the boot-time pools — /health would report a
                // retired config forever, and worse, keep it alive.
                let upstreams = match routes.read() {
                    Ok(guard) => guard.upstreams(),
                    Err(poisoned) => poisoned.into_inner().upstreams(),
                };
                tokio::spawn(async move {
                    if let Err(e) = tokio::time::timeout(
                        ADMIN_TIMEOUT,
                        serve_one(stream, &metrics, &cache, &upstreams),
                    )
                            .await
                            .unwrap_or_else(|_| {
                                Err(std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "admin exchange timed out",
                                ))
                            })
                    {
                        crate::debug!("[admin {peer}] {e}");
                    }
                });
            }
            Err(e) => crate::error!("admin accept error: {e}"),
        }
    }
}

async fn serve_one(
    stream: TcpStream,
    metrics: &Metrics,
    cache: &crate::cache::Cache,
    upstreams: &[Arc<Upstream>],
) -> std::io::Result<()> {
    let mut conn = Conn::new(stream);
    let head = match conn.read_head().await? {
        Some(h) => h,
        None => return Ok(()), // connected and left without a request
    };
    let req = http::parse_request_head(&head)?;

    // Path only — the admin plane answers GET and rejects everything else.
    // `target_path` strips any query string; there are no parameters here.
    let path = http::target_path(&req.target);
    let (status, reason, content_type, body) = if req.method != "GET" {
        (405, "Method Not Allowed", "text/plain", "405\n".to_string())
    } else {
        match path {
            "/metrics" => (
                200,
                "OK",
                // The exposition format's own content type, version pinned —
                // scrapers are permissive, but saying exactly what we speak
                // costs nothing.
                "text/plain; version=0.0.4",
                {
                    // L10's registry plus L11's cache block: one scrape, one
                    // document — the scraper doesn't care who owns a counter.
                    let mut m = metrics.render();
                    m.push_str(&cache.render_prometheus());
                    m
                },
            ),
            "/health" => {
                let (body, degraded) = health_json(metrics, upstreams);
                // 200 even when degraded: this endpoint reports whether THE
                // PROXY is alive (it is — it answered), with the upstream
                // summary as diagnostic payload. A supervisor that restarts
                // Ferrum because a *backend* died would make the outage worse.
                // The knowledge base's own framing: readiness of the proxy and
                // health of its backends are different questions; L4's breaker
                // already handles the second.
                let _ = degraded;
                (200, "OK", "application/json", body)
            }
            // 404 with a fixed body — no path echo, no reflection surface.
            _ => (404, "Not Found", "text/plain", "404\n".to_string()),
        }
    };

    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let s = conn.stream_mut();
    s.write_all(head.as_bytes()).await?;
    s.write_all(body.as_bytes()).await?;
    s.flush().await
}

/// The proxy's own readiness document. `degraded` when any upstream has zero
/// available servers — the one condition where the proxy is up but some slice
/// of traffic is guaranteed a 502.
fn health_json(metrics: &Metrics, upstreams: &[Arc<Upstream>]) -> (String, bool) {
    let mut degraded = false;
    let mut ups = String::new();
    for (i, u) in upstreams.iter().enumerate() {
        let total = u.servers_slice().len();
        let healthy = u.servers_slice().iter().filter(|s| s.available()).count();
        if healthy == 0 {
            degraded = true;
        }
        if i > 0 {
            ups.push(',');
        }
        // Upstream names are CLI-declared; escaped anyway, same stance as the
        // metrics renderer.
        ups.push_str(&format!(
            "\"{}\":{{\"healthy\":{healthy},\"total\":{total}}}",
            crate::middleware::observe::json_escape(u.name())
        ));
    }
    let body = format!(
        "{{\"status\":\"{}\",\"upstreams\":{{{ups}}},\"active_connections\":{}}}\n",
        if degraded { "degraded" } else { "ok" },
        metrics.active_connections()
    );
    (body, degraded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::{HealthConfig, PoolConfig};

    fn upstream(name: &str, spec: &str) -> Arc<Upstream> {
        Arc::new(
            Upstream::from_spec_with_health(
                name,
                spec,
                &HealthConfig::default(),
                PoolConfig::default(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn health_json_ok_shape() {
        let m = Metrics::new(&["api".to_string()]);
        m.conn_opened();
        let ups = vec![upstream("api", "127.0.0.1:9001,127.0.0.1:9002")];
        let (body, degraded) = health_json(&m, &ups);
        assert!(!degraded);
        assert_eq!(
            body,
            "{\"status\":\"ok\",\"upstreams\":{\"api\":{\"healthy\":2,\"total\":2}},\
             \"active_connections\":1}\n"
        );
    }

    #[test]
    fn health_json_degrades_when_an_upstream_is_empty() {
        let m = Metrics::new(&["api".to_string()]);
        let ups = vec![upstream("api", "127.0.0.1:9001")];
        // Trip the breaker: enough consecutive failures ejects the server.
        let now = std::time::Instant::now();
        for _ in 0..HealthConfig::default().fail_threshold {
            ups[0].servers_slice()[0].record_failure(now);
        }
        let (body, degraded) = health_json(&m, &ups);
        assert!(degraded);
        assert!(body.contains("\"status\":\"degraded\""));
        assert!(body.contains("\"healthy\":0,\"total\":1"));
    }
}
