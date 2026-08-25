//! Level 4 — active health checks.
//!
//! One background task per upstream probes its servers on a timer, entirely
//! independent of client traffic. This is the half of health checking that
//! *passive* observation cannot do: a server with no traffic produces no
//! outcomes, so only an active probe can notice it recovered.
//!
//! The prober is deliberately separate from `balancer.rs`. The breaker is
//! sync, lock-free, and unit-testable without sockets; probing is async and
//! socket-bound. Keeping them in different modules preserves that testability.

use std::sync::Arc;
use std::time::Instant;

use tokio::net::TcpStream;

use crate::balancer::{HealthConfig, Server, Upstream};
use crate::http;
use crate::proxy::Conn;

/// Spawn one prober task per upstream. Called once at startup; the tasks run
/// for the life of the process.
pub fn spawn_probers(upstreams: Vec<Arc<Upstream>>) {
    for up in upstreams {
        tokio::spawn(async move { probe_loop(up).await });
    }
}

/// Probe every due server in this pool, forever.
async fn probe_loop(up: Arc<Upstream>) {
    let cfg = Arc::clone(up.health());
    loop {
        tokio::time::sleep(cfg.interval).await;
        let now = Instant::now();

        // Decide which servers to probe *before* awaiting, so the breaker
        // reads are a consistent snapshot of this tick.
        let due: Vec<usize> = up
            .servers_slice()
            .iter()
            .enumerate()
            .filter(|(_, s)| s.breaker().probe_due(now).is_some())
            .map(|(i, _)| i)
            .collect();

        // Probe concurrently: one slow server must not delay the others. Each
        // probe future owns its own `Arc<Upstream>` clone and only borrows the
        // `Server` *inside* the spawned task, so the future is `'static` and
        // can be handed to `tokio::spawn` (see `futures_unordered`).
        let probes = due.into_iter().map(|i| {
            let up = Arc::clone(&up);
            let cfg = Arc::clone(&cfg);
            async move {
                let server = &up.servers_slice()[i];
                let ok = probe_once(server.addr(), &cfg).await;
                apply_probe_result(server, ok, Instant::now());
            }
        });
        futures_unordered(probes).await;
    }
}

/// Await every future in `iter` concurrently. Hand-rolled to avoid pulling in
/// the `futures` crate for one call site: we spawn each probe and join the
/// handles.
async fn futures_unordered<F>(iter: impl Iterator<Item = F>)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let handles: Vec<_> = iter.map(tokio::spawn).collect();
    for h in handles {
        let _ = h.await;
    }
}

/// Issue one health probe. `true` means the server answered with a 2xx inside
/// the timeout; everything else (connect refused, timeout, malformed response,
/// non-2xx status) is a failure.
pub async fn probe_once(addr: &str, cfg: &HealthConfig) -> bool {
    let deadline = cfg.timeout;
    let result = tokio::time::timeout(deadline, async {
        let stream = TcpStream::connect(addr).await.ok()?;
        let _ = stream.set_nodelay(true);
        let mut conn = Conn::new(stream);

        // Minimal, valid HTTP/1.1: Host is mandatory, and Connection: close
        // means we don't have to care about keep-alive bookkeeping here.
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            cfg.path, addr
        );
        conn.write_all(req.as_bytes()).await.ok()?;
        conn.flush().await.ok()?;

        let head = conn.read_head().await.ok()??;
        let resp = http::parse_response_head(&head).ok()?;
        Some(resp.status)
    })
    .await;

    matches!(result, Ok(Some(status)) if (200..300).contains(&status))
}

/// Map a probe result onto the server's breaker, logging any state change.
/// Split out from the async plumbing so it can be tested synchronously.
pub fn apply_probe_result(server: &Server, ok: bool, now: Instant) {
    let transition = if ok {
        server.record_success(now)
    } else {
        server.record_failure(now)
    };
    if let Some((from, to)) = transition {
        crate::info!(
            "health: {} {from:?}->{to:?} (active probe, cooldown {:?})",
            server.addr(),
            server.breaker().cooldown()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::{Algorithm, BreakerState, HealthConfig, Upstream};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn cfg() -> Arc<HealthConfig> {
        Arc::new(HealthConfig { fail_threshold: 2, ..HealthConfig::default() })
    }

    // The prober's only job is mapping a probe result onto the breaker.
    #[test]
    fn probe_results_drive_the_breaker() {
        let up = Upstream::for_test("p", Algorithm::RoundRobin, &["127.0.0.1:1"], cfg());
        let s = &up.servers_slice()[0];
        let t0 = Instant::now();

        apply_probe_result(s, false, t0);
        assert!(s.available(), "one failure is below the threshold");
        apply_probe_result(s, false, t0);
        assert_eq!(s.breaker().state(), BreakerState::Open, "threshold reached");

        // After the cooldown a trial is admitted; successes restore service.
        let t1 = t0 + Duration::from_secs(1);
        assert!(s.breaker().probe_due(t1).is_some());
        apply_probe_result(s, true, t1);
        apply_probe_result(s, true, t1);
        assert!(s.available(), "successful trials must restore traffic");
    }

    // A probe against a closed port must fail rather than hang or panic.
    #[tokio::test]
    async fn probe_of_dead_port_fails() {
        let c = HealthConfig { timeout: Duration::from_millis(200), ..HealthConfig::default() };
        // Port 1 on loopback is not listening in any sane test environment.
        assert!(!probe_once("127.0.0.1:1", &c).await);
    }
}
