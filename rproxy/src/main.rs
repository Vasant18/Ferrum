//! Ferrum — a reverse proxy in Rust.
//!
//! Levels 1–2: accept TCP connections, parse HTTP/1.1, route each request to
//! a backend by method/host/path, forward it, and relay the response — with
//! keep-alive on the client side and streamed bodies in both directions.
//!
//! Usage:
//!   rproxy [LISTEN_ADDR] ROUTE [ROUTE ...]
//!
//! A ROUTE is `[METHOD ][host]path_expr=BACKEND` (see router::parse_route):
//!   rproxy 127.0.0.1:8080 /=127.0.0.1:9000
//!   rproxy 127.0.0.1:8080 /api/**=127.0.0.1:9001 /=127.0.0.1:9000
//!   rproxy 127.0.0.1:8080 api.example.com/=10.0.0.5:80 /static/**=10.0.0.6:80
//!
//! Backwards-compatible shorthand: `rproxy LISTEN BACKEND` (a bare host:port
//! second argument) is treated as the catch-all route `/=BACKEND`.

mod admin;
mod balancer;
mod health;
mod http;
mod logging;
mod metrics;
mod middleware;
mod proxy;
mod rewrite;
mod router;
mod security;
mod tls;

use std::collections::HashMap;
use std::sync::Arc;

use balancer::Upstream;
use router::{resolve_route, Route, RouteTable};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let listen_addr = args.next().unwrap_or_else(|| "127.0.0.1:8080".to_string());

    // Split the remaining args into `--upstream NAME=SPEC` flags, `--hc-*`
    // health tunables, and plain route specs. Upstreams are declared pools a
    // route can target by name; routes may appear before or after the upstreams
    // they reference because we collect every declaration first and resolve
    // names only afterwards.
    //
    // This is a `match` rather than an `if/else` so unknown *non-flag* args
    // still fall through to `route_specs` (the `_` arm). That fall-through is
    // exactly what preserves every pre-Level-4 invocation: a bare `host:port`
    // shorthand and full `path=BACKEND` route specs are neither `--upstream`
    // nor `--hc-*`, so they land in `route_specs` untouched.
    let mut upstream_specs: Vec<String> = Vec::new();
    let mut route_specs: Vec<String> = Vec::new();
    // Global health-check tunables, seeded with the documented defaults. Each
    // `--hc-*` flag overrides one field; declared upstreams inherit the result.
    let mut hc = balancer::HealthConfig::default();
    // Whether to inject the forwarded headers (X-Forwarded-For and friends).
    // On by default — honest origin reporting is the expected reverse-proxy
    // behavior; `--no-forwarded` opts out for the rare deployment that wants
    // the proxy to stay invisible. Applies to every route.
    let mut forwarded = true;
    // Level 6 observability middleware. Both ON by default — a request id on
    // every response and one access-log line per request are what you want from
    // a proxy on day one, and neither can reject traffic. `--no-*` opts out.
    let mut request_id = true;
    let mut access_log = true;
    // Level 10: the admin plane (`/metrics` + `/health`). `None` = no admin
    // listener at all — exposing it is an explicit choice (see admin.rs).
    let mut admin_addr: Option<String> = None;
    // Level 7 pool tunables, seeded with the same defaults the hardcoded
    // constants carried. Each flag overrides one field; every declared upstream
    // (and the default catch-all) inherits the result — these are GLOBAL, with
    // no per-route override by design. `backend_timeout` mirrors `pool_cfg` but
    // rides a separate path: it is a per-connection deadline threaded straight
    // into `handle_client`, not part of pool construction.
    let mut pool_cfg = balancer::PoolConfig::default();
    let mut backend_timeout = proxy::DEFAULT_BACKEND_RESPONSE_TIMEOUT;
    // Level 8 security surface. TLS is entirely opt-in (no flags = the same
    // plaintext listener Levels 1-7 had), but everything in the armoring half is
    // ON by default with safe values — this level's stated theme is that the
    // config a lazy user gets must be the safe one, and an unbounded listener is
    // a memory-exhaustion primitive rather than a neutral default.
    let mut tls_args = tls::TlsArgs::default();
    let mut max_conns = security::DEFAULT_MAX_CONNS;
    let mut max_conns_per_ip = security::DEFAULT_MAX_CONNS_PER_IP;
    let mut cidrs = security::CidrList::default();
    let mut limits = security::Limits::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--upstream" => upstream_specs.push(next_val(&mut args, "--upstream")?),
            "--hc-interval" => hc.interval = parse_duration(&next_val(&mut args, "--hc-interval")?)?,
            "--hc-timeout" => hc.timeout = parse_duration(&next_val(&mut args, "--hc-timeout")?)?,
            "--hc-backoff-base" => {
                hc.backoff_base = parse_duration(&next_val(&mut args, "--hc-backoff-base")?)?
            }
            "--hc-backoff-max" => {
                hc.backoff_max = parse_duration(&next_val(&mut args, "--hc-backoff-max")?)?
            }
            "--hc-fail" => {
                hc.fail_threshold = next_val(&mut args, "--hc-fail")?
                    .parse()
                    .map_err(|_| bad_arg("--hc-fail expects a number"))?
            }
            "--hc-success" => {
                hc.success_threshold = next_val(&mut args, "--hc-success")?
                    .parse()
                    .map_err(|_| bad_arg("--hc-success expects a number"))?
            }
            "--pool-max-idle" => {
                pool_cfg.max_idle = next_val(&mut args, "--pool-max-idle")?
                    .parse()
                    .map_err(|_| bad_arg("--pool-max-idle expects a number"))?
            }
            "--pool-idle-timeout" => {
                pool_cfg.idle_timeout = parse_duration(&next_val(&mut args, "--pool-idle-timeout")?)?
            }
            "--backend-timeout" => {
                backend_timeout = parse_duration(&next_val(&mut args, "--backend-timeout")?)?
            }
            // ---- Level 8: TLS termination + mTLS ----
            "--tls-cert" => tls_args.cert = Some(next_val(&mut args, "--tls-cert")?.into()),
            "--tls-key" => tls_args.key = Some(next_val(&mut args, "--tls-key")?.into()),
            "--tls-client-ca" => {
                tls_args.client_ca = Some(next_val(&mut args, "--tls-client-ca")?.into())
            }
            "--tls-client-auth" => {
                tls_args.client_auth =
                    tls::ClientAuth::parse(&next_val(&mut args, "--tls-client-auth")?)?
            }
            // ---- Level 8: armoring ----
            "--max-conns" => {
                max_conns = next_val(&mut args, "--max-conns")?
                    .parse()
                    .map_err(|_| bad_arg("--max-conns expects a number"))?
            }
            "--max-conns-per-ip" => {
                max_conns_per_ip = next_val(&mut args, "--max-conns-per-ip")?
                    .parse()
                    .map_err(|_| bad_arg("--max-conns-per-ip expects a number"))?
            }
            "--max-body" => {
                limits.max_body = security::parse_size(&next_val(&mut args, "--max-body")?)
                    .map_err(|e| bad_arg(&e))?
            }
            "--max-headers" => {
                limits.max_headers = next_val(&mut args, "--max-headers")?
                    .parse()
                    .map_err(|_| bad_arg("--max-headers expects a number"))?
            }
            // Repeatable: each occurrence adds one range, so an operator can
            // write several `--deny-cidr` flags rather than inventing a
            // comma-separated sub-grammar. A comma-separated value is also
            // accepted for convenience.
            "--allow-cidr" => {
                for part in next_val(&mut args, "--allow-cidr")?.split(',') {
                    cidrs.push_allow(security::Cidr::parse(part).map_err(|e| bad_arg(&e))?);
                }
            }
            "--deny-cidr" => {
                for part in next_val(&mut args, "--deny-cidr")?.split(',') {
                    cidrs.push_deny(security::Cidr::parse(part).map_err(|e| bad_arg(&e))?);
                }
            }
            "--no-forwarded" => forwarded = false,
            "--no-request-id" => request_id = false,
            "--no-access-log" => access_log = false,
            // ---- Level 10: observability ----
            "--log-level" => {
                let l = logging::Level::parse(&next_val(&mut args, "--log-level")?)
                    .map_err(|e| bad_arg(&e))?;
                logging::set_level(l);
            }
            "--log-plain" => middleware::observe::set_plain(true),
            "--admin" => admin_addr = Some(next_val(&mut args, "--admin")?),
            // Anything else is a route spec (bare host:port or path=BACKEND).
            _ => route_specs.push(arg),
        }
    }

    let routes = build_routes(
        &upstream_specs,
        &route_specs,
        &hc,
        pool_cfg,
        forwarded,
        request_id,
        access_log,
    )?;
    let routes = Arc::new(routes);

    // Level 10: the metrics registry. Built AFTER the route table because its
    // label slots are the declared upstream names — the registry is shaped by
    // config, never by traffic (see metrics.rs on cardinality). Shared with
    // every connection task and the admin listener exactly like `routes`.
    let metrics = Arc::new(metrics::Metrics::new(
        &routes
            .upstreams()
            .iter()
            .map(|u| u.name().to_string())
            .collect::<Vec<_>>(),
    ));

    // Build the TLS config BEFORE binding the listener. A bad cert path, an
    // unreadable key, or an incoherent mTLS combination should fail with exit 1
    // and no socket ever opened — not after the process has announced itself as
    // listening. Same startup-guardrail discipline as Level 5's protected
    // headers and Level 6's `require-user` check.
    let tls_config = tls_args.build()?;
    let tls_acceptor = tls_config.map(tokio_rustls::TlsAcceptor::from);

    // `sanity`: a per-IP cap above the global ceiling can never bind, which
    // means the operator wrote one of the two numbers wrong. Warn rather than
    // fail — the config is safe, just pointless.
    if max_conns_per_ip > max_conns {
        crate::warn!(
            "--max-conns-per-ip {max_conns_per_ip} exceeds --max-conns \
             {max_conns}; the per-IP cap can never be reached"
        );
    }
    let limiter = security::ConnLimiter::new(max_conns, max_conns_per_ip);

    let listener = TcpListener::bind(&listen_addr).await?;
    let scheme = if tls_acceptor.is_some() { "https" } else { "http" };
    println!("ferrum: listening on {listen_addr} ({scheme})");
    if tls_acceptor.is_some() {
        println!(
            "  tls: TLS1.3+1.2, client-auth={:?}",
            tls_args.client_auth
        );
    }
    println!(
        "  limits: max-conns={max_conns} per-ip={max_conns_per_ip} \
         max-body={} max-headers={}",
        limits.max_body, limits.max_headers
    );
    // Only print the access line when a policy actually exists. An unconditional
    // "access: none" trains the operator to skim past the line, which is the
    // opposite of what you want from the one banner entry that says who can
    // reach this listener.
    if !cidrs.is_empty() {
        println!("  access: {}", cidrs.describe());
    }
    for line in routes.describe() {
        println!("  route: {line}");
    }

    // Level 10: the admin plane. Bound HERE, not inside admin::serve, so a bad
    // or taken `--admin` address fails startup with exit 1 — same posture as
    // the TLS guardrails above: fail before announcing service. No flag, no
    // socket: the plane doesn't exist unless asked for.
    if let Some(addr) = &admin_addr {
        let admin_listener = TcpListener::bind(addr).await.map_err(|e| {
            std::io::Error::new(e.kind(), format!("--admin {addr}: {e}"))
        })?;
        println!("  admin: {addr} (/metrics, /health)");
        let metrics = Arc::clone(&metrics);
        let upstreams = routes.upstreams();
        tokio::spawn(async move {
            admin::serve(admin_listener, metrics, upstreams).await;
        });
    }

    // Start active health checking. Probers run for the life of the process,
    // one task per pool, independent of client traffic. This must happen inside
    // the tokio runtime (we are already in `async fn main`, after binding), as
    // `spawn_probers` calls `tokio::spawn`, which panics outside a runtime.
    health::spawn_probers(routes.upstreams());

    // The accept loop is deliberately tiny: pop a completed connection off
    // the kernel's backlog, hand it to its own task, repeat. Anything slow
    // in this loop delays *every* new client.
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // ---- Level 8 gate 1: CIDR policy ----
                // Checked first, and on the *socket* peer address only. This is
                // the cheapest possible rejection: no allocation, no task
                // spawn, no TLS handshake, nothing the caller can make
                // expensive. `normalize_peer` collapses `::ffff:a.b.c.d` to
                // plain v4 so a dual-stack listener does not silently defeat an
                // operator's IPv4 rules.
                let ip = security::normalize_peer(peer);
                if !cidrs.permits(ip) {
                    // Dropped without a response, for the same reason as the
                    // connection limits below: a denied source does not get to
                    // make us do work. `stream` drops here, closing the socket.
                    crate::debug!("[{peer}] refused: address not permitted");
                    continue;
                }

                // ---- Level 8 gate 2: connection limits ----
                // Also before the spawn. The guard is *moved into* the task, so
                // the slot is held for exactly the connection's lifetime and
                // released by `Drop` on every exit path — including a failed
                // TLS handshake and a panicking task.
                let guard = match limiter.try_acquire(ip) {
                    Ok(g) => g,
                    Err(why) => {
                        // Report the in-flight count alongside the reason. On a
                        // `GlobalLimit` refusal this is the number that explains
                        // it, and on a `PerIpLimit` refusal it is the context an
                        // operator needs to tell "one abusive source" from "we
                        // are genuinely at capacity" — two situations with
                        // opposite responses that otherwise look identical in
                        // the log.
                        crate::warn!(
                            "[{peer}] refused: {why} ({} connections in flight)",
                            limiter.in_flight()
                        );
                        continue;
                    }
                };

                // Small writes (our serialized heads) should not sit in Nagle's
                // buffer waiting for a coalescing timer; proxies universally
                // disable it. This moved here from `handle_client` in Level 8:
                // it is a `TcpStream` inherent method, and once TLS wraps the
                // socket the generic proxy core no longer knows it has one.
                // Setting it on the raw socket first is both necessary and
                // correct — the option lives on the file descriptor, which the
                // TLS stream goes on to own.
                let _ = stream.set_nodelay(true);

                // Cloning the Arc is a cheap refcount bump; every task
                // shares one immutable route table with no locking.
                let routes = Arc::clone(&routes);
                // `backend_timeout` is `Copy` (a `Duration`), so the spawned
                // task takes its own copy the same way it clones the `routes`
                // Arc — no shared state, no locking.
                let acceptor = tls_acceptor.clone();
                let metrics = Arc::clone(&metrics);
                tokio::spawn(async move {
                    // Hold the limiter slot for the whole connection. Named
                    // `_guard` rather than `_` because `let _ = guard;` would
                    // drop it immediately and release the slot before the
                    // connection had even started.
                    let _guard = guard;
                    // Level 10: the active_connections gauge. Wrapped in a
                    // Drop guard for the same reason `_guard` is — the dec
                    // must fire on every exit path out of this task (clean
                    // close, error, failed TLS handshake), and RAII is the
                    // only construct that promises that.
                    let _conn_gauge = metrics::ConnGauge::open(&metrics);
                    match acceptor {
                        // ---- TLS listener ----
                        Some(acceptor) => {
                            // THE handshake ordering decision of this level.
                            //
                            // This `.await` is inside the spawned task, NOT in
                            // the accept loop above. Awaiting a handshake in the
                            // accept loop would mean one client that connects
                            // and sends a single ClientHello byte stalls *every*
                            // new connection process-wide — a one-attacker,
                            // one-line total denial of service that would pass
                            // every functional test, because a proxy with one
                            // client at a time still works perfectly.
                            //
                            // The deadline is the TLS-layer analogue of Level
                            // 1's HEAD_READ_TIMEOUT, and it is not optional:
                            // without it slowloris just moves one layer down. A
                            // connection stuck mid-handshake never produces a
                            // request head, so the head deadline never arms and
                            // would never fire.
                            let tls = match tokio::time::timeout(
                                tls::TLS_HANDSHAKE_TIMEOUT,
                                acceptor.accept(stream),
                            )
                            .await
                            {
                                Ok(Ok(s)) => s,
                                Ok(Err(e)) => {
                                    // A failed handshake is routine, not
                                    // exceptional: a probe, a client that does
                                    // not trust our cert, or — with mTLS
                                    // `required` — a client with no certificate.
                                    // Logged at connection level and dropped;
                                    // there is no HTTP layer yet to answer on.
                                    crate::debug!("[{peer}] tls handshake failed: {e}");
                                    return;
                                }
                                Err(_) => {
                                    crate::debug!(
                                        "[{peer}] tls handshake timed out after {:?}",
                                        tls::TLS_HANDSHAKE_TIMEOUT
                                    );
                                    return;
                                }
                            };
                            // "https" is what makes X-Forwarded-Proto honest,
                            // filling the seam Level 5 left at proxy.rs's
                            // ForwardContext.
                            proxy::handle_client(tls, &routes, peer, backend_timeout, "https", limits, &metrics)
                                .await;
                        }
                        // ---- plaintext listener (Levels 1-7, unchanged) ----
                        None => {
                            proxy::handle_client(stream, &routes, peer, backend_timeout, "http", limits, &metrics)
                                .await;
                        }
                    }
                });
            }
            Err(e) => {
                // Transient accept errors (e.g. EMFILE when out of file
                // descriptors) must not kill the proxy; log and continue.
                crate::error!("accept error: {e}");
            }
        }
    }
}

/// An `InvalidInput` error from a static message. A one-liner shared by the
/// argument-parsing helpers so their error construction stays uncluttered.
fn bad_arg(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_string())
}

/// Pull the value that must follow a flag, e.g. the `2s` after `--hc-interval`.
/// A missing value is a startup error naming the flag, rather than a silent
/// default, so a typo like a trailing `--hc-interval` fails loudly.
fn next_val(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> std::io::Result<String> {
    args.next().ok_or_else(|| bad_arg(&format!("{flag} requires a value")))
}

/// Parse `"2s"`, `"500ms"`, or a bare number of seconds.
///
/// We hand-roll this instead of taking a dependency (e.g. `humantime`) because
/// the two suffixes the health checker needs — seconds and milliseconds — are
/// trivial, and Level 4 adds no crates. A bare number is read as seconds so the
/// terse `--hc-fail`-style ergonomics extend to durations too.
fn parse_duration(s: &str) -> std::io::Result<std::time::Duration> {
    let bad = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("bad duration {s:?} (expected e.g. 2s or 500ms)"),
        )
    };
    // Check "ms" before "s": "500ms" ends in 's' too, so testing 's' first
    // would strip only the 's' and try to parse "500m".
    if let Some(ms) = s.strip_suffix("ms") {
        return Ok(std::time::Duration::from_millis(ms.parse().map_err(|_| bad())?));
    }
    let secs = s.strip_suffix('s').unwrap_or(s);
    Ok(std::time::Duration::from_secs(secs.parse().map_err(|_| bad())?))
}

/// Turn CLI upstream + route specs into a `RouteTable`.
///
/// First the `--upstream NAME=SPEC` declarations are parsed into a map of named
/// pools (duplicate names are a startup error). Then each route spec is
/// resolved against that map: a target either names a declared upstream, parses
/// as a bare `host:port` (auto-wrapped as a one-server pool), or is rejected.
///
/// Two friendly defaults preserve the Level 1/2 invocations: no route specs at
/// all -> catch-all to :9000; a single bare `host:port` route arg (no `=`) ->
/// catch-all to that backend.
fn build_routes(
    upstream_specs: &[String],
    route_specs: &[String],
    hc: &balancer::HealthConfig,
    pool_cfg: balancer::PoolConfig,
    forwarded: bool,
    request_id: bool,
    access_log: bool,
) -> std::io::Result<RouteTable> {
    let bad = |m: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, m);

    // Build the named-pool map. `--upstream NAME=SPEC`. Each declared pool
    // inherits the global health tunables (`hc`); its spec may still override
    // the probe path via the `;health=PATH` suffix.
    let mut upstreams: HashMap<String, Arc<Upstream>> = HashMap::new();
    for decl in upstream_specs {
        let (name, spec) = decl
            .split_once('=')
            .ok_or_else(|| bad(format!("--upstream must be NAME=SPEC, got {decl:?}")))?;
        if name.is_empty() {
            return Err(bad(format!("--upstream has empty name: {decl:?}")));
        }
        if upstreams.contains_key(name) {
            return Err(bad(format!("duplicate upstream name {name:?}")));
        }
        upstreams.insert(
            name.to_string(),
            Arc::new(Upstream::from_spec_with_health(name, spec, hc, pool_cfg)?),
        );
    }

    // The two friendly defaults build a catch-all directly (bypassing
    // resolve_route), so `forwarded` would not reach them on its own. Apply it
    // here too — otherwise `rproxy LISTEN --no-forwarded` and the bare
    // `host:port` shorthand would silently keep injecting forwarded headers,
    // making the flag a no-op for exactly the simplest invocations. The same
    // reasoning applies to `--no-request-id` / `--no-access-log`: rebuild the
    // default chain with the flags so they aren't silent no-ops on the defaults.
    if route_specs.is_empty() {
        let mut route = Route::catch_all("127.0.0.1:9000");
        route.rules.forwarded = forwarded;
        route.chain = router::default_chain(request_id, access_log);
        return Ok(RouteTable::new(vec![route]));
    }
    if route_specs.len() == 1 && !route_specs[0].contains('=') {
        let mut route = Route::catch_all(&route_specs[0]);
        route.rules.forwarded = forwarded;
        route.chain = router::default_chain(request_id, access_log);
        return Ok(RouteTable::new(vec![route]));
    }
    let mut routes = Vec::with_capacity(route_specs.len());
    for spec in route_specs {
        routes.push(resolve_route(spec, &upstreams, forwarded, request_id, access_log)?);
    }
    Ok(RouteTable::new(routes))
}
