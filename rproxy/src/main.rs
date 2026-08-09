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

mod balancer;
mod health;
mod http;
mod middleware;
mod proxy;
mod rewrite;
mod router;

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
            "--no-forwarded" => forwarded = false,
            "--no-request-id" => request_id = false,
            "--no-access-log" => access_log = false,
            // Anything else is a route spec (bare host:port or path=BACKEND).
            _ => route_specs.push(arg),
        }
    }

    let routes = build_routes(
        &upstream_specs,
        &route_specs,
        &hc,
        forwarded,
        request_id,
        access_log,
    )?;
    let routes = Arc::new(routes);

    let listener = TcpListener::bind(&listen_addr).await?;
    println!("ferrum: listening on {listen_addr}");
    for line in routes.describe() {
        println!("  route: {line}");
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
                // Cloning the Arc is a cheap refcount bump; every task
                // shares one immutable route table with no locking.
                let routes = Arc::clone(&routes);
                tokio::spawn(async move {
                    proxy::handle_client(stream, &routes, peer).await;
                });
            }
            Err(e) => {
                // Transient accept errors (e.g. EMFILE when out of file
                // descriptors) must not kill the proxy; log and continue.
                eprintln!("accept error: {e}");
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
            Arc::new(Upstream::from_spec_with_health(name, spec, hc)?),
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
