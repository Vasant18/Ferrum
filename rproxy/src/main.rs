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
mod proxy;
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

    // Split the remaining args into `--upstream NAME=SPEC` flags and plain
    // route specs. Upstreams are declared pools a route can target by name;
    // routes may appear before or after the upstreams they reference because
    // we collect every declaration first and resolve names only afterwards.
    let mut upstream_specs: Vec<String> = Vec::new();
    let mut route_specs: Vec<String> = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--upstream" {
            let spec = args.next().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "--upstream requires an argument (NAME=SPEC)",
                )
            })?;
            upstream_specs.push(spec);
        } else {
            route_specs.push(arg);
        }
    }

    let routes = build_routes(&upstream_specs, &route_specs)?;
    let routes = Arc::new(routes);

    let listener = TcpListener::bind(&listen_addr).await?;
    println!("ferrum: listening on {listen_addr}");
    for line in routes.describe() {
        println!("  route: {line}");
    }

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
fn build_routes(upstream_specs: &[String], route_specs: &[String]) -> std::io::Result<RouteTable> {
    let bad = |m: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, m);

    // Build the named-pool map. `--upstream NAME=SPEC`.
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
        upstreams.insert(name.to_string(), Arc::new(Upstream::from_spec(name, spec)?));
    }

    if route_specs.is_empty() {
        return Ok(RouteTable::new(vec![Route::catch_all("127.0.0.1:9000")]));
    }
    if route_specs.len() == 1 && !route_specs[0].contains('=') {
        return Ok(RouteTable::new(vec![Route::catch_all(&route_specs[0])]));
    }
    let mut routes = Vec::with_capacity(route_specs.len());
    for spec in route_specs {
        routes.push(resolve_route(spec, &upstreams)?);
    }
    Ok(RouteTable::new(routes))
}
