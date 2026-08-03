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
mod http;
mod proxy;
mod router;

use std::sync::Arc;

use router::{parse_route, Route, RouteTable};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let listen_addr = args.next().unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let route_specs: Vec<String> = args.collect();

    let routes = build_routes(&route_specs)?;
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

/// Turn CLI route specs into a `RouteTable`, applying the two friendly
/// defaults: no args at all -> catch-all to :9000; a single bare `host:port`
/// (no `=`) -> catch-all to that backend (the old Level 1 invocation).
fn build_routes(specs: &[String]) -> std::io::Result<RouteTable> {
    if specs.is_empty() {
        return Ok(RouteTable::new(vec![Route::catch_all("127.0.0.1:9000")]));
    }
    if specs.len() == 1 && !specs[0].contains('=') {
        return Ok(RouteTable::new(vec![Route::catch_all(&specs[0])]));
    }
    let mut routes = Vec::with_capacity(specs.len());
    for spec in specs {
        routes.push(parse_route(spec)?);
    }
    Ok(RouteTable::new(routes))
}
