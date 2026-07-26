//! Ferrum — a reverse proxy in Rust.
//!
//! Level 1: accept TCP connections, parse HTTP/1.1, forward each request to
//! a single backend, and relay the response — with keep-alive on the client
//! side and streamed (never fully buffered) bodies in both directions.
//!
//! Usage: rproxy [LISTEN_ADDR] [BACKEND_ADDR]
//! Defaults:      127.0.0.1:8080  127.0.0.1:9000

mod http;
mod proxy;

use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let listen_addr = args.next().unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let backend_addr = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_string());

    let listener = TcpListener::bind(&listen_addr).await?;
    println!("ferrum: listening on {listen_addr}, forwarding to {backend_addr}");

    // The accept loop is deliberately tiny: pop a completed connection off
    // the kernel's backlog, hand it to its own task, repeat. Anything slow
    // in this loop delays *every* new client.
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let backend = backend_addr.clone();
                // The stream is moved into the task: from here on, exactly
                // one owner is responsible for this socket's lifetime.
                tokio::spawn(async move {
                    proxy::handle_client(stream, &backend, peer).await;
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
