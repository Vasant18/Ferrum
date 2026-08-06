//! The proxy engine: per-connection loop, forwarding, and body streaming.
//!
//! One client connection = one Tokio task running `handle_client`. Within a
//! connection we serve requests sequentially (HTTP/1.1 semantics), opening
//! one backend connection per request for now — connection pooling arrives
//! in Level 7.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::http::{
    self, BodyFraming, ResponseHead, Version, MAX_HEAD_BYTES,
};
use crate::router::RouteTable;

/// Read buffer size per direction. Bodies stream through this window, so
/// per-connection memory stays flat no matter how large the payload is.
const BUF_SIZE: usize = 16 * 1024;

/// Deadline for the client to deliver a complete request head. This is the
/// slowloris defense: a client trickling one header byte a minute gets cut
/// off instead of holding a socket forever.
const HEAD_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Deadline for establishing the TCP connection to the backend. The kernel
/// default (~2 minutes) is an eternity to hold client resources.
const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum in-request retries after a failed backend *connect*. Three tries
/// total by default. Kept small on purpose: retries multiply load on an
/// already-struggling pool, and a client would rather get a fast 502 than wait
/// through five timeouts.
const MAX_RETRIES: usize = 2;

/// Whether a request method may be safely replayed on another backend.
///
/// Retrying is only correct when re-sending cannot cause a second side effect.
/// `POST`/`PATCH` may have been processed by the backend before the failure
/// surfaced, so replaying them risks duplicate writes; the safe methods here
/// are idempotent by definition in RFC 9110.
fn is_idempotent(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE"
    )
}

/// A buffered reader that owns the "bytes read but not yet consumed"
/// problem. TCP does not respect message boundaries: one read may contain
/// half a request head, or a head plus the beginning of the body, or two
/// pipelined requests. Everything we over-read stays in `buf` for the next
/// consumer instead of being lost.
pub struct Conn<S> {
    stream: S,
    buf: Vec<u8>,
    /// Bytes [0..filled) of `buf` are valid, unconsumed data.
    filled: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    pub fn new(stream: S) -> Self {
        Conn { stream, buf: vec![0; BUF_SIZE], filled: 0 }
    }

    /// Read a complete message head (through `\r\n\r\n`), returning the raw
    /// head bytes. Returns Ok(None) on clean EOF before any byte arrives —
    /// that's a client closing an idle keep-alive connection, not an error.
    pub async fn read_head(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(end) = http::find_head_end(&self.buf[..self.filled]) {
                let head = self.buf[..end].to_vec();
                self.consume(end);
                return Ok(Some(head));
            }
            if self.filled >= MAX_HEAD_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request head exceeds limit",
                ));
            }
            if self.filled == self.buf.len() {
                self.buf.resize((self.buf.len() * 2).min(MAX_HEAD_BYTES), 0);
            }
            let n = self.stream.read(&mut self.buf[self.filled..]).await?;
            if n == 0 {
                if self.filled == 0 {
                    return Ok(None); // clean EOF between requests
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed mid-head",
                ));
            }
            self.filled += n;
        }
    }

    /// Drop the first `n` consumed bytes, shifting any over-read remainder
    /// (start of body, or a pipelined next request) to the front.
    fn consume(&mut self, n: usize) {
        self.buf.copy_within(n..self.filled, 0);
        self.filled -= n;
    }

    /// Stream a body from this connection into `dst`, honoring `framing`.
    /// Returns whether the connection is still usable for another message
    /// afterwards (UntilClose bodies consume the connection by definition).
    pub async fn copy_body_to<W>(
        &mut self,
        dst: &mut W,
        framing: BodyFraming,
    ) -> io::Result<bool>
    where
        W: AsyncWrite + Unpin,
    {
        match framing {
            BodyFraming::None => Ok(true),
            BodyFraming::Length(len) => {
                self.copy_exact(dst, len).await?;
                Ok(true)
            }
            BodyFraming::Chunked => {
                self.copy_chunked(dst).await?;
                Ok(true)
            }
            BodyFraming::UntilClose => {
                // Relay whatever is buffered, then pump until EOF.
                if self.filled > 0 {
                    dst.write_all(&self.buf[..self.filled]).await?;
                    self.filled = 0;
                }
                tokio::io::copy(&mut self.stream, dst).await?;
                Ok(false)
            }
        }
    }

    /// Copy exactly `len` body bytes, window by window. Never buffers more
    /// than one BUF_SIZE window — a 2 GB upload costs 16 KB of memory.
    async fn copy_exact<W>(&mut self, dst: &mut W, mut len: u64) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        while len > 0 {
            if self.filled == 0 {
                let n = self.stream.read(&mut self.buf).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed mid-body",
                    ));
                }
                self.filled = n;
            }
            // Take only what belongs to this body; the rest may be the
            // next pipelined request and must stay buffered.
            let take = (self.filled as u64).min(len) as usize;
            dst.write_all(&self.buf[..take]).await?;
            self.consume(take);
            len -= take as u64;
        }
        Ok(())
    }

    /// Read one line ending in CRLF (used for chunk-size lines). The line
    /// must fit in the buffer, which is generous for hex sizes.
    async fn read_line(&mut self) -> io::Result<String> {
        loop {
            if let Some(pos) = self.buf[..self.filled].windows(2).position(|w| w == b"\r\n") {
                let line = String::from_utf8_lossy(&self.buf[..pos]).into_owned();
                self.consume(pos + 2);
                return Ok(line);
            }
            if self.filled == self.buf.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk line too long"));
            }
            let n = self.stream.read(&mut self.buf[self.filled..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed mid-chunk",
                ));
            }
            self.filled += n;
        }
    }

    /// Relay a chunked body, re-encoding the framing verbatim:
    /// `<hex-size>\r\n<data>\r\n` repeated, then `0\r\n`, optional trailers,
    /// and the final blank line.
    async fn copy_chunked<W>(&mut self, dst: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        loop {
            let size_line = self.read_line().await?;
            // Chunk extensions (";ext=val") are allowed after the size;
            // we strip them rather than forward what we don't understand.
            let size_hex = size_line.split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(size_hex, 16).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid chunk size: {size_line:?}"),
                )
            })?;

            dst.write_all(format!("{size_hex}\r\n").as_bytes()).await?;

            if size == 0 {
                // Trailer section: forward lines until the blank one.
                loop {
                    let trailer = self.read_line().await?;
                    dst.write_all(trailer.as_bytes()).await?;
                    dst.write_all(b"\r\n").await?;
                    if trailer.is_empty() {
                        return Ok(());
                    }
                }
            }

            self.copy_exact(dst, size).await?;

            // Each chunk's data is followed by its own CRLF.
            let sep = self.read_line().await?;
            if !sep.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing CRLF after chunk data",
                ));
            }
            dst.write_all(b"\r\n").await?;
        }
    }

    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(data).await
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.stream.flush().await
    }
}

/// Hop-by-hop headers describe one TCP connection, not the end-to-end
/// message. Forwarding them verbatim is a protocol violation (a client's
/// `Connection: close` would close our backend leg) and mishandling
/// Transfer-Encoding here is the literal mechanism of request smuggling —
/// we strip them all and manage each leg's connection semantics ourselves.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

fn strip_hop_by_hop(headers: &mut Vec<(String, String)>) {
    // Also strip anything the Connection header itself names.
    let named: Vec<String> = http::header(headers, "connection")
        .map(|v| v.split(',').map(|t| t.trim().to_ascii_lowercase()).collect())
        .unwrap_or_default();
    headers.retain(|(n, _)| {
        let n = n.to_ascii_lowercase();
        !HOP_BY_HOP.contains(&n.as_str()) && !named.contains(&n)
    });
}

/// Serve one client connection: a sequence of request/response exchanges
/// on the same socket (keep-alive), each routed to a backend by `routes`.
pub async fn handle_client(client: TcpStream, routes: &RouteTable, peer: std::net::SocketAddr) {
    // Small writes (our serialized heads) should not sit in Nagle's buffer
    // waiting for a coalescing timer; proxies universally disable it.
    let _ = client.set_nodelay(true);
    let mut client = Conn::new(client);

    loop {
        match serve_one(&mut client, routes, peer).await {
            Ok(true) => continue,          // keep-alive: next request, same socket
            Ok(false) => return,           // clean close
            Err(e) => {
                // One connection's failure is that connection's problem —
                // log and drop it; the accept loop is unaffected.
                eprintln!("[{peer}] connection ended: {e}");
                return;
            }
        }
    }
}

/// Serve exactly one exchange. Returns Ok(true) if the client connection
/// should be kept open for another request.
async fn serve_one(
    client: &mut Conn<TcpStream>,
    routes: &RouteTable,
    peer: std::net::SocketAddr,
) -> io::Result<bool> {
    // ---- 1. Read + parse the request head (with slowloris deadline) ----
    let head_bytes =
        match tokio::time::timeout(HEAD_READ_TIMEOUT, client.read_head()).await {
            Err(_) => {
                // Timeout: tell the client why before hanging up.
                let _ = respond_error(client, 408, "Request Timeout").await;
                return Ok(false);
            }
            Ok(Ok(None)) => return Ok(false), // idle keep-alive conn closed
            Ok(Ok(Some(bytes))) => bytes,
            Ok(Err(e)) => {
                let _ = respond_error(client, 400, "Bad Request").await;
                return Err(e);
            }
        };

    let mut req = match http::parse_request_head(&head_bytes) {
        Ok(r) => r,
        Err(e) => {
            let _ = respond_error(client, 400, "Bad Request").await;
            return Err(e);
        }
    };

    let req_framing = match http::request_body_framing(&req) {
        Ok(f) => f,
        Err(e) => {
            let _ = respond_error(client, 400, "Bad Request").await;
            return Err(e);
        }
    };

    let client_keep_alive = http::wants_keep_alive(req.version, &req.headers);
    let method = req.method.clone();

    // ---- 2. Route: pick a POOL from method + host + path ----
    let host = http::header(&req.headers, "host").map(http::host_without_port);
    let path = http::target_path(&req.target);
    let upstream = match routes.find(&method, host, path) {
        Some(u) => u,
        None => {
            // No route matched. This is a routing decision, not a client
            // error — the request was well-formed, we just don't serve it.
            println!(
                "[{peer}] {} {} {} -> 404 (no route)",
                req.method,
                req.target,
                req.version.as_str()
            );
            // respond_error sends Connection: close, so we honestly close.
            respond_error(client, 404, "Not Found").await?;
            return Ok(false);
        }
    };

    // ---- 2b. Balance + connect, with retry ----
    // Retry is gated on three conditions, all required:
    //   1. attempts remain (MAX_RETRIES),
    //   2. the method is idempotent (safe to replay),
    //   3. we are still at the connect stage — no request-body bytes have been
    //      forwarded, so nothing is committed to a backend yet.
    // Only a failed *connect* retries. A failure after the request was sent
    // (5xx, mid-response I/O error) is not replayable: it still feeds the
    // breaker, but the client gets the error.
    //
    // The lease holds one in-flight count on the chosen server and feeds the
    // breaker on drop (see balancer::Lease); we keep the winning lease alive
    // until the exchange ends, so the loop yields it outward.
    let retryable = is_idempotent(&method);
    let mut attempt = 0usize;
    let (mut lease, backend) = loop {
        let mut lease = match upstream.pick(peer.ip()) {
            Some(l) => l,
            None => {
                // Every server in the pool is ejected by its breaker (or the
                // pool is empty, which startup validation forbids).
                eprintln!(
                    "[{peer}] no healthy server in upstream {:?}",
                    upstream.name()
                );
                respond_error(client, 502, "Bad Gateway").await?;
                return Ok(false);
            }
        };
        let addr = lease.addr().to_string();
        // Observability: name the pool, algorithm, chosen server, and its
        // current in-flight depth so balancing is visible under a `curl` loop.
        // On a retry we tag the attempt so the fan-out to a fresh server shows.
        println!(
            "[{peer}] {} {} {} -> {}[{}] {addr} (inflight={}){}",
            req.method,
            req.target,
            req.version.as_str(),
            upstream.name(),
            upstream.algorithm().tag(),
            lease.inflight(),
            if attempt > 0 { format!(" [retry {attempt}/{MAX_RETRIES}]") } else { String::new() },
        );

        match tokio::time::timeout(BACKEND_CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => break (lease, s),
            Ok(Err(e)) => {
                // Transport failure: indict this server, then consider retrying
                // on a different one. mark_failure fires before the next pick,
                // so a tripped breaker excludes this server immediately. We must
                // drop the lease before continuing: it borrows the Upstream, so
                // the next pick() would conflict with the outstanding borrow.
                lease.mark_failure();
                eprintln!("[{peer}] backend {addr} connect failed: {e}");
                drop(lease);
                if retryable && attempt < MAX_RETRIES {
                    attempt += 1;
                    continue;
                }
                respond_error(client, 502, "Bad Gateway").await?;
                return Ok(false);
            }
            Err(_) => {
                lease.mark_failure();
                eprintln!("[{peer}] backend {addr} connect timed out");
                drop(lease);
                if retryable && attempt < MAX_RETRIES {
                    attempt += 1;
                    continue;
                }
                respond_error(client, 504, "Gateway Timeout").await?;
                return Ok(false);
            }
        }
    };
    // The exchange is now underway; a completed exchange should feed the
    // server's response-time average, so arm the lease's RTT recording.
    lease.mark_served();
    // Pessimistic default: the request is about to go out, and from here to the
    // point where we hold a valid response head there are six `?` early-returns
    // (write head, stream body, flush, read head, "closed before responding",
    // parse head, framing). Each of those is a *real observed I/O failure* on a
    // request we already committed to this backend, so each must indict it — but
    // wiring mark_failure() into all six sites is easy to get wrong and easy for
    // a future edit to skip. Instead we default the outcome to failure right
    // here and let the mark_success() below upgrade it once a `<500` response
    // head is actually in hand. Any `?` that fires in between therefore scores a
    // failure automatically, without touching a single call site. This is safe
    // because it only runs *after* the request was sent: cancellation before
    // this point leaves the lease unmarked (correctly neutral), and these `?`
    // paths are exactly the "response-read error / mid-response I/O error"
    // failures the health-check spec says to feed the breaker. Note this does
    // not affect retries: the retry loop lives entirely above mark_served(), so
    // a failure recorded here can never trigger a replay.
    lease.mark_failure();
    let _ = backend.set_nodelay(true);
    let mut backend = Conn::new(backend);

    // ---- 4. Forward the request: rewritten head, then streamed body ----
    strip_hop_by_hop(&mut req.headers);
    // Take exclusive control of the body-framing header. strip_hop_by_hop
    // removes the "TE" header but NOT "Transfer-Encoding"; if we re-added a
    // chunked TE below without removing the original, the backend would see
    // two Transfer-Encoding lines — a smuggling desync. Content-Length is
    // left untouched: the parser already guaranteed at most one, and for
    // Length framing it carries the backend's only body delimiter.
    http::remove_header(&mut req.headers, "transfer-encoding");
    // We speak HTTP/1.1 to the backend and manage its connection per
    // exchange (Connection: close until Level 7 adds pooling).
    req.version = Version::Http11;
    req.headers.push(("Connection".to_string(), "close".to_string()));
    // Re-declare the body framing we just stripped/validated.
    if req_framing == BodyFraming::Chunked {
        req.headers.push(("Transfer-Encoding".to_string(), "chunked".to_string()));
    }

    backend.write_all(&http::write_request_head(&req)).await?;
    client.copy_body_to(&mut backend.stream_mut(), req_framing).await?;
    backend.flush().await?;

    // ---- 5. Read the backend's response head ----
    let resp_bytes = backend.read_head().await?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "backend closed before responding")
    })?;
    let mut resp = http::parse_response_head(&resp_bytes)?;
    let resp_framing = http::response_body_framing(&method, &resp)?;

    println!("[{peer}]   -> {} {}", resp.status, resp.reason);

    // Passive health check: 5xx indicts the backend, anything below it does
    // not (a 404 means the backend is healthy and the path is wrong).
    if resp.status >= 500 {
        lease.mark_failure();
    } else {
        lease.mark_success();
    }

    // ---- 6. Relay the response: rewritten head, then streamed body ----
    strip_hop_by_hop(&mut resp.headers);
    // Same framing-header ownership as the request leg: drop any existing
    // Transfer-Encoding so re-declaring chunked below can't produce a
    // duplicate TE toward the client.
    http::remove_header(&mut resp.headers, "transfer-encoding");
    // The version on the client leg describes *our* conversation with the
    // client, not the backend's dialect — an HTTP/1.0 backend must not
    // downgrade what we advertise.
    resp.version = Version::Http11;
    let client_still_usable;
    match resp_framing {
        BodyFraming::UntilClose => {
            // We can't know the length, and we won't buffer to find out:
            // signal the end to the client by closing, HTTP/1.0 style.
            resp.headers.push(("Connection".to_string(), "close".to_string()));
            client_still_usable = false;
        }
        _ => {
            if resp_framing == BodyFraming::Chunked {
                resp.headers
                    .push(("Transfer-Encoding".to_string(), "chunked".to_string()));
            }
            resp.headers.push((
                "Connection".to_string(),
                if client_keep_alive { "keep-alive" } else { "close" }.to_string(),
            ));
            client_still_usable = client_keep_alive;
        }
    }

    client.write_all(&http::write_response_head(&resp)).await?;
    backend.copy_body_to(client.stream_mut(), resp_framing).await?;
    client.flush().await?;

    // Backend conn drops here (Connection: close) — pooling is Level 7.
    Ok(client_still_usable)
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    /// Escape hatch for copy loops that need the raw stream as a write
    /// target while another Conn drives the reads.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

/// Minimal error response, generated by the proxy itself.
async fn respond_error<S>(client: &mut Conn<S>, status: u16, reason: &str) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let body = format!("{status} {reason}\n");
    let head = ResponseHead {
        version: Version::Http11,
        status,
        reason: reason.to_string(),
        headers: vec![
            ("Content-Type".to_string(), "text/plain".to_string()),
            ("Content-Length".to_string(), body.len().to_string()),
            ("Connection".to_string(), "close".to_string()),
        ],
    };
    client.write_all(&http::write_response_head(&head)).await?;
    client.write_all(body.as_bytes()).await?;
    client.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Feed raw bytes through a Conn using an in-memory duplex pipe.
    async fn conn_with(data: &[u8]) -> Conn<tokio::io::DuplexStream> {
        let (mut tx, rx) = duplex(64 * 1024);
        tx.write_all(data).await.unwrap();
        drop(tx); // EOF after the data
        Conn::new(rx)
    }

    #[tokio::test]
    async fn reads_head_across_fragmented_input() {
        let (mut tx, rx) = duplex(1024);
        let mut conn = Conn::new(rx);
        // Deliver the head one fragment at a time, like a slow network.
        tokio::spawn(async move {
            for frag in [&b"GET / HT"[..], b"TP/1.1\r\nHost:", b" x\r\n\r\n"] {
                tx.write_all(frag).await.unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let head = conn.read_head().await.unwrap().unwrap();
        assert!(head.ends_with(b"\r\n\r\n"));
        assert!(head.starts_with(b"GET / HTTP/1.1"));
    }

    #[tokio::test]
    async fn clean_eof_returns_none() {
        let mut conn = conn_with(b"").await;
        assert!(conn.read_head().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn eof_mid_head_is_error() {
        let mut conn = conn_with(b"GET / HTTP/1.1\r\nHos").await;
        assert!(conn.read_head().await.is_err());
    }

    #[tokio::test]
    async fn preserves_pipelined_bytes_after_head() {
        let mut conn = conn_with(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloGET /next HTTP/1.1\r\n\r\n").await;
        let _head = conn.read_head().await.unwrap().unwrap();
        let mut body = Vec::new();
        conn.copy_body_to(&mut body, BodyFraming::Length(5)).await.unwrap();
        assert_eq!(body, b"hello");
        // The pipelined second request must still be readable.
        let head2 = conn.read_head().await.unwrap().unwrap();
        assert!(head2.starts_with(b"GET /next"));
    }

    #[tokio::test]
    async fn copies_chunked_body_verbatim() {
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut conn = conn_with(raw).await;
        let mut out = Vec::new();
        conn.copy_body_to(&mut out, BodyFraming::Chunked).await.unwrap();
        assert_eq!(out, raw);
    }

    #[tokio::test]
    async fn chunked_with_extension_is_normalized() {
        let raw = b"5;ext=1\r\nhello\r\n0\r\n\r\n";
        let mut conn = conn_with(raw).await;
        let mut out = Vec::new();
        conn.copy_body_to(&mut out, BodyFraming::Chunked).await.unwrap();
        assert_eq!(out, b"5\r\nhello\r\n0\r\n\r\n");
    }

    #[tokio::test]
    async fn rejects_garbage_chunk_size() {
        let mut conn = conn_with(b"zzz\r\nhello\r\n0\r\n\r\n").await;
        let mut out = Vec::new();
        assert!(conn.copy_body_to(&mut out, BodyFraming::Chunked).await.is_err());
    }

    #[tokio::test]
    async fn until_close_copies_to_eof() {
        let mut conn = conn_with(b"raw bytes until eof").await;
        let mut out = Vec::new();
        let reusable = conn.copy_body_to(&mut out, BodyFraming::UntilClose).await.unwrap();
        assert_eq!(out, b"raw bytes until eof");
        assert!(!reusable);
    }

    #[test]
    fn strips_hop_by_hop_and_connection_named() {
        let mut headers = vec![
            ("Host".to_string(), "x".to_string()),
            ("Connection".to_string(), "close, X-Custom".to_string()),
            ("Keep-Alive".to_string(), "timeout=5".to_string()),
            ("X-Custom".to_string(), "die".to_string()),
            ("Accept".to_string(), "*/*".to_string()),
        ];
        strip_hop_by_hop(&mut headers);
        let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["Host", "Accept"]);
    }

    // Retry is only safe for methods with no side effects. A POST may already
    // have been processed by the backend before the failure, so replaying it
    // could double-charge a card; GET can always be repeated.
    #[test]
    fn idempotent_methods_are_retryable() {
        for m in ["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"] {
            assert!(is_idempotent(m), "{m} should be retryable");
        }
        for m in ["POST", "PATCH", "CONNECT", "WEIRD"] {
            assert!(!is_idempotent(m), "{m} must NOT be retried");
        }
        // Method matching is case-insensitive per RFC 9110 practice here.
        assert!(is_idempotent("get"));
    }
}
