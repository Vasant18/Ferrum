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

/// Default deadline for the backend to deliver its response HEAD after we
/// finished sending the request. Protects against hung application code —
/// until this existed, a backend that accepted the connection and never
/// responded blocked that connection task forever with no client-visible
/// error and no breaker signal. This closes that gap: a hang now looks, to
/// the breaker, like a connect failure. Does NOT bound body-streaming time —
/// that's size-and-route-dependent and stays a documented gap
/// (time-to-first-byte only, matching the knowledge base's framing of this
/// timeout).
///
/// Level 7 makes this the *default*: `--backend-timeout` overrides it at
/// startup, so this constant is now the fallback value threaded into
/// `serve_one` rather than the only value it can read. Named with the
/// `DEFAULT_` prefix and made `pub` so `main.rs` can seed its CLI variable
/// from the same source of truth.
pub const DEFAULT_BACKEND_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum in-request retries after a failed backend *connect*. Three tries
/// total by default. Kept small on purpose: retries multiply load on an
/// already-struggling pool, and a client would rather get a fast 502 than wait
/// through five timeouts.
const MAX_RETRIES: usize = 2;

/// How much of a short-circuited request's body we drain before giving up and
/// closing. 64 KB is generous for the challenge case (a client retrying a small
/// request after a 401) and small enough that we never read a large upload we
/// intend to discard. See `Conn::drain_body` for why draining matters at all.
const REJECT_DRAIN_CAP: u64 = 64 * 1024;

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

/// How a body copy ended.
///
/// A three-state outcome rather than `io::Result<bool>` because "the body was
/// too large" is not an I/O error and must not be handled like one: the socket
/// is healthy, the client is well-behaved by TCP's standards, and the correct
/// response is a specific HTTP status (413), not a dropped connection with a
/// logged errno. Making it a distinct variant means the caller has to decide
/// what to do about it, which is exactly the property we want at a security
/// boundary — a `?` cannot silently swallow it into the generic error path.
#[derive(Debug, PartialEq, Eq)]
enum BodyCopy {
    /// The whole body was relayed. `reusable` carries the existing keep-alive
    /// meaning (false for until-close framing, which consumes the connection).
    Done { reusable: bool },
    /// The configured cap was hit. For chunked framing this means part of the
    /// body was already forwarded and BOTH connections are desynced.
    TooLarge,
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
        match self.copy_body_limited(dst, framing, None).await? {
            BodyCopy::Done { reusable } => Ok(reusable),
            // Unreachable with `None`, but expressed as an error rather than
            // `unreachable!()` so a future caller that passes a cap here cannot
            // turn a limit breach into a panic.
            BodyCopy::TooLarge => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "body exceeded limit",
            )),
        }
    }

    /// Stream a body, optionally aborting once `max` decoded bytes have passed.
    ///
    /// The cap is enforced **during** the copy, never by buffering the body and
    /// checking afterwards. That ordering is this level's named mistake #1 —
    /// "reading the whole body then checking the size limit: the damage is
    /// done." Level 1's windowed copy loop is what makes the correct version
    /// cheap: there is already a loop that sees every byte, so enforcement is a
    /// running total and a comparison, not a new mechanism.
    ///
    /// Note the asymmetry between framings, which is the interesting part:
    ///
    /// - `Length(n)` is knowable **before** any byte moves, so `serve_one`
    ///   rejects an over-cap request up front and this path never sees it. That
    ///   is strictly better than streaming-and-aborting: the client gets a clean
    ///   413 and the backend is never contacted at all.
    /// - `Chunked` has no declared size — that is the whole point of chunked —
    ///   so the only possible enforcement is mid-stream, and by then the request
    ///   head is already at the backend. The exchange is therefore *unsalvageable*:
    ///   we stop mid-body, which leaves the backend connection desynced (it is
    ///   still expecting chunks) and the client connection desynced (it is still
    ///   sending them). Both must close. `TooLarge` says so rather than pretending
    ///   the connection can be reused.
    async fn copy_body_limited<W>(
        &mut self,
        dst: &mut W,
        framing: BodyFraming,
        max: Option<u64>,
    ) -> io::Result<BodyCopy>
    where
        W: AsyncWrite + Unpin,
    {
        match framing {
            BodyFraming::None => Ok(BodyCopy::Done { reusable: true }),
            BodyFraming::Length(len) => {
                if max.is_some_and(|m| len > m) {
                    return Ok(BodyCopy::TooLarge);
                }
                self.copy_exact(dst, len).await?;
                Ok(BodyCopy::Done { reusable: true })
            }
            BodyFraming::Chunked => self.copy_chunked(dst, max).await,
            BodyFraming::UntilClose => {
                // Relay whatever is buffered, then pump until EOF.
                if self.filled > 0 {
                    dst.write_all(&self.buf[..self.filled]).await?;
                    self.filled = 0;
                }
                // `copy` returns the byte count, which makes the cap checkable
                // here too — but only after the fact, so an over-cap
                // until-close body has already been forwarded. That is
                // acceptable because a request can never legitimately use
                // until-close framing (a client cannot signal "body ends at
                // EOF" and still read a response), so this arm is
                // response-side only, where the cap is `None`.
                let n = tokio::io::copy(&mut self.stream, dst).await?;
                if max.is_some_and(|m| n > m) {
                    return Ok(BodyCopy::TooLarge);
                }
                Ok(BodyCopy::Done { reusable: false })
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
    ///
    /// `max` bounds the total *decoded* payload — the sum of the chunk sizes,
    /// not the wire bytes. Counting decoded payload is the right choice: chunk
    /// framing overhead is attacker-controlled (a million 1-byte chunks carry a
    /// megabyte of framing around a megabyte of data), so a wire-byte cap would
    /// reject honest large-chunk requests and admit pathological small-chunk
    /// ones. The framing overhead is separately bounded by `read_line`'s
    /// buffer-size check.
    async fn copy_chunked<W>(&mut self, dst: &mut W, max: Option<u64>) -> io::Result<BodyCopy>
    where
        W: AsyncWrite + Unpin,
    {
        let mut decoded: u64 = 0;
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

            // Enforce the cap BEFORE forwarding this chunk's header, so we stop
            // on a clean chunk boundary rather than emitting a size line and
            // then refusing to supply its bytes (which would desync the backend
            // parser in a second, avoidable way on top of the truncation).
            // `saturating_add` because both operands are attacker-controlled and
            // a wrap would turn "absurdly large" into "under the limit."
            if max.is_some_and(|m| decoded.saturating_add(size) > m) {
                return Ok(BodyCopy::TooLarge);
            }

            dst.write_all(format!("{size_hex}\r\n").as_bytes()).await?;

            if size == 0 {
                // Trailer section: forward lines until the blank one.
                loop {
                    let trailer = self.read_line().await?;
                    dst.write_all(trailer.as_bytes()).await?;
                    dst.write_all(b"\r\n").await?;
                    if trailer.is_empty() {
                        return Ok(BodyCopy::Done { reusable: true });
                    }
                }
            }

            self.copy_exact(dst, size).await?;
            decoded = decoded.saturating_add(size);

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

    /// Discard up to `cap` bytes of a request body for a short-circuited
    /// request. Returns `true` if the whole body was consumed within the cap
    /// (the connection is reusable), `false` if the cap was hit (caller closes).
    ///
    /// Why drain at all, even when we intend to close: unread bytes still in the
    /// socket when we `close()` make the kernel send a TCP **RST** instead of a
    /// clean FIN, and an RST can discard data already in flight — including the
    /// rejection response we just wrote. So the client would see a connection
    /// reset rather than the 401/429 explaining why. Draining lets us send a
    /// clean FIN, or keep-alive (which a 401 challenge needs so the client can
    /// retry with credentials on the same connection).
    pub async fn drain_body(&mut self, framing: BodyFraming, cap: u64) -> io::Result<bool> {
        let mut sink = tokio::io::sink();
        match framing {
            BodyFraming::None => Ok(true),
            // Length is known up front, so the keep-vs-close decision is made
            // before reading a byte: a body within the cap is drained and the
            // connection kept; an over-cap body is left unread and we signal
            // close (reading megabytes we intend to discard is pointless).
            BodyFraming::Length(n) if n <= cap => {
                self.copy_exact(&mut sink, n).await?;
                Ok(true)
            }
            BodyFraming::Length(_) => Ok(false),
            BodyFraming::Chunked => self.drain_chunked_capped(cap).await,
            // Requests never use until-close framing (http.rs enforces this);
            // treat it defensively as "cannot safely reuse".
            BodyFraming::UntilClose => Ok(false),
        }
    }

    /// Drain a chunked request body, discarding, until the terminating
    /// zero-chunk or until more than `cap` data bytes have gone by — whichever
    /// comes first. Returns `false` on the cap overflow so the caller closes
    /// (we can't know where the body ends without reading it all).
    async fn drain_chunked_capped(&mut self, cap: u64) -> io::Result<bool> {
        let mut sink = tokio::io::sink();
        let mut seen: u64 = 0;
        loop {
            let size_line = self.read_line().await?;
            let size_hex = size_line.split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(size_hex, 16).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid chunk size: {size_line:?}"),
                )
            })?;
            if size == 0 {
                // Consume the trailer section up to the blank line.
                loop {
                    let trailer = self.read_line().await?;
                    if trailer.is_empty() {
                        return Ok(true);
                    }
                }
            }
            seen = seen.saturating_add(size);
            if seen > cap {
                return Ok(false);
            }
            self.copy_exact(&mut sink, size).await?;
            // Each chunk's data is followed by its own CRLF.
            let sep = self.read_line().await?;
            if !sep.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing CRLF after chunk data",
                ));
            }
        }
    }

    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(data).await
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.stream.flush().await
    }

    /// Whether every byte read from the stream so far has been consumed —
    /// no pipelined-request or leftover body bytes are sitting in `buf`.
    /// Used only by the backend-leg poolability check: a non-empty buffer
    /// here means either backend misbehavior or a framing-accounting bug,
    /// and pooling it forward would leak those bytes into the next checkout.
    pub fn buffer_is_empty(&self) -> bool {
        self.filled == 0
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

/// Whether a backend connection that just finished an exchange may be
/// returned to the pool. All five conditions are required:
///
///   1. `resp_framing` is not `UntilClose` — that framing means "read until
///      the backend closes", which is unreusable by definition.
///   2. the backend did not send `Connection: close` (`backend_sent_close`).
///   3. the backend spoke HTTP/1.1 (`backend_is_http11`) — an HTTP/1.0
///      backend doesn't support persistent connections at all.
///   4. the exchange completed with no I/O error (`exchange_errored`).
///   5. the connection's read buffer is fully drained. Unlike the client
///      leg, there is no pipelining on the backend leg — this proxy sends
///      one request per checkout and waits for its response before sending
///      another. So any leftover bytes here are not a next message to
///      preserve; pooling them forward would hand the next checkout's
///      `read_head` a mix of stale and fresh bytes, the same class of
///      connection-desync bug Level 1 closed on the client side.
///
/// Conditions 2 and 3 arrive as plain bools, not the response head itself —
/// see the caller in `serve_one` for why they must be captured immediately
/// after the head is parsed, before any later rewriting for the client leg.
fn is_poolable(
    resp_framing: BodyFraming,
    backend_sent_close: bool,
    backend_is_http11: bool,
    exchange_errored: bool,
    buffer_empty: bool,
) -> bool {
    if resp_framing == BodyFraming::UntilClose {
        return false;
    }
    if backend_sent_close {
        return false;
    }
    if !backend_is_http11 {
        return false;
    }
    if exchange_errored {
        return false;
    }
    buffer_empty
}

/// Serve one client connection: a sequence of request/response exchanges
/// on the same socket (keep-alive), each routed to a backend by `routes`.
///
/// `backend_timeout` is a connection-level tunable (the `--backend-timeout`
/// CLI value), passed alongside `routes` because — like the route table — it
/// is fixed for the life of the process, not per request. It rides down into
/// every `serve_one` on this connection.
/// `scheme` is what the *client* spoke to reach us — `"http"` on the plaintext
/// listener, `"https"` once Level 8 has terminated TLS. It exists because after
/// termination the backend receives plain HTTP and has no other way to learn
/// that the original hop was encrypted; it rides down into `X-Forwarded-Proto`.
///
/// Generic over `S` rather than concrete over `TcpStream` so the same code path
/// serves both listeners: `S` is `TcpStream` for plaintext and
/// `tokio_rustls::server::TlsStream<TcpStream>` for TLS. `Conn<S>` was already
/// generic (Level 1); these two signatures were the only things pinning the
/// concrete type. Generics rather than an `enum Stream { Plain, Tls }` because
/// this is the hottest loop in the program and an enum would cost a match on
/// every single read and write; the price is two monomorphized copies in the
/// binary, which is the right trade for a proxy.
pub async fn handle_client<S: AsyncRead + AsyncWrite + Unpin>(
    client: S,
    routes: &RouteTable,
    peer: std::net::SocketAddr,
    backend_timeout: Duration,
    scheme: &'static str,
    limits: crate::security::Limits,
) {
    // NOTE: `set_nodelay` used to live here, but it is a `TcpStream` inherent
    // method and this function no longer knows it has one. It moved to the
    // accept loop in `main.rs`, applied to the raw socket *before* any TLS
    // wrap — which is also the only place it can go, since the TLS stream owns
    // the `TcpStream` afterwards.
    let mut client = Conn::new(client);

    loop {
        match serve_one(&mut client, routes, peer, backend_timeout, scheme, limits).await {
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
async fn serve_one<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut Conn<S>,
    routes: &RouteTable,
    peer: std::net::SocketAddr,
    backend_timeout: Duration,
    scheme: &'static str,
    limits: crate::security::Limits,
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

    // ---- 1a. Level 8: header-count cap -> 431 ----
    // Level 1's MAX_HEAD_BYTES already bounds total head *size* at 16 KB, but
    // not field *count*: ~8,000 one-byte header lines fit inside that budget,
    // and every one of them multiplies the linear header scans this proxy does
    // per request (routing, hop-by-hop stripping, rewriting, framing, the
    // middleware chain). 431 is the status RFC 6585 defines for exactly this,
    // and it is checked before routing so the work is refused before it starts.
    if req.headers.len() > limits.max_headers {
        println!(
            "[{peer}] {} {} -> 431 ({} headers, limit {})",
            req.method,
            req.target,
            req.headers.len(),
            limits.max_headers
        );
        respond_error(client, 431, "Request Header Fields Too Large").await?;
        return Ok(false);
    }

    let req_framing = match http::request_body_framing(&req) {
        Ok(f) => f,
        Err(e) => {
            let _ = respond_error(client, 400, "Bad Request").await;
            return Err(e);
        }
    };

    // ---- 1b. Level 8: declared-body-size cap -> 413 ----
    // A Content-Length body announces its size before a single byte of it
    // arrives, so this is the one case where the limit can be enforced with
    // *zero* cost to anyone: no body read, no backend connection, no backend
    // load at all. Chunked bodies cannot be checked here (no declared size) and
    // are enforced mid-stream in `copy_body_limited` instead.
    //
    // Deliberately placed BEFORE routing and the middleware chain: an oversized
    // request should not consume a rate-limit token or run an auth comparison,
    // and it certainly should not open a backend socket.
    if let BodyFraming::Length(n) = req_framing {
        if n > limits.max_body {
            println!(
                "[{peer}] {} {} -> 413 (body {n} bytes, limit {})",
                req.method, req.target, limits.max_body
            );
            // No drain: the point is that we never read those bytes. Sending
            // `Connection: close` (which respond_error does) is what makes that
            // safe — the unread body cannot desync a connection we are closing,
            // and Level 6's drain-before-reuse rule only binds when we intend to
            // reuse.
            respond_error(client, 413, "Payload Too Large").await?;
            return Ok(false);
        }
    }

    let client_keep_alive = http::wants_keep_alive(req.version, &req.headers);
    let method = req.method.clone();

    // ---- 2. Route: pick the ROUTE (not just its pool) from method + host +
    // path. Level 5 needs the whole route to reach `route.rules`; we bind
    // `upstream` from it to keep the balancing code below unchanged.
    let host = http::header(&req.headers, "host").map(http::host_without_port);
    let path = http::target_path(&req.target);
    let route = match routes.find_route(&method, host, path) {
        Some(r) => r,
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
    let upstream = &route.upstream;

    // Capture the client's original request target, version, and Host BEFORE
    // any rewriting. The original target feeds the "rewrite:" log line below,
    // and `original_host` is what makes `X-Forwarded-Host` report what the
    // client actually asked for even when a `host=` rule clobbers the Host
    // header. `original_version` exists purely so the balancer "pick" log lines
    // keep printing the client's own version: the rewrite now runs BEFORE the
    // pick loop (so the head is serialized exactly once), and it force-sets
    // `req.version = Http11` — so reading `req.version` live in the loop would
    // report Http11 even for an HTTP/1.0 client, changing today's log output.
    // `Version` is `Copy`, so this is a trivial snapshot.
    let original_target = req.target.clone();
    let original_version = req.version;
    let original_host = http::header(&req.headers, "host").map(str::to_string);

    // ---- 2a. Middleware pipeline (Level 6) ----
    // Runs AFTER routing (the chain is per-route, so we must know the route
    // first) and BEFORE the balancer lease below (a rejected request must never
    // open a backend socket or feed the breaker — that is the whole value of
    // short-circuiting). The context carries the ORIGINAL method/target/host so
    // the response-phase log reports what the client asked for, not the
    // Level-5-rewritten values.
    let mut ctx = crate::middleware::ReqCtx::new(
        peer,
        method.clone(),
        original_target.clone(),
        original_host.clone(),
    );
    if let Err((entered, rej)) = route.chain.run_request(&mut req, &mut ctx) {
        // Drain the request body so closing (or keeping) the connection is safe
        // — see Conn::drain_body for the TCP-RST reasoning. Within the cap the
        // connection stays reusable; beyond it we must close.
        let reusable = match client.drain_body(req_framing, REJECT_DRAIN_CAP).await {
            Ok(r) => r,
            // If draining errors the connection is unusable; still try to send
            // the rejection, then close.
            Err(_) => false,
        };
        // Build the rejection response and run the response phase in reverse for
        // exactly the layers that were entered (indices [0, entered)). The
        // rejecting layer produced this response and doesn't post-process its
        // own output; layers after it never ran. So a 401 still gets its
        // X-Request-Id and its access-log line.
        let mut resp = ResponseHead {
            version: Version::Http11,
            status: rej.status,
            reason: rej.reason.to_string(),
            headers: rej.headers.clone(),
        };
        route.chain.run_response(&ctx, &mut resp, entered);
        send_rejection(client, &resp, &rej.body, reusable && client_keep_alive).await?;
        return Ok(reusable && client_keep_alive);
    }

    // ---- 2c. Serialize the forwarded request head ONCE, before any connection
    // attempt. This ordering is the whole point of this function's shape:
    // `route.rules.apply_request` (Level 5's rewrite) mutates `req` in place and
    // is NOT idempotent — it APPENDS to `X-Forwarded-For`, sets `Connection`,
    // etc., so running it twice would double-append forwarded headers. But
    // `http::write_request_head(&req)` is a pure serialization of the
    // already-rewritten head. Doing the rewrite here, exactly once, lets the
    // acquire+write loop below re-attempt the *write* of these identical bytes
    // on a fresh connection (when a pooled connection turns out dead) WITHOUT
    // ever re-running the rewrite. Serialize once; retry only the write.
    strip_hop_by_hop(&mut req.headers);
    // Level 5: forwarded headers + path/Host/header rewriting. This must run
    // AFTER hop-by-hop stripping (so a client cannot smuggle in a
    // Connection-listed header that a rule then re-adds) and BEFORE the
    // framing re-declaration below (so no rule can displace the framing
    // headers this proxy owns).
    let fwd_ctx = crate::rewrite::ForwardContext {
        client_ip: peer.ip(),
        original_host: original_host.as_deref(),
        // Level 8: this was hardcoded `"http"` with a comment naming this level
        // as the one that would fill it in. It now reports what the client
        // actually spoke on *this* listener. Note it is the listener's scheme,
        // never a client-supplied hint — the same stance Level 5 took when it
        // chose to overwrite `X-Real-IP` rather than trust it, and Level 6 took
        // when it keyed the rate limiter on the socket peer instead of XFF. A
        // backend making an authorization decision on `X-Forwarded-Proto`
        // (redirect-to-HTTPS logic, secure-cookie gating) must be reading an
        // observation, not an assertion.
        scheme,
    };
    route.rules.apply_request(&mut req, &fwd_ctx);
    // Diagnostics for the rewrite, emitted right where the rewrite happens.
    // (These moved up with the rewrite block; the pick log lines below now read
    // the captured pre-rewrite originals instead of the live, rewritten `req`.)
    if req.target != original_target {
        println!("[{peer}]   rewrite: {original_target} -> {}", req.target);
    }
    if let (Some(before), Some(after)) =
        (original_host.as_deref(), http::header(&req.headers, "host"))
    {
        if before != after {
            println!("[{peer}]   host: {before} -> {after}");
        }
    }
    // Take exclusive control of the body-framing header. strip_hop_by_hop
    // removes the "TE" header but NOT "Transfer-Encoding"; if we re-added a
    // chunked TE below without removing the original, the backend would see
    // two Transfer-Encoding lines — a smuggling desync. Content-Length is
    // left untouched: the parser already guaranteed at most one, and for
    // Length framing it carries the backend's only body delimiter.
    http::remove_header(&mut req.headers, "transfer-encoding");
    req.version = Version::Http11;
    // Level 7: ask the backend to keep the connection open so it becomes a
    // candidate for pooling. This does not by itself decide whether we
    // actually pool it afterward — is_poolable still checks the backend's
    // OWN Connection header on the response, since a backend is free to
    // ignore our keep-alive request and close anyway (that's condition 2 of
    // the poolability check).
    req.headers.push(("Connection".to_string(), "keep-alive".to_string()));
    if req_framing == BodyFraming::Chunked {
        req.headers.push(("Transfer-Encoding".to_string(), "chunked".to_string()));
    }
    // The single serialization. These exact bytes are what the loop below
    // (re)writes on each connection attempt.
    let head_bytes = http::write_request_head(&req);

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
    let (mut lease, mut backend, _from_pool) = loop {
        let mut lease = match upstream.pick(peer.ip()) {
            Some(l) => l,
            None => {
                eprintln!(
                    "[{peer}] no healthy server in upstream {:?}",
                    upstream.name()
                );
                respond_error(client, 502, "Bad Gateway").await?;
                return Ok(false);
            }
        };
        let addr = lease.addr().to_string();

        // Acquire a backend connection for this attempt: a pooled one first
        // (Level 7's "0 RTT setup" path — a hit skips TcpStream::connect and
        // its timeout entirely), else dial fresh. Either way we leave this
        // block holding a `Conn` we have NOT yet written to. The pick log
        // lines read the pre-rewrite originals (`original_target`,
        // `original_version`) rather than the live `req`: the rewrite ran once
        // above the loop and force-set `req.version = Http11`, so reading it
        // here would change today's log output for an HTTP/1.0 client.
        let (mut conn, from_pool) = if let Some(conn) = lease.take_conn() {
            println!(
                "[{peer}] {} {} {} -> {}[{}] {addr} (inflight={}) [pooled]",
                req.method,
                original_target,
                original_version.as_str(),
                upstream.name(),
                upstream.algorithm().tag(),
                lease.inflight(),
            );
            (conn, true)
        } else {
            println!(
                "[{peer}] {} {} {} -> {}[{}] {addr} (inflight={}){}",
                req.method,
                original_target,
                original_version.as_str(),
                upstream.name(),
                upstream.algorithm().tag(),
                lease.inflight(),
                if attempt > 0 { format!(" [retry {attempt}/{MAX_RETRIES}]") } else { String::new() },
            );

            match tokio::time::timeout(BACKEND_CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    (Conn::new(s), false)
                }
                Ok(Err(e)) => {
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

        // Write the pre-serialized request head, and treat a failure here
        // EXACTLY like a failed connect: indict the server, drop the lease, and
        // retry on a different server when the method is idempotent and
        // attempts remain (the same two conditions the connect arms check). This
        // arm exists because `take_conn()` can hand back a pooled connection the
        // backend silently closed during its idle window — a classic
        // time-of-check/time-of-use race. The socket looked alive at checkout,
        // but the very first write discovers it is dead; a fresh-connect miss
        // can never reach this, only a pool hit can. Retry is SAFE here, and
        // ONLY here, because not one request byte has reached any backend yet:
        // `head_bytes` is the identical pre-serialized head (the non-idempotent
        // rewrite already ran once, above the loop, so replaying does not
        // double-append X-Forwarded-For), and the body has not begun streaming.
        // The moment we leave this loop and start `copy_body_to` below, a
        // failure is no longer replayable — part of a possibly non-idempotent
        // request is already committed to a backend — so those failures feed the
        // breaker and surface to the client instead of retrying.
        match conn.write_all(&head_bytes).await {
            Ok(()) => break (lease, conn, from_pool),
            Err(e) => {
                lease.mark_failure();
                eprintln!("[{peer}] backend {addr} write failed: {e}");
                drop(lease);
                if retryable && attempt < MAX_RETRIES {
                    attempt += 1;
                    continue;
                }
                respond_error(client, 502, "Bad Gateway").await?;
                return Ok(false);
            }
        }
    };
    // The exchange is now underway; a completed exchange should feed the
    // server's response-time average, so arm the lease's RTT recording.
    lease.mark_served();
    // Record the chosen pool and server so the access-log middleware (which
    // runs in the response phase, after the body streams) can report where the
    // request actually went.
    ctx.upstream = Some(upstream.name().to_string());
    ctx.backend = Some(lease.addr().to_string());
    // Pessimistic default: the request head is already out (the acquire+write
    // loop above sent it), and from here to the point where we hold a valid
    // response head there are several `?` early-returns (stream body, flush,
    // read head, "closed before responding", parse head, framing). Each of
    // those is a *real observed I/O failure* on a request we already committed
    // to this backend, so each must indict it — but
    // wiring mark_failure() into every one of those sites is easy to get wrong
    // and easy for a future edit to skip. Instead we default the outcome to
    // failure right here and let the mark_success() below upgrade it once a `<500` response
    // head is actually in hand. Any `?` that fires in between therefore scores a
    // failure automatically, without touching a single call site. This is safe
    // because it only runs *after* the request was sent: cancellation before
    // this point leaves the lease unmarked (correctly neutral), and these `?`
    // paths are exactly the "response-read error / mid-response I/O error"
    // failures the health-check spec says to feed the breaker. Note this does
    // not affect retries: the retry loop lives entirely above mark_served(), so
    // a failure recorded here can never trigger a replay.
    lease.mark_failure();

    // ---- 4. Forward the request body, then flush ----
    // The request head was rewritten, serialized, and written inside the
    // acquire+write loop above (that is what lets a dead-pooled-connection
    // write failure retry on a fresh server). Only the body remains. Unlike the
    // head-write, a failure here is NOT retried: once any request-body byte
    // reaches a backend, part of a possibly non-idempotent request is committed,
    // so a `?` from here on feeds the breaker (via the pessimistic
    // mark_failure() above) and surfaces to the client rather than replaying.
    //
    // Level 8: the body cap rides along here. For `Length` framing this is
    // already decided (an over-cap request was refused with 413 before we ever
    // routed it), so in practice the cap only bites on `Chunked` — where no
    // declared size exists and mid-stream is the only place enforcement is
    // possible.
    match client
        .copy_body_limited(&mut backend.stream_mut(), req_framing, Some(limits.max_body))
        .await?
    {
        BodyCopy::Done { .. } => {}
        BodyCopy::TooLarge => {
            // A chunked body that outgrew the cap after we had already forwarded
            // part of it. Both connections are now unsalvageable: the backend is
            // mid-body waiting for chunks it will never get, and the client is
            // still sending them. There is no version of this where either
            // socket can be reused, so we send a final 413 (respond_error sets
            // `Connection: close`) and return `false` to close the client leg.
            // `backend` drops here; the pessimistic `mark_failure()` above stays
            // in force, which is correct — from the backend's point of view this
            // exchange really did fail, and it never sees a poolable connection.
            println!(
                "[{peer}] {} {} -> 413 (chunked body exceeded {} bytes mid-stream)",
                method, original_target, limits.max_body
            );
            respond_error(client, 413, "Payload Too Large").await?;
            return Ok(false);
        }
    }
    backend.flush().await?;

    // ---- 5. Read the backend's response head, with a deadline ----
    let resp_bytes = match tokio::time::timeout(backend_timeout, backend.read_head()).await {
        Err(_) => {
            // Hung backend: the connect succeeded and the request was sent,
            // so this is exactly as real a failure as a refused connect —
            // indict the server the same way.
            lease.mark_failure();
            eprintln!("[{peer}] backend {} response timed out", lease.addr());
            respond_error(client, 504, "Gateway Timeout").await?;
            return Ok(false);
        }
        Ok(Ok(None)) => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "backend closed before responding",
            ));
        }
        Ok(Ok(Some(bytes))) => bytes,
        Ok(Err(e)) => return Err(e),
    };
    let mut resp = http::parse_response_head(&resp_bytes)?;
    let resp_framing = http::response_body_framing(&method, &resp)?;
    // Level 7: capture the backend's ORIGINAL Connection header and version
    // right now. Later in this function, resp.headers goes through
    // strip_hop_by_hop (which strips Connection) and the client-leg framing
    // block pushes a NEW Connection header describing what WE told the
    // client — and resp.version gets force-set to Http11 for the client leg
    // regardless of what the backend spoke. By the time this function
    // reaches the poolability check, both fields describe the client leg,
    // not the backend's original response — so both must be read here, now,
    // or the poolability check would silently answer a different question.
    let backend_sent_close = http::header(&resp.headers, "connection")
        .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
        .unwrap_or(false);
    let backend_is_http11 = resp.version == Version::Http11;

    // (The per-request status line is now emitted by the access-log middleware
    // in the response phase below, so the old `-> {status}` println is gone.)

    // Passive health check: 5xx indicts the backend, anything below it does
    // not (a 404 means the backend is healthy and the path is wrong).
    if resp.status >= 500 {
        lease.mark_failure();
    } else {
        lease.mark_success();
    }

    // ---- 6. Relay the response: rewritten head, then streamed body ----
    // Level 6 response phase, in REVERSE chain order, for every layer (the
    // request was not rejected, so all were entered). Runs BEFORE Level 5's
    // apply_response so an operator's explicit `set-resp-header` stays the final
    // word over a middleware-injected header (X-Request-Id), matching Level 5's
    // "explicit rules run last" principle — and both stay before the framing
    // block below, so no header rule can displace the framing the proxy owns.
    route.chain.run_response_all(&ctx, &mut resp);
    strip_hop_by_hop(&mut resp.headers);
    // Level 5 response rewriting (explicit set-/remove-resp-header rules).
    // Placed after hop-by-hop stripping for the same reason as the request
    // leg, and before the framing block so a rule cannot displace the
    // Connection/Transfer-Encoding headers this proxy owns on the client leg.
    route.rules.apply_response(&mut resp);
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

    // Level 7: decide whether this backend connection can be reused. The
    // exchange already fully completed by this point (both bodies streamed,
    // both flushes succeeded) — an error anywhere above already returned via
    // `?` and never reaches this line, so `exchange_errored` is always
    // `false` here structurally, not by a separate flag. This is what makes
    // the knowledge base's "a connection that just errored doesn't go back
    // to the pool" rule true by construction: only the success path reaches
    // `is_poolable` at all.
    if is_poolable(
        resp_framing,
        backend_sent_close,
        backend_is_http11,
        false, // see comment above: reaching this line means no error occurred
        backend.buffer_is_empty(),
    ) {
        lease.return_conn(backend);
    }
    // else: `backend` is dropped here, closing the socket — today's behavior.

    Ok(client_still_usable)
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    /// Escape hatch for copy loops that need the raw stream as a write
    /// target while another Conn drives the reads.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

/// Send a middleware rejection: the response head (already carrying the
/// middleware's headers and any response-phase annotations like X-Request-Id),
/// plus the proxy-managed framing headers, then the body. `keep_alive` decides
/// the `Connection` header — false when the body couldn't be fully drained.
async fn send_rejection<S>(
    client: &mut Conn<S>,
    resp: &ResponseHead,
    body: &str,
    keep_alive: bool,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Start from the middleware-supplied headers, then take exclusive control
    // of the framing headers the proxy owns (same discipline as the forward
    // path): drop any middleware-supplied framing, then set our own.
    let mut headers = resp.headers.clone();
    http::remove_header(&mut headers, "content-length");
    http::remove_header(&mut headers, "transfer-encoding");
    http::remove_header(&mut headers, "connection");
    headers.push(("Content-Type".to_string(), "text/plain".to_string()));
    headers.push(("Content-Length".to_string(), body.len().to_string()));
    headers.push((
        "Connection".to_string(),
        if keep_alive { "keep-alive" } else { "close" }.to_string(),
    ));
    let head = ResponseHead {
        version: Version::Http11,
        status: resp.status,
        reason: resp.reason.clone(),
        headers,
    };
    client.write_all(&http::write_response_head(&head)).await?;
    client.write_all(body.as_bytes()).await?;
    client.flush().await
}

/// Minimal error response, generated by the proxy itself.
async fn respond_error<S>(client: &mut Conn<S>, status: u16, reason: &str) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    respond_error_with(client, status, reason, &[]).await
}

/// Like `respond_error` but carries extra headers. Middleware rejections need
/// this: a 401 must send `WWW-Authenticate`, a 429 `Retry-After`, and every
/// rejection still gets its `X-Request-Id` from the response-phase pass.
async fn respond_error_with<S>(
    client: &mut Conn<S>,
    status: u16,
    reason: &str,
    extra_headers: &[(String, String)],
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let body = format!("{status} {reason}\n");
    let mut headers = vec![
        ("Content-Type".to_string(), "text/plain".to_string()),
        ("Content-Length".to_string(), body.len().to_string()),
        ("Connection".to_string(), "close".to_string()),
    ];
    headers.extend_from_slice(extra_headers);
    let head = ResponseHead {
        version: Version::Http11,
        status,
        reason: reason.to_string(),
        headers,
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

    // ---- Level 8: body size caps ----

    /// A declared Content-Length over the cap is refused without reading the
    /// body. Cheapest possible enforcement: the bytes never move.
    #[tokio::test]
    async fn length_body_over_cap_is_refused_without_copying() {
        let mut conn = conn_with(b"0123456789").await;
        let mut out = Vec::new();
        let r = conn
            .copy_body_limited(&mut out, BodyFraming::Length(10), Some(4))
            .await
            .unwrap();
        assert_eq!(r, BodyCopy::TooLarge);
        assert!(out.is_empty(), "no body byte may be forwarded when over cap");
    }

    #[tokio::test]
    async fn length_body_at_the_cap_is_allowed() {
        let mut conn = conn_with(b"01234").await;
        let mut out = Vec::new();
        // Exactly at the limit must pass — the check is `>`, not `>=`. An
        // off-by-one here would reject a request of precisely the documented
        // maximum size.
        let r = conn
            .copy_body_limited(&mut out, BodyFraming::Length(5), Some(5))
            .await
            .unwrap();
        assert_eq!(r, BodyCopy::Done { reusable: true });
        assert_eq!(out, b"01234");
    }

    /// Chunked has no declared size, so the cap can only be enforced mid-stream.
    /// The cumulative decoded total is what counts, not any single chunk.
    #[tokio::test]
    async fn chunked_body_over_cap_stops_mid_stream() {
        // Three 4-byte chunks = 12 decoded bytes, cap of 10.
        let body = b"4\r\naaaa\r\n4\r\nbbbb\r\n4\r\ncccc\r\n0\r\n\r\n";
        let mut conn = conn_with(body).await;
        let mut out = Vec::new();
        let r = conn
            .copy_body_limited(&mut out, BodyFraming::Chunked, Some(10))
            .await
            .unwrap();
        assert_eq!(r, BodyCopy::TooLarge);
        // The first two chunks (8 bytes) were under the cap and did go through;
        // the third would have crossed it and must not have been started. This
        // is the documented, unavoidable consequence of chunked framing — and
        // the reason TooLarge forces both connections closed.
        let sent = String::from_utf8_lossy(&out);
        assert!(sent.contains("aaaa") && sent.contains("bbbb"), "got {sent:?}");
        assert!(!sent.contains("cccc"), "chunk crossing the cap leaked: {sent:?}");
    }

    /// A single chunk larger than the entire cap must be caught before its
    /// header is forwarded, not after its bytes are.
    #[tokio::test]
    async fn single_oversized_chunk_is_caught_before_its_header() {
        let body = b"20\r\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n0\r\n\r\n";
        let mut conn = conn_with(body).await;
        let mut out = Vec::new();
        let r = conn
            .copy_body_limited(&mut out, BodyFraming::Chunked, Some(10))
            .await
            .unwrap();
        assert_eq!(r, BodyCopy::TooLarge);
        assert!(out.is_empty(), "oversized chunk emitted framing: {out:?}");
    }

    #[tokio::test]
    async fn chunked_body_under_cap_passes_through_whole() {
        let body = b"4\r\naaaa\r\n4\r\nbbbb\r\n0\r\n\r\n";
        let mut conn = conn_with(body).await;
        let mut out = Vec::new();
        let r = conn
            .copy_body_limited(&mut out, BodyFraming::Chunked, Some(1024))
            .await
            .unwrap();
        assert_eq!(r, BodyCopy::Done { reusable: true });
        assert_eq!(String::from_utf8_lossy(&out), "4\r\naaaa\r\n4\r\nbbbb\r\n0\r\n\r\n");
    }

    /// `None` means uncapped, which is what the response leg passes. A large
    /// body must not be affected by the request-side limit.
    #[tokio::test]
    async fn no_cap_allows_any_size() {
        // 32 KiB: two full BUF_SIZE windows, so the multi-window path is
        // exercised, while still fitting inside `conn_with`'s 64 KiB duplex
        // buffer. A larger body would deadlock the *test*, not the proxy —
        // `conn_with` writes everything before returning a reader, so anything
        // over the pipe's capacity blocks with nobody draining it.
        let big = vec![b'x'; 32 * 1024];
        let mut conn = conn_with(&big).await;
        let mut out = Vec::new();
        let r = conn
            .copy_body_limited(&mut out, BodyFraming::Length(big.len() as u64), None)
            .await
            .unwrap();
        assert_eq!(r, BodyCopy::Done { reusable: true });
        assert_eq!(out.len(), big.len());
    }

    /// A zero-length body is not "over" a zero cap, and `None` framing must not
    /// consult the cap at all.
    #[tokio::test]
    async fn empty_body_passes_any_cap() {
        let mut conn = conn_with(b"").await;
        let mut out = Vec::new();
        let r = conn
            .copy_body_limited(&mut out, BodyFraming::None, Some(0))
            .await
            .unwrap();
        assert_eq!(r, BodyCopy::Done { reusable: true });
    }

    #[tokio::test]
    async fn read_head_can_be_timed_out() {
        // A duplex pipe whose write side never sends the terminating CRLF CRLF
        // stands in for a backend that accepted the connection but never
        // responds — read_head blocks forever without a timeout wrapper.
        let (_tx, rx) = duplex(64);
        let mut conn = Conn::new(rx);
        let result = tokio::time::timeout(Duration::from_millis(50), conn.read_head()).await;
        assert!(result.is_err(), "read_head must not resolve before data arrives");
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
    async fn drain_length_body_within_cap_keeps_alive() {
        let mut conn = conn_with(b"hello").await; // 5 bytes
        let usable = conn.drain_body(BodyFraming::Length(5), 64 * 1024).await.unwrap();
        assert!(usable);
    }

    #[tokio::test]
    async fn drain_oversized_length_signals_close() {
        // A 100 KB body against a 1 KB cap: we don't read it, we signal close.
        let mut conn = conn_with(&vec![b'x'; 1024]).await;
        let usable = conn.drain_body(BodyFraming::Length(100 * 1024), 1024).await.unwrap();
        assert!(!usable);
    }

    #[tokio::test]
    async fn drain_then_next_request_parses() {
        // A rejected POST body followed by a pipelined GET: after draining the
        // body, the next request head must still parse cleanly.
        let mut conn = conn_with(b"helloGET /next HTTP/1.1\r\n\r\n").await;
        let usable = conn.drain_body(BodyFraming::Length(5), 64 * 1024).await.unwrap();
        assert!(usable);
        let head = conn.read_head().await.unwrap().unwrap();
        assert!(head.starts_with(b"GET /next"));
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

    // ---- Level 7: poolability predicate ----

    #[test]
    fn poolable_when_all_five_conditions_hold() {
        assert!(is_poolable(BodyFraming::Length(5), false, true, false, true));
    }

    #[test]
    fn not_poolable_on_until_close_framing() {
        assert!(!is_poolable(BodyFraming::UntilClose, false, true, false, true));
    }

    #[test]
    fn not_poolable_when_backend_sent_connection_close() {
        assert!(!is_poolable(BodyFraming::Length(5), true, true, false, true));
    }

    #[test]
    fn not_poolable_on_http10_backend() {
        assert!(!is_poolable(BodyFraming::Length(5), false, false, false, true));
    }

    #[test]
    fn not_poolable_when_exchange_errored() {
        assert!(!is_poolable(BodyFraming::Length(5), false, true, true, true));
    }

    #[test]
    fn not_poolable_when_buffer_not_empty() {
        assert!(!is_poolable(BodyFraming::Length(5), false, true, false, false));
    }

    #[tokio::test]
    async fn conn_buffer_is_empty_true_when_fully_consumed() {
        let mut conn = conn_with(b"GET / HTTP/1.1\r\n\r\n").await;
        let _ = conn.read_head().await.unwrap();
        assert!(conn.buffer_is_empty());
    }

    #[tokio::test]
    async fn conn_buffer_is_empty_false_with_leftover_bytes() {
        // A pipelined second request's bytes are still buffered after the
        // first head is read — buffer_is_empty must report false.
        let mut conn = conn_with(b"GET / HTTP/1.1\r\n\r\nGET /next HTTP/1.1\r\n\r\n").await;
        let _ = conn.read_head().await.unwrap();
        assert!(!conn.buffer_is_empty());
    }
}
