# Level 7 — Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reuse backend TCP connections across requests instead of closing one after every exchange, and close two real timeout gaps (no deadline on reading the backend's response head; no idle bound on a pooled connection).

**Architecture:** A bounded LIFO stack of idle `Conn<TcpStream>` lives on each `Server` (one pool per backend, not per-upstream or global), guarded by a `std::sync::Mutex` with no `.await` in its critical section. Checkout/return are two new methods on the existing `Lease` RAII type. A connection is only ever returned to the pool if a five-condition poolability check passes; anything else is dropped, matching today's behavior.

**Tech Stack:** Rust 2024, Tokio (already a dep). No new dependencies.

## Global Constraints

- **No new dependencies.** The crate stays at `tokio` + `regex`.
- **`std::sync::Mutex`, not `tokio::sync::Mutex`**, for the pool's lock — the critical section (`Vec::push`/`pop`) never awaits. (Spec: "Lifecycle and bounds".)
- **No background sweeper/reaper task.** Idle-timeout eviction is lazy, checked only on `take_conn`. (Spec: "Idle timeout — lazy, no sweeper".)
- **Pool is per-`Server`**, not per-`Upstream`, not global. (Spec: "Where the pool lives".)
- **Global CLI flags only** for the three new tunables (`--pool-max-idle`, `--pool-idle-timeout`, `--backend-timeout`); no per-route or per-upstream override. (Spec: "Non-goals".)
- **All 152 existing tests must stay green** after every task. Target ~165 tests total.
- **`cargo build --release` must not add warnings** beyond the existing 4-warning baseline.
- **Heavy in-code teaching comments** — "I implement, you learn" mode, matching the density in `balancer.rs`/`proxy.rs`.
- **Do NOT commit.** Leave all changes in the working tree; Vishwa commits himself (signed or unsigned, his call each time).

### Existing APIs this plan consumes (verified against source)

From `balancer.rs`:
- `pub struct HealthConfig { pub fail_threshold: usize, pub success_threshold: usize, pub backoff_base: Duration, pub backoff_max: Duration, pub interval: Duration, pub timeout: Duration, pub path: String }` with `impl Default`
- `fn Server::new(addr: String, health: Arc<HealthConfig>) -> Server` (private to the module — pool tests must live in `balancer.rs`'s own `#[cfg(test)] mod tests`, which already has a `pool(algo, servers)` helper and an `hc() -> Arc<HealthConfig>` helper)
- `pub fn Upstream::pick(&self, client_ip: IpAddr) -> Option<Lease<'_>>`
- `pub struct Lease<'a> { server: &'a Server, started: Instant, served: bool, outcome: Option<bool> }` with `pub fn addr(&self) -> &str`, `pub fn inflight(&self) -> usize`, `pub fn mark_served(&mut self)`, `pub fn mark_success(&mut self)`, `pub fn mark_failure(&mut self)`, and `impl Drop`
- `impl Server { pub fn addr(&self) -> &str; pub fn available(&self) -> bool; pub fn breaker(&self) -> &Breaker; fn inflight(&self) -> usize; fn record_rtt(&self, rtt: Duration) }`

From `proxy.rs`:
- `pub struct Conn<S> { stream: S, buf: Vec<u8>, filled: usize }` — **fields are private to `proxy.rs`**, so any buffer-empty check must live in `proxy.rs`, either as a new `Conn` method or a field read from within the module.
- `impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S>`: `pub fn new(stream: S) -> Self`, `pub async fn read_head(&mut self) -> io::Result<Option<Vec<u8>>>`, `pub async fn copy_body_to<W>(&mut self, dst: &mut W, framing: BodyFraming) -> io::Result<bool>`, `pub fn stream_mut(&mut self) -> &mut S`, `pub async fn write_all(&mut self, data: &[u8])`, `pub async fn flush(&mut self)`
- Test helper: `async fn conn_with(data: &[u8]) -> Conn<tokio::io::DuplexStream>` using `tokio::io::duplex(64 * 1024)`
- Constants: `const BUF_SIZE: usize = 16 * 1024`, `const HEAD_READ_TIMEOUT`, `const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5)`, `const MAX_RETRIES: usize = 2`
- `serve_one`'s exact current sequence (lines given are pre-plan line numbers, verified 2026-08-10):
  - Balance+connect retry loop at `proxy.rs:500-559`, breaking `(mut lease, backend): (Lease, TcpStream)` out of the loop on a successful connect.
  - `lease.mark_served()` then `ctx.upstream = ...; ctx.backend = ...;` then the pessimistic `lease.mark_failure()` default, then `backend.set_nodelay(true); let mut backend = Conn::new(backend);` — lines 560-586.
  - Request forwarding: `strip_hop_by_hop`, Level 5 rewrite, then **line 621: `req.headers.push(("Connection".to_string(), "close".to_string()));` — unconditional.** This must change for pooling to ever find a live connection (see Task 3).
  - `backend.write_all(...)`, `client.copy_body_to(&mut backend.stream_mut(), req_framing)`, `backend.flush()` — lines 627-629.
  - Response read: `backend.read_head()` **with no timeout** at line 632 — this is the gap Task 4 closes.
  - Passive health check (`resp.status >= 500` → `mark_failure` else `mark_success`) at lines 643-647.
  - Response relay through `route.chain.run_response_all`, `strip_hop_by_hop`, `route.rules.apply_response`, framing block computing `client_still_usable` — lines 649-690. **This existing four-check shape for the client leg (not-UntilClose, no close request, HTTP version, no error) is what the new backend-side poolability predicate in Task 3/5 mirrors** — but the backend-leg checks must read the backend's *own* `Connection`/version fields captured immediately after the response head is parsed, before this same block mutates `resp.headers`/`resp.version` for the client leg (see Task 5, Edit D).
  - `client.write_all(...)`, `backend.copy_body_to(client.stream_mut(), resp_framing)`, `client.flush()`, then **line 696: `// Backend conn drops here (Connection: close) — pooling is Level 7.`** — this comment is the seam Task 3/5 fill.

From `main.rs`:
- `fn next_val(args: &mut impl Iterator<Item = String>, flag: &str) -> io::Result<String>`
- `fn parse_duration(s: &str) -> io::Result<Duration>` (accepts `"2s"`, `"500ms"`, or a bare number as seconds)
- `fn bad_arg(msg: &str) -> io::Error`
- The `while let Some(arg) = args.next() { match arg.as_str() { ... } }` CLI parse loop, currently handling `--upstream`, `--hc-*`, `--no-forwarded`, `--no-request-id`, `--no-access-log`.

---

## File Structure

```
rproxy/src/
  balancer.rs   Server gains `idle: Mutex<Vec<PooledConn>>`; new PooledConn
                struct; Lease gains take_conn/return_conn; POOL_MAX_IDLE /
                POOL_IDLE_TIMEOUT constants
  proxy.rs      poolability predicate (pure fn); Conn gains a buffer-empty
                check; serve_one wires take_conn before connect, sends
                Connection: keep-alive to poolable-candidate backends,
                times the response-head read, calls return_conn at the end
  main.rs       --pool-max-idle / --pool-idle-timeout / --backend-timeout
                flags; threaded into a small config struct
```

No new files. `balancer.rs` (1516 lines) and `proxy.rs` (grew across Levels 5/6) both already hold structures this level extends directly — a new pool module would duplicate the `Server`/`Lease` relationship Level 3/4 already established.

---

## Task 1: `PooledConn` and the idle pool on `Server`

**Files:**
- Modify: `rproxy/src/balancer.rs`
- Test: in `balancer.rs`'s existing `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `Server` (existing, private fields `addr`/`inflight`/`ewma_us`/`breaker`), `crate::proxy::Conn` (already `pub`, so `balancer.rs` can `use crate::proxy::Conn;` with no visibility changes needed).
- Produces:
  - `pub const POOL_MAX_IDLE: usize = 4;`
  - `pub const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);`
  - `struct PooledConn { conn: crate::proxy::Conn<TcpStream>, idle_since: Instant }` (private to `balancer.rs`)
  - `Server` gains a private field `idle: Mutex<Vec<PooledConn>>`
  - `impl Server { fn take_conn(&self) -> Option<crate::proxy::Conn<TcpStream>>; fn return_conn(&self, conn: crate::proxy::Conn<TcpStream>); }` (private — `Lease` wraps these as the public API in Task 2)

`Server`'s pool stores `Conn<TcpStream>` concretely, matching production (only real backend sockets are ever pooled). Tests therefore need real `Conn<TcpStream>` values, not a `DuplexStream` stand-in (`Conn<DuplexStream>` is a different, incompatible monomorphization). Build them with a loopback listener bound once per test:

```rust
/// A real (but otherwise unused) TcpStream pair, so pool tests can construct
/// `Conn<TcpStream>` values matching Server's actual storage type without a
/// live backend on the other end. Bind an ephemeral port, connect to it, and
/// accept once.
async fn tcp_conn_pair() -> (crate::proxy::Conn<TcpStream>, TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = TcpStream::connect(addr);
    let (accepted, connected) = tokio::join!(
        async { listener.accept().await.unwrap().0 },
        async { connect.await.unwrap() }
    );
    (crate::proxy::Conn::new(connected), accepted)
}
```

The caller must keep the returned peer socket (`_peer` below) alive for the test's duration, or the OS resets the connection immediately.

- [ ] **Step 1: Write the failing tests**

Add to `balancer.rs`'s existing `#[cfg(test)] mod tests` (which already has `use super::*;`, `fn pool(...)`, `fn hc() -> Arc<HealthConfig>`, and `fn ip(...)`). Add `use tokio::net::TcpListener;` to the test module (the production `use tokio::net::TcpStream;` added in Step 3 is inherited via `use super::*;`):

```rust
    // ---- Level 7: connection pooling ----

    async fn tcp_conn_pair() -> (crate::proxy::Conn<TcpStream>, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = TcpStream::connect(addr);
        let (accepted, connected) = tokio::join!(
            async { listener.accept().await.unwrap().0 },
            async { connect.await.unwrap() }
        );
        (crate::proxy::Conn::new(connected), accepted)
    }

    #[tokio::test]
    async fn take_conn_on_empty_pool_returns_none() {
        let srv = Server::new("127.0.0.1:9000".to_string(), hc());
        assert!(srv.take_conn().is_none());
    }

    #[tokio::test]
    async fn return_then_take_round_trips() {
        let srv = Server::new("127.0.0.1:9000".to_string(), hc());
        let (conn, _peer) = tcp_conn_pair().await;
        srv.return_conn(conn);
        assert!(srv.take_conn().is_some());
        assert!(srv.take_conn().is_none(), "pool is empty after the one entry was taken");
    }

    #[tokio::test]
    async fn idle_timeout_discards_stale_then_returns_live() {
        let srv = Server::new("127.0.0.1:9000".to_string(), hc());
        let (fresh_conn, _p1) = tcp_conn_pair().await;
        let (stale_conn, _p2) = tcp_conn_pair().await;
        // Push fresh FIRST (bottom of the LIFO stack), stale SECOND (top) — so
        // take_conn's single pop-loop must walk past the stale entry on top
        // before it reaches the live one underneath, in the SAME call.
        srv.return_conn(fresh_conn);
        srv.return_conn(stale_conn);
        // Backdate the entry we just pushed (index 1, the stale one) by
        // mutating it directly through the lock — this test lives in the same
        // module as Server, so its private `idle` field is reachable.
        srv.idle.lock().unwrap()[1].idle_since = Instant::now() - Duration::from_secs(120);
        // take_conn pops the stale entry first, discards it (too old), and
        // continues the loop to the fresh entry underneath, returning it.
        assert!(srv.take_conn().is_some());
        // Both entries are now gone: the stale one was discarded in the loop,
        // the fresh one was returned. The pool is empty.
        assert!(srv.idle.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn return_past_cap_drops_new_keeps_existing_count() {
        let srv = Server::new("127.0.0.1:9000".to_string(), hc());
        let mut peers = Vec::new();
        for _ in 0..POOL_MAX_IDLE {
            let (conn, peer) = tcp_conn_pair().await;
            srv.return_conn(conn);
            peers.push(peer);
        }
        assert_eq!(srv.idle.lock().unwrap().len(), POOL_MAX_IDLE);
        let (extra_conn, _peer) = tcp_conn_pair().await;
        srv.return_conn(extra_conn);
        assert_eq!(
            srv.idle.lock().unwrap().len(),
            POOL_MAX_IDLE,
            "returning past the cap must not grow the pool"
        );
    }

    #[tokio::test]
    async fn take_conn_lifo_order() {
        let srv = Server::new("127.0.0.1:9000".to_string(), hc());
        let (conn_a, _pa) = tcp_conn_pair().await;
        let (conn_b, _pb) = tcp_conn_pair().await;
        srv.return_conn(conn_a);
        srv.return_conn(conn_b);
        // conn_b was returned LAST, so it must be taken FIRST.
        assert!(srv.take_conn().is_some());
        assert!(srv.take_conn().is_some());
        assert!(srv.take_conn().is_none(), "only two entries were ever in the pool");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rproxy && cargo test balancer::tests::take_conn_on_empty_pool_returns_none 2>&1 | tail -10`
Expected: compile error (`Server` has no field `idle`, no method `take_conn`).

- [ ] **Step 3: Write the minimal implementation**

At the top of `balancer.rs`, add:

```rust
use tokio::net::TcpStream;

/// How many idle backend connections one server's pool keeps at most. Bounds
/// worst-case memory: a pool doesn't grow to match peak historical
/// concurrency, it caps at a small constant per backend.
///
/// Unused until `Lease::return_conn` (Task 2) and the `serve_one` wiring
/// (Task 5) read it — allowed dead for now, same treatment `Upstream::from_spec`
/// already carries elsewhere in this file for a "defined now, wired in later"
/// item.
#[allow(dead_code)]
pub const POOL_MAX_IDLE: usize = 4;

/// How long an idle pooled connection is trusted to still be alive on the
/// backend's side before we discard it rather than risk using it. Checked
/// lazily on `take_conn` — no background sweeper task exists anywhere in
/// this codebase, and this pool doesn't start one either.
#[allow(dead_code)]
pub const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// One idle backend connection, plus when it went idle. Storing the whole
/// `Conn<TcpStream>` (not just the raw socket) means its already-allocated
/// read buffer comes along for free — reusing the connection reuses the
/// buffer, with no separate buffer-pool abstraction needed.
#[allow(dead_code)]
struct PooledConn {
    conn: crate::proxy::Conn<TcpStream>,
    idle_since: Instant,
}
```

Add the field to the existing `Server` struct definition and its `fn new` constructor:

```rust
pub struct Server {
    addr: String,
    inflight: AtomicUsize,
    ewma_us: AtomicU64,
    breaker: Breaker,
    /// Level 7: idle backend connections available for reuse. A plain
    /// `std::sync::Mutex`, not `tokio::sync::Mutex` — every critical section
    /// below is a `Vec::pop`/`push` with no `.await` inside, so an async
    /// mutex would buy a scheduler hop for nothing (the same reasoning
    /// Level 6's rate limiter used for its shard locks).
    #[allow(dead_code)]
    idle: Mutex<Vec<PooledConn>>,
}
```

```rust
impl Server {
    fn new(addr: String, health: Arc<HealthConfig>) -> Server {
        Server {
            addr,
            inflight: AtomicUsize::new(0),
            ewma_us: AtomicU64::new(0),
            breaker: Breaker::new(health),
            idle: Mutex::new(Vec::new()),
        }
    }

    // ... existing methods unchanged ...

    /// Take a live pooled connection, if one exists. Discards anything past
    /// `POOL_IDLE_TIMEOUT` along the way — a stale entry costs nothing until
    /// something actually tries to use it, so there's no reason to clean the
    /// pool proactively.
    ///
    /// Unused until `Lease::take_conn` (Task 2) wraps it — allowed dead until
    /// then, same as the items above.
    #[allow(dead_code)]
    fn take_conn(&self) -> Option<crate::proxy::Conn<TcpStream>> {
        let mut guard = self.idle.lock().unwrap();
        let now = Instant::now();
        while let Some(pc) = guard.pop() {
            if now.saturating_duration_since(pc.idle_since) < POOL_IDLE_TIMEOUT {
                return Some(pc.conn);
            }
            // else: stale, `pc` drops here (closes the socket), loop continues.
        }
        None
    }

    /// Return a connection whose exchange just finished successfully and was
    /// judged poolable (see proxy.rs's poolability predicate). Bounded: past
    /// `POOL_MAX_IDLE`, the NEW connection is dropped rather than evicting an
    /// existing one — there's no reason to prefer a fresh-idle connection
    /// over ones already resident.
    #[allow(dead_code)]
    fn return_conn(&self, conn: crate::proxy::Conn<TcpStream>) {
        let mut guard = self.idle.lock().unwrap();
        if guard.len() < POOL_MAX_IDLE {
            guard.push(PooledConn { conn, idle_since: Instant::now() });
        }
        // else: `conn` is dropped here (closes the socket) — pool stays capped.
    }
}
```

Every `#[allow(dead_code)]` above is temporary scaffolding, not a permanent annotation, but it survives Task 2 unchanged: `Lease::take_conn`/`return_conn` (Task 2) call these methods, but only from a `#[tokio::test]` — invisible to a `--release` build, which has no `#[cfg(test)]` code at all. So `Server::take_conn`/`return_conn` remain unreachable from any non-test path until Task 5 wires `Lease`'s wrappers into `serve_one`. Task 5's brief removes all of these allows at once, when the chain becomes genuinely live end to end.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test balancer:: 2>&1 | tail -20`
Expected: the 5 new tests pass (`take_conn_on_empty_pool_returns_none`, `return_then_take_round_trips`, `idle_timeout_discards_stale_then_returns_live`, `return_past_cap_drops_new_keeps_existing_count`, `take_conn_lifo_order`), plus all existing `balancer::` tests still green.

Run: `cd rproxy && cargo test 2>&1 | tail -3`
Expected: **157 passed** (152 existing + 5 new).

- [ ] **Step 5: Stop and report for review** (no commit — see Global Constraints)

---

## Task 2: `take_conn`/`return_conn` on `Lease`

**Files:**
- Modify: `rproxy/src/balancer.rs`
- Test: in `balancer.rs`'s existing `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `Server::take_conn`/`Server::return_conn` from Task 1 (private, same module — `Lease` already holds `server: &'a Server`).
- Produces:
  - `impl<'a> Lease<'a> { pub fn take_conn(&self) -> Option<crate::proxy::Conn<TcpStream>>; pub fn return_conn(&self, conn: crate::proxy::Conn<TcpStream>); }`

This task is a thin, one-line-body wrapper making Task 1's private `Server` methods reachable from `proxy.rs` (which only ever holds a `Lease`, never a bare `&Server`).

- [ ] **Step 1: Write the failing test**

```rust
    #[tokio::test]
    async fn lease_take_and_return_conn_delegates_to_server() {
        let up = pool(Algorithm::RoundRobin, &[("127.0.0.1:9000", 1)]);
        let lease = up.pick(ip(127, 0, 0, 1)).unwrap();
        assert!(lease.take_conn().is_none(), "fresh server has an empty pool");
        let (conn, _peer) = tcp_conn_pair().await;
        lease.return_conn(conn);
        assert!(lease.take_conn().is_some());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rproxy && cargo test balancer::tests::lease_take_and_return_conn_delegates_to_server 2>&1 | tail -10`
Expected: compile error (`Lease` has no method `take_conn`/`return_conn`).

- [ ] **Step 3: Write the minimal implementation**

Find `impl<'a> Lease<'a> { ... }` (already has `fn new`, `pub fn addr`, `pub fn inflight`, `pub fn mark_served`, `pub fn mark_success`, `pub fn mark_failure`) and add:

```rust
    /// Take a live pooled connection for this lease's server, if one exists.
    /// See `Server::take_conn` for the idle-timeout eviction this performs.
    ///
    /// Called only from this file's tests until Task 5 wires it into
    /// `serve_one` — invisible to a `--release` build, so still dead code
    /// from the compiler's perspective. Allowed dead for now, same as
    /// `Server::take_conn`/`return_conn`.
    #[allow(dead_code)]
    pub fn take_conn(&self) -> Option<crate::proxy::Conn<TcpStream>> {
        self.server.take_conn()
    }

    /// Return a connection whose exchange just finished successfully and was
    /// judged poolable by the caller (see `proxy.rs`'s poolability
    /// predicate — this method trusts the caller's judgement and performs no
    /// re-checking of its own).
    #[allow(dead_code)]
    pub fn return_conn(&self, conn: crate::proxy::Conn<TcpStream>) {
        self.server.return_conn(conn)
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test 2>&1 | tail -3`
Expected: **158 passed** (157 + 1 new).

Run: `cd rproxy && cargo build --release 2>&1 | grep -c warning`
Expected: still the pre-existing **4-warning baseline** — every Task 1/2 addition carries `#[allow(dead_code)]` until Task 5 makes the chain genuinely reachable from `serve_one`.

- [ ] **Step 5: Stop and report for review**

---

## Task 3: The poolability predicate and the buffer-empty check

**Files:**
- Modify: `rproxy/src/proxy.rs`
- Test: in `proxy.rs`'s existing `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `BodyFraming` (existing, already imported in `proxy.rs`).
- Produces:
  - `impl<S> Conn<S> { pub fn buffer_is_empty(&self) -> bool }` — reads the private `filled` field, so it must live in `proxy.rs`.
  - `fn is_poolable(resp_framing: BodyFraming, backend_sent_close: bool, backend_is_http11: bool, exchange_errored: bool, buffer_empty: bool) -> bool` — pure, no I/O, five independent conditions.

The predicate takes plain `bool`s for conditions 2 and 3 rather than the response head itself. This is deliberate: Task 5 (which calls `is_poolable` from `serve_one`) must capture "did the backend send `Connection: close`" and "did the backend speak HTTP/1.1" *before* `serve_one` rewrites `resp.headers`/`resp.version` for the client leg later in the function — by the time the poolability check runs, those fields describe the client leg, not the backend's original response. Taking `bool`s here makes "captured from what, and when" the caller's explicit responsibility at the call site, rather than something `is_poolable` could silently get wrong by reading a mutated struct.

- [ ] **Step 1: Write the failing tests**

Add to `proxy.rs`'s existing `#[cfg(test)] mod tests` (which already has `use super::*;`, `conn_with`, and `use tokio::io::duplex;`):

```rust
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd rproxy && cargo test proxy::tests::poolable 2>&1 | tail -10`
Run: `cd rproxy && cargo test proxy::tests::conn_buffer_is_empty 2>&1 | tail -10`
Expected: compile errors (`is_poolable`, `buffer_is_empty` not defined).

- [ ] **Step 3: Write the minimal implementation**

Add near `strip_hop_by_hop` (both are pure header/framing logic):

```rust
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
///
/// Called only from tests until Task 5 wires it into `serve_one` — allowed
/// dead for now, same treatment as the Task 1/2 pool items.
#[allow(dead_code)]
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
```

Add to `impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S>` (the same block that has `read_head`, `copy_body_to`, `write_all`, `flush`):

```rust
    /// Whether every byte read from the stream so far has been consumed —
    /// no pipelined-request or leftover body bytes are sitting in `buf`.
    /// Used only by the backend-leg poolability check: a non-empty buffer
    /// here means either backend misbehavior or a framing-accounting bug,
    /// and pooling it forward would leak those bytes into the next checkout.
    ///
    /// Called only from tests until Task 5 wires it into `serve_one` —
    /// allowed dead for now, same treatment as `is_poolable` above.
    #[allow(dead_code)]
    pub fn buffer_is_empty(&self) -> bool {
        self.filled == 0
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test 2>&1 | tail -3`
Expected: **166 passed** (158 + 8 new: 6 `is_poolable` cases + 2 `buffer_is_empty` cases).

Run: `cd rproxy && cargo build --release 2>&1 | grep -c warning`
Expected: still the pre-existing **4-warning baseline** — `is_poolable` and `buffer_is_empty` both carry `#[allow(dead_code)]` until Task 5 wires them into `serve_one`.

- [ ] **Step 5: Stop and report for review**

---

## Task 4: `BACKEND_RESPONSE_TIMEOUT` around the response-head read

**Files:**
- Modify: `rproxy/src/proxy.rs`
- Test: in `proxy.rs`'s existing `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `tokio::time::timeout` (already used elsewhere in this file for `HEAD_READ_TIMEOUT`/`BACKEND_CONNECT_TIMEOUT`), `Lease::mark_failure`.
- Produces: `const BACKEND_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);`; modifies `serve_one`'s response-head read (currently `proxy.rs:632-634`) to time out, mark the lease failed, and return a 504.

This task changes `serve_one`, an `async fn` that is not directly unit-testable in isolation (it takes a live `Conn<TcpStream>` and a `RouteTable`) — the existing test suite for `serve_one`-adjacent behavior lives at the `Conn` level (`reads_head_across_fragmented_input` etc.) and via live verification (Task 7), not via a mocked `serve_one` call. This task's correctness is verified by:
1. A focused unit test on the **timeout-wrapping pattern in isolation** (proving `tokio::time::timeout` around a slow `read_head()` behaves as expected — a regression guard for the exact code shape used in `serve_one`).
2. Live verification in Task 7 against a deliberately hanging backend.

- [ ] **Step 1: Write the failing test**

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

This test should actually **pass immediately** even before any production change — it tests `tokio::time::timeout`'s own behavior, which already works. Run it to confirm the harness and pattern are correct before wiring the same pattern into `serve_one`:

Run: `cd rproxy && cargo test proxy::tests::read_head_can_be_timed_out 2>&1 | tail -10`
Expected: **PASS** (this is a smoke test of the pattern, not a red-phase test of new production code — the actual behavior change is in `serve_one`, verified by Task 7's live check since `serve_one` isn't unit-callable with a fake hanging backend without a real listener).

- [ ] **Step 3: Write the implementation**

Add the constant next to the other timeout constants near the top of `proxy.rs`:

```rust
/// Deadline for the backend to deliver its response HEAD after we finished
/// sending the request. Protects against hung application code — until this
/// existed, a backend that accepted the connection and never responded
/// blocked that connection task forever with no client-visible error and no
/// breaker signal. This closes that gap: a hang now looks, to the breaker,
/// like a connect failure. Does NOT bound body-streaming time — that's
/// size-and-route-dependent and stays a documented gap (time-to-first-byte
/// only, matching the knowledge base's framing of this timeout).
const BACKEND_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
```

Change the response-head read (currently):

```rust
    // ---- 5. Read the backend's response head ----
    let resp_bytes = backend.read_head().await?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "backend closed before responding")
    })?;
```

to:

```rust
    // ---- 5. Read the backend's response head, with a deadline ----
    let resp_bytes = match tokio::time::timeout(BACKEND_RESPONSE_TIMEOUT, backend.read_head()).await {
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
```

Note this replaces the `?`-based one-liner with an explicit match because the timeout path needs its own client-facing response (504) and lease-failure call, which a bare `?` can't express — this mirrors the exact shape already used for `HEAD_READ_TIMEOUT` at the top of `serve_one` (lines 383-389) and `BACKEND_CONNECT_TIMEOUT` in the retry loop (lines 547-557).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test 2>&1 | tail -3`
Expected: **167 passed** (166 + 1 new). All prior tests, including the existing response-handling tests, remain green since the success path (`Ok(Ok(Some(bytes)))`) behaves identically to before.

- [ ] **Step 5: Stop and report for review**

---

## Task 5: Wire pooling into `serve_one` — checkout, keep-alive to the backend, and return

**Files:**
- Modify: `rproxy/src/proxy.rs`
- Modify: `rproxy/src/balancer.rs` (remove the now-unneeded `#[allow(dead_code)]` markers from Tasks 1 and 2)
- Modify: `rproxy/src/proxy.rs` (also remove the `#[allow(dead_code)]` markers from Task 3's `is_poolable`/`buffer_is_empty`, in addition to the `serve_one` edits below)

**Interfaces:**
- Consumes: `Lease::take_conn`/`Lease::return_conn` (Task 2), `is_poolable`/`Conn::buffer_is_empty` (Task 3), `BACKEND_RESPONSE_TIMEOUT` (Task 4).
- Produces: `serve_one`'s connect block now checks the pool first; the request's `Connection` header to the backend becomes conditional; the end of the function returns poolable connections.

This task makes `Server::take_conn`, `Server::return_conn`, `Lease::take_conn`, `Lease::return_conn`, `is_poolable`, and `Conn::buffer_is_empty` genuinely reachable from a non-test path for the first time (via `serve_one`), so as the last step of this task, remove the ten `#[allow(dead_code)]` markers Tasks 1, 2, and 3 added — in `balancer.rs`: `POOL_MAX_IDLE`, `POOL_IDLE_TIMEOUT`, `struct PooledConn`, the `Server.idle` field, `Server::take_conn`, `Server::return_conn`, `Lease::take_conn`, `Lease::return_conn`; in `proxy.rs`: `is_poolable`, `Conn::buffer_is_empty` — the compiler no longer needs telling, since the code is live.

This is the task that actually changes proxy behavior end-to-end. Five edits to `serve_one` (plus the allow-removal above), in order:

**Edit A — checkout before connect.** Replace the start of the balance+connect loop body. Currently (verified at `proxy.rs:500-513`):

```rust
    let (mut lease, backend) = loop {
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
```

The loop currently always dials `TcpStream::connect`. It needs to become "try the pool; on a miss, dial as before" — but the loop's break type is `(Lease, TcpStream)` because the code below (`backend.set_nodelay(true)`, `Conn::new(backend)`) assumes a raw socket. Pooling changes the break type to `(Lease, Conn<TcpStream>, bool)` where the `bool` records whether this connection came from the pool (needed later to decide whether to call `set_nodelay` again — a pooled connection already had it set once and doesn't need it re-applied, though re-applying is harmless; track it anyway since the spec's data flow diagram shows the pool hit path skipping the connect step entirely, and `set_nodelay` is logically part of "new connection setup").

Replace the whole loop (lines 500-559) with:

```rust
    let (mut lease, mut backend, from_pool) = loop {
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

        // Level 7: try a pooled connection first — this is the "0 RTT setup"
        // path. A pool hit skips TcpStream::connect (and its timeout)
        // entirely; only a miss falls through to dialing fresh.
        if let Some(conn) = lease.take_conn() {
            println!(
                "[{peer}] {} {} {} -> {}[{}] {addr} (inflight={}) [pooled]",
                req.method,
                req.target,
                req.version.as_str(),
                upstream.name(),
                upstream.algorithm().tag(),
                lease.inflight(),
            );
            break (lease, conn, true);
        }

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
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                break (lease, Conn::new(s), false);
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
```

Note `set_nodelay` moved inside the `Ok(Ok(s))` arm (it now runs on the raw `TcpStream` before wrapping it in `Conn::new`, since the break value is now the already-wrapped `Conn`, not the raw stream) — this replaces the old post-loop `let _ = backend.set_nodelay(true); let mut backend = Conn::new(backend);` lines, which are deleted (see Edit B below, they come right after the loop).

**Edit B — remove the now-redundant post-loop socket setup, keep the rest.** Immediately after the loop (currently `proxy.rs:560-586`), delete these two lines since Edit A already produced a ready `Conn`:

```rust
    let _ = backend.set_nodelay(true);
    let mut backend = Conn::new(backend);
```

Everything else in that block (`lease.mark_served()`, `ctx.upstream = ...`, `ctx.backend = ...`, the pessimistic `lease.mark_failure()` default, and its explanatory comment) stays unchanged — it still applies identically whether `backend` came from the pool or a fresh connect. Add one line noting the pool interaction for the pessimistic-default comment's neighbor:

```rust
    lease.mark_served();
    ctx.upstream = Some(upstream.name().to_string());
    ctx.backend = Some(lease.addr().to_string());
    // (pessimistic-default comment and its lease.mark_failure() call, unchanged)
    lease.mark_failure();
```

**Edit C — make the request's `Connection` header conditional, and return the connection at the end.** Currently the request-forwarding block (`proxy.rs:611-625`) unconditionally sends `Connection: close` to the backend:

```rust
    http::remove_header(&mut req.headers, "transfer-encoding");
    req.version = Version::Http11;
    req.headers.push(("Connection".to_string(), "close".to_string()));
    if req_framing == BodyFraming::Chunked {
        req.headers.push(("Transfer-Encoding".to_string(), "chunked".to_string()));
    }
```

Change the `Connection` line to invite the backend to keep the connection open — pooling can never find a live connection if every request tells the backend to close it:

```rust
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
```

**Edit D — capture the backend's original `Connection` and HTTP version immediately after the response head is parsed, before anything rewrites them for the client leg.** Find where the response head is parsed and `resp_framing` computed (right after Task 4's timeout block):

```rust
    let mut resp = http::parse_response_head(&resp_bytes)?;
    let resp_framing = http::response_body_framing(&method, &resp)?;
```

Add two captures immediately after, before the passive-health-check block or anything else touches `resp`:

```rust
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
```

This is why Task 3's `is_poolable` takes plain `bool`s for these two conditions instead of the response head itself: capturing them at the wrong point in this mutating pipeline is exactly the bug this comment exists to prevent, so the call site is written to make "captured early" the only option.

**Edit E — the poolability check and conditional return, at the end of `serve_one`.** Replace the last two lines of the function (currently the comment `// Backend conn drops here (Connection: close) — pooling is Level 7.` followed by `Ok(client_still_usable)`) with:

```rust
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
```

- [ ] **Step 1: Apply Edits A through E to `serve_one`**

Apply exactly the code shown above, in order, to `rproxy/src/proxy.rs`.

- [ ] **Step 2: Remove the temporary `#[allow(dead_code)]` markers in `balancer.rs` and `proxy.rs`**

Find and delete the ten `#[allow(dead_code)]` attributes Tasks 1, 2, and 3 added: in `balancer.rs` — `POOL_MAX_IDLE`, `POOL_IDLE_TIMEOUT`, `struct PooledConn`, the `Server.idle` field, `Server::take_conn`, `Server::return_conn`, `Lease::take_conn`, `Lease::return_conn`; in `proxy.rs` — `is_poolable`, `Conn::buffer_is_empty`. Leave every other comment on these items untouched — only the attribute line goes.

- [ ] **Step 3: Run the full suite**

Run: `cd rproxy && cargo test 2>&1 | tail -5`
Expected: **167 passed** (unchanged from Task 4's count — Task 5 changes `serve_one`'s internals but not any behavior the existing unit tests observe directly; `serve_one` itself has no direct unit tests per the note in Task 4, and its correctness is verified live in Task 7).

Run: `cd rproxy && cargo build --release 2>&1 | grep -c warning`
Expected: exactly the pre-existing **4-warning baseline** — no more (nothing new should be dead now that `serve_one` reaches the whole pooling chain) and no fewer (removing the allows must not have been *necessary* to reach 4; if the build still shows 4 warnings without Step 2's removals, something in Edits A–E didn't actually wire the code path live — investigate before proceeding, don't just leave the allows in). If `from_pool` (the loop's third break value) is unused after Edit A/B, either use it (e.g. in the pooled-hit log line already shown in Edit A) or prefix with `_from_pool`.

- [ ] **Step 4: Stop and report for review**

---

## Task 6: CLI flags — `--pool-max-idle`, `--pool-idle-timeout`, `--backend-timeout`

**Files:**
- Modify: `rproxy/src/main.rs`
- Modify: `rproxy/src/balancer.rs` (make `POOL_MAX_IDLE`/`POOL_IDLE_TIMEOUT` overridable rather than hardcoded constants)
- Modify: `rproxy/src/proxy.rs` (make `BACKEND_RESPONSE_TIMEOUT` overridable)

**Interfaces:**
- Consumes: `next_val`, `parse_duration`, `bad_arg` (existing, `main.rs`).
- Produces: three new CLI flags; `POOL_MAX_IDLE`/`POOL_IDLE_TIMEOUT` become fields threaded from `main.rs` into `Server::new` (via `Upstream`'s construction path) rather than free constants; `BACKEND_RESPONSE_TIMEOUT` becomes a parameter threaded into `serve_one`.

This task turns three compile-time constants into runtime-configurable values with the same defaults, following the exact pattern `--hc-*` already established for `HealthConfig`. Rather than duplicating `HealthConfig`'s per-upstream-inheriting shape (rejected in the spec — these are global, not per-upstream), the three values are threaded as plain function parameters / one small struct passed once at startup.

- [ ] **Step 1: Write the failing test**

```rust
    // in balancer.rs's test module
    #[tokio::test]
    async fn server_respects_configured_pool_bounds() {
        let cfg = PoolConfig { max_idle: 1, idle_timeout: Duration::from_secs(60) };
        let srv = Server::new_with_pool_config("127.0.0.1:9000".to_string(), hc(), cfg);
        let (c1, _p1) = tcp_conn_pair().await;
        let (c2, _p2) = tcp_conn_pair().await;
        srv.return_conn(c1);
        srv.return_conn(c2); // max_idle = 1, so this one is dropped
        assert_eq!(srv.idle.lock().unwrap().len(), 1);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rproxy && cargo test balancer::tests::server_respects_configured_pool_bounds 2>&1 | tail -10`
Expected: compile error (`PoolConfig`, `Server::new_with_pool_config` not defined).

- [ ] **Step 3: Write the minimal implementation**

In `balancer.rs`, add a small config struct and thread it through `Server`:

```rust
/// Level 7 pool tunables, set once at startup from CLI flags and shared by
/// every `Server` in every `Upstream` — see the design spec's "global flags
/// only, no per-route override" decision.
#[derive(Clone, Copy)]
pub struct PoolConfig {
    pub max_idle: usize,
    pub idle_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> PoolConfig {
        PoolConfig { max_idle: POOL_MAX_IDLE, idle_timeout: POOL_IDLE_TIMEOUT }
    }
}
```

Add a `pool: PoolConfig` field to `Server`, replacing the two constant references inside `take_conn`/`return_conn` with `self.pool.idle_timeout` / `self.pool.max_idle`:

```rust
pub struct Server {
    addr: String,
    inflight: AtomicUsize,
    ewma_us: AtomicU64,
    breaker: Breaker,
    idle: Mutex<Vec<PooledConn>>,
    pool: PoolConfig,
}

impl Server {
    fn new(addr: String, health: Arc<HealthConfig>) -> Server {
        Server::new_with_pool_config(addr, health, PoolConfig::default())
    }

    fn new_with_pool_config(addr: String, health: Arc<HealthConfig>, pool: PoolConfig) -> Server {
        Server {
            addr,
            inflight: AtomicUsize::new(0),
            ewma_us: AtomicU64::new(0),
            breaker: Breaker::new(health),
            idle: Mutex::new(Vec::new()),
            pool,
        }
    }

    fn take_conn(&self) -> Option<crate::proxy::Conn<TcpStream>> {
        let mut guard = self.idle.lock().unwrap();
        let now = Instant::now();
        while let Some(pc) = guard.pop() {
            if now.saturating_duration_since(pc.idle_since) < self.pool.idle_timeout {
                return Some(pc.conn);
            }
        }
        None
    }

    fn return_conn(&self, conn: crate::proxy::Conn<TcpStream>) {
        let mut guard = self.idle.lock().unwrap();
        if guard.len() < self.pool.max_idle {
            guard.push(PooledConn { conn, idle_since: Instant::now() });
        }
    }
}
```

`new` keeping the old signature (delegating to `new_with_pool_config` with `PoolConfig::default()`) means every existing call site keeps compiling unchanged — only the places that need a *non-default* pool config call the new constructor.

**Exact call sites to update** (verified against source):

`Upstream::build`'s current signature (`balancer.rs:469-474`):
```rust
fn build(
    name: String,
    algorithm: Algorithm,
    servers: Vec<(String, u32)>,
    health: Arc<HealthConfig>,
) -> Upstream {
```
with the internal server-construction loop at line 507: `servers.into_iter().map(|(addr, _)| Server::new(addr, Arc::clone(&health))).collect()`.

Add a fifth parameter and use it in that loop:
```rust
fn build(
    name: String,
    algorithm: Algorithm,
    servers: Vec<(String, u32)>,
    health: Arc<HealthConfig>,
    pool: PoolConfig,
) -> Upstream {
    // ...
    let servers = servers
        .into_iter()
        .map(|(addr, _)| Server::new_with_pool_config(addr, Arc::clone(&health), pool))
        .collect();
```

`Upstream::build` has exactly four call sites (verified via `grep -n 'Upstream::build('`):
- `balancer.rs:533` — inside `Upstream::for_test(name, algorithm, addrs, health)`: add a `PoolConfig::default()` argument (test helper, no CLI reaches it).
- `balancer.rs:949` — inside `from_spec_with_health(name, spec, base: &HealthConfig)`: this function is the one real CLI path (`--upstream NAME=SPEC`, called from `main.rs::build_routes`). Give it a fifth parameter `pool: PoolConfig`, threaded from its own caller, and pass it straight through: `Ok(Upstream::build(name.to_string(), algorithm, servers, Arc::new(health), pool))`.
- `balancer.rs:957` (inside `Upstream::single(addr: &str)`): pass `PoolConfig::default()` — this is the Level-1-compatibility shorthand path (bare `host:port` route, or the two catch-all defaults in `main.rs::build_routes`) and has no CLI flag reaching it by design, matching how `Upstream::single` already hardcodes `HealthConfig::default()` at this same call site today.
- `balancer.rs:979` (test helper `fn pool(algo, servers) -> Upstream` in `#[cfg(test)] mod tests`): pass `PoolConfig::default()`.

`from_spec_with_health`'s signature (`balancer.rs:890-894`) gains the same fifth parameter:
```rust
pub fn from_spec_with_health(
    name: &str,
    spec: &str,
    base: &HealthConfig,
    pool: PoolConfig,
) -> io::Result<Upstream> {
```
Its one call site is in `main.rs::build_routes` (`Arc::new(Upstream::from_spec_with_health(name, spec, hc)?)`, inside the `--upstream` declaration loop) — add `pool_cfg` as a fourth argument there.

In `proxy.rs`, add a similar override for `BACKEND_RESPONSE_TIMEOUT`: change `serve_one`'s signature to accept it as a parameter (`backend_timeout: Duration`) rather than reading the constant directly, defaulting the constant's value when called from `handle_client`'s existing loop, and threading the CLI value down from `main.rs` through `handle_client` (which already receives `routes: &RouteTable` — add a sibling `backend_timeout: Duration` parameter alongside it, since it's a connection-level tunable like the route table itself, not per-request).

In `main.rs`, add the three flags to the existing parse loop (find the `match arg.as_str() { "--upstream" => ..., "--hc-interval" => ..., ..., "--no-forwarded" => forwarded = false, "--no-request-id" => ..., "--no-access-log" => ..., _ => route_specs.push(arg) }` block) and thread them into `build_routes`'s construction path and into the `handle_client` call in the accept loop:

```rust
    let mut pool_cfg = balancer::PoolConfig::default();
    let mut backend_timeout = proxy::DEFAULT_BACKEND_RESPONSE_TIMEOUT;
    // ... inside the match arm list, alongside the existing --hc-* arms:
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
```

Export `proxy::DEFAULT_BACKEND_RESPONSE_TIMEOUT` (rename the Task 4 constant from `BACKEND_RESPONSE_TIMEOUT` to `DEFAULT_BACKEND_RESPONSE_TIMEOUT` and make it `pub`, since it's now a default rather than the only value) and thread `pool_cfg`/`backend_timeout` through `build_routes` (which already takes `hc: &balancer::HealthConfig` — add `pool_cfg: balancer::PoolConfig` alongside it) and through the accept loop's `proxy::handle_client(stream, &routes, peer)` call (add `backend_timeout` as a fourth argument, cloned/copied per spawned task same as `routes`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test 2>&1 | tail -5`
Expected: **168 passed** (167 + 1 new).

Run: `cd rproxy && cargo build --release 2>&1 | tail -5`
Expected: builds clean at the 4-warning baseline.

- [ ] **Step 5: Stop and report for review**

---

## Task 7: Live verification and PROGRESS.md

**Files:**
- Modify: `PROGRESS.md`
- No further code changes unless live verification surfaces a bug.

- [ ] **Step 1: Build and start a test backend that logs each new TCP accept**

```bash
cd rproxy && cargo build --release
python3 -c '
import http.server, socket
accepts = [0]
class H(http.server.BaseHTTPRequestHandler):
    def do(self):
        b = f"hit {accepts[0]}".encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    do_GET = do
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 9001), H)
orig = srv.get_request
def counted():
    accepts[0] += 1
    print(f"ACCEPT #{accepts[0]}", flush=True)
    return orig()
srv.get_request = counted
srv.serve_forever()
' 2>&1 &
sleep 0.5
./target/release/rproxy 127.0.0.1:8080 --pool-idle-timeout 5s '/=127.0.0.1:9001' &
sleep 0.5
```

- [ ] **Step 2: Confirm connection reuse — N requests on a keep-alive client connection produce fewer than N backend accepts**

```bash
for i in $(seq 1 5); do curl -s http://127.0.0.1:8080/ -o /dev/null; done
# Expect far fewer than 5 ACCEPT lines in the backend's output — most
# requests reused a pooled connection instead of opening a new one.
```

Confirm by inspecting the backend's stdout/log for `ACCEPT #N` count vs. 5 requests sent — pooling is working if the count is small and stable (e.g. 1-2) rather than climbing by 1 per request.

- [ ] **Step 3: Confirm a backend `Connection: close` is honored — that connection isn't pooled**

Point one route at a backend that always closes, confirm subsequent requests to it each produce a fresh accept, while a sibling route to the always-keep-alive backend continues reusing connections.

- [ ] **Step 4: Confirm pipelining still works with pooling active**

```bash
printf 'GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n' | nc -w2 127.0.0.1 8080
```

Expect two distinct, correctly-framed responses with no cross-talk — confirming a pooled backend connection's buffer state doesn't leak between the two client-side pipelined requests it serves in turn.

- [ ] **Step 5: Confirm idle-timeout eviction is observable**

```bash
curl -s http://127.0.0.1:8080/ -o /dev/null   # warms the pool
sleep 6                                        # past --pool-idle-timeout 5s
curl -s http://127.0.0.1:8080/ -o /dev/null   # should trigger a fresh ACCEPT
```

Confirm a new `ACCEPT #N` line appears after the sleep, proving the aged-out pooled connection was discarded rather than reused.

- [ ] **Step 6: Confirm a hung backend produces a 504 within `--backend-timeout` and feeds the breaker**

```bash
python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 9002)); s.listen(5)
while True:
    conn, _ = s.accept()  # accept but never respond
' &
sleep 0.3
pkill -f 'release/rproxy'
./target/release/rproxy 127.0.0.1:8080 --backend-timeout 2s --hc-fail 1 '/=127.0.0.1:9002' &
sleep 0.5
time curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/
# Expect: ~2s elapsed, code 504
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/
# Expect: fast 502 — breaker already tripped after one hang with --hc-fail 1
```

- [ ] **Step 7: Clean up all background processes**

```bash
pkill -f 'release/rproxy'; pkill -f 'http.server' ; pkill -f 'socket.socket'
pgrep -f 'release/rproxy' || echo "proxy clean"
```

- [ ] **Step 8: Update PROGRESS.md**

- Tracker row: Level 7 → 🟢 Implemented, matching the style of the Level 5/6 rows (module + test count + one-line summary).
- "Level 7 — what was built" section covering: the per-`Server` pool + RAII checkout/return via `Lease`, the five-condition poolability predicate (call out condition 5 — the buffer-empty check — and why it has no client-leg analogue), the `Connection: keep-alive` change on the request leg (and that the backend's own response `Connection` header is still the authority, captured before any rewriting touches it — this is the subtle bug this plan's own Task 5 caught and fixed, worth keeping as a teaching note), the new `BACKEND_RESPONSE_TIMEOUT` and what it closes, the lazy no-sweeper idle-timeout design (tying back to Level 6's rate-limiter precedent), and the three new CLI flags.
- The theory-documented items: async worker model (Tokio task-per-connection, already built in Level 1), zero-copy (explained, not implemented, with the KB's own caveat), lock contention (using this level's own per-`Server` sharding as the worked example — contrast with what a single global pool mutex would have cost), request pipelining (verified via the existing Level 1 test plus this level's live check, no new code).
- Level 7 quiz — mirror the 8-10 question style of Levels 5/6. Suggested questions:
  1. The poolability predicate needed a fifth condition beyond the four the client-leg keep-alive check already makes. What is it, and why does the backend leg need it when the client leg doesn't?
  2. Two of the five poolability conditions had to be captured *before* certain lines in `serve_one`, not read at the point where `return_conn` is called. Which two, and what specifically would go wrong reading them late?
  3. Why does `Server::return_conn` drop the *new* connection past the size cap instead of evicting an older one?
  4. Why is there no background task sweeping idle connections for staleness? What would such a task cost that the lazy check avoids?
  5. `Server.idle` uses `std::sync::Mutex`, not `tokio::sync::Mutex`. What property of `take_conn`/`return_conn` makes that correct?
  6. The pool is per-`Server`, not per-`Upstream` or global. Explain the lock-contention argument for that choice concretely — what would a single global pool mutex cost under load that per-server pools don't?
  7. Changing the backend's `Connection` header from `close` to `keep-alive` was necessary but not sufficient for pooling to work. What's the second, independent thing that has to be true for a connection to actually get reused?
  8. `BACKEND_RESPONSE_TIMEOUT` only wraps the response-head read, not the body. Why is bounding total-transfer time out of scope for this timeout specifically?
  9. A write to a pooled connection can still fail (the backend closed it between our idle check and our write). How does that failure get handled — does it need its own retry-budget category?
  10. Why does storing a whole `Conn<TcpStream>` in the pool (not just the raw socket) give buffer reuse "for free," and what would a separate buffer-pool abstraction have needed to reimplement?
- Session-log entry dated today.

- [ ] **Step 9: Stop and report** — final test count, warning count, verification results, everything uncommitted awaiting Vishwa's commit decision.

---

## Self-Review

**Spec coverage:**
- Pool location (per-`Server`) → Task 1 ✓
- Checkout/return RAII via `Lease` → Task 2 ✓
- Five-condition poolability (including the buffer-empty condition added in spec self-review) → Task 3, corrected in Task 5 ✓
- Idle timeout (lazy, no sweeper) + max size → Task 1 ✓
- `BACKEND_RESPONSE_TIMEOUT` → Task 4 ✓
- Buffer reuse "for free" → a consequence of Task 1's `PooledConn` holding `Conn<TcpStream>`, documented in Task 7's PROGRESS.md write-up, no separate task needed (matches spec: "not separate work") ✓
- Connect-path change (checkout before connect) → Task 5 Edit A ✓
- `Connection: keep-alive` to the backend → Task 5 Edit C ✓
- Global CLI flags, no per-route override → Task 6 ✓
- Theory-only items (async worker model, zero-copy, lock contention, pipelining) → documented in Task 7, no code ✓
- Non-goals (TLS pooling, per-route tuning, body-transfer timeout) → correctly excluded from every task ✓

**Placeholder scan:** no "TBD"/"handle appropriately"/"similar to Task N" — every code step shows real code.

**Type consistency:** `is_poolable`'s signature is `fn is_poolable(resp_framing: BodyFraming, backend_sent_close: bool, backend_is_http11: bool, exchange_errored: bool, buffer_empty: bool) -> bool` everywhere it appears — defined this way in Task 3, called this way in Task 5 (Edit D captures `backend_sent_close`/`backend_is_http11` immediately after the response head is parsed, before `resp.headers`/`resp.version` are mutated for the client leg later in the same function; Edit E's call site passes them straight through). `Server::new` keeps its original signature (delegating to `new_with_pool_config`) so Task 1/2's tests and every pre-existing call site in `balancer.rs` remain valid after Task 6 adds configurability — verified against source that `Upstream::build`'s and `Upstream::single`'s existing call sites are `Server::new(addr, health)`-shaped, unchanged by Task 6.

**Cross-task consistency note:** an earlier draft of this plan wrote Task 3's poolability predicate against the raw response head (`resp_headers: &[(String, String)]`, `resp_version: Version`), then discovered while drafting Task 5 that reading those fields at the return-conn call site would silently answer the wrong question — by then `resp.headers`/`resp.version` had already been rewritten for the client leg. Both tasks were corrected in place to the `bool`-based signature shown above before this plan was finalized, so the two tasks are consistent as written and an implementer following them in order never encounters the earlier, wrong shape.

**Resolved during self-review:** Task 6's `PoolConfig` threading initially described `Upstream::build`/`from_spec_with_health`'s call sites at the "add a parameter, pass it down" level without verbatim signatures. Re-checked against source and corrected inline: `Upstream::build` (4 call sites: `for_test`, `from_spec_with_health`, `single`, and the test helper `pool()`) and `from_spec_with_health` (1 call site: `main.rs::build_routes`) now each show their exact current signature, the exact new parameter, and what each of the 4 `Upstream::build` call sites passes (`PoolConfig::default()` for the three paths with no CLI flag reaching them — `for_test`, `single`, the test helper — and the real threaded value only through `from_spec_with_health`, the one path `--upstream NAME=SPEC` actually uses).
