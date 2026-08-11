# Level 7 — Performance: Design

**Date:** 2026-08-10
**Course:** [Build.md](../../../Build.md) Level 7
**Status:** approved, ready for implementation planning
**Mode:** "I implement, you learn" — heavy in-code teaching comments, quiz at the end

## Goal

Stop paying a fresh TCP handshake for every proxied request. Levels 1–6 close
the backend connection after every exchange — both `proxy.rs`'s framing block
and its final comment say so explicitly ("Connection: close until Level 7
adds pooling"). That is correct but slow: at any real concurrency, every
single request pays ~1 RTT to the backend before byte one, purely to set up a
TCP connection that gets thrown away one response later.

Level 7 closes that gap and, while doing so, fills two timeout holes the
knowledge base's own "every await gets a deadline" table shows are still
open: there is no timeout on reading the backend's response head, and (once
pooling exists) a pooled connection needs an idle bound so it doesn't outlive
the backend's own patience and produce a mysterious reset on reuse.

The eight Build.md items map onto: connection pooling (built), buffer reuse
(a consequence of pooling the right thing, not separate work), timeouts
(two real gaps filled), Keep-Alive tuning (the pool's idle bound *is* the
tuning knob), request pipelining (verified, not built — already correct
since Level 1), and three items done as *explained, not implemented*:
async worker model, zero-copy, memory pools beyond the connection pool, and
lock contention (the pool's own sharding choice becomes the worked example).

## Non-goals (theory-only, or explicitly deferred)

- **`splice()`/`sendfile()` zero-copy body streaming.** OS-specific unsafe
  syscalls, and the KB's own guidance is "measure before reaching for it" —
  there is no benchmark yet showing the streaming copy loop is the
  bottleneck. Explained in PROGRESS.md; not implemented.
- **A generic buffer/object-pool abstraction beyond the connection pool.**
  Pooling `Conn<TcpStream>` (socket + its already-allocated read buffer)
  gives buffer reuse for free on the backend leg. A separate pool for some
  other buffer class has no identified need yet — building one without a
  measured allocator-pressure problem is exactly the guessing the KB warns
  against ("measure, don't guess").
- **Async worker model as new code.** Level 1 already built
  task-per-connection on Tokio. Level 7 documents *why* that design avoids
  C10K (vs. Nginx's process+epoll model); it does not change the model.
- **Per-route or per-upstream pool tuning.** Pool max size, idle timeout, and
  the new backend response timeout are global CLI flags with one hardcoded
  default each, applied uniformly. Unlike health checks (genuinely different
  per backend) or auth (genuinely different per route), no scenario in this
  project yet needs one backend pooled differently from another. Adding the
  override surface without a use case repeats the config-surface mistake
  Level 6 deliberately avoided for rate-limit scoping.
- **A timeout on response *body* streaming.** Only the response *head* read
  gets a deadline (time-to-first-byte). Total-transfer time is
  size-and-route-dependent and stays unbounded, matching the KB's own framing
  of this timeout as protecting against "hung application code" up to first
  byte, not slow-but-alive transfers.
- **TLS/mTLS backend connections.** Level 8's job; the pool stores plain
  `TcpStream`s. (Generic-over-`AsyncRead + AsyncWrite` pooling is a documented
  seam for Level 8 to widen, not built now.)

## Architecture

One new field on an existing struct, two new methods on an existing RAII
type, no new modules.

### Where the pool lives: `Server`, not `Upstream` or global

`balancer.rs`'s `Server` already owns per-backend atomics (`inflight`,
`ewma_us`, `breaker`) and is already the thing a `Lease` borrows for its
whole lifetime. The idle pool is one more field on it:

```rust
pub struct Server {
    addr: String,
    inflight: AtomicUsize,
    ewma_us: AtomicU64,
    breaker: Breaker,
    idle: Mutex<Vec<PooledConn>>,   // NEW
}

struct PooledConn {
    conn: crate::proxy::Conn<TcpStream>,  // socket + its read buffer, together
    idle_since: Instant,
}
```

`std::sync::Mutex`, not `tokio::sync::Mutex` — the critical section is a
`Vec::pop`/`push` with no `.await` inside, the same reasoning Level 6 used
for the rate limiter's shards. Sharding *by server* is, if anything, more
natural here than Level 6's hash-based shards: it is already the unit of
concurrency the balancer fans requests across, so contention on any one
mutex falls as the pool count grows — this is the worked example for the
KB's "shard the state" lock-contention lesson (see Observability below).

A pool per `Server` (not one pool per `Upstream`, and not a single global
pool) also means the existing per-server breaker/EWMA data and the new idle
pool live and die together: when a server is removed from a pool's config,
its idle connections go with it, with no separate cleanup pass.

### Checkout/return: two new methods on `Lease`, not a second guard type

```rust
impl<'a> Lease<'a> {
    /// Take a live pooled connection for this server, if one exists. Pops
    /// LIFO (most-recently-idle first) and silently discards anything past
    /// `POOL_IDLE_TIMEOUT`, so a stale entry costs nothing until something
    /// actually tries to use it.
    pub fn take_conn(&self) -> Option<Conn<TcpStream>>;

    /// Return a connection that just finished a fully successful, reusable
    /// exchange (see poolability below). Consumes `self`-adjacent state by
    /// reference; called only from the one call site that has already
    /// verified poolability.
    pub fn return_conn(&self, conn: Conn<TcpStream>);
}
```

One RAII object already exists per exchange (`Lease`; inflight/EWMA/breaker
already feed on `Drop`). Pooling becomes two more methods on it rather than
a second, parallel guard type with its own lifecycle to reason about.

### Poolability is derived, not tracked separately

A connection is eligible to return to the pool iff, using state `serve_one`
already computes for the *client*-leg keep-alive decision:

1. the response used **not** `BodyFraming::UntilClose` (that framing means
   "read until the backend closes" — unreusable by definition, the backend
   itself told us so),
2. the backend did **not** send `Connection: close`,
3. the backend spoke **HTTP/1.1**,
4. the whole exchange completed with **no I/O error** anywhere along the way,
5. **the connection's read buffer is fully drained** (`Conn`'s internal
   `filled == 0`) after the body finished streaming.

Conditions 1–4 mirror `client_still_usable`'s checks for the client leg,
applied symmetrically to the backend leg. Condition 5 has no client-leg
analogue and is genuinely new: on the client leg, "extra buffered bytes
after this message" correctly means *the next pipelined request* and must
be preserved. On the backend leg there is no pipelining (this proxy sends
one request per checkout and waits for its response before sending
another — see Theory below), so any bytes still sitting in the buffer after
the body was fully consumed are not a next message to preserve; they are
either backend misbehavior or an accounting bug in the framing logic, and
either way must not be pooled forward. Pooling a connection with a
non-empty buffer would hand the *next* checkout's `read_head` a mix of
stale and fresh bytes — the exact connection-desync failure mode Level 1
closed for the client leg, now on the backend leg instead. `Conn`'s buffer
fields are private and this check lives in the same module (`proxy.rs`), so
no new public API is needed to read it.

No new state to track for 1–4 — `resp_framing`, `resp.headers`, and
`resp.version` are all in hand by the time the response is relayed;
error-freedom is structural (see Error Handling). Condition 5 is a direct
field read on the `Conn` already in hand.

## Lifecycle and bounds

**Idle timeout — lazy, no sweeper.** Each `PooledConn` carries
`idle_since: Instant`, stamped at return time. `take_conn` pops from the
back and discards anything whose age exceeds `POOL_IDLE_TIMEOUT`, looping
until it finds a live one or the stack empties:

```rust
pub fn take_conn(&self) -> Option<Conn<TcpStream>> {
    let mut idle = self.idle.lock().unwrap();
    while let Some(pc) = idle.pop() {
        if pc.idle_since.elapsed() < POOL_IDLE_TIMEOUT {
            return Some(pc.conn);
        }
        // else: too old, drop it, try the next one
    }
    None
}
```

No background reaper task, no per-server timer — the same "nobody pays
until somebody looks" principle as Level 6's lazy token-bucket refill. A
connection that ages out is garbage the next `take_conn` walks past; it
costs nothing while unused.

**Max size — bounded at return, not at checkout.** `POOL_MAX_IDLE` per
server (default 4). If the stack is already at cap when a connection is
returned, the *new* connection is dropped (closed) rather than evicting an
existing one — there is no reason to prefer a fresh-idle connection over
ones already resident.

**Two new timeouts**, following the exact `tokio::time::timeout(DURATION,
future)` pattern `HEAD_READ_TIMEOUT` and `BACKEND_CONNECT_TIMEOUT` already
use:

| Constant | Wraps | Default | On expiry |
|---|---|---|---|
| `BACKEND_RESPONSE_TIMEOUT` | `backend.read_head()` | 30s | 504 to the client, `lease.mark_failure()` (feeds the L4 breaker exactly like a connect failure) |
| `POOL_IDLE_TIMEOUT` | (not a live `.await` — the lazy check above) | 60s | discard, try the next pooled connection |

`BACKEND_RESPONSE_TIMEOUT` is the one genuinely new *behavior*: today a
hung backend blocks that connection task forever with no client-visible
error and no breaker signal. This closes the gap and makes "hangs"
ejectable the same way "refuses" already is — a backend that never
answers now looks, to the breaker, like a backend that never connects.

**Connect path change.** Before dialing `TcpStream::connect`, try
`lease.take_conn()`. On a hit, skip the connect and its timeout entirely —
this is the "0 RTT setup" the KB diagrams. On a miss, connect as today,
unchanged. The retry loop is otherwise untouched: a pooled connection that
turns out to be dead on write is handled by the *same* failure path as a
fresh connect failure (see Error Handling) — pooling adds a new connection
*source*, not a new failure category.

**Config — global flags, hardcoded per-backend defaults, no per-route
override:**

```
--pool-max-idle N        (default 4)
--pool-idle-timeout DUR  (default 60s)
--backend-timeout DUR    (default 30s)
```

## Data flow

```
route match (L2/L3/L4/L6 chain) → pool pick → lease = upstream.pick(...)
                                       │
                    ┌──────────────────┴──────────────────┐
                    │ lease.take_conn()                     │  NEW
                    │   Some(conn) → skip connect entirely   │  (0 RTT, reused buffer)
                    │   None       → TcpStream::connect(...)  │  (existing, timed, retried)
                    └──────────────────┬──────────────────┘
                                       ▼
                    forward request head + stream body (unchanged, L1/L5/L6)
                                       ▼
                    tokio::time::timeout(BACKEND_RESPONSE_TIMEOUT,
                                          backend.read_head())            NEW
                                       ▼
                    relay response head + stream body (unchanged, L1/L5/L6)
                                       ▼
        poolable = resp_framing != UntilClose
                 && backend sent no "Connection: close"
                 && backend spoke HTTP/1.1
                 && no I/O error anywhere above
                 && Conn's read buffer is empty
                                       │
                    ┌──────────────────┴──────────────────┐
                    │ poolable  → lease.return_conn(conn)   │  NEW
                    │ !poolable → conn drops (closed)        │  (today's behavior,
                    └───────────────────────────────────────┘   unchanged)
```

## Error handling

Pooling introduces no new failure category. A pooled connection is simply
an alternate *source* of a `TcpStream`, fed into the same forwarding code
that already handles connect failures, timeouts, and retries.

- **Write to a dead pooled connection fails.** This is a genuine TOCTOU
  window inherent to any pool: the backend can close a connection after our
  idle-age check passes but before we write to it. Handled identically to a
  fresh connect failure — `lease.mark_failure()`, retry on another server if
  the method is idempotent and attempts remain, the existing `MAX_RETRIES`
  budget (no separate pooled-retry budget).
- **Response-head timeout** (new): `lease.mark_failure()` + 504, the same
  shape as the existing connect-timeout branch.
- **A timed-out or errored connection is never pooled.** Only the success
  path — the one that reaches the poolability check with no error — ever
  calls `return_conn`. This makes the KB's rule ("a timed-out backend
  connection must be dropped, not pooled; its state is unknown") true by
  construction rather than by a separate check: every fallible step between
  connect and the poolability decision already returns early via `?` or an
  explicit error branch, none of which reach `return_conn`.

## Buffer reuse

A consequence of the architecture, not separate work. `PooledConn` holds a
whole `Conn<TcpStream>` — the struct that already owns the read buffer — so
reusing the connection reuses its buffer automatically. No standalone
buffer-pool abstraction is needed; this is why "pool the `Conn`, not the
raw socket" is the load-bearing choice in this design. The KB's
per-connection memory model (`connections × buffers`) becomes, for pooled
backend legs, closer to `min(pool occupancy, historical concurrency) ×
buffers` instead of `requests × buffers` under sustained keep-alive
load — fewer allocator round-trips, not less peak memory (the pool is
still bounded per server by `POOL_MAX_IDLE`, so worst-case memory is
unchanged; the win is fewer allocations per request, not a smaller ceiling).

## Observability

The startup banner and per-request log line gain nothing new to *display*
per se, but the pool's own design is this level's worked example for the
KB's lock-contention section: sharding per-`Server` rather than one global
`Mutex<HashMap<Addr, Vec<Idle>>>` is what keeps a busy backend's pool
traffic from serializing behind an unrelated backend's pool traffic. This
gets written up in PROGRESS.md as the concrete answer to "why shard", using
this pool as the example rather than a hypothetical.

## Theory documented, not implemented

Matching how Levels 5/6 handled knowledge-base sections framed as
explanation rather than code:

- **Async worker model.** Tokio's existing task-per-connection design
  (built in Level 1) explained: why it sidesteps C10K, how it differs from
  Nginx's process+epoll model, why Rust+Tokio gives event-driven behavior
  with task-shaped ergonomics instead of raw callback/epoll code.
- **Zero-copy / `splice()`/`sendfile()`.** Explained with the KB's own
  caveat: an L7 proxy mostly can't use it for headers (must inspect them),
  and it needs measurement before reaching for it. No unsafe syscalls added.
- **Lock contention.** Explained using this level's own pool as the worked
  example (see Observability above) rather than an abstract discussion.
- **Request pipelining.** Verified, not built. `Conn::read_head`'s existing
  buffering already carries bytes past one request's boundary into the
  next — proven by the Level 1 test `preserves_pipelined_bytes_after_head`.
  Level 7 adds a live-verification step confirming this still holds with
  pooling active (a pooled connection's buffer must not leak a prior
  exchange's leftover bytes into the next one — see Testing item 10) and
  documents the result. No code change expected on the client leg; the
  backend leg has no pipelining today (one request per checkout) and this
  level does not add it, since nothing currently sends two requests to one
  backend connection without waiting for the first response.

## Testing

New coverage in `balancer.rs` (pool mechanics — pure, synchronous, no
sockets, using the same discipline as every prior level's core logic) and
`proxy.rs` (poolability decision + timeout wiring):

1. `take_conn` returns `None` on an empty pool.
2. `return_conn` then `take_conn` round-trips the same connection (identity
   check: same underlying stream survives the trip).
3. Idle timeout: a connection older than `POOL_IDLE_TIMEOUT` is discarded by
   `take_conn`, and popping continues until a live one surfaces or the stack
   empties (synthetic `now`, not real sleep — same testability pattern as
   Level 6's rate limiter).
4. Max size: returning past `POOL_MAX_IDLE` drops the new connection; the
   existing stack contents are unchanged (order and members).
5. LIFO order: the most recently returned connection is the one `take_conn`
   hands back first.
6. Poolability predicate (extracted as a pure function taking
   `resp_framing`, the response headers, `resp.version`, an error-occurred
   flag, and a buffer-empty flag): each of the five conditions independently
   forces `false`; all five true forces `true`.
7. Response-head timeout fires 504 and calls `mark_failure` (mirrors the
   existing connect-timeout test shape in `proxy.rs`).
8. A write failure on a pooled connection retries on another server exactly
   like a fresh-connect failure (reuses the existing retry test pattern —
   same assertion shape, pooled connection as the failing source instead of
   a fresh connect).
9. A pooled connection's leftover buffer state cannot leak: after one
   exchange completes and the connection is returned, the next checkout's
   `read_head` sees only the new exchange's bytes, not any stale remainder
   (guards the pipelining-safety claim above).
10. Multi-threaded `#[tokio::test]` exercising concurrent `take_conn`/
    `return_conn` on one `Server` from several tasks — no panic, no
    deadlock (mirrors Level 6's `concurrent_allow_no_panic` shape).

All prior tests (152) must stay green. Target **~165 tests**.

**Live verification:**

- A python backend and a proxy configured with default pool settings;
  drive N sequential requests through one client connection and confirm
  (via the backend's own accept-count logging, or `netstat`/`lsof` showing
  a stable small number of ESTABLISHED backend connections regardless of
  request count) that backend TCP connections are being reused rather than
  reopened per request.
- Confirm a `Connection: close` from the backend on one response is
  honored — that specific connection is not pooled, while sibling
  connections to the same backend still are.
- Confirm pipelining still works end-to-end with pooling active: two
  requests pipelined on the client connection each get correctly-framed,
  distinct responses, with no cross-talk from a pooled backend connection's
  buffer.
- Confirm idle-timeout eviction is observable: after waiting past
  `--pool-idle-timeout`, the next request to that backend triggers a fresh
  connect (visible in the backend's connection log) rather than reusing the
  now-expired pooled entry.
- Confirm a hung backend (accepts the connection, never responds) produces
  a 504 within `--backend-timeout`, and that the breaker ejects it after
  repeated hangs the same way it already ejects repeated connect failures.

## Implementation order

1. `balancer.rs`: `PooledConn`, `Server.idle`, `take_conn`/`return_conn` on
   `Lease`, `POOL_MAX_IDLE`/`POOL_IDLE_TIMEOUT` constants. Tests 1–5, 10.
2. `proxy.rs`: extract the poolability predicate as a pure function; test 6.
3. `proxy.rs`: wire `take_conn` into the connect path (skip connect on hit);
   wire `return_conn` at the end of a successful, poolable exchange.
4. `proxy.rs`: add `BACKEND_RESPONSE_TIMEOUT` around `backend.read_head()`,
   feeding `mark_failure` + 504 on expiry. Test 7.
5. Verify the existing retry loop's failure path already covers a pooled
   connection's write failure with no code change (or make the minimal
   change if it doesn't); test 8.
6. Buffer-leak guard test (9) against a pooled connection reused across two
   exchanges.
7. Concurrency test (10) if not already covered by step 1.
8. CLI: `--pool-max-idle`, `--pool-idle-timeout`, `--backend-timeout` flags,
   threaded into `HealthConfig`-adjacent construction or a small sibling
   config struct; startup banner note if useful.
9. Live verification, PROGRESS.md (Level 7 section: what was built +
   theory-documented items + lock-contention worked example), Level 7 quiz.
