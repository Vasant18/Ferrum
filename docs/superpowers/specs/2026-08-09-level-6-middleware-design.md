# Level 6 — Middleware: Design

**Date:** 2026-08-09
**Course:** [Build.md](../../../Build.md) Level 6
**Status:** approved, ready for implementation planning
**Mode:** "I implement, you learn" — heavy in-code teaching comments, quiz at the end

## Goal

Stop bolting cross-cutting features onto the forwarding loop. Levels 1–5 grew
`serve_one` into a 270-line function that reads, routes, balances, retries,
rewrites, and relays. Every feature so far earned its place there because it
*is* forwarding. Auth, rate limiting, request IDs, and access logging are not
— they are policy applied *around* forwarding, and each one added inline would
make the core loop longer and more tangled.

Level 6 builds the architecture that lets those features stack like Lego
instead of tangling like spaghetti:

1. **A middleware pipeline** — an ordered chain of composable interceptors that
   run before the backend is touched and again as the response leaves, each
   able to short-circuit the request or annotate it.
2. **Five middleware built on it** — request ID, access log, authentication,
   authorization, rate limiting — enough real policy to prove the abstraction
   carries weight.

The Rust lesson this level exists to teach, per the knowledge base: **traits,
trait objects, and `Box<dyn>` — dynamic dispatch as an explicit engineering
choice**, plus the concurrency shape of shared mutable state (the rate
limiter's sharded bucket store).

## Non-goals (owned by later levels, or deliberately dropped)

Build.md lists eight middleware for this level. Two are deferred and one is
mostly already built:

- **Compression.** Needs a codec dependency (`flate2`/`brotli`), and it
  interacts with body streaming and `Content-Length` rewriting in ways that
  belong with Level 7's buffer work. Deferred to Level 7.
- **Metrics.** Level 10 (Observability) owns metrics, tracing, and structured
  log export. Building a metrics middleware now guarantees Level 10 reworks it.
  The access-log middleware here is deliberately a single `key=value` line, not
  a metrics backend.
- **Request validation.** Level 1's parser already enforces the validation that
  matters at this layer: framing coherence (the CL+TE smuggling vector), head
  size caps, and malformed request lines. A configurable body-size limit is a
  documented gap, not a Level 6 deliverable.
- **Config-defined chain ordering.** The chain order is fixed in code and
  documented (see below). Which middleware are *enabled* is config; their
  *sequence* is not. Reordering-as-config is a Level 12 (config/hot-reload)
  concern.
- **Static composition (nested generics, Tower's `ServiceBuilder`).** The
  knowledge base is explicit: understand it, don't start there. We build the
  `Vec<Box<dyn Middleware>>` version and document the trade-off.
- **Trusted-proxy allowlists.** The rate limiter keys on the socket-observed
  peer IP. Deriving a client identity from `X-Forwarded-For` requires a trusted
  proxy model, which the Level 5 spec already deferred to Level 13.

## Architecture

A new module *directory*, not a single file. `rewrite.rs` is already 1022 lines
and `balancer.rs` 1516; five middleware plus a sharded limiter plus config
parsing in one file would be the largest file in the crate on arrival.

```
middleware/
  mod.rs        the trait, Decision, Rejection, ReqCtx, Chain (build + run),
                per-route config parsing, startup validation
  auth.rs       Basic + Bearer authentication, require-user authorization,
                base64 decoding, constant-time comparison
  ratelimit.rs  token bucket + sharded per-IP store
  observe.rs    request ID generation/validation, access log line
```

### The trait

```rust
pub trait Middleware: Send + Sync {
    /// Stable name, used in log lines and rejection attribution.
    fn name(&self) -> &'static str;

    /// Inbound half of the onion. May mutate the request, may reject it.
    fn on_request(&self, req: &mut RequestHead, ctx: &mut ReqCtx) -> Decision;

    /// Outbound half. Default no-op so request-only middleware stay terse.
    fn on_response(&self, _ctx: &ReqCtx, _resp: &mut ResponseHead) {}
}

pub enum Decision {
    Continue,
    Reject(Rejection),
}

/// A proxy-generated refusal. Carries headers because the status alone is
/// not a valid response: 401 REQUIRES `WWW-Authenticate` (RFC 9110 §11.6.1),
/// and a 429 without `Retry-After` tells the client nothing actionable.
pub struct Rejection {
    pub status: u16,
    pub reason: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: String,
}
```

`Send + Sync` is required because the chain lives inside the `Arc<RouteTable>`
that every connection task shares.

**Ownership:** `Route` gains a `chain: Chain` field alongside its existing
`rules: RewriteRules`, where `Chain` wraps `Vec<Box<dyn Middleware>>`. A boxed
trait object is not `Clone`, so `Chain` is not `Clone` either — which is fine
and worth stating, because `Route` does not derive `Clone` and is never cloned
today (verified: it is built once at startup and shared through
`Arc<RouteTable>`). Any middleware needing shared mutable state holds its own
`Arc` internally — the rate limiter's `Arc<Limiter>` is the only such case, and
that Arc is what lets one configured limiter be shared if two routes ever want
the same bucket namespace (they don't today; each route gets its own).

**Both methods are synchronous.** This is the central design decision of the
level, and it is a deliberate deviation from the knowledge base's textbook
signature. The KB describes `async handle(request, next) -> Response` — the
onion made explicit, where `next` invokes the rest of the chain. That signature
requires the response to be a **value**, and `serve_one` never has one: it
reads the backend's response head, writes it to the client, and then *streams*
the body through a 16 KB window (`Conn::copy_body_to`). A 2 GB download costs
16 KB of memory today. An owned-response middleware contract would mean
buffering every response body, throwing away Level 1's flat-memory guarantee
and pre-breaking Level 7.

The two-phase split keeps the onion's semantics without owning the body:

- `on_request` runs **forward** through the chain, before the backend exists.
- the exchange streams, untouched, exactly as in Level 5.
- `on_response` runs in **reverse** through the chain — the onion's "way out".

Because neither method awaits, there is no `async fn` in a trait object, no
`Pin<Box<dyn Future>>`, and no `async-trait` dependency. The module docs still
explain *why* that boxing exists in Tower-shaped designs (async fns desugar to
returning futures; `dyn` needs a known size, hence the box) — the teaching
point survives even though we don't pay its cost. The one thing we give up is
a middleware that awaits (an auth middleware calling an external OIDC endpoint,
say). That is a documented boundary of the design, and the reason the trait
takes `&self` rather than `&mut self`: any future async middleware can hold its
own interior mutability without changing every signature.

### `ReqCtx` — what crosses the chain

```rust
pub struct ReqCtx {
    pub peer: SocketAddr,
    pub started: Instant,
    /// Method + original target/host, captured before Level 5 rewrites them.
    pub method: String,
    pub target: String,
    pub host: Option<String>,
    /// Set by RequestId, read by its own on_response and by the log.
    pub request_id: String,
    /// Set by Auth on success, read by Authz. The one piece of state that
    /// genuinely flows *between* middleware.
    pub identity: Option<String>,
    /// Written by proxy.rs after the pool pick, read by the access log.
    pub backend: Option<String>,
    pub upstream: Option<String>,
    /// Name of the middleware that rejected, if any. Log attribution.
    pub rejected_by: Option<&'static str>,
}
```

`ReqCtx` is what makes `on_response` self-sufficient: by the time the response
comes back, the request head has been rewritten by Level 5, so a middleware
that needs the *original* method/target/host must read them from the context.

### The chain and its fixed order

| # | Middleware | Default | Rejects | Why at this position |
|---|-----------|---------|---------|----------------------|
| 0 | `Log` | on | — | Outermost, so its `on_response` runs LAST and observes the final status and the full duration including every inner layer |
| 1 | `RequestId` | on | — | Before anything that can log or reject, so every response — including a 401 — carries the ID |
| 2 | `RateLimit` | off | 429 | **Before** auth: throttles credential-guessing floods without paying for a credential check |
| 3 | `Auth` | off | 401 | Establishes `ctx.identity` |
| 4 | `Authz` | off | 403 | Consumes `ctx.identity`, so it must follow auth |

Rate-limit-before-auth is the one genuinely contestable choice. The KB names
the trade-off directly: "rate-limit before auth if you want to throttle
password-guessing; after, if limits are per-user." We take the security side.
Per-user limits would require the opposite order and a header-keyed bucket;
both are documented extensions.

### Where it plugs into `serve_one`

```
  read + parse head (L1)
        │
        ▼
  route match (L2/L3/L4)            ← chain is per-route, so routing comes first
        │
        ▼
  ┌────────────────────────┐
  │ MIDDLEWARE on_request  │  forward order: Log, RequestId, RateLimit,
  │  (middleware/mod.rs)   │                 Auth, Authz
  └───────┬────────────────┘
          │
    Reject├──────► drain request body (bounded) ──► on_response in REVERSE for
          │        the layers actually entered ──► write 401/403/429 ──► done
          │        NO lease, NO backend socket, NO breaker signal
          ▼
  pool pick + connect + retry (L3/L4)
        │
        ▼
  strip_hop_by_hop ──► L5 apply_request ──► framing re-declare ──► backend
        │
        ▼
  read response head (L1)
        │
        ▼
  ┌────────────────────────┐
  │ MIDDLEWARE on_response │  REVERSE order: Authz, Auth, RateLimit,
  │                        │                 RequestId, Log
  └───────┬────────────────┘
          ▼
  strip_hop_by_hop ──► L5 apply_response ──► framing re-declare ──► client
```

Three placement decisions, each load-bearing:

**1. After routing, not before it.** The KB's lifecycle diagram places
middleware *ahead* of the router. That ordering assumes a single global chain.
Per-route configuration inverts it: you cannot know which chain applies until
you know which route matched. A deliberate, documented deviation — and the same
one Nginx makes in practice (its `access` phase runs per-`location`).

**2. Before the lease and the connect loop.** A rejected request must not
consume a balancer lease, open a backend socket, or feed the circuit breaker.
That is the entire value of short-circuiting: a 429 flood costs the backend
fleet nothing. It also means the chain sits *above* the retry loop, so a
rejection can never trigger a replay.

**3. Middleware precedes Level 5 on both legs.** On the request leg the chain
runs before `strip_hop_by_hop` + `apply_request`; on the response leg
`on_response` runs before `apply_response`. Two consequences, both wanted: an
operator's explicit `set-resp-header` stays the final word over a
middleware-injected header (consistent with Level 5's "explicit rules run
last"), and both stages remain *before* the framing re-declaration, so no
middleware can displace `Content-Length` / `Transfer-Encoding` / `Connection`.
The Level 1 smuggling guarantees are untouched by anything in this level.

### The reverse-order asymmetry

When middleware *k* rejects, `on_response` runs for middlewares *k-1 … 0* only
— the layers that were actually entered on the way in. Middleware *k* produced
the response, so it does not post-process its own output, and layers after *k*
never ran at all.

Concretely: a 401 from `Auth` (#3) still gets stamped with `X-Request-Id` (#1)
and still gets logged (#0), while `Authz` (#4) is never consulted. That is the
onion model behaving correctly — a station that rejected you doesn't re-screen
you on the way out, but the stations you already passed still see you leave.
This asymmetry gets a dedicated test, because the naive implementation (run
`on_response` for every middleware unconditionally) looks identical until a
middleware's `on_response` depends on its own `on_request` having run.

## Config surface (CLI)

Route options extend the Level 5 `;option` grammar. No new config idiom, and
the existing severing rule (options split on the first `;`, before the `=`
target split) already handles values containing `=` and `:`.

**Parser split.** `RewriteRules::from_options` currently *hard-errors* on any
key it doesn't recognize (`rewrite.rs`: `other => return Err(err(...unknown
option...))`). Level 6 options would therefore fail startup if simply passed
through. The fix is an explicit partition in `router.rs::resolve_route`: split
the severed option string into Level 5 keys and Level 6 keys, hand each half to
its own parser, and make **`from_options` no longer the arbiter of "unknown"**.
`middleware::Chain::from_options` owns the final unknown-key error, so a typo
still fails at startup with exactly one clear message and neither parser
silently ignores the other's keys. The partition is a static list of the six
Level 6 key names; a key in neither list is the error case.

| Option | Meaning |
|--------|---------|
| `auth=basic:USER:PASS` | Accept this HTTP Basic credential. Repeatable → a credential set |
| `auth=bearer:TOKEN` | Accept this bearer token. Repeatable |

`auth=basic:USER:PASS` splits on the **first two** colons only; everything after
the second is the password. So `auth=basic:admin:p:ss` means user `admin`,
password `p:ss`. A password may therefore contain `:` but not `;` (the option
separator) — the same restriction Level 5's options already carry, and it gets a
parser test.
| `realm=NAME` | Realm in the `WWW-Authenticate` challenge (default `ferrum`) |
| `require-user=USER` | Authorization allowlist. Repeatable |
| `rate=N/s` or `rate=N/m` | Token-bucket sustained rate |
| `burst=N` | Bucket capacity (default: one second's worth of `rate`, min 1) |

Global flags: `--no-request-id`, `--no-access-log` (mirroring
`--no-forwarded`'s shape from Level 5).

Example:

```
rproxy 127.0.0.1:8080 \
  '/admin/**=127.0.0.1:9001;auth=basic:admin:s3cret;require-user=admin;rate=5/s' \
  '/api/**=127.0.0.1:9002;strip=/api;rate=100/s;burst=200' \
  '/health=127.0.0.1:9002' \
  '/=127.0.0.1:9000'
```

**Default posture:** request ID and access log are ON for every route — neither
can reject a request, and both are what you want from a proxy on day one. Auth,
authz, and rate limiting are OFF unless configured. A proxy that starts
refusing traffic because you upgraded it is a bad proxy.

**Startup validation, all `exit 1` before binding the listener:**

- `require-user` on a route with no `auth=` — nothing could ever populate
  `ctx.identity`, so that route would 403 every request forever. This is the
  Level 6 sibling of Level 5's protected-header guardrail: an incoherent config
  fails at boot, not at 3am.
- `rate=` malformed, or a rate of 0 (`rate=0/s` would reject everything —
  almost certainly a typo for "unlimited", which is expressed by omitting the
  option).
- `burst=0`.
- `auth=` with an unknown scheme, or a `basic:` value without a `:` separator.

## The middleware

### Request ID (`observe.rs`)

Generates a per-request identifier, injects it as `X-Request-Id` on the request
leg, and echoes it onto the response in `on_response` so a client can quote it
in a bug report.

An **inbound** `X-Request-Id` is honored — that is how a trace stitches across
hops — but only after validation: at most 64 characters, and only
alphanumerics, `-`, and `_`. It is a client-controlled string that lands in log
lines, so an unvalidated value is a log-injection vector (a newline in a header
value forges a whole log entry). An invalid inbound value is *replaced*, not
rejected; the request is fine, its label isn't.

Generation is a startup-seeded `AtomicU64` counter rendered with the process
start time — documented explicitly as **not a UUID**. Globally-unique IDs need
either randomness or coordination; a monotonic counter is honest about being
per-process and costs one atomic increment.

### Access log (`observe.rs`)

One `key=value` line per completed request, emitted from `on_response`:

```
id=1a2b-17 peer=127.0.0.1:54321 method=GET target=/api/users status=200 dur=3.1ms upstream=api backend=127.0.0.1:9002 user=admin
```

Rejections are logged the same way with `status=429 rejected_by=ratelimit`, so
a refused request is as visible as a served one.

`proxy.rs` writes `upstream` and `backend` into `ctx` after the pool pick, so
the log middleware needs nothing from the request head. The existing
`-> {status} {reason}` println becomes redundant and is removed; the balancer's
pick line **stays**, because it fires once per *attempt* and shows retry
attribution and in-flight depth that the access log does not. Full log
consolidation (levels, structured export, sampling) is Level 10's job.

### Authentication (`auth.rs`)

Two schemes, both configured per route and both compared in **constant time**:

- **Basic** — decode the base64 payload of `Authorization: Basic ...` and match
  `user:pass` against the configured set. We write our own ~30-line base64
  decoder rather than adding a dependency; the crate stays at tokio + regex.
- **Bearer** — match the token in `Authorization: Bearer ...`.

Constant-time comparison matters: `==` on byte slices short-circuits at the
first differing byte, so response timing leaks the length and matching prefix
of the secret, one byte at a time. A difference-accumulating loop over a
fixed number of bytes does not. This is cheap to do right and embarrassing to
do wrong.

Failure returns **401** carrying `WWW-Authenticate: Basic realm="..."` — RFC
9110 requires the challenge, and it is precisely why `Rejection` carries
headers rather than a bare status. Missing, malformed, wrong-scheme, and
undecodable credentials all produce the same 401 with no detail: distinguishing
"no such user" from "wrong password" is a username oracle.

On success, `ctx.identity = Some(user)` (for bearer: a configurable label, or
the token's configured name).

### Authorization (`auth.rs`)

Reads `ctx.identity` and checks it against the route's `require-user` set.

Failure returns **403, not 401**. The distinction is the whole point of having
a separate middleware: 401 means "I don't know who you are, try again with
credentials"; 403 means "I know exactly who you are and you may not do this."
Returning 401 here would prompt a client to retry credentials that were already
accepted — an infinite loop by design.

A route with `require-user` and no `auth=` is rejected at startup (above), so
`identity == None` at this point is unreachable in a valid config; the code
still handles it defensively with a 403 and a comment explaining why the branch
exists.

### Rate limiting (`ratelimit.rs`)

**Algorithm: token bucket.** A bucket holds up to `burst` tokens and refills at
`rate` tokens/second; each request spends one or gets 429. This allows short
bursts while capping the sustained rate — unlike a fixed window, which permits
`2N` requests back-to-back across a window boundary (the classic fixed-window
flaw the KB calls out).

**State: sharded.**

```rust
pub struct Limiter {
    rate: f64,          // tokens per second
    burst: f64,         // bucket capacity
    shards: Vec<Mutex<HashMap<IpAddr, Bucket>>>,   // std::sync::Mutex, N = 16
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}
```

Sharding by `hash(ip) % 16` means concurrent clients usually touch different
locks; a single global map would serialize every request in the proxy on one
mutex — the exact bottleneck the KB warns about, for ~10 lines of savings.

Deliberately **`std::sync::Mutex`, not `tokio::sync::Mutex`.** The critical
section is a few floating-point operations with no `.await` anywhere inside it,
so an async mutex would buy a scheduler interaction for nothing. This is the
KB's "never hold a lock across `.await`" rule seen from the constructive side:
the reason we *can* use the cheap lock is that the whole check is synchronous —
which is itself a consequence of the sync trait design above. The pieces
interlock.

**Lazy refill, no timer.** On access:
`tokens = min(burst, tokens + elapsed_secs × rate)`. There is no background
refill task and no sweeper — a bucket nobody touches costs nothing and needs no
upkeep. `allow()` takes `now: Instant` as an **explicit parameter** rather than
calling `Instant::now()` internally, which is what makes refill behavior
testable without sleeping in tests.

**Bounded memory.** An attacker cycling source IPs would otherwise grow the map
without limit. Each shard has an entry cap; on insert into a full shard, we
evict entries that are both full (`tokens >= burst`) and idle past a TTL — a
full bucket carries no rate-limiting information, so dropping it is free. If
nothing is evictable the request is allowed rather than rejected: failing open
on an internal capacity limit is correct, because the alternative is that
memory pressure becomes an outage.

**Key: the socket-observed peer IP.** `peer.ip()`, never `X-Forwarded-For`.
This is the one identity in the request that cannot be forged — we watched it
on the socket. Keying on XFF would let an attacker send a random
`X-Forwarded-For` per request for unlimited throughput *and* poison the bucket
of any real IP they chose to name. Level 5 established the same stance for
`X-Real-IP` (overwrite, never trust); this is that principle applied to policy.

**Documented limitation:** when Ferrum itself runs behind another proxy, every
request arrives from that proxy's IP and all clients share one bucket. The fix
is a trusted-proxy allowlist that lets us derive the client from XFF *only*
when the peer is trusted — deferred to Level 13 by the Level 5 spec.

429 carries `Retry-After`, computed from the token deficit
(`ceil((1 - tokens) / rate)` seconds, minimum 1).

## The rejection path

A short-circuit is not just "write a response" — there is a real connection-
safety trap here.

Consider a 429 on a `POST` carrying a 10 MB body. We reject before reading that
body. If we then write the 429 and keep the connection alive, those 10 MB are
still queued in the socket, and the next `read_head()` parses request-*body*
bytes as a request line. That is connection desync — the same class of bug
Level 1 spent two commits closing.

So a rejection must:

1. **Drain the request body, bounded.** Read and discard up to 64 KB using the
   already-parsed `BodyFraming`. Within the cap, the connection stays
   consistent and keep-alive is safe.
2. **Beyond the cap, close.** Send `Connection: close` and hang up rather than
   read megabytes we intend to throw away. Nginx calls this lingering close.

The framing cases are decidable up front, which keeps the drain simple.
`request_body_framing` can only return `None`, `Length(n)`, or `Chunked` — a
request can never use until-close framing (`http.rs` documents this). So:
`None` drains nothing and always keeps alive; `Length(n)` keeps alive iff
`n <= 64 KB`, and the decision is known *before* reading a byte; `Chunked` has
unknown length, so it drains up to the cap and closes if it hits it. The
existing `copy_body_to` already handles all three — the drain writes into a
sink rather than a backend socket.

Keep-alive within the cap matters specifically for **401**: that status is a
*challenge*, and the client is expected to immediately retry with credentials
on the same connection. Closing on every 401 would force a fresh TCP handshake
for every authenticated request.

**The drain is not only about keep-alive.** Even on the close path, unread bytes
sitting in the receive buffer when we `close()` cause the kernel to send a TCP
**RST** rather than a clean FIN — and an RST can discard data already in flight,
including the 429 we just wrote. The client then sees a connection reset instead
of the status explaining why it was refused. That is the real reason nginx
drains before closing, and it means the drain runs in both branches: bounded
drain, then either keep-alive or a deliberate close.

Rejection response construction reuses the existing `respond_error` shape but
must accept extra headers (`WWW-Authenticate`, `Retry-After`, `X-Request-Id`),
so that helper gains a headers parameter.

## Data flow

```
client req ──► parse + framing (L1)
           ──► route match (L2/L3/L4)
           ──► ReqCtx::new  (peer, started, method, ORIGINAL target/host)
           ──► chain.on_request, forward:
                 0. Log        — no-op inbound (records nothing until response)
                 1. RequestId  — validate inbound or generate; set X-Request-Id
                 2. RateLimit  — bucket for peer.ip(); 429 + Retry-After or pass
                 3. Auth       — constant-time credential check; 401 + challenge
                                 or set ctx.identity
                 4. Authz      — ctx.identity ∈ require-user? or 403
           ──► [reject] drain body (≤64 KB) ──► on_response reverse for entered
                        layers only ──► write status + headers + body ──► END
           ──► pool pick + connect + retry (L3/L4); ctx.backend/upstream set
           ──► strip_hop_by_hop ──► L5 apply_request ──► framing ──► backend

backend resp ──► parse head (L1)
             ──► chain.on_response, REVERSE:
                   4. Authz     — no-op
                   3. Auth      — no-op
                   2. RateLimit — no-op
                   1. RequestId — echo X-Request-Id onto the response
                   0. Log       — emit the access line (final status, full dur)
             ──► strip_hop_by_hop ──► L5 apply_response ──► framing ──► client
```

The ordering guarantee that this level exists to establish: **an unauthenticated
flood against a route with both `auth=` and `rate=` returns 429, not 401.** Rate
limiting sits outside auth, so the flood is refused before a single credential
comparison runs. That is the observable proof the chain order is real.

## Observability

The access log line described above is the level's main output. The existing
balancer pick line stays; the per-request `-> {status}` line goes away as
redundant.

Startup gains a chain summary per route so the configured policy is visible
without re-reading the command line:

```
  route: /admin/** -> admin[rr] (middleware: log, request-id, ratelimit(5/s burst=5), auth(basic,1 cred), authz(1 user))
  route: /health -> api[rr] (middleware: log, request-id)
```

## Testing

Everything in this level is synchronous and pure over head structs, so it is
unit-testable end to end with no sockets — the same discipline as Level 3's
algorithms, Level 4's breaker, and Level 5's transforms.

**Chain (`middleware/mod.rs`):**

1. `on_request` runs in forward declaration order.
2. `on_response` runs in **reverse** order (a test middleware appending its
    name to a shared `Vec` proves the sequence, not just the set).
3. A rejection short-circuits: inner middlewares' `on_request` never run.
4. **The asymmetry:** reject at #3 runs `on_response` for #1 and #0 only —
    not for #3 itself, and not for #4.
5. `Continue` all the way through leaves the request unmodified except for the
    documented annotations.

**Auth (`auth.rs`):**

6. Valid Basic credential passes and sets `ctx.identity`.
7. Wrong password → 401; unknown user → 401 with an identical body (no oracle).
8. Missing `Authorization` → 401 with `WWW-Authenticate` present and the
    configured realm.
9. Malformed base64, and a `Basic` payload with no `:`, → 401 (not a panic).
10. Wrong scheme (`Bearer` sent to a Basic-only route) → 401.
11. Valid bearer token passes; wrong token → 401.
12. Base64 decoder: round-trip, padding variants, rejects invalid alphabet.
13. Constant-time compare returns correct results for equal, different-length,
    and differing-at-first-byte inputs.
14. Authz: identity in the allowlist passes; identity not in it → **403**, and
    the test asserts 403 ≠ 401.

**Rate limit (`ratelimit.rs`):**

15. A fresh bucket with `burst=N` allows exactly N requests, then rejects.
16. After a synthetic `now` advance of one second at `rate=R`, exactly R more
    tokens are available (never more than `burst`).
17. `Retry-After` arithmetic: correct seconds for a given deficit, minimum 1.
18. Two distinct IPs get independent buckets (one exhausted, the other free).
19. IPv4 and IPv6 keys coexist.
20. Shard cap: filling a shard past its cap evicts a full+idle bucket and keeps
    the active one.
21. A full shard with nothing evictable fails **open** (allows).
22. Multi-threaded `#[tokio::test]` hammering `allow()` from many tasks — no
    panic, no deadlock, and the total allowed never exceeds `burst + rate ×
    elapsed`.

**Request ID / log (`observe.rs`):**

23. Generated when absent; appears on both request and response.
24. A valid inbound ID is honored (trace stitching).
25. An oversized (>64 char) inbound ID is replaced.
26. An inbound ID containing CR/LF or other control characters is replaced —
    the log-injection guard.
27. Generated IDs are unique across many calls.
28. Access log line contains id, status, and duration fields; a rejection line
    carries `rejected_by`.

**Config (`middleware/mod.rs`):**

29. Every new option parses: `auth=basic`, `auth=bearer`, repeated `auth=`,
    `realm=`, repeated `require-user=`, `rate=N/s`, `rate=N/m`, `burst=`.
30. Error cases each exit 1: `require-user` without `auth`, `rate=0/s`,
    `burst=0`, malformed `rate=`, unknown auth scheme, `basic:` without `:`.
31. Level 5 and Level 6 options compose on one route spec
    (`;strip=/api;auth=basic:u:p;rate=10/s`) — the two grammars must not
    interfere.
32. A route with no middleware options gets the default chain (log +
    request-id) and behaves like Level 5.
33. `--no-request-id` / `--no-access-log` clear those, including on the
    catch-all default routes (so the flags are never silent no-ops — the same
    bug class `--no-forwarded` had to avoid in Level 5).

**Drain (`proxy.rs`):**

34. A rejection on a request with a body leaves the connection parseable: the
    next pipelined request on the same socket is read correctly.
35. A rejection on a body larger than the drain cap sends `Connection: close`.

All 104 existing tests must stay green. Target **~140 tests**.

**Live verification:**

- `curl` flood against `rate=5/s` → 200s then 429 carrying `Retry-After`;
  after a pause, 200s resume.
- 401 without credentials (with `WWW-Authenticate`), 200 with `-u user:pass`,
  401 with a wrong password.
- 403 for an authenticated user absent from `require-user`.
- `X-Request-Id` present on every response; an inbound ID echoed back; a
  CRLF-bearing inbound ID replaced rather than echoed.
- **The ordering proof:** an unauthenticated flood against a route with both
  `auth=` and `rate=` returns **429, not 401**.
- A rejected request does not appear in the backend's log at all (short-circuit
  cost nothing downstream), and `--hc-*` breaker state is untouched by a flood
  of 429s.
- Startup failures: `require-user` without `auth`, and `rate=0/s`, both exit 1
  with a clear message.
- `/health` with no options still serves normally alongside a locked-down
  `/admin/**` in the same invocation.

## Implementation order

1. `middleware/mod.rs`: the trait, `Decision`, `Rejection`, `ReqCtx`, and
   `Chain` with forward/reverse execution and short-circuiting, driven by test
   middleware only. Tests 1–5.
2. `middleware/observe.rs`: request ID (generation, inbound validation) and the
   access log line. Tests 23–28.
3. `middleware/auth.rs`: base64 decoder, constant-time compare, Basic + Bearer
   authentication, `require-user` authorization. Tests 6–14.
4. `middleware/ratelimit.rs`: `Bucket` + sharded `Limiter` with lazy refill,
   eviction, and `Retry-After`. Tests 15–22.
5. Config: extend the route-spec option parser, add `--no-request-id` /
   `--no-access-log`, wire the chain into `Route`, add startup validation and
   the chain summary line. Tests 29–33.
6. `proxy.rs`: run the chain at the documented positions, add the bounded
   rejection drain, extend `respond_error` with headers, populate
   `ctx.backend`/`upstream`, remove the redundant status println. Tests 34–35;
   all 104 prior tests green.
7. Live verification, `PROGRESS.md` update, Level 6 quiz.
