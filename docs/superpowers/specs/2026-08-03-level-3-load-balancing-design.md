# Level 3 — Load Balancing: Design

**Date:** 2026-08-03
**Course:** [Build.md](../../../Build.md) Level 3
**Status:** approved, ready for implementation planning
**Mode:** "I implement, you learn" — heavy in-code teaching comments, quiz at the end

## Goal

Turn each route's single backend address into a *pool* of servers, and choose
one server per request using a configurable algorithm. Seven algorithms, as
specified in Build.md:

Round Robin, Weighted Round Robin, Random, Least Connections,
Least Response Time, IP Hash, Consistent Hashing.

## Non-goals (owned by later levels)

- **Health checks, liveness, retry-on-failure** — Level 4. A dead server is
  still picked and still yields `502`. We leave a documented seam for this
  (see `Server::available()` below) but do not implement it.
- **Connection pooling / reuse of backend sockets** — Level 7. Still one
  backend TCP connection per request.
- **Metrics endpoints, structured logs** — Level 10. Observability here is a
  single extended `println!` line per request.
- **Cookie-based session affinity** — hash-based affinity only (client IP).
  Cookie affinity needs header rewriting (Level 5) and middleware (Level 6).

## Architecture

```
                      ┌─────────────────────────────────────┐
   request            │ RouteTable (immutable, Arc)          │
  ─────────►  route ──►  Route { host, method, path,          │
                      │          upstream: Arc<Upstream> }   │
                      └──────────────┬──────────────────────┘
                                     │  Arc clone, no lock
                                     ▼
                      ┌─────────────────────────────────────┐
                      │ Upstream (shared, interior-mutable) │
                      │   name: "api"                        │
                      │   algorithm: Algorithm               │
                      │   servers: Vec<Server>               │
                      │   rr_cursor: AtomicUsize             │
                      │   ring: Vec<(u64, usize)>  (consist.)│
                      └──────────────┬──────────────────────┘
                                     │ pick(client_ip)
                                     ▼
                      ┌─────────────────────────────────────┐
                      │ Lease<'a>  (RAII)                    │
                      │   server: &'a Server                 │
                      │   started: Instant                   │
                      │   Drop → inflight -= 1, record RTT   │
                      └─────────────────────────────────────┘
                                     │
                                     ▼  TcpStream::connect(lease.addr())
                                  backend
```

### New module: `balancer.rs`

Owns `Algorithm`, `Server`, `Upstream`, `Lease`, and the upstream spec parser.
`router.rs` continues to own *match* logic only — the separation is that the
router answers "which pool?" and the balancer answers "which server in it?".

Changes to existing code:

- `Route.backend: String` → `Route.upstream: Arc<Upstream>`
- `RouteTable::find()` → returns `Option<&Arc<Upstream>>`
- `proxy.rs::serve_one` gains one step between route and connect:
  `let lease = upstream.pick(peer.ip())`
- `Route::catch_all(backend)` keeps its signature, internally wrapping the
  address in a 1-server `rr` pool.

### The three teaching groups

| Group | Algorithms | Rust concept it teaches |
|---|---|---|
| Stateless | RoundRobin, Random, WeightedRoundRobin | `AtomicUsize::fetch_add` + wrapping; weight expansion vs. smooth WRR |
| Load-aware | LeastConnections, LeastResponseTime | atomics under contention, `Ordering`, **`Drop` as the only correct release path** |
| Hash-based | IpHash, ConsistentHash | modulo-rehash disaster → virtual-node ring; `partition_point` binary search |

### Seams left for later levels

- `Server::available() -> bool`, hardcoded `true`, called by every `pick()`.
  Level 4 makes it read a health flag; no call-site changes needed then.
- `Lease` already records round-trip time into the server's EWMA on drop.
  Level 4's passive health checks and Level 10's metrics both read it.

## Config surface (CLI)

```
rproxy LISTEN [--upstream NAME=SPEC ...] ROUTE [ROUTE ...]

--upstream api=lc:127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003
--upstream web=wrr:10.0.0.1:80*5,10.0.0.2:80*1
--upstream cache=chash:node1:6379,node2:6379,node3:6379
```

`SPEC` = `algo:server[*weight][,server[*weight]...]`

| Tag | Algorithm |
|---|---|
| `rr` | Round Robin (**default** when tag omitted) |
| `wrr` | Weighted Round Robin |
| `rand` | Random |
| `lc` | Least Connections |
| `lrt` | Least Response Time |
| `iphash` | IP Hash |
| `chash` | Consistent Hashing |

Weight suffix `*N` is only meaningful for `wrr`; elsewhere it is accepted,
warned about on stderr, and ignored. Rationale: a no-op misconfiguration
should not prevent startup.

### Route → upstream resolution

A route's target resolves in this order:

1. Matches a declared `--upstream` name → bind to that pool.
2. Otherwise parses as `host:port` → auto-wrap as a single-server `rr` pool.
3. Otherwise → startup error `unknown upstream "x"`.

Rule 2 is what preserves backward compatibility: every existing invocation
and all 36 existing tests keep working unchanged, and `Route` can drop
`String` entirely because a single backend is genuinely just a 1-member pool.

**Validation at startup:** empty pool → error; duplicate upstream name →
error; unparseable server address → error; weight `0` → error (a
zero-weight server can never be picked, which is certainly a typo).

## Data flow

Per request, between routing and connecting:

```
route → Arc<Upstream> → pick(client_ip) → Lease ─┬─ connect OK → forward → Drop: inflight--, EWMA += rtt
                                                 └─ connect FAIL → 502, Drop still fires
```

`pick()` returns `Option<Lease<'_>>`, borrowing from the `Upstream`. `None`
only when the pool has no servers, which startup validation already rejects —
so the call site treats it as a defensive `502` rather than an expected
condition.

The lease borrows the `Upstream`, and the `Upstream` is reached through an
`Arc` that `serve_one` holds for the whole exchange, so the borrow is
straightforward — no `'static` bound and no owned-index workaround needed.
The backend address is read via `lease.addr()` rather than stored in the
lease, keeping a single source of truth in `Server`.

The `Lease` decrements the in-flight counter on **every** exit path,
including `?`-propagation mid-body and task cancellation, because release
lives in `Drop` rather than an explicit call. This is the whole reason for
the RAII design: an explicit `release()` is one early return away from
leaking a counter, and a leaked in-flight count permanently biases
least-connections against a healthy server.

## Algorithm details

**Round Robin** — `cursor.fetch_add(1, Relaxed) % n`. `Relaxed` is
sufficient: we need a distinct-ish index, not a synchronization edge.

**Weighted Round Robin** — weights expanded once at startup into an index
vector (`[0,0,0,0,0,1]` for weights 5:1), then plain RR over it. O(1) pick,
O(sum of weights) memory. Note in comments that Nginx uses *smooth* WRR to
avoid the bursty run of consecutive picks this produces, and why we don't.

**Random** — a small xorshift PRNG in a `std::cell::Cell` inside a
`thread_local!`, seeded once per worker thread from a process-start `Instant`
elapsed-nanos value mixed with the thread id. No `rand` dependency added, and
no shared atomic in the hot path. Teaching point: random balancing needs no
coordinated state at all and is surprisingly competitive in practice
(cf. power-of-two-choices).

**Least Connections** — O(n) scan of `AtomicUsize` in-flight counts, lowest
wins, ties to the lower index. Documented race: two tasks scanning
concurrently can both pick the same server. This is *acceptable* — the error
is one request deep and self-correcting — and fixing it with a lock would
serialize every request. This trade-off is the lesson.

**Least Response Time** — same scan over an EWMA of observed RTT stored as
`AtomicU64` microseconds, `alpha = 0.2`. Servers with no samples yet sort
first, so a new server gets traffic instead of being starved.

**IP Hash** — `hash(client_ip) % n` using an explicit FNV-1a written out in
the module (~6 lines), *not* `std`'s `DefaultHasher`. Two reasons: FNV's
arithmetic is visible and teachable, and `DefaultHasher`'s output is
explicitly unspecified across Rust versions, which would silently move every
client's affinity on a toolchain upgrade. Teaching point: this is affinity by
accident of arithmetic, and changing `n` remaps almost every key.

**Consistent Hashing** — 160 virtual nodes per server on a `u64` ring
(hashing `"addr#vnode_index"` with the same FNV-1a), sorted
`Vec<(u64, usize)>`, lookup by `partition_point` binary search, wrapping to
index 0. This directly answers the IP-hash weakness: removing 1 of 4 servers
moves only the ~1/4 of keys that belonged to it, instead of remapping nearly
everything.

## Complexity summary

| Algorithm | pick() cost | State |
|---|---|---|
| RR | O(1) | one `AtomicUsize` |
| Random | O(1) | none |
| Weighted RR | O(1) | pre-expanded index vec; cursor |
| Least Connections | O(n) | per-server `AtomicUsize` |
| Least Response Time | O(n) | per-server `AtomicU64` EWMA |
| IP Hash | O(1) | none |
| Consistent Hash | O(log(n·v)) | sorted ring, v=160 |

## Observability

Extend the existing per-request log line to name the pool, algorithm, and
chosen server:

```
[127.0.0.1:54321] GET /api/users HTTP/1.1 -> api[lc] 127.0.0.1:9002 (inflight=3)
```

Enough to *see* balancing happen under a `curl` loop, with zero new
machinery. Real metrics are Level 10.

## Testing

Unit tests in `balancer.rs`, no sockets required:

1. RR cycles `0,1,2,0` across picks.
2. WRR honors a 5:1 ratio over 100 picks.
3. Random touches every server over many picks (no server starved).
4. LeastConn picks the idle server while leases are held on others.
5. LeastConn rebalances after leases drop.
6. **Lease decrements on early return / drop mid-scope** — the leak bug this
   design exists to prevent.
7. LeastResponseTime prefers the lower-EWMA server; untried servers sort first.
8. IpHash is stable for one IP across repeated picks.
9. IpHash spreads a range of IPs across all servers.
10. ConsistentHash is stable for one key.
11. ConsistentHash vs. IpHash under server removal, over 10 000 synthetic
    keys with 4 servers → 3. Consistent hashing must keep **≥ 70%** of keys on
    their original server (theory says ~75%; 70% leaves headroom for vnode
    imbalance). The same test asserts plain IpHash keeps **< 40%** under the
    identical change. Asserting both numbers is the point — the contrast is
    the lesson, and a one-sided assertion would pass even if the ring were
    silently behaving like modulo.
12. Spec parser: all 7 algo tags, default tag, weights, whitespace.
13. Spec parser errors: empty pool, bad address, unknown algo, zero weight.
14. Route resolution: name binding, `host:port` auto-wrap, unknown name error.

Existing 36 tests must keep passing unmodified except for mechanical
`find()` return-type adjustments. Target ~56 tests total.

**Live verification:** 3 python backends on :9001–:9003, `curl` in a loop
against each algorithm, confirm the distribution from the log lines; confirm
`iphash`/`chash` pin a single client to one server; confirm a dead server in
an `lc` pool still returns 502 (documenting that Level 4 fixes this).

## Implementation order

1. `balancer.rs` skeleton: `Server`, `Upstream`, `Lease`, `Algorithm` enum,
   RR only + tests.
2. Spec parser + startup validation + tests.
3. Wire into `router.rs` / `main.rs` / `proxy.rs`; keep all 36 tests green.
4. Stateless group: Random, Weighted RR + tests.
5. Load-aware group: LeastConnections, LeastResponseTime + tests.
6. Hash group: IpHash, ConsistentHash + tests.
7. Log line, live verification, PROGRESS.md update, quiz questions.
