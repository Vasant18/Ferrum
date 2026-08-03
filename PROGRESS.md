# Build Your Own Reverse Proxy — Course Progress

Course defined in [Build.md](Build.md). Theory reference: [Reverse-Proxy-Knowledge-Base.html](Reverse-Proxy-Knowledge-Base.html). Code lives in [`rproxy/`](rproxy/).

**Mode:** originally strict mentor mode; at kickoff Vishwa asked Claude to implement Level 1 directly ("I implement, you learn" mode) with heavy in-code teaching. Each implemented level ends with a study quiz; later levels can return to mentor mode at any time.

## Level / Module Tracker

| Level | Topic | Status | Notes |
|-------|-------|--------|-------|
| 1 | Core Networking (TCP, HTTP/1.1, forwarding, keep-alive, chunked) | 🟢 **Implemented + hardened** (2026-07-26/27) | `http.rs` (parsing/framing) + `proxy.rs` (Conn, forwarding) + `main.rs` (accept loop). 24 unit tests. Request-smuggling gaps closed. Quiz pending. |
| 2 | Routing (host/path/method, precedence) | 🟢 **Implemented** (2026-07-28) | `router.rs`: RouteTable + PathMatcher (exact/prefix/wildcard/regex/any) + host/method filters + specificity-ranked `find()`; CLI route specs; shared as `Arc<RouteTable>`. 404 on no match. 36 unit tests. Quiz pending. |
| 3 | Load Balancing (RR, weighted, least-conn, consistent hashing) | 🟢 **Implemented** (2026-08-04) | `balancer.rs`: `Upstream` pools + 7 algorithms (rr/wrr/rand/lc/lrt/iphash/chash) + RAII `Lease`; `Route` now targets `Arc<Upstream>`; `--upstream NAME=SPEC` CLI. 52 unit tests. Live-verified all algos. Quiz pending. |
| 4 | Health Checks (active/passive, retries, circuit breaker) | ⚪ Not started | |
| 5 | Proxy Headers & Rewriting (XFF, host/URL rewrite) | ⚪ Not started | |
| 6 | Middleware (pipeline, auth, rate limiting) | ⚪ Not started | |
| 7 | Performance (pooling, buffers, timeouts) | ⚪ Not started | Backend conns are close-per-request until pooling lands here |
| 8 | Security & TLS (termination, mTLS, slowloris) | ⚪ Not started | Head-read timeout + head size cap already in place from L1 |
| 9 | OS Internals (epoll/kqueue, Tokio internals) — theory | ⚪ Not started | |
| 10 | Observability (logs, metrics, tracing) | ⚪ Not started | Currently println/eprintln placeholders |
| 11 | Caching (LRU, TTL, ETag, revalidation) | ⚪ Not started | |
| 12 | Production Features (graceful shutdown, config, hot reload) | ⚪ Not started | Listen/backend addrs via CLI args for now |
| 13 | Basic WAF (SQLi/XSS/traversal detection, reputation) | ⚪ Not started | CL+TE smuggling vector already rejected in L1 parser |
| 14 | Scalability (clusters, HA, anycast) — theory | ⚪ Not started | |

## Level 1 — what was built

- [x] Module 1.1 — TCP listener, task-per-connection accept loop (`main.rs`)
- [x] Module 1.2 — Request/response head parsing into structs (`http.rs`)
- [x] Module 1.3 — Forwarding to one backend (CLI-configurable), response relay (`proxy.rs::serve_one`)
- [x] Module 1.4 — Content-Length bodies both directions, windowed streaming (`Conn::copy_exact`)
- [x] Module 1.5 — Client-side keep-alive loop with per-request backend connections
- [x] Module 1.6 — Chunked transfer encoding relay (incl. extensions stripped, trailers forwarded)
- [x] Extras: hop-by-hop header stripping, CL+TE rejection (anti-smuggling), head size cap,
      slowloris head-read timeout, backend connect timeout, 400/408/502/504 error responses,
      TCP_NODELAY, HTTP/1.0-backend (until-close) response handling
- [x] Security hardening (2026-07-27): reject bare CR/LF in message heads (strict CRLF
      splitting, no `str::lines()`); reject duplicate Content-Length / Transfer-Encoding;
      strict all-ASCII-digit Content-Length parsing; strip incoming Transfer-Encoding
      before re-declaring canonical framing on both legs (no duplicate TE to backend/client)
- [ ] **Level 1 quiz — Vishwa to answer before Level 2** (questions in session notes / ask Claude)

**Verified end-to-end:** `cargo test` (19 tests), GET/POST via curl against python backends,
100 KB binary body round-trip byte-identical, chunked request via netcat, 20 concurrent requests,
dead backend → 502, garbage request → 400, keep-alive connection reuse confirmed by curl.

**Run it:** `cargo run -- 127.0.0.1:8080 127.0.0.1:9000` (shorthand: bare host:port = catch-all).

## Level 2 — what was built

- [x] `router.rs`: `RouteTable`, `Route`, `PathMatcher` (Exact / Prefix / Wildcard / Regex / Any)
- [x] Match dimensions: host (port-stripped, case-insensitive), method, path
- [x] Precedence by computed specificity (exact > wildcard > longest-prefix > regex > any;
      host- and method-scoped routes rank above bare ones) — order-independent, not declaration-order
- [x] CLI route specs `[METHOD ][host]path_expr=BACKEND`; `/**` prefix, `/*` wildcard, `~regex`
- [x] `http::target_path` (strip query) + `http::host_without_port` (incl. IPv6) helpers
- [x] Router shared as `Arc<RouteTable>`, cloned per connection, lock-free reads
- [x] 404 Not Found on no matching route (well-formed request, just unserved)
- [ ] **Level 2 quiz — Vishwa to answer before Level 3**

**Verified end-to-end (2026-07-28):** `cargo test` (36 tests), two live backends with 5-route table —
prefix/catch-all/method/host/regex all routed correctly; exact-beats-prefix precedence; 404 on no
route; keep-alive serving two requests on one connection to different backends.

**Run with routes:** `cargo run -- 127.0.0.1:8080 /api/**=127.0.0.1:9001 /=127.0.0.1:9000`

## Level 3 — what was built

- [x] `balancer.rs`: `Upstream` (named pool + algorithm + servers), `Server`
      (addr + `AtomicUsize` inflight + `AtomicU64` EWMA), `Lease` (RAII), `Algorithm` enum
- [x] All 7 algorithms: Round Robin, Weighted RR (pre-expanded index vector),
      Random (thread-local xorshift, no `rand` dep), Least Connections (O(n) inflight scan),
      Least Response Time (EWMA µs, α=0.2, untried-first), IP Hash (explicit FNV-1a),
      Consistent Hash (160 vnodes/server, sorted ring, `partition_point` lookup)
- [x] RAII `Lease`: inflight released on **every** exit path via `Drop`; RTT recorded into
      EWMA only after `mark_served()` — a failed connect must not teach LRT to prefer dead servers
- [x] `Route.backend: String` → `Route.upstream: Arc<Upstream>`; `find()` → `Option<&Arc<Upstream>>`;
      a single backend is now a 1-member `rr` pool (`Upstream::single`)
- [x] CLI `--upstream NAME=SPEC` where `SPEC = algo:server[*weight][,server...]`; 3-rule route
      resolution (declared name → `host:port` auto-wrap → error); startup validation
      (empty pool / bad addr / unknown algo / zero weight / duplicate name all reject with exit 1)
- [x] Level 4 seam: `Server::available()` hardcoded `true`, already honored by every `select` branch
- [x] Observability: per-request log line `-> name[algo] addr (inflight=N)`
- [x] 52 unit tests (36 existing kept green, mechanical `find()`/`route_to` adjustment only)
- [ ] **Level 3 quiz — Vishwa to answer before Level 4** (questions below)

**Verified end-to-end (2026-08-04):** `cargo test` (52 tests); 3 python backends on :9001–:9003
driven by `curl` loops — rr cycles `9001,9002,9003`; wrr `*5,*1` gives 50:10 over 60 requests;
iphash & chash each pin one client to one server; rr over `[alive, dead]` alternates `200 502`
(dead server still picked → 502, confirming the Level-4 seam); old L1/L2 bare-`host:port`
invocations still work unchanged; all four bad configs reject at startup with exit 1.

**Run with a pool:** `cargo run -- 127.0.0.1:8080 --upstream 'api=lc:127.0.0.1:9001,127.0.0.1:9002' '/api/**=api' '/=127.0.0.1:9000'`

### Level 3 quiz — Vishwa to answer before Level 4

1. `Lease` releases the in-flight count in `Drop` rather than an explicit
   `release()` call. Give a concrete request flow where an explicit call would
   leak the counter, and explain why the leak specifically penalizes a *healthy*
   server under least-connections.
2. The `Lease` decrements inflight unconditionally on drop but records RTT into
   the EWMA *only* after `mark_served()`. What goes wrong with least-response-time
   if a failed (instantly-refused) connect records its RTT?
3. Round robin uses `fetch_add(1, Relaxed)`. Why is `Relaxed` ordering sufficient
   here, and what would `SeqCst` buy you (or not)?
4. Weighted RR pre-expands weights `5:1` into `[0,0,0,0,0,1]` and does plain RR
   over it. Nginx instead uses "smooth" WRR. What observable difference in the
   request pattern does the simple expansion produce, and when would it matter?
5. IP hash is `hash(ip) % n`. Walk through what happens to client→server
   mappings when `n` goes from 4 to 3. Roughly what fraction of clients move?
6. Consistent hashing keeps ≥70% of keys on their original server under the same
   4→3 change. What is the role of the 160 virtual nodes per server — what breaks
   if you use 1 vnode per server instead?
7. Why does the code use a hand-written FNV-1a instead of `std`'s
   `DefaultHasher` for both IP hash and the ring? (Two reasons.)
8. Least-connections has a documented race: two tasks can pick the same idle
   server simultaneously. Why is this acceptable, and what would the fix cost?

## Session log

- **2026-07-26** — Course kickoff. Knowledge base built (all 14 levels). `rproxy` crate created. Module 1.1 taught & assigned. Repo pushed to github.com/Vasant18/Ferrum.
- **2026-07-26 (later)** — Mode switch: Vishwa asked for direct implementation. Level 1 implemented in full (http.rs, proxy.rs, main.rs), tested end-to-end, pushed.
- **2026-07-27** — Closed two request-smuggling gaps flagged by security review (bare-LF parsing, duplicate/ambiguous framing headers). 24 tests pass; live-verified all three vectors return 400. Level 1 complete pending quiz.
- **2026-07-28** — Level 2 (Routing) implemented: `router.rs` with host/path/method matching and specificity-based precedence; wired through proxy + main as `Arc<RouteTable>`; added `regex` dep. 36 tests pass; live-verified against two backends; pushed.
- **2026-08-03/04** — Level 3 (Load Balancing) implemented across two sessions per the approved design (`docs/superpowers/specs/2026-08-03-level-3-load-balancing-design.md`). New `balancer.rs`: 7 algorithms, `Upstream` pools, RAII `Lease` (inflight released on every path via `Drop`; RTT gated on `mark_served`). `Route` retargeted from `String` backend to `Arc<Upstream>`; `--upstream` CLI + 3-rule resolution + startup validation. 52 tests pass (36 existing kept green). Live-verified all algorithms with 3 python backends; dead-server-still-502 confirms the Level-4 seam. Refinement over the spec: RTT recording gated behind `mark_served()` so a failed connect can't bias LRT toward dead servers.
