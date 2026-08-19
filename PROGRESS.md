# Build Your Own Reverse Proxy — Course Progress

Course defined in [Build.md](Build.md). Theory reference: [Reverse-Proxy-Knowledge-Base.html](Reverse-Proxy-Knowledge-Base.html). Code lives in [`rproxy/`](rproxy/).

**Mode:** originally strict mentor mode; at kickoff Vessey asked Claude to implement Level 1 directly ("I implement, you learn" mode) with heavy in-code teaching. Each implemented level ends with a study quiz; later levels can return to mentor mode at any time.

## Level / Module Tracker

| Level | Topic | Status | Notes |
|-------|-------|--------|-------|
| 1 | Core Networking (TCP, HTTP/1.1, forwarding, keep-alive, chunked) | 🟢 **Implemented + hardened** (2026-07-26/27) | `http.rs` (parsing/framing) + `proxy.rs` (Conn, forwarding) + `main.rs` (accept loop). 24 unit tests. Request-smuggling gaps closed. Quiz pending. |
| 2 | Routing (host/path/method, precedence) | 🟢 **Implemented** (2026-07-28) | `router.rs`: RouteTable + PathMatcher (exact/prefix/wildcard/regex/any) + host/method filters + specificity-ranked `find()`; CLI route specs; shared as `Arc<RouteTable>`. 404 on no match. 36 unit tests. Quiz pending. |
| 3 | Load Balancing (RR, weighted, least-conn, consistent hashing) | 🟢 **Implemented** (2026-08-04) | `balancer.rs`: `Upstream` pools + 7 algorithms (rr/wrr/rand/lc/lrt/iphash/chash) + RAII `Lease`; `Route` now targets `Arc<Upstream>`; `--upstream NAME=SPEC` CLI. 52 unit tests. Live-verified all algos. Quiz pending. |
| 4 | Health Checks (active/passive, retries, circuit breaker) | 🟢 **Implemented** (2026-08-06) | `balancer.rs`: per-server `Breaker` (Closed/Open/HalfOpen) + shared passive/active feeds via `Server::record_*`; `health.rs`: one prober task per upstream (`GET /health`, timeout, `probe_due` gate); `proxy.rs`: connect-retry loop (idempotent + pre-body + cap 2); `;health=PATH` spec suffix + `--hc-*` flags. 72 unit tests. Live-verified ejection, recovery, retry, and cap all with default config. Quiz pending. |
| 5 | Proxy Headers & Rewriting (XFF, host/URL rewrite) | 🟢 **Implemented** (2026-08-07) | `rewrite.rs`: pure sync transforms over head structs — four forwarded headers (XFF append, X-Real-IP overwrite, XFH/XFP set-if-absent), segment-aware path rewriting (`strip`/`prefix`, query preserved), Host rewriting with original capture, request/response header rules, protected-header guardrail; route-spec `;option` grammar + `--no-forwarded`; fixed transform ordering. 99 unit tests. Live-verified all four headers, append-vs-overwrite, path+Host+response rewrite ordering, guardrail. Quiz pending. |
| 6 | Middleware (pipeline, auth, rate limiting) | 🟢 **Implemented** (2026-08-09) | `middleware/` dir: sync two-phase `Middleware` trait (`on_request` fwd / `on_response` reverse) + `Chain` + `ReqCtx` + `Decision`/`Rejection`; five middleware — request-id, access-log (`observe.rs`), Basic/Bearer auth + require-user authz (`auth.rs`, constant-time + own base64), token-bucket rate limit (`ratelimit.rs`, 16-shard `std::sync::Mutex`, lazy refill, socket-IP key); fixed order log→request-id→ratelimit→auth→authz; per-route `;auth=/rate=/burst=/realm=/require-user=` via an option partition in `router.rs`; `--no-request-id`/`--no-access-log`; bounded 64 KB rejection drain in `proxy.rs`. 152 unit tests. Live-verified the ordering proof (`401×5 then 429×5` on an unauth flood), 403≠401, drain+keep-alive, and that rejections never hit the backend. Quiz pending. |
| 7 | Performance (pooling, buffers, timeouts) | 🟢 **Implemented** (2026-08-10/11) | `balancer.rs`: per-`Server` bounded LIFO idle-connection pool (`std::sync::Mutex<Vec<PooledConn>>`, lazy idle-timeout eviction, max-size cap dropping the newest on overflow) + `Lease::take_conn`/`return_conn`; `proxy.rs`: five-condition `is_poolable` predicate (framing, backend `Connection: close`, HTTP/1.1, no I/O error, drained buffer) + `Conn::buffer_is_empty`, `BACKEND_RESPONSE_TIMEOUT` around the response-head read; wired into `serve_one` (pool-hit skips connect entirely, backend leg asks for `keep-alive`, poolability captured *before* the client-leg rewrite touches the response head); `--pool-max-idle`/`--pool-idle-timeout`/`--backend-timeout` CLI flags, global only. 168 unit tests. Live-verified connection reuse (`[pooled]` tag + backend accept counts), honoring a backend's own `Connection: close`, pipelining unaffected, idle-timeout eviction, and a hung backend producing a 504 + breaker ejection. Quiz pending. |
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
- [ ] **Level 1 quiz — Vessey to answer before Level 2** (questions in session notes / ask Claude)

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
- [ ] **Level 2 quiz — Vessey to answer before Level 3**

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
- [ ] **Level 3 quiz — Vessey to answer before Level 4** (questions below)

**Verified end-to-end (2026-08-04):** `cargo test` (52 tests); 3 python backends on :9001–:9003
driven by `curl` loops — rr cycles `9001,9002,9003`; wrr `*5,*1` gives 50:10 over 60 requests;
iphash & chash each pin one client to one server; rr over `[alive, dead]` alternates `200 502`
(dead server still picked → 502, confirming the Level-4 seam); old L1/L2 bare-`host:port`
invocations still work unchanged; all four bad configs reject at startup with exit 1.

**Run with a pool:** `cargo run -- 127.0.0.1:8080 --upstream 'api=lc:127.0.0.1:9001,127.0.0.1:9002' '/api/**=api' '/=127.0.0.1:9000'`

### Level 3 quiz — Vessey to answer before Level 4

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

## Level 4 — what was built

- [x] `balancer.rs`: per-server `Breaker` — a three-state machine (`Closed` serving,
      `Open` tripped/cooling, `HalfOpen` one recovery trial outstanding). All fields are
      `Relaxed` atomics; every method takes `now: Instant` so the machine is testable
      without sleeping. Transitions: `Closed->Open` on `fail_threshold` consecutive
      failures; `Open->HalfOpen` when the cooldown elapses (`probe_due` admits exactly one
      trial per episode); `HalfOpen->Closed` on `success_threshold` consecutive successes;
      `HalfOpen->Open` (backoff doubled) on a failed trial
- [x] Shared passive + active feeds: both funnel through `Server::record_success` /
      `record_failure` into the *same* breaker counters. Passive = real client exchanges
      via `Lease` on drop (`mark_success`/`mark_failure`; a 4xx counts as success — the
      backend is fine); active = the `health.rs` prober. Neither feed knows the other
      exists, so a trafficked server trips from client failures without a probe, and an
      idle server still recovers via probes
- [x] `Server::available()` (the Level-3 seam that was hardcoded `true`) now returns
      `breaker.allows_traffic()`, true only in `Closed`. No `select` branch changed —
      routing already skipped unavailable servers, so ejection "just worked" once the flag
      became real
- [x] `health.rs`: one `probe_loop` task per upstream, spawned at startup. Each tick sleeps
      `interval`, snapshots which servers are `probe_due`, then probes them concurrently
      (`GET <path>` with `Connection: close` under `timeout`); 2xx = success, everything
      else (refused/timeout/malformed/non-2xx) = failure. `apply_probe_result` maps the
      outcome onto the breaker and logs any transition
- [x] `proxy.rs`: connect-retry loop gated on **three** conditions, all required — (1)
      attempts remain (cap `MAX_RETRIES = 2`), (2) the method is idempotent (safe to
      replay), (3) still at the connect stage (no request-body bytes forwarded yet). Only a
      failed *connect* retries onto a fresh pick; a failure after the head was sent (5xx,
      mid-response I/O) is not replayable. Retries are tagged `[retry N/2]` in the log
- [x] Exponential backoff: cooldown starts at `backoff_base`, doubles on each failed
      HalfOpen trial, caps at `backoff_max`, and resets to base on recovery
- [x] Recovery: `probe_due` keeps admitting a `HalfOpenTrial` while HalfOpen (not just the
      first tick), so a server that needs `success_threshold` (default 2) consecutive probe
      successes can actually reach it. The anti-hammering ceiling stays the Open cooldown —
      a *failed* trial trips straight back to Open with a doubled backoff, so a truly dead
      backend is still probed at most once per (growing) cooldown, not once per tick
- [x] CLI surface: per-upstream `;health=PATH` suffix on the `--upstream` spec (inherits
      global thresholds, overrides only the path); global `--hc-interval`, `--hc-timeout`,
      `--hc-fail`, `--hc-success`, `--hc-backoff-base`, `--hc-backoff-max`. The CLI now
      builds pools via `Upstream::from_spec_with_health` (the old `from_spec` is retained as
      the default-config API, exercised by tests)
- [x] 72 unit tests (52 from Level 3 kept green; +20 for breaker states, backoff, passive
      feed, prober-driven recovery, spec health suffix, prober mapping)
- [ ] **Level 4 quiz — Vessey to answer before Level 5** (questions below)

**Verified end-to-end (2026-08-06):** `cargo test` (72 tests); release binary driven against
python backends on :9001–:9003, all with the **default** config (`--hc-interval 1s --hc-fail 2`,
no `--hc-success` override). **Ejection:** killing 9002 tripped `127.0.0.1:9002 Closed->Open`
after 2 failed active probes; the 9-GET loop returned only `9001`/`9003` with zero 502s, and
failed HalfOpen trials doubled the cooldown live (1s→2s→4s). **Recovery:** restarting 9002
produced `HalfOpen->Closed` (backoff reset to 1s), and 9002 rejoined rotation — the follow-up
9-GET loop split evenly 3/3/3 across all three backends. **Retry (the sole coverage — the loop
has no unit test):** with `rr:127.0.0.1:9001,127.0.0.1:9099` (9099 closed) and `--hc-fail 100`
so the dead server stayed pickable, all 6 GETs returned `200` with `[retry 1/2]` lines showing
the retry landing on 9001; a POST loop returned alternating `502 200`, proving non-idempotent
requests are not replayed; with three dead servers + one alive, the highest marker observed was
`[retry 2/2]` (never `3/..`) and a GET that drew dead picks for all three attempts correctly gave
up with 502. (An earlier build wedged in HalfOpen under the default `success_threshold=2` because
`probe_due` returned `None` for HalfOpen after the first trial; that was fixed by continuing to
admit trials while HalfOpen, and a prober-loop-shaped regression test now guards it.)

**Run it:** `cargo run --release -- 127.0.0.1:8080 --upstream 'api=rr:127.0.0.1:9001,127.0.0.1:9002;health=/health' --hc-interval 1s --hc-fail 2 '/**=api'`

### Level 4 quiz — Vessey to answer before Level 5

1. `allows_traffic()` is true only in `Closed`, not in `HalfOpen`. Why must
   client traffic stay blocked while a recovery probe is outstanding?
2. Active and passive checks share one set of counters. Give one failure
   scenario that *only* the passive feed catches, and one that *only* the
   active feed catches.
3. `Lease`'s outcome is `Option<bool>`, and `None` reports nothing. Why is
   "no opinion" a distinct case from "success"?
4. Retry requires idempotent + pre-body + attempts-remaining. Construct a
   concrete request where dropping the *pre-body* gate would corrupt data.
5. Why does a 4xx response count as a health *success*?
6. `probe_due` admits exactly one `HalfOpenTrial` per cooldown. What goes
   wrong if it admitted one per tick instead?
7. Backoff doubles on a failed trial but resets on recovery. What would a
   backoff that never reset do to a backend that flaps?
8. The breaker uses `Relaxed` atomics, so two concurrent `record_failure`
   calls can lose an increment. Why is that acceptable here?

## Level 5 — what was built

- [x] `rewrite.rs`: the whole level is **pure synchronous transforms over head
      structs** — no sockets, no async, no I/O. `RewriteRules::apply_request`
      mutates a `RequestHead`, `apply_response` mutates a `ResponseHead`; both are
      testable by building a head, applying rules, and asserting — the same
      unit-test discipline as Level 3's algorithms and Level 4's breaker
- [x] Four forwarded headers, each with a deliberate append-vs-overwrite choice:
      **`X-Forwarded-For` APPENDS** (`existing, client_ip`) — replacing would
      erase the upstream chain and *trusting* an inbound value would let any
      client forge its origin; appending is honest because the rightmost entry is
      the address we observed on the socket and cannot be forged (backends read
      XFF from the RIGHT). **`X-Real-IP` OVERWRITES** with the observed peer — a
      single-value header, so a forged `X-Real-IP: 9.9.9.9` must be replaced, not
      trusted. **`X-Forwarded-Host` / `X-Forwarded-Proto` set-if-absent** from
      `ctx.original_host` / `ctx.scheme`
- [x] Segment-aware path rewriting (`strip`, `prefix`) with **query preserved**:
      the `?query` is split off before prefix arithmetic and re-appended, so a
      `?` can never be mangled. `strip` only fires on a path-SEGMENT boundary —
      `strip=/api` turns `/api/users` into `/users` but leaves `/apixyz`
      untouched (remainder `xyz` has no leading `/`), matching nginx/Traefik.
      Stripping the whole path yields `/`, never `""` (an empty target is
      malformed HTTP)
- [x] Host rewriting with original capture: `host=backend.local` clobbers the
      `Host` header (remove-then-push, so exactly one Host survives — a duplicate
      Host is a smuggling vector), while `ForwardContext.original_host` — captured
      **before** any rewriting — feeds `X-Forwarded-Host`, so the backend still
      learns the client's real Host even after we rewrote it
- [x] Request/response header rules: `set-header` / `remove-header` on the request
      leg, `set-resp-header` / `remove-resp-header` on the response leg. Removals
      run before sets so a `(remove X, set X)` pair is order-independent
- [x] Protected-header guardrail: `set-header`/`remove-header` refuse
      `Content-Length`, `Transfer-Encoding`, `Connection`, and `Host`
      (case-insensitively) at **startup** with exit 1 — these are framing/routing
      headers the proxy manages; letting a rule touch them reopens smuggling and
      keep-alive-desync holes Level 1 closed. (`Host` has its own dedicated
      `host=` option, which is the safe way to set it.)
- [x] Route-spec `;option` grammar: options are severed on the first `;` BEFORE
      the `=TARGET` split, because option values contain `=` (`strip=/api`) — the
      naive order would swallow the target into the option string and mis-route.
      A route's options therefore cannot contain a literal `;`. `--no-forwarded`
      is a global flag clearing forwarded-injection on every route (applied even
      to the two friendly catch-all defaults, so the flag is never a silent no-op)
- [x] Fixed transform ordering in `apply_request`: (1) path rewrite, (2) Host
      rewrite, (3) forwarded injection, (4) explicit header rules LAST. Explicit
      rules run last so an operator can deliberately override an injected value
      (e.g. pinning `X-Forwarded-Proto: https` behind an external TLS terminator).
      The proxy's own framing re-declaration still runs after all of this, so a
      rewrite rule can never desync Content-Length/Transfer-Encoding
- [x] 99 unit tests (72 from Level 4 kept green; +27 for forwarded injection,
      append/overwrite, segment-boundary strip, query preservation, Host + XFH
      ordering, header rules, protected-header rejection, spec-option parsing)
- [ ] **Level 5 quiz — Vessey to answer before Level 6** (questions below)

**Verified end-to-end (2026-08-07):** release binary driven against a python
echo backend on :9001 that reports the path and headers it received. **Four
forwarded headers** arrived exactly as designed: `x-forwarded-for: 127.0.0.1`,
`x-real-ip: 127.0.0.1`, `x-forwarded-host: example.com`, `x-forwarded-proto:
http`. **Append/overwrite:** sending `X-Forwarded-For: 1.2.3.4` + `X-Real-IP:
9.9.9.9` produced `x-forwarded-for: 1.2.3.4, 127.0.0.1` (appended, chain
preserved) and `x-real-ip: 127.0.0.1` (forgery replaced). **Rewrite +
ordering:** with `/api/**=...;strip=/api;host=backend.local;remove-resp-header=Server`,
a client GET to `/api/users?page=2` (Host `example.com`) reached the backend as
`"path": "/users?page=2"` (prefix stripped, query intact), `"host":
"backend.local"` (rewritten), and STILL `x-forwarded-host: example.com` (the
client's original Host — the whole-level ordering guarantee), while the client's
response had no `Server` header. **`--no-forwarded`** produced 0 forwarded
headers. **Guardrail:** `;set-header=Content-Length:5` failed startup with
`exit=1` (`header "Content-Length" is managed by the proxy and cannot be
rewritten`). **Two extra regression checks passed:** on a live request with a
catch-all `strip=/api`, `/apixyz` reached the backend as `/apixyz` (NOT `/xyz`),
`/api/real` stripped to `/real`, and `/api` alone became `/`; and an
`--upstream 'pool=rr:...;health=/health'` (L4 `;` grammar) coexisted in the same
invocation with `/api/**=...;strip=...;host=...` (L5 `;` grammar) — both routes
served correctly, the two `;` grammars did not interfere.

**Run it:** `cargo run --release -- 127.0.0.1:8080 '/api/**=127.0.0.1:9001;strip=/api;host=backend.local;remove-resp-header=Server' '/=127.0.0.1:9000'`

### Level 5 quiz — Vessey to answer before Level 6

1. `X-Forwarded-For` is appended but `X-Real-IP` is overwritten. Explain why
   each choice is the secure one, and what a client could forge if we made the
   opposite choice for either.
2. A backend behind two proxies reads `X-Forwarded-For: 1.2.3.4, 10.0.0.1,
   10.0.0.2`. Which entry is trustworthy, and why must it count from the right?
3. `X-Forwarded-Host` is populated from `ForwardContext.original_host` rather
   than from the `Host` header at injection time. What breaks if you read the
   header instead, and which config makes the bug visible?
4. The transform runs after `strip_hop_by_hop` and before the framing
   re-declaration. Give a concrete attack or bug that each ordering constraint
   prevents.
5. `set-header` refuses `Content-Length`, `Transfer-Encoding`, `Connection`,
   and `Host` at startup. For each, say what would break if it were allowed.
6. Route specs sever `;` options before splitting on `=`. Show what
   `/api/**=api;strip=/api` parses to under the naive order, and why the bug
   would be hard to notice in production.
7. Explicit header rules run last, after forwarded injection. Name a real
   deployment where that ordering is required.
8. `strip` of the entire path yields `/` rather than `""`. Why does the
   distinction matter to a backend?

## Level 6 — what was built

- [x] `middleware/` **directory** (not one file): `mod.rs` (trait, `Chain`,
      `ReqCtx`, config parsing), `observe.rs`, `auth.rs`, `ratelimit.rs`.
      `rewrite.rs` was already 1022 lines and `balancer.rs` 1516; five
      middleware + a sharded limiter + config in one file would have been the
      biggest file in the crate on arrival.
- [x] **A synchronous two-phase trait**, deliberately NOT the textbook async
      `handle(req, next) -> Response`. `on_request` runs FORWARD through the
      chain; the exchange streams untouched (Level 1's flat-memory guarantee
      intact); `on_response` runs in REVERSE. The onion's semantics without ever
      owning the response body — which is what lets it stay sync: no `async fn`
      in a trait object, so no `Pin<Box<dyn Future>>` and no `async-trait` dep.
      The async version would have needed an owned `Response`, forcing every
      body to buffer and pre-breaking Level 7.
- [x] **The reverse-order asymmetry**: when middleware *k* rejects,
      `on_response` runs for layers *k-1…0* only (the ones actually entered).
      A 401 from Auth still gets stamped with `X-Request-Id` and logged, while
      Authz never runs. `Chain::run_request` returns the rejecting index so the
      caller unwinds exactly the entered layers.
- [x] **Five middleware** in a fixed, in-code order (log → request-id →
      ratelimit → auth → authz): request-id (generate / honor-valid-inbound /
      replace-hostile, echoed onto the response), access log (one `key=value`
      line from `on_response`, so it sees final status + full duration), Basic +
      Bearer auth (constant-time compare, own ~40-line base64 decoder, 401 +
      `WWW-Authenticate`), require-user authz (403, NOT 401), and a token-bucket
      rate limiter.
- [x] **Rate-limit sits BEFORE auth** — a credential-guessing flood is refused
      by the cheap bucket check before any comparison runs. The knowledge base
      names this exact trade-off; we take the security side and document that
      per-user limits would need the opposite order.
- [x] **Token bucket keyed on the socket peer IP, never `X-Forwarded-For`** —
      the one unforgeable identity. Keying on XFF would let an attacker send a
      random value per request for unlimited throughput AND poison a chosen
      real IP's bucket. Level 5 took the same stance for `X-Real-IP`. State is
      16 `std::sync::Mutex<HashMap<IpAddr, Bucket>>` shards (an async mutex would
      buy a scheduler hop for a critical section that never awaits; one global
      mutex would serialize every request); lazy refill on access means no timer
      task and no sweeper; a full+idle bucket is evicted under a per-shard cap,
      and a full shard with nothing evictable fails OPEN. `allow(ip, now)` takes
      `now` as a parameter, so refill is testable without sleeping.
- [x] **Per-route config via an option partition.** `router.rs::resolve_route`
      splits the severed `;options` by key into the Level 5 set
      (`rewrite::L5_KEYS`) and the Level 6 set (`middleware::L6_KEYS`), hands
      each half to its own parser, and is itself the single arbiter of "unknown
      option" — so neither sub-parser has to know the other's keys and a typo
      still fails startup with one clear message. This is why `rewrite.rs`
      needed no change: only L5 keys ever reach it.
- [x] **Startup guardrails (exit 1), the Level 6 sibling of L5's protected-header
      rejection:** `require-user` with no `auth=` (nothing could set the identity
      it checks), `rate=0`, `burst` without `rate`, unknown auth scheme,
      `basic:` without `user:pass`. `--no-request-id` / `--no-access-log`
      applied even to the catch-all defaults so the flags are never silent
      no-ops (the bug class `--no-forwarded` had to avoid).
- [x] **Chain runs AFTER routing** (the KB's lifecycle diagram puts middleware
      first, but per-route config forces the other order — you can't pick the
      chain before the route) **and BEFORE the balancer lease** (a rejection
      takes no lease, opens no backend socket, and never feeds the breaker).
      On both legs the chain wraps *outside* Level 5, so an operator's explicit
      `set-resp-header` stays the final word over a middleware-injected header,
      and both stay before the framing re-declaration so nothing can desync
      Content-Length/Transfer-Encoding.
- [x] **Bounded rejection drain (64 KB).** A rejected request carrying a body
      must be drained before the connection is reused OR closed: unread bytes in
      the socket at `close()` make the kernel send a TCP RST, which can nuke the
      429/401 we just wrote. Within the cap the connection keeps alive (a 401 is
      a challenge — the client retries on the same connection); over the cap we
      send `Connection: close`.
- [x] 152 unit tests (104 from Level 5 kept green; +48 for chain ordering /
      reverse / short-circuit asymmetry, request-id, base64 + constant-time
      compare, auth/authz, token-bucket refill + eviction + concurrency, config
      parsing + partition, and the rejection drain).
- [ ] **Level 6 quiz — Vessey to answer before Level 7** (questions below)

**Verified end-to-end (2026-08-09):** release binary against a python echo
backend on :9001. **Request-id:** present on every response, a valid inbound
`X-Request-Id` honored, a generated id otherwise (`18ca...-N` counter form).
**Auth:** 401 + `WWW-Authenticate: Basic realm="ferrum"` with no creds, 200 with
`-u admin:s3cret`, 401 with a wrong password. **Authz vs auth (403≠401):** on a
route with two valid creds but `require-user=admin`, `intern` authenticates but
gets **403**, `admin` gets 200, no creds gets 401 — three distinct statuses,
one per stage. **Rate limit:** flooding `/api` (burst 3) gave `200 200 200 429
429 …` with `Retry-After: 1`. **The ordering proof:** an unauthenticated flood
against `/admin` (auth + `rate=5/s`) returned **`401 401 401 401 401 429 429 429
429 429`** — five challenges drain the bucket, then rate-limit short-circuits
*before auth runs*, proving it sits outside auth. **Short-circuit cost nothing
downstream:** the backend logged zero hits for any 401/429 (only the 3 stripped
`/api`→`/x` successes and the health prober's `/health` appeared). **Drain +
keep-alive:** three pipelined `POST`s with bodies on one connection each got a
correctly-framed 429 (`Connection: keep-alive`, distinct id, right
Content-Length), so the body drain left no desync. **Startup guardrails:**
`require-user` without `auth`, `rate=0/s`, unknown scheme, and unknown option
each exit 1 with a clear message; `--no-request-id --no-access-log` produced an
empty chain on the default route.

**Run it:** `cargo run --release -- 127.0.0.1:8080 '/admin/**=127.0.0.1:9001;auth=basic:admin:s3cret;require-user=admin;rate=5/s' '/api/**=127.0.0.1:9001;strip=/api;rate=100/s;burst=200' '/health=127.0.0.1:9001' '/=127.0.0.1:9000'`

### Level 6 quiz — Vessey to answer before Level 7

1. The trait is synchronous with a reverse `on_response` pass, not the textbook
   async `handle(req, next) -> Response`. What does the async version cost in
   *this* proxy specifically, and which Level 1 guarantee would it break?
2. The chain runs AFTER routing, contradicting the knowledge base's lifecycle
   diagram. Why is that forced here, and what config feature makes it necessary?
3. Rate-limit sits before auth. Give the concrete attack this ordering defeats,
   and the use case that would justify the opposite order.
4. Why key the limiter on the socket IP and never on `X-Forwarded-For`? Describe
   the two-part exploit if you keyed on XFF.
5. A rejected request never takes a balancer lease. Why does that matter for the
   circuit breaker during a 429 flood?
6. Auth returns 401, authz returns 403. What goes wrong if authz returned 401
   instead?
7. A rejected request with a body must be drained before the connection is
   reused *or* closed. Name the TCP mechanism that makes the "or closed" half
   necessary, not just the keep-alive half.
8. `require-user` with no `auth=` fails at startup. What would that route do on
   every request if it were allowed to start?
9. The rate limiter uses `std::sync::Mutex`, not `tokio::sync::Mutex`. What
   property of the critical section makes that correct, and what would the async
   mutex cost?
10. When middleware #3 rejects, `on_response` runs for #1 and #0 but not #3 or
    #4. Explain why each of those four choices is correct.

## Level 7 — what was built

- [x] **Per-`Server` idle-connection pool**, not per-`Upstream` or global.
      `Server` (already the home of `inflight`/`ewma_us`/`breaker`) gains
      `idle: Mutex<Vec<PooledConn>>`, a bounded LIFO stack. `std::sync::Mutex`,
      not `tokio::sync::Mutex` — the critical section is a `Vec::pop`/`push`
      with no `.await` inside, the same reasoning Level 6's rate limiter used
      for its shard locks. Sharding by *server* is, if anything, more natural
      than Level 6's hash shards: it's already the unit of concurrency the
      balancer fans requests across.
- [x] **Lazy idle-timeout eviction, no sweeper task.** `take_conn` pops from
      the back and discards anything past `POOL_IDLE_TIMEOUT`, walking
      further down the stack until it finds a live connection or the pool
      empties. A stale entry costs nothing until something actually tries to
      use it — the same "nobody pays until somebody looks" principle as Level
      6's lazy token-bucket refill. `return_conn` bounds the pool at
      `POOL_MAX_IDLE` by dropping the *new* connection on overflow, never
      evicting an existing one.
- [x] **`Conn<TcpStream>` is what gets pooled, not the raw socket** — buffer
      reuse "for free," the whole reason this design choice matters. A
      reused connection's read buffer comes back already allocated; no
      separate buffer-pool abstraction was needed.
- [x] **Five-condition `is_poolable` predicate**, pure and synchronous:
      not `BodyFraming::UntilClose`; backend didn't send `Connection: close`;
      backend spoke HTTP/1.1; the exchange had no I/O error; the connection's
      read buffer is fully drained. The fifth condition has no client-leg
      analogue — there's no pipelining on the backend leg (one request per
      checkout, wait for its response before sending another), so any
      leftover buffered bytes are backend misbehavior or a framing-accounting
      bug, never a next message worth preserving. Pooling them forward would
      leak stale bytes into the next checkout's response parsing — the same
      connection-desync bug class Level 1 closed on the client side.
- [x] **The ordering bug caught during planning, and kept out of the code.**
      Two of the five conditions (`backend_sent_close`, `backend_is_http11`)
      must be captured *immediately* after the response head is parsed, not
      read from `resp.headers`/`resp.version` at the point the pooling
      decision actually happens — by then, the client-leg framing block has
      already rewritten both fields for what the proxy tells the *client*,
      not what the backend actually sent. `is_poolable` takes plain `bool`s
      instead of the response head itself specifically so the caller cannot
      make this mistake inside the function — it has to capture the right
      values at the right time, at the call site. Every implementer and
      reviewer in this level's build independently re-verified this ordering
      by tracing the actual code, not trusting a comment.
- [x] **`BACKEND_RESPONSE_TIMEOUT`** wraps the response-head read with
      `tokio::time::timeout`, mirroring the existing `HEAD_READ_TIMEOUT`/
      `BACKEND_CONNECT_TIMEOUT` pattern. Closes a real gap: before this, a
      backend that accepted the connection and never responded blocked that
      connection task forever, with no client-visible error and no breaker
      signal. Now a hang is ejectable the same way a refused connect already
      was — `lease.mark_failure()` fires on expiry, and a 504 goes to the
      client. Bounds only time-to-first-byte, not total body-transfer time.
- [x] **The backend leg now asks for `Connection: keep-alive`**, not
      `close` — pooling can never find a live connection if every request
      tells the backend to close it. This alone doesn't decide poolability:
      `is_poolable` still independently checks the backend's *own* response
      `Connection` header, since a backend is free to ignore the invitation.
- [x] **Global CLI flags** `--pool-max-idle`, `--pool-idle-timeout`,
      `--backend-timeout`, following the exact `--hc-*` pattern. No per-route
      or per-upstream override — a deliberate scope decision (these are
      transport tuning, not routing policy), not an oversight. `PoolConfig`
      threads through `Upstream::build`/`from_spec_with_health` the same way
      `HealthConfig` already does.
- [x] 168 unit tests (152 from Level 6 kept green; +16 for the pool's LIFO/
      cap/idle-timeout mechanics, the poolability predicate's five independent
      conditions, the buffer-drain check, and the configured-vs-default pool
      bound).
- [ ] **Level 7 quiz — Vessey to answer before Level 8** (questions below)

**Verified end-to-end (2026-08-10/11):** release binary against a real
`ThreadingHTTPServer` Python backend (a `BaseHTTPRequestHandler` defaults to
HTTP/1.0 unless `protocol_version` is set — a real trap this verification hit
and fixed in the test harness, not the proxy, before any of the following
checks would have shown pooling at all).

- **Connection reuse:** 5 requests on a keep-alive client connection produced
  1 backend accept, not 5; the proxy's log line tagged requests 2-5 `[pooled]`
  with response times dropping from ~1.3ms to ~0.5ms once the TCP handshake
  was skipped.
- **A backend's own `Connection: close` is honored per-request** while a
  sibling keep-alive route on the same backend still pools: two requests to a
  `/closeme` path (backend sends `Connection: close` every time) produced two
  fresh accepts, while `/` on the same backend pooled normally.
- **Pipelining is unaffected by pooling.** Two requests pipelined on one
  client connection produced two distinct, correctly-framed responses (each
  with its own `X-Request-Id`, correct `Content-Length`); the proxy's own log
  showed the *backend* connection from serving the first request reused
  (`[pooled]`) to serve the second.
- **Idle-timeout eviction is observable.** With `--pool-idle-timeout 3s`: a
  warm pool entry, followed by a 5-second gap with no traffic, followed by
  another request — that request showed no `[pooled]` tag and produced a
  second, fresh backend accept. The aged-out entry was discarded, not reused.
- **A hung backend (accepts the connection, never responds) produces a 504
  within `--backend-timeout`** (measured ~2.08s against a 2s configured
  timeout) **and the breaker ejects it** on the very next request — a repeat
  request returned an immediate 502 (0.04s) rather than hanging again,
  confirming `lease.mark_failure()` on timeout genuinely feeds the same
  passive breaker feed a refused connect already used.
- **Two test-harness bugs found and fixed during verification, not proxy
  bugs:** the default-HTTP/1.0 Python backend (above), and a hung-backend
  test script that reassigned its `conn` variable each `accept()` loop —
  letting the *health prober's* connection garbage-collect and RST the
  *client's* still-in-flight connection when both landed on the same
  never-responding backend. Neither affected the pool/timeout code under
  test; both were caught by tracing an unexpected result back to its actual
  cause rather than accepting a flaky number.

**Theory documented, not implemented** (matching how Levels 5/6 handled
knowledge-base sections framed as explanation rather than code):

- **Async worker model.** Level 1's existing task-per-connection design on
  Tokio, explained: why it sidesteps C10K (no per-connection thread, no
  per-connection stack-sized memory cost) versus Nginx's process+epoll model,
  and why Rust+Tokio gives event-driven behavior with task-shaped ergonomics
  instead of raw callback/epoll code.
- **Zero-copy / `splice()`/`sendfile()`.** Explained with the knowledge
  base's own caveat: an L7 proxy mostly can't use it for headers (it has to
  inspect them), and it needs measurement before reaching for it. No unsafe
  syscalls added — there is no benchmark yet showing the streaming copy loop
  (`Conn::copy_body_to`) is a bottleneck.
- **Lock contention**, using this level's own pool as the worked example
  rather than an abstract discussion: sharding per-`Server` (this level)
  versus one global `Mutex<HashMap<Addr, Vec<Idle>>>` is exactly the
  "shard the state" lesson — a busy backend's pool traffic never serializes
  behind an unrelated backend's pool traffic, because they're different
  mutexes entirely.
- **Request pipelining.** Verified, not built. `Conn::read_head`'s existing
  buffering already carries bytes past one request's boundary into the next
  (proven by the Level 1 test `preserves_pipelined_bytes_after_head`, and
  reconfirmed live above with pooling active). No pipelining exists on the
  *backend* leg and none was added — this proxy sends one request per
  checkout and waits for its response before sending the next.

### Level 7 quiz — Vessey to answer before Level 8

1. The poolability predicate needed a fifth condition beyond the four the
   client-leg keep-alive check already makes. What is it, and why does the
   backend leg need it when the client leg doesn't?
2. Two of the five poolability conditions had to be captured *before* certain
   lines in `serve_one`, not read at the point where `return_conn` is called.
   Which two, and what specifically would go wrong reading them late?
3. Why does `Server::return_conn` drop the *new* connection past the size cap
   instead of evicting an older one?
4. Why is there no background task sweeping idle connections for staleness?
   What would such a task cost that the lazy check avoids?
5. `Server.idle` uses `std::sync::Mutex`, not `tokio::sync::Mutex`. What
   property of `take_conn`/`return_conn` makes that correct?
6. The pool is per-`Server`, not per-`Upstream` or global. Explain the
   lock-contention argument for that choice concretely — what would a single
   global pool mutex cost under load that per-server pools don't?
7. Changing the backend's `Connection` header from `close` to `keep-alive`
   was necessary but not sufficient for pooling to work. What's the second,
   independent thing that has to be true for a connection to actually get
   reused?
8. `BACKEND_RESPONSE_TIMEOUT` only wraps the response-head read, not the
   body. Why is bounding total-transfer time out of scope for this timeout
   specifically?
9. A write to a pooled connection can still fail (the backend closed it
   between our idle check and our write). How does that failure get
   handled — does it need its own retry-budget category?
10. Why does storing a whole `Conn<TcpStream>` in the pool (not just the raw
    socket) give buffer reuse "for free," and what would a separate
    buffer-pool abstraction have needed to reimplement?

## Session log

- **2026-07-26** — Course kickoff. Knowledge base built (all 14 levels). `rproxy` crate created. Module 1.1 taught & assigned. Repo pushed to github.com/Vasant18/Ferrum.
- **2026-07-26 (later)** — Mode switch: Vessey asked for direct implementation. Level 1 implemented in full (http.rs, proxy.rs, main.rs), tested end-to-end, pushed.
- **2026-07-27** — Closed two request-smuggling gaps flagged by security review (bare-LF parsing, duplicate/ambiguous framing headers). 24 tests pass; live-verified all three vectors return 400. Level 1 complete pending quiz.
- **2026-07-28** — Level 2 (Routing) implemented: `router.rs` with host/path/method matching and specificity-based precedence; wired through proxy + main as `Arc<RouteTable>`; added `regex` dep. 36 tests pass; live-verified against two backends; pushed.
- **2026-08-03/04** — Level 3 (Load Balancing) implemented across two sessions per the approved design (`docs/superpowers/specs/2026-08-03-level-3-load-balancing-design.md`). New `balancer.rs`: 7 algorithms, `Upstream` pools, RAII `Lease` (inflight released on every path via `Drop`; RTT gated on `mark_served`). `Route` retargeted from `String` backend to `Arc<Upstream>`; `--upstream` CLI + 3-rule resolution + startup validation. 52 tests pass (36 existing kept green). Live-verified all algorithms with 3 python backends; dead-server-still-502 confirms the Level-4 seam. Refinement over the spec: RTT recording gated behind `mark_served()` so a failed connect can't bias LRT toward dead servers.
- **2026-08-05/06** — Level 4 (Health Checks) implemented across six subagent-driven tasks per the approved design (`.superpowers/sdd/2026-08-05-level-4-health-checks/`). Tasks 1–5: per-server three-state `Breaker` with shared passive/active feeds (filling the Level-3 `available()` seam with no `select` changes), exponential backoff (double/cap/reset), one-prober-task-per-upstream in `health.rs` (`GET /health`), a three-gate connect-retry loop in `proxy.rs` (idempotent + pre-body + cap 2), and the CLI surface (`;health=PATH` + `--hc-*`). Task 6 (this session): tidied a carried-over dead-code warning (`from_spec` now `#[allow(dead_code)]` with a why-comment; release build down from 3 warnings to 2). Live-verified against python backends: ejection trips `Closed->Open` and drops the dead server from rotation with no 502s; backoff doubles live (1→2→4s); the retry loop (which has *no* unit test) hides a dead backend on GET with `[retry 1/2]` and returns 200, does NOT replay a POST (alternating `502 200`), and caps at `[retry 2/2]`. **Found and fixed a real bug:** active-only recovery deadlocked with the default `success_threshold=2` — `probe_due` returned `None` for HalfOpen after the single admitted trial, so `consec_success` froze at 1 and the breaker wedged in HalfOpen (client traffic is blocked there too, so passive successes can't help). Fix (fix round 1): `probe_due` now keeps admitting a `HalfOpenTrial` while HalfOpen, so the prober can accumulate the successes it needs; the one-probe-per-cooldown ceiling still holds because a failed trial trips straight back to Open with a doubled backoff. Added an integration-shaped regression test that drives recovery the way the prober does (alternating `probe_due`/`record_success` per tick) and asserts `Closed` with the default threshold — the case the old direct-call unit test missed. Re-verified live with the default config (no `--hc-success` override): `HalfOpen->Closed` and 9002 rejoined 3/3/3. 72 tests pass. Full report: `.superpowers/sdd/2026-08-05-level-4-health-checks/task-6-report.md`.
- **2026-08-07** — Level 5 (Proxy Headers & Rewriting) implemented across six subagent-driven tasks per the approved design (`.superpowers/sdd/2026-08-07-level-5-proxy-headers-rewriting/`). New `rewrite.rs`: pure sync transforms over head structs — four forwarded headers (XFF append / X-Real-IP overwrite / XFH+XFP set-if-absent), segment-aware path rewriting with query preservation, Host rewriting with pre-rewrite `original_host` capture feeding XFH, request/response header rules, a startup protected-header guardrail (Content-Length/Transfer-Encoding/Connection/Host), the route-spec `;option` grammar (severed before `=` so option values keep their `=`), `--no-forwarded`, and a fixed transform order (path → Host → forwarded → explicit rules, all before framing re-declaration). Task 6 (this session): **live end-to-end verification + docs**. Drove the release binary against a python echo backend on :9001 and confirmed all 9 checks: four forwarded headers correct; `X-Forwarded-For: 1.2.3.4` appends to `1.2.3.4, 127.0.0.1` while forged `X-Real-IP: 9.9.9.9` is replaced with `127.0.0.1`; `strip=/api` + `host=backend.local` gives the backend `"path": "/users?page=2"` and `"host": "backend.local"` while `x-forwarded-host` STILL reports the client's `example.com` (the level's core ordering guarantee); `remove-resp-header=Server` strips it from the client's response; `--no-forwarded` yields 0 forwarded headers; `;set-header=Content-Length:5` fails startup with exit 1. **Two extra regression checks (beyond the brief):** on a live request the segment-boundary strip left `/apixyz` untouched (not `/xyz`), stripped `/api/real`→`/real`, and turned `/api`→`/`; and the L4 `;health=/health` upstream suffix coexisted with an L5 `;strip/;host` route in one invocation with no grammar interference. 99 tests pass. All background processes cleaned up (`pgrep` clean). Full report: `.superpowers/sdd/2026-08-07-level-5-proxy-headers-rewriting/task-6-report.md`.
- **2026-08-09** — Level 6 (Middleware) implemented inline in one session (not subagent-driven) per the approved design (`docs/superpowers/specs/2026-08-09-level-6-middleware-design.md`) and plan (`docs/superpowers/plans/2026-08-09-level-6-middleware.md`), across the plan's 7 tasks. New `middleware/` directory: a synchronous two-phase `Middleware` trait (`on_request` forward / `on_response` reverse — the onion without owning the streamed body, so no `async fn`-in-trait boxing and no new deps), `Chain` with short-circuit + entered-layer unwind, `ReqCtx`, `Decision`/`Rejection`; five middleware — request-id + access-log (`observe.rs`), Basic/Bearer auth + require-user authz (`auth.rs`; own base64 + constant-time compare), token-bucket rate limit (`ratelimit.rs`; 16-shard `std::sync::Mutex`, lazy refill, no timer, socket-IP key, fail-open eviction). Wired into `serve_one` AFTER routing and BEFORE the balancer lease (a rejection takes no lease / opens no socket / never touches the breaker), with a bounded 64 KB rejection drain to avoid the close-time TCP-RST that would nuke the 429/401. Per-route config via an option partition in `router.rs` (the single arbiter of "unknown option"; `rewrite::L5_KEYS` vs `middleware::L6_KEYS`), so `rewrite.rs` needed no change. `--no-request-id`/`--no-access-log` applied even to the catch-all defaults. **Design refinements over the plan:** kept the partition as the unknown-key arbiter (plan had proposed relaxing `rewrite.rs`'s error arm — unnecessary once the partition guarantees each parser sees only its keys); added a `Chain.summary` field so the startup banner shows per-layer tunables (`ratelimit(5/s burst=5)`) rather than bare names, which also made `MiddlewareConfig::describe` genuinely used. 152 tests pass (104 from L5 kept green, +48). Release build back to the 4-warning baseline (one new `Chain::new` warning resolved with `#[allow(dead_code)]` + why-comment, matching the `for_test`/`from_spec` precedent). Live-verified all checklist items incl. the ordering proof (`401×5 then 429×5`), 403≠401 via a two-cred/one-allow route, drain+keep-alive over pipelined POST bodies (raw-byte inspected), zero backend hits for rejections, and all startup guardrails. Background processes cleaned (`pgrep` clean). Not committed — working tree left for Vessey to commit (repo history is all unsigned; he commits himself).
- **2026-08-10/11** — Level 7 (Performance) implemented via subagent-driven development across the plan's 7 tasks (`docs/superpowers/plans/2026-08-10-level-7-performance.md`, design at `docs/superpowers/specs/2026-08-10-level-7-performance-design.md`). Per-`Server` bounded LIFO idle-connection pool (`balancer.rs`: `PooledConn`, `Server.idle`, `Lease::take_conn`/`return_conn`) with lazy idle-timeout eviction and no background sweeper; a five-condition `is_poolable` predicate and `Conn::buffer_is_empty` (`proxy.rs`); a `BACKEND_RESPONSE_TIMEOUT` closing a real gap (a hung backend previously blocked forever with no client-visible error and no breaker signal); all wired into `serve_one` (pool-hit skips the connect+timeout entirely, backend leg now asks for `Connection: keep-alive`, poolability captured immediately after the response head is parsed — before the client-leg framing block rewrites the same fields); three global CLI flags (`--pool-max-idle`, `--pool-idle-timeout`, `--backend-timeout`) following the `--hc-*` pattern. 168 tests pass; release build holds the 4-warning baseline throughout every task. **Plan quality note:** during Task 1, the first implementer caught two real bugs in the plan text itself before writing any final code — a test whose push order couldn't produce the behavior its own comment claimed, and a missing `#[allow(dead_code)]` that would have broken the warning-baseline constraint — both fixed at the plan source (not just the dispatch message) so every downstream task's brief was already correct. During Task 6, a second implementer found and self-resolved an unanticipated consequence (`Server::new` becoming production-dead once its callers moved to a pool-config-aware constructor) using the exact same `from_spec` precedent, independently confirmed by that task's reviewer. **The task the whole level's design most worried about — Task 5's wiring — reviewed clean**, with the reviewer independently tracing (not trusting the report) that the two ordering-sensitive fields are captured before the client-leg rewrite and consumed correctly at the final call site, confirming the exact bug caught during planning did not creep back into the implementation. Live verification (done inline, not by subagent, since it needed real background processes and iterative debugging) hit two of its own bugs — a test backend defaulting to HTTP/1.0 (Python's `BaseHTTPRequestHandler`) and a hung-backend test script whose `accept()` loop let the health prober's connection garbage-collect and RST the client's in-flight one — both diagnosed to their actual cause and fixed in the harness, not the proxy, before re-confirming all six verification checks: connection reuse, per-request `Connection: close` honored, pipelining unaffected, idle-timeout eviction, and hung-backend 504 + breaker ejection. Every task's diff was independently re-verified (test counts, exact warning sets) rather than trusting subagent-reported numbers. All 6 code-task commits pushed to `github.com/Vasant18/Ferrum` main (`7809e8e` through `3064163`) via the `switching-gh-accounts` skill, each authored solely as Vasant18 with no co-author, gh credential switched back to the personal account after every push. Background test processes cleaned (`pgrep` clean).
- **2026-08-11 (later)** — Final whole-branch review of Level 7 (most capable model, looking at the six task-diffs as one composed feature rather than task-by-task) found one **critical cross-task interaction bug** that no individual task review could see: a pooled connection that dies between the idle-check and the first write (a genuine TOCTOU race — the backend closes it during its idle window) was neither retried nor answered. The connect-retry loop only covered `TcpStream::connect`; a pool hit broke out of that loop immediately, so the first write's failure hit a bare `?` that propagated past the already-exited retry logic straight to `handle_client`'s generic handler, which just logs and drops the connection — **no HTTP response at all**, not even a 502, for a case that should have retried on another server exactly like a failed connect already did. Confirmed independently by re-reading the actual source before dispatching a fix (not just trusting the reviewer's report). The review also caught four stale "dead until Task 5" comments that should have been removed when Task 5 removed the `#[allow(dead_code)]` attributes they were justifying. **Fix:** the non-idempotent request rewrite (`route.rules.apply_request` — appends `X-Forwarded-For`, etc.) now runs exactly once, before any connection attempt, producing a serialized `head_bytes` once; the connection-acquisition loop was extended so a write failure on either a pooled or freshly-dialed connection is handled identically to a connect failure (`mark_failure`, log, retry-or-502) — scoped *only* to the head-write, never to body-streaming or flush, since a body byte reaching a backend commits a possibly non-idempotent side effect and can never be safely replayed. Live-verified with a deliberately-poisoned pooled socket (TCP RST via `SO_LINGER`): an idempotent GET drawing the dead connection produces a `write failed` log line and a transparent retry to a healthy backend (client sees 200); a non-idempotent POST in the same situation correctly gets 502 with no replay. Fix dispatch took three attempts — two lost to transient infrastructure errors (API stream timeouts), not design problems; the correct design (serialize once, retry only the write) was worked out on the first attempt and carried forward via resume, then via a fresh self-contained brief once resume itself hit the same class of error. One agent's mid-edit had left a coherent-but-incomplete intermediate state (a duplicate rewrite block, two extra transient warnings); the next dispatch correctly detected and finished it rather than compounding it — verified by the coordinator reading the final source directly, not by trusting either report. Scoped re-review (most capable model) verdict: **ADDRESSED, no new findings**, independently re-confirmed. 168 tests pass; release build holds the exact 4-warning baseline throughout. This finding and its fix are the reason a whole-branch final review is worth the cost even after every task passed its own scoped review — cross-task composition bugs are structurally invisible to a reviewer who only ever sees one task's diff at a time.
