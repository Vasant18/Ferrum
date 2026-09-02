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
| 8 | Security & TLS (termination, mTLS, slowloris) | 🟢 **Implemented** (2026-08-19/20) | `tls.rs`: rustls + tokio-rustls (`ring` provider), PEM loading, TLS1.3+1.2 with no path to anything older, ALPN pinned to `http/1.1`, mTLS as `off`/`optional`/`required` via `WebPkiClientVerifier`, 4 startup guardrails, `TLS_HANDSHAKE_TIMEOUT`; `security.rs`: `ConnLimiter` (global + per-IP, `Drop`-released) + hand-rolled `Cidr`/`CidrList` (deny-beats-allow, allow-list is default-deny, IPv4-mapped normalized) + `Limits`/`parse_size`; `proxy.rs`: `handle_client`/`serve_one` now generic over `S: AsyncRead + AsyncWrite + Unpin`, `scheme` threaded into `ForwardContext` (fills the L5 seam), `BodyCopy` + `copy_body_limited` enforcing the body cap mid-stream, 431 on header count, 413 on body; `main.rs`: handshake moved INSIDE the spawned task, 10 CLI flags. 214 unit tests. Live-verified TLS, mTLS reject/admit, 413/431, CIDR, connection cap, slot reuse, and that 3 stalled handshakes don't block the accept loop. Quiz pending. |
| 9 | OS Internals (epoll/kqueue, Tokio internals) — theory | 🔵 **Studied** (2026-08-21) | Theory level, no production code. [`docs/level-9-os-internals.md`](docs/level-9-os-internals.md): the `read()`-blocks problem and C10K; `select`→`poll`→`epoll`/`kqueue`→`io_uring` and why O(n)→O(ready) is the whole ballgame; the full `.await`→`Waker`→reactor→`kevent` path traced through Ferrum's own `Conn::read_head`; this machine's actual stack (Darwin arm64 → **kqueue** not epoll, `mio 1.2.2`, 8 worker threads from `#[tokio::main]`); Ferrum's 3 production spawn sites and its await map (**only 3 of 13 files hold a production `.await`**; `balancer.rs` has zero); a blocking-the-executor audit that found the no-lock-across-await guarantee is **compiler-enforced**, not conventional; and nginx read back as the same architecture. Turned up 2 real findings, recorded not fixed. Quiz pending. |
| 10 | Observability (logs, metrics, tracing) | 🟢 **Implemented** (2026-08-24/25) | `metrics.rs`: from-scratch registry — status-class counters, `active_connections` gauge (RAII `ConnGauge`), fixed-bucket duration histograms (cumulative `le` computed at scrape time), hand-rolled Prometheus text renderer, zero locks/allocations at record time; `logging.rs`: leveled error log (`error!`..`debug!` macros, `--log-level`, hand-rolled RFC 3339) — per-request diagnostics demoted to `debug`, silent by default; `observe.rs`: access log upgraded to one JSON object per line (RFC 8259 escaping of attacker-controlled values, stage timings, `--log-plain` escape hatch); `proxy.rs`: per-stage `Instant` stamps (route/connect/TTFB) + metrics recorded at every exit path; `admin.rs`: separate admin listener (`--admin`, off by default) serving `/metrics` + `/health` JSON with a 5 s deadline. 230 unit tests. Live-verified JSON log via `jq`, counters/histogram/gauge movement, rejection attribution, `/health` ok→degraded→recovered, admin-plane isolation, `--log-plain` + `--log-level debug`. Quiz pending. |
| 11 | Caching (LRU, TTL, ETag, revalidation) | 🟢 **Implemented** (2026-08-26/27) | `cache.rs`: sharded approximately-LRU store (16 `std::sync::Mutex` shards, per-shard byte+entry budgets, lazy TTL, `Arc<[u8]>` bodies) + pure RFC 9111 semantics (GET-only, 200/301/404, `Authorization`/`Set-Cookie`/`no-store`/`private` gates, `s-maxage`>`max-age`, `no-cache`=store-but-always-revalidate, `Vary` two-step keying, full-key equality so hash collisions miss); `proxy.rs`: lookup after middleware (auth before cache), fresh hit skips the balancer lease entirely, stale entries send `If-None-Match` and a 304 re-stamps+serves (`X-Cache: REVALIDATED`), `TeeWriter` captures streamed bodies with zero extra reads, RFC 9111 §4.4 unsafe-method invalidation, client `If-None-Match` answered 304 at the proxy; `;cache[=SECS]` route option (third partition family), `--cache-max-*` flags, `cache_events_total` metrics, `"cache"` access-log field, `X-Cache`+`Age` headers. 250 unit tests. Live-verified all 13 checks incl. both revalidation legs, Vary variants, POST invalidation, LRU eviction under a 16 KB budget. Quiz pending. |
| 12 | Production Features (graceful shutdown, config, hot reload) | 🟢 **Implemented** (2026-09-02) | `config.rs`: hand-rolled TOML-subset parser that LOWERS the file onto the existing CLI vocabulary (one parser per value forever; CLI-beats-file precedence falls out of arg ordering; duplicate keys are errors; line-numbered messages) + `--config`/`--validate` (nginx -t); `main.rs`: parse loop extracted into `parse_settings` (boot, --validate, and reload share ONE path), accept loop `select!`s accept vs SIGTERM/SIGINT/SIGHUP, graceful shutdown = drop listener → drain flag → poll L8's ConnLimiter to zero under `--drain-timeout` (double-signal skips the wait), SIGHUP reload builds the whole new table off to the side and swaps one `Arc` pointer (invalid config rejected wholesale, old config stays live); `proxy.rs`: `RwLock<Arc<RouteTable>>` snapshotted PER EXCHANGE (mid-flight keeps its table, next keep-alive request sees the new one), drain forces `Connection: close`; `health.rs`: probers hold `Weak<Upstream>` and expire with their table. Graceful restart + worker processes explained, deliberately not built. 261 unit tests. Live-verified: file boot, --validate both ways, CLI-over-file, reload under a concurrent slow request, broken reload rejected, clean drain (`Connection: close` + exit after in-flight completes), deadline cut of a too-slow request. Quiz pending. |
| 13 | Basic WAF (SQLi/XSS/traversal detection, reputation) | 🟢 **Implemented** (2026-09-02) | `waf.rs`: normalization first (two-pass percent decode with double-encoding flagged AND scored, entity decode, whitespace collapse, null-byte flag, path canonicalization with climb-above-root detection) + a ~16-rule table (data, not code) scanned over path/query/UA/Referer + CRS-style anomaly scoring (lone quote 2, unambiguous attack grammar 10, block only ≥ threshold) + `Reputation` (16-shard strikes → temp ban with L4-style doubling backoff, lazy decay, process-wide store surviving L12 reloads); wired as an L6 middleware at log → request-id → **waf** → ratelimit → auth → authz; `;waf=block\|detect` + `;waf-threshold=N`; `--waf-ban-after/-secs`; rule names log-only (no payload-tuning oracle); `waf_events_total` metrics + `waf_score` log field. Body inspection deliberately absent (streams stay flat-memory). 280 unit tests. Live-verified: SQLi/XSS/traversal/double-encoded payloads 403'd with zero backend contact, benign lookalikes pass, 3 convictions → ban → innocent request also 403 → decay → served, detect mode forwards + logs, unprotected route untouched. Quiz pending. |
| 14 | Scalability (clusters, HA, anycast) — theory | 🔵 **Studied** (2026-09-02) | Theory level, no production code — the course's closing move. [`docs/level-14-scalability.md`](docs/level-14-scalability.md): who balances the load balancers (DNS → VRRP → anycast → L4-over-L7, and why they layer); **a verified audit of Ferrum's own state** against the KB's don't-share / share-approximately / share-for-real hierarchy — route table, health state, pools, and metrics ship to N instances unchanged; rate limits, WAF reputation, and the cache go quietly approximate (×N admission, ×N strike budgets, ×N misses — each with its remedy); only "exactly-one-does-X" needs consensus (etcd leases; *use a store, don't implement Raft*); sessions externalize so `iphash` affinity becomes unnecessary; CDN integration lands on three seams already built (L5 XFF trust + L8 CidrList, L11 as cache layer two via `s-maxage`, L7 pools serving origin pull); every level's fleet-scale reappearance mapped (chash → Maglev, breakers → fleet membership, SIGHUP → xDS, drain → rolling deploys). **Course complete: 14/14.** Quiz pending. |

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

## Level 8 — what was built

- [x] **`tls.rs` — the one place this course stops building from scratch.**
      `rustls` + `tokio-rustls`, with the crypto provider pinned to **`ring`**
      rather than the `aws-lc-rs` default: a far lighter build with no
      cmake/NASM toolchain requirement. First new dependencies since Level 2's
      `regex`, and the knowledge base names hand-rolling crypto or certificate
      parsing as this level's mistake #1 — the failure mode is not a visible bug,
      it is a silent loss of confidentiality.
- [x] **Levels 1–7 run over TLS completely unchanged**, because Level 1 made
      `Conn<S>` generic over `S: AsyncRead + AsyncWrite + Unpin` instead of
      concrete over `TcpStream`, and `tokio_rustls::server::TlsStream` satisfies
      both. Seven levels later that single decision *is* this level's entire
      integration cost: `handle_client` and `serve_one` were the only two
      signatures pinning the concrete type. Generics rather than an
      `enum Stream { Plain, Tls }` — this is the hottest loop in the program and
      an enum would cost a match on every read and write; the price is two
      monomorphized copies in the binary, the right trade for a proxy.
- [x] **The handshake runs INSIDE the spawned task, never in the accept loop.**
      The most important decision in the level, and it is about our code, not
      rustls. Awaiting `acceptor.accept()` in the accept loop would let one
      client that connects and sends a single `ClientHello` byte stall *every*
      new connection process-wide — a one-attacker, one-line total denial of
      service that would pass every functional test, because a proxy serving one
      client at a time still works perfectly. Level 1's own comment on that loop
      already stated the rule ("anything slow in this loop delays every new
      client"); TLS is where breaking it becomes catastrophic rather than slow.
- [x] **`TLS_HANDSHAKE_TIMEOUT` (10s)** — the TLS-layer analogue of Level 1's
      `HEAD_READ_TIMEOUT`, and not optional: without it slowloris simply moves
      one layer down. A connection stuck mid-handshake never produces a request
      head, so the head deadline never *arms*, let alone fires. Deliberately
      tighter than the 30s head deadline — a handshake is a fixed small number
      of round trips with no user think-time in it.
- [x] **mTLS as three modes** (`off`/`optional`/`required`) via
      `WebPkiClientVerifier` against `--tls-client-ca`. `optional` exists because
      it is the only safe migration path: enable it, watch which callers actually
      present certificates, *then* flip to `required`. Going straight to
      `required` on a live listener is an outage. A misspelled mode is a startup
      error, never a silent downgrade — quietly reading `requried` as `off` would
      disable client authentication on a listener whose operator believes it is
      enforced.
- [x] **Four startup guardrails, both directions of the trap** (exit 1, the
      Level-5/6 discipline): cert without key, key without cert, client-auth with
      no CA to validate against, and — the inverse, easier-to-miss one — a CA
      supplied while client-auth is off, where the bundle would be loaded, never
      consulted, and read as enforcement to whoever wrote the config. TLS is
      built **before** `bind`, so a bad certificate fails with no socket ever
      opened.
- [x] **`security.rs` — armoring, answering this level's threat table.**
      `ConnLimiter` gives a global ceiling plus a per-source-IP cap, checked
      before the spawn (the check has to be cheaper than the attack). This is the
      piece Level 1's per-connection deadline *cannot* provide: a deadline does
      not help when the attacker simply opens more connections. Released by
      `Drop` on an RAII guard — the Level 3 `Lease` pattern, for a sharper
      version of the same reason: a connection ends on many paths (clean close,
      parse error, head timeout, failed handshake, a task unwinding from a
      panic), an explicit `release()` will eventually be missed on one, and a
      leaked *connection slot* is permanent where a leaked in-flight count merely
      biases least-connections.
- [x] **Three subtleties in the limiter that a naive version gets wrong.**
      (1) The global claim uses `fetch_update`, not `load`-then-`fetch_add`, so
      two accepts cannot both observe `total == max - 1` and both proceed —
      unlike Level 4's breaker counters, where a lost increment merely delays a
      state change, a lost increment here means the ceiling does not hold.
      (2) A per-IP refusal **rolls back** the global claim it already made,
      otherwise a source hammering its own cap would leak the global counter to
      exhaustion and take the whole listener down — the refusal path becoming the
      outage. (3) The map entry is *removed* when a source's last connection
      closes, not left at zero, or the map grows one permanent entry per address
      ever seen: a slow memory leak reachable by a source-address scan.
- [x] **Hand-rolled CIDR allow/deny**, no new dependency (the practice this
      project already follows for FNV-1a in L3, duration parsing in L4, base64
      and constant-time compare in L6). Matched against the **socket peer
      address only**, never `X-Forwarded-For` — Level 5 took this stance for
      `X-Real-IP` and Level 6 for the rate-limit key, and this is the third time:
      a deny list keyed on something the client controls is not a deny list.
      Deny beats allow (a broad `--allow-cidr 10.0.0.0/8` must not silently
      re-admit a host the operator just banned) and a non-empty allow list is
      default-deny (otherwise `--allow-cidr` is a no-op).
- [x] **IPv4-mapped normalization at the edge.** A listener on `[::]` reports an
      IPv4 client as `::ffff:203.0.113.7`. Without collapsing that once, at the
      edge, an operator's perfectly reasonable `--deny-cidr 203.0.113.0/24`
      matches nothing — a deny list that appears configured and enforces
      *nothing*, which is the worst available failure mode for this feature.
- [x] **A denied connection is closed with no response — deliberately not 403,
      reversing the design doc.** nginx's `deny` does answer 403, so 403 was the
      obvious default and is what the spec originally said. But on a TLS listener
      the proxy cannot send any HTTP status without first completing a handshake,
      and handshaking for an address already refused means spending an
      RSA/ECDHE operation on the attacker's behalf — turning the cheapest
      rejection in the system into one of the most expensive. Both alternatives
      were worse: 403 on plaintext but drop on TLS means one config behaving two
      ways depending on a flag, and handshake-then-403 everywhere is a DoS
      amplifier. The connection limits shed load the same way, so the two gates
      stay consistent.
- [x] **Body caps enforced WHILE streaming**, never buffer-then-check — this
      level's named mistake #1 ("the damage is done"). Level 1's windowed copy
      loop is what makes the correct version cheap: a loop already sees every
      byte, so enforcement is a running total and a comparison, not a new
      mechanism. The framings are deliberately asymmetric: a declared
      `Content-Length` is knowable before any byte moves, so an over-cap request
      is refused with **413 before routing, before the middleware chain, and
      before any backend socket opens** — strictly better than
      stream-and-abort, since the client gets a clean answer and the backend is
      never contacted. `Chunked` has no declared size, so mid-stream at a chunk
      boundary is the *only* possible enforcement point, and by then the head is
      already at the backend: that exchange is unsalvageable by construction and
      closes both legs.
- [x] **The chunked cap counts decoded payload, not wire bytes.** Framing
      overhead is attacker-controlled — a million 1-byte chunks carry a megabyte
      of framing around a megabyte of data — so a wire-byte cap would reject
      honest large-chunk requests while admitting pathological small-chunk ones.
      The overhead is separately bounded by `read_line`'s buffer check.
- [x] **`BodyCopy { Done { reusable }, TooLarge }` instead of
      `io::Result<bool>`.** "Too large" is not an I/O error and must not be
      handled like one: the socket is healthy, the client is well-behaved by
      TCP's standards, and the right answer is a specific HTTP status rather than
      a dropped connection with a logged errno. A distinct variant forces the
      caller to decide — a `?` cannot silently swallow a limit breach into the
      generic error path, which is exactly the property wanted at a security
      boundary.
- [x] **Header count capped at 431** (RFC 6585). Level 1's 16 KB
      `MAX_HEAD_BYTES` bounds head *size* but not field *count*: ~8,000 one-byte
      header lines fit inside that budget, and every one multiplies the linear
      header scans this proxy performs per request (routing, hop-by-hop
      stripping, rewriting, framing, the middleware chain). Checked before
      routing, so the work is refused before it starts.
- [x] **Filled the Level 5 seam.** `proxy.rs` had carried
      `scheme: "http", // Level 8 sets "https" after TLS termination` since
      Level 5; `X-Forwarded-Proto` now reports what the client actually spoke.
      It is the *listener's* scheme, never a client-supplied hint — a backend
      gating secure cookies or redirect-to-HTTPS on that header must be reading
      an observation, not an assertion.
- [x] **Secure defaults.** TLS is opt-in (every Level 1–7 invocation still
      works untouched), but the armoring half is ON by default with safe values:
      an unbounded listener is a memory-exhaustion primitive, not a neutral
      default. rustls gives no path to SSLv3 or TLS 1.0/1.1 at all — that
      absence is the strongest form of "the config a lazy user gets must be the
      safe one," a config where the unsafe option cannot be typed. Plus a
      warning when a private key is readable beyond its owner (warn, not refuse:
      key material legitimately arrives group-readable from plenty of secret
      managers, and a proxy that will not start over a permission bit it merely
      dislikes is one operators route around).
- [x] 214 unit tests (168 from Level 7 kept green; +13 `tls`, +26 `security`,
      +7 `proxy` body-cap). Release build holds the exact 4-warning baseline —
      and the two dead-code warnings this level introduced were resolved by
      **making the methods real** rather than by `#[allow(dead_code)]`:
      `in_flight` now reports the in-flight count on every refusal line (the
      number that distinguishes "one abusive source" from "genuinely at
      capacity"), and `is_empty` suppresses the banner's access line when no
      policy exists.
- [ ] **Level 8 quiz — Vessey to answer before Level 9** (questions below)

**Verified end-to-end (2026-08-20):** release binary against a
`ThreadingHTTPServer` echo backend on :9001, with a self-signed server
certificate (SAN `DNS:localhost,IP:127.0.0.1`) and a separate test CA issuing a
`clientAuth` certificate for the mTLS checks.

- **TLS termination:** `curl https://localhost:8443/hello` → 200 relayed to the
  backend, banner reporting `(https)` and `TLS1.3+1.2, client-auth=Off`.
- **The Level 5 seam:** the backend received `x-forwarded-proto: https`
  alongside `x-forwarded-for`, `x-real-ip`, and `x-forwarded-host` — the whole
  point of threading `scheme` through.
- **mTLS `required` both ways:** no client certificate → handshake refused with
  `tls handshake failed: peer sent no certificates`; a CA-issued client
  certificate → 200, request served.
- **413 and 431:** with `--max-body 100 --max-headers 5`, a 50-byte body → 200,
  a 500-byte body → `413 Payload Too Large`, 12 headers →
  `431 Request Header Fields Too Large`.
- **Rejections cost the backend nothing:** a baseline-versus-after hit count
  across one 413 and one 431 showed the backend saw *only* the two measurement
  probes — zero rejected requests reached it.
- **CIDR both semantics:** `--deny-cidr 127.0.0.0/8` refused our connection
  (`refused: address not permitted`); `--allow-cidr 10.0.0.0/8`, which excludes
  us, *also* refused — confirming a non-empty allow list is default-deny rather
  than merely additive.
- **Connection cap and slot reuse:** with `--max-conns-per-ip 3`, six
  slowloris-shaped connections gave exactly 3 held and 3 refused, each refusal
  logged with the in-flight count; after closing them a fresh request returned
  200, proving `Drop` released the slots.
- **The accept-loop guarantee, measured:** with **three handshakes deliberately
  stalled** (one TLS record byte, then silence), a real client was served in
  **0.03s**. This is the level's central claim and the one thing a unit test
  cannot check.
- **The handshake deadline fires:** a stalled connection was closed at exactly
  **10.0s** with `tls handshake timed out after 10s`.
- **Backward compatibility:** the Level 1 shorthand
  `rproxy LISTEN BACKEND` → 200 unchanged; and an invocation combining L4
  `--upstream …;health=`, L5 `;strip=`, L6 `;rate=`, and L7 `--pool-max-idle`
  served correctly with `/api/users` still arriving as `/users`.
- **All 8 startup guardrails** exit 1 with a specific, actionable message.
- **A verification bug worth recording.** The first guardrail run reported all
  four cases exiting 1 and *looked* like a pass. It was not: unquoted `$args` in
  **zsh does not word-split** (unlike bash), so each flag pair arrived as one
  argument, fell through to the route-spec arm, and exited 1 with `route spec
  missing '=TARGET'` — the right exit code for entirely the wrong reason. Caught
  by reading the error text instead of the exit status, and re-run through a
  shell function taking `"$@"`. Level 7's verification hit this class twice (a
  Python backend defaulting to HTTP/1.0, a test script whose `accept()` loop let
  the health prober's socket garbage-collect and RST the client's); the standing
  lesson is that **a passing test harness is itself untested code.** Separately,
  one new unit test wrote 200 KB into `conn_with`'s 64 KB duplex and deadlocked
  the suite — the test's bug, not the proxy's; reduced to 32 KB, which still
  exercises the multi-window path.

**Run it (TLS):** `cargo run --release -- 127.0.0.1:8443 --tls-cert server-cert.pem --tls-key server-key.pem '/=127.0.0.1:9001'`

**Run it (mTLS + armoring):** `cargo run --release -- 127.0.0.1:8443 --tls-cert server-cert.pem --tls-key server-key.pem --tls-client-ca ca-cert.pem --tls-client-auth required --max-conns-per-ip 32 --max-body 1m --deny-cidr 203.0.113.0/24 '/=127.0.0.1:9001'`

### Level 8 quiz — Vessey to answer before Level 9

1. `Conn<S>` was generic from Level 1 and this level finally used it. Name the
   two signatures that had to change, and explain why `set_nodelay` could not
   stay where it was.
2. The TLS handshake is awaited inside the spawned task, not in the accept loop.
   Describe the exact attack the other placement enables, and say why every
   functional test would still pass.
3. There are now two deadlines that both defend against slowloris
   (`HEAD_READ_TIMEOUT` and `TLS_HANDSHAKE_TIMEOUT`). Why does the first one not
   cover the case the second one does?
4. `ClientAuth::Optional` looks strictly weaker than `Required`. What is it for,
   and what breaks if you skip it?
5. Two of the four TLS startup guardrails catch a *missing* thing; one catches a
   *present* thing (`--tls-client-ca` with client-auth off). Why is that third
   one worth an exit-1 rather than a warning?
6. `try_acquire` claims the global counter with `fetch_update` rather than
   `load` then `fetch_add`. Level 4's breaker happily uses `Relaxed` atomics and
   tolerates lost increments. What makes this counter different?
7. A per-IP refusal rolls back the global claim. Construct the outage that
   happens if it does not.
8. The per-IP map removes an entry when a source's last connection closes,
   rather than leaving a zero. What attack does that prevent?
9. A denied CIDR closes the connection instead of answering 403, even though
   nginx answers 403. Give the TLS-specific reason, and say why "403 on
   plaintext, drop on TLS" would be worse than either consistent choice.
10. `Content-Length` over the cap is refused before routing, but a chunked body
    over the cap is only caught mid-stream. Explain why the second case leaves
    *both* connections unusable, and why that is unavoidable rather than a
    shortcoming of the implementation.
11. The chunked cap counts decoded payload rather than bytes on the wire.
    Construct the request that would defeat a wire-byte cap.
12. Body-too-large is a `BodyCopy::TooLarge` variant rather than an
    `io::Error`. What specifically goes wrong if it were an error that callers
    reach with `?`?
13. Level 1 already caps the head at 16 KB. Why was a separate header-*count*
    cap still needed, and what does the count protect that the byte cap does
    not?
14. `X-Forwarded-Proto` is set from the listener's scheme rather than from
    anything the client sent. Name a concrete backend behaviour that becomes a
    vulnerability if you trust the client's value instead.
15. An IPv4 client on a `[::]` listener arrives as `::ffff:a.b.c.d`. Describe
    the failure an operator would see if `normalize_peer` did not exist, and why
    it is more dangerous than an outright error.

## Level 9 — what was studied

Theory level. **No production code changed** — that is the correct outcome, not a
shortfall: Levels 1–8 already run on this machinery, so the work was reading the
existing code through a lower lens rather than adding to it. Full write-up in
[`docs/level-9-os-internals.md`](docs/level-9-os-internals.md).

- [x] **The problem, precisely stated.** A blocking `read()` parks the calling
      thread, so thread-per-connection at 10k connections means 10k stacks and a
      scheduler that does nothing but context-switch — the C10K problem. The fix
      is to change the question from "give me data on THIS socket, I'll wait" to
      "here are 10,000 sockets, wake me when ANY has data." Two ingredients:
      `O_NONBLOCK` sockets and a kernel readiness API. **Ferrum never sets
      `O_NONBLOCK` itself** — Tokio does it for every `TcpStream`/`TcpListener`,
      which is the first thing the abstraction hides.
- [x] **The readiness-API evolution, and why one line of it matters.**
      `select()` (1983, O(n) scan, ~1024 FD cap) → `poll()` (1986, O(n), no cap)
      → `epoll`/`kqueue` (2002/2000, **O(ready)**) → `IOCP`/`io_uring`
      (completion-based: "tell me when it's DONE" rather than "tell me when I
      may read"). The O(n)→O(ready) transition is the entire ballgame: with
      `select`, 9,999 idle connections cost work on *every* wait; with `epoll`,
      they cost nothing until they have data. That single property is why 10k
      idle connections are cheap and why C10K dissolved.
- [x] **What is actually running on this machine**, verified rather than assumed:
      `Darwin 25.6.0 arm64` → **`kqueue`, not `epoll`**. Every mental model in
      the knowledge base is written around epoll because Linux is where proxies
      deploy, but the code exercised locally is the BSD path. Reactor is
      **`mio 1.2.2`** — a *transitive* dependency, present in `Cargo.lock` and
      never named in `Cargo.toml`. Runtime is `tokio 1.53.1` with
      `features = ["full"]`, hence the **multi-threaded** scheduler and **8
      worker threads** (`hw.ncpu = 8`).
- [x] **The full path from `.await` to `kevent`**, traced through this proxy's
      own code rather than a toy example: `serve_one` → `client.read_head()` →
      `self.stream.read(&mut self.buf[self.filled..])` → non-blocking `read()`
      **attempted immediately** (the fast path — data already in the kernel
      returns with no reactor involvement at all, so async is not "always slower
      by a scheduler hop") → on `EWOULDBLOCK`, register a `Waker` and return
      `Pending` → executor runs other tasks and steals across workers → kernel
      delivers bytes → `kevent()` returns → `waker.wake()` → re-poll, and **the
      state machine resumes exactly at the await point** with every local intact,
      because those locals are fields of the compiler-generated struct.
- [x] **The load-bearing consequence:** an `async fn` is inert until polled.
      There is no thread behind an un-awaited future; constructing one does no
      work whatsoever. This is the single point that most often survives eight
      levels of async programming as a misconception.
- [x] **Ferrum's whole concurrency structure is three `tokio::spawn` sites:**
      `main.rs:291` (one task per connection), `health.rs:25` (one prober per
      upstream), `health.rs:70` (one task per concurrent probe). Task-per-
      connection is what sidesteps C10K here — a task is a heap state machine
      scheduled onto one of 8 workers, not a thread, so 10k connections means
      10k parked state machines and not 10k stacks. Level 1 made that choice
      before the project had any vocabulary to justify it; this level supplies
      the vocabulary.
- [x] **The await map, and the design decision hiding in it.** Counting `.await`
      in code (excluding the comment mentions that inflate a naive `grep` here by
      ~5%): **72 production, 61 test.** Only **three of thirteen files** contain a
      production `.await` — `proxy.rs` (57), `health.rs` (10), `main.rs` (5).
      Everything else is synchronous code merely *called from* async contexts.
      `balancer.rs` is the sharpest case: 1,750+ lines of seven balancing
      algorithms, a three-state breaker, and a LIFO connection pool with **zero**
      production await points (its 13 are tests building real `TcpStream` pairs).
- [x] **Four levels independently made the same optimization without naming it.**
      L1 put parsing in `http.rs` as functions over byte slices; L5 made
      `rewrite.rs` pure transforms over head structs ("no sockets, no async, no
      I/O"); L6 deliberately rejected the textbook `async fn handle(req, next)`
      middleware trait; L8 kept `tls.rs` to config construction with the
      handshake `.await` in `main.rs`. Read through this level's lens all four are
      one decision: **keep the generated state machine small.** Every `.await` in
      a function makes every live local a field of its future, which is why
      `serve_one` being long is tolerable but an async `rewrite.rs` would not
      have been.
- [x] **The cardinal sin, audited rather than asserted.** Blocking a worker costs
      12.5% of capacity here and shows up as an unexplained p99 spike; blocking
      all 8 is a hang. Three classic causes, each checked against the tree:
      **(1) Locks across `.await` — structurally impossible.** Every production
      function that takes a lock (`take_conn`, `return_conn`, `try_acquire`,
      `release`, `RateLimiter::allow`) is a plain `fn`, not an `async fn`. Since
      `.await` cannot appear in a non-async fn, **the compiler enforces this**
      rather than a review convention. L6, L7, and L8 each wrote a comment
      explaining their `std::sync::Mutex` choice; that signature list is the proof
      those comments are still true. Corroborating: `tokio::sync` appears in this
      codebase **only inside comments explaining why it is not used**, and
      `spawn_blocking` and `thread::sleep` appear zero times.
      **(2) Synchronous `std::fs` — present but harmless:** `tls.rs` reads
      certificates in `TlsArgs::build()`, which `main.rs` calls *before*
      `TcpListener::bind`, so it runs once at startup with no request work to
      starve. L8 ordered it that way to fail before announcing a listener; the
      async-hygiene benefit is a coincidence, and is recorded as one rather than
      claimed as foresight.
      **(3) CPU-bound work — one real instance, safe for a non-obvious reason:**
      `router.rs:53` runs `re.is_match(path)` on the worker for every `~regex`
      route. In nginx or any PCRE-based proxy this is a live DoS vector, since
      catastrophic backtracking turns one crafted path into seconds of frozen
      worker. It is safe here only because Rust's `regex` crate has **no
      backtracking and guarantees linear time** — the blowup is not expressible.
      The safety comes from a Level 2 dependency choice, and swapping that crate
      for a backtracking engine would silently reintroduce the vulnerability.
- [x] **nginx, read back fluently.** One master process forks N single-threaded
      workers; each runs `epoll_wait` in a loop; connection state lives in
      hand-written C structs; `SO_REUSEPORT` spreads accepts. **Tokio and nginx
      are the same architecture wearing different clothes** — the difference is
      who writes the state machines, nginx's authors by hand or Rust's compiler
      for free. One asymmetry worth naming: nginx is process-per-core with no
      shared mutable state, so it has no lock-contention problem at all, while
      Tokio's threads-per-core model is exactly why L6, L7, and L8 each needed a
      sharding decision. Ferrum pays a cost nginx does not, and buys a route
      table and connection pool shared across all cores with no IPC.
- [ ] **Level 9 quiz — Vessey to answer before Level 10** (questions below)

### Two findings this reading turned up — recorded, not fixed

1. **Backend addresses are re-resolved on every connect.** `Server.addr` is a
   `String` (`balancer.rs:402`), and startup validation (`balancer.rs:973`) checks
   only the *shape* — non-empty host, port parsing as `u16` ≥ 1 — then keeps the
   string. So `TcpStream::connect(&addr)` (`proxy.rs:853`) goes through
   `ToSocketAddrs` on every pool miss. For `127.0.0.1:9001` that parse is trivial;
   for a DNS name like `api.internal:8080`, which the shape check happily accepts,
   it is a `getaddrinfo`. Tokio routes that onto its blocking pool rather than a
   worker, so no core freezes — but it consumes a blocking-pool thread per connect
   with **no DNS caching and no TTL awareness**. Level 7's pooling hides most of
   it (a pool hit skips `connect` entirely), which is why it has never surfaced.
   Not fixed because the obvious fix is wrong: resolving once at startup breaks
   DNS-named backends that move, and the correct answer is a TTL-aware resolver
   cache — real work that deserves its own level, not a theory-chapter aside.
2. **The runtime's shape is entirely implicit.** 8 workers, a work-stealing
   multi-threaded scheduler, and a blocking pool all exist purely because
   `#[tokio::main]` defaults to them. Nothing in the codebase mentions any of it,
   and `features = ["full"]` points the wrong way — it reads as "give me
   everything" rather than "select the multi-threaded scheduler." This matters the
   first time anyone tunes the proxy, because worker count is a real dial and it
   is currently invisible. Not changed, because changing a default with no
   benchmark behind it is precisely the "measure, don't guess" mistake Level 7
   warned about — and there is still no benchmark.

**Explicitly not done:** no `io_uring` experiment (Linux-only; this machine is
kqueue), no runtime tuning (no benchmark to justify it), no DNS caching (a
feature, not a theory aside), no `spawn_blocking` added for symmetry, and no
benchmarks — the missing `wrk`/`oha` baseline stays Level 7's recorded debt
rather than being quietly reassigned here.

### Level 9 quiz — Vessey to answer before Level 10

1. `select()` and `epoll` both let one thread watch many sockets. State the
   complexity difference precisely, and explain why it is the reason 10,000
   *idle* connections are cheap under one and ruinous under the other.
2. `epoll` is readiness-based and `io_uring` is completion-based. Give the
   question each one answers, and say why the completion model needs fewer
   syscalls.
3. This proxy runs on `kqueue`, not `epoll`. What in the codebase had to change
   to make that true?
4. A future is "inert until polled." Someone writes
   `let f = fetch_backend(); do_other_work().await; f.await;` expecting the fetch
   to overlap with `do_other_work`. What actually happens, and what would they
   need instead?
5. When a task parks at an `.await`, its local variables survive. Where do they
   physically live, and why does that make a 500-line `async fn` with 100 await
   points more expensive than ten 50-line ones?
6. Tokio attempts the non-blocking `read()` syscall *before* involving the
   reactor at all. Why is that fast path important, and what would the
   latency profile look like without it?
7. Only three files in this crate hold a production `.await`, and `balancer.rs`
   holds none despite implementing seven algorithms, a circuit breaker, and a
   connection pool. Explain why that is a design achievement rather than a
   coincidence.
8. Level 6 rejected the textbook `async fn handle(req, next) -> Response`
   middleware signature. Name the two things that trait would have forced, and
   which later level it would have broken before it was written.
9. Every production function in this codebase that takes a lock is a plain `fn`.
   Explain why that makes "never hold a lock across `.await`" a *compiler-
   enforced* property rather than a convention — and why that is stronger than
   the comments in `ratelimit.rs`, `balancer.rs`, and `security.rs` that argue
   for it.
10. `router.rs:53` runs a regex on a worker thread for every request on a
    `~regex` route. Explain why this is safe in Ferrum but would be a denial-of-
    service vector in nginx, and name the single change that would make it
    dangerous here.
11. `tls.rs` performs synchronous `std::fs` I/O. Why is that not a
    blocking-the-executor bug, and what would have to move for it to become one?
12. nginx forks single-threaded workers; Tokio runs 8 threads with work stealing.
    Name one problem nginx's model does not have, and the corresponding
    capability Ferrum gets in exchange — citing a specific decision from Levels
    6, 7, or 8.
13. `TcpStream::connect(&addr)` takes a `String` here. Describe what happens on
    each pool miss when that string is a DNS name, why it does not freeze a
    worker, and why "just resolve once at startup" is the wrong fix.
14. This proxy runs 8 worker threads and nothing in the source says so. Where
    does that number come from, and what would you need before changing it?

## Level 10 — what was built

Observability: the three pillars (logs, metrics, traces), from scratch. Design
at [`docs/superpowers/specs/2026-08-24-level-10-observability-design.md`](docs/superpowers/specs/2026-08-24-level-10-observability-design.md).
The knowledge base frames the level as the 3 a.m. question — "the site is slow"
must resolve to *which backend, which route, which percentile* in 30 seconds.

- [x] **Zero new dependencies, and that was the design's first decision.** The
      lessons of this level ARE the internals — the Prometheus text format, why
      histograms are pre-allocated buckets rather than stored samples, why
      counters must be atomics — and the `metrics`/`tracing` crates make
      exactly those invisible. Unlike L8's crypto, nothing here is dangerous to
      hand-roll: a wrong bucket is a wrong number on a graph, not a hole. The
      KB recommends the `tracing` crate because spans follow tasks across await
      points; that solves a problem Ferrum does not have — L9 established the
      whole request lifecycle lives in ONE task, so a timing struct passed down
      the call path does the same job with zero magic. `Cargo.toml` still
      reads: regex (L2), rustls family (L8), everything else ours.
- [x] **`metrics.rs` — the registry, built like the pool it instruments.** The
      L7 rule applied to our own instrumentation: no mutex, no allocation at
      record time. Counters are `AtomicU64` labeled by status *class*
      (`code="2xx"`, 5 values) × upstream — label sets fixed at startup from
      declared config, never from the request, because a path label would be
      an attacker-controlled cardinality bomb (`curl /$(uuidgen)` allocating
      series forever). `UpstreamId` pre-resolves the name→slot lookup once per
      request so recording is pure index+`fetch_add`. The histogram stores each
      observation in exactly ONE of 9 fixed buckets; the cumulative `le`
      semantics Prometheus requires are computed at *scrape* time (`snapshot`),
      because scrapes are ~1/15 s and observations are thousands/s — do the
      O(buckets) work on the rare path. `sum` is integer micros because there
      is no atomic f64. `Ordering::Relaxed` everywhere, with the "why that
      never loses an increment" argument in the module docs — and a 8-thread ×
      10k-increment hammer test backing the claim, same pattern as L6's
      sharded limiter test. Never-touched series are elided from `render()`
      rather than emitted as zeros.
- [x] **`logging.rs` — the error log, and the access/error split.** One
      stdout stream for machines (JSON access log), one stderr stream for
      humans (leveled error log) — independently redirectable, which is the
      entire reason the split exists. Hand-rolled `error!`/`warn!`/`info!`/
      `debug!` macros over a global `AtomicU8` level (`--log-level`, default
      info): the macro checks the level BEFORE evaluating its arguments, so a
      suppressed `debug!` costs one atomic load, not a thrown-away `format!` —
      that gating IS the performance story of log levels. The per-request
      routing/rewrite/pick diagnostics that previously printed unconditionally
      on every request (priceless while building L2–L8, noise in operation)
      are now `debug!` and silent by default. RFC 3339 UTC timestamps via
      Howard Hinnant's `civil_from_days` (~15 lines, verified against Python
      at three fixed points including a century non-leap boundary) rather than
      a `chrono` dependency.
- [x] **`observe.rs` — the access log goes JSON.** One object per line, emitted
      by the same outermost-middleware `on_response` as before:
      `ts` (wall-clock, for cross-system correlation) + `dur_ms`/`route_ms`/
      `connect_ms`/`ttfb_ms` (monotonic-derived — never mix the two clocks'
      jobs), status, upstream/backend, user, `pooled`, `rejected_by`. The L6
      log-injection lesson upgraded for the format change: in a JSON log an
      unescaped `"` in the attacker-controlled target doesn't just forge a
      line, it forges *fields* — and a raw control byte makes the line
      unparseable, silently dropping it from every `jq` query, which is an
      attacker's favorite outcome. RFC 8259 escaper on every dynamic value;
      keys are static. Stage timings are `null` (not 0, not -1) when the
      request died before the stage — zero is a legitimate measurement (a pool
      hit connects in ~0 ms) and a sentinel would poison aggregation.
      `--log-plain` keeps the old `key=value` line for eyeball debugging.
- [x] **`proxy.rs` — timing capture + the recording discipline.** The clock
      starts AFTER `read_head` returns, not before: on a keep-alive connection
      the head-read spends its life waiting for the client to *decide* to send
      another request, and folding that think-time in would make every
      keep-alive connection look slow. Stamps at route-matched,
      backend-in-hand (dialed or pooled), response-head-parsed (the honest
      TTFB from where we sit), and completion. `requests_total` is recorded at
      **every** exit path — 431/413/400 pre-route (as `upstream="-"`), 404,
      middleware rejections (double-counted into `rejected_total{by=...}`
      deliberately: "how many 429s" and "which layer is rejecting" are
      different questions), 502/504 connect failures, and the one success-path
      record placed AFTER the last body byte flushes — a duration that stopped
      at the response head would hide the transfer time of a slow client or a
      huge body. Requests that die mid-exchange via `?` are NOT in
      `requests_total` (that series means "the client got an answer"); the
      error log and breaker carry the deaths.
- [x] **`admin.rs` — the admin plane is a different socket.** `/metrics` and
      `/health` on their own listener (`--admin ADDR`, no default, docs say
      `127.0.0.1:9100`): `/metrics` leaks route names, backend addresses, and
      error rates — reconnaissance gold — so exposure is an explicit operator
      choice, a backend legitimately serving `/metrics` is never shadowed, and
      the main listener's routing is untouched. This is Envoy's admin port and
      HAProxy's stats socket. Deliberately tiny: reuses the battle-tested
      L1 parser (a second hand-written one is a second bug surface) and
      nothing else — no routing, no middleware, no keep-alive, one request per
      connection, `Connection: close`, a whole-exchange 5 s deadline (not
      exempt from slowloris thinking), 404 with no path echo. Bound in `main`
      before the banner so a bad `--admin` address fails startup with exit 1,
      same posture as the L8 TLS guardrails. `/health` reports the PROXY's
      own liveness with an upstream summary — and stays HTTP 200 even when
      `"status":"degraded"` (some upstream has zero healthy servers), because
      a supervisor that restarts Ferrum when a *backend* dies makes the outage
      worse; L4's breaker owns backend health.
- [x] **`main.rs` — wiring.** Registry built from declared upstream names
      (config-shaped, the L12 hot-reload seam recorded in `metrics.rs` docs);
      `ConnGauge` RAII guard on every connection task (inc on accept, dec on
      `Drop` through every exit path incl. failed TLS handshakes — the gauge
      cannot leak upward, same discipline as L8's limiter slot); three new
      flags (`--log-level`, `--log-plain`, `--admin`) plus the banner line.
- [x] **230 unit tests** (214 from L8 kept green, +16): histogram bucket
      boundaries (a value exactly on an edge), cumulative render + `+Inf` ==
      `_count`, status-class clamping (0 and 999 don't panic — metrics must
      never take the process down), rejection attribution incl. the `other`
      fallback for a future middleware nobody registered, label escaping, the
      concurrency hammer, level gating, RFC 3339 fixed points, JSON escaping
      of a field-forging target, `null`-vs-`0.0` stage timing, `/health` JSON
      shape ok + degraded (breaker tripped the L4 way).
- [x] **Live verification, all green:** JSON log parses under `jq` (`select(.status==401)`
      filter works); stage timings show `connect_ms:0.0` + `"pooled":true` on
      keep-alive reuse and `null`s on an auth rejection that never routed;
      `/metrics` shows correct 2xx/4xx/5xx class counts, `rejected_total{by="auth"}`,
      cumulative buckets, and elided zero-series; `/health` walked
      ok(2/2) → ok(1/2) → degraded(0/2, still HTTP 200) → recovered as backends
      were killed and revived, matching WARN connect-failures and INFO breaker
      transitions in the error log; admin 404/405 behave; `/metrics` on the
      MAIN listener proxies to the backend (isolation proof); `--log-plain`
      emits the old line; `--log-level debug` brings back the per-request
      diagnostics. One harness bug (not the proxy's): a `pkill -f` pattern of
      `127.0.0.1.*9002` matched the *proxy's own command line* (its args
      contain the backend list) and killed it mid-test — killed by listening
      port via `lsof -sTCP:LISTEN` thereafter; the L7/L8 "the harness is
      untested code" lesson strikes a third time.
- [ ] **Level 10 quiz — Vessey to answer before Level 11** (questions below)

### Level 10 quiz — Vessey to answer before Level 11

1. The access log went from `key=value` prose to JSON. What concrete operation
   does the structured version enable that the prose version made painful, and
   what NEW attack surface did the format change open that `json_escape`
   closes? Describe what an attacker's request target would look like and what
   it would accomplish against a naive logger.
2. `requests_total` is labeled `code="2xx"` (status class) and `upstream`, but
   never by path or raw status code. What goes wrong — mechanically, in memory
   and in Prometheus — if you label by path? Why is the rule "labels come from
   config, never from the request"?
3. A histogram here is 9 atomics per series, and each observation increments
   exactly ONE bucket. Prometheus requires cumulative `le` buckets. Where does
   the cumulative sum happen, and why there? What would be wrong with storing
   cumulative counts at record time?
4. Why does an average hide what a histogram shows? Give the concrete example
   from the knowledge base (the 40 ms average) and name which bucket boundary
   in `BUCKET_BOUNDS` would expose it.
5. The duration clock starts after `read_head` returns, not when `serve_one`
   is entered. What specific keep-alive behavior would corrupt the metric the
   other way, and which timeout bounds the gap the current placement excludes?
6. The success-path `record_request` sits after `client.flush()`, not after
   the response head is parsed. What real slowness does that ordering capture
   that the earlier placement would hide? And why are mid-exchange `?` deaths
   deliberately NOT in `requests_total`?
7. `ttfb_ms` is `null` for a request rejected by auth, but `0.0` is a possible
   value for a pooled connect. Why is `null`-vs-`0` a load-bearing distinction
   and not pedantry? What breaks if you use `-1` as "didn't happen"?
8. Rejections increment BOTH `requests_total` and `rejected_total{by=...}`.
   Defend the double-count: what two different questions do the two series
   answer, and what would you lose folding them into one?
9. Why do `/metrics` and `/health` live on a separate listener instead of
   reserved paths on :8080? Give all three reasons from the design, and name
   which production proxies made the same choice.
10. `/health` returns HTTP 200 even when `"status":"degraded"`. Why is 503
    the wrong status for "an upstream has zero healthy backends"? What
    component already owns backend health, and what would a supervisor
    restarting Ferrum on backend death actually accomplish?
11. The `active_connections` gauge is maintained by a `Drop` guard rather
    than paired `conn_opened()`/`conn_closed()` calls. Name the failure mode
    this makes unrepresentable, the two prior levels that used the same
    pattern, and what a leaked gauge looks like on a dashboard a week later.
12. A suppressed `debug!` costs one atomic load and a compare. Walk through
    what the macro does BEFORE calling `emit`, and explain why putting the
    level check inside `emit` instead would still allocate. Where else in
    this level does the same "do the work on the rare path" principle appear?
13. `metrics.rs` says the fix for two threads bumping a counter losing an
    increment is NOT `Ordering::SeqCst`. What actually guarantees no lost
    increments under `Relaxed`, and what DOESN'T Relaxed guarantee here that
    a scrape can observe? Why is that acceptable for metrics?
14. The registry's label slots are fixed at startup from declared upstreams.
    Which future level breaks that assumption, and where is the seam
    recorded? What would have to change in `Metrics` to survive it?

## Level 11 — what was built

Caching: the proxy becomes a shared RFC 9111 cache. Design at
[`docs/superpowers/specs/2026-08-26-level-11-caching-design.md`](docs/superpowers/specs/2026-08-26-level-11-caching-design.md).
The KB's framing: the fastest backend request is the one you never make —
and the job is to *honor* HTTP's caching contract, not invent one.

- [x] **Zero new dependencies, again — and the KB blessed the shape.** The
      classic O(1) LRU (hash map into a doubly-linked recency list) is
      "famously miserable" in safe Rust because aliasing+mutation is exactly
      what the borrow checker rejects — and it is right; LRU aliasing bugs
      are real CVEs in C. The KB's own listed alternative is what concurrent
      production caches do anyway: **a sharded map with approximate LRU**.
      That is L6's 16-shard rate limiter idiom with a bigger value type.
      Eviction scans one shard for the oldest `last_used` — O(shard) on the
      insert-when-full path only; the hit path pays a hash, a short lock, an
      `Instant` store. A true recency list would optimize nanoseconds at the
      cost of `unsafe` or an arena.
- [x] **`cache.rs`, two sections in one file.** Storage (`Cache`/`Shard`/
      `Entry`) knows nothing about HTTP; semantics (`freshness_from_headers`,
      `etag_matches`, `Key::build`) are pure functions that know nothing
      about locking; `proxy.rs` composes them. Doubly bounded per shard
      (bytes = the real bound, entries = a metadata bound). TTL is lazy — no
      sweeper task (L9 counted three spawn sites; a fourth would buy memory
      reclamation seconds earlier), and an expired entry with a validator is
      not garbage but a *revalidation candidate*. Bodies are `Arc<[u8]>`: a
      hit is a refcount bump, eviction racing a streaming hit is deferred by
      the refcount, no lock anywhere near an `.await`.
- [x] **The cache key — the level's one dangerous decision.** The KB: getting
      the key wrong is how caches leak one user's data to another, the worst
      bug class in the level. Key = route index + method + ORIGINAL
      (pre-rewrite) host + target + each `Vary`-named header's value from
      THIS request (absent = empty string, its own variant per RFC 9111
      §4.1), names lowercased and sorted. The hash only picks the shard —
      **full struct equality decides the lookup**, so a collision degrades to
      a miss, never to the colliding entry. `KeyInput` snapshots the
      pre-rewrite request because the cache is consulted twice per exchange
      (lookup before the L5 rewrite, store after the response) and `req` is
      mutated in place between the two.
- [x] **Vary needs two probes, and the second is the point.** The caller
      cannot know which request headers belong in the key until a stored
      response says so. Probe 1 uses the vary-less key; for varying resources
      that slot holds a tiny *index entry* recording WHICH headers matter
      (`vary_names`); probe 2 rebuilds the key with this request's values for
      those names. Live-verified: `Vary: Accept-Encoding` stored gzip and
      plain variants separately and served each requester its own.
- [x] **Semantics, the confusables handled by name.** `no-store` = never
      write; `no-cache` = store but revalidate before EVERY use (zero TTL +
      validator — without a validator, don't store); `private` = the browser
      may cache, a SHARED cache must not, and we are the shared cache the
      directive was written for; `s-maxage` beats `max-age` because
      shared-cache-specific TTL is its entire purpose. Status gate 200/301/
      404 (absence is an answer; caching it shields against retry storms on
      dead links). `Set-Cookie` = user-specific, full stop. Request
      `Authorization` bypasses the cache entirely (no read, no write, not
      even an X-Cache header). Route default TTL applies ONLY when the
      response carries a validator — invented freshness must at least be
      checkable.
- [x] **Placement in `serve_one`: after middleware, instead of the lease.**
      A cached response must never bypass auth or rate limiting — a 401'd
      client gets no cache read at all. A fresh hit skips the balancer lease
      entirely: no socket, no breaker traffic, no inflight count. The hit
      then runs the SAME client-leg pipeline as a forwarded response
      (middleware response phase, L5 rules, framing), so cached and forwarded
      responses are indistinguishable except for `X-Cache` and `Age` — both
      set BEFORE the chain/L5 passes so an operator's explicit rule keeps the
      last word (L5's ordering principle, third appearance).
- [x] **Revalidation, both legs.** Proxy→origin: a stale entry turns the
      outbound request conditional (`If-None-Match`, else
      `If-Modified-Since`); a 304 re-stamps the entry (TTL from the 304's own
      Cache-Control, else route default) and serves the cached body —
      live-verified as `X-Cache: REVALIDATED` with the origin hit count
      frozen at 1. Client→proxy: a client `If-None-Match` matching the
      entry's ETag gets **304 with no body** straight from the proxy (weak
      comparison: strip `W/`, octet-exact, honor `*`). Client-side
      `If-Modified-Since` is a recorded scope cut — it needs HTTP-date
      parsing and the ETag path answers the same question better wherever an
      ETag exists; `Entry` still keeps Last-Modified for the origin leg,
      where the ORIGIN does the comparing.
- [x] **The body tee.** The cache must capture streamed bodies without
      breaking L1's flat-memory guarantee. `TeeWriter` wraps the client-side
      sink inside the existing `copy_body_to` loop — every byte is touched
      exactly once, the capture buffers only what the wire accepted, and
      outgrowing `--cache-max-body` sets an overflow flag that silently
      cancels the store while the client keeps streaming unaffected. Every
      cache decision fails open: full, oversized, poisoned lock — the request
      proceeds uncached and only the metrics see it.
- [x] **Invalidation (RFC 9111 §4.4).** A non-error (2xx/3xx) response to a
      non-GET/HEAD method through a caching route removes every variant of
      that URI's entry. Write-through correctness for plain CRUD:
      live-verified update-then-read saw the update (`HIT` → POST → `MISS`
      with a fresh origin hit).
- [x] **Observability pays forward.** `ferrum_cache_events_total{result=
      hit|miss|revalidated|stored|evicted|invalidated}` rendered by
      `cache.rs` itself and appended to the L10 exposition by the admin
      listener (one scrape, one document); `"cache"` field in the JSON access
      log; `X-Cache: HIT|MISS|REVALIDATED` + `Age` headers.
- [x] **Recorded debt, deliberate:** no stampede defenses (request
      coalescing/singleflight, stale-while-revalidate, TTL jitter — the KB's
      "lovely exercise" is a second synchronization design and its own
      lesson), no disk persistence, no `stale-if-error`, no purge API (L12's
      config story owns that).
- [x] **250 unit tests** (230 kept green, +20): key isolation by route/host,
      collision-degrades-to-miss (by construction: full equality), lazy
      expiry, stale-with-validator → restamp revives, Vary variants, LRU
      eviction under tight budgets, oversized-body rejection, invalidation
      across variants, 8-thread hammer staying within bounds, all the
      directive parsing edge cases (case-insensitivity, quoted values), weak
      ETag comparison, 304-head header subset.
- [x] **Live verification, 13 checks all green:** miss→hit with origin
      frozen; TTL expiry; both revalidation legs (`REVALIDATED` + origin 304
      + frozen hit count; client conditional → 304 no body with caching
      headers only); `no-store`/`private` never stored; `Authorization`
      bypass (no X-Cache at all); Vary variants; POST invalidation;
      eviction under `--cache-max-bytes 16k` (30 evictions); metrics
      counters; access-log field; uncached route untouched; keep-alive
      across hits. **One gap found live and fixed:** misses on caching
      routes carried no `X-Cache` header at all, making a caching route's
      miss indistinguishable from an uncached route — `X-Cache: MISS` now
      set on the forwarded path, after the cache snapshot (the stored entry
      must stay free of per-exchange annotations), before the chain/L5
      passes.
- [ ] **Level 11 quiz — Vessey to answer before Level 12** (questions below)

### Level 11 quiz — Vessey to answer before Level 12

1. The KB calls the cache key "the worst bug class in this level." Walk
   through what happens, request by request, if the key omits (a) the Vary
   values, (b) the route index, (c) the original pre-rewrite target. Which
   of the three leaks one user's data to another?
2. Why does the lookup compare full key structs when the hash already picked
   the shard? What exactly goes wrong if two different keys hash identically
   and the code trusts the hash?
3. `no-cache` and `no-store` differ by one word and by everything. What does
   each direct this cache to do, and how does the code express "store but
   revalidate before every use" without a special case in the lookup path?
4. Why does `s-maxage` override `max-age` for Ferrum but not for a browser?
   What kind of cache is each directive addressed to?
5. The route's `;cache=SECS` default TTL applies only when the response
   carries a validator. What could a validator-less response with invented
   freshness do that a validated one cannot, and why is that asymmetry worth
   a rule?
6. Vary lookup takes two probes. What does the first probe's entry store for
   a varying resource, why can't the caller build the right key in one step,
   and what happens to a request whose named header is absent?
7. A fresh hit skips the balancer lease entirely. Name three distinct pieces
   of L3/L4 machinery that consequently never see the request, and argue in
   each case whether that blindness is correct.
8. The cache lookup runs AFTER the middleware chain. What specific attack
   works if it runs before? Which L6 middleware would it neuter, and how is
   that different from the `Authorization` request-header gate?
9. Proxy→origin revalidation replaced the client's own If-None-Match with
   the cache's validator. Where did the client's conditional go, and how
   does the client still get its 304 when its validator matches? Trace both
   the fresh-hit and the revalidated-stale paths.
10. `TeeWriter` captures "only what the inner sink actually accepted." What
    corruption does that clause prevent, and why does overflow cancel the
    store instead of erroring the exchange?
11. The stored entry snapshots headers after `strip_hop_by_hop` but before
    the middleware response phase, L5 response rules, and the framing block.
    For each of the three, give a concrete header that would be wrong in the
    cache if the snapshot moved after it.
12. POST-invalidation removes the entry but the next GET is a MISS, not a
    fresh entry. Why doesn't the POST response itself refresh the cache, and
    what RFC-shaped assumption would that violate?
13. Eviction scans the shard for the oldest `last_used` instead of keeping a
    recency list. State the exact asymptotic costs of both designs on the
    hit path and the insert-when-full path, and the argument for paying the
    scan here.
14. The level ships with no stampede defense. Describe the dog-pile scenario
    concretely (numbers welcome), then sketch how request coalescing would
    fit THIS codebase — which type would own the in-flight map, and what
    Tokio primitive would the 999 waiters block on?

## Level 12 — what was built

Production features: the gap between a program and infrastructure — config
files, graceful shutdown, hot reload. Design at
[`docs/superpowers/specs/2026-09-02-level-12-production-features-design.md`](docs/superpowers/specs/2026-09-02-level-12-production-features-design.md).

- [x] **The config file is the CLI, persisted — a decision, not a parser
      shortcut.** Ferrum already had a configuration language: eleven levels
      of flags, route specs, and upstream specs, each with a parser and
      startup guardrails. A second schema (nested route tables, a
      `[[middleware]]` array) would mean every value has two parsers that
      must agree forever; config-vs-flag drift is a classic operational bug.
      So `config.rs` parses a stated TOML subset (`key = value`, one
      `[upstreams]` table, one `routes` string array, comments — and loudly
      nothing else) and LOWERS it into the argument vector `main.rs` already
      consumes. File args first, real CLI args after: the parse loop's
      last-write-wins arms implement "CLI overrides file" with zero
      precedence code. Duplicate keys are errors, not last-wins — a config
      where `max-conns` appears twice is drift in progress, and honoring the
      second occurrence silently is how it stays hidden. Every error carries
      a line number.
- [x] **`--validate` (nginx -t).** Parse-and-exit, but through the FULL
      startup path: `parse_settings` runs every guardrail from L5's
      protected headers to L8's TLS coherence, plus `TlsArgs::build`. Deploy
      pipelines depend on a validator that answers the same question the
      boot would — which is exactly why boot, `--validate`, and SIGHUP
      reload share one extracted function rather than a "reload parser"
      that accepts a subset. Live-verified: a route targeting an undeclared
      upstream fails `--validate` with the same message boot would give.
- [x] **Graceful shutdown — the KB's four-step choreography, on machinery
      already built.** (1) `tokio::signal` streams for SIGTERM/SIGINT,
      `select!`ed with `accept()`. (2) Breaking the loop drops the listener;
      the kernel refuses new connections from that instant. (3) Drain: a
      process-wide `AtomicBool` makes every completing exchange answer
      `Connection: close` (cached responses included) — and the in-flight
      count is **L8's `ConnLimiter`**, whose RAII guard releases on every
      exit path; the security accounting IS a drain tracker, no new
      counters, no watch channel. (4) `--drain-timeout` (default 15 s)
      bounds the wait; a second SIGTERM during the drain means "now"; the
      cut count is logged and exit is 0 either way — the deploy succeeded,
      the log records what it cost.
- [x] **Hot reload — the Arc-swap pattern the KB promised in Level 2.** The
      shared handle is `RwLock<Arc<RouteTable>>` (arc-swap without the
      dependency). `handle_client` snapshots the Arc **per exchange**, not
      per connection: a request mid-flight keeps the consistent table it
      started with; the next request on the same keep-alive connection sees
      the new config (per-connection granularity would let one chatty client
      pin a retired config forever). The read lock is held for one refcount
      bump, never across an await — L9's compiler-enforced rule, still
      compiler-enforced. SIGHUP re-reads the file and runs the ENTIRE
      boot-time parse+build+guardrail path off to the side; only success
      swaps the pointer. An invalid file is rejected wholesale at ERROR and
      the old config stays live — a reload can never take a working proxy
      down. Live-verified: routes swapped under a concurrent 4-second
      request that completed on the old table; a garbage line appended to
      the file logged `reload REJECTED` and traffic continued on the
      current config.
- [x] **The reload's lifetime problem, solved by `Weak`.** Probers used to
      hold `Arc<Upstream>` — immortal-table-era code that becomes a leak
      the moment tables retire: a prober owning a strong ref keeps its pool
      and its idle connections alive forever. Now `spawn_probers` hands each
      task a `Weak<Upstream>`, upgraded per tick and held only for the
      tick; when a reload swaps the table and the last in-flight request
      drops the old Arc, the next upgrade fails and the loop exits. **The
      `Weak` IS the shutdown signal** — no kill channel, no generation
      counter, no task registry. Same fix in `admin.rs`, which had captured
      a boot-time `Vec<Arc<Upstream>>`: `/health` now resolves upstreams
      per request through the shared handle (the old capture would have
      reported — and pinned — the boot config forever).
- [x] **Reload scope, drawn where nginx draws it.** Routes, upstreams, and
      their per-route options reload; listener, TLS material, connection
      limits, cache bounds, and log settings are startup-only (parsed and
      validated on reload, not applied). You can reroute live; you cannot
      re-listen. Metrics label slots stay boot-time — the L10 cardinality
      seam is now real: a reload-introduced upstream records under
      `upstream="-"` until restart. Documented, accepted, quiz fodder.
- [x] **Explained, deliberately not built** (the course asks for the
      explanation): **graceful restart** — zero-refusal binary upgrade via
      FD passing (nginx: the listening socket survives the exec, so the
      listen queue never closes) or `SO_REUSEPORT` overlap (old and new
      bind simultaneously; brief dual-serving window) — skipped because the
      KB itself concedes the industry answer is increasingly "let the
      orchestrator roll pods", and Ferrum already demonstrates both halves
      (drain + config swap) separately. **Worker processes** — nginx's
      master/worker split exists substantially because C segfaults and a
      worker's death must not take the fleet; Rust panics are per-task and
      Pingora ships single-process multi-threaded on exactly that argument
      (L9 documented our 8-thread work-stealing runtime).
- [x] **261 unit tests** (250 kept green, +11): the config parser's whole
      grammar (value shapes, comments-vs-# -in-strings, duplicate key/
      upstream rejection, unknown keys/sections, unterminated forms,
      single- and multi-line route arrays, switch-false-is-noop, line
      numbers in errors) and the `Weak` upgrade lifetime contract
      (mid-tick strong ref does not extend the pool; the upgrade after the
      last drop fails).
- [x] **Live verification, all green:** boot from file identical to CLI
      (banner, routing, strip rewrite, admin plane); `--validate` exit 0 /
      exit 1 with the boot-path error; CLI `--admin 9200` overriding the
      file's 9100; SIGHUP route swap under a concurrent slow request that
      finished on the old table; broken-file reload rejected with traffic
      uninterrupted; clean drain — in-flight 4 s request completed, its
      response carried `Connection: close`, then exit with "drained
      cleanly"; deadline drain — a request slower than `--drain-timeout`
      was cut after 3 s with the count logged; new connections refused the
      moment the listener dropped.
- [ ] **Level 12 quiz — Vessey to answer before Level 13** (questions below)

### Level 12 quiz — Vessey to answer before Level 13

1. The config file lowers into the CLI's argument vector instead of filling
   a Settings struct directly. What class of bug does that design make
   impossible, and what is the concrete mechanism by which `--log-level
   debug` on the command line beats `log-level = "info"` in the file?
2. Duplicate keys in the file are a hard error. Defend that against the
   TOML-standard-ish alternative (last wins) — what operational failure
   mode is the strictness aimed at?
3. Why must `--validate` run the ENTIRE boot path (guardrails, TLS build,
   route resolution) rather than just the file parser? Give a concrete
   config that parses cleanly but must still fail validation.
4. Walk the four steps of graceful shutdown in order and name the exact
   mechanism Ferrum uses for each. Which two steps were already built by
   earlier levels, and by which?
5. Why does the drain flag live in an `AtomicBool` instead of a
   `tokio::sync::watch` channel? What property of the readers makes the
   channel's extra capability worthless here?
6. During a drain, where exactly does `Connection: close` get injected, and
   why must the check happen per-exchange rather than once per connection?
   What would a client experience if it happened only at accept time?
7. The route-table snapshot is taken per exchange, not per connection.
   State the failure mode of each alternative granularity (per-request is
   ours; consider per-connection and per-read).
8. The reload path builds the complete new RouteTable BEFORE taking the
   write lock, and the swap is one pointer store. What two distinct
   correctness properties does that ordering buy?
9. In-flight requests keep the old table through a reload with no
   generation counter, no epoch, no RCU library. What Rust mechanism
   provides the guarantee, and when exactly does the old table's memory
   free?
10. Before this level, a prober held `Arc<Upstream>`; now it holds `Weak`
    and upgrades per tick. Explain the leak chain the strong ref would have
    created after a reload (name every object kept alive), and why the
    upgrade must be per-tick rather than once at loop start.
11. admin.rs used to capture `Vec<Arc<Upstream>>` at boot. After a reload,
    what would /health have reported, and what worse thing would it have
    done beyond misreporting?
12. Which config keys are reload-scoped and which are startup-only? Pick
    two startup-only keys and give the concrete technical reason each
    cannot be swapped by a pointer store.
13. A reload-introduced upstream records its metrics under `upstream="-"`.
    Trace why, through L10's registry design, and state the fix's cost that
    made "document it as a seam" the right call for now.
14. Make the case FOR and AGAINST implementing graceful restart (FD
    passing) in Ferrum. Your AGAINST case must cite what the KB says the
    industry increasingly does instead; your FOR case must name what a
    plain drain-and-restart drops that FD passing would not.

## Level 13 — what was built

Basic WAF: the proxy grows an immune system. Design at
[`docs/superpowers/specs/2026-09-02-level-13-basic-waf-design.md`](docs/superpowers/specs/2026-09-02-level-13-basic-waf-design.md).
The KB's one-liner was the architecture: "you already built the platform —
the WAF is middleware with opinions."

- [x] **Normalization first — the KB calls it 80% of WAF quality.** Evasion
      is mostly encoding games, so `normalize()` percent-decodes twice (a
      second pass that changes anything IS double-encoding — flagged and
      scored, since legitimate clients single-encode), decodes the entity
      forms attackers use to smuggle angle brackets, lowercases, collapses
      whitespace runs (one `union select` pattern matches all spacings),
      and strips-and-flags null bytes. Broken escapes stay literal — a WAF
      must never 500 on hostile input. `canonicalize_path()` resolves
      `.`/`..` and flags any attempt to climb above root even when the
      final path lands innocently: we cannot know how the BACKEND resolves
      paths, so the *attempt* is the signal (the L2 normalization lesson,
      weaponized, per the KB).
- [x] **Score, don't hair-trigger — the ModSecurity CRS model.** ~16 rules
      in a `const` table (data, not code), scanned over four normalized
      surfaces: canonicalized path, query string, User-Agent, Referer.
      Points accumulate; conviction only at the threshold (default 10).
      A lone quote is 2 points — O'Brien buys coffee too; `union`+`select`
      co-occurring is 10, because that conjunction has no benign URL
      reading. Anomaly scoring is the difference between a WAF and a
      false-positive generator ops disables within a week. Benign
      lookalikes are first-class tests: `O'Brien`, `union station`,
      `select a plan`, `script kiddie` as prose, versioned paths — all
      documented as staying under threshold.
- [x] **Detectors:** SQLi (union-select, comment sequences, tautologies —
      including FALSE ones like `or 1=2`, which is how blind injection is
      probed — stacked queries after `;`, timing functions,
      information_schema), XSS (`<script`, event handlers, `javascript:`
      URLs, vector tags, eval-family), traversal (`../` literals scanned
      pre-canonicalization so absorbed climbs still score, sensitive-file
      paths post-canonicalization, encoded and double-encoded forms),
      scanner UAs (sqlmap/nikto/…, conviction-weight; a missing UA is 1
      nuisance point — curl scripts are legitimate, but it tips stacked
      borderline scores, as in CRS).
- [x] **No backreferences, and that's a feature.** The precise tautology
      regex is `(\d+)=\1`; Rust's regex crate rejects backreferences BY
      DESIGN — the same no-backtracking guarantee that L9 identified as
      the only reason L2's `~regex` routes aren't a per-request DoS
      vector. The looser `digit=digit` form convicts blind-injection
      probes correctly anyway. The constraint and its upside are both in
      the rule's comment.
- [x] **Reputation — the L4 breaker pointed inward.** Convictions become
      strikes (16-shard map, the L6/L11 idiom; lazy decay, the L11 TTL
      pattern); `ban-after` strikes (default 3) inside the decay window
      bans the IP for `ban-secs` (default 60 s), doubling per repeat ban
      to a 1 h cap — the L4 backoff, applied to clients. A banned IP is
      refused for one hash + one short lock, before any normalization: 
      cheap refusal of known offenders is most of what reputation buys.
      The store is process-wide (one `OnceLock`'d `Arc`): an attacker
      probing /api and /admin is ONE offender — and it survives L12
      reloads, because rerouting is not an amnesty. Memory-only, restart
      amnesties: persistent cross-customer feeds are precisely the
      commercial vendors' moat (KB).
- [x] **A WAF is a middleware — literally.** `impl Middleware for Waf`,
      chain order log → request-id → waf → ratelimit → auth → authz:
      hostility is refused before it consumes a rate token or triggers a
      credential comparison, and the L6 contract supplies rejection
      short-circuiting (a blocked request never touches a backend),
      response-phase unwind (the 403 still carries request-id + log line),
      `rejected_by:"waf"` attribution, and per-route config through the
      existing option partition (`waf=`/`waf-threshold=` joined L6_KEYS —
      they configure a middleware). `waf-threshold` without `waf=` is a
      boot error, the L6 coherence-guardrail pattern.
- [x] **Modes, because every WAF ships watching first.** `;waf=detect`
      logs the verdict, counts `detected`, records strikes (so flipping
      to block starts with history) but never bans and always forwards;
      `;waf=block` convicts. In BOTH modes the rule hit-list goes to the
      error log only — a response that names the rule that fired is a
      payload-tuning oracle, so the client sees a generic 403 and the
      access log carries only the numeric `waf_score`.
- [x] **The honesty checkpoint, kept.** Signature WAFs are a speed bump,
      not a wall; the real injection fixes are parameterized queries and
      output encoding in the application. This level buys the automated
      99%, time during 0-days, and visibility. Request-BODY inspection is
      deliberately absent: Ferrum streams bodies in 16 KB windows (L1's
      flat-memory guarantee) and buffering for inspection is a different
      architecture — the WAF sees heads only and the module docs say so.
- [x] **280 unit tests** (261 kept green, +19): the normalization table,
      canonicalization incl. climbs, every detector against real payloads
      AND benign lookalikes, cross-surface score accumulation, ban
      threshold/lift/backoff-doubling/decay, detect-never-bans, the
      middleware contract (403 with no oracle, benign passes, third
      conviction bans, fourth request refused uninspected).
- [x] **Live verification, all green:** five payload families (incl.
      double-encoded traversal) → 403 with generic body; ban after 3
      convictions refused an INNOCENT request from that IP, lifted after
      the configured 2 s; detect mode forwarded the attack to the backend
      while logging `score=10 rules=[...]`; unprotected route passed the
      same attack untouched; benign lookalikes 200'd; metrics showed
      convicted=3 detected=1 banned=1 ban_refused=3; `waf_score` in the
      JSON log. **Two gaps found live, both fixed + committed:** the WAF
      counters were rendered but never appended to `/metrics` (caught by
      the warning baseline — `render_prometheus` showed up as dead code),
      and the startup banner's middleware summary omitted the WAF layer
      (the banner exists precisely so execution order is readable at
      boot).
- [ ] **Level 13 quiz — Vessey to answer before Level 14** (questions below)

### Level 13 quiz — Vessey to answer before Level 14

1. The KB calls normalization 80% of WAF quality. Take `%252e%252e%2fetc/passwd`
   and walk it through both decode passes: what does each pass produce,
   which flag is raised where, and what total score accrues before any
   traversal rule even matches?
2. Why does the double-encoding flag itself score points, independent of
   what was hidden? What legitimate client behavior would be punished if
   single-encoding also scored, and why doesn't it?
3. `canonicalize_path("/a/../../b")` returns `/b` with the climb flag set.
   Why is the ATTEMPT convicted when the resolved path is harmless, and
   which unknown makes the conservative choice correct?
4. A lone `'` scores 2; `union`+`select` scores 10. Reconstruct the
   reasoning for each weight, then explain what breaks operationally if
   you swap them.
5. The tautology rule matches `or 1=2` — a FALSE tautology. Why is that
   over-match actually correct, and what does Rust's regex crate refuse to
   support that forced the looser pattern? Connect that refusal to a
   safety property L9 identified in the router.
6. Chain order puts the WAF after request-id but before ratelimit and
   auth. Give one concrete consequence of each of the two orderings it
   rejected (WAF-before-request-id; WAF-after-ratelimit).
7. The 403 body is generic and the rule hit-list is log-only, in both
   modes. What attack workflow does a rule-naming error page (or an
   X-Waf-Score header) enable? Walk it.
8. Why does detect mode record strikes but never ban? What operational
   sequence is that designed for, and what state advantage does it hand
   the operator at the moment enforcement flips on?
9. The ban check runs before inspection. Quantify what a banned IP costs
   the proxy per request versus an inspected one, and explain why that
   asymmetry is "most of what reputation buys."
10. The reputation store survives an L12 config reload but not a restart.
    Defend both halves of that sentence — why is reload-survival correct
    and why is restart-amnesty acceptable?
11. Body inspection is absent by architecture. Name the L1 guarantee that
    conflicts with it, describe what a body-inspecting WAF must do
    instead, and name one attack class this WAF consequently cannot see.
12. The rules live in a `const` table, not code. Add (on paper) a rule
    catching `<base href=` injection: pattern kind, points, and the
    justification for your weight against the benign-lookalike test.
13. Reputation keys on `ctx.peer.ip()` — the socket address. Three levels
    made the same choice for three different features. Name them and the
    shared reason.
14. The KB's honesty checkpoint says signature WAFs are a speed bump.
    Name the three commercial layers above signatures, and for each, what
    it catches that this level structurally cannot.

## Level 14 — what was studied

Scalability & HA — the final level, theory like Level 9. Full write-up in
[`docs/level-14-scalability.md`](docs/level-14-scalability.md). No
production code changed; the work was auditing THIS tree against the
question "what breaks at N > 1?", with every claim verified by grep
rather than recalled.

- [x] **Who balances the load balancers** — the recursion at the top of
      the stack: DNS round-robin (cheap, TTL-slow failover), VRRP floating
      IPs (sub-second, scales to 2), anycast (one IP everywhere via BGP),
      and the L4-tier-over-L7-tier architecture inside every major cloud.
      The satisfying part verified in code: Maglev-style L4 tiers spread
      flows by consistent hashing — the ring `balancer.rs` already builds
      for `chash` — and they hash the 4-tuple for the same reason
      `iphash` exists: affinity to held state.
- [x] **The state audit** (the level's centerpiece): every `static`,
      `OnceLock`, and sharded map in the tree classified per the KB's
      hierarchy. **Don't share:** route table (identical config to all
      instances — L12's validate-wholesale/swap-atomic reload IS the data
      plane of an xDS-style control plane), health state (independent
      learning, slight disagreement harmless), pools and metrics
      (per-instance by nature; Prometheus aggregates fleets). **Share
      approximately:** rate limits (×N admission — per-instance ÷N is
      usually fine; Redis for a loose global count), WAF reputation (×N
      strike budgets; commercial cross-customer feeds are the moat), the
      cache (×N misses — wasteful, never incorrect; chash partitioning or
      "the CDN above absorbs it"). **Share for real:** only exactly-once
      duties (cert renewal) via etcd/ZooKeeper leases — use a store,
      implementing Raft is its own course. One pleasant find: L6's
      per-process request-id seeding was cluster-ready three levels
      before clusters existed.
- [x] **HA:** the L4 flap-prevention asymmetry generalizes to fleet
      membership; L10's `/health` (with its deliberate degraded-≠-dead
      distinction) is exactly the endpoint an L4 tier would consume; L12's
      drain is the per-instance half of a rolling deploy; failure domains
      stack process → machine → site, each layer's failure the next
      layer's health-check event.
- [x] **CDN integration** — three consequences, each landing on a seam
      already built: the "client IP" becomes a CDN node (L5's XFF trust
      rules + L8's CidrList = the trusted-ranges allowlist), the L11
      cache becomes layer two of two (`s-maxage` is how origins address
      the layers separately), and origin pull is the ideal customer for
      L7's pools.
- [x] **The closing map:** every level reappears at cluster scale —
      chash → Maglev, breakers → fleet membership, per-IP buckets →
      replicated approximate limits, SIGHUP → control planes, drain →
      rolling deploys. Distributed systems are the same subject,
      multiplied. Course complete: **14/14 levels, 280 tests, ~13.4k
      lines, two dependencies** (regex, rustls) — everything else from
      scratch, on purpose.
- [ ] **Level 14 quiz — Vessey to answer to close the course** (below)

### Level 14 quiz — Vessey to answer to close the course

1. Rank DNS round-robin, VRRP, and anycast by failover speed and explain
   what mechanically limits each. Which one requires resources you cannot
   simply buy more of, and what are they?
2. The L4-over-L7 architecture puts a consistent-hashing tier ABOVE your
   proxies. Why must the L4 tier hash the 4-tuple rather than
   round-robin packets, and which Ferrum algorithm exists for the same
   reason one layer down?
3. Classify Ferrum's route table, rate limiter, and TLS-cert renewal
   into the KB's three-tier state hierarchy, and justify each placement
   in one sentence.
4. Health state is deliberately NOT shared across a fleet. What makes
   slight disagreement between instances harmless here, and what
   property of the L4 breaker design (built eight levels earlier) makes
   independent learning cheap?
5. A `rate=100/s` route behind 3 Ferrum instances admits ~300/s. Give
   the two remedies in the share-approximately tier and state the cost
   that rules out exact distributed counting.
6. Why is N independent caches "wasteful but correct" while N
   independent rate limiters are "quietly wrong"? What distinguishes the
   two kinds of state?
7. An attacker sprays a 3-instance fleet. Walk through what the L13
   reputation store does per instance, what the fleet-level effect is,
   and what commercial WAFs have that structurally fixes it.
8. Leader election via an etcd lease: describe the mechanism (what is
   leased, what renewing means, what losing it triggers), and name the
   one Ferrum duty on the horizon that would first need it.
9. "Statelessness is what makes horizontal scaling linear." Connect that
   claim to L3's iphash: what problem does iphash solve, why does the
   cluster answer make it unnecessary, and when does it remain the
   right tool?
10. Your proxy moves behind a CDN. Name the three integration
    consequences from the study doc and, for each, the existing Ferrum
    seam (level + mechanism) it lands on.
11. L12 built SIGHUP reload; Envoy uses xDS. State precisely which half
    of the control-plane/data-plane split L12 already implements, and
    what the other half adds.
12. Failure domains stack: process, machine, site. For each, name the
    detection mechanism and the recovery mechanism from the study doc,
    and identify which levels of this course built the per-instance
    analogue.
13. The Rust concepts map says ArcSwap/atomic config swap solves hot
    reload. Ferrum used `RwLock<Arc<T>>` instead. What does real
    `arc_swap` buy over the RwLock form, and why was the difference
    immaterial here? (L12's design doc took a position — check it.)
14. The course's final claim: "distributed systems are the same subject,
    multiplied." Argue it concretely using exactly three mechanisms you
    built, tracing each from its single-instance form to its fleet form
    — then name ONE genuinely new problem that only exists at fleet
    scale, with no single-instance analogue in this codebase.

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
- **2026-08-19/20** — Level 8 (Security & TLS) implemented inline **in one pass, straight from the design to code**, at Vessey's explicit instruction to skip the approval ceremony and execute in "auto mode" — the first level built without either a subagent-driven task sequence (L4/L5/L7) or a pre-written plan reviewed before coding (L6). Design at `docs/superpowers/specs/2026-08-19-level-8-security-tls-design.md`; the plan (`docs/superpowers/plans/2026-08-19-level-8-security-tls.md`) was written *after* the code, as a record rather than a brief. New `tls.rs`: rustls + tokio-rustls with the crypto provider pinned to `ring` rather than the `aws-lc-rs` default (far lighter build, no cmake/NASM), PEM chain/key loading, TLS1.3+1.2 with no reachable path to anything older, ALPN pinned to `http/1.1`, mTLS as `off`/`optional`/`required` via `WebPkiClientVerifier`, four startup guardrails covering both directions of the config trap, and `TLS_HANDSHAKE_TIMEOUT`. New `security.rs`: `ConnLimiter` (global ceiling + per-IP cap, `Drop`-released via the L3 `Lease` pattern, `fetch_update` for the global claim, rollback on per-IP refusal, map-entry removal on last close) plus hand-rolled `Cidr`/`CidrList` (deny-beats-allow, non-empty allow list is default-deny, socket-peer only, IPv4-mapped normalized at the edge) plus `Limits`/`parse_size`. `proxy.rs`: `handle_client`/`serve_one` made generic over `S: AsyncRead + AsyncWrite + Unpin` — the only two signatures that had pinned `TcpStream`, since Level 1 already made `Conn<S>` generic, which is why all seven prior levels run over TLS with no other change; `scheme` threaded into `ForwardContext`, filling the seam L5 left behind; `BodyCopy` + `copy_body_limited` enforcing the body cap mid-stream on decoded payload; 431 on header count and 413 on body, both before routing. `main.rs`: the handshake moved **inside** the spawned task (awaiting it in the accept loop would let a single `ClientHello` byte stall every new connection process-wide — a one-attacker total DoS that passes every functional test), ten new CLI flags, and TLS built before `bind`. **Two decisions reversed from the design during implementation, both recorded rather than quietly applied:** a denied CIDR closes the connection instead of answering 403 (on a TLS listener a 403 would require completing a handshake for an address already refused — spending an RSA/ECDHE operation on the attacker's behalf, turning the cheapest rejection into one of the most expensive), and the two dead-code warnings the level introduced were resolved by making `in_flight`/`is_empty` genuinely used rather than by `#[allow(dead_code)]`. 214 tests pass (168 from L7 kept green, +46); release build holds the exact 4-warning baseline. Live-verified all 15 checks incl. mTLS reject/admit, 413/431 with zero backend hits for rejections, both CIDR semantics, the per-IP cap with slot reuse proving `Drop` released, the 10.0s handshake deadline firing, backward compatibility for the L1 shorthand and a combined L4+L5+L6+L7 invocation, and — the level's central claim, unreachable by unit test — **three deliberately stalled handshakes while a real client was served in 0.03s**. **Process cost of skipping the plan-first flow, recorded because it is the point:** the design/code divergence on the 403 went uncaught until live verification, where a subagent-driven level would have had a reviewer read the plan against the diff. Two harness bugs also found: a first guardrail run that reported four passes but was worthless because **unquoted `$args` in zsh does not word-split** (each flag pair fell through to the route-spec arm and exited 1 for the wrong reason — caught by reading the error text, not the exit status), and a unit test that deadlocked the suite by writing 200 KB into a 64 KB duplex. Both were the harness's bugs, not the proxy's; L7 hit the same class twice, and the standing lesson is that a passing test harness is itself untested code. Background processes cleaned (`pgrep` clean). Commits `baff59b` (name correction) and `ead48a2` (the WIP push, made before verification at Vessey's request) pushed to `github.com/Vasant18/Ferrum` main as Vasant18 via the `switching-gh-accounts` skill, gh credential switched back to the personal account afterwards.
- **2026-08-21** — Level 9 (OS Internals) studied. **Theory level, zero production code changed** — the correct outcome rather than a shortfall, since Levels 1–8 already run on this machinery; the work was reading the existing code through a lower lens. Write-up at `docs/level-9-os-internals.md`: the `read()`-blocks problem and C10K; the readiness-API evolution (`select`→`poll`→`epoll`/`kqueue`→`IOCP`/`io_uring`) with the O(n)→O(ready) transition identified as the single property that makes 10k idle connections cheap; the full `.await`→`Poll::Pending`→`Waker`→reactor→`kevent`→re-poll path traced through Ferrum's own `Conn::read_head` rather than a toy example, including the non-blocking-read fast path that bypasses the reactor entirely; and nginx re-read as the same epoll architecture, differing only in who writes the state machines. **Facts verified against the tree rather than recalled:** this machine is `Darwin arm64` so the reactor is **`kqueue`, not `epoll`** (every KB mental model is epoll-shaped because that is where proxies deploy); the reactor crate is `mio 1.2.2`, a transitive dependency never named in `Cargo.toml`; `features = ["full"]` silently selects the multi-threaded scheduler with **8 worker threads**. **The award for most interesting measurement goes to the await map:** counting `.await` in code and excluding the comment mentions that inflate a naive `grep` by ~5% gives **72 production / 61 test**, with only **three of thirteen files** holding a production await (`proxy.rs` 57, `health.rs` 10, `main.rs` 5). `balancer.rs` has **zero** — 1,750+ lines of seven balancing algorithms, a three-state breaker, and a LIFO pool, entirely synchronous. Read through this lens, four separate levels (L1 `http.rs`, L5 `rewrite.rs`, L6's rejection of the async middleware trait, L8 `tls.rs`) independently made one unnamed optimization: keep the compiler-generated state machine small. **The blocking-the-executor audit produced a genuinely stronger result than expected:** every production function that takes a lock (`take_conn`, `return_conn`, `try_acquire`, `release`, `RateLimiter::allow`) is a plain `fn`, not `async fn` — so "never hold a lock across `.await`" is **compiler-enforced**, not a review convention, since `.await` cannot appear in a non-async fn. Corroborated by `tokio::sync` appearing *only* inside comments explaining why it is unused, and `spawn_blocking`/`thread::sleep` appearing zero times. Two lesser audit results: `tls.rs`'s synchronous `std::fs` is harmless because L8 ordered it before `bind` (recorded as a coincidence, not claimed as foresight), and `router.rs:53`'s per-request regex is safe **only** because Rust's `regex` crate guarantees linear time with no backtracking — the same line in a PCRE-based proxy is a DoS vector, so this is a Level 2 dependency choice quietly holding up a Level 9 safety property. **Two findings recorded, deliberately not fixed:** (1) `Server.addr` is a `String` shape-validated at startup but never resolved, so `TcpStream::connect` re-resolves on every pool miss with no DNS caching or TTL awareness — invisible so far because L7's pooling skips `connect` on a hit, and not fixed because resolving once at startup is the *wrong* fix for backends that move, with a TTL-aware resolver cache deserving its own level; (2) the runtime's whole shape (8 workers, work stealing, blocking pool) is implicit in `#[tokio::main]` and stated nowhere, which matters the first time anyone tunes it — not changed, because changing a default with no benchmark is exactly the "measure, don't guess" mistake L7 warned about, and the missing `wrk`/`oha` baseline stays L7's recorded debt rather than being reassigned here. 14-question quiz added. Two corrections made during the write-up, both caught by re-verifying rather than trusting the first number: an initial `.await` count of 137 was wrong because it counted prose mentions inside doc comments, and a claimed "7,000-line proxy" was stale (8,793 lines after L8's `tls.rs` + `security.rs`).
- **2026-08-24/25** — Level 10 (Observability) implemented inline across two sessions in "auto mode" (Vessey approved the recommended decisions and asked for direct execution), per the approved design (`docs/superpowers/specs/2026-08-24-level-10-observability-design.md`). Session 1 (08-24): design brainstormed (three decision points resolved — from-scratch over the `tracing`/`metrics` crates since L9 proved the request lifecycle lives in one task; per-stage timing in the access log over W3C traceparent for a single-hop proxy; a separate off-by-default admin listener over reserved paths since `/metrics` is reconnaissance gold), spec written and committed, `metrics.rs` built (atomic registry, fixed-bucket histograms with scrape-time cumulation, Prometheus text renderer, 9 tests) — then work paused mid-level at Vessey's request with a WIP push. Session 2 (08-25): the rest — `logging.rs` (leveled stderr macros, hand-rolled RFC 3339 with the `civil_from_days` calendar math cross-checked against Python at three fixed points, catching a first hardcoded test timestamp that was off by 4 days), `ReqCtx` timing fields + `Instant` stamps and every-exit-path metrics recording in `proxy.rs`, JSON access log with RFC 8259 escaping + `--log-plain`, per-request diagnostics demoted to `debug!` across five files, `admin.rs` (`/metrics` + `/health`, 5 s deadline, startup-fatal bind), `ConnGauge` RAII wiring, three CLI flags. 230 tests pass (214 kept green, +16). Live-verified the full checklist: `jq`-parseable log with stage timings (`null` on a rejection that never routed, `connect_ms:0.0`+`pooled:true` on reuse), status-class counters + `rejected_total{by="auth"}` attribution, cumulative buckets with `+Inf`==`_count`, `/health` walked ok(2/2)→ok(1/2)→degraded(0/2, still HTTP 200)→recovered against live backend kills with matching WARN/INFO breaker lines in the error log, admin-plane isolation (`/metrics` on :8080 proxies to the backend), 404/405 on the admin socket, and both escape hatches. One harness bug, third strike for the "the harness is untested code" lesson: a `pkill -f '127.0.0.1.*9002'` aimed at a backend matched the proxy's own command line (its args contain the backend list) and killed it mid-test — switched to killing by listening port (`lsof -sTCP:LISTEN`). Commits `22a4629` (spec), `83a9400` (metrics WIP, pushed 08-24), `9ebf1c6` (the rest) pushed to `github.com/Vasant18/Ferrum` main via the `switching-gh-accounts` skill, gh switched back to the personal account after each push.
- **2026-08-26/27** — Level 11 (Caching) implemented inline across two sessions in auto mode (Vessey pre-approved the recommended decisions), per the approved design (`docs/superpowers/specs/2026-08-26-level-11-caching-design.md`). Session 1 (08-26): design brainstormed and spec committed (from-scratch sharded approximate-LRU per the KB's own blessing — the linked-list LRU is the borrow checker's least favorite data structure and production caches shard anyway; opt-in `;cache=` per route with HTTP deciding per response; separate storage/semantics sections in one `cache.rs`); storage engine + RFC 9111 semantics built with 20 unit tests (key isolation, Vary two-step, lazy TTL, restamp, LRU bounds, directive parsing, weak ETag comparison, 8-thread hammer); router grew a third option-partition family (`L11_KEYS`) and `find_route_indexed` (the key carries the route index). Session 2 (08-27): the wiring — `KeyInput` snapshot refactor (the cache is consulted before AND after the in-place L5 rewrite, so the key inputs must be captured once, early), `Lookup::Stale` carrying its key (by restamp time the live head is rewritten), lookup-after-middleware/instead-of-lease in `serve_one`, `serve_cached` running the full client-leg pipeline (chain → L5 → framing) so cached responses are indistinguishable from forwarded ones, proxy→origin conditionals with 304 restamp+serve, client `If-None-Match` answered 304 at the proxy, `TeeWriter` (an `AsyncWrite` wrapper capturing only what the sink accepted, overflow = silent store-cancel, client unaffected), §4.4 unsafe-method invalidation, `--cache-max-*` flags, `cache_events_total` appended to `/metrics` by the admin listener, `"cache"` JSON log field. 250 tests pass (230 kept green, +20). One test's assertion was corrected against the code rather than vice versa (the size gate rejects BEFORE counting `stored` — "stored" means in the cache, not offered to it). `find_route` went production-dead and took the documented `#[allow(dead_code)]`-with-why treatment (the `find`/`for_test` precedent); `CachedResponse.last_modified` was instead REMOVED with the scope-cut argument written where the field was (client-side `If-Modified-Since` needs HTTP-date parsing; the ETag path answers the same question better; `Entry` keeps Last-Modified for the origin leg where the origin compares). Live verification: 13/13 green — miss→hit with the origin's own hit-counter frozen, TTL expiry, `REVALIDATED` with origin answering 304 to our `If-None-Match`, client-conditional 304 with no body and caching headers only, `no-store`/`private` never stored, `Authorization` bypassing the cache entirely, `Vary: Accept-Encoding` serving per-encoding variants, POST invalidation (HIT → POST → MISS with fresh origin hit), 30 LRU evictions under `--cache-max-bytes 16k`, metrics/log fields, an uncached route carrying zero cache artifacts, keep-alive across hits. **One gap found live, fixed, committed separately:** misses on caching routes carried no `X-Cache` at all — indistinguishable from an uncached route; `X-Cache: MISS` now set after the cache snapshot and before the chain/L5 passes so the stored entry stays annotation-free and operator rules keep the last word. Commits `081fae5` (spec), `d453077` (implementation), `cfc3b66` (X-Cache fix), plus docs, pushed to `github.com/Vasant18/Ferrum` main via the `switching-gh-accounts` skill, gh switched back afterwards.
- **2026-09-02** — Level 12 (Production Features) implemented inline in one session in auto mode, per the approved design (`docs/superpowers/specs/2026-09-02-level-12-production-features-design.md`). New `config.rs`: a hand-rolled TOML-subset parser that LOWERS the file onto the existing CLI vocabulary — `max-conns = 10000` IS `--max-conns 10000`, an `[upstreams]` entry IS `--upstream NAME=SPEC`, a `routes` element IS a positional route spec — so every value keeps its one parser and "CLI overrides file" falls out of argument ordering with zero precedence code; duplicate keys are hard errors (last-wins hides drift), messages carry line numbers, and the subset is stated exactly and rejected loudly outside it. `main.rs`: the eleven-level parse loop extracted verbatim into `parse_settings` so boot, `--validate` (nginx -t, runs the FULL guardrail path incl. `TlsArgs::build`), and SIGHUP reload share one parser; the accept loop now `select!`s accept against SIGTERM/SIGINT (break → drain) and SIGHUP (reload → continue); graceful shutdown drops the listener (kernel refuses from that instant), sets a process-wide drain flag that makes every completing exchange — cached responses included — answer `Connection: close`, and polls **L8's ConnLimiter** (the RAII security accounting IS a drain tracker; zero new machinery) to zero under `--drain-timeout`, second signal skips the wait, exit 0 either way with the cut count logged. Hot reload: `RwLock<Arc<RouteTable>>` snapshotted PER EXCHANGE in `handle_client` (mid-flight requests keep a consistent table; the next request on a keep-alive connection sees the new config; per-connection granularity would let a chatty client pin a retired config forever), the whole new table built off to the side through the identical boot path and swapped with one pointer store, invalid files rejected wholesale at ERROR with the old config live. The reload's lifetime problem: `health.rs` probers now hold `Weak<Upstream>` upgraded per tick — a retired table's probers expire within one interval of its last Arc dropping, the `Weak` IS the shutdown signal (no kill channel, no generation counter); same class of fix in `admin.rs`, whose boot-time `Vec<Arc<Upstream>>` capture would have pinned (and misreported) the boot config forever — `/health` now resolves upstreams per request through the shared handle. Graceful restart (FD passing / SO_REUSEPORT) and worker processes explained and deliberately not built, with the KB's own "the orchestrator rolls pods now" concession and Pingora's single-process argument recorded. One dead-code decision: the spec's diff-and-warn on startup-only keys was consciously dropped during implementation (detecting "changed" needs boot values threaded through for a WARN nobody acts on), so `STARTUP_ONLY_KEYS` was REMOVED rather than `#[allow]`ed, and the doc comment that referenced it fixed in the same pass. 261 tests (250 kept green, +11: the config grammar end to end, and the `Weak` upgrade lifetime contract tested directly). Live verification all green: file boot identical to CLI, `--validate` 0/1 with boot-quality errors, CLI `--admin` overriding the file's, SIGHUP swapping routes under a concurrent 4 s request that completed on the OLD table, a garbage config line rejected with traffic uninterrupted, a clean drain (in-flight request finished, response carried `Connection: close`, "drained cleanly" logged, process exited), a deadline drain cutting a too-slow request at 3 s with the count logged, and new connections refused the instant the listener dropped. Commits `ffb8636` (spec), `5b2dbb9` (config parser WIP), `549b0c9` (shutdown+reload), plus docs, pushed to `github.com/Vasant18/Ferrum` main via the `switching-gh-accounts` skill, gh switched back afterwards.
- **2026-09-02 (later)** — Level 13 (Basic WAF) implemented inline in one session in auto mode, per the approved design (`docs/superpowers/specs/2026-09-02-level-13-basic-waf-design.md`). New `waf.rs` (~750 lines incl. tests), the KB's "middleware with opinions" built literally: normalization first (two-pass percent decode where a changed second pass IS double-encoding — flagged and scored, legitimate clients single-encode; targeted entity decode; whitespace collapse; null-byte flag; broken escapes stay literal because a WAF must never 500 on hostile input), path canonicalization with the climb-above-root ATTEMPT convicted even when the resolved path lands innocent (the backend's resolution is unknowable), a ~16-rule `const` table scanned linearly over four normalized surfaces (canonical path, query, UA, Referer — body inspection deliberately absent, it conflicts with L1's flat-memory streaming and the module docs say so), CRS-style anomaly scoring with benign lookalikes as first-class tests (O'Brien, union station, select a plan all pass), and `Reputation` — the L4 breaker pointed inward: sharded strikes with lazy decay, bans with doubling backoff capped at 1 h, banned IPs refused for one hash + one lock before any inspection. Wired as an L6 middleware (chain slot: log → request-id → waf → ratelimit → auth → authz, so hostility never consumes a rate token or a credential comparison), `;waf=block|detect` + `;waf-threshold=N` through the existing option partition, threshold-without-waf a boot error, one process-wide `OnceLock` reputation store shared across routes AND surviving L12 reloads (rerouting is not an amnesty). Rule names are log-only in both modes — a response naming the fired rule is a payload-tuning oracle. Three implementation corrections worth recording: the tautology rule's precise form needs a backreference, which Rust's regex crate rejects BY DESIGN (the same linear-time guarantee L9 identified as what keeps L2's `~regex` routes DoS-safe) — the looser `digit=digit` form convicts blind-injection probes (`or 1=2`) correctly anyway; and `union+select` co-occurrence and `;DDL-verb` stacked queries were raised to conviction weight after the test suite showed them under threshold — no benign URL reading exists for either conjunction. 280 tests (261 kept green, +19). Live verification all green: five payload families incl. double-encoded traversal 403'd with generic bodies and zero backend contact, 3 convictions → ban that refused an INNOCENT request from that IP → 2 s decay → served again, detect mode forwarding the attack while logging `score=10 rules=[...]`, the unprotected route passing the same attack untouched, metrics (convicted/detected/banned/ban_refused) and the `waf_score` log field all moving. **Two gaps found live, fixed, committed separately:** WAF counters were rendered but never appended to the `/metrics` document (caught by the warning baseline — dead-code warnings are a wiring detector, third time this course), and the startup banner's middleware summary omitted the WAF layer (the banner exists so execution order is readable at boot). Commits `04f7b0a` (spec), `4623bd3` (implementation), `fcdff9e` (metrics wiring), `817fa27` (banner), plus docs, pushed to `github.com/Vasant18/Ferrum` main via the `switching-gh-accounts` skill, gh switched back afterwards.
- **2026-09-02 (evening)** — Level 14 (Scalability & HA) studied. **Theory level, zero production code changed — and with it the course's build phase is COMPLETE: 14/14 levels.** Write-up at `docs/level-14-scalability.md`, following the L9 method: every claim verified against the tree rather than recalled. The traffic-distribution ladder (DNS → VRRP → anycast → L4-over-L7) with the recursion named and grepped: Maglev-style L4 tiers consistent-hash flows exactly like `balancer.rs:598`'s `chash` ring, and hash the 4-tuple for the same affinity reason `iphash` exists at `:711`. The centerpiece is a state audit of `rproxy/src` against the KB's don't-share / share-approximately / share-for-real hierarchy: route table, health state, pools, and metrics ship to N instances unchanged (L12's validate-wholesale/swap-atomic reload turns out to be the data-plane half of an xDS control plane; L6's per-process request-id seeding was cluster-ready three levels early); rate limits, WAF reputation, and the cache go quietly approximate at N>1 (×N admission, ×N strike budgets, ×N misses — the first two get per-instance ÷N or Redis-replicated loose counts, the cache is wasteful-but-correct and either lives behind the CDN's hit rate or chash-partitions across the tier); only exactly-once duties need consensus (etcd/ZooKeeper leases, and the KB's rule — use a store, implementing Raft is its own course — kept verbatim; nearest future need is ACME renewal of L8's certs). HA: the L4 flap asymmetry generalizes to fleet membership, L10's `/health` with its degraded-≠-dead distinction is precisely what an L4 tier consumes, L12's drain is half of a rolling deploy, failure domains stack process→machine→site. CDN integration lands on three pre-built seams: L5's XFF trust + L8's CidrList (trusted CDN ranges), L11 as cache layer two (`s-maxage` addresses the layers separately), L7's pools serving origin pull. Closing map: chash→Maglev, breakers→fleet membership, SIGHUP→control planes, drain→rolling deploys — distributed systems are the same subject, multiplied. Final tally recorded: 14/14 levels, 280 tests, ~13.4k lines, two dependencies (regex, rustls), everything else from scratch on purpose. 14-question quiz added (deliberately including one question — #14 — that asks for a problem with NO single-instance analogue, so the closing lesson isn't self-congratulation). Quizzes L9–L14 all pending Vessey. Commits `3c0fe90` (study doc) + docs, pushed to `github.com/Vasant18/Ferrum` main via the `switching-gh-accounts` skill, gh switched back afterwards.
