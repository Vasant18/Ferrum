# Level 10 — Observability: Design

**Date:** 2026-08-24
**Course level:** 10 of 14 (`Build.md` LEVEL 10 — Observability; knowledge base § "Level 10 · Observability")
**Follows:** Level 9 (OS Internals — theory, no code)

## Scope

The knowledge base frames this level as the 3 a.m. question: "the site is slow"
must resolve to *which backend, which route, which percentile* in 30 seconds.
Three pillars, proxy edition:

1. **Logs** — one structured (JSON) access-log line per request; a separate
   leveled error log for proxy-internal events.
2. **Metrics** — counters, gauges, and histograms cheap enough to record on
   every request, exposed on `GET /metrics` in Prometheus text format.
3. **Traces** — per-stage timing (parse → route → backend connect → first
   byte → done) attached to the access log and the histograms, correlated by
   the request ID Level 6 already propagates.

Explicitly **out of scope** (decided at design time):

- **W3C `traceparent` propagation.** Ferrum is a single hop; per-stage timing
  deltas answer the 3 a.m. question without a second instrumented service to
  trace into. The request ID already stitches logs across hops. Revisit only
  if a downstream service learns to speak traceparent.
- **The `tracing`/`metrics`/`prometheus` crates.** See Decision 1.
- **Log files / rotation.** Ferrum writes stdout/stderr; files are the
  supervisor's job (Level 12 territory, and the twelve-factor position).

## Decisions

### 1. From scratch — zero new dependencies

The lessons of this level *are* the internals: the Prometheus text exposition
format, why histograms are pre-allocated buckets rather than stored samples,
why counters must be atomics and never a mutex on the hot path. Pulling in the
`metrics` crate turns all of that into invisible config. Unlike Level 8's
crypto, nothing here is dangerous to hand-roll — a wrong histogram bucket is a
wrong number on a graph, not a security hole.

The knowledge base recommends Rust's `tracing` crate because spans follow
tasks across await points. That solves a problem Ferrum does not have: Level 9
established the entire request lifecycle lives in **one task** (`serve_one`),
with only 3 of 13 files holding a production `.await`. A request-scoped timing
struct passed down the call path does the same job with zero magic.

`Cargo.toml` stays: regex (L2), rustls family (L8, crypto is forbidden to
hand-roll), everything else ours.

### 2. Separate admin listener, off by default

`/metrics` and `/health` live on their own plain-HTTP listener
(`--admin ADDR`, no default — enabling it is an explicit choice; docs
recommend `127.0.0.1:9100`). Rationale:

- `/metrics` leaks route names, backend addresses, and error rates —
  reconnaissance gold. The main listener faces the internet; the admin plane
  binding to localhost by default makes exposure a deliberate act.
- A backend that legitimately serves `/metrics` is never shadowed; the main
  listener's routing is untouched.
- This is what Envoy and HAProxy do; "the admin plane is a different socket"
  is the production lesson itself.

The admin server is a deliberately tiny hand-rolled responder (~1 read, parse
the request line, match on path, write a response, close). It does not reuse
the proxy machinery: no routing, no middleware, no keep-alive. Reusing
`http::read_head` for parsing is fine; reusing `serve_one` is not.

### 3. Access log: JSON, emitted where the old line was

`AccessLog::on_response` keeps its position (outermost middleware, runs last)
and switches from `key=value` prose to one JSON object per line:

```json
{"ts":"2026-08-24T10:15:42.123Z","id":"a1b2-42","peer":"127.0.0.1:55123",
 "method":"GET","target":"/api/users","status":200,"dur_ms":12.4,
 "parse_ms":0.1,"route_ms":0.0,"connect_ms":1.2,"ttfb_ms":10.8,
 "upstream":"api","backend":"127.0.0.1:9001","user":"-","rejected_by":null,
 "bytes_out":5120,"pooled":true}
```

Field notes:

- `ts` is wall-clock (RFC 3339 UTC, milliseconds); durations come from the
  existing monotonic `ReqCtx::started`. Wall time for correlation with other
  systems, monotonic for arithmetic — never mix the two jobs.
- JSON strings are escaped by a small hand-rolled escaper (quotes, backslash,
  control bytes). Request targets are attacker-controlled; the L6 lesson about
  log injection now applies to JSON validity.
- Numbers are emitted bare; absent optionals are `null` or `"-"` matching the
  old line's conventions (`user` keeps `"-"` since it is a string field).
- `--no-access-log` still works. A `--log-plain` escape hatch keeps the old
  human-readable line for eyeball debugging.

### 4. Error log: leveled, structured-ish, on stderr

A tiny `log` module (macros `error!`, `warn!`, `info!`, `debug!`) wrapping
stderr with a global level set by `--log-level LEVEL` (default `info`).
Existing `eprintln!` call sites in `proxy.rs`, `main.rs`, `balancer.rs`,
`health.rs`, `tls.rs` migrate to it; the `[peer]`-prefixed diagnostic
`println!`s in the request path become `debug!` (today they are unconditional
noise on every request — after this level, silence at the default level).
Format stays one human-readable line with a level tag and timestamp; the
*access* log is the machine-parseable stream, the error log is for humans.

### 5. Metrics: atomics + fixed buckets, Prometheus text format

New `metrics.rs`, a `Metrics` struct created once in `main` and shared as
`Arc<Metrics>` (same pattern as `RouteTable`):

- **Counters** (`AtomicU64`, `fetch_add(1, Relaxed)`):
  `requests_total{code="2xx",upstream="api"}` — labeled by status **class**
  (1xx–5xx) and upstream name, plus `rejected_total{by="auth"}` for
  middleware rejections and `connect_errors_total{upstream}`.
  Label sets are **fixed at startup** (upstreams are declared via CLI), so the
  registry is a pre-built `Vec` of named atomics — zero allocation, zero
  locking at record time. Status class rather than raw code keeps the
  cardinality at 5 per upstream, honest to Prometheus practice.
- **Gauges** (`AtomicI64`): `active_connections` (inc on accept, dec on drop —
  piggybacks on L8's `ConnLimiter` guard), `healthy_backends{upstream}`
  (maintained by the breaker transitions in `balancer.rs`).
- **Histogram**: `request_duration_seconds` per upstream + one `all` series.
  Fixed buckets `[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, +Inf]` — each an
  `AtomicU64`, plus `sum` (micros, `AtomicU64`) and `count`. Recording is a
  linear scan over 9 atomics; no allocation, no lock. Cumulative bucket
  semantics (`le`) computed at scrape time, not record time — scrapes are
  rare, requests are not.
- **Exposition**: `Metrics::render()` walks the registry and writes the
  Prometheus text format (`# HELP`, `# TYPE`, one line per series). Built at
  scrape time into a `String`; correctness over cleverness here.

### 6. Timing capture: a `Timings` struct threaded through `serve_one`

`Instant` stamps at: request-head parsed, route matched, backend connected
(or pool hit), first response byte, response complete. Lives in `ReqCtx` (new
fields), written by `proxy.rs` at the points it already logs, read by the
access log and by the histogram recorder at completion. Deltas tell you
*where* slowness lives: client (parse), Ferrum (route), network/backend
(connect, TTFB), transfer (rest). The KB names this the entire 3 a.m.
question.

### 7. `/health`: the proxy's own liveness + upstream summary

`GET /health` on the admin listener returns 200 with a small JSON body:

```json
{"status":"ok","upstreams":{"api":{"healthy":2,"total":3}},"active_connections":7}
```

Degrades to `"status":"degraded"` (still 200 — the *proxy* is alive) when any
upstream has zero healthy backends. This is Ferrum's own readiness signal for
*its* supervisors, distinct from L4's outbound probes of backends.

## Components

| Unit | File | Responsibility | Depends on |
|------|------|----------------|-----------|
| Metrics registry | `metrics.rs` (new) | counters/gauges/histograms + Prometheus render | std only |
| Error log | `logging.rs` (new) | leveled stderr macros, global level | std only |
| Admin server | `admin.rs` (new) | tiny listener: `/metrics`, `/health` | metrics, balancer (read-only), tokio |
| Timing capture | `proxy.rs` (edit) | stamp Instants into `ReqCtx` | — |
| JSON access log | `middleware/observe.rs` (edit) | JSON line, escaping, timings | ReqCtx fields |
| Gauge feeds | `security.rs`, `balancer.rs` (edit) | conn gauge, healthy gauge | metrics |
| Wiring | `main.rs` (edit) | `--admin`, `--log-level`, `--log-plain`; spawn admin task | all |

Data flow: `proxy.rs` stamps timings → middleware `on_response` logs JSON →
`serve_one` records counters + histogram after the response completes (so it
sees pooled/status/duration truth, including middleware rejections which
record with `upstream="-"`).

## Error handling

- Admin listener bind failure at startup = fatal, same posture as the L8 TLS
  guardrails (fail before announcing service).
- Admin connections get a 5 s overall deadline (read + write) — it is not
  exempt from slowloris thinking, but a full `ConnLimiter` is overkill for a
  localhost-default socket.
- Unknown admin path → 404, no body echo (no reflection surface).
- Metrics recording can never fail and never blocks: atomics only.

## Testing

- Unit: histogram bucketing boundaries (value on a bucket edge), counter
  label resolution, Prometheus render golden-string, JSON escaper against
  quotes/backslash/control/UTF-8, log-level filtering, health JSON shape,
  admin request-line parsing (path extraction, junk rejection).
- Existing 214 tests must stay green (ReqCtx gains fields with defaults; the
  old access-log tests update to parse JSON).
- Live verification (documented in PROGRESS.md like every level): run proxy +
  two backends, drive traffic including 404s/401s/a killed backend; verify the
  JSON log with `jq`, scrape `/metrics` and check counters move and histogram
  buckets are cumulative, check `/health` degrades when a backend dies and
  recovers after, confirm admin endpoints are absent from the main listener.
