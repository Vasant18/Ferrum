# Level 4 — Health Checks: Design

**Date:** 2026-08-05
**Course:** [Build.md](../../../Build.md) Level 4
**Status:** approved, ready for implementation planning
**Mode:** "I implement, you learn" — heavy in-code teaching comments, quiz at the end

## Goal

Stop sending traffic to backends that are down, route around them
automatically, and let them rejoin once they recover — without any manual
intervention. Concretely, the seven Build.md items:

Active health checks, Passive health checks, Retry logic, Exponential backoff,
Circuit breaker, Failure detection, Recovery logic.

These are not seven independent features. They are facets of **one circuit
breaker per server**: failure detection and recovery are its transitions, the
breaker *is* the circuit breaker, backoff paces its recovery attempts, and
active/passive checks are just two feeders of the same success/failure signal.
Retry is the one genuinely separate piece — it acts on the breaker's verdict.

## Non-goals (owned by later levels)

- **Header rewriting on the probe path (XFF etc.)** — Level 5. The active
  prober sends a minimal `GET`, no forwarded headers.
- **Connection reuse for probes** — Level 7. Each probe opens and closes one
  TCP connection, same as client-facing requests today.
- **Metrics / structured health events** — Level 10. Observability here is the
  existing per-request log line plus a one-line state-transition log.
- **Configurable per-request retry budgets, hedged requests** — out of scope.
  A single global retry cap is enough to teach the mechanism.
- **Outlier detection across the pool** (eject the statistical outlier) — the
  breaker is strictly per-server and threshold-based.

## Architecture

```
                         ┌──────────────────────────────────────┐
   client request        │ Upstream (Arc, shared)               │
  ───────────► pick() ───►  servers: Vec<Server>                 │
                         │    each Server:                       │
                         │      inflight: AtomicUsize   (L3)     │
                         │      ewma_us:  AtomicU64     (L3)     │
                         │      breaker:  Breaker       (L4 NEW) │
                         │  available() = breaker.allows_traffic()│
                         └───────┬───────────────────────▲───────┘
             passive feed        │                        │  active feed
        (Lease.mark_success/     │                        │ (health.rs prober
         mark_failure on Drop)   ▼                        │  task, GET /health)
                         ┌──────────────────────┐         │
                         │ Breaker (per Server)  │◄────────┘
                         │  state: Closed/Open/  │
                         │         HalfOpen      │
                         │  open_until, backoff  │
                         │  consec_fail/success  │
                         └──────────────────────┘
```

### Module layout

- **`balancer.rs`** (existing) — gains a `Breaker` type and a `breaker` field on
  `Server`. `Server::available()` stops returning hardcoded `true` and returns
  `self.breaker.allows_traffic()`. The breaker is **pure sync** (atomics + an
  injected `now: Instant`), so it unit-tests without sockets or sleeping — the
  same discipline that keeps the L3 algorithms testable.
- **`health.rs`** (new) — the **async** active prober. One tokio task per
  `Upstream`, spawned at startup. Holds `Arc<Upstream>`, ticks on a timer,
  probes due servers over HTTP, feeds results into their breakers. Kept
  separate from `balancer.rs` precisely because it is async and socket-bound,
  where the breaker is neither.
- **`proxy.rs`** (existing) — the retry loop and the passive-feed calls.
- **`main.rs`** (existing) — new global flags; spawns the prober task(s).

## The `Breaker` state machine

Three states, one source of truth. `Server::available()` is true **only in
Closed** — client traffic resumes only after the prober confirms recovery, never
speculatively.

```
                  record_failure() × fail_threshold consecutive
    ┌──────────┐ ───────────────────────────────────────►  ┌────────┐
    │  Closed  │                                            │  Open  │
    │ traffic  │ ◄──────────────────────────────────────    │ no traf│
    └──────────┘   record_success() × success_threshold      └───┬────┘
         ▲              (while HalfOpen)                          │ cooldown
         │                                                        │ elapsed
         │              ┌──────────┐                              │ (prober
         └──────────────│ HalfOpen │◄─────────────────────────────┘  gate)
          recovered,    │ probing  │──── record_failure() ──► Open
          backoff reset └──────────┘      (backoff doubles)
```

### State representation (all interior-mutable, `&self` throughout)

- `state: AtomicU8` — `Closed=0`, `Open=1`, `HalfOpen=2`.
- `open_until_nanos: AtomicU64` — when the Open cooldown ends, as nanoseconds
  since a process-start `Instant` baseline (same baseline trick as L3's PRNG
  seed). Read by the prober's "is this server due?" gate.
- `backoff_nanos: AtomicU64` — current cooldown length; doubles on each trip,
  capped at `backoff_max`, reset to `backoff_base` on recovery.
- `consec_fail: AtomicUsize`, `consec_success: AtomicUsize` — consecutive
  counters; each is zeroed by the opposite outcome.

### Transition methods (take `now: Instant` so tests inject a clock)

- `record_failure(now)`:
  - **Closed**: `consec_fail += 1`; if it reaches `fail_threshold` → **Open**,
    set `open_until = now + backoff`, `consec_success = 0`.
  - **HalfOpen**: immediately → **Open**, `backoff = min(backoff*2, max)`,
    `open_until = now + backoff`. (A probe during recovery failed.)
  - **Open**: no-op (already open; cooldown governs the next probe).
- `record_success(now)`:
  - **HalfOpen**: `consec_success += 1`; if it reaches `success_threshold` →
    **Closed**, `backoff = base`, both counters `0`.
  - **Closed**: `consec_fail = 0` (a good result clears a partial failure run).
  - **Open**: no-op (shouldn't happen — traffic is blocked in Open).
- `allows_traffic() -> bool`: `state == Closed`. This is what
  `Server::available()` calls, so **every L3 algorithm already respects it** —
  no selection-logic changes.
- `probe_due(now) -> Option<Probe>`: the prober's gate.
  - **Closed** → `Some(Normal)` every interval (liveness monitoring).
  - **Open** and `now >= open_until` → transition to **HalfOpen**, return
    `Some(HalfOpenTrial)`. Exactly one trial is admitted per cooldown; further
    ticks while HalfOpen return `None` until it resolves.
  - **Open** and `now < open_until` → `None` (still cooling down).
  - **HalfOpen** → `None` (a trial is already outstanding).

Backoff doubling lives entirely in the Open transitions: first trip waits
`backoff_base` (default 1s), then 2s, 4s, 8s … capped at `backoff_max`
(default 30s), reset to base once the server returns to Closed.

## Feeds — passive and active

Both call the *same* `Server::record_success` / `record_failure`. Neither knows
the other exists.

### Passive (client traffic)

`Lease` already wraps every request and fires on `Drop`. Extend it with an
explicit outcome, set by the proxy before the lease drops:

- `Lease::mark_success()` / `Lease::mark_failure()` set an
  `Option<bool> outcome` field.
- On `Drop`: release `inflight` (unchanged, unconditional), record the EWMA if
  `served` (unchanged), and **if `outcome` is set**, call the matching breaker
  method. If `outcome` is `None` (task cancelled mid-flight, or we never got far
  enough to judge), the breaker is left untouched — we never *guess* an outcome.

Outcome mapping at the call site:
- connect failure / connect timeout / response-read error / backend status
  `>= 500` → `mark_failure()`.
- response head parsed with status `< 500` → `mark_success()`.

Rationale for treating 5xx as failure but 4xx as success: 4xx is the client's
fault (bad request, not found), the backend is healthy; 5xx is the backend
failing. This mirrors how real proxies score passive health.

### Active (background prober, `health.rs`)

One task per `Upstream`, spawned in `main` after the table is built, each
holding an `Arc<Upstream>`. Loop:

1. Sleep `hc_interval` (default 2s).
2. For each server, ask `breaker.probe_due(now)`. Skip `None`.
3. For a due server, open a TCP connection (honoring `hc_timeout`, default 1s),
   send `GET <health_path> HTTP/1.1` with `Host` + `Connection: close`, read the
   response head using the existing L1 helpers. Status `2xx` → `record_success`,
   anything else / connect fail / timeout / parse error → `record_failure`.
4. Probes run concurrently across servers within a tick (a slow server must not
   delay the others), via `tokio::join`-style fan-out over the pool.

The prober **reuses `proxy`/`http` connect+write+read-head code** rather than
re-implementing HTTP. The only new HTTP concern is issuing a fixed `GET` and
checking the status class.

The payoff of the shared breaker: a server under live traffic trips **Open from
passive failures without waiting for a probe interval**, and a server with no
client traffic still **recovers via active probes**. The two feeds cover each
other's blind spots.

## Retry path (`proxy.rs`)

Makes a dead backend invisible to clients — the visible reason health checks
matter. Today `serve_one` picks once and 502s on connect failure. New flow:

```
attempt = 0
loop:
  lease = upstream.pick(peer.ip())        # None → 502 (no healthy server)
  connect(lease.addr()) with timeout
    ok   → break (proceed to forward)
    fail → lease.mark_failure()           # feeds breaker immediately
           if attempt < retry_cap
              AND method is idempotent
              AND no request-body bytes forwarded yet:
                 attempt += 1 ; continue  # pick() again — breaker now routes around it
           else:
              502 ; return
forward request → stream body → read response
  → lease.mark_success() / mark_failure() by response outcome
```

**Retry requires all three, every time:**

1. **Attempts remaining** — global `--retries` cap, default **2** (3 tries
   total). Each retry calls `pick()` fresh; because the just-failed server's
   `mark_failure()` already ran, a tripped breaker excludes it. (One failure
   won't trip a 3-fail threshold on its own; the retry still moves to another
   server because `pick()`'s algorithm advances — e.g. RR cursor moved, LC sees
   the +1 inflight — and repeated failures across requests do trip it.)
2. **Idempotent method** — `GET/HEAD/PUT/DELETE/OPTIONS/TRACE` retry;
   `POST/PATCH`/unknown do not (possible side effects; not safe to replay).
3. **Pre-body** — retry only while still at the connect stage, before any
   request-body bytes have been forwarded to any backend. Once body streaming
   starts, the request is committed to that backend.

**Only connect failure / connect timeout trigger a retry.** A failure *after*
the request was sent (backend 5xx, mid-response I/O error) is not safely
replayable: it still records failure into the breaker, but the error/response
is returned to the client. `502 Bad Gateway` surfaces only when attempts are
exhausted or no healthy server remains.

## Config surface (CLI)

Per-upstream health path, appended to the existing spec grammar with a `;`
separator:

```
--upstream api=lc:127.0.0.1:9001,127.0.0.1:9002;health=/healthz
--upstream web=127.0.0.1:8001            # health path defaults to /health
```

`SPEC = algo:server[*weight][,server...][;health=PATH]`. `health=` is optional;
default `/health`. Placing it in the spec keeps all per-pool config in one place,
consistent with L3.

Global flags (all optional, all defaulted), parsed alongside `--upstream`:

| Flag | Default | Meaning |
|---|---|---|
| `--hc-interval` | `2s` | Active probe period |
| `--hc-timeout` | `1s` | Per-probe connect+read deadline |
| `--hc-fail` | `3` | Consecutive failures: Closed → Open |
| `--hc-success` | `2` | Consecutive successes in HalfOpen → Closed |
| `--hc-backoff-base` | `1s` | Initial Open cooldown, before any doubling |
| `--hc-backoff-max` | `30s` | Cap on the doubling Open cooldown |
| `--retries` | `2` | Max in-request retries (idempotent, pre-body only) |

Backoff **base** defaults to `1s`, independent of `--hc-interval`, so tuning
probe frequency doesn't accidentally change recovery pacing. Durations accept
`s`/`ms` suffixes. Old invocations (no L4 flags, no `;health=`) behave exactly as L3 —
every server starts **Closed**, so with no prober configured differently the
proxy is unchanged until a real failure trips a breaker.

## Observability

- Per-request log gains a retry marker when a retry happened:
  `-> api[lc] 127.0.0.1:9002 (inflight=1) [retry 1/2 after 127.0.0.1:9001 connect-refused]`
- One line per **state transition**, from whichever feed caused it:
  `health: 127.0.0.1:9001 Closed->Open (3 consecutive failures, cooldown 1s)`
  `health: 127.0.0.1:9001 Open->HalfOpen (probing)`
  `health: 127.0.0.1:9001 HalfOpen->Closed (recovered)`

Enough to *watch* a backend get ejected and rejoin under a `curl` loop. Metrics
are Level 10.

## Testing

`Breaker` unit tests (sync, injected `now: Instant`, **no sleeping**):

1. Closed stays Closed under `fail_threshold - 1` failures; `allows_traffic()`
   true throughout.
2. `fail_threshold` consecutive failures → Open; `allows_traffic()` false.
3. A success in Closed resets the consecutive-failure counter (failures must be
   *consecutive* to trip).
4. Open blocks `probe_due` until `open_until`; after it, one `HalfOpenTrial` is
   admitted and exactly one (subsequent ticks return `None`).
5. HalfOpen + `success_threshold` successes → Closed, backoff reset,
   `allows_traffic()` true again.
6. HalfOpen + one failure → Open, backoff **doubled** (assert the new cooldown).
7. Backoff doubles across repeated trips and **caps** at `backoff_max`.
8. Backoff **resets** to base after a recovery.

Retry-logic tests (`proxy` helpers, no real sockets where avoidable):

9. Idempotent method retries on connect failure; `POST` does not.
10. Retry stops at the cap and returns 502.
11. Retry is refused once body bytes have been forwarded (pre-body gate).

Active prober (`health.rs`): a small unit test that a 2xx probe result calls
`record_success` and a non-2xx / connect-fail calls `record_failure` (the HTTP
send itself is covered by the L1 client; here we assert the mapping).

Existing 52 tests must keep passing unmodified except mechanical changes where
`Server::available()` is now breaker-derived (tests that assumed always-available
construct servers whose breaker starts Closed, so they are unaffected by
default).

**Live verification:** 3 python backends on :9001–:9003 behind an `lc` pool with
`--upstream api=lc:...;health=/health`.
- Kill :9002 → within `hc_fail × interval` its breaker trips Open; log shows
  `Closed->Open`; a `curl` loop stops hitting :9002 and never 502s (retry +
  remaining healthy servers).
- Confirm an idempotent request whose first pick is the just-killed server
  retries onto a healthy one (log shows the `[retry …]` marker).
- Restart :9002 → after the cooldown a HalfOpen probe succeeds
  `success_threshold` times; log shows `Open->HalfOpen` then `HalfOpen->Closed`;
  :9002 rejoins the rotation.
- Confirm a `POST` to a dead server does **not** retry (returns 502), proving the
  idempotent gate.

## Implementation order

1. `Breaker` in `balancer.rs` (states, atomics, transitions, `probe_due`) +
   unit tests 1–8. `Server::available()` → `breaker.allows_traffic()`.
2. Passive feed: `Lease` outcome field + `mark_success/mark_failure` + Drop
   wiring; proxy sets the outcome at the response/connect sites.
3. Retry loop in `proxy.rs` (idempotent + pre-body + cap gates) + tests 9–11 +
   the retry log marker.
4. `health.rs` active prober + per-`Upstream` spawn in `main` + prober mapping
   test + transition log lines.
5. CLI: `;health=PATH` spec suffix + global `--hc-*` / `--retries` flags +
   defaults + validation.
6. Live verification (kill/restart backend, idempotent vs POST), PROGRESS.md
   update, Level 4 quiz.
