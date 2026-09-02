# Level 12 — Production Features: Design

**Date:** 2026-09-02
**Course level:** 12 of 14 (`Build.md` LEVEL 12 — Production Features; KB § "Level 12 · Production Features")
**Follows:** Level 11 (Caching)

## Scope

The KB's framing: the gap between a program and infrastructure is that
infrastructure changes configuration, upgrades itself, and shuts down —
without dropping a single in-flight request. Four deliverables:

1. **Config file** — a TOML(-subset) file declaring everything the CLI
   declares today, `--config PATH`, CLI flags override file values, and
   `--validate` (parse-and-exit, `nginx -t`; deploy pipelines depend on it).
2. **Graceful shutdown** — SIGTERM/SIGINT: stop accepting, drain in-flight
   exchanges (keep-alive connections answer the current request with
   `Connection: close`), hard deadline so a hung client can't hold the
   deploy hostage.
3. **Hot reload** — SIGHUP: re-read the config, validate wholesale (invalid
   ⇒ keep the old config live, log, carry on), atomically swap the route
   table. In-flight requests keep the snapshot they started with; new
   requests — *including the next request on an existing keep-alive
   connection* — see the new one.
4. **Explained, deliberately not implemented** (each gets its "why" in code
   or PROGRESS and a quiz question): **graceful restart** (FD passing /
   `SO_REUSEPORT` binary swap — the KB itself notes the industry answer is
   increasingly "let the orchestrator roll pods") and **worker processes**
   (nginx's master/worker exists because C segfaults; Rust panics are
   per-task and Pingora ships single-process multi-threaded on this exact
   argument — L9 already documented our runtime's shape).

## Decisions

### 1. Config format: a hand-rolled TOML subset that reuses the CLI grammar

Zero new dependencies, consistent with the whole course — and honest about
what a config file *is* here: the CLI vocabulary, persisted. Every existing
value already has a parser (`parse_route`, `Upstream::from_spec_with_health`,
`parse_size`, `parse_duration`, `Level::parse`); the config file maps onto
that vocabulary 1:1 rather than inventing a second schema:

```toml
# ferrum.toml
listen = "127.0.0.1:8080"
admin = "127.0.0.1:9100"
log-level = "info"          # any CLI flag name, minus the leading --
max-conns = 10000
tls-cert = "cert.pem"       # startup-only (see Decision 4)

[upstreams]                  # NAME = "SPEC" — the --upstream grammar
api = "127.0.0.1:9001,127.0.0.1:9002;health=/health"

routes = [                   # the route-spec grammar, verbatim
  "/api/**=api;cache=60;rate=100/s",
  "/=api",
]
```

The parser handles exactly: `key = value` (strings, integers, booleans),
one `[upstreams]` table of string values, one `routes` string array
(single- or multi-line), `#` comments, and nothing else. No nested tables,
no datetimes, no floats — a documented subset, rejected loudly on anything
outside it. Grammar choices that keep it honest: values are typed by shape
(quoted = string, `true`/`false` = bool, digits = integer), duplicate keys
are an error (silent last-wins is how config drift hides).

**Precedence: CLI beats file.** `rproxy --config ferrum.toml --log-level
debug` runs the file's config with debug logging. Mechanically, the config
file is lowered into the same argument vector the CLI parser already
consumes — file values first, real CLI args after, so the existing
last-write-wins `match` arms implement the precedence for free. One parser
owns every value's grammar; the file cannot drift from the flags.

### 2. Graceful shutdown: signal → close listener → drain → deadline

- `tokio::signal::unix` streams for SIGTERM + SIGINT, `select!`-ed with
  `listener.accept()` in the accept loop. On signal: break the loop —
  dropping the listener closes the socket, new connections are refused by
  the kernel.
- **Drain tracking is already built:** L8's `ConnLimiter` counts every live
  connection and releases on `Drop` through every exit path. Shutdown polls
  `limiter.in_flight()` to zero (100 ms ticks) under a
  `tokio::time::timeout(drain deadline)`. No new counters, no watch
  channels — the RAII guard that L8 built for security is exactly a drain
  tracker.
- **Keep-alive connections must not linger:** a process-wide
  `AtomicBool` (`shutting_down`), checked by `serve_one` after each
  exchange completes — during shutdown the response carries
  `Connection: close` and the connection ends after the in-flight request.
  The check rides the existing `client_still_usable` computation.
- `--drain-timeout SECS` (default 15 s). On expiry, remaining tasks are
  cut by process exit; the count is logged first.
- Exit code 0 on clean drain, 0 on deadline too (the deploy succeeded;
  the log records what was cut).

### 3. Hot reload: SIGHUP swaps `Arc<RouteTable>`; readers are lock-free-ish

The KB names the Rust pattern and this design follows it with std only:
the shared handle is `RwLock<Arc<RouteTable>>` (arc-swap without the
dependency). Request path: `routes.read().clone()` — a refcount bump under
a read lock held for nanoseconds, never across `.await` (the L9 rule,
compiler-enforced as ever). Reload path: build the ENTIRE new table off to
the side (parse, validate, resolve upstreams, spawn nothing yet), then
`*routes.write() = Arc::new(new_table)`.

- **Snapshot granularity is the request, not the connection.**
  `handle_client` loads the current `Arc` at the top of each `serve_one`
  iteration, so the next request on a year-old keep-alive connection sees
  the new routes, while a request mid-flight keeps the table it started
  with until it finishes. The old `Arc` frees itself when its last holder
  drops — ownership solving the torn-read problem by construction.
- **Validation is wholesale:** the new file parses completely and builds a
  full `RouteTable` (every startup guardrail from L5/L6/L8 runs) before
  the swap; any error keeps the old config live and logs at ERROR with the
  reason. A reload can never take a working proxy down.
- **Probers follow the table's lifetime via `Weak`.** `spawn_probers`
  changes to hold `Weak<Upstream>`; each tick upgrades, and a failed
  upgrade ends the loop. A reload spawns probers for the new table's
  upstreams; the old table's probers die within one interval of the last
  in-flight request dropping the old `Arc`. Old pooled connections close
  with their `Upstream`. No kill channel, no generation counter — the
  `Weak` IS the shutdown signal.
- **Reload scope: routes + upstreams (+ their middleware/cache options).**
  Startup-only: `listen`, `admin`, TLS material, connection limits, cache
  bounds, log settings. Changing those requires a restart, stated in the
  config file's own comments — the same line nginx draws for listeners.
  SIGHUP with startup-only changes in the file logs a WARN naming the
  ignored keys and applies the rest. Metrics' upstream label slots are
  fixed at startup (the L10 seam, now real): a reload-introduced upstream
  name records under `upstream="-"`; noted, accepted, quiz fodder.

### 4. What is deliberately NOT built

- **Graceful restart** (zero-refusal binary upgrade): FD passing or
  `SO_REUSEPORT` overlap. Theory documented; the KB itself concedes the
  production answer is increasingly the orchestrator's rolling deploy.
  Implementing it would be a second process-lifecycle protocol for a
  teaching proxy that already demonstrates the halves (drain + config
  swap) separately.
- **Worker processes**: Rust's per-task panic isolation removes the
  crash-containment argument; Pingora ships single-process on exactly
  this reasoning. L9 documented the 8-thread work-stealing runtime.
- **File watching** (inotify/kqueue auto-reload): SIGHUP is the interface
  every process manager already speaks; a watcher adds a platform API and
  debounce logic to save typing `kill -HUP`.

## Components

| Unit | File | Responsibility | Depends on |
|------|------|----------------|-----------|
| Config parser | `config.rs` (new) | TOML-subset → arg vector; `--validate` | std only |
| Shutdown | `main.rs` (edit) | signal select, listener close, drain poll, deadline | tokio::signal, ConnLimiter |
| Keep-alive close | `proxy.rs` (edit) | `shutting_down` check → `Connection: close` | one AtomicBool |
| Shared table | `main.rs` + `proxy.rs` (edit) | `RwLock<Arc<RouteTable>>`, per-request load | std |
| Reload | `main.rs` (edit) | SIGHUP → rebuild → validate → swap → respawn probers | config.rs |
| Prober lifetime | `health.rs` (edit) | `Weak<Upstream>` upgrade-per-tick | std |

## Error handling

- Bad config at boot: exit 1 with the parse/validation error, no socket
  bound (the L8 guardrail posture).
- Bad config at reload: ERROR log, old config stays live, proxy unaffected.
- `--validate`: exit 0 + "config OK" or exit 1 + the error; nothing bound.
- Drain deadline expiry: WARN with the count of connections cut.
- Double SIGTERM: second signal skips the drain (immediate exit) — the
  operator asked twice.

## Testing

- Unit (config.rs): every value shape, comments, duplicate-key rejection,
  unknown-key rejection, `[upstreams]`/`routes` forms, multi-line arrays,
  precedence lowering order, error messages name the line.
- Unit (health.rs): prober loop exits when the `Weak` fails to upgrade.
- Existing 250 stay green (RouteTable behavior unchanged; `serve_one`
  signature gains nothing — the shared handle is loaded in
  `handle_client`).
- Live: boot from config file behaves identically to the equivalent CLI;
  `--validate` both ways; SIGTERM mid-long-request drains it then exits;
  keep-alive connection gets `Connection: close` during drain; SIGHUP
  swaps a route (old route 404s, new route serves) without dropping a
  concurrent slow request on the OLD table; SIGHUP with a broken file
  keeps serving the old routes; drain deadline cuts a deliberately hung
  connection.
