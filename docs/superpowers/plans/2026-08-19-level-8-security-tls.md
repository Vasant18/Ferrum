# Level 8 — Security & TLS: Implementation Plan

**Design:** [`../specs/2026-08-19-level-8-security-tls-design.md`](../specs/2026-08-19-level-8-security-tls-design.md)
**Date:** 2026-08-19/20

> **How this level was built, honestly.** Levels 4, 5, and 7 were subagent-driven:
> a plan written first, then dispatched task by task. Level 6 was written inline in
> one session. Level 8 was implemented inline **in one pass, from the design
> straight to code**, at Vessey's explicit instruction to skip the approval
> ceremony and execute. This plan was therefore written *after* the code, as a
> record rather than a brief.
>
> That ordering costs something real, and the cost showed up: the design doc said
> a denied CIDR would get a 403, the code closes the connection instead, and
> nothing caught the divergence until live verification. On the subagent-driven
> levels a reviewer reads the plan against the diff and that gap surfaces
> immediately. Recorded here because the next level should know which mode it is
> operating in and what that mode does not catch.

## Tasks, as actually executed

### Task 1 — Dependencies and `tls.rs`
Add `rustls` (0.23, `ring` provider, no default features), `tokio-rustls`,
`rustls-pemfile`, `rustls-pki-types`. First new deps since Level 2's `regex`.

New `src/tls.rs`:
- `ClientAuth` enum (`Off`/`Optional`/`Required`) with `parse`, rejecting typos.
- `TlsArgs` — CLI paths plus mode; `requested()` and `build()`.
- `build_server_config` — PEM chain + key, safe protocol versions,
  `WebPkiClientVerifier` for mTLS, ALPN pinned to `http/1.1`.
- Startup guardrails for all four incoherent combinations.
- `TLS_HANDSHAKE_TIMEOUT = 10s`.
- Unix-only warning when the key file is readable beyond its owner.

**Landed:** 13 unit tests.

### Task 2 — Make the proxy generic over the stream
- `handle_client(client: TcpStream, …)` → `handle_client<S: AsyncRead + AsyncWrite + Unpin>(client: S, …)`.
- `serve_one(client: &mut Conn<TcpStream>, …)` → `serve_one<S>(client: &mut Conn<S>, …)`.
- Add a `scheme: &'static str` parameter and feed it to `rewrite::ForwardContext`,
  filling the seam `proxy.rs` had carried since Level 5.
- Move `set_nodelay` out of `handle_client` (it is a `TcpStream` inherent method)
  and into the accept loop, on the raw socket before any TLS wrap.

`Conn<S>` needed no change — Level 1 already made it generic. This task was two
signatures and one argument.

### Task 3 — `security.rs`
- `ConnLimiter` + `ConnGuard`: global ceiling, per-IP cap, `Drop`-released.
  `fetch_update` for the global claim so two accepts cannot both pass at the
  boundary; per-IP refusal rolls the global claim back; the map entry is removed
  when a source's last connection closes.
- `Cidr` / `CidrList`: hand-rolled parse and prefix match, `/0` and `/32`–`/128`
  boundaries handled explicitly, deny-beats-allow, non-empty allow list is
  default-deny.
- `normalize_peer`: collapse IPv4-mapped IPv6 so a dual-stack listener cannot
  void an operator's v4 rules.
- `Limits` (`max_body`, `max_headers`) and `parse_size` (`10m`/`512k`/`1g`).

**Landed:** 26 unit tests.

### Task 4 — Accept-loop wiring
Order: CIDR check → connection limit → `set_nodelay` → spawn → (TLS handshake
under deadline) → `handle_client`. The handshake is **inside** the spawned task;
the guard is moved in so the slot covers the whole connection including a failed
handshake.

CLI: `--tls-cert`, `--tls-key`, `--tls-client-ca`, `--tls-client-auth`,
`--max-conns`, `--max-conns-per-ip`, `--max-body`, `--max-headers`,
`--allow-cidr`, `--deny-cidr`. TLS config is built **before** `bind`, so a bad
cert fails with no socket ever opened.

### Task 5 — Request size limits
- `BodyCopy { Done { reusable }, TooLarge }` — a distinct variant rather than an
  `io::Error`, so a `?` cannot swallow a limit breach into the generic error path.
- `copy_body_limited(dst, framing, max)`; `copy_body_to` delegates with `None`.
- `copy_chunked` gains a running decoded-byte total, checked **before** each
  chunk header is forwarded so the abort lands on a clean boundary.
- `serve_one`: header count → 431 before routing; declared `Content-Length` →
  413 before routing, middleware, and any backend socket; chunked overflow →
  413 mid-stream with both legs closed.

**Landed:** 7 unit tests.

### Task 6 — Verification
Full suite, release warning baseline, live end-to-end. See below.

## Verification results (2026-08-20)

**Unit tests: 214 passed, 0 failed.** 168 from Level 7 kept green, +46
(13 `tls`, 26 `security`, 7 `proxy` body-cap).

**Release build: exactly 4 warnings** — the documented baseline, and the same
four as Level 7 (`for_test`, `Chain::new`/`no_forwarded`, `find`, `state`). The
two dead-code warnings this level introduced were resolved by *making the methods
real* rather than by `#[allow(dead_code)]`: `ConnLimiter::in_flight` now reports
the in-flight count on every refusal line (which is the number that distinguishes
"one abusive source" from "genuinely at capacity"), and `CidrList::is_empty` now
suppresses the banner's access line when no policy exists.

**Live, against a `ThreadingHTTPServer` echo backend on :9001:**

| Check | Result |
|---|---|
| TLS termination | `curl https://localhost:8443/hello` → 200 through to the backend |
| `X-Forwarded-Proto` | backend received `x-forwarded-proto: https` — the L5 seam filled |
| mTLS `required`, no client cert | handshake refused, `tls handshake failed: peer sent no certificates` |
| mTLS `required`, valid client cert | 200, request served |
| Body under cap | 200 |
| Body over cap (500 B vs 100 B) | `413 Payload Too Large` |
| Header count over cap (12 vs 5) | `431 Request Header Fields Too Large` |
| Rejections reaching the backend | **zero** — baseline-vs-after hit count showed only the two probes |
| `--deny-cidr 127.0.0.0/8` | connection refused, `refused: address not permitted` |
| `--allow-cidr 10.0.0.0/8` (excludes us) | refused — default-deny confirmed |
| `--max-conns-per-ip 3`, 6 attempts | 3 held, 3 refused, each logged with the in-flight count |
| Slot reuse after release | fresh request → 200, so `Drop` released correctly |
| **3 stalled handshakes + a real client** | **real client served in 0.03 s** — accept loop not blocked |
| Handshake deadline | stalled connection closed at **10.0 s**, `tls handshake timed out after 10s` |
| L1 shorthand `rproxy LISTEN BACKEND` | 200, plaintext, unchanged |
| L4+L5+L6+L7 flags together, plaintext | 200, `strip=/api` still rewrote `/api/users` → `/users` |
| Startup guardrails | all 8 exit 1 with a specific message |

**A verification bug worth recording.** The first guardrail run reported all four
cases exiting 1 and looked like a pass. It was not: unquoted `$args` in **zsh
does not word-split** (unlike bash), so each flag pair arrived as a single
argument, fell through to the route-spec arm, and exited 1 with `route spec
missing '=TARGET'` — the right exit code for entirely the wrong reason. Caught by
reading the error text rather than the exit status. Re-run with a shell function
taking `"$@"`, all eight then failed for their actual reasons. Level 7's
verification hit the same class of problem twice (a Python backend defaulting to
HTTP/1.0, a test script's `accept()` loop garbage-collecting the wrong socket);
the pattern is that **a passing test harness is itself untested code.**

Also fixed during verification: one new unit test wrote 200 KB into
`conn_with`'s 64 KB duplex and deadlocked the test suite — the test's bug, not
the proxy's. Reduced to 32 KB, which still exercises the multi-window path.

## Deliberately not built

Re-encrypt to backend, SNI passthrough, ACME/automatic certificates, session-
resumption tuning, response-side size limits, and reputation-fed deny lists
(Level 13). Rationale in the design doc's "Explicitly out of scope".
