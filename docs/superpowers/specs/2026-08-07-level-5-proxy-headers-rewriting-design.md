# Level 5 — Proxy Headers & Rewriting: Design

**Date:** 2026-08-07
**Course:** [Build.md](../../../Build.md) Level 5
**Status:** approved, ready for implementation planning
**Mode:** "I implement, you learn" — heavy in-code teaching comments, quiz at the end

## Goal

Make the proxy honest about itself. Right now a backend sees a request that
appears to come from the proxy, on the proxy's own terms: the client's IP is
lost, the original `Host` is whatever the client sent, and the path is
whatever the client asked for. Level 5 adds the two halves of being a *reverse
proxy* rather than a dumb forwarder:

1. **Forwarded headers** — tell the backend who really called
   (`X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`).
2. **Rewriting** — change what the backend sees (path, `Host`, arbitrary
   request and response headers) so the proxy's public URL space can differ
   from the backend's internal one.

The eight Build.md items map onto these: header manipulation, XFF, XFH, XFP,
X-Real-IP, URL rewriting, header rewriting, host rewriting.

## Non-goals (owned by later levels)

- **A middleware pipeline.** Level 6 owns the extensible chain. Level 5 is a
  single fixed transform step; Level 6 will generalize it. Deliberately *not*
  building a plugin architecture now — YAGNI, and Level 6's design should be
  free to choose its own abstraction.
- **`Forwarded:` (RFC 7239).** The standardized single-header form. The
  `X-*` family is what backends actually read; adding both doubles the surface
  for no teaching gain. Noted as a documented gap.
- **HTTPS / `X-Forwarded-Proto: https`.** Level 8 adds TLS termination. We
  emit `http` and leave a one-line seam.
- **Cookie/session rewriting, `Set-Cookie` domain rewriting.** Needs response
  cookie parsing; not in Build.md's list for this level.
- **Regex path rewriting with capture groups.** Prefix strip/replace covers the
  common cases (`/api/**` → backend `/`); full regex substitution is a
  documented extension point.
- **Trusting inbound XFF selectively.** We always append (never trust-and-
  replace), which is the safe default. Trusted-proxy allowlists are a Level 13
  (WAF/reputation) concern.

## Architecture

One new module, one new call site.

```
   request  ──►  route match  ──►  pool pick  ──►  ┌──────────────────┐
   (L2)          (L3/L4)                            │  TRANSFORM (L5)  │
                                                    │  rewrite.rs      │
                                                    │  • path rewrite  │
                                                    │  • Host rewrite  │
                                                    │  • XFF/XRI/XFH/  │
                                                    │    XFP injection │
                                                    │  • header set/rm │
                                                    └────────┬─────────┘
                                                             ▼
                                              forward to backend  (L1)
                                                             │
                                              response head ◄─┘
                                                    ┌──────────────────┐
                                                    │ RESPONSE HEADERS │
                                                    │ set / remove     │
                                                    └────────┬─────────┘
                                                             ▼
                                                          client
```

### New module: `rewrite.rs`

Owns `RewriteRules` (the parsed per-route configuration) and the two transform
entry points:

- `apply_request(&self, req: &mut RequestHead, ctx: &ForwardContext)`
- `apply_response(&self, resp: &mut ResponseHead)`

Both are **pure, synchronous functions over a head struct** — no sockets, no
async, no I/O. That is deliberate: it makes the entire level unit-testable by
constructing a `RequestHead`, applying rules, and asserting on the result. The
same discipline that kept `Breaker` testable in Level 4.

`ForwardContext` carries what the transform needs from the connection that the
head itself doesn't know:

```rust
pub struct ForwardContext<'a> {
    /// The immediate peer's IP — the client, or the last proxy in the chain.
    pub client_ip: IpAddr,
    /// The Host the client originally asked for, captured BEFORE any rewrite.
    pub original_host: Option<&'a str>,
    /// "http" today; Level 8 sets "https" after TLS termination.
    pub scheme: &'static str,
}
```

### Where it plugs in

`proxy.rs::serve_one`, at the existing request-rewrite site (currently the
`strip_hop_by_hop` / framing block around line 456). Ordering matters and is
fixed:

1. `strip_hop_by_hop` (existing) — remove headers that must not be forwarded.
2. **`rules.apply_request(&mut req, &ctx)`** (new).
3. Framing re-declaration (existing) — `Connection: close`,
   `Transfer-Encoding: chunked`.

Step 2 sits between them on purpose. It must run *after* hop-by-hop stripping
(so a client can't smuggle in a `Connection`-listed header that our rewrite
then re-adds) and *before* framing (so a misconfigured
`set-header: Transfer-Encoding: ...` can never displace the framing headers we
own — the parser's smuggling guarantees from Level 1 stay intact).

Response rewriting hooks in after `strip_hop_by_hop(&mut resp.headers)`, for
the same reason.

## The forwarded headers

On by default for every route — these are near-universal and requiring opt-in
would make the common case wrong. `--no-forwarded` disables all four globally.

| Header | Value | Semantics |
|---|---|---|
| `X-Forwarded-For` | append `client_ip` to any existing value | The chain. `1.2.3.4, 10.0.0.1` means the original client was `1.2.3.4` and it passed through `10.0.0.1`. |
| `X-Real-IP` | `client_ip`, **overwritten** | The immediate peer only. Single-valued by convention. |
| `X-Forwarded-Host` | `original_host`, set only if absent | The `Host` the client asked for, captured before Host rewriting. |
| `X-Forwarded-Proto` | `ctx.scheme` (`http`), set only if absent | Scheme on the client leg. |

**Append vs. overwrite is the security-relevant decision.** For `X-Forwarded-For`
we **append** rather than replace: replacing would let this proxy erase the
chain recorded by upstream proxies, and *trusting* an inbound value outright
would let any client forge its own origin IP by sending
`X-Forwarded-For: 1.2.3.4`. Appending is honest in both directions — the
rightmost entry is always the one *we* observed and cannot be forged; anything
to its left is hearsay from upstream. The teaching point: a backend reading XFF
must count from the right, not the left, and must know how many proxies it sits
behind.

`X-Real-IP` is overwritten precisely because it is *not* a chain: a client-sent
`X-Real-IP` is a forgery attempt, and there is no legitimate multi-hop meaning
to preserve.

`X-Forwarded-Host` / `-Proto` are set only if absent, so a legitimate upstream
proxy's value survives (it knows the true original, we don't).

## Rewriting

### Path rewriting

Two forms, both operating on the target's path while preserving the query
string:

- `strip=/api` — remove the prefix. `/api/users?p=2` → `/users?p=2`.
  The single most common reverse-proxy rewrite: the proxy exposes `/api/**`,
  the backend serves `/**`.
- `prefix=/v2` — prepend. `/users` → `/v2/users`.

Both may be combined; `strip` runs first, then `prefix`. Result is always
normalized to start with `/` — stripping `/api` from exactly `/api` yields `/`,
not the empty string, because an empty request target is malformed.
The query string is split off before rewriting and re-appended after, so `?`
and `#` in the path can't be mangled.

### Host rewriting

- `host=backend.local` — replace the `Host` header sent to the backend.

The original is captured into `X-Forwarded-Host` *before* replacement, which is
the whole reason `ForwardContext.original_host` exists and why capture must
happen at the top of `apply_request`.

### Header rewriting

- `set-header=Name:Value` — add or overwrite a request header.
- `remove-header=Name` — remove a request header.
- `set-resp-header=Name:Value` / `remove-resp-header=Name` — same on the
  response.

Repeatable. `set` is an overwrite (remove-then-push), not an append, so a rule
is idempotent and can't accumulate duplicates across retries.

**Guardrail:** a rule may not target a framing or connection header —
`Content-Length`, `Transfer-Encoding`, `Connection`, `Host` (use `host=`
instead). Attempting it is a **startup error**, not a silent ignore: a config
that appears to set `Transfer-Encoding` but doesn't would be a trap, and one
that actually did would reopen the Level 1 smuggling holes.

## Config surface (CLI)

Rewrite rules attach to a route, appended to the existing route-spec grammar
with `;`-separated options — the same shape Level 4 used for `;health=`:

```
/api/**=api;strip=/api;host=backend.local
/legacy/**=127.0.0.1:9002;strip=/legacy;prefix=/v1;set-header=X-Env:prod
/=web;remove-resp-header=Server
```

`ROUTE = [METHOD ][host]path_expr=TARGET[;opt=val]...`

| Option | Meaning |
|---|---|
| `strip=/p` | Remove path prefix |
| `prefix=/p` | Prepend path prefix |
| `host=h` | Rewrite the `Host` header |
| `set-header=N:V` | Set/overwrite a request header |
| `remove-header=N` | Remove a request header |
| `set-resp-header=N:V` | Set/overwrite a response header |
| `remove-resp-header=N` | Remove a response header |

Global: `--no-forwarded` turns off all four `X-Forwarded-*`/`X-Real-IP`
injections.

**Validation at startup** (all hard errors): unknown option name; `strip`/
`prefix`/`host` with an empty value; `set-header` without a `:`; any header
rule naming a protected header (see guardrail above). Note `Route` grows a
`rules: RewriteRules` field; a route with no options gets
`RewriteRules::default()`, which injects the forwarded headers and nothing else.

**Backward compatibility:** every existing invocation keeps working. A route
spec with no `;` options parses exactly as before. The one *intentional*
behavior change is that requests now carry four extra headers to the backend —
that is the point of the level, and `--no-forwarded` restores the old bytes
exactly.

## Data flow

```
client req ──► strip_hop_by_hop
           ──► apply_request:
                 1. capture original Host           (before anything mutates it)
                 2. path: strip -> prefix           (query preserved)
                 3. Host rewrite                    (if host=)
                 4. XFF append / XRI set / XFH+XFP set-if-absent
                 5. set-header / remove-header      (protected names rejected at startup)
           ──► framing re-declaration              (Connection, Transfer-Encoding)
           ──► backend

backend resp ──► strip_hop_by_hop
             ──► apply_response: set-resp-header / remove-resp-header
             ──► framing re-declaration
             ──► client
```

Step 1 before step 3 is load-bearing: capture the original `Host` before the
rewrite overwrites it, or `X-Forwarded-Host` reports the rewritten value and
the backend can never learn what the client actually asked for.

Step 5 last means an explicit `set-header` can deliberately override an
injected forwarded header (e.g. pinning `X-Forwarded-Proto: https` behind an
external TLS terminator) — a useful escape hatch, and the reason header rules
run after injection rather than before.

## Observability

Extend the existing per-request log line with the rewritten target and Host
when either actually changed, so a rewrite is visible without guesswork:

```
[127.0.0.1:54321] GET /api/users HTTP/1.1 -> api[lc] 127.0.0.1:9002 (inflight=1)
    rewrite: /api/users -> /users  host: example.com -> backend.local
```

Emitted only when something changed, so unrewritten routes stay quiet.

## Testing

Unit tests in `rewrite.rs` — all pure, no sockets:

1. XFF appends to an existing chain (`1.2.3.4` + our IP → `1.2.3.4, <ip>`).
2. XFF is created when absent.
3. A client-forged `X-Real-IP` is overwritten, not preserved.
4. `X-Forwarded-Host` / `-Proto` are set when absent and preserved when
   already present.
5. `X-Forwarded-Host` captures the ORIGINAL host even when `host=` rewrites it
   (the ordering bug this design exists to prevent).
6. `--no-forwarded` injects none of the four.
7. `strip` removes the prefix and preserves the query string.
8. `strip` of the whole path yields `/`, not `""`.
9. `strip` that doesn't match the path leaves it unchanged.
10. `prefix` prepends; `strip`+`prefix` compose in the documented order.
11. `host=` replaces `Host`.
12. `set-header` overwrites an existing value rather than duplicating it.
13. `remove-header` removes case-insensitively.
14. Response `set-resp-header` / `remove-resp-header` work.
15. Spec parser: every option, combined options, whitespace.
16. Spec parser errors: unknown option, empty values, `set-header` without
    `:`, and each protected header name rejected.
17. Route integration: a route with no `;` options still parses and yields
    default rules (backward compatibility).

Existing 73 tests must keep passing. Tests that assert exact forwarded bytes to
a backend may need the four new headers accounted for — that is the one
expected mechanical adjustment. Target ~95 tests.

**Live verification:** a python backend that echoes the request headers and
path it received.
- Confirm `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`,
  `X-Forwarded-Proto` all arrive with correct values.
- Send a request already carrying `X-Forwarded-For: 1.2.3.4` and confirm our IP
  is *appended*, and that a forged `X-Real-IP` is *replaced*.
- Confirm `strip=/api` makes the backend see `/users` while the client asked
  for `/api/users`, with the query string intact.
- Confirm `host=` changes the `Host` the backend sees while
  `X-Forwarded-Host` still reports the original.
- Confirm `remove-resp-header=Server` strips it from the client's response.
- Confirm `--no-forwarded` produces byte-identical headers to Level 4.
- Confirm a protected-header rule fails startup with exit 1.

## Implementation order

1. `rewrite.rs`: `RewriteRules`, `ForwardContext`, forwarded-header injection
   only (`apply_request` partial) + tests 1–6. Add `http::set_header`.
2. Path rewriting (`strip`/`prefix`, query preservation) + tests 7–10.
3. Host rewriting + request/response header rules + tests 11–14.
4. Spec parser + startup validation incl. protected-header guardrail +
   tests 15–16.
5. Wire into `router.rs` (`Route.rules`) and `proxy.rs` (both call sites, in
   the documented order); keep all 73 tests green + test 17.
6. Log line, live verification, PROGRESS.md, Level 5 quiz.
