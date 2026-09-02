# Level 13 — Basic WAF: Design

**Date:** 2026-09-02
**Course level:** 13 of 14 (`Build.md` LEVEL 13 — Basic WAF; KB § "Level 13 · Basic WAF")
**Follows:** Level 12 (Production Features)

## Scope

The KB's framing: a WAF is a reverse proxy that grew an immune system — and
"you already built the platform; the WAF is middleware with opinions."
Deliverables:

1. **Normalization** — the KB calls it 80% of WAF quality: URL-decode
   (twice, flagging double-encoding as itself suspicious), lowercase,
   collapse whitespace, decode basic HTML entities, canonicalize `.`/`..`
   path segments. Evasion is mostly encoding games.
2. **Detection** — scored signature rules over the normalized request
   surfaces (path, query string, selected headers) for:
   - **SQL injection** — quotes escaping into code context, `UNION SELECT`,
     comment tricks (`--`, `/**/`, `#`), tautologies (`OR 1=1`), stacked
     queries.
   - **XSS** — `<script>`, event handlers (`onerror=`), `javascript:` URLs,
     `<img/svg/iframe` vectors.
   - **Path traversal** — `..` escapes surviving canonicalization, encoded
     and double-encoded forms, absolute-path and null-byte tricks.
   - **Scanner fingerprints** — sqlmap/nikto/etc. User-Agents; absent UA
     scores a nuisance point.
3. **Anomaly scoring, not hair-triggers** — the ModSecurity CRS model: each
   rule adds points; block only ≥ threshold. A lone quote is 2 points; a
   quote + UNION + comment is a conviction.
4. **IP reputation** — score sources by their own recent behavior (WAF
   convictions); repeat offenders get a temporary ban with decay. The L4
   breaker's philosophy pointed inward at clients.
5. **Modes** — every WAF ships in detection mode first: `detect` (log +
   metrics, forward anyway) vs `block` (403). Per route.

**Out of scope, recorded:** request-**body** inspection (Ferrum streams
bodies by design — L1's flat-memory guarantee; buffering bodies for
inspection is a different architecture, noted as the honest limitation),
geo blocking (the KB itself says the interesting part is the plumbing,
which `allow-cidr`/`deny-cidr` already demonstrate), JS challenges / ML
(the KB's own "honesty checkpoint" labels those the vendors' layer).

## Decisions

### 1. A WAF is a middleware — literally

`Waf` implements the L6 `Middleware` trait and slots into the fixed chain
order as: **log → request-id → WAF → ratelimit → auth → authz**. Rationale:

- Before ratelimit/auth: a detected attack should never consume a rate
  token or trigger an auth comparison, and `rejected_by="waf"` must
  attribute correctly. (Rate limiting protects the backend from volume;
  the WAF refuses hostility outright — hostility first.)
- The middleware contract already provides: rejection short-circuiting
  (never touches a backend, the L6 invariant), response-phase unwind so a
  403 still carries its request-id and access-log line, per-route config
  via the option partition, and `rejected_by` log attribution.
- Detection itself is pure sync functions over the head — exactly the
  shape the L6 trait demands (and the L9 "small state machine" pattern).

Per-route options: `;waf=block` / `;waf=detect`, `;waf-threshold=N`
(default 10). Off by default like every security opt-in since L8's TLS.

### 2. Hand-rolled detectors on the existing `regex` dep — no RegexSet, no Aho-Corasick crate

The KB suggests `RegexSet` + Aho-Corasick as production shape. We already
have the `regex` crate (L2), but the detectors are deliberately **plain
string scans over the normalized buffer** where possible and a handful of
compiled regexes where structure matters. Reasons: the rule count is ~20,
not CRS's thousands — a linear pass over a normalized string beats the
setup cost of set-matching machinery at this scale; and the *lesson* is
normalization + scoring, not matcher engineering. The rules table is a
`const` array of (pattern-kind, points, name) — data, not code, so the
quiz can ask "add a rule" meaningfully.

### 3. Normalization is one function with receipts

`normalize(raw) -> Normalized { text, flags }`: percent-decode up to two
passes (a second pass that changes anything sets `DOUBLE_ENCODED`, itself
worth points — legitimate clients single-encode), `+`→space in queries,
lowercase, whitespace collapse, `\0` flagged, basic entity decode
(`&lt; &gt; &quot; &#x..; &#..;`). Path canonicalization resolves `.`/`..`
segments and flags any attempt to climb above root (`TRAVERSAL_ATTEMPT`)
even when the result lands innocently — the *attempt* is the signal, since
the backend's own resolution is unknown. Canonicalize-then-check, the L2
normalization weaponized, per the KB.

### 4. Scoring and conviction

`inspect(surfaces) -> Verdict { score, hits: Vec<&'static str> }`. Each
surface (path, query, UA, Referer) is normalized once and scanned; points
accumulate across surfaces. `score >= threshold` = conviction. In `block`
mode: 403 with a generic body (no rule names to the attacker — no oracle);
full hit list in the error log at WARN and in `rejected_total{by="waf"}`.
In `detect` mode: same logging, request forwarded, `X-Waf-Score` NOT added
(no oracle in either mode); the access log carries `waf_score` when > 0.

### 5. IP reputation: convictions → strikes → temp ban, lazily decayed

`Reputation`: 16-shard map (the L6/L11 idiom) keyed by client IP. A
conviction (block-mode score ≥ threshold) adds a strike with a timestamp;
`strikes >= ban_after` (default 3) within the decay window bans the IP for
`ban_secs` (default 60, doubling per repeat ban up to 1 h — the L4 breaker
backoff, inward). A banned IP's requests get 403 at the WAF step without
inspection (cheap refusal). Decay is lazy on lookup (the L11 TTL pattern);
`detect` mode records strikes but never bans — reputation enforcement is
part of enforcement mode. Global flags: `--waf-ban-after`, `--waf-ban-secs`.
Scope: process-lifetime, memory-only (a restart amnesties — honest for a
teaching proxy; commercial feeds are the vendors' moat, per the KB).

### 6. Observability

`ferrum_waf_events_total{result="convicted"|"detected"|"banned"|"ban_refused"}`
rendered by `waf.rs` (the L11 pattern), appended to `/metrics`. Access log
gains `"waf_score"` (only when > 0, `null` otherwise). Rejections attribute
as `rejected_by:"waf"` through the existing machinery.

## The honesty checkpoint (goes in code + PROGRESS verbatim-ish)

Signature WAFs are a speed bump, not a wall. Determined attackers bypass
regex rules; the real fixes live in the application (parameterized queries,
output encoding). This level buys: blocking the automated 99%, time during
0-days, and visibility. Body inspection, ML, shared reputation are the
commercial layers above. Build it knowing what it can and cannot promise.

## Components

| Unit | File | Responsibility | Depends on |
|------|------|----------------|-----------|
| Normalizer | `waf.rs` (new) | decode/canonicalize + evasion flags | std |
| Rules + scoring | `waf.rs` | rule table, inspect(), Verdict | regex (existing dep) |
| Reputation | `waf.rs` | sharded strikes/bans, lazy decay | std |
| Middleware | `waf.rs` | `impl Middleware for Waf`, ban check → inspect → verdict | middleware/mod.rs |
| Route options | `router.rs`, `middleware/mod.rs` (edit) | `waf=`, `waf-threshold=` in L6_KEYS (it configures a middleware) | — |
| CLI + shared state | `main.rs` (edit) | `--waf-ban-after/-secs`, one `Arc<Reputation>` shared across routes | — |
| Metrics/log | `metrics.rs` render hook, `observe.rs`, `admin.rs` (edit) | waf_events_total, waf_score field | — |

Chain order lives in `MiddlewareConfig::build` (code, never config), as L6
established.

## Error handling

- The WAF can reject but never error: a normalization pathology (e.g.
  overlong percent sequence) scores points rather than 500s.
- Reputation lock poisoning: fail open per request (no ban check), the
  L6/L11 stance.
- `;waf=` with an unknown mode or non-numeric threshold: startup error
  (the L5/L6 guardrail posture).

## Testing

- Unit: normalization table (single/double encode, entities, null byte,
  `+`, case, whitespace); canonicalization incl. climb-above-root flag;
  each detector against real payloads (`' OR 1=1--`, `1 UNION SELECT
  password FROM users`, `<script>alert(1)</script>`, `<img src=x
  onerror=alert(1)>`, `javascript:` URLs, `../../../etc/passwd`,
  `%2e%2e%2f` and `%252e%252e%252f` forms, sqlmap UA) AND benign
  lookalikes that must stay under threshold (`O'Brien`, `union station`,
  `select a plan`, `script kiddie` as literal text, `/docs/1.2.3/path`);
  scoring accumulation across surfaces; ban threshold, decay, backoff
  doubling; detect-mode-never-bans.
- Wiring: chain order includes WAF at the right slot; rejection
  attribution; 261 existing tests stay green.
- Live: attack payloads → 403 with `rejected_by:"waf"` and zero backend
  hits; encoded variants caught; benign traffic passes; 3 convictions →
  ban → unrelated request from that IP also 403 → wait decay → served
  again; `;waf=detect` logs score and forwards; metrics counters move;
  a route without `;waf=` is untouched.
