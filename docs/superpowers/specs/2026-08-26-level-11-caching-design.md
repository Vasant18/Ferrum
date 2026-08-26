# Level 11 — Caching: Design

**Date:** 2026-08-26
**Course level:** 11 of 14 (`Build.md` LEVEL 11 — Caching; knowledge base § "Level 11 · Caching")
**Follows:** Level 10 (Observability)

## Scope

The KB's framing: the fastest backend request is the one you never make. This
level turns Ferrum into a shared HTTP cache that honors the protocol's own
caching contract rather than inventing one:

1. **Storage engine** — bounded in-memory cache, sharded, approximate LRU +
   TTL, no locks held across `.await`.
2. **HTTP semantics** — what is safe to cache (method/status/headers), TTL
   from `Cache-Control` (`s-maxage` > `max-age`), `no-store`/`no-cache`/
   `private` honored, `Vary` in the cache key, `Authorization`/`Set-Cookie`
   exclusions.
3. **Revalidation** — both legs: proxy→origin conditional requests
   (`If-None-Match`/`If-Modified-Since` → 304 re-stamps the entry, one tiny
   round trip instead of re-transferring the payload) and client→proxy
   conditionals (client's `If-None-Match` against the cached `ETag` → 304
   with no body).
4. **Invalidation** — RFC 9111 §4.4: a non-error response to an unsafe method
   (POST/PUT/DELETE/PATCH) invalidates the cached entry for that URI.

Explicitly **out of scope**, recorded not forgotten:

- **Stampede defenses** (request coalescing / singleflight,
  stale-while-revalidate, TTL jitter). The KB calls coalescing "a lovely
  exercise"; it is also a second synchronization design on top of a level
  that already has one. Recorded as the level's known debt — the spec
  documents the failure mode so the quiz can ask about it.
- **Disk persistence.** Memory only; a restart is a cold cache, which is
  correct for a teaching proxy and most production edges.
- **`stale-if-error`, range requests, `Warning` headers.** YAGNI.

## Decisions

### 1. From scratch, zero new dependencies

Consistent with the whole course (and this level is even less dangerous than
L10: a cache bug is a stale page or a leak the tests catch, not a CVE — with
ONE exception, the cache key, which gets its own decision below). The KB
itself notes the classic linked-list LRU is "famously miserable" in safe Rust
and blesses the alternative production caches actually use: **a sharded map
with approximate LRU**. That is L6's 16-shard rate limiter pattern applied to
a bigger value type, so the codebase already contains the idiom.

### 2. Sharded, approximately-LRU, doubly-bounded

`cache.rs`: `Cache` = 16 shards, each `std::sync::Mutex<Shard>` where `Shard`
holds a `HashMap<Key, Entry>` plus running byte total. Same discipline as
every lock since L6: plain `fn`, lock scope is a few lines, never across
`.await` (compiler-enforced, per L9).

- **Approximate LRU**: each entry carries `last_used: Instant`, bumped on
  hit. On insert overflowing either bound, the shard evicts its
  least-recently-used entries until the new one fits. Eviction scans only
  that shard (1/16 of the cache) — O(shard) on the insert path, zero cost on
  the hit path. A true O(1) recency list buys speed we cannot measure here
  and costs either `unsafe` or an arena; the honest engineering call at this
  scale is the scan, and the doc comment says so.
- **Doubly bounded**: `--cache-max-bytes` (default 64 MB, the real bound —
  bodies dominate) and `--cache-max-entries` (default 4096, a metadata bound
  so a million 10-byte responses can't balloon the map). Per-shard bounds are
  the totals /16.
- **TTL is lazy**: expiry checked on lookup; no background sweeper task. An
  expired entry with validators isn't discarded — it becomes a revalidation
  candidate (below). One with no validators is treated as a miss and
  replaced.
- **Bodies are `Arc<[u8]>`**: a hit hands the client a refcount bump, not a
  copy; an entry evicted while a hit is still streaming it stays alive until
  that response finishes. No copy, no use-after-evict, no lock held while
  writing to the client.

### 3. Opt-in per route; HTTP decides the rest

Caching is enabled per route with a new `;cache[=DEFAULT_TTL]` option (a new
`L11_KEYS` arm in the router's existing partition — `rewrite.rs` and
`middleware/mod.rs` need no changes, same as L6 promised). Off by default:
a proxy that silently starts caching is a behavior change an operator must
ask for (nginx's `proxy_cache` is opt-in for the same reason).

Once enabled, **the protocol decides per response**:

- Cacheable: `GET` requests, response status 200/301/404, no
  `Authorization` on the request, no `Set-Cookie` on the response, no
  `no-store`/`private` in the response `Cache-Control`, body fits
  `--cache-max-body` (default 1 MB).
- TTL: `s-maxage` (shared-cache-specific, our cache IS shared) beats
  `max-age`; if neither is present, `DEFAULT_TTL` from the route option
  (default 60 s) applies **only when the response carries a validator**
  (`ETag` or `Last-Modified`) — freshness we invent must at least be
  revalidatable; a response with no explicit freshness and no validator is
  not cached.
- `no-cache`: stored but marked always-stale — every use revalidates. (The
  confusingly-named one; the KB calls this out and so will the code.)
- `Vary`: the named request headers' values join the cache key. `Vary: *`
  is uncacheable per RFC.

### 4. The cache key — the level's one dangerous decision

The KB: "getting the key wrong is how caches leak one user's data to another
— the worst bug class in this level." Key =
`method + host (from the ORIGINAL request, port-stripped) + path + query +
each Vary header's (name, value) pairs`, hashed into the shard index but
stored **in full and compared on lookup** — hash collisions must degrade to a
miss, never to serving the colliding entry. Keyed on the *pre-rewrite*
target (what the client asked for), because two routes rewriting differently
must not share entries; the route index is part of the key for the same
reason.

### 5. Placement in `serve_one`: after middleware, instead of the lease

Lookup runs AFTER the middleware chain (a cached response must never bypass
auth or rate limiting — a 401'd client gets no cache read at all) and
INSTEAD OF the balancer lease on a fresh hit (no backend socket, no breaker
traffic, no inflight count — the shield the KB describes). The hit
constructs a `ResponseHead` from the entry and runs the normal client-leg
pipeline: middleware `run_response_all` (request-id/log), L5
`apply_response`, framing block. One response path, cached or not.

What is stored is the **origin's response**: captured after
`strip_hop_by_hop(resp)` but before the client-leg mutations (middleware
response phase, L5 response rules, framing/Connection rewrite) — hop-by-hop
headers are connection-specific by definition, and client-leg headers
describe *this* client's connection, not the resource. Body captured by
teeing `copy_body_to` into a bounded buffer; outgrowing `--cache-max-body`
mid-stream drops the buffer and keeps streaming (the client is unaffected;
the entry just isn't stored).

### 6. Revalidation, both legs

- **Proxy→origin** (the ETag lesson): a stale entry with a validator turns
  the outbound request conditional — `If-None-Match: <etag>` /
  `If-Modified-Since: <last-modified>` added to the forwarded head. Origin
  answers **304** → re-stamp the entry's freshness from the 304's
  `Cache-Control` (else `DEFAULT_TTL`), serve the cached body, count a
  `revalidated` hit. Origin answers 200 → normal miss path, entry replaced.
  Any other status → passed through, entry dropped.
- **Client→proxy**: client sends `If-None-Match` matching the entry's
  `ETag` (or `If-Modified-Since` >= entry's `Last-Modified`) and the entry
  is fresh → **304 with no body** straight from the proxy. The full-fidelity
  weak/strong comparison rules collapse to: strip `W/`, compare
  octet-exactly, honor `*`.

### 7. Invalidation

RFC 9111 §4.4: a **non-error** response (2xx/3xx) to POST/PUT/DELETE/PATCH
through a cached route invalidates the stored entry for that URI (all Vary
variants — invalidation is by URI prefix of the key). Write-through
correctness for the common CRUD shape: update-then-read sees the update.
No admin purge endpoint this level; `Vessey can curl -X POST` any URI he
wants purged, and a real purge API belongs with L12's config story.

### 8. Observability (L10 pays forward)

- Metrics: `ferrum_cache_events_total{result="hit"|"miss"|"revalidated"|"stored"|"evicted"|"invalidated"}`
  — one counter family, label set fixed at startup, same no-alloc discipline.
- `X-Cache: HIT|MISS|REVALIDATED` response header on cached routes; `Age`
  header on hits per RFC.
- Access log gains `"cache":"hit"|"miss"|"revalidated"|null` (null = route
  not cached / request not cacheable).

## Components

| Unit | File | Responsibility | Depends on |
|------|------|----------------|-----------|
| Storage | `cache.rs` (new) | Key, Entry, sharded LRU+TTL store, bounds | std only |
| Semantics | `cache.rs` (same file, separate section) | cacheability, TTL parse, validator compare, key build | http.rs helpers |
| Wiring | `proxy.rs` (edit) | lookup/store/revalidate/invalidate in `serve_one`, body tee | cache, metrics |
| Route opt-in | `router.rs` (edit) | `L11_KEYS = ["cache"]` partition arm, `Route.cache_ttl` | — |
| CLI + registry | `main.rs` (edit) | `--cache-max-bytes/-entries/-body`, one shared `Arc<Cache>` | — |
| Metrics | `metrics.rs` (edit) | `cache_events_total` family | — |
| Log field | `middleware/mod.rs`, `observe.rs` (edit) | `ctx.cache` → JSON field | — |

## Error handling

- Cache full / oversized body / any store failure: never an error — the
  request proceeds uncached. A cache must fail open; only the metrics see it.
- A revalidation attempt against a dead backend follows the existing
  connect-retry/breaker path; if no backend answers, the stale entry is NOT
  served (no `stale-if-error` this level) — the client gets the same 502 an
  uncached request would.
- Poisoned shard mutex: same fail-open stance as L6's limiter (treat as
  miss).

## Testing

- Unit (cache.rs): key equality incl. Vary values and route index; collision
  degrades to miss; TTL expiry lazy on lookup; LRU eviction order within a
  shard; byte + entry bounds enforced; `s-maxage`-beats-`max-age`;
  `no-store`/`private`/`Set-Cookie`/`Authorization` exclusions; `no-cache` =
  always-stale; validator comparison (strong, `W/` stripping, `*`);
  invalidation removes all variants; concurrent hammer (the L6/L10 pattern).
- Wiring: existing 230 stay green; access-log/metrics assertions extend.
- Live: hit (backend accept count frozen, `X-Cache: HIT`, `Age` grows),
  expiry → miss, ETag → proxy sends `If-None-Match`, backend 304s, client
  gets 200 full body (`X-Cache: REVALIDATED`); client `If-None-Match` → 304
  no body; `Vary: Accept-Encoding` stores two variants; `no-store` never
  cached; POST invalidates; LRU eviction under a tiny `--cache-max-bytes`;
  `cache_events_total` moves; uncached route untouched.
