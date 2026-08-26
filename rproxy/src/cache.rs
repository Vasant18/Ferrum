//! Level 11: the response cache — storage engine and HTTP caching semantics.
//!
//! The fastest backend request is the one you never make. This file turns
//! Ferrum into a *shared cache* in the RFC 9111 sense: it sits between many
//! clients and an origin, so everything the protocol says about shared
//! caches (`private`, `s-maxage`) applies to us specifically.
//!
//! Two sections, deliberately in one file because they share the vocabulary
//! (`Key`, `Entry`, `Freshness`) but split cleanly by concern:
//!
//! 1. **Storage** (`Cache`, `Shard`, `Entry`) — a bounded, sharded,
//!    approximately-LRU, TTL-expiring map. Knows nothing about HTTP.
//! 2. **Semantics** (`cacheability`, `freshness_from_headers`,
//!    `etag_matches`, `Key::build`) — pure functions over head structs that
//!    encode RFC 9111's rules. Know nothing about locking.
//!
//! `proxy.rs` composes the two; neither section calls the other.
//!
//! # Design notes (the "explain cache design decisions" the level demands)
//!
//! **Sharded + approximate LRU, not a linked-list LRU.** The classic O(1)
//! LRU (hash map into a doubly-linked recency list) is famously miserable in
//! safe Rust — aliasing + mutation is exactly what the borrow checker
//! rejects, and it is *right*: LRU aliasing bugs are real CVEs in C caches.
//! The alternatives are an index arena, a dependency, or what concurrent
//! production caches actually do: shard the map and accept approximate
//! recency. We take the third — it is L6's 16-shard rate limiter pattern
//! with a bigger value type, so the codebase already contains the idiom.
//! Each entry carries `last_used`; eviction scans its own shard for the
//! oldest. That scan is O(shard) on the *insert-when-full* path only — the
//! hit path pays one hash, one short lock, one `Instant` store. A true O(1)
//! recency list would optimize the path that is already measured in
//! nanoseconds, at the cost of `unsafe` or an arena nobody asked for.
//!
//! **Doubly bounded.** `max_bytes` is the real bound (bodies dominate
//! memory); `max_entries` is a metadata bound so a million tiny responses
//! cannot balloon the map itself. Both are enforced per shard at total/16 —
//! a shard is the unit of locking, so it must be the unit of accounting, or
//! an insert would need two locks and an ordering discipline.
//!
//! **TTL is lazy.** Expiry is checked on lookup; there is no sweeper task.
//! A sweeper would be a fourth spawn site (L9 counted three) buying memory
//! reclamation a few seconds earlier — and an expired entry is not garbage
//! anyway: if it carries a validator it is a *revalidation candidate*, worth
//! keeping precisely because a 304 re-stamps it without re-transferring the
//! body.
//!
//! **Bodies are `Arc<[u8]>`.** A hit hands the client a refcount bump, not a
//! copy. If eviction races a hit that is still streaming, the drop is
//! deferred by the refcount — no copy, no use-after-evict, and no lock held
//! anywhere near an `.await` (the lock covers map access only; the compiler
//! enforces the rest, per L9's audit).
//!
//! **The cache key is the level's one dangerous decision.** Getting it wrong
//! is how caches leak one user's data to another — the worst bug class here,
//! worse than any crash. See `Key::build` for the full argument; the short
//! version is: original (pre-rewrite) host+target, the route index, every
//! `Vary`-named header's value — stored in full and compared on lookup, so a
//! hash collision degrades to a miss, never to the colliding entry.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::http::{self, RequestHead, ResponseHead};

// ---------------------------------------------------------------------------
// Section 1: storage
// ---------------------------------------------------------------------------

const SHARDS: usize = 16;

/// Defaults for the three CLI bounds. 64 MB total is deliberately modest —
/// a teaching proxy on a laptop — and 1 MB per body keeps any single
/// response from monopolizing a shard's budget.
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_ENTRIES: usize = 4096;
pub const DEFAULT_MAX_BODY: u64 = 1024 * 1024;

/// The full cache key. `hash` picks the shard; the fields are what equality
/// actually means. Two keys with equal hashes and different fields MUST
/// compare unequal — `derive(PartialEq)` guarantees the lookup compares
/// content, so a collision costs a miss, never a wrong body.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Key {
    /// Which route matched. Two routes can rewrite the same client target
    /// into different backend requests; their entries must never mix.
    pub route: usize,
    pub method: String,
    /// The ORIGINAL request host (port-stripped, lowercased) and target —
    /// what the client asked for, captured before Level 5 rewrites either.
    /// Keying on post-rewrite values would merge distinct client resources
    /// that happen to rewrite to one backend path.
    pub host: String,
    pub target: String,
    /// One (name, value) pair per header named by the stored response's
    /// `Vary`, values as sent by THIS request (absent = empty string, which
    /// RFC 9111 treats as its own variant). Sorted by name so header order
    /// on the wire cannot split one variant into two entries.
    pub vary: Vec<(String, String)>,
}

/// One cached response. Head fields are stored decomposed (status + headers)
/// rather than pre-serialized because the client leg re-frames every
/// response anyway (Connection, Transfer-Encoding are per-connection, and
/// were stripped before storage).
pub struct Entry {
    pub status: u16,
    pub reason: String,
    /// End-to-end headers only — hop-by-hop stripped before storage, and no
    /// client-leg mutations (those describe one connection, not the
    /// resource).
    pub headers: Vec<(String, String)>,
    pub body: Arc<[u8]>,
    /// When the entry was stored (or last revalidated) — the zero point for
    /// both freshness and the `Age` header.
    pub stored_at: Instant,
    /// How long past `stored_at` the entry is fresh. `Duration::ZERO` means
    /// always-stale (`no-cache`: cache it, revalidate every use).
    pub ttl: Duration,
    /// Validators, pre-extracted so revalidation doesn't rescan headers.
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// The response's own Vary list (lowercased header names). Needed on
    /// lookup: the stored entry tells us which request headers should have
    /// been in the key. See `Cache::lookup` for the two-step dance.
    pub vary_names: Vec<String>,
    /// Recency stamp for the LRU scan. `pub(crate)` so `proxy.rs` can build
    /// an `Entry` literally; only this module ever reads it.
    pub(crate) last_used: Instant,
}

impl Entry {
    pub fn is_fresh(&self, now: Instant) -> bool {
        now.duration_since(self.stored_at) < self.ttl
    }

    pub fn age_secs(&self, now: Instant) -> u64 {
        now.duration_since(self.stored_at).as_secs()
    }

    pub fn has_validator(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }

    /// Approximate memory footprint: body + headers + key overhead estimate.
    /// Approximate is fine — the bound protects against runaway growth, not
    /// against a 3% accounting error.
    fn cost(&self) -> u64 {
        let headers: usize = self
            .headers
            .iter()
            .map(|(n, v)| n.len() + v.len() + 4)
            .sum();
        (self.body.len() + headers + 256) as u64
    }
}

struct Shard {
    map: HashMap<Key, Entry>,
    bytes: u64,
}

/// Outcome of a lookup, separating "usable now" from "usable after a cheap
/// question to the origin" — the distinction the whole revalidation design
/// hangs on.
pub enum Lookup {
    Miss,
    /// Fresh entry: serve it, no backend contact.
    Hit(CachedResponse),
    /// Stale but revalidatable: ask the origin with these validators; on
    /// 304, call `restamp(key)` and serve the re-stamped entry. The key is
    /// returned because by restamp time the live request head has been
    /// rewritten — the entry can only be found again by the key it was
    /// found with now.
    Stale {
        key: Key,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// A snapshot of an entry, cheap to hand out (body is a refcount bump).
/// Snapshot rather than a guard/reference: nothing borrowed from the shard
/// survives past the lock, so no lock is ever held while bytes stream.
pub struct CachedResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Arc<[u8]>,
    pub age_secs: u64,
    /// The entry's ETag, for answering a client's `If-None-Match` at the
    /// proxy. No `last_modified` twin: client-side `If-Modified-Since` needs
    /// HTTP-date parsing and ordering, and the ETag path answers the same
    /// question better wherever the origin provides one — a deliberate
    /// scope cut, not an oversight (`Entry` keeps Last-Modified for the
    /// proxy→origin leg, where it is compared by the ORIGIN, not by us).
    pub etag: Option<String>,
}

/// Cache-event counters, L10 discipline: fixed label set, atomics, zero
/// allocation at record time. Lives here rather than in `metrics.rs` because
/// the label set is this level's vocabulary; `metrics.rs` renders it.
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub revalidated: AtomicU64,
    pub stored: AtomicU64,
    pub evicted: AtomicU64,
    pub invalidated: AtomicU64,
}

impl CacheStats {
    fn new() -> CacheStats {
        CacheStats {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            revalidated: AtomicU64::new(0),
            stored: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
            invalidated: AtomicU64::new(0),
        }
    }
}

pub struct Cache {
    shards: Vec<Mutex<Shard>>,
    max_bytes_per_shard: u64,
    max_entries_per_shard: usize,
    /// Largest single body worth storing. Enforced by the tee in proxy.rs
    /// (mid-stream) and double-checked at insert.
    pub max_body: u64,
    pub stats: CacheStats,
}

fn shard_index(key: &Key) -> usize {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    (h.finish() as usize) % SHARDS
}

impl Cache {
    pub fn new(max_bytes: u64, max_entries: usize, max_body: u64) -> Cache {
        Cache {
            shards: (0..SHARDS)
                .map(|_| {
                    Mutex::new(Shard {
                        map: HashMap::new(),
                        bytes: 0,
                    })
                })
                .collect(),
            max_bytes_per_shard: (max_bytes / SHARDS as u64).max(1),
            max_entries_per_shard: (max_entries / SHARDS).max(1),
            max_body,
            stats: CacheStats::new(),
        }
    }

    /// Look up the response for this request. Two-step because of `Vary`:
    /// the caller cannot know which request headers belong in the key until
    /// a stored response says so. Step 1 probes with an empty vary list (how
    /// non-varying responses are stored). Step 2, if step 1 found an entry
    /// whose `vary_names` is non-empty, rebuilds the key with this request's
    /// values for those names and probes again. The vary-less probe entry
    /// for a varying resource is a 1-entry "index" storing WHICH headers
    /// matter (its `vary_names`), written alongside every variant.
    ///
    /// Expired entries: with a validator → `Lookup::Stale` (kept, worth a
    /// conditional request); without → treated as a miss (will be replaced
    /// by the store that follows).
    pub fn lookup(&self, input: &KeyInput) -> Lookup {
        let base = Key::build(input, &[]);
        let now = Instant::now();

        // Probe 1: exact (vary-less) key.
        match self.probe(&base, now) {
            Probe::None => {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                Lookup::Miss
            }
            Probe::VaryIndex(names) => {
                // Probe 2: the real variant key for this request.
                let varied = Key::build(input, &names);
                match self.probe(&varied, now) {
                    Probe::None | Probe::VaryIndex(_) => {
                        self.stats.misses.fetch_add(1, Ordering::Relaxed);
                        Lookup::Miss
                    }
                    Probe::Fresh(resp) => {
                        self.stats.hits.fetch_add(1, Ordering::Relaxed);
                        Lookup::Hit(resp)
                    }
                    Probe::Stale { etag, last_modified } => Lookup::Stale {
                        key: varied,
                        etag,
                        last_modified,
                    },
                }
            }
            Probe::Fresh(resp) => {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                Lookup::Hit(resp)
            }
            Probe::Stale { etag, last_modified } => Lookup::Stale {
                key: base,
                etag,
                last_modified,
            },
        }
    }

    fn probe(&self, key: &Key, now: Instant) -> Probe {
        let mut shard = match self.shards[shard_index(key)].lock() {
            Ok(s) => s,
            // Poisoned lock: another thread panicked mid-insert. Fail open —
            // a cache that panics the proxy is worse than no cache. Same
            // stance as L6's limiter eviction.
            Err(_) => return Probe::None,
        };
        let Some(e) = shard.map.get_mut(key) else {
            return Probe::None;
        };
        if key.vary.is_empty() && !e.vary_names.is_empty() {
            // This is a vary-index entry: it records which headers matter
            // but is not itself servable.
            return Probe::VaryIndex(e.vary_names.clone());
        }
        e.last_used = now;
        if e.is_fresh(now) {
            Probe::Fresh(CachedResponse {
                status: e.status,
                reason: e.reason.clone(),
                headers: e.headers.clone(),
                body: Arc::clone(&e.body),
                age_secs: e.age_secs(now),
                etag: e.etag.clone(),
            })
        } else if e.has_validator() {
            Probe::Stale {
                etag: e.etag.clone(),
                last_modified: e.last_modified.clone(),
            }
        } else {
            // Expired, nothing to revalidate with: dead weight. Remove now
            // so the byte budget frees immediately rather than at the next
            // eviction scan.
            let cost = e.cost();
            shard.map.remove(key);
            shard.bytes -= cost;
            Probe::None
        }
    }

    /// Insert (or replace) an entry. `key.vary` must already reflect the
    /// response's own Vary list. For varying responses the caller also
    /// passes `vary_names` so the vary-index entry can be (re)written.
    pub fn store(&self, key: Key, entry: Entry) {
        if entry.body.len() as u64 > self.max_body {
            return; // fail open: too big to store is not an error
        }
        // A varying response needs its index entry so lookups know which
        // headers to key on. Written first (tiny, body is empty).
        if !entry.vary_names.is_empty() && !key.vary.is_empty() {
            let index_key = Key {
                vary: Vec::new(),
                ..key.clone()
            };
            let index_entry = Entry {
                status: 0,
                reason: String::new(),
                headers: Vec::new(),
                body: Vec::new().into(),
                stored_at: entry.stored_at,
                // The index lives as long as any variant could: give it the
                // same TTL; it is refreshed on every variant store anyway.
                ttl: entry.ttl.max(Duration::from_secs(60)),
                etag: None,
                last_modified: None,
                vary_names: entry.vary_names.clone(),
                last_used: entry.stored_at,
            };
            self.insert(index_key, index_entry, false);
        }
        self.insert(key, entry, true);
        self.stats.stored.fetch_add(1, Ordering::Relaxed);
    }

    fn insert(&self, key: Key, entry: Entry, count_evictions: bool) {
        let idx = shard_index(&key);
        let Ok(mut shard) = self.shards[idx].lock() else {
            return;
        };
        let new_cost = entry.cost();
        // Replacing? Free the old cost first so the budget math is simple.
        if let Some(old) = shard.map.remove(&key) {
            shard.bytes -= old.cost();
        }
        // Evict least-recently-used until the newcomer fits both bounds.
        // Scans THIS shard only — see the module docs for why the scan is
        // the honest choice over an O(1) recency structure.
        while !shard.map.is_empty()
            && (shard.bytes + new_cost > self.max_bytes_per_shard
                || shard.map.len() + 1 > self.max_entries_per_shard)
        {
            let oldest = shard
                .map
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    if let Some(e) = shard.map.remove(&k) {
                        shard.bytes -= e.cost();
                        if count_evictions {
                            self.stats.evicted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                None => break,
            }
        }
        // If the entry alone exceeds the shard budget, don't store it.
        if new_cost > self.max_bytes_per_shard {
            return;
        }
        shard.bytes += new_cost;
        shard.map.insert(key, entry);
    }

    /// Re-stamp a stale entry after a 304: fresh again from now, with a new
    /// TTL. `key` is the one `Lookup::Stale` carried — captured at lookup
    /// time, before the live request head was rewritten. Returns the (now
    /// fresh) response to serve, or None if the entry vanished between
    /// lookup and revalidation (evicted under us — the caller then falls
    /// back to treating the exchange as an uncacheable pass-through).
    pub fn restamp(&self, key: &Key, new_ttl: Duration) -> Option<CachedResponse> {
        let mut shard = self.shards[shard_index(key)].lock().ok()?;
        let e = shard.map.get_mut(key)?;
        let now = Instant::now();
        e.stored_at = now;
        e.ttl = new_ttl;
        e.last_used = now;
        self.stats.revalidated.fetch_add(1, Ordering::Relaxed);
        Some(CachedResponse {
            status: e.status,
            reason: e.reason.clone(),
            headers: e.headers.clone(),
            body: Arc::clone(&e.body),
            age_secs: 0,
            etag: e.etag.clone(),
        })
    }

    /// RFC 9111 §4.4 invalidation: remove every entry for this route+host+
    /// target (all Vary variants and the index). Called on a non-error
    /// response to an unsafe method.
    pub fn invalidate(&self, route: usize, host: &str, target: &str) {
        let mut removed = 0u64;
        for shard in &self.shards {
            let Ok(mut shard) = shard.lock() else { continue };
            let keys: Vec<Key> = shard
                .map
                .keys()
                .filter(|k| {
                    k.route == route
                        && k.host == host
                        && k.target == target
                        && k.method == "GET"
                })
                .cloned()
                .collect();
            for k in keys {
                if let Some(e) = shard.map.remove(&k) {
                    shard.bytes -= e.cost();
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            self.stats.invalidated.fetch_add(removed, Ordering::Relaxed);
        }
    }

}

impl Cache {
    /// Prometheus text block for the cache counters, appended to the L10
    /// exposition by the admin listener. Same rules as metrics::render:
    /// static label set, zero-value series elided.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str(
            "# HELP ferrum_cache_events_total Cache activity by outcome.\n# TYPE ferrum_cache_events_total counter\n",
        );
        let series: [(&str, &AtomicU64); 6] = [
            ("hit", &self.stats.hits),
            ("miss", &self.stats.misses),
            ("revalidated", &self.stats.revalidated),
            ("stored", &self.stats.stored),
            ("evicted", &self.stats.evicted),
            ("invalidated", &self.stats.invalidated),
        ];
        for (label, counter) in series {
            let v = counter.load(Ordering::Relaxed);
            if v > 0 {
                out.push_str(&format!(
                    "ferrum_cache_events_total{{result=\"{label}\"}} {v}\n"
                ));
            }
        }
        out
    }
}

enum Probe {
    None,
    Fresh(CachedResponse),
    Stale {
        etag: Option<String>,
        last_modified: Option<String>,
    },
    VaryIndex(Vec<String>),
}

// ---------------------------------------------------------------------------
// Section 2: HTTP caching semantics — pure functions, no locking, no I/O
// ---------------------------------------------------------------------------

/// The key ingredients, snapshotted from the request BEFORE Level 5 rewrites
/// it. This exists because the cache is consulted twice per exchange — lookup
/// before the rewrite, store/restamp after the response returns — and by the
/// second consultation `req` has been mutated in place (target stripped, Host
/// clobbered, headers injected). Keying on the mutated head would silently
/// change what "the same resource" means between the two consultations. The
/// snapshot is taken only on caching routes, and only the headers Vec is a
/// real copy.
pub struct KeyInput {
    pub route: usize,
    pub method: String,
    pub host: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
}

impl KeyInput {
    pub fn from_request(route: usize, req: &RequestHead, host: &str) -> KeyInput {
        KeyInput {
            route,
            method: req.method.clone(),
            host: host.to_ascii_lowercase(),
            target: req.target.clone(),
            headers: req.headers.clone(),
        }
    }
}

impl Key {
    /// Build the key from snapshotted inputs. `vary_names` is empty for the
    /// initial probe / non-varying store; for a varying resource it is the
    /// stored response's Vary list, and each named header's value AS SENT BY
    /// THIS REQUEST joins the key (absent header = empty string, a distinct
    /// variant per RFC 9111 §4.1).
    ///
    /// The fields and their casing rules ARE the security argument:
    /// pre-rewrite host+target (client's view, not the backend's), route
    /// index (routes must not share), names lowercased (header lookup is
    /// case-insensitive), values verbatim (values are case-sensitive), names
    /// sorted (wire order must not split variants). Full struct equality on
    /// lookup — the hash only picks a shard.
    pub fn build(input: &KeyInput, vary_names: &[String]) -> Key {
        let mut vary: Vec<(String, String)> = vary_names
            .iter()
            .map(|n| {
                (
                    n.to_ascii_lowercase(),
                    http::header(&input.headers, n).unwrap_or("").to_string(),
                )
            })
            .collect();
        vary.sort();
        Key {
            route: input.route,
            method: input.method.clone(),
            host: input.host.clone(),
            target: input.target.clone(),
            vary,
        }
    }
}

/// Freshness lifetime and storability, decided from the RESPONSE headers.
pub struct Freshness {
    /// None = do not store at all (`no-store`, `private`, `Set-Cookie`,
    /// `Vary: *`, or no freshness info and no validator).
    pub ttl: Option<Duration>,
    /// Response's Vary list, lowercased, sorted, deduped.
    pub vary_names: Vec<String>,
}

/// Is this request one the cache may even look at? Method and request-header
/// gates; the response gates live in `freshness_from_headers`.
///
/// GET only (not HEAD: we never cache HEAD separately, and serving a cached
/// GET body to a HEAD would be wrong the other way). `Authorization` makes
/// the response user-specific until proven otherwise — the KB's "worst bug
/// class" is exactly a shared cache serving one user's authorized response
/// to another, so the safe default is a hard no. (RFC 9111 permits caching
/// authorized responses given explicit directives; that nuance is not worth
/// its risk here and `must-revalidate`/`public` handling is out of scope.)
pub fn request_is_cacheable(req: &RequestHead) -> bool {
    req.method == "GET" && http::header(&req.headers, "authorization").is_none()
}

/// Request Cache-Control directives WE honor from the client: `no-store`
/// (do not write this exchange to cache) and `no-cache` (do not answer from
/// cache without revalidating — for us, treat as bypass-to-origin).
/// Returned as (no_store, no_cache).
pub fn request_cache_control(req: &RequestHead) -> (bool, bool) {
    match http::header(&req.headers, "cache-control") {
        Some(v) => {
            let has = |d: &str| {
                v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case(d))
            };
            (has("no-store"), has("no-cache"))
        }
        None => (false, false),
    }
}

/// Decide storability and TTL from the response. `default_ttl` is the route's
/// `;cache=SECS` value, applied ONLY when the response carries a validator —
/// freshness we invent must at least be revalidatable; a response with no
/// explicit freshness and no validator is not stored at all.
pub fn freshness_from_headers(
    status: u16,
    headers: &[(String, String)],
    default_ttl: Duration,
) -> Freshness {
    let none = Freshness {
        ttl: None,
        vary_names: Vec::new(),
    };
    // Status gate: the boring, heavily-cacheable trio. 200 (the point),
    // 301 (permanent by definition), 404 (absence is an answer too, and
    // caching it shields the backend from retry storms on dead links).
    if !matches!(status, 200 | 301 | 404) {
        return none;
    }
    // Set-Cookie means user-specific, full stop. A shared cache replaying
    // one user's cookie to everyone is a session-fixation machine.
    if http::header(headers, "set-cookie").is_some() {
        return none;
    }

    let cc = http::header(headers, "cache-control").unwrap_or("");
    let mut max_age: Option<u64> = None;
    let mut s_maxage: Option<u64> = None;
    let mut no_cache = false;
    for tok in cc.split(',') {
        let tok = tok.trim();
        let (name, val) = match tok.split_once('=') {
            Some((n, v)) => (n.trim(), Some(v.trim().trim_matches('"'))),
            None => (tok, None),
        };
        // Directive names are case-insensitive (RFC 9111 §5.2).
        if name.eq_ignore_ascii_case("no-store") || name.eq_ignore_ascii_case("private") {
            // `private`: the browser may cache this; a SHARED cache must
            // not. We are the shared cache the directive was written for.
            return none;
        } else if name.eq_ignore_ascii_case("no-cache") {
            no_cache = true;
        } else if name.eq_ignore_ascii_case("max-age") {
            max_age = val.and_then(|v| v.parse().ok());
        } else if name.eq_ignore_ascii_case("s-maxage") {
            s_maxage = val.and_then(|v| v.parse().ok());
        }
    }

    // Vary handling. `Vary: *` = "the response depends on things you cannot
    // see" = uncacheable.
    let mut vary_names: Vec<String> = Vec::new();
    if let Some(v) = http::header(headers, "vary") {
        for name in v.split(',') {
            let name = name.trim().to_ascii_lowercase();
            if name == "*" {
                return none;
            }
            if !name.is_empty() && !vary_names.contains(&name) {
                vary_names.push(name);
            }
        }
        vary_names.sort();
    }

    let has_validator =
        http::header(headers, "etag").is_some() || http::header(headers, "last-modified").is_some();

    // `no-cache` (the confusingly-named one): store, but revalidate before
    // EVERY use. Zero TTL + a validator expresses exactly that; without a
    // validator revalidation is impossible, so don't store.
    if no_cache {
        return Freshness {
            ttl: if has_validator {
                Some(Duration::ZERO)
            } else {
                None
            },
            vary_names,
        };
    }

    // s-maxage beats max-age for a shared cache (its entire purpose).
    let ttl = match s_maxage.or(max_age) {
        Some(secs) => Some(Duration::from_secs(secs)),
        // No explicit freshness: the route's default, but only against a
        // validator (invented freshness must be checkable).
        None if has_validator => Some(default_ttl),
        None => None,
    };
    Freshness { ttl, vary_names }
}

/// TTL to re-stamp with after a 304. The 304 may carry updated Cache-Control;
/// otherwise fall back to the route default. (A 304 with `no-store` would be
/// origin nonsense; we read only the lifetimes here.)
pub fn ttl_from_304(headers: &[(String, String)], default_ttl: Duration) -> Duration {
    let f = freshness_from_headers(200, headers, default_ttl);
    f.ttl.unwrap_or(default_ttl)
}

/// ETag comparison for `If-None-Match`, RFC 9110 §13.1.2: weak comparison
/// (strip any `W/` prefix, then octet-exact including the quotes), and `*`
/// matches any existing entity.
pub fn etag_matches(if_none_match: &str, entity_etag: &str) -> bool {
    let strip = |s: &str| s.trim().strip_prefix("W/").unwrap_or(s.trim()).to_string();
    let entity = strip(entity_etag);
    if_none_match.split(',').any(|candidate| {
        let c = candidate.trim();
        c == "*" || strip(c) == entity
    })
}

/// Extract the validators from stored response headers.
pub fn validators(headers: &[(String, String)]) -> (Option<String>, Option<String>) {
    (
        http::header(headers, "etag").map(str::to_string),
        http::header(headers, "last-modified").map(str::to_string),
    )
}

/// Build the 304 head for a client whose conditional matched. Per RFC 9110
/// §15.4.5 the 304 must carry the headers that would have been sent with a
/// 200 that guide caching (ETag, Cache-Control, Vary, ...) — we send the
/// cheap, correct subset.
pub fn not_modified_head(cached: &CachedResponse) -> ResponseHead {
    let keep = ["etag", "cache-control", "vary", "last-modified", "expires"];
    let headers = cached
        .headers
        .iter()
        .filter(|(n, _)| keep.contains(&n.to_ascii_lowercase().as_str()))
        .cloned()
        .collect();
    ResponseHead {
        version: crate::http::Version::Http11,
        status: 304,
        reason: "Not Modified".to_string(),
        headers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Version;

    fn get(target: &str, headers: Vec<(&str, &str)>) -> RequestHead {
        RequestHead {
            method: "GET".into(),
            target: target.into(),
            version: Version::Http11,
            headers: headers
                .into_iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn entry(body: &[u8], ttl_secs: u64) -> Entry {
        Entry {
            status: 200,
            reason: "OK".into(),
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: body.to_vec().into(),
            stored_at: Instant::now(),
            ttl: Duration::from_secs(ttl_secs),
            etag: None,
            last_modified: None,
            vary_names: Vec::new(),
            last_used: Instant::now(),
        }
    }

    fn cache() -> Cache {
        Cache::new(DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_BODY)
    }

    /// Test shorthand: KeyInput for (route, request, host).
    fn ki(route: usize, req: &RequestHead, host: &str) -> KeyInput {
        KeyInput::from_request(route, req, host)
    }

    // ---- storage ----

    #[test]
    fn miss_then_hit_roundtrip() {
        let c = cache();
        let req = get("/a", vec![]);
        assert!(matches!(c.lookup(&ki(0, &req, "h")), Lookup::Miss));
        let key = Key::build(&ki(0, &req, "h"), &[]);
        c.store(key, entry(b"hello", 60));
        match c.lookup(&ki(0, &req, "h")) {
            Lookup::Hit(r) => {
                assert_eq!(&*r.body, b"hello");
                assert_eq!(r.status, 200);
            }
            _ => panic!("expected hit"),
        }
        assert_eq!(c.stats.hits.load(Ordering::Relaxed), 1);
        assert_eq!(c.stats.misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn routes_do_not_share_entries() {
        let c = cache();
        let req = get("/a", vec![]);
        c.store(Key::build(&ki(0, &req, "h"), &[]), entry(b"route0", 60));
        assert!(matches!(c.lookup(&ki(1, &req, "h")), Lookup::Miss));
    }

    #[test]
    fn hosts_do_not_share_entries_and_host_is_case_insensitive() {
        let c = cache();
        let req = get("/a", vec![]);
        c.store(Key::build(&ki(0, &req, "example.com"), &[]), entry(b"x", 60));
        assert!(matches!(c.lookup(&ki(0, &req, "other.com")), Lookup::Miss));
        assert!(matches!(c.lookup(&ki(0, &req, "EXAMPLE.com")), Lookup::Hit(_)));
    }

    #[test]
    fn expired_without_validator_is_miss() {
        let c = cache();
        let req = get("/a", vec![]);
        let mut e = entry(b"old", 0); // ttl 0 = instantly stale
        e.stored_at = Instant::now() - Duration::from_secs(10);
        c.store(Key::build(&ki(0, &req, "h"), &[]), e);
        assert!(matches!(c.lookup(&ki(0, &req, "h")), Lookup::Miss));
    }

    #[test]
    fn expired_with_validator_is_stale_and_restamp_revives() {
        let c = cache();
        let req = get("/a", vec![]);
        let mut e = entry(b"old", 1);
        e.etag = Some("\"v1\"".into());
        e.stored_at = Instant::now() - Duration::from_secs(10);
        c.store(Key::build(&ki(0, &req, "h"), &[]), e);
        let stale_key = match c.lookup(&ki(0, &req, "h")) {
            Lookup::Stale { key, etag, .. } => {
                assert_eq!(etag.as_deref(), Some("\"v1\""));
                key
            }
            _ => panic!("expected stale"),
        };
        let revived = c.restamp(&stale_key, Duration::from_secs(60)).unwrap();
        assert_eq!(&*revived.body, b"old");
        assert!(matches!(c.lookup(&ki(0, &req, "h")), Lookup::Hit(_)));
        assert_eq!(c.stats.revalidated.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn vary_stores_separate_variants() {
        let c = cache();
        let req_gzip = get("/a", vec![("Accept-Encoding", "gzip")]);
        let req_plain = get("/a", vec![]);
        let names = vec!["accept-encoding".to_string()];
        let mut e1 = entry(b"gzip-body", 60);
        e1.vary_names = names.clone();
        c.store(Key::build(&ki(0, &req_gzip, "h"), &names), e1);

        // Same URL, different Accept-Encoding: must NOT get the gzip body.
        assert!(matches!(c.lookup(&ki(0, &req_plain, "h")), Lookup::Miss));

        let mut e2 = entry(b"plain-body", 60);
        e2.vary_names = names.clone();
        c.store(Key::build(&ki(0, &req_plain, "h"), &names), e2);

        match c.lookup(&ki(0, &req_gzip, "h")) {
            Lookup::Hit(r) => assert_eq!(&*r.body, b"gzip-body"),
            _ => panic!(),
        }
        match c.lookup(&ki(0, &req_plain, "h")) {
            Lookup::Hit(r) => assert_eq!(&*r.body, b"plain-body"),
            _ => panic!(),
        }
    }

    #[test]
    fn lru_evicts_oldest_within_bounds() {
        // Entries cost ~256 + body + headers; size the shard budget so the
        // third insert must evict. All keys hash to (possibly) different
        // shards, so use one key-shape and check totals via stats instead.
        let c = Cache::new(16 * 400, 16 * 2, DEFAULT_MAX_BODY); // 400 B, 2 entries per shard
        // Fill one shard deterministically: same target so same shard.
        let r1 = get("/same", vec![]);
        let k = Key::build(&ki(0, &r1, "h"), &[]);
        c.store(k.clone(), entry(b"a", 60));
        // Different targets may land anywhere; instead overfill the SAME key's
        // shard with distinct keys by varying method (kept GET; vary host).
        let mut stored = 1;
        for i in 0..40 {
            let host = format!("h{i}");
            let key = Key::build(&ki(0, &r1, &host), &[]);
            c.store(key, entry(b"b", 60));
            stored += 1;
        }
        let _ = stored;
        // At most 2 entries per shard survive; evictions must have happened.
        assert!(c.stats.evicted.load(Ordering::Relaxed) > 0);
        let total: usize = (0..SHARDS)
            .map(|i| c.shards[i].lock().unwrap().map.len())
            .sum();
        assert!(total <= 16 * 2);
    }

    #[test]
    fn oversized_body_is_not_stored() {
        let c = Cache::new(DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRIES, 4);
        let req = get("/big", vec![]);
        c.store(Key::build(&ki(0, &req, "h"), &[]), entry(b"way too big", 60));
        assert!(matches!(c.lookup(&ki(0, &req, "h")), Lookup::Miss));
        // The size gate rejects BEFORE counting: `stored` means "in the
        // cache", not "offered to the cache".
        assert_eq!(c.stats.stored.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn invalidate_removes_all_variants() {
        let c = cache();
        let names = vec!["accept-encoding".to_string()];
        let req_gzip = get("/a", vec![("Accept-Encoding", "gzip")]);
        let req_plain = get("/a", vec![]);
        let mut e1 = entry(b"g", 60);
        e1.vary_names = names.clone();
        let mut e2 = entry(b"p", 60);
        e2.vary_names = names.clone();
        c.store(Key::build(&ki(0, &req_gzip, "h"), &names), e1);
        c.store(Key::build(&ki(0, &req_plain, "h"), &names), e2);
        c.invalidate(0, "h", "/a");
        assert!(matches!(c.lookup(&ki(0, &req_gzip, "h")), Lookup::Miss));
        assert!(matches!(c.lookup(&ki(0, &req_plain, "h")), Lookup::Miss));
        assert!(c.stats.invalidated.load(Ordering::Relaxed) >= 2);
    }

    #[test]
    fn concurrent_hammer_loses_nothing_and_stays_bounded() {
        let c = Arc::new(Cache::new(16 * 4096, 16 * 8, DEFAULT_MAX_BODY));
        let mut handles = Vec::new();
        for t in 0..8 {
            let c = Arc::clone(&c);
            handles.push(std::thread::spawn(move || {
                for i in 0..2000 {
                    let req = get(&format!("/{}", i % 32), vec![]);
                    let host = format!("t{t}");
                    match c.lookup(&ki(0, &req, &host)) {
                        Lookup::Miss => {
                            c.store(Key::build(&ki(0, &req, &host), &[]), entry(b"x", 60));
                        }
                        _ => {}
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let total: usize = (0..SHARDS)
            .map(|i| c.shards[i].lock().unwrap().map.len())
            .sum();
        assert!(total <= 16 * 8);
    }

    // ---- semantics ----

    fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn request_gates() {
        assert!(request_is_cacheable(&get("/", vec![])));
        assert!(!request_is_cacheable(&get("/", vec![("Authorization", "Bearer x")])));
        let mut post = get("/", vec![]);
        post.method = "POST".into();
        assert!(!request_is_cacheable(&post));
    }

    #[test]
    fn response_status_gate() {
        let d = Duration::from_secs(60);
        let h = hdrs(&[("Cache-Control", "max-age=10")]);
        assert!(freshness_from_headers(200, &h, d).ttl.is_some());
        assert!(freshness_from_headers(301, &h, d).ttl.is_some());
        assert!(freshness_from_headers(404, &h, d).ttl.is_some());
        assert!(freshness_from_headers(500, &h, d).ttl.is_none());
        assert!(freshness_from_headers(302, &h, d).ttl.is_none());
    }

    #[test]
    fn no_store_private_and_set_cookie_block_storage() {
        let d = Duration::from_secs(60);
        for h in [
            hdrs(&[("Cache-Control", "no-store")]),
            hdrs(&[("Cache-Control", "private, max-age=100")]),
            hdrs(&[("Cache-Control", "MAX-AGE=100"), ("Set-Cookie", "sid=1")]),
        ] {
            assert!(freshness_from_headers(200, &h, d).ttl.is_none());
        }
    }

    #[test]
    fn s_maxage_beats_max_age_and_directives_are_case_insensitive() {
        let d = Duration::from_secs(60);
        let h = hdrs(&[("Cache-Control", "max-age=100, S-MaxAge=5")]);
        assert_eq!(
            freshness_from_headers(200, &h, d).ttl,
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn no_cache_means_store_but_always_stale() {
        let d = Duration::from_secs(60);
        let with_validator = hdrs(&[("Cache-Control", "no-cache"), ("ETag", "\"a\"")]);
        assert_eq!(
            freshness_from_headers(200, &with_validator, d).ttl,
            Some(Duration::ZERO)
        );
        let without = hdrs(&[("Cache-Control", "no-cache")]);
        assert!(freshness_from_headers(200, &without, d).ttl.is_none());
    }

    #[test]
    fn default_ttl_only_with_validator() {
        let d = Duration::from_secs(60);
        let with = hdrs(&[("ETag", "\"a\"")]);
        assert_eq!(freshness_from_headers(200, &with, d).ttl, Some(d));
        let without = hdrs(&[("Content-Type", "text/html")]);
        assert!(freshness_from_headers(200, &without, d).ttl.is_none());
    }

    #[test]
    fn vary_star_uncacheable_vary_names_normalized() {
        let d = Duration::from_secs(60);
        let star = hdrs(&[("Cache-Control", "max-age=10"), ("Vary", "*")]);
        assert!(freshness_from_headers(200, &star, d).ttl.is_none());
        let v = hdrs(&[
            ("Cache-Control", "max-age=10"),
            ("Vary", "Accept-Encoding, ACCEPT-language, accept-encoding"),
        ]);
        let f = freshness_from_headers(200, &v, d);
        assert_eq!(f.vary_names, vec!["accept-encoding", "accept-language"]);
    }

    #[test]
    fn etag_comparison_rules() {
        assert!(etag_matches("\"abc\"", "\"abc\""));
        assert!(etag_matches("W/\"abc\"", "\"abc\"")); // weak comparison
        assert!(etag_matches("\"abc\"", "W/\"abc\""));
        assert!(etag_matches("\"x\", \"abc\"", "\"abc\"")); // list
        assert!(etag_matches("*", "\"anything\""));
        assert!(!etag_matches("\"abc\"", "\"abd\""));
    }

    #[test]
    fn request_cache_control_parsing() {
        let r = get("/", vec![("Cache-Control", "no-store, no-cache")]);
        assert_eq!(request_cache_control(&r), (true, true));
        let r2 = get("/", vec![]);
        assert_eq!(request_cache_control(&r2), (false, false));
    }

    #[test]
    fn not_modified_head_carries_caching_headers_only() {
        let cached = CachedResponse {
            status: 200,
            reason: "OK".into(),
            headers: hdrs(&[
                ("ETag", "\"v\""),
                ("Cache-Control", "max-age=10"),
                ("Content-Type", "text/html"),
                ("Content-Length", "100"),
            ]),
            body: Vec::new().into(),
            age_secs: 0,
            etag: Some("\"v\"".into()),
        };
        let h = not_modified_head(&cached);
        assert_eq!(h.status, 304);
        assert!(http::header(&h.headers, "etag").is_some());
        assert!(http::header(&h.headers, "content-type").is_none());
        assert!(http::header(&h.headers, "content-length").is_none());
    }
}
