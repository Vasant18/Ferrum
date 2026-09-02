//! Level 13: the WAF — a reverse proxy that grew an immune system.
//!
//! The KB's one-liner is the architecture: "you already built the platform —
//! the WAF is middleware with opinions." This file is those opinions:
//!
//! 1. **Normalize** (`normalize`, `canonicalize_path`) — the KB calls this
//!    80% of WAF quality. Evasion is mostly encoding games: `%27` for a
//!    quote, `%252e` for a double-encoded dot, case tricks, entity forms.
//!    Naive regex on raw bytes catches only lazy attackers.
//! 2. **Match + score** (`RULES`, `inspect`) — the ModSecurity CRS model:
//!    each rule adds points, conviction only at a threshold. A lone quote
//!    in a query is 2 points (O'Brien buys coffee too); quote + UNION +
//!    comment is a conviction. Anomaly scoring is the difference between a
//!    WAF and a false-positive generator that ops disables within a week.
//! 3. **Reputation** (`Reputation`) — score sources by their own recent
//!    behavior. Convictions become strikes; strikes become a temporary ban
//!    with doubling backoff. The L4 breaker's philosophy pointed inward:
//!    a client that keeps attacking is "unhealthy" the same way a backend
//!    that keeps 500ing is.
//!
//! # The honesty checkpoint (the KB's, kept verbatim in spirit)
//!
//! Signature WAFs are a speed bump, not a wall. Determined attackers bypass
//! regex rules — vendors know it, which is why the commercial layers above
//! this (ML, shared reputation feeds, managed rules, JS challenges) exist.
//! The real injection fixes live in the application: parameterized queries,
//! output encoding. What this level buys: the automated 99% blocked, time
//! during 0-days, and visibility. Body inspection is deliberately absent —
//! Ferrum streams bodies in 16 KB windows (L1's flat-memory guarantee), and
//! buffering them for inspection is a different architecture; this WAF sees
//! heads only, and says so rather than pretending otherwise.
//!
//! # Where it sits
//!
//! Chain order (L6, order in code never config):
//! log → request-id → **waf** → ratelimit → auth → authz.
//! Before ratelimit and auth: hostility is refused outright before it can
//! consume a rate token or trigger a credential comparison, and the ban
//! check makes a banned IP's requests nearly free to refuse. Per-route
//! opt-in (`;waf=block|detect`), threshold tunable (`;waf-threshold=N`),
//! detection mode first — every WAF ships watching before it enforces.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::http::{self, RequestHead};
use crate::middleware::{Decision, Middleware, Rejection, ReqCtx};

// ---------------------------------------------------------------------------
// Normalization — decode first, judge after
// ---------------------------------------------------------------------------

/// Evasion flags raised during normalization. Each is itself worth points:
/// legitimate clients do not double-encode, and a null byte in a URL has no
/// honest use — the *evasion attempt* is a signal independent of what it
/// was hiding.
#[derive(Default, Debug, PartialEq)]
pub struct NormFlags {
    pub double_encoded: bool,
    pub null_byte: bool,
    /// A `..` segment tried to climb above the path root at some point
    /// during canonicalization — even if later segments descended again and
    /// the final path looks innocent. We cannot know how the BACKEND
    /// resolves paths, so the attempt is the conviction-worthy fact.
    pub traversal_attempt: bool,
}

/// Percent-decode one pass. Invalid sequences (`%q1`, truncated `%2`) are
/// kept literally — a WAF must never 500 on hostile input, and a broken
/// escape is not a decoding.
fn percent_decode_once(s: &str, plus_is_space: bool) -> (String, bool) {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() + 1 && i + 2 <= bytes.len() - 1 + 1 => {
                let hex = bytes.get(i + 1..i + 3);
                match hex.and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        changed = true;
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                changed = true;
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    (String::from_utf8_lossy(&out).into_owned(), changed)
}

/// Decode the handful of HTML entities attackers actually use to smuggle
/// angle brackets and quotes past byte-level filters. Not an HTML parser —
/// a targeted de-cloaking of the characters our rules need to see.
fn entity_decode(s: &str) -> String {
    let mut out = s.to_string();
    for (ent, ch) in [
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&apos;", "'"),
        ("&#x27;", "'"),
        ("&#39;", "'"),
        ("&#x3c;", "<"),
        ("&#60;", "<"),
        ("&#x3e;", ">"),
        ("&#62;", ">"),
    ] {
        if out.contains(ent) {
            out = out.replace(ent, ch);
        }
    }
    out
}

/// Full normalization: percent-decode up to twice (recording whether the
/// second pass changed anything — that IS double-encoding), entity-decode,
/// lowercase, collapse whitespace runs to one space, flag null bytes.
/// Returns the normalized text plus the evasion receipts.
pub fn normalize(raw: &str, plus_is_space: bool) -> (String, NormFlags) {
    let mut flags = NormFlags::default();
    let (once, _) = percent_decode_once(raw, plus_is_space);
    let (twice, changed_again) = percent_decode_once(&once, false);
    if changed_again {
        flags.double_encoded = true;
    }
    let mut text = entity_decode(&twice).to_lowercase();
    if text.contains('\0') {
        flags.null_byte = true;
        text = text.replace('\0', "");
    }
    // Collapse whitespace: `UNION/**/SELECT` handled by rules; `UNION
    // SELECT` with tabs/newlines collapses to one space so one pattern
    // matches all spacings.
    let mut collapsed = String::with_capacity(text.len());
    let mut last_ws = false;
    for c in text.chars() {
        if c.is_whitespace() {
            if !last_ws {
                collapsed.push(' ');
            }
            last_ws = true;
        } else {
            collapsed.push(c);
            last_ws = false;
        }
    }
    (collapsed, flags)
}

/// Canonicalize a (already percent-decoded) path: resolve `.` and `..`
/// segments, flagging any attempt to climb above the root. The L2 lesson
/// weaponized: canonicalize FIRST, judge the result — but here the attempt
/// itself is also recorded, because `/a/../../b` normalizing to `/b` still
/// told us someone probed how far up they could walk.
pub fn canonicalize_path(path: &str) -> (String, bool) {
    let mut segments: Vec<&str> = Vec::new();
    let mut climbed = false;
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    climbed = true;
                }
            }
            s => segments.push(s),
        }
    }
    let mut out = String::from("/");
    out.push_str(&segments.join("/"));
    (out, climbed)
}

// ---------------------------------------------------------------------------
// Rules — data, not code
// ---------------------------------------------------------------------------

/// How a rule matches the normalized text.
enum Pat {
    /// Substring present.
    Sub(&'static str),
    /// All of these substrings present (order-free conjunction — cheaper
    /// and clearer than a regex with lookaheads).
    All(&'static [&'static str]),
    /// Compiled regex, for the few shapes where structure matters.
    Re(&'static str),
}

/// One signature. Points follow the CRS spirit: ambient-noise patterns
/// score low, unambiguous attack grammar scores at-or-near threshold.
struct Rule {
    name: &'static str,
    points: u32,
    pat: Pat,
}

/// The rule table. ~20 rules, linear scan — at this scale a pass over an
/// already-normalized string beats set-matching machinery, and the table
/// stays readable enough to answer "why did this block" by eye.
/// (Production CRS has thousands of rules; that is what RegexSet and
/// Aho-Corasick pre-filters are for. Different scale, different tool.)
static RULES: &[Rule] = &[
    // ---- SQL injection ----
    // Conviction-weight on its own: "union" and "select" CO-OCCURRING in
    // one normalized surface has no benign URL reading ("union station"
    // alone scores nothing — the conjunction is the signature).
    Rule { name: "sqli:union-select", points: 10, pat: Pat::All(&["union", "select"]) },
    Rule { name: "sqli:comment-seq", points: 4, pat: Pat::Re(r"(--|#|/\*)\s*$|/\*.*\*/") },
    // NOTE: no backreference here (`(\d+)=\1` would be the precise form).
    // Rust's regex crate rejects backreferences BY DESIGN — that refusal is
    // the same linear-time guarantee that makes L2's `~regex` routes safe to
    // run per request (L9 §blocking audit). The looser digit=digit form
    // over-matches `1=2` — which is fine: `or 1=2` in a query string is
    // still an injection probe (a FALSE tautology is how attackers test
    // blind injection), so the "imprecision" convicts exactly the right
    // people.
    Rule { name: "sqli:tautology", points: 8, pat: Pat::Re(r"\b(or|and)\s+(\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*')") },
    // Also conviction-weight: `;` immediately followed by a DDL/DML verb is
    // the stacked-query shape itself; no legitimate query string terminates
    // one statement and opens another.
    Rule { name: "sqli:stacked-query", points: 10, pat: Pat::Re(r";\s*(drop|insert|update|delete|create|alter)\b") },
    Rule { name: "sqli:sleep-bench", points: 8, pat: Pat::Re(r"\b(sleep|benchmark|pg_sleep|waitfor)\s*\(") },
    Rule { name: "sqli:info-schema", points: 6, pat: Pat::Sub("information_schema") },
    Rule { name: "sqli:quote", points: 2, pat: Pat::Sub("'") },
    // ---- XSS ----
    Rule { name: "xss:script-tag", points: 10, pat: Pat::Sub("<script") },
    Rule { name: "xss:event-handler", points: 8, pat: Pat::Re(r"\bon(error|load|click|mouseover|focus|submit)\s*=") },
    Rule { name: "xss:js-url", points: 8, pat: Pat::Sub("javascript:") },
    Rule { name: "xss:vector-tag", points: 6, pat: Pat::Re(r"<(img|svg|iframe|object|embed|body)\b") },
    Rule { name: "xss:eval-family", points: 6, pat: Pat::Re(r"\b(eval|settimeout|setinterval|document\.cookie|window\.location)\b") },
    // ---- Path traversal (post-canonicalization text forms) ----
    Rule { name: "traversal:dotdot", points: 8, pat: Pat::Sub("../") },
    Rule { name: "traversal:sensitive-file", points: 8, pat: Pat::Re(r"/etc/(passwd|shadow|hosts)|(^|/)proc/self|boot\.ini|win\.ini") },
    // ---- Scanner fingerprints (User-Agent surface) ----
    Rule { name: "scanner:tool-ua", points: 10, pat: Pat::Re(r"\b(sqlmap|nikto|nessus|acunetix|dirbuster|gobuster|wpscan|masscan|zgrab)\b") },
];

/// Evasion-flag scores, applied per surface where the flag was raised.
const DOUBLE_ENCODED_POINTS: u32 = 4;
const NULL_BYTE_POINTS: u32 = 6;
const CLIMB_POINTS: u32 = 8;
const NO_UA_POINTS: u32 = 1;

/// Compiled-regex cache: the `Re` patterns compile once at first use and
/// live for the process. `OnceLock` because the table is static and the
/// regex crate's compiled form is Send+Sync.
fn compiled() -> &'static Vec<Option<regex::Regex>> {
    static COMPILED: std::sync::OnceLock<Vec<Option<regex::Regex>>> = std::sync::OnceLock::new();
    COMPILED.get_or_init(|| {
        RULES
            .iter()
            .map(|r| match &r.pat {
                Pat::Re(src) => Some(regex::Regex::new(src).expect("static rule regex must compile")),
                _ => None,
            })
            .collect()
    })
}

/// The verdict for one request: accumulated points and which rules hit.
/// Hit names go to the error log and metrics — never to the client, in
/// either mode. Telling an attacker WHICH rule fired is an oracle for
/// tuning payloads; a 403 with a generic body tells them only "no".
#[derive(Debug, Default)]
pub struct Verdict {
    pub score: u32,
    pub hits: Vec<&'static str>,
}

impl Verdict {
    fn add(&mut self, name: &'static str, points: u32) {
        self.score += points;
        self.hits.push(name);
    }
}

/// Scan one normalized surface against the rule table.
fn scan(text: &str, verdict: &mut Verdict) {
    let res = compiled();
    for (i, rule) in RULES.iter().enumerate() {
        let hit = match &rule.pat {
            Pat::Sub(s) => text.contains(s),
            Pat::All(subs) => subs.iter().all(|s| text.contains(s)),
            Pat::Re(_) => res[i].as_ref().unwrap().is_match(text),
        };
        if hit {
            verdict.add(rule.name, rule.points);
        }
    }
}

/// Inspect a request head: normalize each surface once, scan each once,
/// accumulate one verdict. Surfaces: path (canonicalized), query string,
/// User-Agent, Referer. Headers beyond those two are protocol plumbing the
/// L1 parser already constrained; body is out of scope by architecture
/// (see module docs).
pub fn inspect(req: &RequestHead) -> Verdict {
    let mut verdict = Verdict::default();

    let (raw_path, raw_query) = match req.target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (req.target.as_str(), None),
    };

    // Path: decode (%2e%2e%2f games), THEN canonicalize, then scan.
    let (decoded_path, path_flags) = normalize(raw_path, false);
    let (canon, climbed) = canonicalize_path(&decoded_path);
    if path_flags.double_encoded {
        verdict.add("evasion:double-encoding", DOUBLE_ENCODED_POINTS);
    }
    if path_flags.null_byte {
        verdict.add("evasion:null-byte", NULL_BYTE_POINTS);
    }
    if climbed {
        verdict.add("traversal:climb-above-root", CLIMB_POINTS);
    }
    // Scan the DECODED text (pre-canonicalization) so `../` literals score
    // even when canonicalization would have absorbed them, plus the canon
    // form for sensitive-file hits that only assemble after resolution.
    scan(&decoded_path, &mut verdict);
    if canon != decoded_path {
        scan(&canon, &mut verdict);
    }

    if let Some(q) = raw_query {
        let (norm_q, q_flags) = normalize(q, true);
        if q_flags.double_encoded {
            verdict.add("evasion:double-encoding", DOUBLE_ENCODED_POINTS);
        }
        if q_flags.null_byte {
            verdict.add("evasion:null-byte", NULL_BYTE_POINTS);
        }
        scan(&norm_q, &mut verdict);
    }

    match http::header(&req.headers, "user-agent") {
        Some(ua) => {
            let (norm_ua, _) = normalize(ua, false);
            scan(&norm_ua, &mut verdict);
        }
        // No UA at all: one nuisance point. Plenty of legitimate tools omit
        // it (curl scripts), so it can never convict alone — but stacked on
        // real signals it tips borderline scores, which is what the CRS
        // does with it too.
        None => verdict.add("scanner:no-ua", NO_UA_POINTS),
    }
    if let Some(referer) = http::header(&req.headers, "referer") {
        let (norm_r, _) = normalize(referer, false);
        scan(&norm_r, &mut verdict);
    }

    verdict
}

// ---------------------------------------------------------------------------
// Reputation — the breaker pointed inward
// ---------------------------------------------------------------------------

struct Offender {
    strikes: u32,
    last_strike: Instant,
    banned_until: Option<Instant>,
    /// Ban count for backoff doubling: 60s, 120s, ... capped at 1h. The L4
    /// breaker's exponential backoff, applied to clients: a source that
    /// re-offends the moment a ban lifts earns geometrically longer bans.
    bans: u32,
}

/// Per-IP strike/ban bookkeeping. 16 mutex shards (the L6/L11 idiom), lazy
/// decay on lookup (the L11 TTL pattern): entries whose last strike is
/// outside the decay window reset when next touched, and an expired ban
/// lifts the same way. Process-lifetime and memory-only — a restart
/// amnesties everyone, which is honest for a teaching proxy (persistent,
/// cross-customer reputation feeds are precisely the commercial vendors'
/// moat, per the KB).
pub struct Reputation {
    shards: Vec<Mutex<HashMap<IpAddr, Offender>>>,
    ban_after: u32,
    ban_base: Duration,
    /// Strikes older than this stop counting toward a ban.
    decay: Duration,
    pub stats: WafStats,
}

/// WAF counters, L10 discipline: fixed label set, atomics, rendered by this
/// module (the L11 pattern) and appended to /metrics by the admin listener.
pub struct WafStats {
    pub convicted: AtomicU64,
    pub detected: AtomicU64,
    pub banned: AtomicU64,
    pub ban_refused: AtomicU64,
}

const BAN_CAP: Duration = Duration::from_secs(3600);

impl Reputation {
    pub fn new(ban_after: u32, ban_base: Duration) -> Reputation {
        Reputation {
            shards: (0..16).map(|_| Mutex::new(HashMap::new())).collect(),
            ban_after,
            ban_base,
            // Strikes decay after 10 ban-lengths: long enough that a slow
            // scanner still accumulates, short enough that yesterday's
            // fat-fingered quote doesn't count toward today's ban.
            decay: ban_base.saturating_mul(10),
            stats: WafStats {
                convicted: AtomicU64::new(0),
                detected: AtomicU64::new(0),
                banned: AtomicU64::new(0),
                ban_refused: AtomicU64::new(0),
            },
        }
    }

    fn shard(&self, ip: IpAddr) -> &Mutex<HashMap<IpAddr, Offender>> {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        ip.hash(&mut h);
        &self.shards[(h.finish() as usize) % self.shards.len()]
    }

    /// Is this IP currently banned? Lazily lifts expired bans and decays
    /// stale strikes. Fail open on a poisoned lock — the L6/L11 stance: a
    /// WAF that panics the proxy is a worse outcome than one skipped check.
    pub fn is_banned(&self, ip: IpAddr, now: Instant) -> bool {
        let Ok(mut map) = self.shard(ip).lock() else { return false };
        let Some(o) = map.get_mut(&ip) else { return false };
        if let Some(until) = o.banned_until {
            if now < until {
                return true;
            }
            // Ban served. Strikes reset — the slate is clean, but `bans`
            // is NOT reset: re-offending earns the doubled term.
            o.banned_until = None;
            o.strikes = 0;
        }
        if now.duration_since(o.last_strike) > self.decay {
            o.strikes = 0;
        }
        false
    }

    /// Record a conviction. Returns the ban duration if this strike tipped
    /// the threshold (enforce mode only — detect mode records but never
    /// bans; watching is not punishing).
    pub fn strike(&self, ip: IpAddr, now: Instant, enforce: bool) -> Option<Duration> {
        let Ok(mut map) = self.shard(ip).lock() else { return None };
        let o = map.entry(ip).or_insert(Offender {
            strikes: 0,
            last_strike: now,
            banned_until: None,
            bans: 0,
        });
        if now.duration_since(o.last_strike) > self.decay {
            o.strikes = 0;
        }
        o.strikes += 1;
        o.last_strike = now;
        if enforce && o.strikes >= self.ban_after {
            let term = self
                .ban_base
                .saturating_mul(1u32 << o.bans.min(6))
                .min(BAN_CAP);
            o.banned_until = Some(now + term);
            o.bans += 1;
            o.strikes = 0;
            self.stats.banned.fetch_add(1, Ordering::Relaxed);
            return Some(term);
        }
        None
    }

    /// Prometheus block, appended to /metrics by admin.rs (L11 pattern).
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push_str(
            "# HELP ferrum_waf_events_total WAF activity by outcome.\n# TYPE ferrum_waf_events_total counter\n",
        );
        for (label, c) in [
            ("convicted", &self.stats.convicted),
            ("detected", &self.stats.detected),
            ("banned", &self.stats.banned),
            ("ban_refused", &self.stats.ban_refused),
        ] {
            let v = c.load(Ordering::Relaxed);
            if v > 0 {
                out.push_str(&format!(
                    "ferrum_waf_events_total{{result=\"{label}\"}} {v}\n"
                ));
            }
        }
        out
    }
}

/// The process-wide reputation store. A global because the chain is built
/// per route inside `MiddlewareConfig::build` (which has no path to main's
/// locals), and because one store is the SEMANTICS: an attacker probing
/// /api and /admin is one offender. `configure_reputation` runs once in
/// main before any route is built; `shared_reputation` hands out clones.
/// Same shape as logging::LEVEL and observe::PLAIN — process-wide operator
/// posture, set at boot. (A Level 12 reload rebuilds chains but NOT this
/// store: strikes and bans survive a config reload, which is what an
/// operator would want — reloading routes is not an amnesty.)
static REPUTATION: std::sync::OnceLock<Arc<Reputation>> = std::sync::OnceLock::new();

pub fn configure_reputation(ban_after: u32, ban_base: Duration) {
    let _ = REPUTATION.set(Arc::new(Reputation::new(ban_after, ban_base)));
}

pub fn shared_reputation() -> Arc<Reputation> {
    Arc::clone(REPUTATION.get_or_init(|| {
        Arc::new(Reputation::new(DEFAULT_BAN_AFTER, DEFAULT_BAN_BASE))
    }))
}

pub const DEFAULT_BAN_AFTER: u32 = 3;
pub const DEFAULT_BAN_BASE: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// The middleware
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum WafMode {
    Detect,
    Block,
}

impl WafMode {
    pub fn parse(s: &str) -> Result<WafMode, String> {
        match s {
            "detect" => Ok(WafMode::Detect),
            "block" => Ok(WafMode::Block),
            other => Err(format!("waf mode {other:?} (expected block|detect)")),
        }
    }
}

pub const DEFAULT_THRESHOLD: u32 = 10;

pub struct Waf {
    pub mode: WafMode,
    pub threshold: u32,
    /// One process-wide reputation store shared by every waf-enabled route:
    /// an attacker probing /api and /admin is one offender, not two.
    pub reputation: Arc<Reputation>,
}

/// The generic refusal. Deliberately indistinguishable from any other 403
/// and free of rule names: an error page that explains which pattern fired
/// is a payload-tuning oracle. The full hit list goes to the error log and
/// nowhere else.
fn forbidden() -> Rejection {
    Rejection {
        status: 403,
        reason: "Forbidden",
        headers: Vec::new(),
        body: "403 Forbidden\n".to_string(),
    }
}

impl Middleware for Waf {
    fn name(&self) -> &'static str {
        "waf"
    }

    fn on_request(&self, req: &mut RequestHead, ctx: &mut ReqCtx) -> Decision {
        let now = Instant::now();
        let ip = ctx.peer.ip();

        // Ban check FIRST, before inspection: a banned IP is refused for
        // ~one hash and one short lock — no normalization, no rule scan.
        // Cheap refusal of known offenders is most of what reputation buys.
        // Socket IP, never XFF, the L5/L6 stance.
        if self.mode == WafMode::Block && self.reputation.is_banned(ip, now) {
            self.reputation.stats.ban_refused.fetch_add(1, Ordering::Relaxed);
            crate::debug!("[{}] waf: refused banned ip", ctx.peer);
            return Decision::Reject(forbidden());
        }

        let verdict = inspect(req);
        if verdict.score == 0 {
            return Decision::Continue;
        }
        ctx.waf_score = Some(verdict.score);

        if verdict.score >= self.threshold {
            match self.mode {
                WafMode::Block => {
                    self.reputation.stats.convicted.fetch_add(1, Ordering::Relaxed);
                    // The hit list is log-only by design (no oracle).
                    crate::warn!(
                        "[{}] waf: BLOCKED {} {} score={} rules={:?}",
                        ctx.peer,
                        ctx.method,
                        ctx.target,
                        verdict.score,
                        verdict.hits
                    );
                    if let Some(term) = self.reputation.strike(ip, now, true) {
                        crate::warn!("[{}] waf: banned for {:?}", ctx.peer, term);
                    }
                    return Decision::Reject(forbidden());
                }
                WafMode::Detect => {
                    self.reputation.stats.detected.fetch_add(1, Ordering::Relaxed);
                    // Strike bookkeeping runs (so flipping to block mode
                    // starts with history) but never bans: watching first,
                    // enforcement later is the whole point of detect mode.
                    self.reputation.strike(ip, now, false);
                    crate::warn!(
                        "[{}] waf: detected (not blocked) {} {} score={} rules={:?}",
                        ctx.peer,
                        ctx.method,
                        ctx.target,
                        verdict.score,
                        verdict.hits
                    );
                }
            }
        }
        Decision::Continue
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

    fn score(target: &str) -> u32 {
        inspect(&get(target, vec![("User-Agent", "Mozilla/5.0")])).score
    }

    // ---- normalization ----

    #[test]
    fn percent_decoding_single_and_double() {
        let (t, f) = normalize("%27%20or%201=1", false);
        assert_eq!(t, "' or 1=1");
        assert!(!f.double_encoded);
        let (t, f) = normalize("%2527", false); // %25 = '%', second pass %27 = '
        assert_eq!(t, "'");
        assert!(f.double_encoded);
    }

    #[test]
    fn plus_space_entities_case_whitespace_null() {
        let (t, _) = normalize("a+b", true);
        assert_eq!(t, "a b");
        let (t, _) = normalize("a+b", false);
        assert_eq!(t, "a+b"); // + is data outside query strings
        let (t, _) = normalize("&lt;SCRIPT&gt;", false);
        assert_eq!(t, "<script>");
        let (t, _) = normalize("UNION\t\n  SELECT", false);
        assert_eq!(t, "union select");
        let (t, f) = normalize("abc%00def", false);
        assert_eq!(t, "abcdef");
        assert!(f.null_byte);
    }

    #[test]
    fn broken_escapes_stay_literal() {
        let (t, _) = normalize("100%zz%2", false);
        assert_eq!(t, "100%zz%2");
    }

    #[test]
    fn canonicalization_and_climb() {
        assert_eq!(canonicalize_path("/a/./b/../c"), ("/a/c".into(), false));
        assert_eq!(canonicalize_path("/a/../../etc/passwd"), ("/etc/passwd".into(), true));
        assert_eq!(canonicalize_path("/..//../x"), ("/x".into(), true));
        assert_eq!(canonicalize_path("/normal/path"), ("/normal/path".into(), false));
    }

    // ---- detectors: real payloads convict ----

    #[test]
    fn sqli_payloads_convict() {
        assert!(score("/login?user=admin&pass=%27%20OR%201=1--") >= DEFAULT_THRESHOLD);
        assert!(score("/q?id=1%20UNION%20SELECT%20password%20FROM%20users") >= DEFAULT_THRESHOLD);
        assert!(score("/q?id=1;DROP%20TABLE%20users") >= DEFAULT_THRESHOLD);
        assert!(score("/q?id=1%20AND%20sleep(5)--") >= DEFAULT_THRESHOLD);
        assert!(score("/q?t=information_schema.tables%20--") >= DEFAULT_THRESHOLD);
    }

    #[test]
    fn xss_payloads_convict() {
        assert!(score("/s?q=%3Cscript%3Ealert(1)%3C/script%3E") >= DEFAULT_THRESHOLD);
        assert!(score("/s?q=%3Cimg%20src=x%20onerror=alert(1)%3E") >= DEFAULT_THRESHOLD);
        assert!(score("/s?q=javascript:document.cookie") >= DEFAULT_THRESHOLD);
        // Entity-cloaked
        assert!(score("/s?q=&lt;script&gt;alert(1)&lt;/script&gt;") >= DEFAULT_THRESHOLD);
    }

    #[test]
    fn traversal_payloads_convict() {
        assert!(score("/files/../../../etc/passwd") >= DEFAULT_THRESHOLD);
        assert!(score("/files/%2e%2e/%2e%2e/etc/passwd") >= DEFAULT_THRESHOLD);
        // Double-encoded dots: decoding flags + traversal text both score.
        assert!(score("/files/%252e%252e/%252e%252e/etc/shadow") >= DEFAULT_THRESHOLD);
    }

    #[test]
    fn scanner_ua_convicts() {
        let v = inspect(&get("/", vec![("User-Agent", "sqlmap/1.7-dev")]));
        assert!(v.score >= DEFAULT_THRESHOLD);
    }

    // ---- benign lookalikes stay under threshold ----

    #[test]
    fn benign_traffic_passes() {
        // The apostrophe crowd.
        assert!(score("/search?q=O%27Brien") < DEFAULT_THRESHOLD);
        // SQL words as English.
        assert!(score("/directions?to=union+station") < DEFAULT_THRESHOLD);
        assert!(score("/pricing?cta=select+a+plan") < DEFAULT_THRESHOLD);
        // "script" as a word, no tag.
        assert!(score("/blog?tag=script+kiddie+culture") < DEFAULT_THRESHOLD);
        // Version-y dots.
        assert!(score("/docs/1.2.3/api") < DEFAULT_THRESHOLD);
        // Perfectly ordinary.
        assert!(score("/api/users/42?fields=name,email") == 0);
    }

    #[test]
    fn no_ua_is_a_nudge_not_a_conviction() {
        let v = inspect(&get("/plain", vec![]));
        assert_eq!(v.score, NO_UA_POINTS);
        assert!(v.score < DEFAULT_THRESHOLD);
    }

    #[test]
    fn scores_accumulate_across_surfaces() {
        // Quote in query (2) + comment-seq (4) alone: under threshold.
        // Same plus a scanner UA (10): over.
        let weak = inspect(&get("/q?a=%27--", vec![("User-Agent", "Mozilla")]));
        assert!(weak.score < DEFAULT_THRESHOLD);
        let stacked = inspect(&get("/q?a=%27--", vec![("User-Agent", "nikto/2.1")]));
        assert!(stacked.score >= DEFAULT_THRESHOLD);
    }

    // ---- reputation ----

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn strikes_ban_at_threshold_and_ban_lifts() {
        let r = Reputation::new(3, Duration::from_millis(50));
        let now = Instant::now();
        let a = ip("10.0.0.1");
        assert!(r.strike(a, now, true).is_none());
        assert!(r.strike(a, now, true).is_none());
        let term = r.strike(a, now, true);
        assert_eq!(term, Some(Duration::from_millis(50)));
        assert!(r.is_banned(a, now));
        assert!(!r.is_banned(a, now + Duration::from_millis(60)), "ban expired");
    }

    #[test]
    fn ban_backoff_doubles() {
        let r = Reputation::new(1, Duration::from_secs(60));
        let now = Instant::now();
        let a = ip("10.0.0.2");
        assert_eq!(r.strike(a, now, true), Some(Duration::from_secs(60)));
        // Serve the ban, reoffend: doubled.
        assert!(!r.is_banned(a, now + Duration::from_secs(61)));
        assert_eq!(
            r.strike(a, now + Duration::from_secs(61), true),
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn detect_mode_records_but_never_bans() {
        let r = Reputation::new(1, Duration::from_secs(60));
        let now = Instant::now();
        let a = ip("10.0.0.3");
        assert!(r.strike(a, now, false).is_none());
        assert!(r.strike(a, now, false).is_none());
        assert!(!r.is_banned(a, now));
    }

    #[test]
    fn stale_strikes_decay() {
        let r = Reputation::new(2, Duration::from_millis(10)); // decay = 100ms
        let now = Instant::now();
        let a = ip("10.0.0.4");
        assert!(r.strike(a, now, true).is_none());
        // Second strike far outside the decay window: counter restarted.
        assert!(r
            .strike(a, now + Duration::from_millis(200), true)
            .is_none());
    }

    #[test]
    fn strangers_are_not_banned() {
        let r = Reputation::new(1, Duration::from_secs(60));
        assert!(!r.is_banned(ip("192.168.1.1"), Instant::now()));
    }

    // ---- middleware ----

    #[test]
    fn waf_blocks_convicts_and_passes_benign() {
        let waf = Waf {
            mode: WafMode::Block,
            threshold: DEFAULT_THRESHOLD,
            reputation: Arc::new(Reputation::new(3, Duration::from_secs(60))),
        };
        let mut ctx = ReqCtx::new(
            "127.0.0.1:9".parse().unwrap(),
            "GET".into(),
            "/".into(),
            None,
        );
        let mut attack = get("/q?id=1%20UNION%20SELECT%20*%20FROM%20users--", vec![]);
        match waf.on_request(&mut attack, &mut ctx) {
            Decision::Reject(rej) => {
                assert_eq!(rej.status, 403);
                assert!(!rej.body.contains("union"), "no rule oracle in the body");
            }
            Decision::Continue => panic!("attack must be blocked"),
        }
        let mut benign = get("/api/users/42", vec![("User-Agent", "Mozilla")]);
        assert!(matches!(
            waf.on_request(&mut benign, &mut ctx),
            Decision::Continue
        ));
    }

    #[test]
    fn detect_mode_forwards_the_attack() {
        let waf = Waf {
            mode: WafMode::Detect,
            threshold: DEFAULT_THRESHOLD,
            reputation: Arc::new(Reputation::new(3, Duration::from_secs(60))),
        };
        let mut ctx = ReqCtx::new(
            "127.0.0.1:9".parse().unwrap(),
            "GET".into(),
            "/".into(),
            None,
        );
        let mut attack = get("/q?id=%27%20OR%201=1--", vec![]);
        assert!(matches!(
            waf.on_request(&mut attack, &mut ctx),
            Decision::Continue
        ));
        assert!(ctx.waf_score.unwrap() >= DEFAULT_THRESHOLD);
    }

    #[test]
    fn third_conviction_bans_and_fourth_request_is_refused_uninspected() {
        let waf = Waf {
            mode: WafMode::Block,
            threshold: DEFAULT_THRESHOLD,
            reputation: Arc::new(Reputation::new(3, Duration::from_secs(60))),
        };
        let peer: std::net::SocketAddr = "10.9.9.9:1234".parse().unwrap();
        let mut ctx = ReqCtx::new(peer, "GET".into(), "/".into(), None);
        for _ in 0..3 {
            let mut attack = get("/q?id=1%20UNION%20SELECT%20x--", vec![]);
            assert!(matches!(
                waf.on_request(&mut attack, &mut ctx),
                Decision::Reject(_)
            ));
        }
        // Now even an innocent request from that IP is refused (banned).
        let mut innocent = get("/perfectly/fine", vec![("User-Agent", "Mozilla")]);
        assert!(matches!(
            waf.on_request(&mut innocent, &mut ctx),
            Decision::Reject(_)
        ));
        assert_eq!(waf.reputation.stats.ban_refused.load(Ordering::Relaxed), 1);
    }
}
