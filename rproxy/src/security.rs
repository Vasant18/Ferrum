//! Level 8 — armoring the front door.
//!
//! TLS (see `tls.rs`) makes the transport private. This module makes the
//! listener *survivable*: the proxy is the one machine deliberately exposed to
//! every stranger on the internet, and every defense here answers a specific
//! attack from this level's threat table.
//!
//! | Attack | Defense in this module |
//! |---|---|
//! | Slowloris — hundreds of connections, one byte a minute each | `ConnLimiter`: global ceiling + per-source-IP cap |
//! | Resource exhaustion — 10 GB body, 10,000 headers | `Limits`: body cap enforced *while streaming*, header count cap |
//! | Known-bad sources / admin paths | `CidrList`: allow and deny lists on the socket peer address |
//!
//! Note what is *not* here: Level 1 already shipped the head-read deadline and
//! the 16 KB head byte cap, which are the other two-thirds of the slowloris
//! answer. This level adds the piece those cannot provide — a bound on how many
//! connections a single source may hold at once. A per-connection deadline does
//! not help when the attacker simply opens more connections.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Default global connection ceiling.
///
/// On by default, per this level's "the config a lazy user gets must be the safe
/// one" theme — an unbounded listener is a memory-exhaustion primitive. 10,000
/// is chosen to sit at the C10K reference point the knowledge base keeps using:
/// high enough that no realistic small deployment trips it, low enough that the
/// per-connection memory budget (buffers + task) stays bounded.
pub const DEFAULT_MAX_CONNS: usize = 10_000;

/// Default per-source-IP connection cap.
///
/// This is the number that actually stops slowloris. A browser legitimately
/// opens ~6 parallel connections per host; 64 leaves generous headroom for a
/// NAT'd office or a busy API client while still meaning one attacker needs 157
/// distinct source addresses to reach the global ceiling.
pub const DEFAULT_MAX_CONNS_PER_IP: usize = 64;

/// Default cap on request-body bytes forwarded to a backend.
///
/// 10 MiB: comfortable for JSON APIs and form posts, small enough that an
/// upload route has to opt in deliberately via `;max-body=`. The knowledge base
/// makes the per-route point explicitly — "an upload route allows more than an
/// API route."
pub const DEFAULT_MAX_BODY: u64 = 10 * 1024 * 1024;

/// Default cap on the number of header fields in a request head.
///
/// The 16 KB `MAX_HEAD_BYTES` cap from Level 1 already bounds total head *size*,
/// but not field *count* — 8,000 one-byte headers fit inside 16 KB and can still
/// force pathological work in any code that scans headers linearly (which ours
/// does, repeatedly: routing, hop-by-hop stripping, rewriting, framing).
pub const DEFAULT_MAX_HEADERS: usize = 100;

// ---------------------------------------------------------------------------
// Connection limiting
// ---------------------------------------------------------------------------

/// Global and per-IP connection accounting for the accept loop.
///
/// Checked *before* spawning a task: the check has to be cheaper than the
/// attack, or it becomes the attack. An over-limit connection is dropped
/// without a response — writing a 503 would mean allocating and doing I/O on
/// behalf of exactly the traffic we decided to shed.
pub struct ConnLimiter {
    max_total: usize,
    max_per_ip: usize,
    total: AtomicUsize,
    /// Per-source in-flight counts.
    ///
    /// One `std::sync::Mutex`, not Level 6's 16 shards, and not
    /// `tokio::sync::Mutex`. The critical section is a `HashMap` increment with
    /// no `.await` in it, so an async mutex would buy a scheduler hop for
    /// nothing (the same reasoning Level 6 used for the rate-limiter shards and
    /// Level 7 for the idle pool). Sharding is skipped because the access
    /// pattern is genuinely light here: exactly one lock per connection accept
    /// (from the single accept loop) and one per connection teardown. Level 6's
    /// limiter had to shard because it locked on *every request* from *every*
    /// task; this does not.
    per_ip: Mutex<HashMap<IpAddr, usize>>,
}

/// Why a connection was refused, kept distinct so the log can say which ceiling
/// was hit — "global" and "this one IP" call for very different operator
/// responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The process-wide ceiling is full.
    GlobalLimit,
    /// This source address is at its own cap.
    PerIpLimit,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::GlobalLimit => write!(f, "global connection limit"),
            Refusal::PerIpLimit => write!(f, "per-IP connection limit"),
        }
    }
}

impl ConnLimiter {
    pub fn new(max_total: usize, max_per_ip: usize) -> Arc<Self> {
        Arc::new(ConnLimiter {
            max_total,
            max_per_ip,
            total: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::new()),
        })
    }

    /// Try to admit one connection from `ip`.
    ///
    /// Returns a guard that releases both counters on drop, or the reason the
    /// connection was refused.
    ///
    /// The global counter is claimed first and rolled back if the per-IP check
    /// then fails. Claiming it *after* the per-IP check would leave a window
    /// where the process exceeds `max_total`; rolling back is the cheaper
    /// correctness fix than holding the map lock across both checks.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<ConnGuard, Refusal> {
        // `fetch_update` gives us claim-if-under-limit as one atomic step. A
        // bare `load` then `fetch_add` would let two accepts both observe
        // `total == max - 1` and both proceed. (Unlike Level 4's breaker
        // counters, where a lost increment merely delays a state change, a lost
        // increment here means the ceiling does not hold.)
        if self
            .total
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.max_total).then_some(n + 1)
            })
            .is_err()
        {
            return Err(Refusal::GlobalLimit);
        }

        {
            let mut map = self.per_ip.lock().expect("conn limiter mutex poisoned");
            let slot = map.entry(ip).or_insert(0);
            if *slot >= self.max_per_ip {
                drop(map);
                // Roll back the global claim we just made.
                self.total.fetch_sub(1, Ordering::AcqRel);
                return Err(Refusal::PerIpLimit);
            }
            *slot += 1;
        }

        Ok(ConnGuard { limiter: Arc::clone(self), ip })
    }

    /// Current global in-flight count. Used by the startup banner and tests.
    pub fn in_flight(&self) -> usize {
        self.total.load(Ordering::Acquire)
    }

    /// In-flight count for one source address. Test-facing.
    #[cfg(test)]
    fn in_flight_for(&self, ip: IpAddr) -> usize {
        self.per_ip
            .lock()
            .unwrap()
            .get(&ip)
            .copied()
            .unwrap_or(0)
    }

    /// Release one connection from `ip`. Private — the only caller is
    /// `ConnGuard::drop`, which is the point: there is no way to decrement
    /// without having held a guard.
    fn release(&self, ip: IpAddr) {
        self.total.fetch_sub(1, Ordering::AcqRel);
        let mut map = self.per_ip.lock().expect("conn limiter mutex poisoned");
        match map.get_mut(&ip) {
            Some(n) if *n > 1 => *n -= 1,
            // Last connection from this address: remove the entry entirely
            // rather than leaving a zero behind. Otherwise the map grows one
            // permanent entry per source address ever seen — which is itself a
            // slow memory-exhaustion vector, reachable by a spoofed-source scan.
            Some(_) => {
                map.remove(&ip);
            }
            None => debug_assert!(false, "released an untracked ip {ip}"),
        }
    }
}

/// RAII release for one admitted connection.
///
/// Drop-based, exactly like Level 3's `Lease`, and for a sharper version of the
/// same reason. A connection ends on many paths — clean close, parse error,
/// head-read timeout, TLS handshake failure, a task unwinding from a panic — and
/// an explicit `release()` call will eventually be missed on one of them. A
/// leaked in-flight count merely biases least-connections; a leaked *connection
/// slot* is permanent, and enough of them wedge the listener shut for good.
///
/// The guard is moved into the connection's task, so its lifetime is exactly the
/// connection's lifetime with no bookkeeping at any of the exit points.
pub struct ConnGuard {
    limiter: Arc<ConnLimiter>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

/// Hand-written rather than derived: deriving would require `ConnLimiter` to be
/// `Debug` too, which would expose the mutex-guarded map in any log line that
/// formatted a guard. The address is the only useful field anyway.
impl std::fmt::Debug for ConnGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnGuard({})", self.ip)
    }
}

// ---------------------------------------------------------------------------
// CIDR allow / deny
// ---------------------------------------------------------------------------

/// One CIDR block, e.g. `10.0.0.0/8`, `192.168.1.5`, `2001:db8::/32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    /// The network address, already masked so two spellings of the same block
    /// compare equal and matching never has to re-mask this side.
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    /// Parse `ADDR[/BITS]`. A bare address is a host route (`/32` for IPv4,
    /// `/128` for IPv6) — the shorthand an operator reaches for when denying a
    /// single abusive client.
    ///
    /// Hand-rolled rather than taking an `ipnet`-style dependency, following
    /// this project's established practice with FNV-1a (L3), duration parsing
    /// (L4), and base64 + constant-time compare (L6): a prefix comparison over
    /// 4 or 16 bytes is smaller than any of those, and `IpAddr` already did the
    /// genuinely fiddly part (parsing the address, including IPv6 forms).
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr_str, bits_str) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let addr: IpAddr = addr_str
            .trim()
            .parse()
            .map_err(|_| format!("bad IP address {addr_str:?} in CIDR {s:?}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match bits_str {
            None => max,
            Some(b) => {
                let n: u8 = b
                    .trim()
                    .parse()
                    .map_err(|_| format!("bad prefix length {b:?} in CIDR {s:?}"))?;
                if n > max {
                    return Err(format!(
                        "prefix /{n} too long for {} address in CIDR {s:?} (max /{max})",
                        if addr.is_ipv4() { "IPv4" } else { "IPv6" }
                    ));
                }
                n
            }
        };
        Ok(Cidr { net: mask(addr, bits), bits })
    }

    /// Whether `ip` falls inside this block.
    ///
    /// An IPv4 address never matches an IPv6 block or vice versa. In particular
    /// an IPv4-mapped IPv6 peer (`::ffff:10.0.0.1`, which is what a dual-stack
    /// listener reports) does NOT match `10.0.0.0/8` — see `normalize_peer`,
    /// which is where that is dealt with, deliberately once and at the edge
    /// rather than in every comparison.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask(ip, self.bits) == self.net
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.net, self.bits)
    }
}

/// Zero every bit below the prefix length.
fn mask(ip: IpAddr, bits: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let raw = u32::from_be_bytes(v4.octets());
            // `u32 << 32` is undefined-behavior-adjacent in C and a debug panic
            // in Rust, so /0 gets its own arm rather than relying on shift
            // semantics. Same for /128 below.
            let m = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            IpAddr::V4(std::net::Ipv4Addr::from((raw & m).to_be_bytes()))
        }
        IpAddr::V6(v6) => {
            let raw = u128::from_be_bytes(v6.octets());
            let m = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            IpAddr::V6(std::net::Ipv6Addr::from((raw & m).to_be_bytes()))
        }
    }
}

/// Collapse an IPv4-mapped IPv6 address to its IPv4 form.
///
/// A listener bound to `[::]` reports an IPv4 client as `::ffff:203.0.113.7`.
/// Without this, an operator's perfectly reasonable `--deny-cidr 203.0.113.0/24`
/// silently matches nothing — a deny list that appears configured and enforces
/// nothing, which is the worst possible failure mode for this feature. Normalize
/// once, here at the edge, so every downstream comparison sees one canonical
/// form.
pub fn normalize_peer(addr: SocketAddr) -> IpAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// An allow list, a deny list, or both.
///
/// Semantics, in order: deny wins over allow, and a non-empty allow list is
/// default-deny.
///
/// "Deny first" is the safe precedence — an address that appears on both lists
/// is being explicitly called out as bad, and honoring the allow entry would
/// mean a broad `--allow-cidr 10.0.0.0/8` silently re-admitted a specific host
/// the operator had just banned. "Non-empty allow list is default-deny" is what
/// makes an allow list mean anything at all; the alternative (allow list merely
/// grants, absence is permitted) would make `--allow-cidr` a no-op.
#[derive(Clone, Debug, Default)]
pub struct CidrList {
    allow: Vec<Cidr>,
    deny: Vec<Cidr>,
}

impl CidrList {
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    pub fn push_allow(&mut self, c: Cidr) {
        self.allow.push(c);
    }

    pub fn push_deny(&mut self, c: Cidr) {
        self.deny.push(c);
    }

    /// Whether `ip` is permitted.
    ///
    /// `ip` must be the **socket peer address**, never a value out of
    /// `X-Forwarded-For` or any other client-supplied header. A deny list keyed
    /// on something the client controls is not a deny list — the banned party
    /// simply sends a different value. Level 5 took this stance for
    /// `X-Real-IP`, Level 6 for the rate-limit key; this is the same rule for
    /// the third time, and it is the reason `normalize_peer` takes a
    /// `SocketAddr` rather than a string.
    pub fn permits(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|c| c.contains(ip)) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        self.allow.iter().any(|c| c.contains(ip))
    }

    /// One-line summary for the startup banner, so an operator can see the
    /// effective policy without re-reading their own command line.
    pub fn describe(&self) -> String {
        let f = |v: &Vec<Cidr>| {
            v.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",")
        };
        match (self.allow.is_empty(), self.deny.is_empty()) {
            (true, true) => "none".to_string(),
            (true, false) => format!("deny {}", f(&self.deny)),
            (false, true) => format!("allow {} (default-deny)", f(&self.allow)),
            (false, false) => {
                format!("deny {} then allow {} (default-deny)", f(&self.deny), f(&self.allow))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Request size limits
// ---------------------------------------------------------------------------

/// Per-request size caps.
///
/// `max_body` is per-route-overridable via `;max-body=`; `max_headers` is
/// global. The asymmetry is deliberate: body size is a legitimate per-route
/// policy question (an upload endpoint differs from a JSON API), whereas a
/// request needing more than a hundred header fields is pathological on every
/// route, so making it tunable per route would only widen the attack surface.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_body: u64,
    pub max_headers: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_body: DEFAULT_MAX_BODY, max_headers: DEFAULT_MAX_HEADERS }
    }
}

/// Parse a size with an optional `k`/`m`/`g` suffix: `1048576`, `512k`, `10m`,
/// `1g`. Case-insensitive, and a trailing `b` is tolerated (`10mb`).
///
/// Hand-rolled for the same reason `parse_duration` in `main.rs` is: two or
/// three suffixes are trivial, and the CLI's terse style wants `10m` rather
/// than a byte count nobody can read at a glance.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim().to_ascii_lowercase();
    let t = t.strip_suffix('b').unwrap_or(&t);
    let (digits, mult) = match t.strip_suffix('k') {
        Some(d) => (d, 1024u64),
        None => match t.strip_suffix('m') {
            Some(d) => (d, 1024 * 1024),
            None => match t.strip_suffix('g') {
                Some(d) => (d, 1024 * 1024 * 1024),
                None => (t, 1),
            },
        },
    };
    let n: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("bad size {s:?} (expected e.g. 10m, 512k, or a byte count)"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("size {s:?} overflows"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ---- ConnLimiter ----

    #[test]
    fn admits_up_to_the_global_cap_then_refuses() {
        let lim = ConnLimiter::new(2, 100);
        let a = ip("10.0.0.1");
        let _g1 = lim.try_acquire(a).unwrap();
        let _g2 = lim.try_acquire(a).unwrap();
        assert_eq!(lim.try_acquire(a).unwrap_err(), Refusal::GlobalLimit);
        assert_eq!(lim.in_flight(), 2);
    }

    #[test]
    fn admits_up_to_the_per_ip_cap_then_refuses() {
        let lim = ConnLimiter::new(100, 2);
        let a = ip("10.0.0.1");
        let _g1 = lim.try_acquire(a).unwrap();
        let _g2 = lim.try_acquire(a).unwrap();
        assert_eq!(lim.try_acquire(a).unwrap_err(), Refusal::PerIpLimit);
    }

    /// The whole point of a per-IP cap: one noisy source must not be able to
    /// lock everyone else out.
    #[test]
    fn one_ip_at_its_cap_does_not_block_another_ip() {
        let lim = ConnLimiter::new(100, 1);
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let _ga = lim.try_acquire(a).unwrap();
        assert_eq!(lim.try_acquire(a).unwrap_err(), Refusal::PerIpLimit);
        // b is unaffected.
        let _gb = lim.try_acquire(b).unwrap();
        assert_eq!(lim.in_flight(), 2);
    }

    #[test]
    fn dropping_a_guard_releases_both_counters() {
        let lim = ConnLimiter::new(1, 1);
        let a = ip("10.0.0.1");
        {
            let _g = lim.try_acquire(a).unwrap();
            assert_eq!(lim.in_flight(), 1);
            assert_eq!(lim.in_flight_for(a), 1);
            assert!(lim.try_acquire(a).is_err());
        }
        assert_eq!(lim.in_flight(), 0);
        assert_eq!(lim.in_flight_for(a), 0);
        // Slot is reusable after release.
        let _g = lim.try_acquire(a).unwrap();
    }

    /// A refusal must not consume a slot. If the rollback were missing, a
    /// source hammering its own per-IP cap would leak the global counter to
    /// exhaustion and take the whole listener down — a refusal path becoming
    /// the outage.
    #[test]
    fn per_ip_refusal_rolls_back_the_global_claim() {
        let lim = ConnLimiter::new(10, 1);
        let a = ip("10.0.0.1");
        let _g = lim.try_acquire(a).unwrap();
        for _ in 0..5 {
            assert_eq!(lim.try_acquire(a).unwrap_err(), Refusal::PerIpLimit);
        }
        assert_eq!(lim.in_flight(), 1, "global counter leaked on the refusal path");
    }

    /// The per-IP map must not accumulate a permanent entry per address ever
    /// seen — that is a slow memory leak reachable by a source-address scan.
    #[test]
    fn releasing_the_last_connection_removes_the_map_entry() {
        let lim = ConnLimiter::new(100, 4);
        for i in 0..50u8 {
            let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            let _g = lim.try_acquire(a).unwrap();
        }
        assert_eq!(lim.in_flight(), 0);
        assert_eq!(lim.per_ip.lock().unwrap().len(), 0, "map retained dead entries");
    }

    #[test]
    fn nested_guards_for_one_ip_decrement_one_at_a_time() {
        let lim = ConnLimiter::new(100, 3);
        let a = ip("10.0.0.1");
        let g1 = lim.try_acquire(a).unwrap();
        let g2 = lim.try_acquire(a).unwrap();
        assert_eq!(lim.in_flight_for(a), 2);
        drop(g2);
        assert_eq!(lim.in_flight_for(a), 1);
        drop(g1);
        assert_eq!(lim.in_flight_for(a), 0);
    }

    // ---- CIDR ----

    #[test]
    fn parses_v4_blocks_and_masks_the_network() {
        let c = Cidr::parse("10.1.2.3/8").unwrap();
        // The host bits are dropped, so the block prints canonically.
        assert_eq!(c.to_string(), "10.0.0.0/8");
        assert!(c.contains(ip("10.255.255.255")));
        assert!(!c.contains(ip("11.0.0.1")));
    }

    #[test]
    fn bare_address_is_a_host_route() {
        let c = Cidr::parse("192.168.1.5").unwrap();
        assert_eq!(c.to_string(), "192.168.1.5/32");
        assert!(c.contains(ip("192.168.1.5")));
        assert!(!c.contains(ip("192.168.1.6")));

        let c6 = Cidr::parse("2001:db8::1").unwrap();
        assert_eq!(c6.to_string(), "2001:db8::1/128");
    }

    /// /0 must match everything without triggering a shift overflow.
    #[test]
    fn slash_zero_matches_everything_in_family() {
        let c = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(c.contains(ip("1.2.3.4")));
        assert!(c.contains(ip("255.255.255.255")));
        // ...but still not across families.
        assert!(!c.contains(ip("::1")));

        let c6 = Cidr::parse("::/0").unwrap();
        assert!(c6.contains(ip("2001:db8::5")));
        assert!(!c6.contains(ip("1.2.3.4")));
    }

    #[test]
    fn boundary_prefixes_are_exact() {
        let c = Cidr::parse("10.0.0.0/32").unwrap();
        assert!(c.contains(ip("10.0.0.0")));
        assert!(!c.contains(ip("10.0.0.1")));

        let c6 = Cidr::parse("::1/128").unwrap();
        assert!(c6.contains(ip("::1")));
        assert!(!c6.contains(ip("::2")));
    }

    /// Off-by-one on the prefix is the classic CIDR bug: /24 must not admit the
    /// neighbouring /24.
    #[test]
    fn adjacent_ranges_do_not_match() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains(ip("192.168.1.0")));
        assert!(c.contains(ip("192.168.1.255")));
        assert!(!c.contains(ip("192.168.0.255")));
        assert!(!c.contains(ip("192.168.2.0")));
    }

    #[test]
    fn non_byte_aligned_prefix_works() {
        // /12 splits mid-octet: 172.16.0.0/12 covers 172.16 through 172.31.
        let c = Cidr::parse("172.16.0.0/12").unwrap();
        assert!(c.contains(ip("172.16.0.1")));
        assert!(c.contains(ip("172.31.255.254")));
        assert!(!c.contains(ip("172.15.255.255")));
        assert!(!c.contains(ip("172.32.0.0")));
    }

    #[test]
    fn v6_prefix_matching() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains(ip("2001:db8:dead:beef::1")));
        assert!(!c.contains(ip("2001:db9::1")));
    }

    #[test]
    fn rejects_malformed_cidrs() {
        assert!(Cidr::parse("").is_err());
        assert!(Cidr::parse("notanip").is_err());
        assert!(Cidr::parse("10.0.0.0/x").is_err());
        // Prefix longer than the family allows.
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("::1/129").is_err());
    }

    /// A /32-style prefix on an IPv6 address is legal (it is a real v6 prefix),
    /// so the max check must be family-aware rather than a flat 32.
    #[test]
    fn v6_accepts_prefixes_above_32() {
        assert!(Cidr::parse("2001:db8::/64").is_ok());
        assert!(Cidr::parse("2001:db8::/128").is_ok());
    }

    // ---- CidrList semantics ----

    #[test]
    fn empty_list_permits_everything() {
        let list = CidrList::default();
        assert!(list.is_empty());
        assert!(list.permits(ip("1.2.3.4")));
    }

    #[test]
    fn deny_list_blocks_only_listed_ranges() {
        let mut list = CidrList::default();
        list.push_deny(Cidr::parse("10.0.0.0/8").unwrap());
        assert!(!list.permits(ip("10.1.1.1")));
        assert!(list.permits(ip("11.1.1.1")));
    }

    #[test]
    fn non_empty_allow_list_is_default_deny() {
        let mut list = CidrList::default();
        list.push_allow(Cidr::parse("192.168.0.0/16").unwrap());
        assert!(list.permits(ip("192.168.5.5")));
        assert!(!list.permits(ip("8.8.8.8")), "allow list must be default-deny");
    }

    /// Deny must win, or a broad allow silently re-admits a specifically
    /// banned host.
    #[test]
    fn deny_beats_allow_on_overlap() {
        let mut list = CidrList::default();
        list.push_allow(Cidr::parse("10.0.0.0/8").unwrap());
        list.push_deny(Cidr::parse("10.1.2.3").unwrap());
        assert!(list.permits(ip("10.9.9.9")));
        assert!(!list.permits(ip("10.1.2.3")), "deny must take precedence");
    }

    #[test]
    fn describe_reports_the_effective_policy() {
        let mut list = CidrList::default();
        assert_eq!(list.describe(), "none");
        list.push_deny(Cidr::parse("10.0.0.0/8").unwrap());
        assert_eq!(list.describe(), "deny 10.0.0.0/8");
        list.push_allow(Cidr::parse("192.168.0.0/16").unwrap());
        assert!(list.describe().contains("default-deny"));
    }

    // ---- IPv4-mapped normalization ----

    /// A dual-stack listener reports IPv4 clients as `::ffff:a.b.c.d`. Without
    /// normalization an operator's v4 deny list would match nothing at all.
    #[test]
    fn ipv4_mapped_peer_normalizes_to_v4() {
        let addr: SocketAddr = "[::ffff:203.0.113.7]:12345".parse().unwrap();
        assert_eq!(normalize_peer(addr), ip("203.0.113.7"));

        let mut list = CidrList::default();
        list.push_deny(Cidr::parse("203.0.113.0/24").unwrap());
        assert!(
            !list.permits(normalize_peer(addr)),
            "v4-mapped peer escaped a v4 deny rule"
        );
    }

    #[test]
    fn genuine_v6_peer_is_left_alone() {
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(normalize_peer(addr), ip("2001:db8::1"));
    }

    // ---- size parsing ----

    #[test]
    fn parses_sizes_with_suffixes() {
        assert_eq!(parse_size("0").unwrap(), 0);
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("512k").unwrap(), 512 * 1024);
        assert_eq!(parse_size("10m").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_size("1g").unwrap(), 1024 * 1024 * 1024);
        // Case and a trailing 'b' are tolerated.
        assert_eq!(parse_size("10MB").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_size("2Kb").unwrap(), 2048);
    }

    #[test]
    fn rejects_bad_sizes() {
        assert!(parse_size("").is_err());
        assert!(parse_size("huge").is_err());
        assert!(parse_size("-1").is_err());
        assert!(parse_size("10x").is_err());
        // Overflow must be an error, not a wrap.
        assert!(parse_size("99999999999999999999g").is_err());
    }

    #[test]
    fn default_limits_are_on_not_unlimited() {
        let l = Limits::default();
        assert!(l.max_body > 0 && l.max_body < u64::MAX);
        assert!(l.max_headers > 0 && l.max_headers < 10_000);
    }
}
