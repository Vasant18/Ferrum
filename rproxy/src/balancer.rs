//! Level 3 — load balancing.
//!
//! Level 2 answered "which pool?"; this module answers "which server in that
//! pool?". A [`Route`](crate::router::Route) now points at an [`Upstream`]: a
//! named group of [`Server`]s plus an [`Algorithm`] for choosing among them.
//! Per request the proxy calls [`Upstream::pick`], which returns a [`Lease`] —
//! an RAII handle borrowing the chosen server. Connecting and forwarding then
//! happen through the lease; when it drops, the server's in-flight counter is
//! released and (if the exchange actually happened) its response-time average
//! is updated.
//!
//! ## Why a lease and not just an index
//!
//! Two of the algorithms (least-connections, least-response-time) are *load
//! aware*: they read live per-server counters. Those counters only stay honest
//! if every increment is paired with exactly one decrement — including on the
//! error paths where a `?` bails out mid-request or the task is cancelled. An
//! explicit `release()` call is always one early `return` away from being
//! skipped, and a single leaked in-flight count permanently biases
//! least-connections *against* a perfectly healthy server. So release lives in
//! `Drop`, which the compiler runs on every exit path. That is the whole
//! reason this type exists.
//!
//! ## The seam for Level 4 (health checks)
//!
//! Every selection routes only among servers for which [`Server::available`]
//! returns true. Today it is hardcoded `true`, so nothing is filtered and a
//! genuinely dead backend is still picked and still yields `502` — detecting
//! liveness is Level 4's job. When Level 4 arrives it flips `available()` to
//! read a health flag and *no call site changes*: the routing already skips
//! unavailable servers. The `Lease` already times each exchange into an EWMA,
//! which Level 4's passive checks and Level 10's metrics will both read.

use std::cell::Cell;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// The seven balancing strategies from the course spec. The discriminant
/// carries no meaning; each variant selects a different `select` branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// Cycle through servers in order. The sensible default.
    RoundRobin,
    /// Round robin over a list pre-expanded by weight (5:1 -> five of A per B).
    WeightedRoundRobin,
    /// Uniform random choice. Needs no shared state at all.
    Random,
    /// Fewest in-flight requests wins. Load-aware, O(n) scan.
    LeastConnections,
    /// Lowest observed average response time wins. Load-aware, O(n) scan.
    LeastResponseTime,
    /// `hash(client_ip) % n` — crude client affinity by arithmetic accident.
    IpHash,
    /// Virtual-node hash ring — affinity that survives adding/removing servers.
    ConsistentHash,
}

impl Algorithm {
    /// The CLI tag for this algorithm, also used in the per-request log line.
    pub fn tag(self) -> &'static str {
        match self {
            Algorithm::RoundRobin => "rr",
            Algorithm::WeightedRoundRobin => "wrr",
            Algorithm::Random => "rand",
            Algorithm::LeastConnections => "lc",
            Algorithm::LeastResponseTime => "lrt",
            Algorithm::IpHash => "iphash",
            Algorithm::ConsistentHash => "chash",
        }
    }

    /// Parse a CLI tag. `None` means "not one of ours" — the spec parser uses
    /// that to tell an algorithm keyword apart from a hostname (see
    /// `Upstream::from_spec`).
    fn from_tag(tag: &str) -> Option<Algorithm> {
        Some(match tag {
            "rr" => Algorithm::RoundRobin,
            "wrr" => Algorithm::WeightedRoundRobin,
            "rand" => Algorithm::Random,
            "lc" => Algorithm::LeastConnections,
            "lrt" => Algorithm::LeastResponseTime,
            "iphash" => Algorithm::IpHash,
            "chash" => Algorithm::ConsistentHash,
            _ => return None,
        })
    }

    fn uses_weight(self) -> bool {
        matches!(self, Algorithm::WeightedRoundRobin)
    }
}

/// Tunables shared by the breaker and the active prober. One instance per
/// upstream, behind an `Arc` so every `Server` in the pool reads the same
/// thresholds without copying them.
#[derive(Clone, Debug)]
pub struct HealthConfig {
    /// Consecutive failures that trip Closed -> Open.
    pub fail_threshold: usize,
    /// Consecutive successes in HalfOpen that restore Closed.
    pub success_threshold: usize,
    /// First Open cooldown, before any doubling.
    pub backoff_base: Duration,
    /// Ceiling on the doubling cooldown.
    pub backoff_max: Duration,
    /// Active probe period.
    pub interval: Duration,
    /// Per-probe connect+read deadline.
    pub timeout: Duration,
    /// Path the active prober requests, e.g. "/health".
    pub path: String,
}

impl Default for HealthConfig {
    fn default() -> HealthConfig {
        HealthConfig {
            fail_threshold: 3,
            success_threshold: 2,
            backoff_base: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            interval: Duration::from_secs(2),
            timeout: Duration::from_secs(1),
            path: "/health".to_string(),
        }
    }
}

/// The three breaker states. `Closed` is the healthy, serving state — the name
/// comes from electrical circuits, where a *closed* circuit conducts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerState {
    /// Serving traffic. Failures accumulate toward the trip threshold.
    Closed,
    /// Tripped. No client traffic; a cooldown must elapse before we retest.
    Open,
    /// Cooldown elapsed, one probe outstanding. Clients are still blocked —
    /// we only *suspect* recovery until `success_threshold` probes agree.
    HalfOpen,
}

/// What the prober should do with a server this tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeAction {
    /// Routine liveness probe of a healthy server.
    Normal,
    /// The single recovery trial admitted per Open cooldown.
    HalfOpenTrial,
}

const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

/// A per-server circuit breaker: the single source of truth for whether this
/// backend gets traffic.
///
/// Both feeds — passive (real request outcomes) and active (the `health.rs`
/// prober) — call the same `record_success`/`record_failure`. That sharing is
/// the point: a server under live traffic trips from client failures without
/// waiting for a probe, and a server with no traffic still recovers via probes.
/// Neither feed knows the other exists.
///
/// Every method takes `now: Instant` instead of reading the clock itself, so
/// the whole state machine is testable without sleeping.
///
/// All fields are `Relaxed` atomics. As in Level 3, these guide a heuristic
/// rather than protect data, so we never need an ordering edge. A concurrent
/// pair of `record_failure` calls can race and lose one increment; the next
/// failure trips the breaker instead. One request of extra tolerance is a fair
/// price for keeping the request path lock-free.
pub struct Breaker {
    cfg: Arc<HealthConfig>,
    state: AtomicU8,
    /// Nanoseconds-since-process-start when the Open cooldown ends. Using a
    /// scalar baseline (rather than storing an `Instant`) keeps this atomic.
    open_until_nanos: AtomicU64,
    /// Current cooldown length in nanos; doubles per trip, capped, reset on
    /// recovery.
    backoff_nanos: AtomicU64,
    consec_fail: AtomicUsize,
    consec_success: AtomicUsize,
}

impl Breaker {
    pub fn new(cfg: Arc<HealthConfig>) -> Breaker {
        // Realize the shared process-start baseline now, at construction, so it
        // is guaranteed to precede every `now: Instant` later handed to a
        // transition method. `stamp` measures nanos from this baseline; if the
        // `LazyLock` were instead first initialized *inside* a transition (its
        // only other toucher is the Random PRNG seed), a `now` captured before
        // that point would saturate to 0 and desynchronize the cooldown
        // arithmetic. Touching it here costs nothing in the real server — the
        // first breaker is built at startup — and removes the ordering hazard.
        let _ = *PROCESS_START;
        let base = cfg.backoff_base.as_nanos() as u64;
        Breaker {
            cfg,
            state: AtomicU8::new(STATE_CLOSED),
            open_until_nanos: AtomicU64::new(0),
            backoff_nanos: AtomicU64::new(base),
            consec_fail: AtomicUsize::new(0),
            consec_success: AtomicUsize::new(0),
        }
    }

    /// Nanos from the process-start baseline to `t`. Shares `PROCESS_START`
    /// with the Random algorithm's seeding.
    fn stamp(t: Instant) -> u64 {
        t.saturating_duration_since(*PROCESS_START).as_nanos() as u64
    }

    fn load_state(&self) -> BreakerState {
        match self.state.load(Ordering::Relaxed) {
            STATE_OPEN => BreakerState::Open,
            STATE_HALF_OPEN => BreakerState::HalfOpen,
            _ => BreakerState::Closed,
        }
    }

    pub fn state(&self) -> BreakerState {
        self.load_state()
    }

    /// The gate every selection algorithm consults (via `Server::available`).
    /// True only in `Closed`: recovery must be *confirmed* by probes before
    /// clients are exposed to a server again.
    pub fn allows_traffic(&self) -> bool {
        self.state.load(Ordering::Relaxed) == STATE_CLOSED
    }

    /// Current Open cooldown. Exposed for log lines and tests.
    pub fn cooldown(&self) -> Duration {
        Duration::from_nanos(self.backoff_nanos.load(Ordering::Relaxed))
    }

    /// Move to Open, arming the cooldown. `double` distinguishes a fresh trip
    /// (keep the current backoff) from a failed recovery trial (double it).
    fn trip_open(&self, now: Instant, double: bool) {
        let mut backoff = self.backoff_nanos.load(Ordering::Relaxed);
        if double {
            let max = self.cfg.backoff_max.as_nanos() as u64;
            backoff = backoff.saturating_mul(2).min(max);
            self.backoff_nanos.store(backoff, Ordering::Relaxed);
        }
        self.open_until_nanos
            .store(Self::stamp(now).saturating_add(backoff), Ordering::Relaxed);
        self.state.store(STATE_OPEN, Ordering::Relaxed);
        self.consec_fail.store(0, Ordering::Relaxed);
        self.consec_success.store(0, Ordering::Relaxed);
    }

    /// Report one failed exchange. Returns `Some((from, to))` if the state
    /// changed, so the caller can log the transition.
    pub fn record_failure(&self, now: Instant) -> Option<(BreakerState, BreakerState)> {
        match self.load_state() {
            BreakerState::Closed => {
                let n = self.consec_fail.fetch_add(1, Ordering::Relaxed) + 1;
                if n >= self.cfg.fail_threshold {
                    // Fresh trip: keep the existing backoff (base, or whatever
                    // a previous un-recovered episode left).
                    self.trip_open(now, false);
                    Some((BreakerState::Closed, BreakerState::Open))
                } else {
                    None
                }
            }
            BreakerState::HalfOpen => {
                // The recovery trial failed: back to Open, waiting longer.
                self.trip_open(now, true);
                Some((BreakerState::HalfOpen, BreakerState::Open))
            }
            // Already Open: the cooldown governs the next attempt.
            BreakerState::Open => None,
        }
    }

    /// Report one successful exchange.
    pub fn record_success(&self, _now: Instant) -> Option<(BreakerState, BreakerState)> {
        match self.load_state() {
            BreakerState::Closed => {
                // A good result clears a partial failure run: only *consecutive*
                // failures should trip the breaker.
                self.consec_fail.store(0, Ordering::Relaxed);
                None
            }
            BreakerState::HalfOpen => {
                let n = self.consec_success.fetch_add(1, Ordering::Relaxed) + 1;
                if n >= self.cfg.success_threshold {
                    self.state.store(STATE_CLOSED, Ordering::Relaxed);
                    self.backoff_nanos
                        .store(self.cfg.backoff_base.as_nanos() as u64, Ordering::Relaxed);
                    self.consec_fail.store(0, Ordering::Relaxed);
                    self.consec_success.store(0, Ordering::Relaxed);
                    Some((BreakerState::HalfOpen, BreakerState::Closed))
                } else {
                    None
                }
            }
            // Traffic is blocked in Open, so this shouldn't happen; ignore it
            // rather than letting a stray success silently un-trip the breaker.
            BreakerState::Open => None,
        }
    }

    /// The prober's gate: may this server be probed right now, and as what?
    ///
    /// Returns `None` for a server that is cooling down or already has a trial
    /// outstanding. Admitting exactly one trial per cooldown is what keeps a
    /// dead backend from being hammered every tick.
    pub fn probe_due(&self, now: Instant) -> Option<ProbeAction> {
        match self.load_state() {
            BreakerState::Closed => Some(ProbeAction::Normal),
            BreakerState::Open => {
                if Self::stamp(now) >= self.open_until_nanos.load(Ordering::Relaxed) {
                    self.state.store(STATE_HALF_OPEN, Ordering::Relaxed);
                    self.consec_success.store(0, Ordering::Relaxed);
                    Some(ProbeAction::HalfOpenTrial)
                } else {
                    None
                }
            }
            BreakerState::HalfOpen => None,
        }
    }
}

/// Virtual nodes per real server on the consistent-hash ring. More vnodes =
/// smoother key distribution but a bigger ring; 160 is the common Ketama value.
const VNODES_PER_SERVER: usize = 160;

/// One backend server in a pool. The address is immutable; the two atomics are
/// the live, shared state the load-aware algorithms read and the `Lease`
/// writes. They are `Relaxed` throughout: these are statistics guiding a
/// heuristic, not a lock protecting data, so we never need an ordering edge.
pub struct Server {
    addr: String,
    /// Requests currently in flight to this server. `Lease` bumps it on
    /// creation and drops it on `Drop`. Read by least-connections.
    inflight: AtomicUsize,
    /// Exponentially weighted moving average of observed round-trip time, in
    /// microseconds. `0` is the sentinel for "no samples yet" — read by
    /// least-response-time, which sorts untried servers first so a fresh
    /// server gets traffic instead of being starved.
    ewma_us: AtomicU64,
    /// Level 4: the circuit breaker deciding whether this server gets traffic.
    breaker: Breaker,
}

/// EWMA smoothing factor. `new = old*(1-alpha) + sample*alpha`, done in integer
/// arithmetic as `(old*4 + sample) / 5` for alpha = 0.2. Higher alpha reacts
/// faster to change but is noisier; 0.2 is a common, calm choice.
const EWMA_ALPHA_NUM: u64 = 1; // alpha = 1/5
const EWMA_ALPHA_DEN: u64 = 5;

impl Server {
    fn new(addr: String, health: Arc<HealthConfig>) -> Server {
        Server {
            addr,
            inflight: AtomicUsize::new(0),
            ewma_us: AtomicU64::new(0),
            breaker: Breaker::new(health),
        }
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Whether this server may receive traffic. Level 3 hardcoded `true` and
    /// left this seam; Level 4 fills it in from the breaker. Because every
    /// selection algorithm already routed only among available servers, no
    /// selection logic changed to make ejection work.
    pub fn available(&self) -> bool {
        self.breaker.allows_traffic()
    }

    pub fn breaker(&self) -> &Breaker {
        &self.breaker
    }

    /// Passive/active feed entry points. Both feeds funnel through here.
    pub fn record_success(&self, now: Instant) -> Option<(BreakerState, BreakerState)> {
        self.breaker.record_success(now)
    }

    pub fn record_failure(&self, now: Instant) -> Option<(BreakerState, BreakerState)> {
        self.breaker.record_failure(now)
    }

    fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Relaxed)
    }

    /// Fold one observed round-trip time into the EWMA. Samples are floored at
    /// 1µs so a real (fast) sample can never masquerade as the `0` = untried
    /// sentinel.
    fn record_rtt(&self, rtt: Duration) {
        let sample = (rtt.as_micros() as u64).max(1);
        let _ = self.ewma_us.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
            Some(if old == 0 {
                sample
            } else {
                (old * (EWMA_ALPHA_DEN - EWMA_ALPHA_NUM) + sample * EWMA_ALPHA_NUM) / EWMA_ALPHA_DEN
            })
        });
    }
}

/// A named pool of servers plus the algorithm that chooses among them. Built
/// once at startup and shared read-only behind an `Arc`; the only mutation is
/// through the interior-mutable atomics, so `pick` takes `&self` and needs no
/// lock. This is the same lock-free-shared-config pattern as the router.
pub struct Upstream {
    name: String,
    algorithm: Algorithm,
    servers: Vec<Server>,
    /// Monotonic counter for round robin / weighted round robin. `% len`
    /// on read; wraps naturally at `usize::MAX`.
    cursor: AtomicUsize,
    /// Weighted round robin only: server indices pre-expanded by weight, e.g.
    /// weights 5:1 -> `[0,0,0,0,0,1]`. Empty for every other algorithm. This
    /// turns a weighted pick into a plain O(1) round robin over the expansion.
    wrr_index: Vec<usize>,
    /// Consistent hashing only: `(hash, server_index)` pairs sorted by hash,
    /// `VNODES_PER_SERVER` entries per server. Empty otherwise.
    ring: Vec<(u64, usize)>,
    /// Level 4 health tunables for this pool, shared with every `Server` in it.
    health: Arc<HealthConfig>,
}

impl Upstream {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// One-line pool summary for the startup banner, e.g.
    /// `[lc] 127.0.0.1:9001, 127.0.0.1:9002`.
    pub fn describe(&self) -> String {
        let addrs: Vec<&str> = self.servers.iter().map(Server::addr).collect();
        format!("[{}] {}", self.algorithm.tag(), addrs.join(", "))
    }

    /// Build a pool from an already-parsed algorithm and `(addr, weight)`
    /// list. Precomputes the weighted-RR expansion and the consistent-hash
    /// ring so that `pick` stays cheap. Callers that go through the CLI use
    /// [`Upstream::from_spec`]; this is the seam tests and internal helpers use.
    fn build(
        name: String,
        algorithm: Algorithm,
        servers: Vec<(String, u32)>,
        health: Arc<HealthConfig>,
    ) -> Upstream {
        let wrr_index = if algorithm.uses_weight() {
            let mut v = Vec::new();
            for (i, (_, weight)) in servers.iter().enumerate() {
                for _ in 0..*weight {
                    v.push(i);
                }
            }
            v
        } else {
            Vec::new()
        };

        let ring = if algorithm == Algorithm::ConsistentHash {
            let mut r = Vec::with_capacity(servers.len() * VNODES_PER_SERVER);
            for (i, (addr, _)) in servers.iter().enumerate() {
                for v in 0..VNODES_PER_SERVER {
                    // Hash "addr#vnode" so each server scatters across the ring
                    // instead of owning one contiguous arc — that scattering is
                    // what keeps the load even and makes removal cheap.
                    let key = format!("{addr}#{v}");
                    r.push((fnv1a(key.as_bytes()), i));
                }
            }
            // Sorted once so lookup is a binary search (`partition_point`).
            r.sort_unstable_by_key(|&(h, _)| h);
            r
        } else {
            Vec::new()
        };

        let servers = servers
            .into_iter()
            .map(|(addr, _)| Server::new(addr, Arc::clone(&health)))
            .collect();
        Upstream {
            name,
            algorithm,
            servers,
            cursor: AtomicUsize::new(0),
            wrr_index,
            ring,
            health,
        }
    }

    pub fn health(&self) -> &Arc<HealthConfig> {
        &self.health
    }

    /// Read-only view of the pool for the prober to walk.
    pub fn servers_slice(&self) -> &[Server] {
        &self.servers
    }

    /// Choose a server index for this request, or `None` if the pool has no
    /// available server. Split out from `pick` so it carries no lease
    /// side effects — handy for tests and for the log line.
    fn select(&self, client_ip: IpAddr) -> Option<usize> {
        let n = self.servers.len();
        if n == 0 {
            return None;
        }
        match self.algorithm {
            Algorithm::RoundRobin => {
                // Relaxed: we want a distinct-ish index, not a happens-before
                // edge. `%` folds the ever-growing counter onto the servers.
                let start = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
                self.first_available_from(start)
            }
            Algorithm::WeightedRoundRobin => {
                // Plain round robin over the pre-expanded index list. O(1), at
                // the cost of O(sum of weights) memory. Note this produces a
                // *bursty* run (AAAAAB for 5:1); Nginx uses "smooth WRR" to
                // interleave (AABAAB-ish). We keep the simple expansion because
                // the burst is harmless for a teaching proxy and the array
                // makes the weighting obvious.
                let slot = self.cursor.fetch_add(1, Ordering::Relaxed) % self.wrr_index.len();
                self.first_available_from(self.wrr_index[slot])
            }
            Algorithm::Random => {
                // No shared state at all — each worker thread rolls its own
                // PRNG. Surprisingly competitive in practice (see
                // power-of-two-choices), and it never contends a cache line.
                let start = (next_random() % n as u64) as usize;
                self.first_available_from(start)
            }
            Algorithm::LeastConnections => {
                // O(n) scan for the fewest in-flight requests. Documented race:
                // two tasks can scan at the same instant and both pick the same
                // idle server, briefly over-loading it by one request. That is
                // acceptable — the error is one request deep and self-corrects
                // on the next pick — and a lock to prevent it would serialize
                // every request through the proxy. Living with the race is the
                // lesson. Ties go to the lower index (`min_by_key` keeps the
                // first minimum).
                self.servers
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.available())
                    .min_by_key(|(_, s)| s.inflight())
                    .map(|(i, _)| i)
            }
            Algorithm::LeastResponseTime => {
                // Same scan, keyed on the EWMA. `0` = untried sorts first, so a
                // newly added server receives traffic instead of being starved
                // behind servers that already have (non-zero) history.
                self.servers
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.available())
                    .min_by_key(|(_, s)| s.ewma_us.load(Ordering::Relaxed))
                    .map(|(i, _)| i)
            }
            Algorithm::IpHash => {
                // Affinity by arithmetic: the same client IP hashes to the same
                // index — as long as `n` never changes. Add or remove one
                // server and `% n` shifts almost every client to a new server.
                // That fragility is exactly what consistent hashing fixes.
                let start = (hash_ip(client_ip) % n as u64) as usize;
                self.first_available_from(start)
            }
            Algorithm::ConsistentHash => {
                // Walk the sorted ring clockwise from the client's hash to the
                // first available server. Removing a server only orphans the
                // ~1/n of keys that landed on *its* vnodes; everyone else keeps
                // their server. `partition_point` is a binary search for the
                // first ring entry with hash >= ours; wrap to 0 past the end.
                let h = hash_ip(client_ip);
                let mut idx = self.ring.partition_point(|&(hh, _)| hh < h);
                for _ in 0..self.ring.len() {
                    if idx == self.ring.len() {
                        idx = 0;
                    }
                    let s = self.ring[idx].1;
                    if self.servers[s].available() {
                        return Some(s);
                    }
                    idx += 1;
                }
                None
            }
        }
    }

    /// Linear probe from `start`, wrapping, for the first available server.
    /// With every server available (Level 3) the first probe always succeeds,
    /// so the O(1) algorithms stay O(1); the loop is the Level 4 seam that lets
    /// selection skip a server marked unhealthy without touching call sites.
    fn first_available_from(&self, start: usize) -> Option<usize> {
        let n = self.servers.len();
        (0..n)
            .map(|k| (start + k) % n)
            .find(|&i| self.servers[i].available())
    }

    /// Pick a server for `client_ip` and return an RAII [`Lease`] on it, or
    /// `None` if the pool has no available server. Startup validation forbids
    /// an empty pool, so the call site treats `None` as a defensive `502`
    /// rather than an expected outcome.
    pub fn pick(&self, client_ip: IpAddr) -> Option<Lease<'_>> {
        let idx = self.select(client_ip)?;
        Some(Lease::new(&self.servers[idx]))
    }
}

/// An RAII handle to a picked server. Holding it counts as one in-flight
/// request; dropping it releases that count on *every* exit path. See the
/// module docs for why release must live in `Drop` and not an explicit call.
pub struct Lease<'a> {
    server: &'a Server,
    /// When the lease was taken (just before connecting). On drop, if the
    /// exchange completed, `now - started` is folded into the server's EWMA.
    started: Instant,
    /// Set by [`Lease::mark_served`] once the backend exchange actually
    /// happened. Gates the EWMA update: a *failed* connect must not record a
    /// (tiny) RTT, or least-response-time would learn to prefer dead servers —
    /// the fastest way to "respond" is to refuse the connection instantly.
    served: bool,
    /// Level 4 passive health feed. `Some(true)` = healthy exchange,
    /// `Some(false)` = failure, `None` = we never formed a judgement (e.g. the
    /// task was cancelled mid-flight). `None` deliberately reports *nothing*:
    /// guessing an outcome would poison the breaker with noise.
    outcome: Option<bool>,
}

impl<'a> Lease<'a> {
    fn new(server: &'a Server) -> Lease<'a> {
        server.inflight.fetch_add(1, Ordering::Relaxed);
        Lease { server, started: Instant::now(), served: false, outcome: None }
    }

    /// The chosen backend's address. Read straight from the `Server` rather
    /// than copied into the lease, keeping one source of truth.
    pub fn addr(&self) -> &str {
        self.server.addr()
    }

    /// Current in-flight count for the chosen server (including this lease).
    /// Used only for the observability log line.
    pub fn inflight(&self) -> usize {
        self.server.inflight()
    }

    /// Record that the backend exchange completed, so the EWMA update fires on
    /// drop. Call this only after a successful connect + forward.
    pub fn mark_served(&mut self) {
        self.served = true;
    }

    /// Report a healthy exchange to the breaker (passive health check).
    /// A 4xx counts as success: the *backend* is fine, the client sent a bad
    /// request. Only 5xx and transport failures indict the server.
    pub fn mark_success(&mut self) {
        self.outcome = Some(true);
    }

    /// Report a failed exchange to the breaker: connect refused/timed out,
    /// a read error, or a 5xx response.
    pub fn mark_failure(&mut self) {
        self.outcome = Some(false);
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        // Unconditional: the in-flight count must fall no matter how we got
        // here (normal finish, `?`-propagation, panic, task cancel).
        self.server.inflight.fetch_sub(1, Ordering::Relaxed);
        // Conditional: only a real exchange contributes to response-time
        // history. See the `served` field for why.
        if self.served {
            self.server.record_rtt(self.started.elapsed());
        }
        // Level 4 passive feed. Only report when we actually judged the
        // exchange; `None` stays silent by design.
        match self.outcome {
            Some(true) => {
                self.server.record_success(Instant::now());
            }
            Some(false) => {
                if let Some((from, to)) = self.server.record_failure(Instant::now()) {
                    eprintln!(
                        "health: {} {from:?}->{to:?} (passive, cooldown {:?})",
                        self.server.addr(),
                        self.server.breaker().cooldown()
                    );
                }
            }
            None => {}
        }
    }
}

// ---- Hashing ---------------------------------------------------------------

/// FNV-1a, 64-bit. We write it out (six lines) instead of using `std`'s
/// `DefaultHasher` for two reasons: the arithmetic is visible and teachable,
/// and — critically for affinity — `DefaultHasher`'s output is explicitly
/// unspecified across Rust versions, so a toolchain upgrade could silently
/// remap every client to a different server. A named, fixed algorithm keeps
/// affinity stable forever.
fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET_BASIS;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Hash a client IP by its raw octets (4 for v4, 16 for v6). Hashing octets
/// rather than the textual form avoids formatting quirks like `::1` vs
/// `0:0:...:1` mapping to different servers.
fn hash_ip(ip: IpAddr) -> u64 {
    match ip {
        IpAddr::V4(a) => fnv1a(&a.octets()),
        IpAddr::V6(a) => fnv1a(&a.octets()),
    }
}

// ---- Per-thread PRNG for Random --------------------------------------------

/// Process start, captured lazily on first use. Its elapsed nanos seed the
/// per-thread PRNG so seeds differ run-to-run without a `rand` dependency.
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);
/// Handed out one-per-thread so two threads seeded in the same nanosecond
/// still diverge.
static SEED_COUNTER: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// xorshift64 state, one per worker thread. Non-zero invariant maintained
    /// at seed time (xorshift is stuck at 0 forever if it ever reaches 0).
    static RNG: Cell<u64> = Cell::new({
        let n = SEED_COUNTER.fetch_add(1, Ordering::Relaxed);
        let t = PROCESS_START.elapsed().as_nanos() as u64;
        let seed = t ^ n.wrapping_mul(0x9E3779B97F4A7C15); // golden-ratio mix
        if seed == 0 { 0xDEAD_BEEF_CAFE_F00D } else { seed }
    });
}

/// One xorshift64 step. Fast, not cryptographic — all we need is a spread of
/// indices with no shared state in the hot path.
fn next_random() -> u64 {
    RNG.with(|cell| {
        let mut x = cell.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        cell.set(x);
        x
    })
}

// ---- Spec parsing ----------------------------------------------------------

/// Parse one server token `addr[*weight]` into `(addr, weight)`. Weight
/// defaults to 1. The address must look like `host:port` with a non-empty host
/// and a port in `1..=65535`; we don't resolve it here (that happens at
/// connect time, per level's connection model), only validate the shape.
fn parse_server(token: &str, algorithm: Algorithm, err: &impl Fn(&str) -> io::Error)
    -> io::Result<(String, u32)>
{
    let (addr, weight) = match token.rsplit_once('*') {
        Some((addr, w)) => {
            let weight: u32 = w
                .parse()
                .map_err(|_| err(&format!("bad weight {w:?}")))?;
            if weight == 0 {
                // A zero-weight server can never be picked, so it is certainly
                // a typo; refusing at startup beats silently dropping it.
                return Err(err("weight must be >= 1"));
            }
            if !algorithm.uses_weight() {
                // Accept-but-warn: a no-op misconfiguration should not stop the
                // proxy from starting. Only weighted RR consumes the weight.
                eprintln!(
                    "ferrum: warning: weight on {addr:?} ignored (algorithm {} is not weighted)",
                    algorithm.tag()
                );
            }
            (addr, weight)
        }
        None => (token, 1),
    };

    if !is_host_port(addr) {
        return Err(err(&format!("server address must be host:port, got {addr:?}")));
    }
    Ok((addr.to_string(), weight))
}

/// Does `addr` look like `host:port` with a non-empty host and a port in
/// `1..=65535`? Split off the port from the *right* so IPv6 hosts (which
/// themselves contain ':') survive: `[::1]:8080` -> host `[::1]`, port `8080`.
/// We validate shape only, never resolve — resolution happens at connect time.
/// Shared by the spec parser and by route resolution's `host:port` auto-wrap
/// (rule 2), so both agree on exactly what a bare backend address is.
pub fn is_host_port(addr: &str) -> bool {
    match addr.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && matches!(port.parse::<u16>(), Ok(p) if p >= 1),
        None => false,
    }
}

impl Upstream {
    /// Parse a full upstream spec `algo:server[*w][,server[*w]...]` into a
    /// pool. The algorithm tag is optional and defaults to round robin.
    ///
    /// Telling the tag apart from a hostname is the one subtlety. An address is
    /// always `host:port`, so its first colon is followed by more colons or a
    /// port; a leading token is treated as an algorithm keyword only when it is
    /// all ASCII letters *and* the remainder still contains a `:` (i.e. it
    /// really looks like `tag:host:port...`). Thus:
    ///   - `lc:127.0.0.1:9001,...`  -> tag `lc`
    ///   - `chash:node1:6379,...`   -> tag `chash`
    ///   - `127.0.0.1:9001`         -> no tag (default rr)
    ///   - `localhost:9001`         -> no tag (remainder `9001` has no `:`)
    ///   - `bogus:127.0.0.1:9001`   -> looks like a tag, isn't known -> error
    pub fn from_spec(name: &str, spec: &str) -> io::Result<Upstream> {
        let err = |m: &str| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("upstream {name:?}: {m}"))
        };

        let (algorithm, server_list) = match spec.split_once(':') {
            Some((lead, rest))
                if !lead.is_empty()
                    && lead.chars().all(|c| c.is_ascii_alphabetic())
                    && rest.contains(':') =>
            {
                // Leading token looks like an algorithm keyword.
                match Algorithm::from_tag(lead) {
                    Some(a) => (a, rest),
                    None => return Err(err(&format!("unknown algorithm {lead:?}"))),
                }
            }
            // No recognizable tag: whole spec is the server list, default rr.
            _ => (Algorithm::RoundRobin, spec),
        };

        let mut servers = Vec::new();
        for token in server_list.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            servers.push(parse_server(token, algorithm, &err)?);
        }
        if servers.is_empty() {
            return Err(err("empty pool (no servers)"));
        }
        Ok(Upstream::build(
            name.to_string(),
            algorithm,
            servers,
            Arc::new(HealthConfig::default()),
        ))
    }

    /// A single-server round-robin pool wrapping one backend address. This is
    /// how a bare `host:port` route target (and the Level 1 catch-all) becomes
    /// an `Upstream`: a one-member pool is genuinely just a degenerate pool, so
    /// the rest of the code has exactly one path.
    pub fn single(addr: &str) -> Upstream {
        Upstream::build(
            addr.to_string(),
            Algorithm::RoundRobin,
            vec![(addr.to_string(), 1)],
            Arc::new(HealthConfig::default()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Build an upstream directly from `(addr, weight)` pairs for tests that
    /// don't exercise the spec parser.
    fn pool(algo: Algorithm, servers: &[(&str, u32)]) -> Upstream {
        let servers = servers.iter().map(|(a, w)| (a.to_string(), *w)).collect();
        Upstream::build("test".to_string(), algo, servers, hc())
    }

    fn hc() -> Arc<HealthConfig> {
        Arc::new(HealthConfig {
            fail_threshold: 3,
            success_threshold: 2,
            backoff_base: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            interval: Duration::from_secs(2),
            timeout: Duration::from_secs(1),
            path: "/health".to_string(),
        })
    }

    const ANY: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

    // 1. Round robin cycles 0,1,2,0.
    #[test]
    fn round_robin_cycles() {
        let up = pool(Algorithm::RoundRobin, &[("a:1", 1), ("b:1", 1), ("c:1", 1)]);
        let seq: Vec<_> = (0..4).map(|_| up.select(ANY).unwrap()).collect();
        assert_eq!(seq, vec![0, 1, 2, 0]);
    }

    // 2. Weighted RR honors a 5:1 ratio.
    #[test]
    fn weighted_round_robin_ratio() {
        let up = pool(Algorithm::WeightedRoundRobin, &[("a:1", 5), ("b:1", 1)]);
        let mut counts = [0usize; 2];
        for _ in 0..100 {
            counts[up.select(ANY).unwrap()] += 1;
        }
        // ~5:1. Assert the heavy server dominates within a wide band rather
        // than an exact number (the tail of 100/6 rounds unevenly).
        assert!(counts[0] > counts[1] * 4, "counts={counts:?}");
        assert!(counts[0] < counts[1] * 6, "counts={counts:?}");
    }

    // 3. Random touches every server; none starved.
    #[test]
    fn random_touches_all() {
        let up = pool(Algorithm::Random, &[("a:1", 1), ("b:1", 1), ("c:1", 1)]);
        let mut seen = [false; 3];
        for _ in 0..300 {
            seen[up.select(ANY).unwrap()] = true;
        }
        assert!(seen.iter().all(|&s| s), "some server never picked: {seen:?}");
    }

    // 4. Least-connections picks the idle server while leases are held.
    #[test]
    fn least_conn_picks_idle() {
        let up = pool(Algorithm::LeastConnections, &[("a:1", 1), ("b:1", 1), ("c:1", 1)]);
        // Pin two requests on server 0 and one on server 1; server 2 is idle.
        let _l0a = Lease::new(&up.servers[0]);
        let _l0b = Lease::new(&up.servers[0]);
        let _l1 = Lease::new(&up.servers[1]);
        assert_eq!(up.select(ANY), Some(2));
    }

    // 5. Least-connections rebalances after leases drop.
    #[test]
    fn least_conn_rebalances_after_drop() {
        let up = pool(Algorithm::LeastConnections, &[("a:1", 1), ("b:1", 1)]);
        {
            let _held = Lease::new(&up.servers[0]);
            assert_eq!(up.select(ANY), Some(1)); // 0 is busy
        }
        // Lease dropped: both idle again, tie -> lower index.
        assert_eq!(up.select(ANY), Some(0));
    }

    // 6. Lease decrements on drop AND on early return mid-scope — the leak this
    //    whole design exists to prevent.
    #[test]
    fn lease_releases_on_every_path() {
        let up = pool(Algorithm::LeastConnections, &[("a:1", 1)]);

        // Normal scoped drop.
        {
            let l = up.pick(ANY).unwrap();
            assert_eq!(l.inflight(), 1);
        }
        assert_eq!(up.servers[0].inflight(), 0);

        // Early return via `?`: the lease is created, then a function bails out
        // before doing anything else. Drop still fires on the way out.
        fn bails(up: &Upstream) -> Result<(), ()> {
            let _lease = up.pick(ANY).ok_or(())?;
            Err(()) // early return with the lease still in scope
        }
        let _ = bails(&up);
        assert_eq!(up.servers[0].inflight(), 0, "lease leaked on early return");
    }

    // 7. Least-response-time prefers the lower EWMA; untried servers sort first.
    #[test]
    fn least_response_time_prefers_faster_and_untried() {
        let up = pool(Algorithm::LeastResponseTime, &[("a:1", 1), ("b:1", 1), ("c:1", 1)]);
        // Give 0 a slow history and 1 a fast one; 2 stays untried.
        up.servers[0].record_rtt(Duration::from_millis(50));
        up.servers[1].record_rtt(Duration::from_millis(5));
        // Untried (2) wins: a fresh server must get traffic, not be starved.
        assert_eq!(up.select(ANY), Some(2));

        // With every server tried, the fastest (1) wins.
        up.servers[2].record_rtt(Duration::from_millis(20));
        assert_eq!(up.select(ANY), Some(1));
    }

    // 8. IP hash is stable for one IP across repeated picks.
    #[test]
    fn ip_hash_stable() {
        let up = pool(Algorithm::IpHash, &[("a:1", 1), ("b:1", 1), ("c:1", 1)]);
        let client = ip(203, 0, 113, 7);
        let first = up.select(client).unwrap();
        for _ in 0..50 {
            assert_eq!(up.select(client), Some(first));
        }
    }

    // 9. IP hash spreads a range of IPs across all servers.
    #[test]
    fn ip_hash_spreads() {
        let up = pool(Algorithm::IpHash, &[("a:1", 1), ("b:1", 1), ("c:1", 1)]);
        let mut seen = [false; 3];
        for i in 0..255u8 {
            seen[up.select(ip(10, 0, 0, i)).unwrap()] = true;
        }
        assert!(seen.iter().all(|&s| s), "IP hash left a server unused: {seen:?}");
    }

    // 10. Consistent hash is stable for one key.
    #[test]
    fn consistent_hash_stable() {
        let up = pool(Algorithm::ConsistentHash, &[("a:1", 1), ("b:1", 1), ("c:1", 1)]);
        let client = ip(198, 51, 100, 23);
        let first = up.select(client).unwrap();
        for _ in 0..50 {
            assert_eq!(up.select(client), Some(first));
        }
    }

    // 11. The headline comparison: under a 4 -> 3 server change, consistent
    //     hashing keeps most keys put while plain IP hash reshuffles nearly
    //     everything. Asserting BOTH bounds is the point — the contrast is the
    //     lesson, and a one-sided assertion would pass even if the ring were
    //     secretly behaving like modulo.
    #[test]
    fn consistent_hash_beats_modulo_under_removal() {
        const KEYS: u32 = 10_000;
        let four = [("s0:1", 1), ("s1:1", 1), ("s2:1", 1), ("s3:1", 1)];
        let three = [("s0:1", 1), ("s1:1", 1), ("s2:1", 1)]; // dropped s3

        let retained = |algo: Algorithm| -> f64 {
            let before = pool(algo, &four);
            let after = pool(algo, &three);
            let mut kept = 0u32;
            for i in 0..KEYS {
                // Scatter sequential keys across the whole address space with a
                // multiplicative (Knuth) permutation. Real clients don't all
                // live in `0.0.0.x`; without this the raw `i` values share their
                // high bytes, FNV-1a maps them into a razor-thin arc of the
                // ring, and the test would measure that arc's luck rather than
                // the ring's redistribution property.
                let client = IpAddr::V4(Ipv4Addr::from(i.wrapping_mul(2_654_435_761)));
                let b = before.servers[before.select(client).unwrap()].addr();
                let a = after.servers[after.select(client).unwrap()].addr();
                if a == b {
                    kept += 1;
                }
            }
            kept as f64 / KEYS as f64
        };

        let chash = retained(Algorithm::ConsistentHash);
        let iphash = retained(Algorithm::IpHash);
        // Theory: consistent hashing moves only ~1/4 of keys (~75% retained);
        // 70% leaves headroom for vnode imbalance.
        assert!(chash >= 0.70, "consistent hash retained only {chash:.3}");
        // Modulo remaps almost everything when n changes.
        assert!(iphash < 0.40, "ip hash retained {iphash:.3} — too stable to be modulo");
    }

    // 12. Spec parser: all 7 tags, default tag, weights, whitespace.
    #[test]
    fn spec_parser_shapes() {
        assert_eq!(
            Upstream::from_spec("x", "127.0.0.1:9001").unwrap().algorithm,
            Algorithm::RoundRobin // no tag -> default
        );
        assert_eq!(
            Upstream::from_spec("x", "localhost:9001").unwrap().algorithm,
            Algorithm::RoundRobin // alpha host, but remainder has no ':' -> not a tag
        );
        for (tag, algo) in [
            ("rr", Algorithm::RoundRobin),
            ("wrr", Algorithm::WeightedRoundRobin),
            ("rand", Algorithm::Random),
            ("lc", Algorithm::LeastConnections),
            ("lrt", Algorithm::LeastResponseTime),
            ("iphash", Algorithm::IpHash),
            ("chash", Algorithm::ConsistentHash),
        ] {
            let spec = format!("{tag}:127.0.0.1:9001,127.0.0.1:9002");
            let up = Upstream::from_spec("x", &spec).unwrap();
            assert_eq!(up.algorithm, algo, "tag {tag}");
            assert_eq!(up.servers.len(), 2);
        }
        // Weight expansion + surrounding whitespace tolerated.
        let up = Upstream::from_spec("x", "wrr: 10.0.0.1:80*3 , 10.0.0.2:80*1 ").unwrap();
        assert_eq!(up.wrr_index.len(), 4); // 3 + 1
        // Hostnames (not just IPs) accepted for chash.
        let up = Upstream::from_spec("x", "chash:node1:6379,node2:6379").unwrap();
        assert_eq!(up.servers.len(), 2);
        assert_eq!(up.ring.len(), 2 * VNODES_PER_SERVER);
    }

    // 13. Spec parser errors: empty pool, bad address, unknown algo, zero weight.
    #[test]
    fn spec_parser_errors() {
        assert!(Upstream::from_spec("x", "").is_err()); // empty pool
        assert!(Upstream::from_spec("x", "rr:").is_err()); // tag but no servers
        assert!(Upstream::from_spec("x", "127.0.0.1").is_err()); // no port
        assert!(Upstream::from_spec("x", "host:0").is_err()); // port 0
        assert!(Upstream::from_spec("x", "bogus:127.0.0.1:9001").is_err()); // unknown algo
        assert!(Upstream::from_spec("x", "wrr:127.0.0.1:9001*0").is_err()); // zero weight
    }

    // Weight on a non-weighted algorithm is accepted (warns on stderr), not an
    // error — a harmless misconfiguration must not block startup.
    #[test]
    fn weight_on_non_weighted_is_accepted() {
        let up = Upstream::from_spec("x", "rr:127.0.0.1:9001*5,127.0.0.1:9002").unwrap();
        assert_eq!(up.servers.len(), 2);
        assert!(up.wrr_index.is_empty()); // weight ignored, no expansion
    }

    // `single` builds a working 1-server RR pool (the backward-compat path).
    #[test]
    fn single_server_pool() {
        let up = Upstream::single("127.0.0.1:9000");
        assert_eq!(up.select(ANY), Some(0));
        assert_eq!(up.servers[0].addr(), "127.0.0.1:9000");
    }

    // 1. Below the threshold, the breaker stays Closed and keeps serving.
    #[test]
    fn breaker_tolerates_failures_below_threshold() {
        let b = Breaker::new(hc());
        let t0 = Instant::now();
        b.record_failure(t0);
        b.record_failure(t0);
        assert!(b.allows_traffic());
        assert_eq!(b.state(), BreakerState::Closed);
    }

    // 2. Hitting the threshold trips the breaker Open and stops traffic.
    #[test]
    fn breaker_trips_open_at_threshold() {
        let b = Breaker::new(hc());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(t0);
        }
        assert_eq!(b.state(), BreakerState::Open);
        assert!(!b.allows_traffic());
    }

    // 3. Failures must be CONSECUTIVE: a success resets the run.
    #[test]
    fn breaker_success_resets_failure_run() {
        let b = Breaker::new(hc());
        let t0 = Instant::now();
        b.record_failure(t0);
        b.record_failure(t0);
        b.record_success(t0); // clears the run
        b.record_failure(t0);
        b.record_failure(t0);
        assert_eq!(b.state(), BreakerState::Closed, "2 failures after reset must not trip");
    }

    // 4. Open blocks probes until the cooldown elapses, then admits exactly one trial.
    #[test]
    fn breaker_open_admits_one_half_open_trial_after_cooldown() {
        let b = Breaker::new(hc());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(t0);
        }
        // Still cooling down: no probe.
        assert!(b.probe_due(t0).is_none());
        assert!(b.probe_due(t0 + Duration::from_millis(999)).is_none());
        // Cooldown elapsed: one trial admitted, and it moves to HalfOpen.
        let after = t0 + Duration::from_secs(1);
        assert!(matches!(b.probe_due(after), Some(ProbeAction::HalfOpenTrial)));
        assert_eq!(b.state(), BreakerState::HalfOpen);
        // A trial is already outstanding: no second probe.
        assert!(b.probe_due(after).is_none());
        // Clients are still blocked while we only *suspect* recovery.
        assert!(!b.allows_traffic());
    }

    // 5. Enough successes in HalfOpen closes the breaker and resets backoff.
    #[test]
    fn breaker_recovers_after_success_threshold() {
        let b = Breaker::new(hc());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(t0);
        }
        let t1 = t0 + Duration::from_secs(1);
        b.probe_due(t1); // -> HalfOpen
        b.record_success(t1);
        assert_eq!(b.state(), BreakerState::HalfOpen, "one success is not enough");
        b.record_success(t1);
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(b.allows_traffic());
        assert_eq!(b.cooldown(), Duration::from_secs(1), "backoff reset on recovery");
    }

    // 6. A failed trial re-opens the breaker and DOUBLES the cooldown.
    #[test]
    fn breaker_failed_trial_doubles_backoff() {
        let b = Breaker::new(hc());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(t0);
        }
        assert_eq!(b.cooldown(), Duration::from_secs(1));
        let t1 = t0 + Duration::from_secs(1);
        b.probe_due(t1); // -> HalfOpen
        b.record_failure(t1); // trial failed
        assert_eq!(b.state(), BreakerState::Open);
        assert_eq!(b.cooldown(), Duration::from_secs(2), "backoff must double");
    }

    // 7. Backoff doubles across repeated failed trials and caps at backoff_max.
    #[test]
    fn breaker_backoff_caps_at_max() {
        let b = Breaker::new(hc());
        let mut t = Instant::now();
        for _ in 0..3 {
            b.record_failure(t);
        }
        // Each failed trial doubles: 1,2,4,8,16,30(cap),30...
        for _ in 0..8 {
            t += b.cooldown();
            b.probe_due(t);
            b.record_failure(t);
        }
        assert_eq!(b.cooldown(), Duration::from_secs(30), "must cap, not grow unbounded");
    }

    // 8. Recovery resets backoff so a later trip starts from base again.
    #[test]
    fn breaker_backoff_resets_after_recovery() {
        let b = Breaker::new(hc());
        let mut t = Instant::now();
        for _ in 0..3 {
            b.record_failure(t);
        }
        t += Duration::from_secs(1);
        b.probe_due(t);
        b.record_failure(t); // backoff -> 2s
        t += Duration::from_secs(2);
        b.probe_due(t);
        b.record_success(t);
        b.record_success(t); // recovered
        assert_eq!(b.cooldown(), Duration::from_secs(1));
        // Trip again: cooldown starts from base, not from 2s.
        for _ in 0..3 {
            b.record_failure(t);
        }
        assert_eq!(b.cooldown(), Duration::from_secs(1));
    }

    // available() is now breaker-derived, but defaults to serving.
    #[test]
    fn server_available_follows_breaker() {
        let up = pool(Algorithm::RoundRobin, &[("a:1", 1)]);
        let s = &up.servers_slice()[0];
        assert!(s.available(), "a fresh server must serve traffic");
        let t0 = Instant::now();
        for _ in 0..3 {
            s.record_failure(t0);
        }
        assert!(!s.available(), "a tripped server must be excluded from selection");
    }

    // The passive feed: a lease marked failed reports into the breaker on drop.
    #[test]
    fn lease_failure_feeds_breaker() {
        let up = pool(Algorithm::RoundRobin, &[("a:1", 1)]);
        let s = &up.servers_slice()[0];
        for _ in 0..3 {
            let mut l = up.pick(ANY).unwrap();
            l.mark_failure();
        } // each drop reports one failure
        assert!(!s.available(), "3 failed requests must trip the breaker");
    }

    // A marked-success lease clears a partial failure run.
    #[test]
    fn lease_success_feeds_breaker() {
        let up = pool(Algorithm::RoundRobin, &[("a:1", 1)]);
        let s = &up.servers_slice()[0];
        {
            let mut l = up.pick(ANY).unwrap();
            l.mark_failure();
        }
        {
            let mut l = up.pick(ANY).unwrap();
            l.mark_failure();
        }
        {
            let mut l = up.pick(ANY).unwrap();
            l.mark_success(); // resets the run
        }
        {
            let mut l = up.pick(ANY).unwrap();
            l.mark_failure();
        }
        assert!(s.available(), "run was reset, so this must not trip");
    }

    // An unmarked lease is NEUTRAL: a cancelled task must not be scored.
    #[test]
    fn unmarked_lease_does_not_touch_breaker() {
        let up = pool(Algorithm::RoundRobin, &[("a:1", 1)]);
        let s = &up.servers_slice()[0];
        for _ in 0..10 {
            let _l = up.pick(ANY).unwrap(); // no mark_* call
        }
        assert!(s.available(), "unjudged requests must not trip the breaker");
        assert_eq!(s.inflight(), 0, "inflight must still be released");
    }
}
