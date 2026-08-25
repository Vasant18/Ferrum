//! Level 10: the metrics registry — counters, gauges, histograms, and the
//! Prometheus text exposition format, all from scratch.
//!
//! # Why this file exists (the 3 a.m. argument)
//!
//! The access log answers "what happened to request X". Metrics answer the
//! other question: "what is happening to *all* requests, right now, and how
//! does that compare to an hour ago" — without grepping a gigabyte of log.
//! Logs are events; metrics are aggregates. You need both because you cannot
//! afford to store every event forever, and you cannot reconstruct a
//! percentile from a counter.
//!
//! # The three instrument types, and why there is no fourth
//!
//! - **Counter**: a monotonically increasing `u64`. Only ever goes up (resets
//!   to zero on restart — Prometheus detects the reset by seeing the value
//!   drop). `requests_total` is the canonical one. Rates are *derived* at
//!   query time (`rate(requests_total[5m])`), never recorded — recording a
//!   rate would bake in a window size forever.
//! - **Gauge**: a value that goes both ways. `active_connections`. The only
//!   instrument allowed to decrease.
//! - **Histogram**: pre-declared buckets, each counting observations `<=` its
//!   bound. Percentiles are computed at query time from bucket counts. The
//!   alternative — storing raw samples — costs memory per request; buckets
//!   cost a fixed 9 atomics per series *total*. That trade is the whole
//!   reason Prometheus histograms look the way they do.
//!
//! # The Level 7 rule applied to ourselves
//!
//! Instrumentation runs on every request, on the hot path, concurrently on
//! all 8 worker threads. So the same discipline as the connection pool:
//! **no mutex, no allocation at record time**. Every instrument is an
//! `AtomicU64`/`AtomicI64` and every label set is resolved to a pre-built
//! slot at startup (upstreams are declared on the CLI and never change —
//! Level 12's hot reload will have to revisit this, and that is recorded
//! here as a known seam, not discovered later as a surprise).
//!
//! `Ordering::Relaxed` everywhere: metric increments have no happens-before
//! relationship to protect. Two threads bumping `requests_total`
//! concurrently must not lose an increment (RMW atomics guarantee that even
//! relaxed), but nobody's *read* of one counter orders anything else. A
//! scrape may observe counter A's increment before counter B's from the same
//! request — Prometheus tolerates that skew by design; every scrape is
//! already a torn snapshot of a moving system.
//!
//! # Label cardinality, or: why `code="2xx"` and not `code="200"`
//!
//! Every distinct label combination is its own series — its own atomics here,
//! its own time series in Prometheus. Labels multiply. Status *class* (5
//! values) × upstream (declared, few) is bounded and useful. Raw status code
//! (dozens) × path (unbounded, attacker-controlled!) is a cardinality bomb —
//! a `curl /$(uuidgen)` loop would allocate series forever. The rule: labels
//! come from *our* config, never from the request. Paths belong in the log.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

/// Histogram bucket upper bounds, in seconds. Chosen to bracket the latencies
/// a local reverse proxy actually sees: sub-millisecond pool hits up through
/// multi-second backend hangs (Level 7's `BACKEND_RESPONSE_TIMEOUT` is 10 s,
/// so anything past 5 s lands in `+Inf` and is de facto "timed out or nearly").
/// Fixed at compile time: buckets are part of the *schema* — changing them
/// mid-flight would make cumulative counts incomparable across scrapes.
pub const BUCKET_BOUNDS: [f64; 8] = [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0];

/// One histogram series: 8 finite buckets + implicit `+Inf`, a running sum,
/// and a count. `sum` is stored in **microseconds as an integer** because
/// there is no atomic f64 add — and a proxy that needs sub-microsecond
/// latency precision in its *metrics* has mistaken itself for a benchmark.
pub struct Histogram {
    /// `buckets[i]` counts observations `<= BUCKET_BOUNDS[i]`. NOT cumulative
    /// in storage — each observation increments exactly ONE bucket (the first
    /// that fits). The cumulative `le` semantics Prometheus requires are
    /// computed at scrape time in `render()`: scrapes happen every ~15 s,
    /// observations happen thousands of times a second. Do the O(buckets)
    /// work on the rare path.
    buckets: [AtomicU64; 8],
    /// Observations larger than every finite bound.
    inf: AtomicU64,
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn new() -> Self {
        Histogram {
            buckets: Default::default(),
            inf: AtomicU64::new(0),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record one observation. A linear scan over 8 comparisons and 3 atomic
    /// adds — no branch is worth optimizing past this, and a binary search
    /// over 8 elements would be slower than the scan it replaces.
    pub fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        match BUCKET_BOUNDS.iter().position(|&b| secs <= b) {
            Some(i) => self.buckets[i].fetch_add(1, Ordering::Relaxed),
            None => self.inf.fetch_add(1, Ordering::Relaxed),
        };
        self.sum_micros
            .fetch_add(d.as_micros() as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot for rendering: cumulative bucket counts (Prometheus `le`
    /// semantics), sum in seconds, total count.
    fn snapshot(&self) -> ([u64; 9], f64, u64) {
        let mut cumulative = [0u64; 9];
        let mut running = 0u64;
        for (i, b) in self.buckets.iter().enumerate() {
            running += b.load(Ordering::Relaxed);
            cumulative[i] = running;
        }
        cumulative[8] = running + self.inf.load(Ordering::Relaxed);
        let sum = self.sum_micros.load(Ordering::Relaxed) as f64 / 1e6;
        // `+Inf` cumulative == count, by construction from the same atomics —
        // but load `count` separately anyway: under concurrent observes the
        // two can disagree by an in-flight observation, and Prometheus
        // requires `le="+Inf"` == `_count`, so we render the bucket walk's
        // number for both and use `count` only where exactness doesn't matter.
        let count = cumulative[8];
        (cumulative, sum, count)
    }
}

/// Per-upstream slot: everything labeled `upstream="NAME"`. Built once at
/// startup; a `Vec<UpstreamSlot>` plus linear name lookup. Linear because a
/// deployment has a handful of upstreams and a `HashMap` buys nothing but a
/// hash per lookup — and lookups themselves happen once per request, with the
/// resolved index reusable from then on.
struct UpstreamSlot {
    name: String,
    /// `requests_total{upstream,code}` by status class: index 0 = 1xx … 4 = 5xx.
    by_class: [AtomicU64; 5],
    connect_errors: AtomicU64,
    duration: Histogram,
}

/// Rejections are labeled by the middleware that issued them. The set of
/// middleware names is fixed in `middleware/mod.rs` (the chain order is a
/// compile-time decision), so these slots are static too. `other` catches a
/// future middleware whose author forgets to extend this list — visible in
/// the metrics rather than silently dropped.
const REJECTORS: [&str; 5] = ["ratelimit", "auth", "authz", "request-id", "other"];

/// The registry. One per process, built in `main`, shared as `Arc<Metrics>`
/// exactly like `Arc<RouteTable>` — same lifetime, same sharing story, and
/// like the route table it is *read-shaped* after startup: the structure is
/// immutable, only the atomic values inside move.
pub struct Metrics {
    upstreams: Vec<UpstreamSlot>,
    /// Requests that never reached an upstream (rejections, 404s): the
    /// `upstream="-"` series. Kept out of `upstreams` so a config with an
    /// upstream literally named "-" can't collide (the router forbids it
    /// anyway, but the type shouldn't depend on the router's manners).
    unrouted: UpstreamSlot,
    rejected: [AtomicU64; 5],
    active_connections: AtomicI64,
    /// Duration across every request regardless of upstream — the series a
    /// dashboard's headline panel reads, and the one that stays comparable
    /// when upstreams are added or renamed.
    duration_all: Histogram,
}

/// A resolved upstream label: an index into the registry, not a string.
/// `proxy.rs` resolves once per request and then records through this —
/// the string comparison happens exactly once, not once per instrument.
#[derive(Clone, Copy)]
pub struct UpstreamId(Option<usize>);

impl Metrics {
    pub fn new(upstream_names: &[String]) -> Self {
        let slot = |name: &str| UpstreamSlot {
            name: name.to_string(),
            by_class: Default::default(),
            connect_errors: AtomicU64::new(0),
            duration: Histogram::new(),
        };
        Metrics {
            upstreams: upstream_names.iter().map(|n| slot(n)).collect(),
            unrouted: slot("-"),
            rejected: Default::default(),
            active_connections: AtomicI64::new(0),
            duration_all: Histogram::new(),
        }
    }

    /// Resolve an upstream name to a slot index. Called once per request in
    /// `serve_one`, after routing picks the upstream.
    pub fn upstream_id(&self, name: &str) -> UpstreamId {
        UpstreamId(self.upstreams.iter().position(|s| s.name == name))
    }

    /// The `upstream="-"` id for requests that never routed.
    pub fn unrouted_id(&self) -> UpstreamId {
        UpstreamId(None)
    }

    fn slot(&self, id: UpstreamId) -> &UpstreamSlot {
        match id.0 {
            Some(i) => &self.upstreams[i],
            None => &self.unrouted,
        }
    }

    /// Record a completed exchange: status + duration, one call site in
    /// `serve_one`. Status class indexing: 100–599 map to slots 0–4; anything
    /// outside that range is a bug upstream of here, clamped rather than
    /// panicking because metrics must never take the process down.
    pub fn record_request(&self, id: UpstreamId, status: u16, dur: Duration) {
        let class = (status / 100).clamp(1, 5) as usize - 1;
        self.slot(id).by_class[class].fetch_add(1, Ordering::Relaxed);
        self.slot(id).duration.observe(dur);
        self.duration_all.observe(dur);
    }

    pub fn record_connect_error(&self, id: UpstreamId) {
        self.slot(id).connect_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a middleware rejection by name. The name comparison is against
    /// a 5-element static array — cheaper than the log line the rejection
    /// also emits, so not worth pre-resolving like `UpstreamId`.
    pub fn record_rejection(&self, by: &str) {
        let i = REJECTORS.iter().position(|&r| r == by).unwrap_or(4);
        self.rejected[i].fetch_add(1, Ordering::Relaxed);
    }

    /// Connection accounting. Paired inc/dec — the caller keeps them matched
    /// by tying the dec to a guard's `Drop`, the same RAII discipline as
    /// Level 8's `ConnLimiter` slot (and for the same reason: early returns).
    pub fn conn_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }
    pub fn conn_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn active_connections(&self) -> i64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Render the whole registry in the Prometheus text exposition format.
    ///
    /// The format, reverse-engineered to its rules (this is the lesson —
    /// it's just lines):
    ///   - `# HELP name description` then `# TYPE name counter|gauge|histogram`
    ///   - one `name{label="v",...} value` line per series
    ///   - histograms explode into `_bucket{le="BOUND"}` lines (cumulative!),
    ///     plus `_sum` and `_count`; `le="+Inf"` must equal `_count`
    ///   - floats render plainly; label values need `\` `"` `\n` escaped —
    ///     ours are config-sourced names, escaped anyway on principle
    ///
    /// Built into a `String` at scrape time. Allocation is fine HERE: scrapes
    /// are ~1/15 s from one collector, not thousands/s from every client.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);

        out.push_str("# HELP ferrum_requests_total Completed exchanges by upstream and status class.\n");
        out.push_str("# TYPE ferrum_requests_total counter\n");
        for s in self.upstreams.iter().chain(std::iter::once(&self.unrouted)) {
            for (i, c) in s.by_class.iter().enumerate() {
                let v = c.load(Ordering::Relaxed);
                // Elide never-incremented series: a scrape full of zeros for
                // 5 classes × N upstreams is noise, and Prometheus treats an
                // absent series and a zero series the same for rate().
                if v > 0 {
                    out.push_str(&format!(
                        "ferrum_requests_total{{upstream=\"{}\",code=\"{}xx\"}} {}\n",
                        escape_label(&s.name),
                        i + 1,
                        v
                    ));
                }
            }
        }

        out.push_str("# HELP ferrum_connect_errors_total Backend connect failures (post-retry, per attempt).\n");
        out.push_str("# TYPE ferrum_connect_errors_total counter\n");
        for s in self.upstreams.iter().chain(std::iter::once(&self.unrouted)) {
            let v = s.connect_errors.load(Ordering::Relaxed);
            if v > 0 {
                out.push_str(&format!(
                    "ferrum_connect_errors_total{{upstream=\"{}\"}} {}\n",
                    escape_label(&s.name),
                    v
                ));
            }
        }

        out.push_str("# HELP ferrum_rejected_total Requests rejected by middleware, by rejector.\n");
        out.push_str("# TYPE ferrum_rejected_total counter\n");
        for (i, r) in self.rejected.iter().enumerate() {
            let v = r.load(Ordering::Relaxed);
            if v > 0 {
                out.push_str(&format!(
                    "ferrum_rejected_total{{by=\"{}\"}} {}\n",
                    REJECTORS[i], v
                ));
            }
        }

        out.push_str("# HELP ferrum_active_connections Client connections currently open.\n");
        out.push_str("# TYPE ferrum_active_connections gauge\n");
        out.push_str(&format!(
            "ferrum_active_connections {}\n",
            self.active_connections.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP ferrum_request_duration_seconds Full exchange duration, client-side.\n");
        out.push_str("# TYPE ferrum_request_duration_seconds histogram\n");
        render_histogram(&mut out, "all", &self.duration_all);
        for s in &self.upstreams {
            render_histogram(&mut out, &s.name, &s.duration);
        }

        out
    }
}

/// RAII guard for the `active_connections` gauge: inc on construction, dec on
/// `Drop`. The same discipline as Level 8's `ConnLimiter` slot and Level 3's
/// `Lease`, for the same reason: a connection task has many exit paths (clean
/// close, I/O error, failed TLS handshake, panic) and a manual `conn_closed()`
/// call would eventually miss one, leaving the gauge drifting upward forever —
/// the classic gauge-leak bug this type makes unrepresentable.
pub struct ConnGauge<'a> {
    metrics: &'a Metrics,
}

impl<'a> ConnGauge<'a> {
    pub fn open(metrics: &'a Metrics) -> ConnGauge<'a> {
        metrics.conn_opened();
        ConnGauge { metrics }
    }
}

impl Drop for ConnGauge<'_> {
    fn drop(&mut self) {
        self.metrics.conn_closed();
    }
}

fn render_histogram(out: &mut String, upstream: &str, h: &Histogram) {
    let (cumulative, sum, count) = h.snapshot();
    let up = escape_label(upstream);
    for (i, bound) in BUCKET_BOUNDS.iter().enumerate() {
        out.push_str(&format!(
            "ferrum_request_duration_seconds_bucket{{upstream=\"{up}\",le=\"{bound}\"}} {}\n",
            cumulative[i]
        ));
    }
    out.push_str(&format!(
        "ferrum_request_duration_seconds_bucket{{upstream=\"{up}\",le=\"+Inf\"}} {}\n",
        cumulative[8]
    ));
    out.push_str(&format!(
        "ferrum_request_duration_seconds_sum{{upstream=\"{up}\"}} {sum}\n"
    ));
    out.push_str(&format!(
        "ferrum_request_duration_seconds_count{{upstream=\"{up}\"}} {count}\n"
    ));
}

/// Prometheus label-value escaping: backslash, double quote, newline. Label
/// values here come from CLI config, not requests — escaped anyway, because
/// "the router validates names" is a fact about today's router.
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m() -> Metrics {
        Metrics::new(&["api".to_string(), "static".to_string()])
    }

    #[test]
    fn upstream_id_resolves_declared_names() {
        let m = m();
        assert!(m.upstream_id("api").0.is_some());
        assert!(m.upstream_id("static").0.is_some());
        assert!(m.upstream_id("nope").0.is_none()); // falls to unrouted
    }

    #[test]
    fn counter_lands_in_status_class() {
        let m = m();
        let id = m.upstream_id("api");
        m.record_request(id, 200, Duration::from_millis(3));
        m.record_request(id, 204, Duration::from_millis(3));
        m.record_request(id, 502, Duration::from_millis(3));
        let text = m.render();
        assert!(text.contains(r#"ferrum_requests_total{upstream="api",code="2xx"} 2"#));
        assert!(text.contains(r#"ferrum_requests_total{upstream="api",code="5xx"} 1"#));
        // Never-touched series are elided, not rendered as zero.
        assert!(!text.contains(r#"upstream="api",code="3xx""#));
        assert!(!text.contains(r#"upstream="static",code="2xx""#));
    }

    #[test]
    fn out_of_range_status_is_clamped_not_panicking() {
        let m = m();
        m.record_request(m.unrouted_id(), 0, Duration::ZERO);
        m.record_request(m.unrouted_id(), 999, Duration::ZERO);
        let text = m.render();
        assert!(text.contains(r#"ferrum_requests_total{upstream="-",code="1xx"} 1"#));
        assert!(text.contains(r#"ferrum_requests_total{upstream="-",code="5xx"} 1"#));
    }

    #[test]
    fn histogram_buckets_observations_at_boundaries() {
        let h = Histogram::new();
        h.observe(Duration::from_millis(1)); // == 0.001 → first bucket (le is <=)
        h.observe(Duration::from_micros(1001)); // just over → second bucket
        h.observe(Duration::from_secs(10)); // beyond all bounds → +Inf
        let (cum, sum, count) = h.snapshot();
        assert_eq!(cum[0], 1); // <= 0.001
        assert_eq!(cum[1], 2); // <= 0.005 cumulative
        assert_eq!(cum[7], 2); // <= 5.0 still 2
        assert_eq!(cum[8], 3); // +Inf catches the 10 s
        assert_eq!(count, 3);
        assert!((sum - 10.002002).abs() < 1e-6);
    }

    #[test]
    fn histogram_render_is_cumulative_and_inf_equals_count() {
        let m = m();
        let id = m.upstream_id("api");
        m.record_request(id, 200, Duration::from_millis(2)); // ≤0.005
        m.record_request(id, 200, Duration::from_millis(80)); // ≤0.1
        let text = m.render();
        assert!(text.contains(r#"_bucket{upstream="api",le="0.001"} 0"#));
        assert!(text.contains(r#"_bucket{upstream="api",le="0.005"} 1"#));
        assert!(text.contains(r#"_bucket{upstream="api",le="0.1"} 2"#));
        assert!(text.contains(r#"_bucket{upstream="api",le="+Inf"} 2"#));
        assert!(text.contains(r#"_count{upstream="api"} 2"#));
    }

    #[test]
    fn gauge_moves_both_ways() {
        let m = m();
        m.conn_opened();
        m.conn_opened();
        m.conn_closed();
        assert_eq!(m.active_connections(), 1);
        assert!(m.render().contains("ferrum_active_connections 1\n"));
    }

    #[test]
    fn rejections_label_by_middleware_with_other_fallback() {
        let m = m();
        m.record_rejection("auth");
        m.record_rejection("auth");
        m.record_rejection("some-future-middleware");
        let text = m.render();
        assert!(text.contains(r#"ferrum_rejected_total{by="auth"} 2"#));
        assert!(text.contains(r#"ferrum_rejected_total{by="other"} 1"#));
    }

    #[test]
    fn label_escaping() {
        assert_eq!(escape_label(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(escape_label("x\ny"), r#"x\ny"#);
    }

    #[test]
    fn concurrent_increments_lose_nothing() {
        // The claim "Relaxed RMW never loses an increment" is load-bearing for
        // every counter in this file — test it the same way L6 tested the
        // sharded rate limiter: hammer from threads, assert the exact total.
        let m = std::sync::Arc::new(m());
        let id = m.upstream_id("api");
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = m.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..10_000 {
                    m.record_request(id, 200, Duration::from_millis(1));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert!(m
            .render()
            .contains(r#"ferrum_requests_total{upstream="api",code="2xx"} 80000"#));
    }
}
