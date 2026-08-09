//! Rate limiting via the token-bucket algorithm.
//!
//! A bucket holds up to `burst` tokens and refills at `rate` tokens/second;
//! each request spends one or gets a 429. This allows short bursts while
//! capping the sustained rate — unlike a fixed window, which lets `2N`
//! requests through back-to-back across a window boundary.
//!
//! # Two decisions worth reading the comments for
//!
//! - **`std::sync::Mutex`, sharded.** The critical section is a few float ops
//!   with no `.await` inside, so a `tokio::sync::Mutex` would buy a scheduler
//!   interaction for nothing. And one global lock would serialize every
//!   request in the proxy on a single mutex — the exact bottleneck to shard
//!   away. Sixteen shards keyed by `hash(ip)` means concurrent clients usually
//!   hit different locks.
//! - **Lazy refill, no timer.** Tokens are recomputed from elapsed time on
//!   access; there is no background refill task and no sweeper. A bucket nobody
//!   touches costs nothing.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::{Decision, Middleware, ReqCtx, Rejection};
use crate::http::RequestHead;

const SHARDS: usize = 16;

/// Per-shard entry cap. Past this, we evict full+idle buckets before inserting
/// a new one — an attacker cycling source IPs must not grow the map without
/// bound. A full bucket carries no rate-limiting information (it would admit a
/// fresh request anyway), so dropping it is free.
const SHARD_CAP: usize = 4096;

/// A bucket counts as evictable if it is full AND has not been touched for this
/// long. Generous, because eviction only fires under the cap.
const IDLE_EVICT_SECS: f64 = 60.0;

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct Limiter {
    rate: f64,
    burst: f64,
    shards: Vec<Mutex<HashMap<IpAddr, Bucket>>>,
}

impl Limiter {
    pub fn new(rate: f64, burst: f64) -> Self {
        let mut shards = Vec::with_capacity(SHARDS);
        for _ in 0..SHARDS {
            shards.push(Mutex::new(HashMap::new()));
        }
        Limiter { rate, burst, shards }
    }

    fn shard_for(&self, ip: IpAddr) -> &Mutex<HashMap<IpAddr, Bucket>> {
        let mut h = DefaultHasher::new();
        ip.hash(&mut h);
        &self.shards[(h.finish() as usize) % SHARDS]
    }

    /// Try to spend one token for `ip` at time `now`. `Ok(())` if a token was
    /// available; `Err(retry_after_secs)` if the bucket was empty.
    ///
    /// `now` is a parameter, not `Instant::now()` — that is what lets tests
    /// exercise refill by advancing a synthetic clock instead of sleeping.
    pub fn allow(&self, ip: IpAddr, now: Instant) -> Result<(), u64> {
        let mut map = self.shard_for(ip).lock().unwrap();

        if !map.contains_key(&ip) && map.len() >= SHARD_CAP {
            // At capacity and this is a new key: try to reclaim space.
            map.retain(|_, b| {
                let idle = now.saturating_duration_since(b.last_refill).as_secs_f64();
                let full = b.tokens >= self.burst;
                !(full && idle >= IDLE_EVICT_SECS)
            });
            if map.len() >= SHARD_CAP {
                // Nothing reclaimable. Fail OPEN: admit the request rather than
                // let an internal capacity limit become an outage. The
                // alternative — rejecting real traffic because the table is
                // full — turns memory pressure into a client-visible failure.
                return Ok(());
            }
        }

        let bucket = map.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last_refill: now,
        });

        // Lazy refill: credit the tokens that accrued since we last looked,
        // capped at burst.
        let elapsed = now.saturating_duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            // Seconds until one whole token accrues, at least 1 so a client
            // never gets `Retry-After: 0`.
            let deficit = 1.0 - bucket.tokens;
            let secs = (deficit / self.rate).ceil() as u64;
            Err(secs.max(1))
        }
    }
}

/// Middleware wrapper: keys the limiter on the socket-observed peer IP.
pub struct RateLimit {
    limiter: Arc<Limiter>,
}

impl RateLimit {
    pub fn new(limiter: Arc<Limiter>) -> Self {
        RateLimit { limiter }
    }
}

impl Middleware for RateLimit {
    fn name(&self) -> &'static str {
        "ratelimit"
    }

    fn on_request(&self, _req: &mut RequestHead, ctx: &mut ReqCtx) -> Decision {
        // Key on `ctx.peer.ip()`, the address we observed on the socket —
        // never `X-Forwarded-For`. XFF is client-controlled: keying on it would
        // let an attacker send a random value per request for unlimited
        // throughput AND poison the bucket of any real IP they chose to name.
        // Level 5 took the same stance for X-Real-IP (overwrite, never trust).
        match self.limiter.allow(ctx.peer.ip(), Instant::now()) {
            Ok(()) => Decision::Continue,
            Err(retry) => Decision::Reject(Rejection {
                status: 429,
                reason: "Too Many Requests",
                headers: vec![("Retry-After".to_string(), retry.to_string())],
                body: "429 Too Many Requests\n".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn burst_allows_exactly_n_then_rejects() {
        let lim = Limiter::new(1.0, 3.0); // 1/s, burst 3
        let now = Instant::now();
        assert!(lim.allow(ip("10.0.0.1"), now).is_ok());
        assert!(lim.allow(ip("10.0.0.1"), now).is_ok());
        assert!(lim.allow(ip("10.0.0.1"), now).is_ok());
        assert!(lim.allow(ip("10.0.0.1"), now).is_err()); // 4th within same instant
    }

    #[test]
    fn refill_after_time_advance() {
        let lim = Limiter::new(2.0, 2.0); // 2/s, burst 2
        let t0 = Instant::now();
        assert!(lim.allow(ip("10.0.0.2"), t0).is_ok());
        assert!(lim.allow(ip("10.0.0.2"), t0).is_ok());
        assert!(lim.allow(ip("10.0.0.2"), t0).is_err());
        // One second later at 2/s => 2 more tokens, capped at burst=2.
        let t1 = t0 + Duration::from_secs(1);
        assert!(lim.allow(ip("10.0.0.2"), t1).is_ok());
        assert!(lim.allow(ip("10.0.0.2"), t1).is_ok());
        assert!(lim.allow(ip("10.0.0.2"), t1).is_err());
    }

    #[test]
    fn retry_after_is_at_least_one() {
        let lim = Limiter::new(1.0, 1.0);
        let now = Instant::now();
        assert!(lim.allow(ip("10.0.0.3"), now).is_ok());
        match lim.allow(ip("10.0.0.3"), now) {
            Err(secs) => assert!(secs >= 1),
            Ok(()) => panic!("should be rejected"),
        }
    }

    #[test]
    fn distinct_ips_have_independent_buckets() {
        let lim = Limiter::new(1.0, 1.0);
        let now = Instant::now();
        assert!(lim.allow(ip("10.0.0.4"), now).is_ok());
        assert!(lim.allow(ip("10.0.0.4"), now).is_err());
        assert!(lim.allow(ip("10.0.0.5"), now).is_ok());
    }

    #[test]
    fn ipv4_and_ipv6_coexist() {
        let lim = Limiter::new(1.0, 1.0);
        let now = Instant::now();
        assert!(lim.allow(ip("10.0.0.6"), now).is_ok());
        assert!(lim.allow(ip("::1"), now).is_ok());
    }

    #[test]
    fn shard_cap_does_not_panic_and_active_ip_works() {
        let lim = Limiter::new(1000.0, 1000.0);
        let base = Instant::now();
        // Drive far more distinct IPs than one shard can hold; they end full
        // (one request each against burst 1000), so they become evictable.
        for i in 0..(SHARD_CAP * 2) {
            let a = ip(&format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255));
            let _ = lim.allow(a, base);
        }
        // Long after, an active IP still succeeds (eviction or fail-open — both
        // acceptable; what matters is liveness).
        let later = base + Duration::from_secs(3600);
        assert!(lim.allow(ip("172.16.0.1"), later).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_allow_no_panic() {
        let lim = Arc::new(Limiter::new(100.0, 100.0));
        let mut handles = vec![];
        for _ in 0..8 {
            let l = lim.clone();
            handles.push(tokio::spawn(async move {
                let now = Instant::now();
                for _ in 0..1000 {
                    let _ = l.allow(ip("192.168.1.1"), now);
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        // Liveness is the assertion: no deadlock, no panic under contention.
    }
}
