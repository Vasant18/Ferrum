# Level 3 — Load Balancing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace each route's single backend address with a named pool of servers, and choose one server per request using any of seven balancing algorithms.

**Architecture:** A new `balancer.rs` module owns `Upstream` (a pool: algorithm + servers + shared cursor/ring state) and `Lease` (an RAII guard that releases in-flight counts on `Drop`). `router.rs` keeps only match logic; `Route.backend: String` becomes `Route.upstream: Arc<Upstream>`. `proxy.rs::serve_one` gains one step between routing and connecting: `upstream.pick(peer.ip())`.

**Tech Stack:** Rust 2024 edition, Tokio 1.53 (`full` features), `regex` 1.13. **No new dependencies** — the PRNG and hasher are written by hand (see Global Constraints).

## Global Constraints

- **No new crate dependencies.** `Cargo.toml` must be unchanged by this level. Random uses a hand-written xorshift; hashing uses a hand-written FNV-1a.
- **All 36 existing tests must stay green** after every task. The only permitted edits to existing tests are mechanical adjustments to `RouteTable::find()`'s return type in `router.rs` tests.
- **Teaching mode:** "I implement, you learn." Every non-obvious decision gets a comment explaining *why*, matching the density already in `router.rs` and `proxy.rs`. Module-level `//!` docs explain the subsystem before the code.
- **Rust edition 2024**, `cargo test` is the only test runner. No benchmarks this level.
- **`Server::available() -> bool` returns hardcoded `true`** with a comment naming Level 4 as its owner. Do not implement liveness.
- **No retry-on-failure.** A dead server is picked and yields `502`. Level 4 owns retries.
- **FNV-1a offset basis** `0xcbf29ce484222325`, **prime** `0x100000001b3`. Use these exact constants; consistent-hash rings must be reproducible across runs.
- **160 virtual nodes per server** on the consistent-hash ring.
- **EWMA alpha = 0.2**, stored as `AtomicU64` microseconds.
- Existing log-line format is `[{peer}] {method} {target} {version} -> {backend}`; it becomes `... -> {pool}[{algo}] {addr} (inflight={n})`.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `rproxy/src/balancer.rs` | `Algorithm`, `Server`, `Upstream`, `Lease`, FNV-1a, xorshift, spec parser. All balancing logic and its tests. | **Create** |
| `rproxy/src/router.rs` | Match logic only. `Route` holds `Arc<Upstream>`; `find()` returns it. | Modify |
| `rproxy/src/main.rs` | Parse `--upstream` flags, build the upstream registry, resolve route targets against it. | Modify |
| `rproxy/src/proxy.rs` | One new step in `serve_one`: `pick()` → `Lease`, connect to `lease.addr()`. | Modify |
| `rproxy/PROGRESS.md` | Level 3 tracker row + "what was built" section + session log. | Modify |

`balancer.rs` lands at roughly 550–650 lines including tests, comparable to the existing `proxy.rs` (569) and `http.rs` (509) — consistent with the codebase's existing file sizing.

---

## Task 1: Balancer skeleton with Round Robin

**Files:**
- Create: `rproxy/src/balancer.rs`
- Modify: `rproxy/src/main.rs` (add `mod balancer;`)
- Test: inline `#[cfg(test)] mod tests` in `rproxy/src/balancer.rs`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `pub enum Algorithm { RoundRobin, WeightedRoundRobin, Random, LeastConnections, LeastResponseTime, IpHash, ConsistentHash }`
  - `Algorithm::as_tag(&self) -> &'static str`
  - `pub struct Server { pub addr: String, pub weight: u32, inflight: AtomicUsize, ewma_micros: AtomicU64 }`
  - `Server::new(addr: String, weight: u32) -> Server`
  - `Server::available(&self) -> bool`
  - `Server::inflight(&self) -> usize`
  - `pub struct Upstream { pub name: String, pub algorithm: Algorithm, servers: Vec<Server>, rr_cursor: AtomicUsize, wrr_slots: Vec<usize>, ring: Vec<(u64, usize)> }`
  - `Upstream::new(name: String, algorithm: Algorithm, servers: Vec<Server>) -> Upstream`
  - `Upstream::pick(&self, client_ip: IpAddr) -> Option<Lease<'_>>`
  - `Upstream::describe(&self) -> String`
  - `pub struct Lease<'a>` with `Lease::addr(&self) -> &'a str`, `Lease::inflight(&self) -> usize`

- [ ] **Step 1: Write the failing test**

Create `rproxy/src/balancer.rs` containing only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn pool(algo: Algorithm, addrs: &[&str]) -> Upstream {
        let servers = addrs.iter().map(|a| Server::new(a.to_string(), 1)).collect();
        Upstream::new("test".to_string(), algo, servers)
    }

    #[test]
    fn round_robin_cycles_in_order() {
        let up = pool(Algorithm::RoundRobin, &["a:1", "b:2", "c:3"]);
        let picked: Vec<String> = (0..4)
            .map(|_| up.pick(ip()).unwrap().addr().to_string())
            .collect();
        assert_eq!(picked, vec!["a:1", "b:2", "c:3", "a:1"]);
    }

    #[test]
    fn lease_increments_then_releases_inflight() {
        let up = pool(Algorithm::RoundRobin, &["a:1"]);
        {
            let lease = up.pick(ip()).unwrap();
            assert_eq!(lease.inflight(), 1, "in-flight counted while lease is held");
        }
        // Lease dropped at end of scope: the counter must return to zero.
        let lease = up.pick(ip()).unwrap();
        assert_eq!(lease.inflight(), 1, "previous lease released on drop");
    }

    #[test]
    fn empty_pool_picks_nothing() {
        let up = pool(Algorithm::RoundRobin, &[]);
        assert!(up.pick(ip()).is_none());
    }
}
```

Add `mod balancer;` to `rproxy/src/main.rs` immediately after `mod http;` (alphabetical order is already broken there — `http, proxy, router` — so insert to keep it alphabetical: `balancer, http, proxy, router`).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rproxy && cargo test balancer`
Expected: FAIL — compile errors, `cannot find type Algorithm in this scope` / `Server` / `Upstream` not found.

- [ ] **Step 3: Write minimal implementation**

Prepend to `rproxy/src/balancer.rs`, above the test module:

```rust
//! Level 3 — load balancing.
//!
//! Routing (Level 2) answers "which pool of servers should serve this
//! request?". Balancing answers the next question: "which server *in* that
//! pool?". Splitting them matters because one pool is usually shared by
//! several routes, and the balancing state — how many requests are in flight
//! on each server — has to be shared across all of them to be correct.
//!
//! An `Upstream` is created once at startup and read concurrently by every
//! connection task through an `Arc`. It is never mutated through `&mut self`;
//! instead the few mutable counters use atomics (interior mutability), so
//! `pick()` takes `&self` and needs no lock. That is the whole reason this
//! module leans on `AtomicUsize` rather than `Mutex`: picking a server sits
//! directly in the request hot path, and a single mutex there would serialize
//! every request the proxy handles.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

/// Which strategy an upstream uses to choose among its servers.
///
/// The seven algorithms fall into three families, and the family explains the
/// implementation more than the individual name does:
///
/// * *Stateless* (RoundRobin, WeightedRoundRobin, Random) — the choice
///   ignores how loaded the servers actually are. Cheap and predictable.
/// * *Load-aware* (LeastConnections, LeastResponseTime) — the choice reads
///   live per-server measurements, so it adapts to slow or busy servers.
/// * *Hash-based* (IpHash, ConsistentHash) — the choice is a pure function of
///   the client, so the same client keeps landing on the same server
///   (session affinity).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algorithm {
    RoundRobin,
    WeightedRoundRobin,
    Random,
    LeastConnections,
    LeastResponseTime,
    IpHash,
    ConsistentHash,
}

impl Algorithm {
    /// The short tag used in CLI specs and log lines.
    pub fn as_tag(&self) -> &'static str {
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
}

/// One backend server in a pool, plus the live measurements the load-aware
/// algorithms read.
///
/// `inflight` and `ewma_micros` are atomics rather than plain integers because
/// this struct is shared immutably (`&Server`) across every connection task.
/// Atomics give us mutation through a shared reference without a lock.
pub struct Server {
    pub addr: String,
    /// Relative share of traffic for WeightedRoundRobin. Ignored elsewhere.
    pub weight: u32,
    /// Requests currently being served by this server. Incremented when a
    /// `Lease` is handed out, decremented when that lease is dropped.
    inflight: AtomicUsize,
    /// Exponentially-weighted moving average of observed round-trip time, in
    /// microseconds. `u64::MAX` is the sentinel for "no samples yet".
    ewma_micros: AtomicU64,
}

/// Sentinel meaning "this server has never completed a request", so
/// LeastResponseTime can tell "fast" apart from "untried".
const NO_SAMPLE: u64 = u64::MAX;

impl Server {
    pub fn new(addr: String, weight: u32) -> Self {
        Server {
            addr,
            weight,
            inflight: AtomicUsize::new(0),
            ewma_micros: AtomicU64::new(NO_SAMPLE),
        }
    }

    /// Whether this server may receive traffic.
    ///
    /// Hardcoded `true` for Level 3: nothing yet marks a server down, so a
    /// dead server is still picked and the request still fails with 502.
    /// Level 4 (health checks) makes this read a real liveness flag — every
    /// `pick()` already calls it, so that change needs no new call sites.
    pub fn available(&self) -> bool {
        true
    }

    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Relaxed)
    }
}

/// A pool of interchangeable servers plus the strategy for choosing among
/// them. Built once at startup, then read-only apart from its atomics.
pub struct Upstream {
    pub name: String,
    pub algorithm: Algorithm,
    servers: Vec<Server>,
    /// Rotating cursor for RoundRobin and WeightedRoundRobin.
    rr_cursor: AtomicUsize,
    /// WeightedRoundRobin: server indices repeated `weight` times, so plain
    /// round-robin over this vector produces the weighted distribution.
    /// Empty for every other algorithm.
    wrr_slots: Vec<usize>,
    /// ConsistentHash: `(hash, server_index)` pairs sorted by hash — the
    /// "ring". Empty for every other algorithm.
    ring: Vec<(u64, usize)>,
}

impl Upstream {
    pub fn new(name: String, algorithm: Algorithm, servers: Vec<Server>) -> Self {
        Upstream {
            name,
            algorithm,
            servers,
            rr_cursor: AtomicUsize::new(0),
            wrr_slots: Vec::new(),
            ring: Vec::new(),
        }
    }

    /// Choose a server for one request and return a `Lease` representing it.
    ///
    /// Returns `None` only when the pool has no usable server. Startup
    /// validation rejects empty pools, so the caller treats `None` as a
    /// defensive 502 rather than an expected outcome.
    pub fn pick(&self, _client_ip: IpAddr) -> Option<Lease<'_>> {
        if self.servers.is_empty() {
            return None;
        }
        let index = match self.algorithm {
            // fetch_add returns the *previous* value and wraps on overflow,
            // which is exactly the rotation we want. `Relaxed` is the right
            // ordering here: we need a distinct-ish number, not a
            // synchronization edge with other memory.
            _ => self.rr_cursor.fetch_add(1, Ordering::Relaxed) % self.servers.len(),
        };
        Some(Lease::new(&self.servers[index]))
    }

    /// Human-readable summary for the startup banner.
    pub fn describe(&self) -> String {
        let servers: Vec<String> = self
            .servers
            .iter()
            .map(|s| {
                if self.algorithm == Algorithm::WeightedRoundRobin {
                    format!("{}*{}", s.addr, s.weight)
                } else {
                    s.addr.clone()
                }
            })
            .collect();
        format!("{}[{}] {}", self.name, self.algorithm.as_tag(), servers.join(","))
    }
}

/// An RAII claim on one server for the duration of one request.
///
/// This type exists because releasing the in-flight count is easy to get
/// wrong. `serve_one` has a dozen `?` early-returns and can be cancelled
/// mid-body; an explicit `release()` call would be skipped on most of those
/// paths, and every skipped decrement permanently biases LeastConnections
/// against a perfectly healthy server. Putting the decrement in `Drop` makes
/// it run on *every* exit path — success, error, and cancellation alike.
pub struct Lease<'a> {
    server: &'a Server,
    started: Instant,
}

impl<'a> Lease<'a> {
    fn new(server: &'a Server) -> Self {
        server.inflight.fetch_add(1, Ordering::Relaxed);
        Lease { server, started: Instant::now() }
    }

    /// The backend address to connect to. Borrowed from the `Server` rather
    /// than copied into the lease, so there is one source of truth.
    pub fn addr(&self) -> &'a str {
        &self.server.addr
    }

    /// In-flight count for the chosen server, including this lease. Used for
    /// the per-request log line and by tests.
    pub fn inflight(&self) -> usize {
        self.server.inflight()
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.server.inflight.fetch_sub(1, Ordering::Relaxed);

        // Fold this request's duration into the server's EWMA so
        // LeastResponseTime has something to compare. A fresh server has no
        // sample, so the first observation becomes the average outright.
        let sample = self.started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        let prev = self.server.ewma_micros.load(Ordering::Relaxed);
        let next = if prev == NO_SAMPLE {
            sample
        } else {
            // alpha = 0.2, in integer arithmetic: (4*prev + 1*sample) / 5.
            (prev.saturating_mul(4).saturating_add(sample)) / 5
        };
        self.server.ewma_micros.store(next, Ordering::Relaxed);
    }
}
```

Note the deliberately odd `match self.algorithm { _ => ... }` in `pick()` — it is a one-armed match that Task 4/5/6 fill in with real arms. Keep it as a `match` from the start so later tasks add arms rather than restructuring.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test`
Expected: PASS — 39 tests (36 existing + 3 new). Warnings about unused `wrr_slots`/`ring`/`ewma_micros` reads are expected at this stage and are resolved by Tasks 4–6.

- [ ] **Step 5: Commit**

```bash
git add rproxy/src/balancer.rs rproxy/src/main.rs
git commit -m "Add balancer skeleton with round-robin and RAII leases

Introduces Upstream (a pool of servers plus a strategy) and Lease, an
RAII guard that decrements the in-flight count in Drop. Drop rather than
an explicit release() call, because serve_one has many early-return paths
and any missed decrement would permanently bias least-connections."
```

---

## Task 2: Upstream spec parser and validation

**Files:**
- Modify: `rproxy/src/balancer.rs` (add parser + tests)

**Interfaces:**
- Consumes: `Algorithm`, `Server`, `Upstream::new` (Task 1).
- Produces:
  - `pub fn parse_upstream(spec: &str) -> io::Result<Upstream>` — parses `NAME=algo:server[*weight][,...]`
  - `pub fn parse_algorithm(tag: &str) -> Option<Algorithm>`

- [ ] **Step 1: Write the failing test**

Append to the `tests` module in `rproxy/src/balancer.rs`:

```rust
#[test]
fn parses_all_algorithm_tags() {
    for (tag, expected) in [
        ("rr", Algorithm::RoundRobin),
        ("wrr", Algorithm::WeightedRoundRobin),
        ("rand", Algorithm::Random),
        ("lc", Algorithm::LeastConnections),
        ("lrt", Algorithm::LeastResponseTime),
        ("iphash", Algorithm::IpHash),
        ("chash", Algorithm::ConsistentHash),
    ] {
        let up = parse_upstream(&format!("p={tag}:a:1,b:2")).unwrap();
        assert_eq!(up.algorithm, expected, "tag {tag}");
    }
}

#[test]
fn algorithm_tag_defaults_to_round_robin() {
    // No "algo:" prefix at all — bare server list.
    let up = parse_upstream("p=127.0.0.1:9001,127.0.0.1:9002").unwrap();
    assert_eq!(up.algorithm, Algorithm::RoundRobin);
    assert_eq!(up.name, "p");
    assert_eq!(up.server_addrs(), vec!["127.0.0.1:9001", "127.0.0.1:9002"]);
}

#[test]
fn parses_weights() {
    let up = parse_upstream("p=wrr:a:1*5,b:2*1").unwrap();
    assert_eq!(up.weights(), vec![5, 1]);
    // Unweighted servers default to weight 1.
    let up = parse_upstream("p=wrr:a:1,b:2*3").unwrap();
    assert_eq!(up.weights(), vec![1, 3]);
}

#[test]
fn tolerates_whitespace_around_servers() {
    let up = parse_upstream("p=rr: a:1 , b:2 ").unwrap();
    assert_eq!(up.server_addrs(), vec!["a:1", "b:2"]);
}

#[test]
fn parse_upstream_errors() {
    // Missing '=' between name and spec.
    assert!(parse_upstream("noequals").is_err());
    // Empty name.
    assert!(parse_upstream("=rr:a:1").is_err());
    // Empty server list.
    assert!(parse_upstream("p=rr:").is_err());
    assert!(parse_upstream("p=").is_err());
    // Unknown algorithm tag.
    assert!(parse_upstream("p=bogus:a:1").is_err());
    // Zero weight can never be picked — certainly a typo.
    assert!(parse_upstream("p=wrr:a:1*0").is_err());
    // Non-numeric weight.
    assert!(parse_upstream("p=wrr:a:1*x").is_err());
    // Server address without a port.
    assert!(parse_upstream("p=rr:noport").is_err());
}
```

Also add these two test-support accessors to `impl Upstream` in the non-test code (they are genuinely useful for the startup banner and tests both, so they are not test-only cruft):

```rust
    /// Addresses of every server, in declaration order.
    pub fn server_addrs(&self) -> Vec<&str> {
        self.servers.iter().map(|s| s.addr.as_str()).collect()
    }

    /// Weights of every server, in declaration order.
    pub fn weights(&self) -> Vec<u32> {
        self.servers.iter().map(|s| s.weight).collect()
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rproxy && cargo test balancer`
Expected: FAIL — `cannot find function parse_upstream in this scope`.

- [ ] **Step 3: Write minimal implementation**

Add `use std::io;` to the imports at the top of `balancer.rs`, then append this above the test module:

```rust
/// Map a CLI algorithm tag to its `Algorithm`.
pub fn parse_algorithm(tag: &str) -> Option<Algorithm> {
    match tag {
        "rr" => Some(Algorithm::RoundRobin),
        "wrr" => Some(Algorithm::WeightedRoundRobin),
        "rand" => Some(Algorithm::Random),
        "lc" => Some(Algorithm::LeastConnections),
        "lrt" => Some(Algorithm::LeastResponseTime),
        "iphash" => Some(Algorithm::IpHash),
        "chash" => Some(Algorithm::ConsistentHash),
        _ => None,
    }
}

/// Parse one `--upstream` value of the form:
///   `NAME=algo:server[*weight][,server[*weight]...]`
/// The `algo:` prefix is optional and defaults to `rr`.
///
/// Examples:
///   `api=lc:127.0.0.1:9001,127.0.0.1:9002`
///   `web=wrr:10.0.0.1:80*5,10.0.0.2:80*1`
///   `plain=127.0.0.1:9000`                  (defaults to rr)
pub fn parse_upstream(spec: &str) -> io::Result<Upstream> {
    let err = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("{m}: {spec:?}"));

    let (name, rest) = spec
        .split_once('=')
        .ok_or_else(|| err("upstream spec missing '=SERVERS'"))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(err("empty upstream name"));
    }

    // Split an optional "algo:" prefix from the server list. The ambiguity to
    // resolve: server addresses contain ':' too ("127.0.0.1:9001"). We only
    // treat text before the first ':' as an algorithm tag if it actually names
    // one — otherwise the whole string is a server list with the default algo.
    let (algorithm, server_list) = match rest.split_once(':') {
        Some((tag, tail)) => match parse_algorithm(tag.trim()) {
            Some(a) => (a, tail),
            // Not a known tag. If it looks like it was *meant* as a tag (no
            // '.' and no digits, so plainly not a hostname:port), reject it
            // rather than silently reading "bogus:a" as a server address.
            None if !tag.contains('.') && !tag.chars().any(|c| c.is_ascii_digit()) => {
                return Err(err(&format!("unknown algorithm tag {:?}", tag.trim())));
            }
            None => (Algorithm::RoundRobin, rest),
        },
        None => (Algorithm::RoundRobin, rest),
    };

    let mut servers = Vec::new();
    for entry in server_list.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // Optional "*weight" suffix.
        let (addr, weight) = match entry.rsplit_once('*') {
            Some((a, w)) => {
                let weight: u32 = w
                    .trim()
                    .parse()
                    .map_err(|_| err(&format!("invalid weight {w:?}")))?;
                if weight == 0 {
                    return Err(err("weight must be at least 1 (a 0-weight server is never picked)"));
                }
                (a.trim(), weight)
            }
            None => (entry, 1),
        };
        // A server address must carry a port: we connect straight to it, and
        // guessing 80 would hide a config typo behind a confusing 502.
        let port_ok = match addr.rsplit_once(':') {
            Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok(),
            None => false,
        };
        if !port_ok {
            return Err(err(&format!("server {addr:?} must be host:port")));
        }
        servers.push(Server::new(addr.to_string(), weight));
    }

    if servers.is_empty() {
        return Err(err("upstream has no servers"));
    }

    // A weight on a non-weighted algorithm is a no-op, not a failure: warn so
    // the mistake is visible, but never refuse to start over a harmless typo.
    if algorithm != Algorithm::WeightedRoundRobin && servers.iter().any(|s| s.weight != 1) {
        eprintln!(
            "warning: upstream {name:?} uses {} but sets weights; weights only apply to wrr",
            algorithm.as_tag()
        );
    }

    Ok(Upstream::new(name.to_string(), algorithm, servers))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test`
Expected: PASS — 44 tests (36 existing + 8 balancer).

- [ ] **Step 5: Commit**

```bash
git add rproxy/src/balancer.rs
git commit -m "Add upstream spec parser with startup validation

Parses NAME=algo:server[*weight],... with rr as the default algorithm.
Rejects empty pools, portless addresses, and zero weights at startup;
warns rather than fails when weights are set on a non-weighted algorithm."
```

---

## Task 3: Wire upstreams through router, main, and proxy

This is the integration task: after it, the proxy balances across a pool end-to-end using round-robin, and all 36 pre-existing tests still pass.

**Files:**
- Modify: `rproxy/src/router.rs` (`Route.backend` → `Route.upstream`; `find()` return type; tests)
- Modify: `rproxy/src/main.rs` (`--upstream` flag parsing, registry, route resolution)
- Modify: `rproxy/src/proxy.rs:322-368` (pick a lease, connect to it, extend the log line)

**Interfaces:**
- Consumes: `Upstream`, `Lease`, `parse_upstream` (Tasks 1–2).
- Produces:
  - `Route.upstream: Arc<Upstream>` (field replaces `backend: String`)
  - `router::parse_route(spec: &str, upstreams: &HashMap<String, Arc<Upstream>>) -> io::Result<Route>` — **note the new second parameter**
  - `RouteTable::find(...) -> Option<&Arc<Upstream>>`
  - `Route::catch_all(backend: &str) -> Route` (unchanged signature; wraps internally)

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `rproxy/src/router.rs`. First, the existing test helper must change, since `parse_route` now needs an upstream registry:

```rust
    fn table(specs: &[&str]) -> RouteTable {
        let upstreams = HashMap::new();
        RouteTable::new(
            specs.iter().map(|s| parse_route(s, &upstreams).unwrap()).collect(),
        )
    }
```

Every existing assertion of the form `assert_eq!(t.find(...), Some("B_EXACT"))` becomes:

```rust
        assert_eq!(t.find("GET", None, "/api/health").map(|u| u.name.as_str()), Some("B_EXACT"));
```

because `find` now yields an `Arc<Upstream>` whose auto-wrapped name is the address. Apply that mechanical change to all 8 existing `find`-based tests. Then add these new tests:

```rust
    #[test]
    fn bare_host_port_target_auto_wraps_as_single_server_pool() {
        let t = table(&["/=127.0.0.1:9000"]);
        let up = t.find("GET", None, "/x").unwrap();
        assert_eq!(up.server_addrs(), vec!["127.0.0.1:9000"]);
        assert_eq!(up.algorithm, Algorithm::RoundRobin);
    }

    #[test]
    fn named_upstream_target_binds_to_declared_pool() {
        let mut upstreams = HashMap::new();
        let pool = Arc::new(crate::balancer::parse_upstream("api=rr:a:1,b:2").unwrap());
        upstreams.insert("api".to_string(), Arc::clone(&pool));

        let route = parse_route("/api/**=api", &upstreams).unwrap();
        assert_eq!(route.upstream.server_addrs(), vec!["a:1", "b:2"]);
    }

    #[test]
    fn unknown_upstream_name_is_an_error() {
        let upstreams = HashMap::new();
        // "nope" is neither a declared upstream nor a host:port.
        let e = parse_route("/=nope", &upstreams).unwrap_err();
        assert!(
            e.to_string().contains("unknown upstream"),
            "expected an unknown-upstream error, got: {e}"
        );
    }
```

Add to the top of `router.rs`: `use std::collections::HashMap;`, `use std::sync::Arc;`, and `use crate::balancer::{Algorithm, Server, Upstream};`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rproxy && cargo test`
Expected: FAIL — `parse_route` takes 1 argument but 2 were supplied; `no field upstream on type Route`.

- [ ] **Step 3: Write minimal implementation**

**3a. `router.rs`** — change the `Route` struct and its two methods:

```rust
pub struct Route {
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: PathMatcher,
    /// The pool of servers this route forwards to. `Arc` because one pool is
    /// typically shared by several routes, and its in-flight counters must be
    /// shared with them — a per-route copy would make LeastConnections wrong.
    pub upstream: Arc<Upstream>,
}

impl Route {
    /// A route matching every request, forwarding to one backend.
    pub fn catch_all(backend: &str) -> Self {
        Route {
            host: None,
            method: None,
            path: PathMatcher::Any,
            upstream: Arc::new(single_server_pool(backend)),
        }
    }
    // matches() and specificity() are unchanged.
}

/// Wrap one `host:port` as a 1-server round-robin pool.
///
/// This is what keeps every pre-Level-3 invocation working: a single backend
/// is not a special case in the code, it is simply a pool of one. The pool is
/// named after the address so log lines and `describe()` stay readable.
fn single_server_pool(addr: &str) -> Upstream {
    Upstream::new(
        addr.to_string(),
        Algorithm::RoundRobin,
        vec![Server::new(addr.to_string(), 1)],
    )
}
```

Change `find` to return the pool:

```rust
    pub fn find(&self, method: &str, host: Option<&str>, path: &str) -> Option<&Arc<Upstream>> {
        self.routes
            .iter()
            .filter(|r| r.matches(method, host, path))
            .max_by_key(|r| r.specificity())
            .map(|r| &r.upstream)
    }
```

Change `describe` to render the pool instead of a bare address:

```rust
                format!("{method} {host} {} -> {}", r.path.describe(), r.upstream.describe())
```

Change `parse_route`'s signature and its two construction sites. The signature becomes:

```rust
pub fn parse_route(
    spec: &str,
    upstreams: &HashMap<String, Arc<Upstream>>,
) -> io::Result<Route> {
```

and immediately after the existing `backend.is_empty()` check, resolve the target:

```rust
    // Resolve the route target to a pool. Precedence:
    //   1. a declared --upstream name
    //   2. a bare host:port (auto-wrapped as a 1-server pool)
    //   3. otherwise it is a typo, and failing at startup beats 502s later
    let upstream = resolve_target(backend, upstreams).ok_or_else(|| {
        err(&format!(
            "unknown upstream {backend:?} (not a declared --upstream name, and not host:port)"
        ))
    })?;
```

Then replace both `backend: backend.to_string()` occurrences (the regex early-return and the final `Ok`) with `upstream: Arc::clone(&upstream)` and `upstream` respectively. Add the resolver:

```rust
/// Resolve a route's target: a declared upstream name, else a bare host:port.
fn resolve_target(
    target: &str,
    upstreams: &HashMap<String, Arc<Upstream>>,
) -> Option<Arc<Upstream>> {
    if let Some(up) = upstreams.get(target) {
        return Some(Arc::clone(up));
    }
    // Auto-wrap only if it really is host:port, so a misspelled pool name is
    // reported as such instead of becoming an unconnectable "server".
    match target.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {
            Some(Arc::new(single_server_pool(target)))
        }
        _ => None,
    }
}
```

**3b. `main.rs`** — parse `--upstream` flags before routes:

```rust
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    // Split argv into --upstream declarations and everything else. Upstreams
    // must be collected before routes are parsed, because a route target may
    // reference a pool by name.
    let mut upstream_specs: Vec<String> = Vec::new();
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--upstream" => {
                let value = argv.get(i + 1).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--upstream requires a value: NAME=algo:server,...",
                    )
                })?;
                upstream_specs.push(value.clone());
                i += 2;
            }
            other if other.starts_with("--upstream=") => {
                upstream_specs.push(other["--upstream=".len()..].to_string());
                i += 1;
            }
            other => {
                positional.push(other.to_string());
                i += 1;
            }
        }
    }

    let mut upstreams: HashMap<String, Arc<Upstream>> = HashMap::new();
    for spec in &upstream_specs {
        let up = balancer::parse_upstream(spec)?;
        if upstreams.contains_key(&up.name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("duplicate upstream name {:?}", up.name),
            ));
        }
        upstreams.insert(up.name.clone(), Arc::new(up));
    }

    let mut positional = positional.into_iter();
    let listen_addr = positional.next().unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let route_specs: Vec<String> = positional.collect();

    let routes = Arc::new(build_routes(&route_specs, &upstreams)?);

    let listener = TcpListener::bind(&listen_addr).await?;
    println!("ferrum: listening on {listen_addr}");
    for line in routes.describe() {
        println!("  route: {line}");
    }
    // ... accept loop unchanged ...
```

and `build_routes` gains the registry parameter:

```rust
fn build_routes(
    specs: &[String],
    upstreams: &HashMap<String, Arc<Upstream>>,
) -> std::io::Result<RouteTable> {
    if specs.is_empty() {
        return Ok(RouteTable::new(vec![Route::catch_all("127.0.0.1:9000")]));
    }
    if specs.len() == 1 && !specs[0].contains('=') {
        return Ok(RouteTable::new(vec![Route::catch_all(&specs[0])]));
    }
    let mut routes = Vec::with_capacity(specs.len());
    for spec in specs {
        routes.push(parse_route(spec, upstreams)?);
    }
    Ok(RouteTable::new(routes))
}
```

Add imports to `main.rs`: `use std::collections::HashMap;` and `use balancer::Upstream;`. Update the module doc comment's usage block to document `--upstream`.

**3c. `proxy.rs`** — replace the routing/connect section (currently lines 322–368). The `backend_addr` lookup becomes a pool lookup plus a pick:

```rust
    let upstream = match routes.find(&method, host, path) {
        Some(u) => u,
        None => {
            println!(
                "[{peer}] {} {} {} -> 404 (no route)",
                req.method,
                req.target,
                req.version.as_str()
            );
            respond_error(client, 404, "Not Found").await?;
            return Ok(false);
        }
    };

    // ---- 2b. Balance: choose one server from the matched pool ----
    // The lease must outlive the whole exchange: its Drop is what releases
    // the in-flight count and records this request's latency, so binding it
    // to a variable here (rather than inlining .pick().addr()) is load-
    // bearing, not stylistic.
    let lease = match upstream.pick(peer.ip()) {
        Some(l) => l,
        None => {
            // Startup validation rejects empty pools, so this is unreachable
            // in practice — but a pool with no usable server is a gateway
            // failure, not a client error.
            eprintln!("[{peer}] upstream {} has no usable server", upstream.name);
            respond_error(client, 502, "Bad Gateway").await?;
            return Ok(false);
        }
    };
    let backend_addr = lease.addr();
    println!(
        "[{peer}] {} {} {} -> {}[{}] {backend_addr} (inflight={})",
        req.method,
        req.target,
        req.version.as_str(),
        upstream.name,
        upstream.algorithm.as_tag(),
        lease.inflight(),
    );
```

The existing `TcpStream::connect(&backend_addr)` call still compiles unchanged (`&&str` derefs to `&str`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test`
Expected: PASS — 47 tests (36 existing, adjusted mechanically, + 8 balancer + 3 new router).

Then verify the binary still behaves like Level 2 for old invocations:

```bash
cd rproxy && cargo run -- 127.0.0.1:8080 127.0.0.1:9000 2>&1 | head -3
```
Expected: prints `route: * * any -> 127.0.0.1:9000[rr] 127.0.0.1:9000`. Ctrl-C to stop.

- [ ] **Step 5: Commit**

```bash
git add rproxy/src/router.rs rproxy/src/main.rs rproxy/src/proxy.rs
git commit -m "Route to upstream pools instead of single addresses

Route.backend: String becomes Route.upstream: Arc<Upstream>, and
find() returns the pool. A bare host:port route target auto-wraps as a
one-server pool, so every pre-Level-3 invocation keeps working and a
single backend stops being a special case in the code."
```

---

## Task 4: Stateless algorithms — Random and Weighted Round Robin

**Files:**
- Modify: `rproxy/src/balancer.rs`

**Interfaces:**
- Consumes: `Upstream::pick`, `Upstream::new`, `Algorithm` (Tasks 1–2).
- Produces: `Upstream::new` now populates `wrr_slots`; `pick()` handles `Random` and `WeightedRoundRobin`. No new public names.

- [ ] **Step 1: Write the failing test**

Append to the `tests` module:

```rust
    fn weighted_pool(entries: &[(&str, u32)]) -> Upstream {
        let servers = entries
            .iter()
            .map(|(a, w)| Server::new(a.to_string(), *w))
            .collect();
        Upstream::new("test".to_string(), Algorithm::WeightedRoundRobin, servers)
    }

    #[test]
    fn weighted_round_robin_honors_ratio() {
        let up = weighted_pool(&[("heavy:1", 5), ("light:2", 1)]);
        let mut heavy = 0;
        let mut light = 0;
        for _ in 0..600 {
            match up.pick(ip()).unwrap().addr() {
                "heavy:1" => heavy += 1,
                "light:2" => light += 1,
                other => panic!("unexpected server {other}"),
            }
        }
        // 600 picks over a 5:1 ratio divides evenly: exactly 500/100.
        assert_eq!(heavy, 500);
        assert_eq!(light, 100);
    }

    #[test]
    fn weighted_round_robin_with_equal_weights_is_plain_round_robin() {
        let up = weighted_pool(&[("a:1", 1), ("b:2", 1)]);
        let picked: Vec<String> = (0..4)
            .map(|_| up.pick(ip()).unwrap().addr().to_string())
            .collect();
        assert_eq!(picked, vec!["a:1", "b:2", "a:1", "b:2"]);
    }

    #[test]
    fn random_eventually_uses_every_server() {
        let up = pool(Algorithm::Random, &["a:1", "b:2", "c:3"]);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..300 {
            seen.insert(up.pick(ip()).unwrap().addr().to_string());
        }
        // With 300 draws over 3 servers, missing one has probability
        // 3*(2/3)^300 — vanishingly small, so this is not a flaky assertion.
        assert_eq!(seen.len(), 3, "every server should be picked at least once");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rproxy && cargo test balancer`
Expected: FAIL — `weighted_round_robin_honors_ratio` fails with `assertion left == right` showing 300/300 (the Task-1 catch-all arm ignores weights), and `random_eventually_uses_every_server` passes only by accident of round-robin. Both must be seen failing/passing-for-the-wrong-reason before proceeding.

- [ ] **Step 3: Write minimal implementation**

In `Upstream::new`, replace `wrr_slots: Vec::new()` with a computed expansion:

```rust
    pub fn new(name: String, algorithm: Algorithm, servers: Vec<Server>) -> Self {
        // Weighted round robin, expanded once at startup: a server with
        // weight 5 occupies 5 slots, so plain rotation over the slot vector
        // yields the weighted distribution with an O(1) pick.
        //
        // The trade-off worth knowing: this produces *bursts* — five
        // consecutive requests to the heavy server, then one to the light
        // one. Nginx implements "smooth" WRR, which interleaves them
        // (H,H,L,H,H rather than H,H,H,H,H,L) at the cost of a per-pick
        // credit calculation. Bursts are fine here and the code stays
        // legible; the smoothing algorithm is the interesting follow-up.
        let wrr_slots = if algorithm == Algorithm::WeightedRoundRobin {
            let mut slots = Vec::new();
            for (i, s) in servers.iter().enumerate() {
                for _ in 0..s.weight {
                    slots.push(i);
                }
            }
            slots
        } else {
            Vec::new()
        };

        Upstream {
            name,
            algorithm,
            servers,
            rr_cursor: AtomicUsize::new(0),
            wrr_slots,
            ring: Vec::new(),
        }
    }
```

Add the PRNG above `impl Upstream`:

```rust
// A tiny xorshift64* PRNG, one instance per worker thread.
//
// Written by hand rather than pulling in `rand`, because the whole
// requirement is "give me a hard-to-predict index" and the algorithm is four
// lines. Thread-local rather than shared, so random balancing needs no
// coordinated state at all — no atomic, no lock, no cache-line ping-pong
// between cores.
thread_local! {
    static RNG: std::cell::Cell<u64> = std::cell::Cell::new(seed_for_thread());
}

/// Seed from wall-clock nanos mixed with the thread's identity, so two worker
/// threads starting in the same instant still diverge.
///
/// Note `SystemTime`, not `Instant`: `Instant` has no readable absolute value
/// (by design — it is only meaningful when subtracted from another `Instant`),
/// so `Instant::now().elapsed()` is always ~0 and would contribute nothing.
fn seed_for_thread() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut h = DefaultHasher::new();
    std::thread::current().id().hash(&mut h);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        .hash(&mut h);
    // A zero seed would make xorshift emit zeros forever.
    h.finish() | 1
}

fn next_random() -> u64 {
    RNG.with(|cell| {
        let mut x = cell.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        cell.set(x);
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    })
}
```

Then expand `pick()`'s match, replacing the single catch-all arm:

```rust
        let index = match self.algorithm {
            Algorithm::RoundRobin => {
                self.rr_cursor.fetch_add(1, Ordering::Relaxed) % self.servers.len()
            }
            Algorithm::WeightedRoundRobin => {
                // Rotate over the pre-expanded slot vector, not the server
                // vector. Guard against an empty slots vector so a pool built
                // directly via Upstream::new (bypassing the parser, as tests
                // do) can never divide by zero.
                if self.wrr_slots.is_empty() {
                    self.rr_cursor.fetch_add(1, Ordering::Relaxed) % self.servers.len()
                } else {
                    let slot = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % self.wrr_slots.len();
                    self.wrr_slots[slot]
                }
            }
            Algorithm::Random => (next_random() % self.servers.len() as u64) as usize,
            // Still a catch-all: the load-aware and hash algorithms arrive in
            // Tasks 5 and 6, which replace this arm. Task 6 removes it
            // entirely, making the match exhaustive over all seven variants.
            _ => self.rr_cursor.fetch_add(1, Ordering::Relaxed) % self.servers.len(),
        };
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test`
Expected: PASS — 50 tests.

- [ ] **Step 5: Commit**

```bash
git add rproxy/src/balancer.rs
git commit -m "Add random and weighted round-robin balancing

Weights are expanded into a slot vector once at startup, keeping pick()
O(1) at the cost of bursty distribution; comments contrast this with
Nginx's smooth WRR. Random uses a hand-written thread-local xorshift, so
it needs no shared state at all."
```

---

## Task 5: Load-aware algorithms — Least Connections and Least Response Time

**Files:**
- Modify: `rproxy/src/balancer.rs`

**Interfaces:**
- Consumes: `Server::inflight`, `Server::available`, `Lease`, `NO_SAMPLE` (Tasks 1–4).
- Produces:
  - `Upstream::ewma_for_test(&self, index: usize) -> u64`
  - `Upstream::set_ewma_for_test(&self, index: usize, micros: u64)`
  - `pick()` handles `LeastConnections` and `LeastResponseTime`

- [ ] **Step 1: Write the failing test**

Append to the `tests` module:

```rust
    #[test]
    fn least_connections_prefers_the_idle_server() {
        let up = pool(Algorithm::LeastConnections, &["a:1", "b:2", "c:3"]);
        // Hold leases on the first two servers.
        let held_a = up.pick(ip()).unwrap();
        assert_eq!(held_a.addr(), "a:1", "first pick: all idle, lowest index wins");
        let held_b = up.pick(ip()).unwrap();
        assert_eq!(held_b.addr(), "b:2", "a:1 now busy, so b:2 is the idle one");
        // With a and b each at 1 in-flight, c is the only idle server.
        let held_c = up.pick(ip()).unwrap();
        assert_eq!(held_c.addr(), "c:3");
        drop((held_a, held_b, held_c));
    }

    #[test]
    fn least_connections_rebalances_after_leases_drop() {
        let up = pool(Algorithm::LeastConnections, &["a:1", "b:2"]);
        let held_a = up.pick(ip()).unwrap();
        assert_eq!(held_a.addr(), "a:1");
        drop(held_a);
        // a:1 is idle again, and ties resolve to the lowest index.
        assert_eq!(up.pick(ip()).unwrap().addr(), "a:1");
    }

    #[test]
    fn lease_releases_on_early_return_path() {
        // This is the bug the RAII design exists to prevent: a function that
        // bails out mid-request must still release its in-flight count.
        let up = pool(Algorithm::LeastConnections, &["a:1"]);

        fn bails_out(up: &Upstream, ip: IpAddr) -> Result<(), &'static str> {
            let _lease = up.pick(ip).ok_or("no server")?;
            Err("simulated mid-request failure")
        }

        assert!(bails_out(&up, ip()).is_err());
        let lease = up.pick(ip()).unwrap();
        assert_eq!(
            lease.inflight(),
            1,
            "the abandoned request must not leak an in-flight count"
        );
    }

    #[test]
    fn least_response_time_prefers_the_faster_server() {
        let up = pool(Algorithm::LeastResponseTime, &["slow:1", "fast:2"]);
        // Seed EWMAs directly: slow=50ms, fast=1ms.
        up.set_ewma_for_test(0, 50_000);
        up.set_ewma_for_test(1, 1_000);
        assert_eq!(up.pick(ip()).unwrap().addr(), "fast:2");
    }

    #[test]
    fn least_response_time_tries_unsampled_servers_first() {
        let up = pool(Algorithm::LeastResponseTime, &["known:1", "fresh:2"]);
        // known has a fast sample; fresh has none at all.
        up.set_ewma_for_test(0, 1_000);
        // A server with no measurement must be tried rather than starved —
        // otherwise a new server never receives traffic and never gets a
        // sample, which is a self-fulfilling prophecy.
        assert_eq!(up.pick(ip()).unwrap().addr(), "fresh:2");
    }

    #[test]
    fn lease_drop_records_a_latency_sample() {
        let up = pool(Algorithm::LeastResponseTime, &["a:1"]);
        assert_eq!(up.ewma_for_test(0), u64::MAX, "no samples before any request");
        drop(up.pick(ip()).unwrap());
        assert_ne!(up.ewma_for_test(0), u64::MAX, "dropping a lease records a sample");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rproxy && cargo test balancer`
Expected: FAIL — `no method named set_ewma_for_test found for struct Upstream`, and the least-connections tests fail on the round-robin fallback arm (`assert_eq!(held_b.addr(), "b:2")` would pass by coincidence, but `least_connections_rebalances_after_leases_drop` fails, returning `b:2`).

- [ ] **Step 3: Write minimal implementation**

Add the two test-visible accessors to `impl Upstream`:

```rust
    /// Read one server's EWMA. Exposed for tests and for Level 10's metrics.
    pub fn ewma_for_test(&self, index: usize) -> u64 {
        self.servers[index].ewma_micros.load(Ordering::Relaxed)
    }

    /// Seed one server's EWMA directly, so tests can assert on selection
    /// without having to make requests actually take measurable time.
    pub fn set_ewma_for_test(&self, index: usize, micros: u64) {
        self.servers[index].ewma_micros.store(micros, Ordering::Relaxed);
    }
```

Add the two arms to `pick()`, before the `_ =>` fallback:

```rust
            Algorithm::LeastConnections => {
                // Linear scan of the in-flight counters, lowest wins, ties to
                // the lowest index (which keeps behavior deterministic).
                //
                // The race worth understanding: two tasks can scan
                // concurrently, both see the same idle server, and both pick
                // it — so it briefly gets two requests where a perfect
                // algorithm would have split them. That error is one request
                // deep and self-correcting on the next pick. Eliminating it
                // would require holding a lock across the scan *and* the
                // increment, serializing every request through the proxy.
                // Real proxies make the same trade; the imprecision is
                // cheaper than the contention.
                self.servers
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.available())
                    .min_by_key(|(_, s)| s.inflight())
                    .map(|(i, _)| i)?
            }
            Algorithm::LeastResponseTime => {
                // Same scan shape, ranked by observed latency instead of
                // queue depth. NO_SAMPLE is u64::MAX, which would sort last
                // and starve any new server forever — so we map it to 0 to
                // give untried servers first refusal.
                self.servers
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.available())
                    .min_by_key(|(_, s)| {
                        let ewma = s.ewma_micros.load(Ordering::Relaxed);
                        if ewma == NO_SAMPLE { 0 } else { ewma }
                    })
                    .map(|(i, _)| i)?
            }
```

Both arms use `?` on the `Option`, which is why `pick` returns `Option<Lease>` — if every server is filtered out by `available()` (impossible today, routine after Level 4), we correctly report "no server" instead of panicking on an index.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test`
Expected: PASS — 56 tests.

- [ ] **Step 5: Commit**

```bash
git add rproxy/src/balancer.rs
git commit -m "Add least-connections and least-response-time balancing

Both scan per-server atomics rather than locking, accepting a one-request
race in exchange for no contention in the hot path; the trade-off is
documented at the call site. Untried servers sort first under
least-response-time so a new server is never starved of samples.

Includes a test asserting an abandoned request releases its in-flight
count, which is the leak the RAII lease exists to prevent."
```

---

## Task 6: Hash-based algorithms — IP Hash and Consistent Hashing

**Files:**
- Modify: `rproxy/src/balancer.rs`

**Interfaces:**
- Consumes: `Upstream::new`, `Algorithm`, `Server` (Tasks 1–5).
- Produces: `fn fnv1a(bytes: &[u8]) -> u64`; `Upstream::new` populates `ring`; `pick()` handles `IpHash` and `ConsistentHash`; `VNODES_PER_SERVER` constant.

- [ ] **Step 1: Write the failing test**

Append to the `tests` module:

```rust
    fn ip_n(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn ip_hash_is_stable_for_one_client() {
        let up = pool(Algorithm::IpHash, &["a:1", "b:2", "c:3"]);
        let first = up.pick(ip_n(7)).unwrap().addr().to_string();
        for _ in 0..20 {
            assert_eq!(up.pick(ip_n(7)).unwrap().addr(), first, "same IP must pin");
        }
    }

    #[test]
    fn ip_hash_spreads_across_servers() {
        let up = pool(Algorithm::IpHash, &["a:1", "b:2", "c:3"]);
        let mut seen = std::collections::HashSet::new();
        for last in 1..=60 {
            seen.insert(up.pick(ip_n(last)).unwrap().addr().to_string());
        }
        assert_eq!(seen.len(), 3, "60 distinct IPs should reach all 3 servers");
    }

    #[test]
    fn consistent_hash_is_stable_for_one_client() {
        let up = pool(Algorithm::ConsistentHash, &["a:1", "b:2", "c:3"]);
        let first = up.pick(ip_n(7)).unwrap().addr().to_string();
        for _ in 0..20 {
            assert_eq!(up.pick(ip_n(7)).unwrap().addr(), first);
        }
    }

    #[test]
    fn consistent_hash_survives_server_removal_far_better_than_modulo() {
        // The core lesson of this level, asserted rather than asserted-at.
        //
        // Take 4 servers, map 10k keys, remove one server, and re-map. With
        // plain modulo hashing almost every key moves, because n changed and
        // n is *in the formula*. With a hash ring, only the keys that belonged
        // to the departed server move — about 1/4 of them.
        let addrs4 = ["s1:1", "s2:2", "s3:3", "s4:4"];
        let addrs3 = ["s1:1", "s2:2", "s3:3"];

        let survivors = |algo: Algorithm| -> f64 {
            let before = pool(algo, &addrs4);
            let after = pool(algo, &addrs3);
            let mut kept = 0;
            let mut eligible = 0;
            for k in 0..10_000u32 {
                let octets = k.to_be_bytes();
                let client = IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3]));
                let a = before.pick(client).unwrap().addr().to_string();
                // Keys that lived on the removed server *must* move; they are
                // not part of the "did it stay put" question.
                if a == "s4:4" {
                    continue;
                }
                eligible += 1;
                if after.pick(client).unwrap().addr() == a {
                    kept += 1;
                }
            }
            kept as f64 / eligible as f64
        };

        let ring_kept = survivors(Algorithm::ConsistentHash);
        let modulo_kept = survivors(Algorithm::IpHash);

        assert!(
            ring_kept >= 0.90,
            "consistent hashing should keep >=90% of unaffected keys, kept {ring_kept:.3}"
        );
        assert!(
            modulo_kept < 0.60,
            "modulo hashing should scatter most keys, kept {modulo_kept:.3}"
        );
        assert!(
            ring_kept > modulo_kept + 0.30,
            "ring ({ring_kept:.3}) should dominate modulo ({modulo_kept:.3})"
        );
    }

    #[test]
    fn fnv1a_is_deterministic_and_distinguishes_inputs() {
        assert_eq!(fnv1a(b"10.0.0.1"), fnv1a(b"10.0.0.1"));
        assert_ne!(fnv1a(b"10.0.0.1"), fnv1a(b"10.0.0.2"));
    }
```

Note the thresholds differ from the spec's ≥70%/<40%: those figures counted keys from the removed server as "moved", which dilutes the ratio. This test excludes them (they *must* move), so the ring's expected retention is ~100% and modulo's is ~1/3. The assertions use 90%/60% with the same contrast requirement, which is both stricter and more honest about what is being measured.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rproxy && cargo test balancer`
Expected: FAIL — `cannot find function fnv1a in this scope`, and the stability tests fail because the fallback arm still round-robins.

- [ ] **Step 3: Write minimal implementation**

Add above `impl Upstream`:

```rust
/// Virtual nodes per server on the consistent-hash ring.
///
/// With one ring position per server, the arcs between positions vary wildly
/// and load ends up lopsided. Giving each server many positions averages the
/// arc lengths out; 100–200 is the usual production range.
const VNODES_PER_SERVER: usize = 160;

/// FNV-1a, 64-bit.
///
/// Hand-written rather than using std's DefaultHasher for two reasons. First,
/// the arithmetic is visible: multiply-and-xor per byte, no magic. Second and
/// more importantly, DefaultHasher's output is explicitly *unspecified* across
/// Rust releases — it is allowed to change. Building client affinity on it
/// would mean a toolchain upgrade silently remapping every client to a
/// different server. Affinity needs a hash that is stable forever, so we own
/// it.
fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x1000_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for b in bytes {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}
```

In `Upstream::new`, replace `ring: Vec::new()` with the built ring (place this after the `wrr_slots` computation):

```rust
        // Consistent-hash ring: every server contributes VNODES_PER_SERVER
        // positions, keyed by "addr#n". Sorting once here turns each lookup
        // into a binary search.
        let ring = if algorithm == Algorithm::ConsistentHash {
            let mut ring = Vec::with_capacity(servers.len() * VNODES_PER_SERVER);
            for (i, s) in servers.iter().enumerate() {
                for vnode in 0..VNODES_PER_SERVER {
                    ring.push((fnv1a(format!("{}#{vnode}", s.addr).as_bytes()), i));
                }
            }
            ring.sort_unstable_by_key(|(h, _)| *h);
            ring
        } else {
            Vec::new()
        };
```

and pass `ring` instead of `Vec::new()` in the struct literal.

Add the two arms to `pick()`, replacing the `_ =>` fallback entirely (all seven algorithms are now covered, so the match becomes exhaustive — which is the point of using an enum):

```rust
            Algorithm::IpHash => {
                // The entire algorithm: hash the client, modulo the server
                // count. Cheap, stateless, and gives affinity for free.
                //
                // The catch is that `n` is *in the formula*. Add or remove one
                // server and almost every client remaps — for a session
                // cache that means a near-total cache miss storm. Consistent
                // hashing below exists precisely to fix this.
                (fnv1a(client_ip.to_string().as_bytes()) % self.servers.len() as u64) as usize
            }
            Algorithm::ConsistentHash => {
                if self.ring.is_empty() {
                    // Defensive: a pool built via Upstream::new with a
                    // different algorithm has no ring.
                    self.rr_cursor.fetch_add(1, Ordering::Relaxed) % self.servers.len()
                } else {
                    // Hash the client to a point on the ring, then walk
                    // clockwise to the first vnode at or after it — wrapping
                    // to the start, because the ring is a circle.
                    //
                    // partition_point is a binary search for that boundary:
                    // it returns the index of the first element for which the
                    // predicate is false.
                    let h = fnv1a(client_ip.to_string().as_bytes());
                    let pos = self.ring.partition_point(|(rh, _)| *rh < h);
                    let (_, server_index) = self.ring[pos % self.ring.len()];
                    server_index
                }
            }
```

Rename `pick`'s parameter from `_client_ip` to `client_ip` now that it is used.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test`
Expected: PASS — 61 tests. There should now be no `dead_code` warnings, since every field of `Upstream` is read.

Confirm the match is exhaustive without a fallback arm:

```bash
cd rproxy && cargo build 2>&1 | grep -c "warning" || echo "no warnings"
```
Expected: `no warnings` (or 0).

- [ ] **Step 5: Commit**

```bash
git add rproxy/src/balancer.rs
git commit -m "Add IP-hash and consistent-hash balancing

Uses a hand-written FNV-1a rather than std's DefaultHasher, whose output
is unspecified across Rust versions and would silently remap every
client's affinity on a toolchain upgrade.

The ring places 160 virtual nodes per server and looks up via
partition_point. A test asserts the payoff directly: removing 1 of 4
servers keeps >=90% of unaffected keys in place under consistent hashing
versus <60% under modulo."
```

---

## Task 7: Live verification and documentation

**Files:**
- Modify: `PROGRESS.md`
- Create: `rproxy/backend.py` — the throwaway test backend used by verification (gitignored, not committed)

**Interfaces:**
- Consumes: the complete Level 3 implementation (Tasks 1–6).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Run the full test suite and record the count**

Run: `cd rproxy && cargo test 2>&1 | tail -5`
Expected: `test result: ok. 61 passed; 0 failed`.

- [ ] **Step 2: Start three backends and verify round-robin distribution**

Write `rproxy/backend.py`:

```python
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"backend-{PORT}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", PORT), H).serve_forever()
```

Run, each in its own shell (or backgrounded):

```bash
cd rproxy
python3 backend.py 9001 & python3 backend.py 9002 & python3 backend.py 9003 &
cargo run -- 127.0.0.1:8080 --upstream api=rr:127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 '/=api' &
sleep 2
for i in $(seq 1 9); do curl -s http://127.0.0.1:8080/; done | sort | uniq -c
```

Expected: exactly `3 backend-9001`, `3 backend-9002`, `3 backend-9003`.

- [ ] **Step 3: Verify weighted, hash, and affinity behavior**

```bash
# Weighted 3:1 — expect ~6 vs ~2 out of 8.
pkill -f "target/debug/rproxy"
cargo run -- 127.0.0.1:8080 --upstream w=wrr:127.0.0.1:9001*3,127.0.0.1:9002*1 '/=w' &
sleep 2
for i in $(seq 1 8); do curl -s http://127.0.0.1:8080/; done | sort | uniq -c
# Expected: 6 backend-9001, 2 backend-9002

# IP hash — one client must pin to exactly one backend.
pkill -f "target/debug/rproxy"
cargo run -- 127.0.0.1:8080 --upstream h=iphash:127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 '/=h' &
sleep 2
for i in $(seq 1 10); do curl -s http://127.0.0.1:8080/; done | sort -u | wc -l
# Expected: 1

# Consistent hash — same pinning property.
pkill -f "target/debug/rproxy"
cargo run -- 127.0.0.1:8080 --upstream c=chash:127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 '/=c' &
sleep 2
for i in $(seq 1 10); do curl -s http://127.0.0.1:8080/; done | sort -u | wc -l
# Expected: 1
```

- [ ] **Step 4: Verify the known Level-3 limitation and backward compatibility**

```bash
# A dead server in the pool still yields 502 — Level 4's job, not this level's.
pkill -f "backend.py 9003"
pkill -f "target/debug/rproxy"
cargo run -- 127.0.0.1:8080 --upstream api=rr:127.0.0.1:9001,127.0.0.1:9003 '/=api' &
sleep 2
for i in 1 2 3 4; do curl -s -o /dev/null -w "%{http_code} " http://127.0.0.1:8080/; done; echo
# Expected: alternating "200 502 200 502" — documented, not a bug at this level.

# Backward compatibility: the Level 1/2 invocations still work unchanged.
pkill -f "target/debug/rproxy"
cargo run -- 127.0.0.1:8080 127.0.0.1:9001 &
sleep 2
curl -s http://127.0.0.1:8080/    # Expected: backend-9001
pkill -f "target/debug/rproxy"; pkill -f backend.py
```

- [ ] **Step 5: Update PROGRESS.md**

Change the Level 3 row in the tracker table to:

```markdown
| 3 | Load Balancing (RR, weighted, least-conn, consistent hashing) | 🟢 **Implemented** (2026-08-03) | `balancer.rs`: 7 algorithms (rr/wrr/rand/lc/lrt/iphash/chash), named `--upstream` pools shared as `Arc<Upstream>`, RAII `Lease` releasing in-flight counts on `Drop`. 61 unit tests. Quiz pending. |
```

Add a "Level 3 — what was built" section after the Level 2 one:

```markdown
## Level 3 — what was built

- [x] `balancer.rs`: `Algorithm` (7 variants), `Server`, `Upstream`, `Lease`
- [x] Stateless: Round Robin, Weighted Round Robin (startup slot expansion), Random
      (hand-written thread-local xorshift, no `rand` dependency)
- [x] Load-aware: Least Connections, Least Response Time (EWMA, alpha=0.2, untried
      servers sort first so a new server is never starved)
- [x] Hash-based: IP Hash (`fnv1a % n`) and Consistent Hashing (160 vnodes/server,
      `partition_point` lookup). Hand-written FNV-1a, because `DefaultHasher`'s output
      is unspecified across Rust versions and would remap affinity on a toolchain bump
- [x] RAII `Lease`: in-flight count released in `Drop`, so it is correct on every
      early-return and cancellation path (tested explicitly)
- [x] Named pools via `--upstream NAME=algo:server[*weight],...`; routes reference by
      name; a bare `host:port` route target auto-wraps as a 1-server pool, so all
      pre-Level-3 invocations and tests keep working
- [x] Startup validation: empty pool, duplicate name, portless address, zero weight
- [x] Per-request log line names pool, algorithm, server, and in-flight count
- [ ] **Level 3 quiz — Vishwa to answer before Level 4**

**Known limitation (by design):** a dead server is still picked and still returns 502.
Active/passive health checks, retries, and circuit breaking are Level 4. The seam is
`Server::available()`, which returns a hardcoded `true` and is already consulted by
every `pick()`.

**Verified end-to-end (2026-08-03):** `cargo test` (61 tests); 3 python backends —
`rr` gave exactly 3/3/3 over 9 requests, `wrr` 3:1 gave 6/2 over 8, `iphash` and
`chash` each pinned one client to exactly 1 backend over 10 requests; dead server in
pool alternated 200/502 as expected; `rproxy LISTEN BACKEND` shorthand unchanged.

**Run with a pool:**
`cargo run -- 127.0.0.1:8080 --upstream api=lc:127.0.0.1:9001,127.0.0.1:9002 /api/**=api /=127.0.0.1:9000`
```

Add to the session log:

```markdown
- **2026-08-03** — Level 3 (Load Balancing) implemented: `balancer.rs` with all 7
  algorithms from Build.md, named upstream pools shared as `Arc<Upstream>`, and an RAII
  `Lease` guard for in-flight accounting. No new dependencies. 61 tests pass;
  live-verified distribution per algorithm against 3 backends. Design spec and plan in
  `docs/superpowers/`.
```

- [ ] **Step 6: Commit**

```bash
git add PROGRESS.md
git commit -m "Record Level 3 completion in PROGRESS.md

61 tests, all 7 algorithms live-verified against 3 backends. Notes the
deliberate limitation that a dead server still yields 502, and names
Server::available() as the seam Level 4 fills in."
```

---

## Verification Summary

| Check | Command | Expected |
|---|---|---|
| Unit tests | `cd rproxy && cargo test` | 61 passed, 0 failed |
| No new deps | `git diff --stat rproxy/Cargo.toml` | no change |
| No warnings | `cd rproxy && cargo build` | clean |
| RR distribution | 9 curls over 3 servers | 3/3/3 exactly |
| WRR ratio | 8 curls, weights 3:1 | 6/2 exactly |
| Affinity | 10 curls, `iphash` / `chash` | 1 distinct backend |
| Ring vs modulo | `cargo test consistent_hash_survives` | ring ≥90%, modulo <60% |
| Lease leak | `cargo test lease_releases_on_early_return_path` | PASS |
| Backward compat | `cargo run -- 127.0.0.1:8080 127.0.0.1:9001` | serves normally |
