# Level 14 — Scalability & High Availability (theory)

**Date:** 2026-09-02 · **Course level:** 14 of 14 — the last one.
Theory level like Level 9: no production code changes. The method is the
same: read the concepts through Ferrum's own code, verify every claim
against the tree, and name what would actually break at N > 1.

The KB's framing: one proxy instance, however fast, is a single point of
failure with a ceiling. This level asks what changes when "the proxy"
becomes "the proxy *tier*" — and the answer, satisfyingly, is that every
level of this course reappears wearing a bigger hat.

---

## 1. Who balances the load balancers?

Ferrum spent Levels 3–4 deciding which *backend* gets a request. At
cluster scale the same question recurses one layer up: which *proxy* gets
the connection? The production answers, usually layered:

| Mechanism | How | Failover speed | The catch |
|---|---|---|---|
| **DNS round-robin** | N A/AAAA records; health-checked DNS (Route 53) pulls dead IPs | minutes (TTL) | Resolvers cache and clients disobey TTLs; failover is advisory |
| **VRRP / keepalived** | Active proxy holds a floating VIP; standby claims it via gratuitous ARP | sub-second | Active/passive wastes half the hardware; scales to exactly 2 |
| **Anycast** | The SAME IP announced from many sites via BGP; routing delivers each client to the nearest | route-convergence | Requires owning IP space + BGP sessions — how Cloudflare puts one IP everywhere |
| **L4 tier over L7 tier** | Thin, near-stateless L4 balancers (LVS, Maglev, NLB) consistent-hash flows onto L7 proxies | seconds, graceful | The architecture inside every major cloud; one more tier to run |

The layering in practice: anycast or DNS gets a client to a *site*; an L4
tier inside the site consistent-hashes the 4-tuple onto the L7 fleet;
Ferrum-shaped proxies do the L7 work. Each layer does what it is cheapest
at.

**The recursion worth savoring:** Maglev-style L4 balancers spread flows
with *consistent hashing* — the same algorithm `balancer.rs:598` builds a
ring for (`Algorithm::ConsistentHash`). Ferrum already contains the core
idea of the tier that would sit above it. And the L4 tier hashes the
4-tuple for the same reason `IpHash` exists at `balancer.rs:711`: so a
flow's packets keep landing on the proxy that holds its TCP state.

---

## 2. The state problem — audited against this tree

N proxies must agree on things Ferrum built as single-instance state. The
KB's design hierarchy — don't share; share approximately; share for real
(rarely) — maps onto a concrete audit of `rproxy/src`:

### Ships to N instances unchanged (don't share)

- **Route table / config** (`RwLock<Arc<RouteTable>>`, L12): identical
  `ferrum.toml` pushed to every instance; SIGHUP is already the reload
  interface a config-push pipeline would use. The grown-up version is a
  control plane streaming config (Envoy xDS) — and L12 unknowingly built
  the data-plane half: validate wholesale, swap atomically, never die on
  bad input. A control plane is "someone else runs `reload()` for you,
  over gRPC."
- **Health state** (`balancer.rs` breakers, `health.rs` probers): each
  instance learns independently. N instances probing one backend N times
  is mild extra load for total independence — no consensus, and slight
  disagreement is *harmless*: an instance that hasn't noticed a recovery
  yet just routes around a healthy server briefly. (The KB's "let each
  proxy learn" is exactly what falls out of having built health checking
  with zero shared state in the first place.)
- **The connection pool** (L7), **metrics** (L10): per-instance by
  nature. Prometheus was designed for fleets — the scraper aggregates
  across instances; `ferrum_requests_total` summed over N proxies is the
  fleet number. The per-instance registry needs zero changes.

### Breaks quietly at N > 1 (share approximately)

Verified by grepping the tree for process-local state (`static`,
`OnceLock`, per-process shards):

- **Rate limiting** (`middleware/ratelimit.rs`, 16-shard token buckets):
  a `rate=100/s` route behind 3 proxies admits up to 300/s — each
  instance's buckets are blind to the others. The KB's hierarchy applies:
  per-instance × N is *often fine* (set 33/s per instance); when it
  isn't, an async-replicated counter (Redis) buys a slightly-loose global
  limit. Exact distributed counting costs a synchronous round-trip per
  request — the approximate answer is usually the right trade, and the
  16-shard design generalizes: shards just move from mutexes to Redis
  keys.
- **WAF reputation** (`waf.rs` `REPUTATION: OnceLock`, L13): strikes and
  bans are per-instance, so an attacker spraying a 3-proxy fleet gets 3×
  the strikes-budget before every instance has banned them
  independently. Same shape as rate limiting (it IS a rate limiter for
  hostility); same remedies. Commercial WAFs share reputation across
  *customers*, not just instances — the network effect the KB calls the
  vendors' moat.
- **The response cache** (`cache.rs`, L11): N independent caches mean N
  misses per resource and N revalidations — wasteful but *correct*
  (each cache honors the same RFC 9111 rules; nothing leaks). The fleet
  fix is either "don't fix it" (hit rate at the CDN layer above makes
  the local cache a second-order optimization) or consistent-hash cache
  keys across the tier so each resource has one home proxy — the L3
  `chash` ring, third appearance.
- **`active_connections`, request-id seeds, ban backoff clocks**: all
  per-instance and all fine — the request-id scheme (L6) already
  seeds per-process exactly so N instances don't collide in a shared
  log. That decision was cluster-ready three levels before clusters.

### Needs real coordination (share for real — rarely)

- **"Exactly one instance does X"** — renew the TLS cert, run the
  nightly purge. This is leader election: an etcd/ZooKeeper lease (a
  TTL'd key the leader must keep renewing; lose it and another instance
  takes over), built on Raft/Paxos consensus. The honest engineering
  rule, per the KB: *use an existing store; implementing Raft is its own
  course.* Nothing in Ferrum needs this today — the nearest future need
  is L8's cert files becoming ACME-renewed.
- **Sessions**: the cluster answer to L3's `iphash` affinity is to make
  affinity unnecessary — externalize session state (Redis) or carry it
  in the token (JWT), so ANY proxy and ANY backend can serve ANY user.
  Statelessness is what makes horizontal scaling linear; `iphash`
  remains the fallback when a legacy backend hoards state in memory.

---

## 3. High availability — what actually pages you

- **The health-check asymmetry generalizes.** L4's "down after 3, up
  after 2" prevents flapping for backends; fleet membership uses the
  same asymmetry for proxies (an L4 tier health-checks its L7 fleet the
  way `health.rs` probes backends — `/health` from L10 is exactly the
  endpoint it would hit, and its "degraded ≠ dead" distinction is
  exactly what keeps a backend outage from cascading into the proxy
  tier's removal).
- **Graceful everything becomes rolling deploys.** L12's drain +
  `Connection: close` is the per-instance move; the fleet version is
  "remove from the L4 tier → drain → replace → re-add", orchestrated by
  Kubernetes or equivalent. The KB already conceded this at L12:
  in-process graceful restart lost to the platform's rolling deploy.
- **Failure domains stack:** process (Tokio task panics are contained —
  L12's worker-processes analysis), machine (VRRP/L4 tier reroutes),
  site (anycast withdraws the BGP announcement). Each layer's failure is
  the next layer's health-check event.

---

## 4. CDN integration — know your place in the chain

In production, Ferrum-shaped proxies usually sit *behind* a CDN. Three
consequences, each landing on a seam this course already built:

1. **The "client IP" is a CDN node.** L5's trust rules (overwrite
   `X-Real-IP`, append to XFF, key limits on the socket peer) now need
   one refinement: a *published allowlist* of CDN ranges from which
   `X-Forwarded-For` may be trusted — L8's `CidrList` is literally the
   machinery (`--allow-cidr` pointed at trust rather than admission).
2. **The cache becomes layer two of two.** The CDN's 300 edge sites
   absorb the hit rate; L11's cache catches what leaks through. `s-maxage`
   vs `max-age` (L11 honored both) is exactly how origins speak to the
   two layers differently.
3. **Origin pull is just another keep-alive client.** A CDN node
   multiplexing thousands of users over a few hot connections is the
   ideal customer for L7's connection pools and L1's keep-alive loop.

---

## 5. Where this leaves the course

Every level reappears at cluster scale wearing a bigger hat:

| Single instance (built) | Fleet (theory) |
|---|---|
| L3 consistent-hash ring over backends | Maglev hashing flows over proxies |
| L4 breakers + probers | Fleet membership + L4-tier health checks |
| L6/L13 per-IP buckets & strikes | Redis-replicated approximate global limits |
| L10 `/health`, `/metrics` | The endpoints the tier and the scraper consume |
| L11 cache | Layer two behind the CDN, or chash-partitioned |
| L12 SIGHUP reload | Control plane (xDS); config push |
| L12 drain | Rolling deploys |

Distributed systems aren't a different subject; they're the same subject,
multiplied. The vocabulary built here — consistent hashing, breakers,
drain, atomic config swap, anomaly scoring — is the vocabulary of the
Envoy architecture docs, the Maglev paper, and the Pingora posts, readable
now as a peer rather than a tourist.

**Course complete: 14/14 levels.** 280 tests, ~13.4k lines, two
dependencies (regex, rustls) — everything else from scratch, on purpose.
