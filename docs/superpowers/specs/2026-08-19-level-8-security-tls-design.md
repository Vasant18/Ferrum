# Level 8 — Security & TLS: Design

**Date:** 2026-08-19
**Course level:** 8 of 14 (`Build.md` LEVEL 8 — Security; knowledge base § "Level 8 · Security & TLS")
**Precedes:** Level 9 (OS Internals — theory)

## Scope

Two halves, both from the knowledge base's own framing of this level:

1. **Encrypted transport** — TLS termination, and mutual TLS (client-certificate
   authentication).
2. **Armored defaults** — the "front door" hardening table: slowloris,
   resource exhaustion, IP allow/deny, secure-by-default posture.

This is the one level where "from scratch" deliberately stops at the library
boundary. The knowledge base is explicit about it, and lists "building your own
crypto or hand-rolling cert parsing" as a common mistake. Everything *around*
the crypto — the accept path, the handshake deadline, the connection accounting,
the limits — is ours.

## The seam this level was built to fill

Level 1 chose `Conn<S>` generic over `S: AsyncRead + AsyncWrite + Unpin` rather
than concrete over `TcpStream`. Seven levels later that decision pays: a
`tokio_rustls::server::TlsStream<TcpStream>` implements both traits, so the
entire parsing/framing/forwarding core works over TLS **unchanged**. Only two
signatures actually pin the concrete type today:

- `proxy::handle_client(client: TcpStream, ...)`
- `proxy::serve_one(client: &mut Conn<TcpStream>, ...)`

Level 5 left a second, narrower seam — `proxy.rs:590` reads
`scheme: "http", // Level 8 sets "https" after TLS termination`. That comment is
now a requirement: `X-Forwarded-Proto` must report what the *client* spoke, and
after termination the backend has no other way to learn it.

## Decisions

### 1. rustls, not OpenSSL

`rustls` + `tokio-rustls`. Memory-safe, no OpenSSL C surface, and the crypto
provider is pinned to **`ring`** rather than the `aws-lc-rs` default: `ring` is
a substantially lighter build and needs no cmake/NASM toolchain. (Evidence that
this matters: `rproxy/target/` still holds ~1.2 GB of stale `aws-lc-sys`
artifacts from an earlier probe of this level.)

These are the **first new dependencies since Level 2's `regex`**. Justified
because hand-rolling TLS is the one thing this course explicitly forbids.

### 2. Generic over the stream, not an enum

`handle_client<S>` / `serve_one<S>` become generic rather than taking an
`enum Stream { Plain(TcpStream), Tls(TlsStream<TcpStream>) }`.

Generics give static dispatch and zero per-read branching; the enum would add a
match on every `read`/`write` in the hottest loop in the program. The cost is
two monomorphized copies of the proxy core in the binary, which is the correct
trade for a proxy.

Consequence: `set_nodelay` moves out of `handle_client` (it is `TcpStream`-only)
and up into the accept loop, applied to the raw socket **before** any TLS wrap.

### 3. The handshake runs inside the spawned task, never in the accept loop

This is the most important security decision in the level, and it is about *our*
code, not rustls.

```
WRONG                                   RIGHT
loop {                                  loop {
  let (s, peer) = accept().await;         let (s, peer) = accept().await;
  let tls = acceptor.accept(s).await;     spawn(async move {
  spawn(handle(tls));                       let tls = timeout(HS, acceptor.accept(s)).await;
}                                           handle(tls);
                                          });
                                        }
```

Awaiting the handshake in the accept loop means one client that opens a
connection and sends a single `ClientHello` byte stalls **every** new connection
process-wide. That is a one-line, one-attacker total denial of service, and it
would look like a working proxy in every functional test. Level 1's own comment
on the accept loop already states the rule ("Anything slow in this loop delays
*every* new client"); TLS is where violating it becomes catastrophic rather than
merely slow.

The handshake also gets its own deadline, `TLS_HANDSHAKE_TIMEOUT` — the
TLS-layer analogue of Level 1's `HEAD_READ_TIMEOUT`. Without it, slowloris just
moves one layer down: a client that never completes a handshake holds a
connection with no request head ever read, so the existing head deadline never
arms.

### 4. mTLS as three modes

`off` (default) / `optional` / `required`, via rustls's `WebPkiClientVerifier`
against a CA bundle from `--tls-client-ca`.

`optional` exists because it is the real migration path: turn it on, watch which
clients present certs, then flip to `required`. Going straight to `required` on
a live listener is an outage.

### 5. Connection limits use the Lease pattern

A global ceiling and a per-IP cap, checked in the accept loop **before**
spawning — the check must be cheaper than the attack.

The counter is released by `Drop` on an RAII guard, exactly like Level 3's
`Lease`. Same reasoning as that level: a connection can end on many paths
(clean close, parse error, timeout, panic-unwind), and an explicit
`release()` call will eventually be missed on one of them. A leaked connection
slot is worse than a leaked in-flight count — it is permanent, and enough of
them wedge the listener shut.

`std::sync::Mutex` for the per-IP map, not `tokio::sync::Mutex`: the critical
section is a `HashMap` increment with no `.await` inside it. Same call Level 6
made for the rate-limiter shards and Level 7 made for the idle pool.

Over-limit connections are **closed without a response**. Writing a 503 would
mean allocating and doing I/O on behalf of the traffic we are shedding, which
inverts the point of shedding it.

### 6. Body limits are enforced while streaming

The knowledge base names "reading the whole body then checking the size limit"
as mistake #1 for this level — "the damage is done." So the cap is enforced
inside the existing streaming copy loop, aborting mid-body, never by buffering
and then deciding. Level 1's windowed `copy_exact` already gives us the loop to
put the check in; this is a counter and a comparison, not a new mechanism.

Over the cap → **413**. Header count over the cap → **431**. Both are
per-route-overridable with a global default, following the `;option` grammar
Level 5 established and Level 6 extended.

### 7. CIDR matching is hand-rolled

No new dependency. The project already hand-rolls FNV-1a (L3), base64 and
constant-time compare (L6), and duration parsing (L4), each with a recorded
reason. A prefix match on 4 or 16 bytes is smaller than any of those.

Matching is against the **socket peer address only**, never `X-Forwarded-For`.
Level 5 took this stance for `X-Real-IP` and Level 6 for the rate-limit key; a
deny list keyed on a client-supplied header is not a deny list.

**A denied connection is closed without a response** — no 403.

This reverses what an earlier draft of this document said, and the reversal is
the interesting part. nginx's `deny` does answer 403, so 403 was the obvious
default. But on a TLS listener the proxy cannot send *any* HTTP status without
first completing a handshake, and completing a handshake for an address we have
already decided to refuse means spending an RSA/ECDHE operation on behalf of the
attacker — turning the cheapest rejection in the system into one of the most
expensive. The alternatives were both worse: answer 403 on the plaintext
listener but drop on the TLS one (the same config behaving differently depending
on a flag, which is how operators get surprised), or handshake-then-403
everywhere (a DoS amplifier).

So the check sits before the handshake and before the task spawn, and the
connection simply closes. Level 8's connection limits shed load the same way for
the same reason, which makes the two gates consistent with each other.

### 8. Secure defaults

The knowledge base's stated theme: "the config a lazy user gets must be the safe
one." Concretely — TLS 1.2 floor (1.3 preferred, both on by default; rustls
gives us no path to the broken versions at all), limits and timeouts on by
default rather than opt-in, no `Server` header emitted, and a startup warning if
a private key file is group- or world-readable.

## Ordering in the request lifecycle

```
accept()
  |
  +-- CIDR deny/allow check ......... close, before any allocation
  +-- connection limits ............ close, before spawn
  |
  spawn task
    |
    +-- TLS handshake (timeout) ..... inside the task, never the accept loop
    |     mTLS client-cert verify
    |
    +-- handle_client<S>  (S = TcpStream or TlsStream<TcpStream>)
          |
          +-- head read (timeout) ... L1, unchanged
          +-- header count cap ...... 431
          +-- route ................. L2
          +-- middleware ............ L6
          +-- body streaming + cap .. 413, enforced mid-stream
          +-- forward ............... L3/L4/L7, scheme = "https"
```

Every pre-existing stage is untouched. Level 8 adds a shell around the outside
and one counter inside the body loop.

## Testing

Unit-testable without sockets, following the discipline of L3's algorithms,
L4's breaker (`now` as a parameter), L5's pure head transforms, and L7's
poolability predicate:

- CIDR parsing and matching, including boundaries (`/0`, `/32`, `/128`, IPv6,
  and the "does not match the neighbouring range" cases).
- `ConnLimiter` accounting: global cap, per-IP cap, release on drop, and that
  one IP exhausting its own cap does not lock out a different IP.
- Header-count and body-size limit decisions as pure predicates.
- PEM loading: a good cert/key pair, a key file with no key in it, a cert file
  with no cert, and a mismatched pair.

Live verification (a real handshake cannot be unit-tested):
HTTPS request end-to-end; `X-Forwarded-Proto: https` observed at the backend;
mTLS `required` refusing a client with no certificate and admitting one with a
valid certificate; the connection cap shedding load; 413 on an over-cap body;
403 on a denied CIDR; and a deliberately-stalled handshake proving the deadline
fires without blocking other clients.

## Explicitly out of scope

- **Re-encrypt to backend** (TLS on the backend leg) and **SNI passthrough**
  (L4 mode) — the knowledge base presents both as *variants* of termination.
  Termination is the level's requirement; these are separate features that would
  each need their own connection-pool interaction story (a pooled TLS connection
  is not interchangeable with a pooled plaintext one).
- **Automatic certificate issuance** (ACME/Let's Encrypt) — Caddy's headline
  feature, and a whole subsystem: account keys, order state, challenge
  responders, renewal timers.
- **Session resumption tuning** — rustls does ticket-based resumption by
  default; deliberately taking the default rather than building a store.
- **Reputation-fed deny lists** — Level 13 owns that.
