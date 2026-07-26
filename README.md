# Ferrum

A production-inspired reverse proxy written in Rust, built on asynchronous networking with Tokio.

Ferrum sits between clients and backend servers: it terminates connections at the edge, parses and routes HTTP traffic, balances load across upstreams, and applies cross-cutting policy — security, caching, observability — in one place, so backends only ever see clean, well-formed requests.

## Features

Ferrum is being built up in deliberate layers, from raw TCP to a full edge server:

| Area | Capabilities |
|------|--------------|
| **Core networking** | TCP listener, hand-rolled HTTP/1.1 parsing, request/response forwarding, persistent connections (keep-alive), streaming bodies, chunked transfer encoding |
| **Routing** | Host, path, and method matching; prefix, wildcard, and regex routes with explicit precedence |
| **Load balancing** | Round robin, weighted round robin, random, least connections, least response time, IP hash, consistent hashing |
| **Resilience** | Active and passive health checks, retries with exponential backoff and jitter, circuit breakers |
| **Proxy semantics** | `X-Forwarded-For` / `X-Forwarded-Host` / `X-Forwarded-Proto` / `X-Real-IP`, URL and host rewriting, hop-by-hop header handling |
| **Middleware** | Composable pipeline: logging, authentication, authorization, compression, request IDs, request validation, rate limiting (token bucket) |
| **Performance** | Connection pooling, buffer reuse, tuned timeouts on every phase, keep-alive tuning |
| **Security** | TLS termination (rustls), mutual TLS, request size limits, slowloris protection, IP allow/deny lists, secure defaults |
| **Observability** | Structured access/error logs, Prometheus metrics endpoint, tracing, per-stage request timing |
| **Caching** | LRU response cache with TTL, `Cache-Control` semantics, ETag revalidation, conditional requests |
| **Operations** | Graceful shutdown and restart, TOML configuration, hot config reload, CLI |
| **WAF** | Request inspection with anomaly scoring: SQL injection, XSS, and path traversal detection; IP reputation; bot heuristics |

> **Status:** early development. The roadmap above is being implemented level by level — see [PROGRESS.md](PROGRESS.md) for what is done and what is next.

## Architecture

```
                           ┌──────────────────────────────────────────────┐
                           │                    Ferrum                    │
  client ──TLS──►  accept ─► parse ─► WAF ─► middleware ─► router ─► cache │
                           │                                    │ miss    │
                           │                             load balancer    │
                           │                                    │         │
                           │                            connection pool   │
                           └────────────────────────────────────┼─────────┘
                                                                ▼
                                                    backend fleet (N upstreams)
```

Ferrum terminates the client connection and maintains its own pooled connections to backends, so the two sides negotiate keep-alive, protocol version, and lifetimes independently.

## Getting started

Requires Rust 1.89+.

```sh
git clone https://github.com/Vasant18/Ferrum.git
cd Ferrum/rproxy
cargo build --release
cargo run
```

Then point a client at it:

```sh
curl -v http://127.0.0.1:8080/
```

## Project layout

```
Ferrum/
├── rproxy/                             # the proxy crate
│   ├── src/
│   └── Cargo.toml
├── Reverse-Proxy-Knowledge-Base.html   # in-depth design & theory reference
├── PROGRESS.md                         # roadmap and implementation status
└── Build.md                            # full project specification
```

The [knowledge base](Reverse-Proxy-Knowledge-Base.html) is a self-contained HTML reference covering the design rationale behind every subsystem — routing engines, load-balancing algorithms, health checking, TLS termination, epoll/kqueue event loops, HTTP caching semantics, and WAF rule engines — with comparisons to Nginx, Envoy, HAProxy, Traefik, Caddy, and Cloudflare's Pingora.

## Design principles

- **Explicit over magical** — protocol handling is implemented from first principles; libraries are adopted only where correctness demands it (e.g. rustls for TLS).
- **Fail fast** — circuit breakers, deadlines on every await, and hard limits on every input.
- **Zero-downtime operations** — config swaps are atomic snapshots; shutdown drains in-flight requests.
- **Measured, not guessed** — changes to the hot path are justified by benchmarks.

## License

[MIT](LICENSE)
