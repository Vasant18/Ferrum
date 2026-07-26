# Build Your Own Reverse Proxy — Course Progress

Mentor-mode course defined in [Build.md](Build.md). Theory reference: [Reverse-Proxy-Knowledge-Base.html](Reverse-Proxy-Knowledge-Base.html). Code lives in [`rproxy/`](rproxy/).

**Rules of engagement:** the mentor (Claude) teaches theory, assigns small tasks, reviews code, and quizzes. The student (Vishwa) writes ALL proxy code. Do not advance a module until the quiz is passed.

## Level / Module Tracker

| Level | Topic | Status | Notes |
|-------|-------|--------|-------|
| 1 | Core Networking (TCP, HTTP/1.1, forwarding, keep-alive, chunked) | 🔵 **In progress** | Module 1.1 assigned: TCP listener + canned HTTP response (see below) |
| 2 | Routing (host/path/method, precedence) | ⚪ Not started | |
| 3 | Load Balancing (RR, weighted, least-conn, consistent hashing) | ⚪ Not started | |
| 4 | Health Checks (active/passive, retries, circuit breaker) | ⚪ Not started | |
| 5 | Proxy Headers & Rewriting (XFF, host/URL rewrite) | ⚪ Not started | |
| 6 | Middleware (pipeline, auth, rate limiting) | ⚪ Not started | |
| 7 | Performance (pooling, buffers, timeouts) | ⚪ Not started | |
| 8 | Security & TLS (termination, mTLS, slowloris) | ⚪ Not started | |
| 9 | OS Internals (epoll/kqueue, Tokio internals) — theory | ⚪ Not started | |
| 10 | Observability (logs, metrics, tracing) | ⚪ Not started | |
| 11 | Caching (LRU, TTL, ETag, revalidation) | ⚪ Not started | |
| 12 | Production Features (graceful shutdown, config, hot reload) | ⚪ Not started | |
| 13 | Basic WAF (SQLi/XSS/traversal detection, reputation) | ⚪ Not started | |
| 14 | Scalability (clusters, HA, anycast) — theory | ⚪ Not started | |

## Level 1 module breakdown

- [ ] **Module 1.1 — TCP listener + fixed HTTP response** *(assigned 2026-07-26)*
      Tokio `TcpListener` on `127.0.0.1:8080`; spawn a task per connection; read and print the raw request bytes; write a fixed valid HTTP/1.1 response. Verify: `curl -v localhost:8080` + concurrent curls.
- [ ] Module 1.2 — Parse the request line + headers into a struct
- [ ] Module 1.3 — Forward the request to one hardcoded backend, relay the response
- [ ] Module 1.4 — Content-Length bodies (both directions), streaming copy
- [ ] Module 1.5 — Keep-alive: multiple requests per connection
- [ ] Module 1.6 — Chunked transfer encoding
- [ ] Level 1 quiz passed → unlock Level 2

## Session log

- **2026-07-26** — Course kickoff. Knowledge base built (all 14 levels). `rproxy` crate created (tokio only). Module 1.1 taught & assigned.
