I want to build my own production-inspired Reverse Proxy from scratch in **Rust** as a deep systems engineering learning project.

Your role is NOT to generate the entire codebase.

Instead, act as a senior systems engineer, networking engineer, and Rust mentor who teaches me how reverse proxies actually work internally.

The objective is not to finish quickly.

The objective is to deeply understand every subsystem involved in building a modern reverse proxy similar to:

- Nginx
- Envoy
- HAProxy
- Traefik
- Caddy
- Cloudflare Proxy
- Barracuda WAF
- AWS Application Load Balancer

Think of this as a multi-week "Build Your Own Reverse Proxy" course where every module builds upon the previous one.

The emphasis should always be on understanding architecture, networking, operating systems, performance, and Rust systems programming—not simply writing code.

The project should be implemented entirely in **Rust**, using idiomatic Rust practices and modern asynchronous networking (Tokio, Hyper/Axum ecosystem where appropriate). However, whenever possible, explain what is happening underneath the abstractions instead of treating libraries as black boxes.

Never hide complexity from me—explain it first, then use Rust abstractions where appropriate.

----------------------------------------------------
LEARNING PHILOSOPHY
----------------------------------------------------

Your goal is to teach me how reverse proxies actually work internally.

For every feature:

1. Explain the theory first.
2. Explain why this feature exists.
3. Explain the networking concepts involved.
4. Explain where it sits in the request lifecycle.
5. Explain production trade-offs.
6. Explain common mistakes.
7. Explain complexity and performance implications.
8. Explain how production systems solve the same problem.
9. Draw an ASCII architecture diagram.
10. Give me a small implementation task.
11. Wait until I complete it before moving to the next stage.

Do NOT dump the entire codebase.

I want to build every component myself.

You should behave like an experienced mentor who gradually teaches me how to engineer production-quality infrastructure software.

----------------------------------------------------
RUST REQUIREMENTS
----------------------------------------------------

Teach Rust concepts naturally throughout the project, including:

- Ownership
- Borrowing
- Lifetimes (only when necessary)
- Traits
- Enums
- Pattern matching
- Async/Await
- Tokio runtime
- Tasks
- Channels
- Arc
- Mutex
- RwLock
- Error handling
- Result and Option
- Modular project organization
- Testing
- Benchmarking
- Performance profiling

Whenever introducing a Rust feature, explain why it is the correct tool for solving the current engineering problem.

----------------------------------------------------
LEVEL 1 — Core Networking

Build from first principles.

Implement:

- TCP listener
- Accepting client connections
- HTTP request parsing
- HTTP response parsing
- Request forwarding
- Response forwarding
- HTTP/1.1
- Persistent connections
- Keep-Alive
- Streaming request bodies
- Streaming response bodies
- Chunked transfer encoding

Explain:

- TCP sockets
- Client/server architecture
- HTTP request lifecycle
- HTTP message format
- Why reverse proxies terminate client connections

----------------------------------------------------
LEVEL 2 — Routing

Implement:

- Path routing
- Host routing
- Method routing
- Prefix matching
- Wildcard matching
- Regex routing
- Route precedence

Explain how routing engines work internally.

----------------------------------------------------
LEVEL 3 — Load Balancing

Implement:

- Round Robin
- Weighted Round Robin
- Random
- Least Connections
- Least Response Time
- IP Hash
- Consistent Hashing

Explain:

- Trade-offs
- Time complexity
- Failure scenarios
- Session affinity

----------------------------------------------------
LEVEL 4 — Health Checks

Implement:

- Active health checks
- Passive health checks
- Retry logic
- Exponential backoff
- Circuit breaker
- Failure detection
- Recovery logic

----------------------------------------------------
LEVEL 5 — Reverse Proxy Features

Implement:

- Header manipulation
- X-Forwarded-For
- X-Forwarded-Host
- X-Forwarded-Proto
- X-Real-IP
- URL rewriting
- Header rewriting
- Host rewriting

----------------------------------------------------
LEVEL 6 — Middleware

Design an extensible middleware architecture.

Implement middleware for:

- Logging
- Authentication
- Authorization
- Compression
- Metrics
- Request IDs
- Request validation
- Rate limiting

Explain middleware pipelines used by production systems.

----------------------------------------------------
LEVEL 7 — Performance

Implement:

- Connection pooling
- Buffer reuse
- Memory pools
- Async worker model
- Efficient buffering
- Timeouts
- Keep-Alive tuning
- Request pipelining

Explain:

- Why Nginx is event-driven
- Async runtime
- Zero-copy techniques
- Memory allocation
- Lock contention
- Throughput vs latency

----------------------------------------------------
LEVEL 8 — Security

Implement:

- TLS termination
- HTTPS
- Certificate loading
- Mutual TLS
- Request size limits
- Slowloris protection
- IP allowlists
- IP denylists
- Secure defaults

----------------------------------------------------
LEVEL 9 — Operating System Internals

Teach:

- Event loops
- epoll
- kqueue
- IOCP
- Polling
- select()
- Non-blocking sockets
- File descriptors
- Kernel networking
- Socket buffers

Explain how Tokio ultimately uses operating system primitives.

----------------------------------------------------
LEVEL 10 — Observability

Implement:

- Structured logging
- Access logs
- Error logs
- Metrics
- Prometheus endpoint
- Health endpoint
- Tracing
- Request timing

----------------------------------------------------
LEVEL 11 — Caching

Implement:

- Response caching
- LRU cache
- TTL
- Cache invalidation
- Cache-Control
- ETag
- Conditional requests

Explain cache design decisions.

----------------------------------------------------
LEVEL 12 — Production Features

Implement:

- Graceful shutdown
- Graceful restart
- Worker processes
- Config reload
- Hot reload
- Configuration parser
- YAML/TOML configuration
- CLI arguments

----------------------------------------------------
LEVEL 13 — Basic WAF

Explain how WAFs extend reverse proxies.

Implement simplified versions of:

- IP reputation
- Rate limiting
- SQL Injection detection
- XSS detection
- Path traversal detection
- Request inspection
- Geo blocking (mock implementation)
- Bot detection (basic heuristics)

Compare these approaches with:

- Barracuda WAF
- Cloudflare WAF
- ModSecurity

Explain the trade-offs each makes.

----------------------------------------------------
LEVEL 14 — Scalability

Teach:

- Reverse proxy clusters
- High availability
- Leader election
- Distributed configuration
- Shared state
- Horizontal scaling
- Anycast
- CDN integration

----------------------------------------------------
FOR EVERY MODULE

Always include:

- Theory
- ASCII diagrams
- Networking concepts
- Rust concepts
- Request lifecycle
- Edge cases
- Performance considerations
- Security considerations
- Production implementation notes
- Common interview questions
- Exercises
- Mini project
- Recommended reading

----------------------------------------------------
PRODUCTION COMPARISONS

Whenever relevant, compare my implementation against:

- Nginx
- Envoy
- HAProxy
- Caddy
- Traefik
- Cloudflare Proxy
- Barracuda WAF

Explain:

- Why they made certain engineering decisions
- What optimizations they use
- What compromises they make
- How my implementation differs

----------------------------------------------------
UNDERSTANDING CHECKS

At the end of every module:

- Quiz me.
- Ask conceptual questions.
- Ask implementation questions.
- Ask debugging questions.
- Do NOT continue until I demonstrate understanding.

----------------------------------------------------
FINAL OBJECTIVE

The ultimate objective of this project is that, by the end, I will have designed, implemented, tested, benchmarked, debugged, documented, and thoroughly understood a fully functional end-to-end reverse proxy capable of serving real production traffic.

The final project should be deployable and include:

- Multiple backend servers
- Advanced routing
- Load balancing
- Health checks
- Middleware pipeline
- HTTPS termination
- Structured logging
- Metrics
- Configuration files
- Graceful shutdown
- Graceful restart
- Caching
- Rate limiting
- Basic WAF capabilities
- Performance optimizations
- Production-style configuration
- Automated tests
- Integration tests
- Benchmarks
- Documentation

The reverse proxy should be capable of sitting in front of real web applications and forwarding requests correctly, efficiently, and securely.

The goal is not merely to write code that works, but to understand every subsystem involved, every engineering trade-off, and how production-grade reverse proxies implement similar functionality.

By the end of this project, I should be able to:

- Explain the complete request lifecycle from client to backend and back.
- Build a reverse proxy entirely from scratch without referencing the tutorial.
- Debug networking issues at the TCP, HTTP, and TLS layers.
- Explain how async runtimes work.
- Explain how operating system networking primitives are used.
- Read and understand portions of the source code of Nginx, Envoy, Traefik, Caddy, HAProxy, and similar systems.
- Confidently extend my reverse proxy with new middleware and features.
- Understand why production systems are designed the way they are.
- Benchmark and profile networking applications.
- Apply Rust effectively for high-performance systems programming.
- Possess a deep mental model of how modern reverse proxies are engineered.

Optimize for deep systems understanding—not speed.

Treat this project as if you are mentoring a systems engineer preparing to build production-grade networking infrastructure.
