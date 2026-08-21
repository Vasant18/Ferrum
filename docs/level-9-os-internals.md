# Level 9 — OS Internals: What Async Actually Is

**Date:** 2026-08-21
**Type:** Theory. No production code changes.
**Course reference:** `Build.md` LEVEL 9; knowledge base § "Level 9 · OS Internals".

You have written `stream.read(&mut buf).await` a hundred times across eight
levels. This level opens the floor and shows the machinery underneath —
non-blocking sockets, the kernel readiness APIs, and the Tokio runtime as a
well-organized event loop.

It is a theory level for a real reason, not as a rest stop: **there is nothing to
build, because Levels 1–8 already run on this machinery.** The valuable work here
is not adding code but *reading the code you already have* through a lower lens
— and, where that reading turns up something real, saying so. It turned up two
things (§7).

Every number and file reference below was verified against the current tree
rather than recalled.

---

## 1. The problem: `read()` blocks

A normal `read()` on a socket with no data parks the calling thread until bytes
arrive. That is fine for one connection and fatal for many: thread-per-connection
at 10,000 connections means 10,000 threads, each with a stack measured in
hundreds of KB to megabytes, and a scheduler doing nothing but context-switching.
This is the C10K problem, and it is the reason every serious proxy is
event-driven.

The fix is to change the question being asked:

```
Blocking asks:       "give me data on THIS socket — I'll wait."
Event-driven asks:   "here are 10,000 sockets — wake me when ANY has data."
```

One thread now serves them all, sleeping until there is genuine work.

Two ingredients are required:

1. **`O_NONBLOCK` sockets**, so `read()` with no data returns `EWOULDBLOCK`
   immediately instead of parking the thread.
2. **A kernel readiness API**, to sleep until something is actually ready.

Ferrum never sets `O_NONBLOCK` itself. Tokio does it when constructing every
`TcpStream` and `TcpListener` — including the ones this proxy gets from
`listener.accept()` in `main.rs`. It is the first piece of machinery the
abstraction hides.

---

## 2. The evolution of the readiness API

The whole story of high-performance servers is the evolution of ingredient 2.

| API | Model | Cost per wait | Why it won / its fatal flaw |
|---|---|---|---|
| `select()` (1983) | Pass a bitmask of FDs on every call | O(n) scan, ~1024 FD cap | Kernel re-scans every FD every call; the cap is compiled in |
| `poll()` (1986) | Pass an array of FDs on every call | O(n) scan, no cap | Still re-passes and re-scans everything each time |
| **`epoll`** (Linux, 2002) | Register FDs **once** in a kernel object; `epoll_wait()` returns only the ready ones | **O(ready)** | The kernel keeps the interest list, so waiting costs nothing per *idle* FD. This is precisely why 10k idle connections are cheap |
| **`kqueue`** (BSD/macOS, 2000) | Same idea, arguably a cleaner API (`kevent` also covers files, signals, timers) | **O(ready)** | **What Ferrum uses on this machine** |
| `IOCP` (Windows) / `io_uring` (modern Linux) | **Completion**-based: "start this read, tell me when it is DONE" rather than "tell me when I may read" | O(done), fewer syscalls | `io_uring` batches submissions and completions through shared-memory rings — the current performance frontier |

The O(n) → O(ready) transition is the entire ballgame. With `select`/`poll`, 9,999
idle connections cost you work on every single wait. With `epoll`/`kqueue`, they
cost nothing until they have data.

### Which one is running here

Verified on this machine:

- **Platform:** `Darwin 25.6.0 arm64` → **kqueue**, not epoll. Every mental model
  in the knowledge base is written around epoll because Linux is where proxies
  deploy, but the code being exercised locally is the BSD path.
- **Reactor crate:** `mio 1.2.2` (a transitive dependency via Tokio — it is in
  `Cargo.lock`, not `Cargo.toml`). `mio` is the thin portability layer that
  presents kqueue, epoll, and IOCP behind one interface.
- **Runtime:** `tokio 1.53.1` with `features = ["full"]`, so the **multi-threaded**
  scheduler. Default worker count is one per core → **8 workers** here
  (`hw.ncpu = 8`).

That last point is worth pausing on. Ferrum has never called
`Runtime::new_multi_thread` or configured a worker count; `#[tokio::main]` on
`async fn main` picks the multi-threaded scheduler by default. Eight OS threads
exist and steal work from each other, and nothing in this codebase says so
anywhere. Level 9's job is that this is no longer invisible.

---

## 3. From `.await` to `kevent`: the full stack

An `async fn` compiles to a **state machine** — an anonymous type implementing
`Future`. Each `.await` is a possible pause point where the machine returns
`Poll::Pending` and parks. The critical consequence, and the thing that trips up
everyone coming from threads or JavaScript promises:

> **Nothing runs in the background. A future is inert until polled.**

There is no thread behind an un-awaited future. Constructing one does no work at
all.

Here is one real request through this proxy, layer by layer:

```
 your async fn  ==compiles to==>  state machine (Future)
       |                                  |
   .await point                  Poll::Pending + register Waker
       |                                  |
 [ EXECUTOR: 8 worker threads, run queues, work stealing ]
       |                                  ^
   parks task                        wake(task)
       |                                  |
 [ REACTOR (mio): one kqueue instance, FD -> Waker map ]
       |                                  ^
  kevent(ADD, fd)              kevent() returns: fd 12 readable
       +-------------- KERNEL ------------+
```

1. `serve_one` reaches `client.read_head().await`, which bottoms out in
   `self.stream.read(&mut self.buf[self.filled..]).await` (`proxy.rs`, inside
   `Conn::read_head` — the `filled` offset is Level 1's over-read buffer, which is
   why a pipelined request that arrived in the same packet is not lost). Tokio's `TcpStream` attempts the **non-blocking `read()`
   syscall right now**. If data is already buffered in the kernel, it returns
   immediately — no waiting, no reactor involvement, no magic. This fast path is
   the common case and is worth knowing: async is not "always slower by a
   scheduler hop."
2. `EWOULDBLOCK`? The future registers interest — *"wake task #417 when FD 12 is
   readable"* — with the reactor, stores a `Waker`, and returns `Pending`. The
   task is now parked: **zero CPU, no thread held**, and its cost is just the
   memory of its own state machine.
3. The **executor** runs other ready tasks on its worker threads. Idle workers
   **steal** queued tasks from busy ones, which is why one slow connection does
   not starve a core.
4. The kernel sees bytes arrive on FD 12. The reactor's `kevent()` call returns,
   the reactor looks up FD 12 → `waker.wake()` → task #417 goes back on a run
   queue.
5. The executor re-polls task #417. **The state machine resumes exactly at the
   await point** — all its local variables intact, because they are fields of the
   generated struct — the `read()` now returns data, and execution continues to
   the next `.await`. Repeat forever.

The restaurant analogy, which is genuinely the clearest one: blocking I/O is a
waiter standing at your table until you decide your order. Async is the waiter
handing you a pager and serving other tables; the kitchen bell (kqueue) tells
them which pager to buzz. The waiter never stands idle at a silent table — and
10,000 tables need only as many waiters as there are tables *currently talking*.

---

## 4. Ferrum's own architecture, read back through this lens

### The task graph

Exactly **three** places in production code create tasks:

| Site | What it spawns | Lifetime |
|---|---|---|
| `main.rs:291` | One task per accepted connection | The connection |
| `health.rs:25` | One prober task per upstream pool | The process |
| `health.rs:70` | One task per concurrent health probe | One probe round |

That is the whole concurrency structure of an 8,800-line proxy. Everything else
is `.await` inside one of those three.

**Task-per-connection is what sidesteps C10K here.** A task is not a thread: it
is a state machine on the heap, scheduled onto one of 8 workers. 10,000
connections means 10,000 parked state machines, not 10,000 stacks. This was
Level 1's choice, made before there was any vocabulary in the project to justify
it — this level supplies the vocabulary.

### The `.await` map, and what it reveals

`.await` occurrences in **code** (comment mentions excluded — this project
discusses `.await` in prose often enough that a naive `grep -c` overcounts by
about 5%), split by production versus test:

| File | prod | test | Reading |
|---|---:|---:|---|
| `proxy.rs` | **57** | 46 | The engine. Almost every suspension point in the proxy is here |
| `health.rs` | 10 | 1 | Prober loop and probe I/O |
| `main.rs` | 5 | 0 | `bind`, `accept`, the TLS handshake, `handle_client` |
| `balancer.rs` | **0** | 13 | — |
| `security.rs` | **0** | 0 | — |
| `tls.rs` | **0** | 0 | — |
| `http.rs` | **0** | 0 | — |
| `rewrite.rs` | **0** | 0 | — |
| `router.rs` | **0** | 0 | — |
| `middleware/mod.rs`, `auth.rs`, `observe.rs` | **0** | 0 | — |
| `middleware/ratelimit.rs` | **0** | 1 | — |
| **Total** | **72** | 61 | |

**Only three files in an 8,800-line crate contain a production `.await`.**
Everything else — all seven load-balancing algorithms, the circuit breaker, the
connection pool, the router, the header rewriter, all five middleware, the TLS
config builder, the connection limiter, the CIDR matcher — is entirely
synchronous code that happens to be *called from* async contexts.

`balancer.rs` is the sharpest case: 1,750+ lines implementing round-robin,
weighted RR, random, least-connections, least-response-time, IP hash, consistent
hashing, a three-state circuit breaker, and a LIFO connection pool, with **zero**
production await points. Its 13 awaits are all in tests, where they exist only to
build real `TcpStream` pairs.

The zeros are not an accident. Four separate levels independently chose to keep
their logic *pure and synchronous*:

- **L1** put parsing and framing in `http.rs` as functions over byte slices.
- **L5** made `rewrite.rs` pure transforms over head structs — "no sockets, no
  async, no I/O", in that level's own words.
- **L6** deliberately rejected the textbook `async fn handle(req, next)`
  middleware trait for a synchronous two-phase one, because an async trait would
  have needed an owned `Response`, forcing every body to buffer and pre-breaking
  Level 7's streaming.
- **L8** made `tls.rs` config-construction only; the handshake `.await` lives in
  `main.rs`, not in the module that builds the `ServerConfig`.

Read through Level 9's lens, those four decisions are the same decision: **keep
the state machine small.** Every `.await` in a function becomes a suspension
point the compiler must be able to resume from, which means every live local
becomes a field in the generated future. A 500-line `async fn` with 100 await
points generates a large state machine; the pure-sync modules generate none at
all. That is why `serve_one` being long is tolerable but `rewrite.rs` being
async would not have been.

---

## 5. The cardinal sin: blocking the executor

A worker thread that blocks is a worker thread that cannot poll anything else.
With 8 workers, blocking one is a 12.5% capacity loss and a mysterious p99 spike;
blocking all 8 is an outage that looks like a hang. The three classic causes:

1. Synchronous I/O (`std::fs`, blocking DNS, a synchronous HTTP client).
2. CPU-heavy work (a pathological regex, crypto, compression).
3. **A lock held across an `.await`** — the worst, because it is also a deadlock
   risk: the task parks *while holding the lock*, and the thread that could
   release it is now running someone else's code.

### Auditing Ferrum against all three

**Locks held across `.await`: structurally impossible.** Every production
function that takes a lock is a plain `fn`, not an `async fn`:

| Function | Signature | Guards |
|---|---|---|
| `Server::take_conn` | `fn take_conn(&self) -> Option<Conn<TcpStream>>` | L7 idle pool |
| `Server::return_conn` | `fn return_conn(&self, conn: Conn<TcpStream>)` | L7 idle pool |
| `ConnLimiter::try_acquire` | `fn try_acquire(self: &Arc<Self>, ip) -> Result<ConnGuard, Refusal>` | L8 per-IP map |
| `ConnLimiter::release` | `fn release(&self, ip: IpAddr)` | L8 per-IP map |
| `RateLimiter::allow` | `fn allow(&self, ip: IpAddr, now: Instant) -> Result<(), u64>` | L6 bucket shards |

This is a stronger guarantee than a code-review convention: **you cannot write
`.await` inside a non-`async fn`,** so the compiler enforces it. Three levels
each wrote a comment explaining why they used `std::sync::Mutex` over
`tokio::sync::Mutex`; this table is the proof those comments are still true.

Corroborating facts, verified: `tokio::sync` appears in this codebase **only
inside comments explaining why it is not used** — there is not one real use.
`spawn_blocking` appears **zero** times. `thread::sleep` appears **zero** times.

**Synchronous `std::fs`: present but harmless.** `tls.rs` uses
`File::open`/`std::fs::metadata` to load certificates. This runs in
`TlsArgs::build()`, which `main.rs` calls **before `TcpListener::bind`** — so it
executes once, at startup, while the runtime has no request work to starve. That
ordering was chosen in Level 8 for a different reason (fail with exit 1 before
announcing a listener), and it happens to also be the correct async-hygiene
answer. Worth noting the coincidence rather than claiming foresight.

**CPU-bound work: one real instance, and it is safe for a non-obvious reason.**
`router.rs:53` runs `re.is_match(path)` on the worker thread for every request
matched against a `~regex` route. In nginx or any PCRE-based proxy this would be
a genuine hazard — catastrophic backtracking can turn one crafted path into
seconds of CPU, which here would mean a frozen worker. It is safe in Ferrum
because Rust's `regex` crate **has no backtracking and guarantees linear time in
the input length**; the pathological blowup is not expressible. The safety comes
from the crate choice made back in Level 2, not from anything the router does.
If that dependency were ever swapped for a backtracking engine, this line becomes
a DoS vector.

---

## 6. Nginx, revisited

With this level's vocabulary, nginx's design reads fluently:

- One **master** process handles config and signals; it forks *N* single-threaded
  **workers**.
- Each worker runs `epoll_wait` in a loop — the same loop mio runs.
- All connection state lives in explicit hand-written C structs, where Ferrum has
  compiler-generated state machines.
- `SO_REUSEPORT` lets every worker accept on the same port, with the kernel
  spreading load.

**Tokio and nginx are the same architecture wearing different clothes.** Both are
an epoll/kqueue event loop over non-blocking sockets. The difference is who
writes the state machines: nginx's authors did it by hand in C, and Rust's
compiler does it for you at zero runtime cost. That is the entire "fearless
async" pitch in one sentence.

One asymmetry worth naming: nginx's model is process-per-core with **no** shared
mutable state between workers, so it has no lock-contention problem to solve.
Tokio's is threads-per-core with shared state and work stealing, which is why
Levels 6, 7, and 8 each had to make a deliberate sharding decision (16 hash
shards, per-`Server` pools, one map behind a mutex). Ferrum pays a cost nginx
does not, and buys the ability to share a route table and a connection pool
across all cores without IPC.

---

## 7. What this reading actually turned up

Two findings. Neither is a bug; both are the kind of thing only visible from this
level.

### 7.1 Backend addresses are re-resolved on every connect

`Server.addr` is a `String` (`balancer.rs:402`). Startup validation
(`balancer.rs:973`) only checks the *shape* — a non-empty host and a port that
parses as a `u16` ≥ 1 — and then keeps the string. So
`TcpStream::connect(&addr)` at `proxy.rs:853` goes through `ToSocketAddrs` on
every pool miss.

For an IP literal like `127.0.0.1:9001` that parse is trivial. For a DNS name
like `api.internal:8080`, which the shape check happily accepts, it is a
`getaddrinfo` call. Tokio routes that through its blocking pool rather than the
worker, so it does not freeze a core — but it does consume a blocking-pool thread
per connect, with **no DNS caching and no respect for TTLs**.

Level 7's connection pooling hides most of this: a pool hit skips `connect`
entirely, so the cost appears only on misses. That is why it has never shown up.
The clean fix is to resolve once at startup into a `SocketAddr` — but that is a
*worse* answer for DNS-named backends, where re-resolution is the only way to
follow a backend that moves. The genuinely correct version is a small resolver
cache with TTL awareness, which is real work and belongs in a level of its own,
not smuggled into a theory chapter.

**Recorded, not fixed.**

### 7.2 The runtime's shape is entirely implicit

Eight worker threads, a multi-threaded work-stealing scheduler, and a blocking
pool all exist because `#[tokio::main]` defaults to them. Nothing in the codebase
mentions any of it. `features = ["full"]` in `Cargo.toml` is the only hint, and it
points the wrong way — it reads like "give me everything" rather than "select the
multi-threaded scheduler."

This matters the first time someone tunes the proxy, because the worker count is
a real dial and it is currently invisible. Not changed, because changing a
default with no benchmark behind it is exactly the "measure, don't guess" mistake
the knowledge base warns about in Level 7 — and there is still no benchmark.

**Recorded, not fixed.**

---

## 8. Deliberately not done

- **No `io_uring` experiment.** It is Linux-only and this machine is Darwin; the
  reactor here is kqueue. Reading about the completion-based model is the whole
  deliverable.
- **No runtime tuning.** See §7.2 — no benchmark, no justification.
- **No DNS caching.** See §7.1 — a real feature, not a theory-level aside.
- **No `spawn_blocking` introduced.** There is nothing in the request path that
  needs it; adding one for symmetry would be cargo-culting.
- **No benchmarks.** Level 7 already recorded that no `wrk`/`oha` run exists for
  this proxy, and that gap is still open. It stays Level 7's debt rather than
  getting quietly reassigned here.

---

## 9. The one-paragraph version

`async fn` compiles to a state machine that is inert until polled. `.await` is a
point where it can return `Pending`, register a `Waker` with the reactor, and
park — costing memory but no thread and no CPU. The reactor (`mio`, over
`kqueue` here and `epoll` on Linux) keeps one kernel object holding every
registered FD, so waiting is O(ready) rather than O(total) — which is the precise
reason 10,000 idle connections are cheap and the C10K problem dissolves. The
executor keeps 8 worker threads polling whatever is ready and steals work between
them. Ferrum's task-per-connection model from Level 1 rides directly on this, and
the pure-synchronous modules from Levels 1, 5, 6, and 8 are all the same
optimization seen from a different angle: keep the generated state machines
small. The only way to break it is to block a worker — and every lock in this
codebase is taken inside a non-`async fn`, which makes that particular failure
mode unrepresentable rather than merely discouraged.
