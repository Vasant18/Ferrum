# Level 6 — Middleware Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an ordered middleware pipeline to the proxy and build five middleware on it — request ID, access log, authentication, authorization, rate limiting — each configured per route.

**Architecture:** A new `middleware/` module directory holds a synchronous `Middleware` trait with two phases (`on_request` forward through the chain, `on_response` in reverse). The chain runs in `serve_one` *after* routing and *before* the balancer lease, so a rejected request never opens a backend socket. Bodies keep streaming exactly as in Level 5 — the trait never owns a response, which is why it can stay sync (no `async fn` in trait objects, no boxed futures).

**Tech Stack:** Rust 2024, Tokio (already a dep), `std::sync::Mutex` + `HashMap` for the sharded rate-limit store. No new crates — a base64 decoder is hand-written (~30 lines).

## Global Constraints

- **No new dependencies.** The crate stays at `tokio` + `regex`. Base64 decoding is hand-written. (Spec: "the crate stays at tokio + regex".)
- **Rust edition 2024** (`rproxy/Cargo.toml` already sets this).
- **Everything in this level is synchronous and pure over head structs** — unit-testable with no sockets. The trait methods do not `await`.
- **All 104 existing tests must stay green** after every task. Target ~140 tests total.
- **`cargo build --release` must not add warnings.** The repo currently has 4 dead-code warnings (pre-existing); do not add more. Test-only constructors get `#[allow(dead_code)]` with a why-comment, matching the `from_spec` precedent.
- **Heavy in-code teaching comments** — this is "I implement, you learn" mode. Every non-obvious decision gets a comment explaining *why*, matching the density in `rewrite.rs` and `balancer.rs`.
- **Fixed chain order, in code not config:** `Log`(0), `RequestId`(1), `RateLimit`(2), `Auth`(3), `Authz`(4). `on_request` runs 0→4; `on_response` runs 4→0 for the layers actually entered.
- **Rate-limit key is `peer.ip()` only** — never `X-Forwarded-For`.
- **Constant-time comparison** for all credential checks.
- **Do NOT commit.** Leave all changes in the working tree; Vessey commits himself. Each task's "Commit" step is replaced by "Stop and report for review" — the reviewer gate still happens, but no `git commit` is run.

### Existing APIs this plan consumes (verified against source)

From `http.rs`:
- `pub struct RequestHead { pub method: String, pub target: String, pub version: Version, pub headers: Vec<(String, String)> }`
- `pub struct ResponseHead { pub version: Version, pub status: u16, pub reason: String, pub headers: Vec<(String, String)> }`
- `pub enum Version { Http10, Http11 }`
- `pub enum BodyFraming { None, Length(u64), Chunked, UntilClose }`
- `pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str>`
- `pub fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str)` — overwrites, debug-asserts no CR/LF
- `pub fn remove_header(headers: &mut Vec<(String, String)>, name: &str)`
- `pub fn write_response_head(head: &ResponseHead) -> Vec<u8>`

From `proxy.rs`:
- `pub struct Conn<S>` with `pub async fn copy_body_to<W>(&mut self, dst: &mut W, framing: BodyFraming) -> io::Result<bool>`, `pub fn stream_mut(&mut self) -> &mut S`, `pub async fn write_all(&mut self, data: &[u8])`, `pub async fn flush(&mut self)`
- `async fn respond_error<S>(client: &mut Conn<S>, status: u16, reason: &str) -> io::Result<()>` — to be extended with headers
- `async fn serve_one(client: &mut Conn<TcpStream>, routes: &RouteTable, peer: SocketAddr) -> io::Result<bool>`

From `router.rs`:
- `pub struct Route { pub host: Option<String>, pub method: Option<String>, pub path: PathMatcher, pub upstream: Arc<Upstream>, pub rules: RewriteRules }` — **not** `Clone`, never cloned
- `pub fn resolve_route(spec: &str, upstreams: &HashMap<String, Arc<Upstream>>, forwarded: bool) -> io::Result<Route>`
- `parse_matchers(spec) -> Matchers` where `Matchers` has an `options: String` field (the severed `;...` string)

From `rewrite.rs`:
- `RewriteRules::from_options(opts: &str, forwarded: bool) -> io::Result<RewriteRules>` — **currently errors on unknown keys; Task 6 changes this**

---

## File Structure

```
rproxy/src/
  middleware/
    mod.rs        trait, Decision, Rejection, ReqCtx, Chain, MiddlewareConfig,
                  option parsing + startup validation, chain summary
    observe.rs    RequestId + AccessLog middleware, request-id validation
    auth.rs       base64 decode, constant-time compare, Auth + Authz middleware
    ratelimit.rs  Bucket, Limiter (sharded), RateLimit middleware
  router.rs       Route gains `chain: Chain`; resolve_route partitions options
  proxy.rs        serve_one runs the chain; respond_error gains headers;
                  bounded rejection drain; ReqCtx populated with backend/upstream
  main.rs         --no-request-id / --no-access-log flags; chain summary print
```

`main.rs` declares the module with `mod middleware;` (Rust treats `middleware/mod.rs` as the module root).

---

## Task 1: The middleware trait and chain

**Files:**
- Create: `rproxy/src/middleware/mod.rs`
- Modify: `rproxy/src/main.rs` (add `mod middleware;` after `mod http;`)
- Test: in `middleware/mod.rs` `#[cfg(test)]`

**Interfaces:**
- Produces:
  - `pub trait Middleware: Send + Sync { fn name(&self) -> &'static str; fn on_request(&self, req: &mut RequestHead, ctx: &mut ReqCtx) -> Decision; fn on_response(&self, _ctx: &ReqCtx, _resp: &mut ResponseHead) {} }`
  - `pub enum Decision { Continue, Reject(Rejection) }`
  - `pub struct Rejection { pub status: u16, pub reason: &'static str, pub headers: Vec<(String, String)>, pub body: String }`
  - `pub struct ReqCtx { pub peer: SocketAddr, pub started: Instant, pub method: String, pub target: String, pub host: Option<String>, pub request_id: String, pub identity: Option<String>, pub backend: Option<String>, pub upstream: Option<String>, pub rejected_by: Option<&'static str> }` with `pub fn new(peer, method, target, host) -> Self`
  - `pub struct Chain { mws: Vec<Box<dyn Middleware>> }` with:
    - `pub fn run_request(&self, req: &mut RequestHead, ctx: &mut ReqCtx) -> Result<(), (usize, Rejection)>` — returns `Err((entered_index, rejection))` where `entered_index` is the index of the rejecting middleware
    - `pub fn run_response(&self, ctx: &ReqCtx, resp: &mut ResponseHead, up_to: usize)` — runs `on_response` for indices `(0..up_to)` in reverse
    - `pub fn run_response_all(&self, ctx: &ReqCtx, resp: &mut ResponseHead)` — reverse over every middleware (the non-rejected path)

`run_request` returns the index so the caller knows how many layers to unwind on rejection. On the success path the caller uses `run_response_all`.

- [ ] **Step 1: Write the failing tests**

Add to a new `#[cfg(test)] mod tests` in `middleware/mod.rs`. Use a recording test middleware:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{RequestHead, ResponseHead, Version};
    use std::sync::Mutex;
    use std::sync::Arc;

    /// A middleware that appends its label to a shared log on each phase,
    /// and optionally rejects on request. Proves ordering and short-circuit.
    struct Probe {
        label: &'static str,
        log: Arc<Mutex<Vec<String>>>,
        reject: bool,
    }
    impl Middleware for Probe {
        fn name(&self) -> &'static str { self.label }
        fn on_request(&self, _req: &mut RequestHead, _ctx: &mut ReqCtx) -> Decision {
            self.log.lock().unwrap().push(format!("req:{}", self.label));
            if self.reject {
                Decision::Reject(Rejection {
                    status: 418, reason: "teapot", headers: vec![], body: String::new(),
                })
            } else {
                Decision::Continue
            }
        }
        fn on_response(&self, _ctx: &ReqCtx, _resp: &mut ResponseHead) {
            self.log.lock().unwrap().push(format!("resp:{}", self.label));
        }
    }

    fn req() -> RequestHead {
        RequestHead { method: "GET".into(), target: "/".into(), version: Version::Http11, headers: vec![] }
    }
    fn resp() -> ResponseHead {
        ResponseHead { version: Version::Http11, status: 200, reason: "OK".into(), headers: vec![] }
    }
    fn ctx() -> ReqCtx {
        ReqCtx::new("127.0.0.1:1".parse().unwrap(), "GET".into(), "/".into(), None)
    }
    fn probes(log: &Arc<Mutex<Vec<String>>>, rejecter: Option<usize>) -> Chain {
        let labels = ["a", "b", "c"];
        let mws: Vec<Box<dyn Middleware>> = labels.iter().enumerate().map(|(i, l)| {
            Box::new(Probe { label: l, log: log.clone(), reject: Some(i) == rejecter }) as Box<dyn Middleware>
        }).collect();
        Chain { mws }
    }

    #[test]
    fn on_request_runs_forward() {
        let log = Arc::new(Mutex::new(vec![]));
        let chain = probes(&log, None);
        assert!(chain.run_request(&mut req(), &mut ctx()).is_ok());
        assert_eq!(*log.lock().unwrap(), ["req:a", "req:b", "req:c"]);
    }

    #[test]
    fn on_response_runs_reverse() {
        let log = Arc::new(Mutex::new(vec![]));
        let chain = probes(&log, None);
        chain.run_response_all(&ctx(), &mut resp());
        assert_eq!(*log.lock().unwrap(), ["resp:c", "resp:b", "resp:a"]);
    }

    #[test]
    fn reject_short_circuits_inner_layers() {
        let log = Arc::new(Mutex::new(vec![]));
        let chain = probes(&log, Some(1)); // "b" rejects
        let err = chain.run_request(&mut req(), &mut ctx());
        assert!(matches!(err, Err((1, _))));
        // "c" never ran on the way in.
        assert_eq!(*log.lock().unwrap(), ["req:a", "req:b"]);
    }

    #[test]
    fn reject_unwinds_only_entered_layers() {
        let log = Arc::new(Mutex::new(vec![]));
        let chain = probes(&log, Some(1)); // "b" rejects at index 1
        let _ = chain.run_request(&mut req(), &mut ctx());
        log.lock().unwrap().clear();
        // On rejection at index 1, unwind on_response for indices 0..1 => just "a".
        chain.run_response(&ctx(), &mut resp(), 1);
        assert_eq!(*log.lock().unwrap(), ["resp:a"]);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd rproxy && cargo test middleware::tests 2>&1 | tail -20`
Expected: compile error (`Middleware`, `Chain`, etc. not defined).

- [ ] **Step 3: Write the module**

Write `middleware/mod.rs`. Module doc comment explains the two-phase design and *why it's sync* (the KB's async `handle(req, next)` needs an owned response; we stream bodies, so we split into two sync passes and run the second in reverse — the onion without owning the body). Then:

```rust
use std::net::SocketAddr;
use std::time::Instant;

use crate::http::{RequestHead, ResponseHead};

pub trait Middleware: Send + Sync {
    fn name(&self) -> &'static str;
    fn on_request(&self, req: &mut RequestHead, ctx: &mut ReqCtx) -> Decision;
    fn on_response(&self, _ctx: &ReqCtx, _resp: &mut ResponseHead) {}
}

pub enum Decision {
    Continue,
    Reject(Rejection),
}

pub struct Rejection {
    pub status: u16,
    pub reason: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub struct ReqCtx {
    pub peer: SocketAddr,
    pub started: Instant,
    pub method: String,
    pub target: String,
    pub host: Option<String>,
    pub request_id: String,
    pub identity: Option<String>,
    pub backend: Option<String>,
    pub upstream: Option<String>,
    pub rejected_by: Option<&'static str>,
}

impl ReqCtx {
    pub fn new(peer: SocketAddr, method: String, target: String, host: Option<String>) -> Self {
        ReqCtx {
            peer,
            started: Instant::now(),
            method,
            target,
            host,
            request_id: String::new(),
            identity: None,
            backend: None,
            upstream: None,
            rejected_by: None,
        }
    }
}

pub struct Chain {
    mws: Vec<Box<dyn Middleware>>,
}

impl Chain {
    /// Run on_request forward. On rejection, return the rejecting index and
    /// the response to send. The index tells the caller how many layers were
    /// entered, so it can unwind exactly those on_response passes.
    pub fn run_request(
        &self,
        req: &mut RequestHead,
        ctx: &mut ReqCtx,
    ) -> Result<(), (usize, Rejection)> {
        for (i, mw) in self.mws.iter().enumerate() {
            match mw.on_request(req, ctx) {
                Decision::Continue => {}
                Decision::Reject(r) => {
                    ctx.rejected_by = Some(mw.name());
                    return Err((i, r));
                }
            }
        }
        Ok(())
    }

    /// Reverse on_response for indices [0, up_to). Used on the rejection path:
    /// the rejecting layer produced the response and does not post-process its
    /// own output, and layers after it never ran.
    pub fn run_response(&self, ctx: &ReqCtx, resp: &mut ResponseHead, up_to: usize) {
        for mw in self.mws[..up_to].iter().rev() {
            mw.on_response(ctx, resp);
        }
    }

    /// Reverse on_response over every layer. The non-rejected path.
    pub fn run_response_all(&self, ctx: &ReqCtx, resp: &mut ResponseHead) {
        for mw in self.mws.iter().rev() {
            mw.on_response(ctx, resp);
        }
    }
}
```

Add `mod middleware;` to `main.rs` (after `mod http;`, before `mod proxy;` — alphabetical-ish, matching existing order). This will warn about unused items until Task 5 wires it in; that is expected mid-plan and resolved by Task 6. Do not add `#[allow(dead_code)]` to public items that later tasks consume — the warnings clear when wiring lands.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test middleware::tests 2>&1 | tail -10`
Expected: 4 passed. Then `cargo test 2>&1 | tail -3` → 108 passed.

- [ ] **Step 5: Stop and report for review** (no commit — see Global Constraints)

---

## Task 2: Request ID and access log (`observe.rs`)

**Files:**
- Create: `rproxy/src/middleware/observe.rs`
- Modify: `rproxy/src/middleware/mod.rs` (add `pub mod observe;`)
- Test: in `observe.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: `Middleware`, `Decision`, `ReqCtx`, `ResponseHead`, `RequestHead` from Task 1; `http::set_header`, `http::header`.
- Produces:
  - `pub struct RequestId { counter: Arc<AtomicU64>, seed: u64 }` with `pub fn new() -> Self`, implementing `Middleware`
  - `pub struct AccessLog;` implementing `Middleware`
  - `pub fn valid_request_id(s: &str) -> bool` (≤64 chars, only `[A-Za-z0-9_-]`)

Design notes for the implementer:
- `RequestId::on_request`: if an inbound `X-Request-Id` exists and `valid_request_id` passes, adopt it into `ctx.request_id`; else generate `format!("{:x}-{}", seed, counter.fetch_add(1, Relaxed))`. Then `http::set_header(&mut req.headers, "X-Request-Id", &ctx.request_id)`. Comment: an inbound id is client-controlled and lands in logs, so a CR/LF or oversized value is a log-injection vector — replaced, not rejected.
- `RequestId::on_response`: `http::set_header(&mut resp.headers, "X-Request-Id", &ctx.request_id)`.
- The `seed` is set once in `new()` from `SystemTime` (allowed here — this is process startup, not the async hot path, and not inside a workflow script). Document it is **not a UUID**: per-process monotonic counter, one atomic increment per request.
- `AccessLog::on_request`: return `Decision::Continue`, record nothing (the `started` stamp lives in `ReqCtx::new`).
- `AccessLog::on_response`: `println!` one `key=value` line. Compute `dur` from `ctx.started.elapsed()`. Include `id`, `peer`, `method`, `target`, `status` (from `resp.status`), `dur`, `upstream`, `backend`, `user` (from `ctx.identity`), and `rejected_by` if `Some`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{RequestHead, ResponseHead, Version, header};
    use crate::middleware::{Middleware, Decision, ReqCtx};

    fn req_with(headers: Vec<(String, String)>) -> RequestHead {
        RequestHead { method: "GET".into(), target: "/".into(), version: Version::Http11, headers }
    }
    fn ctx() -> ReqCtx {
        ReqCtx::new("127.0.0.1:1".parse().unwrap(), "GET".into(), "/".into(), None)
    }

    #[test]
    fn generates_id_when_absent() {
        let mw = RequestId::new();
        let mut r = req_with(vec![]);
        let mut c = ctx();
        assert!(matches!(mw.on_request(&mut r, &mut c), Decision::Continue));
        assert!(!c.request_id.is_empty());
        assert_eq!(header(&r.headers, "x-request-id"), Some(c.request_id.as_str()));
    }

    #[test]
    fn honors_valid_inbound_id() {
        let mw = RequestId::new();
        let mut r = req_with(vec![("X-Request-Id".into(), "trace-abc123".into())]);
        let mut c = ctx();
        mw.on_request(&mut r, &mut c);
        assert_eq!(c.request_id, "trace-abc123");
    }

    #[test]
    fn replaces_oversized_inbound_id() {
        let mw = RequestId::new();
        let big = "x".repeat(65);
        let mut r = req_with(vec![("X-Request-Id".into(), big.clone())]);
        let mut c = ctx();
        mw.on_request(&mut r, &mut c);
        assert_ne!(c.request_id, big);
        assert!(!c.request_id.is_empty());
    }

    #[test]
    fn replaces_control_char_inbound_id() {
        let mw = RequestId::new();
        let mut r = req_with(vec![("X-Request-Id".into(), "evil\r\nSet-Cookie: x".into())]);
        let mut c = ctx();
        mw.on_request(&mut r, &mut c);
        assert!(!c.request_id.contains('\r') && !c.request_id.contains('\n'));
    }

    #[test]
    fn echoes_id_onto_response() {
        let mw = RequestId::new();
        let mut c = ctx();
        c.request_id = "abc-1".into();
        let mut resp = ResponseHead { version: Version::Http11, status: 200, reason: "OK".into(), headers: vec![] };
        mw.on_response(&c, &mut resp);
        assert_eq!(header(&resp.headers, "x-request-id"), Some("abc-1"));
    }

    #[test]
    fn generated_ids_are_unique() {
        let mw = RequestId::new();
        let mut ids = std::collections::HashSet::new();
        for _ in 0..1000 {
            let mut r = req_with(vec![]);
            let mut c = ctx();
            mw.on_request(&mut r, &mut c);
            assert!(ids.insert(c.request_id), "duplicate id generated");
        }
    }

    #[test]
    fn valid_request_id_rules() {
        assert!(valid_request_id("abc-123_XYZ"));
        assert!(!valid_request_id(""));
        assert!(!valid_request_id(&"x".repeat(65)));
        assert!(!valid_request_id("has space"));
        assert!(!valid_request_id("has\nnewline"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd rproxy && cargo test observe:: 2>&1 | tail -20`
Expected: compile error (types not defined).

- [ ] **Step 3: Write `observe.rs`**

Implement per the design notes above. `valid_request_id`:

```rust
pub fn valid_request_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
```

`RequestId::new()` seeds from `SystemTime::now().duration_since(UNIX_EPOCH)` (nanos, truncated to `u64`). Access-log line format:

```rust
fn on_response(&self, ctx: &ReqCtx, resp: &mut ResponseHead) {
    let dur = ctx.started.elapsed();
    let user = ctx.identity.as_deref().unwrap_or("-");
    let upstream = ctx.upstream.as_deref().unwrap_or("-");
    let backend = ctx.backend.as_deref().unwrap_or("-");
    let rejected = ctx.rejected_by.map(|r| format!(" rejected_by={r}")).unwrap_or_default();
    println!(
        "id={} peer={} method={} target={} status={} dur={:.1}ms upstream={} backend={} user={}{}",
        ctx.request_id, ctx.peer, ctx.method, ctx.target, resp.status,
        dur.as_secs_f64() * 1000.0, upstream, backend, user, rejected,
    );
}
```

Add `pub mod observe;` to `middleware/mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test observe:: 2>&1 | tail -10`
Expected: 7 passed. Then `cargo test 2>&1 | tail -3` → 115 passed.

- [ ] **Step 5: Stop and report for review**

---

## Task 3: Authentication and authorization (`auth.rs`)

**Files:**
- Create: `rproxy/src/middleware/auth.rs`
- Modify: `rproxy/src/middleware/mod.rs` (add `pub mod auth;`)
- Test: in `auth.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: `Middleware`, `Decision`, `Rejection`, `ReqCtx` from Task 1; `http::header`.
- Produces:
  - `pub fn base64_decode(s: &str) -> Option<Vec<u8>>`
  - `pub fn ct_eq(a: &[u8], b: &[u8]) -> bool` — constant-time within equal lengths; returns false fast only on length mismatch (length is not secret here — credentials vary in length by construction)
  - `pub enum Credential { Basic { user: String, pass: String }, Bearer { token: String, label: String } }`
  - `pub struct Auth { creds: Vec<Credential>, realm: String }` implementing `Middleware` — 401
  - `pub struct Authz { allowed: Vec<String> }` implementing `Middleware` — 403

Design notes:
- `Auth::on_request`: read `Authorization`. For `Basic <b64>`: decode, split on first `:` into user/pass, compare against each `Basic` credential with `ct_eq` on **both** user and pass. For `Bearer <token>`: compare against each `Bearer` credential's token. Success sets `ctx.identity = Some(user_or_label)` and returns `Continue`. Any failure (missing header, wrong scheme, bad base64, no match) returns the **same** 401 with `WWW-Authenticate: Basic realm="{realm}"` and no distinguishing detail (no username oracle).
- `Authz::on_request`: if `ctx.identity` is in `allowed`, `Continue`; else `Reject` 403. If `identity` is `None`, 403 with a comment noting startup validation makes this branch unreachable in a valid config.
- 401 `Rejection` carries `headers: vec![("WWW-Authenticate".into(), format!("Basic realm=\"{}\"", realm))]`, body `"401 Unauthorized\n"`.

- [ ] **Step 1: Write the failing tests** — tests 6–14 from the spec plus base64/ct_eq units:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{RequestHead, Version};
    use crate::middleware::{Middleware, Decision, ReqCtx, Rejection};

    fn basic_header(user: &str, pass: &str) -> String {
        // Build a valid "Basic <b64(user:pass)>" the same way a client would.
        let raw = format!("{user}:{pass}");
        format!("Basic {}", base64_encode_for_test(raw.as_bytes()))
    }
    // A tiny encoder used ONLY by tests to build inputs for the real decoder.
    fn base64_encode_for_test(data: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
            out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
        }
        out
    }
    fn req(auth: Option<&str>) -> RequestHead {
        let headers = auth.map(|a| vec![("Authorization".into(), a.into())]).unwrap_or_default();
        RequestHead { method: "GET".into(), target: "/".into(), version: Version::Http11, headers }
    }
    fn ctx() -> ReqCtx {
        ReqCtx::new("127.0.0.1:1".parse().unwrap(), "GET".into(), "/".into(), None)
    }
    fn basic_auth() -> Auth {
        Auth { creds: vec![Credential::Basic { user: "admin".into(), pass: "s3cret".into() }], realm: "ferrum".into() }
    }

    #[test]
    fn valid_basic_passes_and_sets_identity() {
        let mut c = ctx();
        let mut r = req(Some(&basic_header("admin", "s3cret")));
        assert!(matches!(basic_auth().on_request(&mut r, &mut c), Decision::Continue));
        assert_eq!(c.identity.as_deref(), Some("admin"));
    }

    #[test]
    fn wrong_password_401() {
        let mut c = ctx();
        let mut r = req(Some(&basic_header("admin", "wrong")));
        match basic_auth().on_request(&mut r, &mut c) {
            Decision::Reject(Rejection { status, .. }) => assert_eq!(status, 401),
            _ => panic!("expected 401"),
        }
    }

    #[test]
    fn unknown_user_401_no_oracle() {
        let mut c = ctx();
        let mut r = req(Some(&basic_header("ghost", "s3cret")));
        let d = basic_auth().on_request(&mut r, &mut c);
        let Decision::Reject(bad_user) = d else { panic!() };
        let mut c2 = ctx();
        let mut r2 = req(Some(&basic_header("admin", "wrong")));
        let Decision::Reject(bad_pass) = basic_auth().on_request(&mut r2, &mut c2) else { panic!() };
        // Same status and body: no way to tell "no such user" from "bad pass".
        assert_eq!(bad_user.status, bad_pass.status);
        assert_eq!(bad_user.body, bad_pass.body);
    }

    #[test]
    fn missing_auth_401_with_challenge() {
        let mut c = ctx();
        let mut r = req(None);
        match basic_auth().on_request(&mut r, &mut c) {
            Decision::Reject(rej) => {
                assert_eq!(rej.status, 401);
                let chal = rej.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("www-authenticate"));
                assert!(chal.unwrap().1.contains("realm=\"ferrum\""));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn malformed_base64_401_not_panic() {
        let mut c = ctx();
        let mut r = req(Some("Basic !!!not base64!!!"));
        assert!(matches!(basic_auth().on_request(&mut r, &mut c), Decision::Reject(_)));
    }

    #[test]
    fn basic_payload_without_colon_401() {
        let mut c = ctx();
        let mut r = req(Some(&format!("Basic {}", base64_encode_for_test(b"nocolon"))));
        assert!(matches!(basic_auth().on_request(&mut r, &mut c), Decision::Reject(_)));
    }

    #[test]
    fn wrong_scheme_401() {
        let mut c = ctx();
        let mut r = req(Some("Bearer sometoken"));
        assert!(matches!(basic_auth().on_request(&mut r, &mut c), Decision::Reject(_)));
    }

    #[test]
    fn valid_bearer_passes() {
        let auth = Auth { creds: vec![Credential::Bearer { token: "tok123".into(), label: "svc".into() }], realm: "ferrum".into() };
        let mut c = ctx();
        let mut r = req(Some("Bearer tok123"));
        assert!(matches!(auth.on_request(&mut r, &mut c), Decision::Continue));
        assert_eq!(c.identity.as_deref(), Some("svc"));
        let mut c2 = ctx();
        let mut r2 = req(Some("Bearer wrong"));
        assert!(matches!(auth.on_request(&mut r2, &mut c2), Decision::Reject(_)));
    }

    #[test]
    fn base64_decoder_roundtrip_and_rejects_garbage() {
        assert_eq!(base64_decode(&base64_encode_for_test(b"hello")).unwrap(), b"hello");
        assert_eq!(base64_decode(&base64_encode_for_test(b"any:pw")).unwrap(), b"any:pw");
        assert!(base64_decode("bad!char").is_none());
        assert!(base64_decode("====").is_none());
    }

    #[test]
    fn ct_eq_correctness() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn authz_allows_and_denies_403() {
        let authz = Authz { allowed: vec!["admin".into()] };
        let mut c = ctx();
        c.identity = Some("admin".into());
        assert!(matches!(authz.on_request(&mut req(None), &mut c), Decision::Continue));

        let mut c2 = ctx();
        c2.identity = Some("intern".into());
        match authz.on_request(&mut req(None), &mut c2) {
            Decision::Reject(Rejection { status, .. }) => assert_eq!(status, 403),
            _ => panic!("expected 403, not 401 — authenticated but not permitted"),
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd rproxy && cargo test auth:: 2>&1 | tail -20`
Expected: compile error.

- [ ] **Step 3: Write `auth.rs`**

Base64 decoder (standard alphabet, requires padding to a multiple of 4, rejects invalid chars, handles `=` only as trailing padding):

```rust
/// Decode standard base64 (with '+' '/' and '=' padding). Returns None on any
/// invalid input rather than being lenient — a malformed credential is a 401,
/// and leniency in a decoder that guards auth is how you get bypasses.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.as_bytes();
    if s.is_empty() || s.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let pad = chunk.iter().filter(|&&b| b == b'=').count();
        if pad > 2 {
            return None;
        }
        // Padding may only be trailing.
        if chunk[..4 - pad].iter().any(|&b| b == b'=') {
            return None;
        }
        let mut n = 0u32;
        for &b in &chunk[..4 - pad] {
            n = (n << 6) | val(b)? as u32;
        }
        // Pad the accumulator for the missing sextets.
        n <<= 6 * pad;
        out.push((n >> 16) as u8);
        if pad < 2 { out.push((n >> 8) as u8); }
        if pad < 1 { out.push(n as u8); }
    }
    Some(out)
}

/// Compare two byte slices without early-exit on the first differing byte.
/// Length mismatch is not secret (credentials differ in length by design), so
/// we bail on that; within equal lengths we accumulate all differences so the
/// running time does not depend on WHERE the mismatch is.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
```

`Auth::on_request` and `Authz::on_request` per the design notes. A `reject_401(&self)` helper builds the shared 401 `Rejection` so every failure path is byte-identical.

Add `pub mod auth;` to `middleware/mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test auth:: 2>&1 | tail -10`
Expected: 12 passed. Then `cargo test 2>&1 | tail -3` → 127 passed.

- [ ] **Step 5: Stop and report for review**

---

## Task 4: Rate limiting (`ratelimit.rs`)

**Files:**
- Create: `rproxy/src/middleware/ratelimit.rs`
- Modify: `rproxy/src/middleware/mod.rs` (add `pub mod ratelimit;`)
- Test: in `ratelimit.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: `Middleware`, `Decision`, `Rejection`, `ReqCtx` from Task 1.
- Produces:
  - `pub struct Limiter { rate: f64, burst: f64, shards: Vec<Mutex<HashMap<IpAddr, Bucket>>> }` with:
    - `pub fn new(rate: f64, burst: f64) -> Self` (16 shards)
    - `pub fn allow(&self, ip: IpAddr, now: Instant) -> Result<(), u64>` — `Ok(())` if a token was spent, `Err(retry_after_secs)` otherwise
  - `pub struct RateLimit { limiter: Arc<Limiter> }` implementing `Middleware` — 429

Design notes:
- `Bucket { tokens: f64, last_refill: Instant }`, private.
- `allow`: lock `shards[hash(ip) % 16]`; get-or-insert a full bucket (`tokens = burst`); refill: `elapsed = (now - last_refill).as_secs_f64(); tokens = (tokens + elapsed * rate).min(burst); last_refill = now;`. If `tokens >= 1.0` spend one, `Ok`; else `retry = ceil((1.0 - tokens) / rate) as u64` min 1, `Err(retry)`.
- Eviction: define `const SHARD_CAP: usize = 4096;`. On insert into a shard at cap, retain only entries that are not (full AND idle past a TTL, say 10× the refill-to-full time or a flat 60s); comment that a full bucket carries no rate info. If still at cap after the retain (nothing evictable), allow the request (fail open) and skip insert.
- `RateLimit::on_request`: `match self.limiter.allow(ctx.peer.ip(), Instant::now())` → `Ok` = `Continue`; `Err(secs)` = `Reject` 429 with `Retry-After: {secs}`, body `"429 Too Many Requests\n"`. Comment: key is `ctx.peer.ip()`, never XFF — the socket IP is the one unforgeable identity.

- [ ] **Step 1: Write the failing tests** — spec tests 15–22:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

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
        // A different IP is unaffected.
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
    fn shard_cap_evicts_full_idle_keeps_active() {
        let lim = Limiter::new(1000.0, 1000.0);
        let base = Instant::now();
        // Fill one shard's worth of distinct IPs that all end full+idle.
        // Then an active IP must still get a bucket. We can't force the hash,
        // so drive many IPs and assert no panic + the active IP works.
        for i in 0..(SHARD_CAP * 2) {
            let a = ip(&format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255));
            let _ = lim.allow(a, base);
        }
        // Long after, an active IP still succeeds (fail-open or eviction both OK).
        let later = base + Duration::from_secs(3600);
        assert!(lim.allow(ip("172.16.0.1"), later).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_allow_no_panic() {
        let lim = std::sync::Arc::new(Limiter::new(100.0, 100.0));
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
        for h in handles { h.await.unwrap(); }
        // Never more than burst allowed at a single instant: hard to assert
        // exactly under concurrency, so we assert liveness (no deadlock/panic).
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd rproxy && cargo test ratelimit:: 2>&1 | tail -20`
Expected: compile error.

- [ ] **Step 3: Write `ratelimit.rs`** per the design notes. Use `std::sync::Mutex`. Hash the IP with `std::hash::{Hash, Hasher}` via `std::collections::hash_map::DefaultHasher`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test ratelimit:: 2>&1 | tail -10`
Expected: 7 passed. Then `cargo test 2>&1 | tail -3` → 134 passed.

- [ ] **Step 5: Stop and report for review**

---

## Task 5: Config parsing, chain assembly, and wiring into Route

**Files:**
- Modify: `rproxy/src/middleware/mod.rs` (add `MiddlewareConfig`, `from_options`, `build`, `describe`)
- Modify: `rproxy/src/router.rs` (partition options; `Route` gains `chain`; `resolve_route`; `catch_all`)
- Modify: `rproxy/src/rewrite.rs` (`from_options` stops erroring on unknown keys — see below)
- Modify: `rproxy/src/main.rs` (`--no-request-id`, `--no-access-log`; pass flags through; chain summary print)
- Test: in `middleware/mod.rs` and `router.rs` `#[cfg(test)]`

**Interfaces:**
- Produces:
  - In `middleware/mod.rs`:
    - `pub const L6_KEYS: &[&str] = &["auth", "realm", "require-user", "rate", "burst"];` — note `realm` and `require-user`; used by the partition. (Six option *spellings*, five keys plus `realm`.)
    - `pub struct MiddlewareConfig { creds, realm, require_user, rate, burst, request_id: bool, access_log: bool }`
    - `pub fn from_options(opts: &str, request_id: bool, access_log: bool) -> io::Result<MiddlewareConfig>` — parses only L6 keys, errors on the validation cases
    - `pub fn build(&self) -> Chain` — assembles boxed middleware in the fixed order, skipping disabled ones
    - `pub fn describe(&self) -> String` — the summary fragment for the startup line
- Consumes: `RequestId`, `AccessLog` (Task 2), `Auth`, `Authz`, `Credential` (Task 3), `RateLimit`, `Limiter` (Task 4).

**The parser partition (the load-bearing change).** In `router.rs::resolve_route`, the severed `m.options` string is split by `;` and each segment's key checked: L5 keys (`strip`, `prefix`, `host`, `set-header`, `set-resp-header`, `remove-header`, `remove-resp-header`) go to one string, `L6_KEYS` to another, and a key in neither is an error *here* (so the error message can name it once). Then:
- `RewriteRules::from_options(l5_opts, forwarded)` — **and `rewrite.rs` changes its `other =>` arm from an error to `continue`/ignore**, because the partition already guarantees only L5 keys reach it. Leave a comment in `rewrite.rs` explaining the arbiter moved to the partition. (Its existing option-parsing tests that assert an unknown key errors must move to the router partition test — see Step 1.)
- `MiddlewareConfig::from_options(l6_opts, request_id, access_log)` then `.build()` → `Chain`.

Startup validations (all `io::Error`, surfaced as exit 1):
- `require-user` present but `creds` empty → `"require-user needs an auth= on the same route"`.
- `rate` parse: `N/s` or `N/m`; `rate=0` → error; malformed → error.
- `burst=0` → error; default burst when `rate` set but no `burst` = `max(1, rate_per_sec.ceil())`.
- `auth=` unknown scheme → error; `auth=basic:` without a second `:` → error (split on first two colons: `basic`, then `user`, then rest = pass; if fewer than 2 colons after `basic`, error).

**`Route` change:** add `pub chain: Chain,`. `catch_all` builds a default `MiddlewareConfig { request_id: true, access_log: true, .. }.build()`. Since `catch_all` currently takes no flag args, add `chain` by having `build_routes` set it (it already special-cases the two catch-all defaults and sets `route.rules.forwarded`); give `catch_all` a default chain and let `build_routes` overwrite it when `--no-request-id`/`--no-access-log` are set — mirror exactly how `route.rules.forwarded` is handled at `main.rs:204-211`.

- [ ] **Step 1: Write the failing tests** — spec tests 29–33, plus the moved unknown-key test:

```rust
// in middleware/mod.rs tests
#[test]
fn parses_all_l6_options() {
    let c = from_options("auth=basic:admin:pw;auth=bearer:tok;realm=api;require-user=admin;rate=100/s;burst=200", true, true).unwrap();
    assert_eq!(c.creds.len(), 2);
    assert_eq!(c.realm, "api");
    assert_eq!(c.require_user, vec!["admin"]);
    assert_eq!(c.rate, Some(100.0));
    assert_eq!(c.burst, Some(200.0));
}
#[test]
fn rate_per_minute() {
    let c = from_options("rate=60/m", true, true).unwrap();
    assert_eq!(c.rate, Some(1.0)); // 60/min = 1/s
}
#[test]
fn require_user_without_auth_errors() {
    assert!(from_options("require-user=admin", true, true).is_err());
}
#[test]
fn rate_zero_errors() {
    assert!(from_options("rate=0/s", true, true).is_err());
}
#[test]
fn burst_zero_errors() {
    assert!(from_options("rate=10/s;burst=0", true, true).is_err());
}
#[test]
fn malformed_rate_errors() {
    assert!(from_options("rate=abc", true, true).is_err());
    assert!(from_options("rate=10/x", true, true).is_err());
}
#[test]
fn unknown_auth_scheme_errors() {
    assert!(from_options("auth=digest:x:y", true, true).is_err());
}
#[test]
fn basic_without_colon_errors() {
    assert!(from_options("auth=basic:nocolon", true, true).is_err());
}
#[test]
fn basic_password_may_contain_colon() {
    let c = from_options("auth=basic:admin:p:ss", true, true).unwrap();
    // split on first two colons: user=admin, pass="p:ss"
    match &c.creds[0] {
        crate::middleware::auth::Credential::Basic { user, pass } => {
            assert_eq!(user, "admin"); assert_eq!(pass, "p:ss");
        }
        _ => panic!(),
    }
}
#[test]
fn default_burst_is_one_second_of_rate() {
    let c = from_options("rate=50/s", true, true).unwrap();
    assert_eq!(c.burst, Some(50.0));
}
```

```rust
// in router.rs tests
#[test]
fn l5_and_l6_options_compose() {
    let ups = std::collections::HashMap::new();
    let r = resolve_route("/api/**=127.0.0.1:9002;strip=/api;auth=basic:u:p;rate=10/s", &ups, true).unwrap();
    assert!(r.rules.strip.is_some());       // L5 parsed
    // L6 chain built (auth + ratelimit present) — assert via describe():
    let d = r.chain.describe();
    assert!(d.contains("auth") && d.contains("ratelimit"));
}
#[test]
fn unknown_option_still_errors_after_partition() {
    let ups = std::collections::HashMap::new();
    assert!(resolve_route("/=127.0.0.1:9000;bogus=1", &ups, true).is_err());
}
#[test]
fn no_options_gets_default_chain() {
    let ups = std::collections::HashMap::new();
    let r = resolve_route("/=127.0.0.1:9000", &ups, true).unwrap();
    let d = r.chain.describe();
    assert!(d.contains("log") && d.contains("request-id"));
    assert!(!d.contains("auth"));
}
```

For `--no-request-id`/`--no-access-log` propagation to defaults (spec test 33), add a test in `main.rs` or assert through `build_routes` if reachable; if `build_routes` is private, add a `#[cfg(test)]` check in `router.rs` that a `MiddlewareConfig` with `request_id: false` builds a chain whose `describe()` omits `request-id`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd rproxy && cargo test 2>&1 | tail -20`
Expected: compile errors (`chain` field, `from_options`, `describe` missing).

- [ ] **Step 3: Implement**

Write `MiddlewareConfig`, `from_options`, `build`, `describe` in `middleware/mod.rs`. Add the option partition and `chain` field in `router.rs`. Change `rewrite.rs` `from_options` `other =>` arm to ignore unknown keys (with comment), and move/delete its unknown-key assertion test. Add the two flags in `main.rs` and thread them through `build_routes` → `resolve_route` and the two catch-all branches. Add the chain summary to the startup route print.

Note the signature change: `resolve_route` and `build_routes` gain `request_id: bool, access_log: bool` parameters (alongside the existing `forwarded: bool`). Update all call sites and existing tests that call `resolve_route`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test 2>&1 | tail -5`
Expected: ~147 passed (134 + ~13 new).

- [ ] **Step 5: Stop and report for review**

---

## Task 6: Wire the chain into serve_one + rejection drain

**Files:**
- Modify: `rproxy/src/proxy.rs` (`serve_one`, `respond_error`, new `drain_body` + `send_rejection`)
- Test: in `proxy.rs` `#[cfg(test)]` (drain tests) + live verification

**Interfaces:**
- Consumes: `middleware::{ReqCtx, Chain, Rejection}`, `route.chain`.

**Placement in `serve_one`** (exact order, per spec):
1. After the route match (`routes.find_route` returns the `Route`) and after capturing `original_target`/`original_host`, build `ctx = ReqCtx::new(peer, method.clone(), req.target.clone(), original_host.clone())`.
2. `match route.chain.run_request(&mut req, &mut ctx)`:
   - `Err((idx, rej))`: drain the request body (bounded), build a `ResponseHead` from `rej`, run `route.chain.run_response(&ctx, &mut resp, idx)`, write it, and return `Ok(keep_alive)` where `keep_alive` is false if we closed. **No lease, no connect, no breaker.**
   - `Ok(())`: continue to the existing balance+connect block.
3. After the pool pick, set `ctx.upstream = Some(upstream.name().into())` and `ctx.backend = Some(addr.clone())`.
4. After reading the response head and computing `resp_framing`, but before `strip_hop_by_hop(&mut resp.headers)` and `apply_response`, run `route.chain.run_response_all(&ctx, &mut resp)`.

**The drain** (`drain_body`): read up to `REJECT_DRAIN_CAP = 64 * 1024` bytes of the request body using the already-computed `req_framing`, discarding into a sink. Returns whether the connection is still usable (true if fully drained within cap, false if it hit the cap). Implementation reuses `Conn::copy_body_to` with a counting/limited sink, OR a dedicated bounded reader. Simplest correct approach: since `copy_body_to` streams to a `W: AsyncWrite`, pass a `tokio::io::sink()` wrapped to stop after N bytes — but `sink()` has no limit. Instead write a small loop mirroring `copy_body_to`'s cases but discarding and counting. Given complexity, add a method:

```rust
impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    /// Discard up to `cap` bytes of a request body for a short-circuited
    /// request. Returns true if the whole body was consumed within the cap
    /// (connection reusable), false if the cap was hit (caller must close).
    ///
    /// Why drain at all: unread bytes in the socket when we close cause a TCP
    /// RST, which can nuke the rejection response we just wrote. Draining lets
    /// us send a clean FIN — or keep-alive, which a 401 challenge needs.
    pub async fn drain_body(&mut self, framing: BodyFraming, cap: u64) -> io::Result<bool> {
        let mut sink = tokio::io::sink();
        match framing {
            BodyFraming::None => Ok(true),
            BodyFraming::Length(n) if n <= cap => {
                self.copy_exact(&mut sink, n).await?;
                Ok(true)
            }
            BodyFraming::Length(_) => Ok(false), // over cap: don't read, signal close
            BodyFraming::Chunked => {
                // Drain chunk-by-chunk, stop if we exceed cap. Reuse read_line
                // + copy_exact, discarding. On overflow, return false.
                self.drain_chunked_capped(&mut sink, cap).await
            }
            BodyFraming::UntilClose => Ok(false), // not valid for requests, be safe
        }
    }
}
```

`drain_chunked_capped` mirrors `copy_chunked` but counts bytes and bails to `Ok(false)` past `cap`. `copy_exact` is currently private — it stays in the same module so `drain_body` can call it.

`send_rejection`: build `ResponseHead { version: Http11, status: rej.status, reason: rej.reason.into(), headers }` where headers = `rej.headers` + `Content-Type: text/plain` + `Content-Length` + `Connection: keep-alive|close`. Run the reverse response pass on it, then write head + body.

**`respond_error` extension:** add an `extra_headers: &[(String, String)]` parameter (or a sibling `respond_error_with`) so rejection responses can carry `WWW-Authenticate`/`Retry-After`/`X-Request-Id`. Update the 3 existing `respond_error` call sites (408, 400, 404, 502, 504) to pass `&[]`.

**Remove** the redundant `println!("[{peer}]   -> {} {}", resp.status, resp.reason)` line — the access-log middleware now emits status. Keep the balancer pick line.

- [ ] **Step 1: Write the failing tests** (drain, spec tests 34–35):

```rust
#[tokio::test]
async fn drain_length_body_within_cap_keeps_alive() {
    let mut conn = conn_with(b"hello").await; // 5 bytes
    let usable = conn.drain_body(BodyFraming::Length(5), 64 * 1024).await.unwrap();
    assert!(usable);
}

#[tokio::test]
async fn drain_oversized_length_signals_close() {
    // A 100 KB body against a 1 KB cap: we don't read it, we signal close.
    let mut conn = conn_with(&vec![b'x'; 1024]).await;
    let usable = conn.drain_body(BodyFraming::Length(100 * 1024), 1024).await.unwrap();
    assert!(!usable);
}

#[tokio::test]
async fn drain_then_next_request_parses() {
    // A rejected POST body followed by a pipelined GET: after draining the
    // body, the next request head must parse cleanly.
    let mut conn = conn_with(b"helloGET /next HTTP/1.1\r\n\r\n").await;
    let usable = conn.drain_body(BodyFraming::Length(5), 64 * 1024).await.unwrap();
    assert!(usable);
    let head = conn.read_head().await.unwrap().unwrap();
    assert!(head.starts_with(b"GET /next"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd rproxy && cargo test proxy:: 2>&1 | tail -15`
Expected: compile error (`drain_body` not defined).

- [ ] **Step 3: Implement** `drain_body`, `drain_chunked_capped`, `send_rejection`, the `respond_error` header param, and the four `serve_one` insertion points. Wire `ctx` through.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rproxy && cargo test 2>&1 | tail -5`
Expected: ~150 passed. Then `cargo build --release 2>&1 | grep -c warning` → should be ≤4 (no new warnings vs. the pre-existing baseline; ideally the wiring clears the middleware-unused warnings, leaving the original 4).

- [ ] **Step 5: Stop and report for review**

---

## Task 7: Live verification, docs, quiz

**Files:**
- Modify: `PROGRESS.md` (Level 6 section + tracker row + session log)
- No code changes unless verification surfaces a bug.

- [ ] **Step 1: Build and start a test backend + proxy**

```bash
cd rproxy && cargo build --release
# Python echo backend that reports method, path, headers:
python3 -c '
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do(self):
        b = json.dumps({"path": self.path, "headers": dict(self.headers)}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    do_GET = do_POST = do
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 9001), H).serve_forever()
' &
./target/release/rproxy 127.0.0.1:8080 \
  '/admin/**=127.0.0.1:9001;auth=basic:admin:s3cret;require-user=admin;rate=5/s' \
  '/api/**=127.0.0.1:9001;strip=/api;rate=3/s;burst=3' \
  '/health=127.0.0.1:9001' \
  '/=127.0.0.1:9001' &
```

- [ ] **Step 2: Run the verification checklist** (record actual output for each):

```bash
# Request ID present on every response, echoed when valid, replaced when hostile:
curl -sD- http://127.0.0.1:8080/health -o /dev/null | grep -i x-request-id
curl -sD- -H 'X-Request-Id: trace-abc' http://127.0.0.1:8080/health -o /dev/null | grep -i x-request-id   # -> trace-abc
curl -sD- -H $'X-Request-Id: evil\r\ninjected' http://127.0.0.1:8080/health -o /dev/null | grep -i x-request-id  # -> generated, not "evil"

# Auth: 401 without creds (with challenge), 200 with, 401 wrong pass:
curl -sD- http://127.0.0.1:8080/admin/x -o /dev/null | grep -iE 'HTTP/|www-authenticate'   # 401 + WWW-Authenticate
curl -sD- -u admin:s3cret http://127.0.0.1:8080/admin/x -o /dev/null | grep HTTP            # 200
curl -sD- -u admin:wrong  http://127.0.0.1:8080/admin/x -o /dev/null | grep HTTP            # 401

# Authz: an authenticated non-allowed user -> 403 (needs a second cred to test;
# add ;auth=basic:intern:pw but NOT require-user=intern to a scratch route).

# Rate limit: flood /api (burst 3, 3/s) -> 200s then 429 with Retry-After:
for i in $(seq 1 8); do curl -s -o /dev/null -w "%{http_code} " http://127.0.0.1:8080/api/x; done; echo
curl -sD- http://127.0.0.1:8080/api/x -o /dev/null | grep -i retry-after   # after exhaustion

# THE ORDERING PROOF: flood /admin WITHOUT creds. Rate-limit is before auth,
# so once the bucket empties we get 429, not 401:
for i in $(seq 1 8); do curl -s -o /dev/null -w "%{http_code} " http://127.0.0.1:8080/admin/x; done; echo
# Expected: 401 401 401 401 401 429 429 429  (5 buckets of 401-challenge, then 429)
```

Expected results (assert each):
- Every response carries `X-Request-Id`; valid inbound echoed; CRLF-bearing one replaced.
- 401 carries `WWW-Authenticate: Basic realm="ferrum"`; correct creds → 200; wrong → 401.
- `/api` flood: three 200s then 429 with `Retry-After`.
- `/admin` unauth flood: 401s until the rate bucket empties, then **429** — proving rate-limit sits outside auth.
- The backend's own stdout shows **no** request for any 401/429 (short-circuit cost nothing downstream).

- [ ] **Step 3: Startup-validation checks**

```bash
./target/release/rproxy 127.0.0.1:8081 '/x=127.0.0.1:9001;require-user=admin'; echo "exit=$?"  # exit 1
./target/release/rproxy 127.0.0.1:8081 '/x=127.0.0.1:9001;rate=0/s'; echo "exit=$?"            # exit 1
```

- [ ] **Step 4: Clean up processes**

```bash
pkill -f 'release/rproxy' ; pkill -f 'HTTPServer' ; pgrep -f rproxy || echo clean
```

- [ ] **Step 5: Update `PROGRESS.md`**

- Tracker row: Level 6 → 🟢 Implemented, with the module list, test count, and a one-line summary matching the L5 row's style.
- "Level 6 — what was built" section: the trait shape and *why sync*, the fixed order + rate-limit-before-auth rationale, the socket-IP key, the drain/RST reasoning, the parser partition, and the ordering proof from live verification.
- Level 6 quiz (8 questions) — mirror the L5 quiz style. Suggested questions:
  1. Why is the trait sync with a reverse `on_response` pass instead of the textbook async `handle(req, next) -> Response`? What would the async version cost here?
  2. The chain runs after routing, contradicting the KB's lifecycle diagram. Why is that forced, and what config feature makes it necessary?
  3. Rate-limit sits before auth. Give the attack this ordering defeats and the use case that would justify the opposite order.
  4. Why key the limiter on the socket IP and never on `X-Forwarded-For`? Show the two-part exploit if you keyed on XFF.
  5. A rejected request never takes a balancer lease. Why does that matter for the circuit breaker during a flood?
  6. Auth returns 401, authz returns 403. What breaks if authz returned 401?
  7. Why must a rejected request with a body be drained before the connection is reused *or* closed? Name the TCP mechanism.
  8. `require-user` with no `auth=` fails at startup. What would the route do at runtime if it were allowed?
- Session-log entry dated 2026-08-09.

- [ ] **Step 6: Stop and report** — final summary: test count, warning count, verification results, and that everything is uncommitted awaiting Vessey's commit decision.

---

## Self-Review

**Spec coverage** — every spec section maps to a task:
- Trait / Decision / Rejection / ReqCtx / Chain → Task 1 ✓
- Fixed order + reverse asymmetry → Task 1 (chain) + Task 6 (wiring) ✓
- Request ID + access log → Task 2 ✓
- Auth (Basic/Bearer, constant-time, 401+challenge) + Authz (403) → Task 3 ✓
- Rate limit (token bucket, sharded, lazy refill, eviction, socket-IP key, Retry-After) → Task 4 ✓
- Config surface, parser partition, startup validation, `--no-*` flags, chain summary → Task 5 ✓
- serve_one placement (after route, before lease; both legs), rejection drain + RST reasoning, respond_error headers, remove redundant println → Task 6 ✓
- Live verification (all checks incl. ordering proof), PROGRESS.md, quiz → Task 7 ✓
- Non-goals (compression, metrics, config-ordering, static composition, trusted-proxy) → not built, documented in spec ✓

**Placeholder scan** — no "TBD"/"handle appropriately"/"similar to Task N"; all code steps carry real code. ✓

**Type consistency** — `ReqCtx`, `Decision`, `Rejection`, `Chain::run_request` (returns `Result<(), (usize, Rejection)>`), `run_response(up_to)`, `run_response_all`, `Credential`, `Limiter::allow(ip, now) -> Result<(), u64>`, `MiddlewareConfig::from_options/build/describe`, `Conn::drain_body(framing, cap) -> bool`, `L6_KEYS`, `resolve_route(spec, upstreams, forwarded, request_id, access_log)` — names and signatures consistent across tasks. ✓

**Known cross-task edits called out:** `resolve_route`/`build_routes` gain two params (Task 5, updates existing tests); `rewrite.rs::from_options` unknown-key arm changes from error to ignore (Task 5, moves one test); `respond_error` gains a headers param (Task 6, updates 3–5 call sites); redundant status println removed (Task 6). ✓
