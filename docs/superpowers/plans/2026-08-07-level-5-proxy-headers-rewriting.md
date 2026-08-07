# Level 5 Proxy Headers & Rewriting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tell backends who really called (`X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`) and let each route rewrite the path, `Host`, and arbitrary request/response headers before forwarding.

**Architecture:** One new module `rewrite.rs` holding `RewriteRules` (parsed per-route config) and two pure, synchronous transforms — `apply_request(&mut RequestHead, &ForwardContext)` and `apply_response(&mut ResponseHead)`. No sockets, no async: the whole level unit-tests by building a head struct, applying rules, and asserting. `Route` gains a `rules: RewriteRules` field; `proxy.rs::serve_one` calls the transforms at two existing rewrite sites.

**Tech Stack:** Rust 2024, std only — no new dependencies.

**Design doc:** `docs/superpowers/specs/2026-08-07-level-5-proxy-headers-rewriting-design.md`

## Global Constraints

- **No new dependencies.** `Cargo.toml` gains nothing.
- **`rewrite.rs` is pure and synchronous.** No `async`, no sockets, no `tokio`. Both transforms operate on `&mut` head structs. This is what keeps the level testable without a network.
- **Transform ordering in `apply_request` is load-bearing and fixed:** (1) capture original `Host`, (2) path `strip` then `prefix`, (3) `Host` rewrite, (4) forwarded-header injection, (5) `set-header`/`remove-header`. Step 1 must precede step 3 or `X-Forwarded-Host` reports the rewritten value. Step 5 must come last so an explicit rule can deliberately override an injected header.
- **Call-site ordering in `proxy.rs` is fixed:** `strip_hop_by_hop` → `apply_request` → framing re-declaration. Never before hop-by-hop stripping (a client could smuggle a `Connection`-listed header we then re-add) and never after framing (a rule must not displace the framing headers we own).
- **Protected headers.** A `set-header`/`remove-header`/`set-resp-header`/`remove-resp-header` rule may NOT name `Content-Length`, `Transfer-Encoding`, `Connection`, or `Host`. This is a **startup error**, not a silent ignore — it would otherwise reopen the Level 1 request-smuggling holes.
- **XFF appends, `X-Real-IP` overwrites.** Never trust an inbound `X-Forwarded-For` by replacing it (that erases upstream proxies' record); never preserve an inbound `X-Real-IP` (a client-sent one is a forgery attempt with no multi-hop meaning).
- **Backward compatibility.** A route spec with no `;` options must parse exactly as before, and all 73 existing tests must pass. `--no-forwarded` must produce byte-identical backend headers to Level 4.
- **Teaching mode.** Heavy in-code comments explaining *why*, matching the density and tone of `balancer.rs` / `proxy.rs`.
- **Commit messages:** plain only. No `Co-Authored-By` trailer, no mention of Claude or "Generated with Claude Code". Commit with `git -c commit.gpgsign=false commit` (signing needs an unavailable passphrase).
- Run all cargo commands from `rproxy/`. Test command: `cargo test`.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `rproxy/src/rewrite.rs` | `RewriteRules`, `ForwardContext`, `apply_request`, `apply_response`, spec-option parser, all rewrite tests | **new** |
| `rproxy/src/http.rs` | gains `set_header` (overwrite-or-insert) | modify |
| `rproxy/src/router.rs` | `Route.rules`; sever `;` options before `=` split; pass options to the rewrite parser | modify |
| `rproxy/src/proxy.rs` | call `apply_request` / `apply_response` at the two rewrite sites; extend the log line | modify |
| `rproxy/src/main.rs` | `mod rewrite;`, `--no-forwarded` flag | modify |

---

### Task 1: `rewrite.rs` skeleton + forwarded-header injection

**Files:**
- Create: `rproxy/src/rewrite.rs`
- Modify: `rproxy/src/http.rs` (add `set_header` after `remove_header`, ~line 224)
- Modify: `rproxy/src/main.rs` (add `mod rewrite;`)
- Test: `rproxy/src/rewrite.rs` (`mod tests`)

**Interfaces:**
- Consumes: `http::{RequestHead, ResponseHead, Version, header, remove_header}`.
- Produces:
  - `pub fn http::set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str)`
  - `pub struct ForwardContext<'a> { pub client_ip: IpAddr, pub original_host: Option<&'a str>, pub scheme: &'static str }`
  - `pub struct RewriteRules { strip: Option<String>, prefix: Option<String>, host: Option<String>, set_headers: Vec<(String, String)>, remove_headers: Vec<String>, set_resp_headers: Vec<(String, String)>, remove_resp_headers: Vec<String>, forwarded: bool }` with `impl Default` (all `None`/empty, `forwarded: true`)
  - `RewriteRules::apply_request(&self, req: &mut RequestHead, ctx: &ForwardContext)`
  - `RewriteRules::apply_response(&self, resp: &mut ResponseHead)`
  - `RewriteRules::no_forwarded() -> RewriteRules` (test/CLI helper: default with `forwarded: false`)

- [ ] **Step 1: Write the failing tests**

Create `rproxy/src/rewrite.rs` with only this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{RequestHead, Version};
    use std::net::{IpAddr, Ipv4Addr};

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    fn req(headers: &[(&str, &str)]) -> RequestHead {
        RequestHead {
            method: "GET".to_string(),
            target: "/users".to_string(),
            version: Version::Http11,
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn ctx<'a>(original_host: Option<&'a str>) -> ForwardContext<'a> {
        ForwardContext { client_ip: CLIENT, original_host, scheme: "http" }
    }

    fn get<'a>(r: &'a RequestHead, name: &str) -> Option<&'a str> {
        crate::http::header(&r.headers, name)
    }

    // 1. XFF appends to an existing chain. The rightmost entry is the one we
    //    observed; everything left of it is hearsay from upstream proxies.
    #[test]
    fn xff_appends_to_existing_chain() {
        let mut r = req(&[("X-Forwarded-For", "1.2.3.4")]);
        RewriteRules::default().apply_request(&mut r, &ctx(None));
        assert_eq!(get(&r, "x-forwarded-for"), Some("1.2.3.4, 203.0.113.7"));
    }

    // 2. XFF is created when absent.
    #[test]
    fn xff_created_when_absent() {
        let mut r = req(&[]);
        RewriteRules::default().apply_request(&mut r, &ctx(None));
        assert_eq!(get(&r, "x-forwarded-for"), Some("203.0.113.7"));
    }

    // 3. A client-forged X-Real-IP must be OVERWRITTEN, not preserved: it is
    //    not a chain, so a client-supplied value is purely a forgery attempt.
    #[test]
    fn x_real_ip_overwrites_forgery() {
        let mut r = req(&[("X-Real-IP", "9.9.9.9")]);
        RewriteRules::default().apply_request(&mut r, &ctx(None));
        assert_eq!(get(&r, "x-real-ip"), Some("203.0.113.7"));
        assert_eq!(
            r.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("x-real-ip")).count(),
            1,
            "overwrite must not leave a duplicate"
        );
    }

    // 4. XFH/XFP are set when absent, and a legitimate upstream proxy's
    //    values are preserved (it knows the true original; we don't).
    #[test]
    fn xfh_xfp_set_when_absent_preserved_when_present() {
        let mut r = req(&[]);
        RewriteRules::default().apply_request(&mut r, &ctx(Some("example.com")));
        assert_eq!(get(&r, "x-forwarded-host"), Some("example.com"));
        assert_eq!(get(&r, "x-forwarded-proto"), Some("http"));

        let mut r2 = req(&[
            ("X-Forwarded-Host", "orig.example.com"),
            ("X-Forwarded-Proto", "https"),
        ]);
        RewriteRules::default().apply_request(&mut r2, &ctx(Some("example.com")));
        assert_eq!(get(&r2, "x-forwarded-host"), Some("orig.example.com"));
        assert_eq!(get(&r2, "x-forwarded-proto"), Some("https"));
    }

    // 6. --no-forwarded injects none of the four.
    #[test]
    fn no_forwarded_injects_nothing() {
        let mut r = req(&[]);
        RewriteRules::no_forwarded().apply_request(&mut r, &ctx(Some("example.com")));
        for h in ["x-forwarded-for", "x-real-ip", "x-forwarded-host", "x-forwarded-proto"] {
            assert_eq!(get(&r, h), None, "{h} must not be injected");
        }
    }

    // http::set_header overwrites rather than duplicating.
    #[test]
    fn set_header_overwrites() {
        let mut h = vec![("A".to_string(), "1".to_string()), ("B".to_string(), "2".to_string())];
        crate::http::set_header(&mut h, "a", "9");
        assert_eq!(crate::http::header(&h, "A"), Some("9"));
        assert_eq!(h.len(), 2, "must overwrite, not append");
    }
}
```

Note: test 5 (`X-Forwarded-Host` captures the original host even when `host=` rewrites it) lands in Task 3, once `host=` exists.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test rewrite:: 2>&1 | tail -20`
Expected: FAIL — `cannot find type RewriteRules`, `cannot find type ForwardContext`, `cannot find function set_header`.

- [ ] **Step 3: Add `http::set_header`**

In `rproxy/src/http.rs`, after `remove_header`:

```rust
/// Set a header, replacing any existing value(s) for that name. Overwrite
/// rather than append, so applying a rule twice (e.g. across a retry) can
/// never accumulate duplicates — and a duplicated header is exactly the
/// ambiguity the Level 1 parser works to reject.
pub fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    remove_header(headers, name);
    headers.push((name.to_string(), value.to_string()));
}
```

- [ ] **Step 4: Implement the module and injection**

Prepend to `rproxy/src/rewrite.rs` (above the test module):

```rust
//! Level 5 — proxy headers and rewriting.
//!
//! A forwarder relays bytes; a *reverse proxy* also tells the backend the
//! truth about the request's origin, and may present the backend a different
//! URL space than it shows the world. This module is both halves:
//!
//! - **Forwarded headers** (`X-Forwarded-For`, `X-Real-IP`,
//!   `X-Forwarded-Host`, `X-Forwarded-Proto`) — who really called.
//! - **Rewriting** (path, `Host`, arbitrary request/response headers) — what
//!   the backend sees.
//!
//! Everything here is a **pure synchronous transform over a head struct**: no
//! sockets, no async, no I/O. That is deliberate. It means the entire level is
//! testable by building a `RequestHead`, applying rules, and asserting on the
//! result — the same discipline that keeps Level 3's algorithms and Level 4's
//! breaker unit-testable.

use std::net::IpAddr;

use crate::http::{self, RequestHead, ResponseHead};

/// Per-connection facts the transform needs that a request head doesn't carry.
pub struct ForwardContext<'a> {
    /// The immediate peer's IP: the real client, or the last proxy in a chain.
    /// This is the one value in the forwarded headers that cannot be forged —
    /// we observed it on the socket.
    pub client_ip: IpAddr,
    /// The `Host` the client originally asked for, captured BEFORE any
    /// rewriting. See `apply_request` for why the capture must happen first.
    pub original_host: Option<&'a str>,
    /// Scheme on the client leg. `"http"` today; Level 8's TLS termination
    /// sets `"https"` here and `X-Forwarded-Proto` follows automatically.
    pub scheme: &'static str,
}

/// Parsed rewrite configuration for one route. `Default` injects the four
/// forwarded headers and changes nothing else, so a route declared with no
/// options behaves like Level 4 plus honest origin reporting.
#[derive(Clone, Debug, Default)]
pub struct RewriteRules {
    /// Path prefix to remove (`strip=/api`).
    pub strip: Option<String>,
    /// Path prefix to prepend (`prefix=/v2`), applied after `strip`.
    pub prefix: Option<String>,
    /// Replacement `Host` header value (`host=backend.local`).
    pub host: Option<String>,
    pub set_headers: Vec<(String, String)>,
    pub remove_headers: Vec<String>,
    pub set_resp_headers: Vec<(String, String)>,
    pub remove_resp_headers: Vec<String>,
    /// Whether to inject the forwarded headers. True by default; `--no-forwarded`
    /// clears it. Not `Default::default()` for `bool`, hence the manual impl
    /// below rather than deriving it on this field alone.
    pub forwarded: bool,
}

impl RewriteRules {
    /// Rules that inject the forwarded headers and do nothing else.
    pub fn new() -> RewriteRules {
        RewriteRules { forwarded: true, ..Default::default() }
    }

    /// Rules with forwarded-header injection disabled (`--no-forwarded`).
    pub fn no_forwarded() -> RewriteRules {
        RewriteRules { forwarded: false, ..Default::default() }
    }

    /// Transform the request head in place, in this fixed order:
    ///
    ///   1. (caller captured the original `Host` into `ctx` already)
    ///   2. path rewrite
    ///   3. `Host` rewrite
    ///   4. forwarded-header injection
    ///   5. explicit header rules
    ///
    /// Order 3-before-4 matters: `X-Forwarded-Host` must report what the
    /// *client* asked for, which is why it reads `ctx.original_host` rather
    /// than the (possibly rewritten) `Host` header.
    ///
    /// Order 5-last matters too: it lets an explicit `set-header` deliberately
    /// override an injected value — e.g. pinning `X-Forwarded-Proto: https`
    /// when an external TLS terminator sits in front of us.
    pub fn apply_request(&self, req: &mut RequestHead, ctx: &ForwardContext) {
        if self.forwarded {
            self.inject_forwarded(req, ctx);
        }
    }

    /// Inject the four forwarded headers. Append-vs-overwrite differs per
    /// header and each choice is a security decision — see the comments.
    fn inject_forwarded(&self, req: &mut RequestHead, ctx: &ForwardContext) {
        let ip = ctx.client_ip.to_string();

        // X-Forwarded-For: APPEND. Replacing would erase the chain recorded by
        // upstream proxies; *trusting* an inbound value would let any client
        // forge its own origin by sending `X-Forwarded-For: 1.2.3.4`.
        // Appending is honest either way: the rightmost entry is the address we
        // observed and cannot be forged, and everything left of it is hearsay.
        // The lesson for a backend reading XFF: count from the RIGHT, and know
        // how many proxies you sit behind.
        let xff = match http::header(&req.headers, "x-forwarded-for") {
            Some(existing) if !existing.trim().is_empty() => format!("{existing}, {ip}"),
            _ => ip.clone(),
        };
        http::set_header(&mut req.headers, "X-Forwarded-For", &xff);

        // X-Real-IP: OVERWRITE. Unlike XFF this is not a chain, so there is no
        // legitimate multi-hop value to preserve — a client-supplied one is
        // purely an attempt to spoof its own address.
        http::set_header(&mut req.headers, "X-Real-IP", &ip);

        // X-Forwarded-Host / -Proto: set only if ABSENT. A legitimate upstream
        // proxy's value is closer to the truth than ours (it spoke to the real
        // client), so we must not clobber it.
        if http::header(&req.headers, "x-forwarded-host").is_none() {
            if let Some(h) = ctx.original_host {
                http::set_header(&mut req.headers, "X-Forwarded-Host", h);
            }
        }
        if http::header(&req.headers, "x-forwarded-proto").is_none() {
            http::set_header(&mut req.headers, "X-Forwarded-Proto", ctx.scheme);
        }
    }

    /// Transform the response head in place. Only explicit header rules apply;
    /// there is nothing to "forward" back toward the client.
    pub fn apply_response(&self, resp: &mut ResponseHead) {
        let _ = resp; // filled in by Task 3
    }
}
```

Add `mod rewrite;` to `rproxy/src/main.rs` alongside the other module declarations (keep them alphabetical: `balancer`, `health`, `http`, `proxy`, `rewrite`, `router`).

Note on `Default`: deriving `Default` gives `forwarded: false`, which is the wrong default for the struct's meaning. Either write a manual `impl Default` setting `forwarded: true` and have `new()` call it, or keep the derive and ensure every construction path goes through `new()`. **Prefer the manual `impl Default`** so a stray `RewriteRules::default()` cannot silently disable forwarded headers:

```rust
impl Default for RewriteRules {
    fn default() -> RewriteRules {
        RewriteRules {
            strip: None,
            prefix: None,
            host: None,
            set_headers: Vec::new(),
            remove_headers: Vec::new(),
            set_resp_headers: Vec::new(),
            remove_resp_headers: Vec::new(),
            forwarded: true,
        }
    }
}
```
and remove `Default` from the `derive` list. Then `new()` is just `Default::default()` and `no_forwarded()` overrides the one field.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test 2>&1 | grep -E "test result:|error"`
Expected: PASS — `test result: ok. 79 passed` (73 existing + 6 new).

- [ ] **Step 6: Commit**

```bash
git add rproxy/src/rewrite.rs rproxy/src/http.rs rproxy/src/main.rs
git -c commit.gpgsign=false commit -m "Add forwarded-header injection (X-Forwarded-For, X-Real-IP, X-Forwarded-Host/Proto)"
```

---

### Task 2: Path rewriting (`strip` / `prefix`)

**Files:**
- Modify: `rproxy/src/rewrite.rs` (add `rewrite_path`, call it from `apply_request`)
- Test: `rproxy/src/rewrite.rs` (`mod tests`, append)

**Interfaces:**
- Consumes: `RewriteRules.strip` / `.prefix` (Task 1), `RequestHead.target`.
- Produces: no new public API — `apply_request` now also rewrites `req.target`.

- [ ] **Step 1: Write the failing tests**

Append to `mod tests`:

```rust
    fn rules_path(strip: Option<&str>, prefix: Option<&str>) -> RewriteRules {
        RewriteRules {
            strip: strip.map(str::to_string),
            prefix: prefix.map(str::to_string),
            ..Default::default()
        }
    }

    fn target_after(target: &str, strip: Option<&str>, prefix: Option<&str>) -> String {
        let mut r = req(&[]);
        r.target = target.to_string();
        rules_path(strip, prefix).apply_request(&mut r, &ctx(None));
        r.target
    }

    // 7. strip removes the prefix AND preserves the query string.
    #[test]
    fn strip_removes_prefix_keeping_query() {
        assert_eq!(target_after("/api/users?page=2", Some("/api"), None), "/users?page=2");
        assert_eq!(target_after("/api/users", Some("/api"), None), "/users");
    }

    // 8. Stripping the whole path yields "/", never "" — an empty request
    //    target is malformed and a backend would reject it.
    #[test]
    fn strip_whole_path_yields_root() {
        assert_eq!(target_after("/api", Some("/api"), None), "/");
        assert_eq!(target_after("/api?x=1", Some("/api"), None), "/?x=1");
    }

    // 9. A strip that doesn't match leaves the path untouched.
    #[test]
    fn strip_non_matching_is_noop() {
        assert_eq!(target_after("/other/users", Some("/api"), None), "/other/users");
    }

    // 10. prefix prepends; strip and prefix compose in the documented order
    //     (strip first, then prefix).
    #[test]
    fn prefix_prepends_and_composes_after_strip() {
        assert_eq!(target_after("/users", None, Some("/v2")), "/v2/users");
        assert_eq!(target_after("/api/users?a=b", Some("/api"), Some("/v2")), "/v2/users?a=b");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test rewrite::tests::strip 2>&1 | tail -15`
Expected: FAIL — targets come back unrewritten (e.g. `assertion failed: "/api/users?page=2" == "/users?page=2"`).

- [ ] **Step 3: Implement path rewriting**

Add to `impl RewriteRules`, and call it from `apply_request` **before** the forwarded injection:

```rust
    /// Rewrite the request target's path, preserving the query string.
    ///
    /// The query is split off first and re-appended after, so a `?` in the
    /// target can never be mangled by prefix arithmetic — and a backend that
    /// depends on its query parameters keeps getting them.
    fn rewrite_path(&self, target: &str) -> String {
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (target, None),
        };

        let mut out = path.to_string();

        // strip first, then prefix — the documented order. Stripping is a
        // no-op when the prefix doesn't match, which keeps a mis-scoped rule
        // from silently mangling unrelated paths.
        if let Some(s) = &self.strip {
            if let Some(rest) = out.strip_prefix(s.as_str()) {
                out = rest.to_string();
            }
        }
        if let Some(p) = &self.prefix {
            out = format!("{p}{out}");
        }

        // An empty target is malformed HTTP; stripping "/api" from exactly
        // "/api" must yield "/", not "".
        if out.is_empty() {
            out.push('/');
        } else if !out.starts_with('/') {
            out.insert(0, '/');
        }

        match query {
            Some(q) => format!("{out}?{q}"),
            None => out,
        }
    }
```

In `apply_request`, insert before the `if self.forwarded` block:

```rust
        // Path first: everything downstream (including the log line) should see
        // the target the backend will actually receive.
        if self.strip.is_some() || self.prefix.is_some() {
            req.target = self.rewrite_path(&req.target);
        }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test 2>&1 | grep -E "test result:|error"`
Expected: PASS — `test result: ok. 83 passed`.

- [ ] **Step 5: Commit**

```bash
git add rproxy/src/rewrite.rs
git -c commit.gpgsign=false commit -m "Add path rewriting (strip and prefix) preserving query strings"
```

---

### Task 3: Host rewriting + request/response header rules

**Files:**
- Modify: `rproxy/src/rewrite.rs` (Host rewrite in `apply_request`, header rules, fill in `apply_response`)
- Test: `rproxy/src/rewrite.rs` (`mod tests`, append)

**Interfaces:**
- Consumes: `RewriteRules.{host, set_headers, remove_headers, set_resp_headers, remove_resp_headers}` (declared in Task 1), `http::set_header` / `http::remove_header`.
- Produces: no new public API — `apply_request` gains Host+header rules; `apply_response` becomes functional.

- [ ] **Step 1: Write the failing tests**

Append to `mod tests`:

```rust
    // 5. THE ORDERING BUG THIS DESIGN EXISTS TO PREVENT: X-Forwarded-Host must
    //    report the host the CLIENT asked for, even though `host=` overwrites
    //    the Host header we send onward.
    #[test]
    fn xfh_reports_original_host_not_rewritten_one() {
        let mut r = req(&[("Host", "example.com")]);
        let rules = RewriteRules { host: Some("backend.local".to_string()), ..Default::default() };
        rules.apply_request(&mut r, &ctx(Some("example.com")));
        assert_eq!(get(&r, "host"), Some("backend.local"), "backend sees the rewritten Host");
        assert_eq!(
            get(&r, "x-forwarded-host"),
            Some("example.com"),
            "but X-Forwarded-Host must preserve what the client asked for"
        );
    }

    // 11. host= replaces the Host header.
    #[test]
    fn host_rewrite_replaces_host() {
        let mut r = req(&[("Host", "example.com")]);
        let rules = RewriteRules { host: Some("backend.local".to_string()), ..Default::default() };
        rules.apply_request(&mut r, &ctx(Some("example.com")));
        assert_eq!(get(&r, "host"), Some("backend.local"));
        assert_eq!(
            r.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("host")).count(),
            1,
            "exactly one Host header — duplicates are a smuggling vector"
        );
    }

    // 12. set-header overwrites rather than duplicating.
    #[test]
    fn set_header_rule_overwrites() {
        let mut r = req(&[("X-Env", "dev")]);
        let rules = RewriteRules {
            set_headers: vec![("X-Env".to_string(), "prod".to_string())],
            ..Default::default()
        };
        rules.apply_request(&mut r, &ctx(None));
        assert_eq!(get(&r, "x-env"), Some("prod"));
        assert_eq!(r.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("x-env")).count(), 1);
    }

    // 13. remove-header is case-insensitive.
    #[test]
    fn remove_header_rule_is_case_insensitive() {
        let mut r = req(&[("X-Secret", "shh")]);
        let rules = RewriteRules {
            remove_headers: vec!["x-secret".to_string()],
            ..Default::default()
        };
        rules.apply_request(&mut r, &ctx(None));
        assert_eq!(get(&r, "X-Secret"), None);
    }

    // Header rules run LAST, so an explicit rule can deliberately override an
    // injected forwarded header (e.g. behind an external TLS terminator).
    #[test]
    fn explicit_rule_overrides_injected_forwarded_header() {
        let mut r = req(&[]);
        let rules = RewriteRules {
            set_headers: vec![("X-Forwarded-Proto".to_string(), "https".to_string())],
            ..Default::default()
        };
        rules.apply_request(&mut r, &ctx(None));
        assert_eq!(get(&r, "x-forwarded-proto"), Some("https"));
    }

    // 14. Response header rules.
    #[test]
    fn response_header_rules_apply() {
        let mut resp = ResponseHead {
            version: Version::Http11,
            status: 200,
            reason: "OK".to_string(),
            headers: vec![
                ("Server".to_string(), "backend/1.0".to_string()),
                ("X-Cache".to_string(), "MISS".to_string()),
            ],
        };
        let rules = RewriteRules {
            set_resp_headers: vec![("X-Cache".to_string(), "HIT".to_string())],
            remove_resp_headers: vec!["server".to_string()],
            ..Default::default()
        };
        rules.apply_response(&mut resp);
        assert_eq!(crate::http::header(&resp.headers, "x-cache"), Some("HIT"));
        assert_eq!(crate::http::header(&resp.headers, "Server"), None);
    }
```

The `ResponseHead` construction must match the real struct — read `rproxy/src/http.rs` (the `ResponseHead` definition near line 30) and use its actual field names and types. Adjust the literal above if they differ.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test rewrite::tests 2>&1 | tail -20`
Expected: FAIL — Host unchanged, header rules not applied, `apply_response` a no-op.

- [ ] **Step 3: Implement Host rewrite and header rules**

Replace `apply_request`'s body so the full documented order is present:

```rust
    pub fn apply_request(&self, req: &mut RequestHead, ctx: &ForwardContext) {
        // 2. Path first: everything downstream (including the log line) should
        //    see the target the backend will actually receive.
        if self.strip.is_some() || self.prefix.is_some() {
            req.target = self.rewrite_path(&req.target);
        }

        // 3. Host rewrite. The ORIGINAL host was captured into `ctx` by the
        //    caller before we got here — that is what makes step 4's
        //    X-Forwarded-Host honest even though we clobber Host here.
        if let Some(h) = &self.host {
            http::set_header(&mut req.headers, "Host", h);
        }

        // 4. Forwarded headers.
        if self.forwarded {
            self.inject_forwarded(req, ctx);
        }

        // 5. Explicit header rules LAST, so they can intentionally override an
        //    injected value. Removals run before sets so a rule pair
        //    (remove X, set X) behaves predictably.
        for name in &self.remove_headers {
            http::remove_header(&mut req.headers, name);
        }
        for (name, value) in &self.set_headers {
            http::set_header(&mut req.headers, name, value);
        }
    }
```

And fill in `apply_response`:

```rust
    /// Transform the response head in place. Only explicit header rules apply;
    /// there is nothing to "forward" back toward the client.
    pub fn apply_response(&self, resp: &mut ResponseHead) {
        for name in &self.remove_resp_headers {
            http::remove_header(&mut resp.headers, name);
        }
        for (name, value) in &self.set_resp_headers {
            http::set_header(&mut resp.headers, name, value);
        }
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test 2>&1 | grep -E "test result:|error"`
Expected: PASS — `test result: ok. 89 passed`.

- [ ] **Step 5: Commit**

```bash
git add rproxy/src/rewrite.rs
git -c commit.gpgsign=false commit -m "Add Host rewriting and request/response header rules"
```

---

### Task 4: Spec-option parser + startup validation

**Files:**
- Modify: `rproxy/src/rewrite.rs` (add `RewriteRules::from_options`)
- Test: `rproxy/src/rewrite.rs` (`mod tests`, append)

**Interfaces:**
- Consumes: `RewriteRules` fields (Task 1).
- Produces: `RewriteRules::from_options(opts: &str, forwarded: bool) -> io::Result<RewriteRules>` — parses a `;`-separated option string (already severed from the route spec by Task 5) such as `strip=/api;host=backend.local;set-header=X-Env:prod`. An empty `opts` yields the default rules.

- [ ] **Step 1: Write the failing tests**

Append to `mod tests`:

```rust
    // 15. Every option parses, including combinations and surrounding space.
    #[test]
    fn options_parse() {
        let r = RewriteRules::from_options(
            " strip=/api ; prefix=/v2 ; host=backend.local ; set-header=X-Env:prod ; \
             remove-header=X-Secret ; set-resp-header=X-Cache:HIT ; remove-resp-header=Server ",
            true,
        )
        .unwrap();
        assert_eq!(r.strip.as_deref(), Some("/api"));
        assert_eq!(r.prefix.as_deref(), Some("/v2"));
        assert_eq!(r.host.as_deref(), Some("backend.local"));
        assert_eq!(r.set_headers, vec![("X-Env".to_string(), "prod".to_string())]);
        assert_eq!(r.remove_headers, vec!["X-Secret".to_string()]);
        assert_eq!(r.set_resp_headers, vec![("X-Cache".to_string(), "HIT".to_string())]);
        assert_eq!(r.remove_resp_headers, vec!["Server".to_string()]);
        assert!(r.forwarded);

        // Empty options -> defaults, forwarded honored.
        let d = RewriteRules::from_options("", true).unwrap();
        assert!(d.strip.is_none() && d.forwarded);
        let n = RewriteRules::from_options("", false).unwrap();
        assert!(!n.forwarded);

        // A header value may itself contain ':' (e.g. a URL).
        let u = RewriteRules::from_options("set-header=X-Url:http://a/b", true).unwrap();
        assert_eq!(u.set_headers[0].1, "http://a/b");
    }

    // 16. Errors: unknown option, empty values, malformed set-header, and each
    //     protected header name. Protected names are a HARD error: silently
    //     ignoring them would be a trap, and honoring them would reopen the
    //     Level 1 request-smuggling holes.
    #[test]
    fn options_reject_bad_input() {
        assert!(RewriteRules::from_options("bogus=1", true).is_err());
        assert!(RewriteRules::from_options("strip=", true).is_err());
        assert!(RewriteRules::from_options("prefix=", true).is_err());
        assert!(RewriteRules::from_options("host=", true).is_err());
        assert!(RewriteRules::from_options("set-header=NoColon", true).is_err());
        assert!(RewriteRules::from_options("remove-header=", true).is_err());
        for protected in ["Content-Length", "Transfer-Encoding", "Connection", "Host"] {
            assert!(
                RewriteRules::from_options(&format!("set-header={protected}:x"), true).is_err(),
                "set-header must reject {protected}"
            );
            assert!(
                RewriteRules::from_options(&format!("remove-header={protected}"), true).is_err(),
                "remove-header must reject {protected}"
            );
            assert!(
                RewriteRules::from_options(&format!("set-resp-header={protected}:x"), true).is_err(),
                "set-resp-header must reject {protected}"
            );
        }
        // Case-insensitively protected.
        assert!(RewriteRules::from_options("set-header=content-length:5", true).is_err());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test rewrite::tests::options 2>&1 | tail -10`
Expected: FAIL — `cannot find function from_options`.

- [ ] **Step 3: Implement the parser**

Add `use std::io;` to `rewrite.rs`'s imports, then add to `impl RewriteRules`:

```rust
/// Headers a rewrite rule may never touch. The first three carry the message
/// framing and connection semantics this proxy owns end to end; letting config
/// set them would reopen the request-smuggling holes Level 1 closed. `Host` is
/// excluded because it has a dedicated `host=` option that also feeds
/// `X-Forwarded-Host` — setting it via `set-header` would bypass that.
const PROTECTED_HEADERS: [&str; 4] =
    ["content-length", "transfer-encoding", "connection", "host"];

fn check_not_protected(name: &str, err: &impl Fn(&str) -> io::Error) -> io::Result<()> {
    if PROTECTED_HEADERS.iter().any(|p| name.eq_ignore_ascii_case(p)) {
        return Err(err(&format!(
            "header {name:?} is managed by the proxy and cannot be rewritten"
        )));
    }
    Ok(())
}
```

(place both at module level, above `impl RewriteRules`), and:

```rust
    /// Parse a `;`-separated option string into rules. The caller has already
    /// severed these options from the route spec, so `opts` here is just
    /// `strip=/api;host=backend.local` — never the whole route.
    pub fn from_options(opts: &str, forwarded: bool) -> io::Result<RewriteRules> {
        let err = |m: &str| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("rewrite option: {m}"))
        };
        let mut rules = RewriteRules { forwarded, ..Default::default() };

        for raw in opts.split(';') {
            let opt = raw.trim();
            if opt.is_empty() {
                continue;
            }
            // Split on the FIRST '=' only: a value may itself contain '='
            // (e.g. set-header=X-Q:a=b).
            let (key, value) = opt
                .split_once('=')
                .ok_or_else(|| err(&format!("{opt:?} must be name=value")))?;
            let key = key.trim();
            let value = value.trim();
            if value.is_empty() {
                return Err(err(&format!("{key} needs a non-empty value")));
            }

            match key {
                "strip" => rules.strip = Some(value.to_string()),
                "prefix" => rules.prefix = Some(value.to_string()),
                "host" => rules.host = Some(value.to_string()),
                "set-header" | "set-resp-header" => {
                    // Split on the FIRST ':' so a value like a URL survives.
                    let (name, hv) = value
                        .split_once(':')
                        .ok_or_else(|| err(&format!("{key} needs Name:Value, got {value:?}")))?;
                    let name = name.trim();
                    let hv = hv.trim();
                    if name.is_empty() || hv.is_empty() {
                        return Err(err(&format!("{key} needs a non-empty name and value")));
                    }
                    check_not_protected(name, &err)?;
                    let pair = (name.to_string(), hv.to_string());
                    if key == "set-header" {
                        rules.set_headers.push(pair);
                    } else {
                        rules.set_resp_headers.push(pair);
                    }
                }
                "remove-header" | "remove-resp-header" => {
                    check_not_protected(value, &err)?;
                    if key == "remove-header" {
                        rules.remove_headers.push(value.to_string());
                    } else {
                        rules.remove_resp_headers.push(value.to_string());
                    }
                }
                other => return Err(err(&format!("unknown option {other:?}"))),
            }
        }
        Ok(rules)
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test 2>&1 | grep -E "test result:|error"`
Expected: PASS — `test result: ok. 91 passed`.

- [ ] **Step 5: Commit**

```bash
git add rproxy/src/rewrite.rs
git -c commit.gpgsign=false commit -m "Parse rewrite options with protected-header validation"
```

---

### Task 5: Wire into `router.rs`, `proxy.rs`, and `main.rs`

**Files:**
- Modify: `rproxy/src/router.rs` (`Route.rules`; sever `;` BEFORE the `=` split in `parse_matchers`; thread `forwarded` through `resolve_route`)
- Modify: `rproxy/src/proxy.rs` (call `apply_request` / `apply_response`; extend the log line)
- Modify: `rproxy/src/main.rs` (`--no-forwarded` flag; pass through `build_routes`)
- Test: `rproxy/src/router.rs` (`mod tests`, append)

**Interfaces:**
- Consumes: `RewriteRules::{from_options, default}` (Tasks 1-4), `ForwardContext` (Task 1).
- Produces: `Route.rules: RewriteRules`; `RouteTable::find` unchanged in shape but callers need the matched `Route`, so **also** add `RouteTable::find_route(&self, method, host, path) -> Option<&Route>` and express `find` in terms of it (keeping `find`'s existing signature so Level 3/4 call sites and tests are untouched).

- [ ] **Step 1: THE PARSING TRAP — read this before writing code**

`parse_matchers` currently does `spec.rsplit_once('=')` to split matchers from target. Rewrite options contain `=`, so on `/api/**=api;strip=/api` that yields target `"/api"` — silently routing to the wrong place. **Verified:**

```
"/api/**=api;strip=/api".rsplit_once('=')  ->  ("/api/**=api;strip", "/api")   WRONG
```

The fix: **sever the `;` options first**, then split the remainder on `=`:

```
"/api/**=api;strip=/api"  --split_once(';')-->  base="/api/**=api"  opts="strip=/api"
"/api/**=api"             --rsplit_once('=')-->  ("/api/**", "api")            CORRECT
```

Note this also means a route's `;` options cannot contain a literal `;`. That's an accepted limitation — document it in a comment.

- [ ] **Step 2: Write the failing tests**

Append to `router.rs`'s `mod tests`:

```rust
    // 17. Backward compatibility: a spec with no ';' options parses exactly as
    //     before and gets default rules (forwarded headers on).
    #[test]
    fn route_without_options_gets_default_rules() {
        let r = resolve_route("/api/**=127.0.0.1:9001", &HashMap::new(), true).unwrap();
        assert!(r.rules.strip.is_none());
        assert!(r.rules.forwarded);
        assert_eq!(r.upstream.name(), "127.0.0.1:9001");
    }

    // Options parse, and — the trap — the TARGET must still be correct even
    // though the options contain '='.
    #[test]
    fn route_with_options_parses_target_correctly() {
        let r = resolve_route("/api/**=127.0.0.1:9001;strip=/api;host=b.local", &HashMap::new(), true)
            .unwrap();
        assert_eq!(r.upstream.name(), "127.0.0.1:9001", "target must not absorb the options");
        assert_eq!(r.rules.strip.as_deref(), Some("/api"));
        assert_eq!(r.rules.host.as_deref(), Some("b.local"));
    }

    // --no-forwarded propagates to every route's rules.
    #[test]
    fn no_forwarded_propagates_to_routes() {
        let r = resolve_route("/=127.0.0.1:9001", &HashMap::new(), false).unwrap();
        assert!(!r.rules.forwarded);
    }

    // A bad rewrite option is a startup error.
    #[test]
    fn route_with_bad_option_errors() {
        assert!(resolve_route("/=127.0.0.1:9001;bogus=1", &HashMap::new(), true).is_err());
        assert!(
            resolve_route("/=127.0.0.1:9001;set-header=Connection:close", &HashMap::new(), true)
                .is_err(),
            "protected header must be rejected at startup"
        );
    }
```

Every existing `resolve_route(spec, &ups)` call in the test module gains a third argument `true`; the `table()` helper likewise. Update them mechanically.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test router:: 2>&1 | tail -15`
Expected: FAIL — `resolve_route` takes 2 arguments, `Route` has no field `rules`.

- [ ] **Step 4: Implement the wiring**

In `rproxy/src/router.rs`:

1. `use crate::rewrite::RewriteRules;`
2. Add to `Route`:
```rust
    /// Level 5 header/path rewriting for requests matched by this route.
    pub rules: RewriteRules,
```
3. `Route::catch_all` sets `rules: RewriteRules::default()`.
4. In `parse_matchers`, sever options first. Change its return type to also yield the option string — add `options: String` to `RouteMatchers` — and at the top of the function:
```rust
    // Sever the ';'-separated rewrite options BEFORE splitting on '=', because
    // option values contain '=' themselves (`strip=/api`). Splitting the other
    // way round makes `rsplit_once('=')` return the option's value as the
    // route target — a silent mis-route. A route's options therefore cannot
    // contain a literal ';'.
    let (spec, options) = match spec.split_once(';') {
        Some((base, opts)) => (base, opts.to_string()),
        None => (spec, String::new()),
    };
```
   (then use the shadowed `spec` for the rest of the function, and put `options` into every `RouteMatchers` construction — both the regex early-return and the final one.)
5. `resolve_route` gains a `forwarded: bool` parameter and builds the rules:
```rust
pub fn resolve_route(
    spec: &str,
    upstreams: &HashMap<String, Arc<Upstream>>,
    forwarded: bool,
) -> io::Result<Route> {
    let m = parse_matchers(spec)?;
    let rules = RewriteRules::from_options(&m.options, forwarded)?;
    // ... existing target resolution unchanged ...
    Ok(Route { host: m.host, method: m.method, path: m.path, upstream, rules })
}
```
6. Add `find_route` and express `find` through it:
```rust
    /// The most specific matching route, or `None`. `find` returns just its
    /// pool; the proxy needs the whole route to reach its rewrite rules.
    pub fn find_route(&self, method: &str, host: Option<&str>, path: &str) -> Option<&Route> {
        self.routes
            .iter()
            .filter(|r| r.matches(method, host, path))
            .max_by_key(|r| r.specificity())
    }

    pub fn find(&self, method: &str, host: Option<&str>, path: &str) -> Option<&Arc<Upstream>> {
        self.find_route(method, host, path).map(|r| &r.upstream)
    }
```

In `rproxy/src/main.rs`:
- add `mod rewrite;` if Task 1 didn't;
- add a `"--no-forwarded" => forwarded = false,` arm to the arg `match` (declare `let mut forwarded = true;` before the loop);
- thread `forwarded` into `build_routes(&upstream_specs, &route_specs, &hc, forwarded)` and on to `resolve_route(spec, &upstreams, forwarded)`.

In `rproxy/src/proxy.rs`, in `serve_one`:
- change the route lookup to `routes.find_route(&method, host, path)`, then use `route.upstream` where `upstream` was used and keep `route.rules` for the transforms. (Bind `let upstream = &route.upstream;` to minimize downstream churn.)
- capture the original target and host BEFORE the transform, for the log line and `ForwardContext`:
```rust
    let original_target = req.target.clone();
    let original_host = http::header(&req.headers, "host").map(str::to_string);
```
- at the request rewrite site, between `strip_hop_by_hop` and the framing block:
```rust
    // Level 5: forwarded headers + path/Host/header rewriting. This must run
    // AFTER hop-by-hop stripping (so a client cannot smuggle in a
    // Connection-listed header that a rule then re-adds) and BEFORE the
    // framing re-declaration below (so no rule can displace the framing
    // headers this proxy owns).
    let ctx = crate::rewrite::ForwardContext {
        client_ip: peer.ip(),
        original_host: original_host.as_deref(),
        scheme: "http", // Level 8 sets "https" after TLS termination
    };
    route.rules.apply_request(&mut req, &ctx);
    if req.target != original_target {
        println!("[{peer}]   rewrite: {original_target} -> {}", req.target);
    }
    if let (Some(before), Some(after)) =
        (original_host.as_deref(), http::header(&req.headers, "host"))
    {
        if before != after {
            println!("[{peer}]   host: {before} -> {after}");
        }
    }
```
- after `strip_hop_by_hop(&mut resp.headers)`, add `route.rules.apply_response(&mut resp);`

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test 2>&1 | grep -E "test result:|error|warning: unused"`
Expected: PASS — `test result: ok. 95 passed`. Existing tests that assert exact forwarded headers may need the four new ones accounted for; that is the expected mechanical adjustment.

- [ ] **Step 6: Commit**

```bash
git add rproxy/src/router.rs rproxy/src/proxy.rs rproxy/src/main.rs
git -c commit.gpgsign=false commit -m "Wire rewrite rules through router, proxy, and CLI"
```

---

### Task 6: Live verification, docs, and quiz

**Files:**
- Modify: `PROGRESS.md`

- [ ] **Step 1: Start an echo backend that reports what it received**

```bash
WORK=$(mktemp -d)
cat > "$WORK/echo.py" <<'EOF'
import sys, http.server, json
port = int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        }, indent=1).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "echo/1.0")
        self.end_headers()
        self.wfile.write(body)
    do_POST = do_GET
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
EOF
python3 "$WORK/echo.py" 9001 >/dev/null 2>&1 &
sleep 1
curl -s http://127.0.0.1:9001/health | head -3
```

- [ ] **Step 2: Verify the four forwarded headers arrive**

```bash
cd rproxy && cargo build --release
./target/release/rproxy 127.0.0.1:18100 '/=127.0.0.1:9001' > /tmp/l5.log 2>&1 &
sleep 1
curl -s -H 'Host: example.com' http://127.0.0.1:18100/hello | grep -E "x-forwarded-|x-real-ip|\"path\""
```

Expected: `x-forwarded-for: 127.0.0.1`, `x-real-ip: 127.0.0.1`,
`x-forwarded-host: example.com`, `x-forwarded-proto: http`.

- [ ] **Step 3: Verify XFF appends and X-Real-IP is not trusted**

```bash
curl -s -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Real-IP: 9.9.9.9' \
  http://127.0.0.1:18100/hello | grep -E "x-forwarded-for|x-real-ip"
```

Expected: `x-forwarded-for: 1.2.3.4, 127.0.0.1` (appended, chain preserved) and
`x-real-ip: 127.0.0.1` (forgery overwritten). Then kill this proxy instance.

- [ ] **Step 4: Verify path rewriting, Host rewriting, and response headers**

```bash
./target/release/rproxy 127.0.0.1:18101 \
  '/api/**=127.0.0.1:9001;strip=/api;host=backend.local;remove-resp-header=Server' \
  > /tmp/l5b.log 2>&1 &
sleep 1
echo "--- backend view (path stripped, Host rewritten, XFH still original) ---"
curl -s -H 'Host: example.com' 'http://127.0.0.1:18101/api/users?page=2' \
  | grep -E "\"path\"|\"host\"|x-forwarded-host"
echo "--- client view: Server header removed ---"
curl -s -D - -o /dev/null -H 'Host: example.com' http://127.0.0.1:18101/api/x | grep -i "^server" \
  || echo "Server header absent (correct)"
grep "rewrite:" /tmp/l5b.log | head -2
```

Expected: `"path": "/users?page=2"` (prefix stripped, query intact),
`"host": "backend.local"` (rewritten), `x-forwarded-host: example.com`
(**original preserved** — the ordering guarantee), and no `Server` header
reaching the client. Kill this instance.

- [ ] **Step 5: Verify `--no-forwarded` and the protected-header guardrail**

```bash
./target/release/rproxy 127.0.0.1:18102 --no-forwarded '/=127.0.0.1:9001' > /tmp/l5c.log 2>&1 &
sleep 1
curl -s http://127.0.0.1:18102/x | grep -cE "x-forwarded-|x-real-ip" \
  && echo "^ expect 0 matches"
kill %1 2>/dev/null

echo "--- protected header must fail startup with exit 1 ---"
./target/release/rproxy 127.0.0.1:18103 '/=127.0.0.1:9001;set-header=Content-Length:5' \
  >/dev/null 2>&1; echo "exit=$?"
pkill -f echo.py
```

Expected: zero forwarded headers with `--no-forwarded`; `exit=1` for the
protected-header rule.

- [ ] **Step 6: Update `PROGRESS.md`**

Set the Level 5 row to implemented (2026-08-07, 95 tests), matching the
formatting of rows 1-4. Add a "## Level 5 — what was built" section in the same
style as Levels 1-4, covering: `rewrite.rs` as pure sync transforms; the four
forwarded headers with append-vs-overwrite rationale; path rewriting with query
preservation; Host rewriting with original capture; request/response header
rules; the protected-header guardrail; the route-spec `;option` grammar and
`--no-forwarded`; and the fixed transform ordering. Include a
"**Verified end-to-end (2026-08-07):**" paragraph citing the ACTUAL captured
results from Steps 2-5, and a "**Run it:**" example. Add a session-log entry.
Then add the quiz:

```markdown
### Level 5 quiz — Vishwa to answer before Level 6

1. `X-Forwarded-For` is appended but `X-Real-IP` is overwritten. Explain why
   each choice is the secure one, and what a client could forge if we made the
   opposite choice for either.
2. A backend behind two proxies reads `X-Forwarded-For: 1.2.3.4, 10.0.0.1,
   10.0.0.2`. Which entry is trustworthy, and why must it count from the right?
3. `X-Forwarded-Host` is populated from `ForwardContext.original_host` rather
   than from the `Host` header at injection time. What breaks if you read the
   header instead, and which config makes the bug visible?
4. The transform runs after `strip_hop_by_hop` and before the framing
   re-declaration. Give a concrete attack or bug that each ordering constraint
   prevents.
5. `set-header` refuses `Content-Length`, `Transfer-Encoding`, `Connection`,
   and `Host` at startup. For each, say what would break if it were allowed.
6. Route specs sever `;` options before splitting on `=`. Show what
   `/api/**=api;strip=/api` parses to under the naive order, and why the bug
   would be hard to notice in production.
7. Explicit header rules run last, after forwarded injection. Name a real
   deployment where that ordering is required.
8. `strip` of the entire path yields `/` rather than `""`. Why does the
   distinction matter to a backend?
```

- [ ] **Step 7: Commit**

```bash
git add PROGRESS.md
git -c commit.gpgsign=false commit -m "Document Level 5: proxy headers and rewriting"
```

---

## Self-Review

**1. Spec coverage:**

| Spec requirement | Task |
|---|---|
| X-Forwarded-For (append) | 1 |
| X-Real-IP (overwrite) | 1 |
| X-Forwarded-Host / -Proto (set-if-absent) | 1 |
| `--no-forwarded` | 1 (flag), 5 (CLI) |
| `http::set_header` | 1 |
| URL/path rewriting (`strip`, `prefix`, query preserved) | 2 |
| Host rewriting + original capture | 3 |
| Header rewriting (request + response) | 3 |
| Header manipulation (general mechanism) | 1, 3 |
| Spec-option parser + validation | 4 |
| Protected-header guardrail | 4 |
| Route-spec `;option` grammar | 4 (parse), 5 (sever + wire) |
| Fixed transform ordering | 3 (in-module), 5 (call site) |
| Log line | 5 |
| Live verification, PROGRESS, quiz | 6 |

No gaps. Design-doc non-goals (RFC 7239 `Forwarded:`, regex path rewriting, cookie rewriting, HTTPS scheme) are intentionally absent.

**2. Placeholder scan:** No TBDs. Every code step contains real code. Task 6's steps are shell commands with expected output, correct for verification. Task 3's `ResponseHead` literal carries an explicit instruction to check the real field names — a known-unknown flagged rather than guessed.

**3. Type consistency:** `RewriteRules` fields are declared in Task 1 and used with identical names in Tasks 2-5. `ForwardContext`'s three fields are consistent between Task 1's definition and Task 5's construction. `from_options(opts, forwarded)` is defined in Task 4 and called that way in Task 5. `resolve_route` gains its third parameter in Task 5, and Task 5 explicitly notes the mechanical update to existing test call sites. `find_route` is added in Task 5 and `find` is redefined in terms of it, preserving Level 3/4 callers.
