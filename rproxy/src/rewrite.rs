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
#[derive(Clone, Debug)]
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
    /// clears it. Note this is NOT `bool::default()` (which is `false`): the
    /// meaning-preserving default for this struct is forwarded-on, so we hand-
    /// write `impl Default` below rather than deriving it. That way a stray
    /// `RewriteRules::default()` can never silently disable forwarded headers.
    pub forwarded: bool,
}

/// Forwarded-header injection is ON by default. Deriving `Default` would set
/// `forwarded: false` (the `bool` default), which is the opposite of what the
/// struct *means* — so we spell the default out here and keep `Default` off the
/// derive list above. `new()` is then just `Default::default()`, and only
/// `no_forwarded()` flips the one field.
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

impl RewriteRules {
    /// Rules that inject the forwarded headers and do nothing else.
    pub fn new() -> RewriteRules {
        RewriteRules::default()
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
        // Path first: everything downstream (including the log line) should see
        // the target the backend will actually receive.
        //
        // When neither rule is set we skip the rewrite entirely — deliberately.
        // This means a malformed target is NOT normalized on this path, but that
        // is a non-issue: HTTP targets are parsed upstream and are always rooted
        // (they start with `/`), so there is nothing to fix up here.
        if self.strip.is_some() || self.prefix.is_some() {
            req.target = self.rewrite_path(&req.target);
        }

        // 3. Host rewrite. The ORIGINAL host was captured into `ctx` by the
        //    caller before we got here — that is what makes step 4's
        //    X-Forwarded-Host honest even though we clobber Host here.
        //    `set_header` is remove-then-push, so exactly one Host survives;
        //    a duplicate Host is a request-smuggling vector.
        if let Some(h) = &self.host {
            http::set_header(&mut req.headers, "Host", h);
        }

        // 4. Forwarded headers. These read `ctx.original_host` / `ctx.scheme`,
        //    NOT the (possibly rewritten) Host header, so X-Forwarded-Host
        //    still reports what the client asked for.
        if self.forwarded {
            self.inject_forwarded(req, ctx);
        }

        // 5. Explicit header rules LAST, so an operator can deliberately
        //    override an injected value — e.g. pinning `X-Forwarded-Proto:
        //    https` behind an external TLS terminator. Removals run before
        //    sets so a rule pair (remove X, set X) behaves predictably rather
        //    than depending on which was declared first.
        for name in &self.remove_headers {
            http::remove_header(&mut req.headers, name);
        }
        for (name, value) in &self.set_headers {
            http::set_header(&mut req.headers, name, value);
        }
    }

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
        //
        // The match must be on a path-SEGMENT boundary, not a raw byte prefix.
        // `str::strip_prefix` alone would strip `/api` from `/apixyz` and yield
        // `/xyz` — but `/apixyz` is a different path that merely shares a textual
        // prefix, and an operator writing `strip=/api` means "the /api segment",
        // exactly as nginx and Traefik do. So we only strip when what remains is
        // empty (the prefix was the whole path) or begins with `/` (a clean
        // segment break). `/apixyz` leaves remainder `xyz` — no boundary — so it
        // passes through untouched.
        if let Some(s) = &self.strip {
            if let Some(rest) = out.strip_prefix(s.as_str()) {
                if rest.is_empty() || rest.starts_with('/') {
                    out = rest.to_string();
                }
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
        // Same removals-before-sets discipline as the request path, for the
        // same reason: a (remove X, set X) pair must land on a clean slate.
        // There are no forwarded headers on the way back — the client is the
        // final hop — so this is purely the explicit response rules.
        for name in &self.remove_resp_headers {
            http::remove_header(&mut resp.headers, name);
        }
        for (name, value) in &self.set_resp_headers {
            http::set_header(&mut resp.headers, name, value);
        }
    }
}

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

    // 9b. strip is SEGMENT-aware, not a raw byte prefix: `/apixyz` merely shares
    //     a textual prefix with `/api`, so it must pass through untouched — a
    //     raw prefix strip would silently mangle it to `/xyz`.
    #[test]
    fn strip_ignores_non_segment_boundary() {
        assert_eq!(target_after("/apixyz", Some("/api"), None), "/apixyz");
    }

    // 9c. A clean segment break (`/api/users`) still strips as expected.
    #[test]
    fn strip_matches_on_segment_boundary() {
        assert_eq!(target_after("/api/users", Some("/api"), None), "/users");
    }

    // 9d. A trailing slash (`/api/`) is a clean break too: remainder is "/",
    //     which the empty/slash normalization collapses to "/".
    #[test]
    fn strip_trailing_slash_yields_root() {
        assert_eq!(target_after("/api/", Some("/api"), None), "/");
    }

    // 10. prefix prepends; strip and prefix compose in the documented order
    //     (strip first, then prefix).
    #[test]
    fn prefix_prepends_and_composes_after_strip() {
        assert_eq!(target_after("/users", None, Some("/v2")), "/v2/users");
        assert_eq!(target_after("/api/users?a=b", Some("/api"), Some("/v2")), "/v2/users?a=b");
    }

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
}
