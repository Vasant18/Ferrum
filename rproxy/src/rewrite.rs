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

use std::io;
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

/// Headers a rewrite rule may never touch. The first three carry the message
/// framing and connection semantics this proxy owns end to end; letting config
/// set them would reopen the request-smuggling holes Level 1 closed. `Host` is
/// excluded because it has a dedicated `host=` option that also feeds
/// `X-Forwarded-Host` — setting it via `set-header` would bypass that.
///
/// `Upgrade`, `TE`, and `Trailer` are the remaining hop-by-hop headers that
/// `proxy.rs::strip_hop_by_hop` deletes on both legs. Without them here, step 5
/// of `apply_request` (explicit `set-header` rules) could RE-ADD a hop-by-hop
/// header after the strip, defeating it — a `set-header=Upgrade:websocket` rule
/// would sail back onto the wire. Listing them preserves the hop-by-hop
/// discipline end to end. We deliberately do NOT protect `Content-Encoding` or
/// `Expect`: those are semantically hazardous but legitimately settable, so
/// blocking them would be over-reach.
const PROTECTED_HEADERS: [&str; 7] = [
    "content-length",
    "transfer-encoding",
    "connection",
    "host",
    "upgrade",
    "te",
    "trailer",
];

fn check_not_protected(name: &str, err: &impl Fn(&str) -> io::Error) -> io::Result<()> {
    if PROTECTED_HEADERS.iter().any(|p| name.eq_ignore_ascii_case(p)) {
        return Err(err(&format!(
            "header {name:?} is managed by the proxy and cannot be rewritten"
        )));
    }
    Ok(())
}

/// Reject a header *name* that is not a valid HTTP field-name token.
///
/// RFC 9110 §5.1 defines a field name as a `token`, whose permitted bytes
/// (`tchar`) are ASCII letters, digits, and `!#$%&'*+-.^_`|~`. Everything else
/// — spaces, `:`, control characters, non-ASCII bytes — is forbidden. This
/// proxy's own Level 1 parser (`parse_header_lines`) would reject such a name
/// off the wire; a name injected via config must clear the same bar, or we
/// would emit a header line our own front door would refuse. Enforced as a
/// hard startup error, consistent with the protected-header philosophy.
fn check_header_name(name: &str, err: &impl Fn(&str) -> io::Error) -> io::Result<()> {
    let is_tchar = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
    if !name.bytes().all(is_tchar) {
        return Err(err(&format!(
            "header name {name:?} is not a valid HTTP token (RFC 9110 tchar: \
             letters, digits, and !#$%&'*+-.^_`|~ only)"
        )));
    }
    Ok(())
}

/// Reject a header *value* containing control characters — chiefly CR (`\r`)
/// and LF (`\n`).
///
/// This is the CRLF-injection / request-smuggling guard. `str::trim()` only
/// strips SURROUNDING whitespace: an interior `"\r\n"` in a configured value
/// passes straight through `http::set_header` and out via `write_request_head`,
/// where it renders as a header separator — turning one config value into an
/// extra header line on the wire (e.g. a smuggled `Transfer-Encoding: chunked`).
///
/// Crucially, the framing re-declaration in `proxy.rs` does NOT save us: that
/// block does `remove_header("transfer-encoding")` then re-pushes it, and
/// `remove_header` matches on the header *name*. A `Transfer-Encoding` smuggled
/// *inside another header's value* is not a distinct header entry — it is bytes
/// in, say, `X-Foo`'s value — so `remove_header` never sees it and it reaches
/// the backend intact. The only place to stop it is here, at parse time, before
/// the bytes are ever accepted.
fn check_header_value(name: &str, value: &str, err: &impl Fn(&str) -> io::Error) -> io::Result<()> {
    if let Some(c) = value.chars().find(|c| c.is_control()) {
        return Err(err(&format!(
            "header {name:?} value contains control character {c:?}; CR/LF (or any \
             control char) in a header value is a CRLF-injection / request-smuggling vector"
        )));
    }
    Ok(())
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
                // An empty segment (e.g. a trailing `;`) is skipped, not an
                // error: writing `strip=/api;` should be as valid as `strip=/api`.
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
                "strip" => {
                    // Trailing-slash normalization — Task 2 review carry-over.
                    //
                    // Task 2 made `strip` segment-aware: it only strips when the
                    // remainder is empty or begins with `/`. That introduced a
                    // sharp edge — a configured `strip=/api/` (trailing slash)
                    // against `/api/users` leaves remainder `users`, which has no
                    // leading `/`, so the strip silently becomes a NO-OP and the
                    // backend receives the un-stripped path. A trailing slash is a
                    // plausible typo, and silent misrouting is the worst outcome,
                    // so we fix it here at parse time (config normalization
                    // belongs at parse time, not on the hot request path).
                    //
                    // We trim trailing `/` so `strip=/api/` == `strip=/api`. But
                    // we must never reduce the value to empty: `strip=/` (or any
                    // run of slashes) would trim to "" — which names no path
                    // segment at all and would strip nothing meaningfully. That
                    // is almost certainly a mistake, so we reject it as a hard
                    // error rather than silently accepting a no-op rule.
                    let normalized = value.trim_end_matches('/');
                    if normalized.is_empty() {
                        return Err(err(&format!(
                            "strip {value:?} normalizes to empty and names no path segment"
                        )));
                    }
                    rules.strip = Some(normalized.to_string());
                }
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
                    check_header_name(name, &err)?;
                    check_header_value(name, hv, &err)?;
                    let pair = (name.to_string(), hv.to_string());
                    if key == "set-header" {
                        rules.set_headers.push(pair);
                    } else {
                        rules.set_resp_headers.push(pair);
                    }
                }
                "remove-header" | "remove-resp-header" => {
                    check_not_protected(value, &err)?;
                    check_header_name(value, &err)?;
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

    /// Transform the request head in place, in this fixed order:
    ///
    ///   1. (caller captured the original `Host` into `ctx` already)
    ///   2. path rewrite
    ///   3. `Host` rewrite
    ///   4. forwarded-header injection
    ///   5. explicit header rules
    ///
    /// `X-Forwarded-Host` reports what the *client* asked for because
    /// `inject_forwarded` reads `ctx.original_host` (captured before any
    /// rewriting), NOT the `Host` header. So the relative order of the Host
    /// rewrite (3) and forwarded injection (4) is not actually observable for
    /// XFH — either order produces the same, honest value. The ordering *would*
    /// matter if injection ever read the live `Host` header instead of
    /// `ctx.original_host`; it deliberately does not, which is what keeps XFH
    /// robust against the Host rewrite.
    ///
    /// Order 5-last matters too: it lets an explicit `set-header` deliberately
    /// override an injected value — e.g. pinning `X-Forwarded-Proto: https`
    /// when an external TLS terminator sits in front of us.
    pub fn apply_request(&self, req: &mut RequestHead, ctx: &ForwardContext) {
        // Path first: everything downstream (including the log line) should see
        // the target the backend will actually receive.
        //
        // When neither rule is set we skip the rewrite entirely. Even when a
        // rule IS set, `rewrite_path` only touches ORIGIN-FORM targets (those
        // starting with `/`); an asterisk-form (`OPTIONS *`) or absolute-form
        // (`http://host/path`) target is left untouched, because prefix/strip
        // arithmetic on it would produce a malformed request line.
        if self.strip.is_some() || self.prefix.is_some() {
            req.target = self.rewrite_path(&req.target);
        }

        // 3. Host rewrite. `set_header` is remove-then-push, so exactly one
        //    Host survives; a duplicate Host is a request-smuggling vector.
        if let Some(h) = &self.host {
            http::set_header(&mut req.headers, "Host", h);
        }

        // 4. Forwarded headers. X-Forwarded-Host reads `ctx.original_host`
        //    (captured before any rewriting), NOT the Host header we may have
        //    just clobbered in step 3 — so it reports what the client asked for
        //    regardless of the step-3/step-4 order. Reading `ctx.original_host`
        //    rather than the live Host is the thing that keeps XFH honest.
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
    ///
    /// Only ORIGIN-FORM targets (starting with `/`) are rewritten. RFC 9112 §3.2
    /// also allows asterisk-form (`*`, for `OPTIONS *`), absolute-form
    /// (`http://host/path`, used to proxies), and authority-form (`CONNECT`).
    /// Prepending a prefix to, or "rooting", any of those would corrupt the
    /// request line — `http://evil.com/api` would become `/http://evil.com/api`
    /// and `*` would become `/*`. So a non-origin-form target is returned
    /// unchanged; strip/prefix simply do not apply to it.
    fn rewrite_path(&self, target: &str) -> String {
        if !target.starts_with('/') {
            return target.to_string();
        }

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
    //
    // The probe MUST be a header that injection OVERWRITES UNCONDITIONALLY.
    // X-Real-IP is exactly that (`inject_forwarded` does a plain `set_header`),
    // so it can detect a step-ordering regression:
    //   - rules last (correct):  injection writes the client IP, the rule then
    //     overrides it -> "10.9.9.9". Passes.
    //   - rules first (buggy):   the rule writes "10.9.9.9", injection then
    //     clobbers it back to the client IP -> "203.0.113.7". FAILS.
    //
    // Do NOT "simplify" this to a set-if-absent header like X-Forwarded-Proto:
    // such a header is vacuous here. With XFP both orderings yield the same
    // result (rules-last: injection writes then rule overrides; rules-first:
    // rule writes then injection sees it present and skips), so the test would
    // pass under the buggy order and prove nothing about ordering — only that
    // set_headers is applied at all. X-Real-IP is what makes the guarantee bite.
    #[test]
    fn explicit_set_header_runs_after_forwarded_injection() {
        let mut r = req(&[]);
        let rules = RewriteRules {
            set_headers: vec![("X-Real-IP".to_string(), "10.9.9.9".to_string())],
            ..Default::default()
        };
        rules.apply_request(&mut r, &ctx(None));
        assert_eq!(
            get(&r, "x-real-ip"),
            Some("10.9.9.9"),
            "an explicit set-header must win over unconditional forwarded injection"
        );

        // Keep the XFP case too — it still documents the intended use (pinning a
        // forwarded value behind a TLS terminator), even though on its own it
        // cannot detect the ordering bug.
        let mut r2 = req(&[]);
        let rules2 = RewriteRules {
            set_headers: vec![("X-Forwarded-Proto".to_string(), "https".to_string())],
            ..Default::default()
        };
        rules2.apply_request(&mut r2, &ctx(None));
        assert_eq!(get(&r2, "x-forwarded-proto"), Some("https"));
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

    // 17. ADDITIONAL (Task 2 review carry-over): a trailing slash in `strip` is
    //     normalized away at parse time, so `strip=/api/` behaves EXACTLY like
    //     `strip=/api`. Without this, Task 2's segment-aware strip turned
    //     `strip=/api/` against `/api/users` into a silent no-op (remainder
    //     `users` has no leading `/`) — a plausible config typo causing silent
    //     misrouting, the worst outcome. `strip=/` (all slashes) normalizes to
    //     empty, which names no segment, so it is a hard error rather than a
    //     silent no-op.
    #[test]
    fn strip_trailing_slash_normalized_at_parse() {
        let a = RewriteRules::from_options("strip=/api/", true).unwrap();
        let b = RewriteRules::from_options("strip=/api", true).unwrap();
        assert_eq!(a.strip, b.strip, "trailing slash must be normalized away");
        assert_eq!(a.strip.as_deref(), Some("/api"));

        // And it produces identical routing behavior.
        let mut r1 = req(&[]);
        r1.target = "/api/users".to_string();
        a.apply_request(&mut r1, &ctx(None));
        let mut r2 = req(&[]);
        r2.target = "/api/users".to_string();
        b.apply_request(&mut r2, &ctx(None));
        assert_eq!(r1.target, r2.target);
        assert_eq!(r1.target, "/users");

        // `strip=/` names no segment once normalized -> hard error, not no-op.
        assert!(RewriteRules::from_options("strip=/", true).is_err());
    }

    // FINDING 1 — CRLF injection in header values. A `\r`, `\n`, or `\r\n` in a
    // set-header / set-resp-header value must be a HARD parse-time error. An
    // interior CRLF survives `str::trim()` (which strips only surrounding
    // whitespace) and, unchecked, `write_request_head` renders it as a header
    // SEPARATOR — turning one config value into an extra header line on the
    // wire. It bypasses PROTECTED_HEADERS entirely because that guard inspects
    // only the header NAME, never the value.
    #[test]
    fn set_header_rejects_crlf_in_value() {
        // The exact smuggling payload from the reproduction: a value that
        // injects a separate `Transfer-Encoding: chunked` line. This must NEVER
        // come back.
        assert!(
            RewriteRules::from_options(
                "set-header=X-Foo:bar\r\nTransfer-Encoding: chunked",
                true
            )
            .is_err(),
            "the reproduced Transfer-Encoding smuggling payload must be refused"
        );
        // Bare CR, bare LF, and CRLF are each rejected, for set- and set-resp-.
        for payload in [
            "set-header=X-Foo:a\rb",
            "set-header=X-Foo:a\nb",
            "set-header=X-Foo:a\r\nb",
            "set-resp-header=X-Foo:a\r\nEvil: 1",
        ] {
            assert!(
                RewriteRules::from_options(payload, true).is_err(),
                "value with CR/LF must be rejected: {payload:?}"
            );
        }
    }

    // FINDING 2 — header-name validation. A name must be a valid RFC 9110 token:
    // no spaces, no `:`, no control chars, ASCII only. `Foo Bar` would reach the
    // wire as `Foo Bar: x` — a name this proxy's own Level 1 parser rejects.
    #[test]
    fn header_names_must_be_valid_tokens() {
        for bad in [
            "set-header=Foo Bar:x",  // space
            "set-header=Foo\x01:x",  // control char
            "set-header=Föö:x",      // non-ASCII
            "remove-header=Foo Bar", // remove path validated too
        ] {
            assert!(
                RewriteRules::from_options(bad, true).is_err(),
                "invalid header name must be rejected: {bad:?}"
            );
        }

        // Don't over-reject: a legitimate name using token-special characters
        // (`-`, `_`, `.`, digits) must still be ACCEPTED.
        let ok = RewriteRules::from_options("set-header=X-My_Header.v1:value", true).unwrap();
        assert_eq!(ok.set_headers[0].0, "X-My_Header.v1");
        // And on the remove path.
        let ok2 = RewriteRules::from_options("remove-header=X-My_Header.v1", true).unwrap();
        assert_eq!(ok2.remove_headers[0], "X-My_Header.v1");
    }

    // FINDING 3 — the extra hop-by-hop names (Upgrade, TE, Trailer) are
    // protected across ALL FOUR rule kinds, so step 5 of apply_request can't
    // re-add what strip_hop_by_hop removed.
    #[test]
    fn hop_by_hop_headers_are_protected() {
        for h in ["Upgrade", "TE", "Trailer"] {
            assert!(
                RewriteRules::from_options(&format!("set-header={h}:x"), true).is_err(),
                "set-header must reject hop-by-hop {h}"
            );
            assert!(
                RewriteRules::from_options(&format!("set-resp-header={h}:x"), true).is_err(),
                "set-resp-header must reject hop-by-hop {h}"
            );
            assert!(
                RewriteRules::from_options(&format!("remove-header={h}"), true).is_err(),
                "remove-header must reject hop-by-hop {h}"
            );
            assert!(
                RewriteRules::from_options(&format!("remove-resp-header={h}"), true).is_err(),
                "remove-resp-header must reject hop-by-hop {h}"
            );
        }
    }

    // FINDING 4 — rewrite_path leaves a non-origin-form target unchanged. An
    // absolute-form or asterisk-form target must pass through even with
    // strip/prefix configured; rooting or prefixing it would corrupt the
    // request line.
    #[test]
    fn non_origin_form_target_is_left_unchanged() {
        // Absolute-form: must not become `/v2/http://host/api/users`.
        assert_eq!(
            target_after("http://evil.com/api/users", Some("/api"), Some("/v2")),
            "http://evil.com/api/users"
        );
        // Asterisk-form (OPTIONS *): must not become `/*` or `/v2*`.
        assert_eq!(target_after("*", Some("/api"), Some("/v2")), "*");
    }
}
