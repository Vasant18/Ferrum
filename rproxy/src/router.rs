//! Level 2 — the routing engine.
//!
//! Routing answers one question per request: given this method, host, and
//! path, *which backend* should handle it? A `RouteTable` is built once at
//! startup into an immutable structure that every connection task reads
//! concurrently (shared as `Arc<RouteTable>`), so matching never takes a
//! lock — foreshadowing Level 12's atomic config swap.
//!
//! Precedence is the subtle part: several routes usually match one request,
//! and "most specific wins" must be deterministic. We rank matches by a
//! score derived from how specific each dimension is, rather than by the
//! order routes were declared, so the result never depends on config order.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use regex::Regex;

use crate::balancer::{self, Upstream};
use crate::rewrite::RewriteRules;

/// How a route matches the request path. Ordered here from most to least
/// specific — the discriminant doubles as a tie-break rank.
pub enum PathMatcher {
    /// Matches one exact path: `/health` matches only `/health`.
    Exact(String),
    /// Matches any path beginning with the prefix: `/api/` matches
    /// `/api/users`. Longer prefixes are more specific (see `specificity`).
    Prefix(String),
    /// Glob-style single wildcard: `/files/*` matches `/files/anything`
    /// (one path segment). A cheap alternative to full regex.
    Wildcard(String),
    /// Full regular expression, anchored against the whole path.
    Regex(Regex),
    /// Matches every path — the catch-all backstop (`/` style default).
    Any,
}

impl PathMatcher {
    fn matches(&self, path: &str) -> bool {
        match self {
            PathMatcher::Exact(p) => path == p,
            PathMatcher::Prefix(p) => path.starts_with(p.as_str()),
            PathMatcher::Wildcard(prefix) => {
                // "/files/*" -> prefix "/files/"; match if path starts with
                // it and the remainder is a single non-empty segment.
                match path.strip_prefix(prefix.as_str()) {
                    Some(rest) => !rest.is_empty() && !rest.contains('/'),
                    None => false,
                }
            }
            PathMatcher::Regex(re) => re.is_match(path),
            PathMatcher::Any => true,
        }
    }

    /// Higher = more specific. Used only to rank *matching* routes against
    /// each other. Within Exact/Any the base rank is enough; for prefixes
    /// the length breaks ties (`/api/v2/` beats `/api/`), which is exactly
    /// the "longest prefix wins" rule from IP routing tables.
    fn specificity(&self) -> u32 {
        match self {
            PathMatcher::Exact(_) => 4000,
            PathMatcher::Wildcard(p) => 3000 + p.len() as u32,
            PathMatcher::Prefix(p) => 2000 + p.len() as u32,
            PathMatcher::Regex(_) => 1000,
            PathMatcher::Any => 0,
        }
    }

    fn describe(&self) -> String {
        match self {
            PathMatcher::Exact(p) => format!("path={p}"),
            PathMatcher::Prefix(p) => format!("prefix={p}"),
            PathMatcher::Wildcard(p) => format!("wildcard={p}*"),
            PathMatcher::Regex(re) => format!("regex={}", re.as_str()),
            PathMatcher::Any => "any".to_string(),
        }
    }
}

/// A single routing rule: match conditions plus the pool to forward to.
///
/// Level 2 stored a single backend address here. Level 3 replaces that with an
/// `Arc<Upstream>` — a whole pool. A single backend is now genuinely just a
/// one-member pool, so there is exactly one downstream path and `Route` no
/// longer carries a `String` at all. The `Arc` is shared: several routes may
/// point at the same declared upstream, and cloning it is a refcount bump.
pub struct Route {
    /// If set, the request `Host` (port stripped) must equal this,
    /// case-insensitively. `None` matches any host.
    pub host: Option<String>,
    /// If set, the request method must equal this. `None` matches any.
    pub method: Option<String>,
    pub path: PathMatcher,
    /// The pool this route forwards to.
    pub upstream: Arc<Upstream>,
    /// Level 5 header/path rewriting for requests matched by this route.
    pub rules: RewriteRules,
    /// Level 6 middleware pipeline for requests matched by this route.
    pub chain: crate::middleware::Chain,
}

impl Route {
    /// A route matching every request, forwarding to one backend. This is
    /// the Level 1 behavior expressed as a single catch-all rule; the backend
    /// address becomes a one-member round-robin pool.
    pub fn catch_all(backend: &str) -> Self {
        Route {
            host: None,
            method: None,
            path: PathMatcher::Any,
            upstream: Arc::new(Upstream::single(backend)),
            rules: RewriteRules::default(),
            // The default posture: access log + request id on, no auth/rate.
            // `build_routes` overrides this for the two catch-all defaults when
            // `--no-request-id` / `--no-access-log` are set, mirroring how it
            // already overrides `rules.forwarded`.
            chain: default_chain(true, true),
        }
    }

    fn matches(&self, method: &str, host: Option<&str>, path: &str) -> bool {
        if let Some(h) = &self.host {
            match host {
                Some(req_host) if req_host.eq_ignore_ascii_case(h) => {}
                _ => return false,
            }
        }
        if let Some(m) = &self.method {
            if !method.eq_ignore_ascii_case(m) {
                return false;
            }
        }
        self.path.matches(path)
    }

    /// Overall specificity: path rank dominates, with host and method
    /// constraints acting as tie-breakers (a host- or method-scoped route
    /// is more specific than an unconstrained one with the same path).
    fn specificity(&self) -> u32 {
        let mut s = self.path.specificity();
        if self.host.is_some() {
            s += 500;
        }
        if self.method.is_some() {
            s += 100;
        }
        s
    }
}

/// The immutable, shareable routing table.
pub struct RouteTable {
    routes: Vec<Route>,
}

impl RouteTable {
    pub fn new(routes: Vec<Route>) -> Self {
        RouteTable { routes }
    }

    /// Find the pool for a request. Among all matching routes, return the most
    /// specific; ties are broken by declaration order (first wins), which
    /// matches Nginx's behavior for equally-specific regex locations. Returns
    /// the `Arc<Upstream>` by reference so the caller can clone it (a refcount
    /// bump) and hold it for the whole exchange while the lease borrows it.
    pub fn find(&self, method: &str, host: Option<&str>, path: &str) -> Option<&Arc<Upstream>> {
        self.find_route(method, host, path).map(|r| &r.upstream)
    }

    /// The most specific matching route, or `None`. `find` returns just its
    /// pool; the proxy needs the whole route to reach its rewrite rules
    /// (`route.rules`). Both share this one selection logic so a Level 3/4
    /// caller reading `find` and a Level 5 caller reading `find_route` can
    /// never disagree about which route won.
    pub fn find_route(&self, method: &str, host: Option<&str>, path: &str) -> Option<&Route> {
        self.routes
            .iter()
            .filter(|r| r.matches(method, host, path))
            .max_by_key(|r| r.specificity())
    }

    /// Every distinct pool referenced by the table, for the health prober to
    /// watch. De-duplicated by `Arc` identity, so a pool shared by several
    /// routes is probed once.
    pub fn upstreams(&self) -> Vec<Arc<Upstream>> {
        let mut out: Vec<Arc<Upstream>> = Vec::new();
        for r in &self.routes {
            if !out.iter().any(|u| Arc::ptr_eq(u, &r.upstream)) {
                out.push(Arc::clone(&r.upstream));
            }
        }
        out
    }

    /// Human-readable dump for the startup banner.
    pub fn describe(&self) -> Vec<String> {
        self.routes
            .iter()
            .map(|r| {
                let host = r.host.as_deref().unwrap_or("*");
                let method = r.method.as_deref().unwrap_or("*");
                format!(
                    "{method} {host} {} -> {} (middleware: {})",
                    r.path.describe(),
                    r.upstream.describe(),
                    r.chain.describe(),
                )
            })
            .collect()
    }
}

/// The match half of a route spec, parsed but not yet bound to a pool:
/// `(host, method, path, target)` where `target` is the raw string after `=`.
struct RouteMatchers {
    host: Option<String>,
    method: Option<String>,
    path: PathMatcher,
    target: String,
    /// The raw `;`-separated rewrite option string (everything after the first
    /// `;`), or empty when the spec carries no options. Parsed into
    /// `RewriteRules` by [`resolve_route`].
    options: String,
}

/// Parse the `[METHOD ][host]path_expr=TARGET` shape into its match conditions
/// plus the still-unresolved target string. Shared by [`parse_route`] and
/// [`resolve_route`]; splitting it out keeps target *resolution* (name vs.
/// `host:port`) separate from *matching*, which never changed in Level 3.
fn parse_matchers(spec: &str) -> io::Result<RouteMatchers> {
    let err = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("{m}: {spec:?}"));

    // Sever the ';'-separated rewrite options BEFORE splitting on '=', because
    // option values contain '=' themselves (`strip=/api`). Splitting the other
    // way round makes `rsplit_once('=')` return the option's value as the
    // route target — a silent mis-route. A route's options therefore cannot
    // contain a literal ';'.
    let (spec, options) = match spec.split_once(';') {
        Some((base, opts)) => (base, opts.to_string()),
        None => (spec, String::new()),
    };

    let (matchers, target) = spec
        .rsplit_once('=')
        .ok_or_else(|| err("route spec missing '=TARGET'"))?;
    if target.is_empty() {
        return Err(err("empty target"));
    }

    // Optional leading "METHOD " (uppercase word before the path part).
    let (method, rest) = match matchers.split_once(' ') {
        Some((m, r)) if !m.is_empty() && m.chars().all(|c| c.is_ascii_alphabetic()) => {
            (Some(m.to_ascii_uppercase()), r)
        }
        _ => (None, matchers),
    };

    // A regex spec (`~...`) takes the whole rest as the pattern; hosts are
    // not supported alongside regex in this simple parser.
    if let Some(pattern) = rest.strip_prefix('~') {
        let re = Regex::new(pattern).map_err(|e| err(&format!("invalid regex ({e})")))?;
        return Ok(RouteMatchers {
            host: None,
            method,
            path: PathMatcher::Regex(re),
            target: target.to_string(),
            options,
        });
    }

    // Split an optional host prefix from the path. The path starts at the
    // first '/'; anything before it is the host.
    let slash = rest.find('/').ok_or_else(|| err("path must contain '/'"))?;
    let host = if slash == 0 { None } else { Some(rest[..slash].to_ascii_lowercase()) };
    let path_expr = &rest[slash..];

    let path = if let Some(prefix) = path_expr.strip_suffix("/**") {
        // "/api/**" -> prefix "/api/"
        PathMatcher::Prefix(format!("{prefix}/"))
    } else if path_expr == "/**" || path_expr == "/" {
        PathMatcher::Any
    } else if let Some(prefix) = path_expr.strip_suffix("/*") {
        PathMatcher::Wildcard(format!("{prefix}/"))
    } else {
        PathMatcher::Exact(path_expr.to_string())
    };

    Ok(RouteMatchers { host, method, path, target: target.to_string(), options })
}

/// Parse one CLI route spec `[METHOD ][host]path_expr=TARGET` and bind its
/// target to a pool. `path_expr` is one of:
///   `/exact`            exact path
///   `/prefix/*`         wildcard (one trailing segment)
///   `/prefix/**`        prefix (any suffix)
///   `~^/regex$`         regex (leading `~`)
///   `/`                 catch-all (Any)
///
/// Examples:
///   `/=127.0.0.1:9000`                everything -> a one-server pool
///   `/api/**=api`                     prefix -> declared `--upstream api`
///   `POST /upload=127.0.0.1:9004`     method + exact path -> one-server pool
///   `~^/v[0-9]+/=127.0.0.1:9005`      regex -> one-server pool
///
/// Given the map of declared `--upstream` pools, target resolution follows
/// three rules, in order:
///
///   1. The target names a declared upstream -> share that `Arc<Upstream>`.
///   2. Otherwise it parses as `host:port` -> auto-wrap as a single-server
///      round-robin pool (this is what preserves Level 1/2 behavior).
///   3. Otherwise -> error `unknown upstream "x"` (it is neither a known name
///      nor a valid address, so it is certainly a typo).
///
/// Several routes naming the same upstream share one `Arc`, so a pool's live
/// counters are common across every route that targets it.
pub fn resolve_route(
    spec: &str,
    upstreams: &HashMap<String, Arc<Upstream>>,
    forwarded: bool,
    request_id: bool,
    access_log: bool,
) -> io::Result<Route> {
    let m = parse_matchers(spec)?;

    // Level 6 added a second family of `;options` (auth, rate, ...). Both
    // families share one severed option string, so we partition it by key
    // before handing each half to its own parser. This partition is the single
    // arbiter of "unknown option": `RewriteRules::from_options` and
    // `MiddlewareConfig::from_options` each see only their own keys, so neither
    // has to know about the other, and a typo is rejected here — once — with a
    // message that names the offending key.
    let (l5_opts, l6_opts) = partition_options(&m.options)?;

    // An empty L5 string yields defaults (forwarded on unless `--no-forwarded`
    // cleared it), so a route with no `;` behaves exactly as before Level 5.
    let rules = RewriteRules::from_options(&l5_opts, forwarded)?;
    let chain = crate::middleware::MiddlewareConfig::from_options(&l6_opts, request_id, access_log)?
        .build();

    let upstream = if let Some(up) = upstreams.get(&m.target) {
        Arc::clone(up) // rule 1: declared name
    } else if balancer::is_host_port(&m.target) {
        Arc::new(Upstream::single(&m.target)) // rule 2: bare host:port
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown upstream {:?} (not a declared --upstream name nor a host:port)", m.target),
        ));
    };

    Ok(Route { host: m.host, method: m.method, path: m.path, upstream, rules, chain })
}

/// The default middleware chain (access log + request id, both toggleable),
/// used by `catch_all` and anywhere a route needs the baseline policy.
pub fn default_chain(request_id: bool, access_log: bool) -> crate::middleware::Chain {
    crate::middleware::MiddlewareConfig::from_options("", request_id, access_log)
        .expect("empty middleware options never error")
        .build()
}

/// Split a route's raw `;`-separated option string into (Level-5 keys,
/// Level-6 keys), preserving each segment verbatim so the sub-parsers see
/// exactly what the operator wrote. A segment whose key is in neither family is
/// the "unknown option" error — raised here, not in either sub-parser.
fn partition_options(opts: &str) -> io::Result<(String, String)> {
    let mut l5: Vec<&str> = Vec::new();
    let mut l6: Vec<&str> = Vec::new();
    for raw in opts.split(';') {
        let seg = raw.trim();
        if seg.is_empty() {
            continue;
        }
        // The key is everything before the first '='. A segment with no '=' is
        // malformed; let the owning sub-parser produce that error, so route it
        // by its bare key if we recognize it, else treat the whole segment as
        // the key for the unknown-option message.
        let key = seg.split_once('=').map(|(k, _)| k.trim()).unwrap_or(seg);
        if crate::rewrite::L5_KEYS.contains(&key) {
            l5.push(seg);
        } else if crate::middleware::L6_KEYS.contains(&key) {
            l6.push(seg);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown route option {key:?}"),
            ));
        }
    }
    Ok((l5.join(";"), l6.join(";")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a table from specs, pre-declaring each spec's target as a named
    /// single-server pool. That lets the opaque sentinel backends below
    /// (`B_EXACT`, `B_ANY`, ...) resolve by name (rule 1) without having to be
    /// valid `host:port` strings — these tests care about *which* target a
    /// request routes to, not about the pool internals.
    fn table(specs: &[&str]) -> RouteTable {
        let mut ups: HashMap<String, Arc<Upstream>> = HashMap::new();
        for s in specs {
            if let Some((_, target)) = s.rsplit_once('=') {
                ups.entry(target.to_string())
                    .or_insert_with(|| Arc::new(Upstream::single(target)));
            }
        }
        RouteTable::new(
            specs
                .iter()
                .map(|s| resolve_route(s, &ups, true, true, true).unwrap())
                .collect(),
        )
    }

    /// The Level 2 assertions compared `find()` to a backend string. `find()`
    /// now returns the whole pool; this thin wrapper recovers the old
    /// `Option<&str>` by reading the pool's name (which, for a single-server
    /// pool, is its target), so every `Some("B_...")` assertion stays verbatim.
    fn route_to<'a>(t: &'a RouteTable, method: &str, host: Option<&str>, path: &str) -> Option<&'a str> {
        t.find(method, host, path).map(|u| u.name())
    }

    #[test]
    fn exact_beats_prefix_beats_catchall() {
        let t = table(&["/=B_ANY", "/api/**=B_PREFIX", "/api/health=B_EXACT"]);
        assert_eq!(route_to(&t, "GET", None, "/api/health"), Some("B_EXACT"));
        assert_eq!(route_to(&t, "GET", None, "/api/users"), Some("B_PREFIX"));
        assert_eq!(route_to(&t, "GET", None, "/other"), Some("B_ANY"));
    }

    #[test]
    fn longest_prefix_wins() {
        let t = table(&["/api/**=B_SHORT", "/api/v2/**=B_LONG"]);
        assert_eq!(route_to(&t, "GET", None, "/api/v2/users"), Some("B_LONG"));
        assert_eq!(route_to(&t, "GET", None, "/api/v1/users"), Some("B_SHORT"));
    }

    #[test]
    fn host_routing() {
        let t = table(&["api.example.com/=B_API", "/=B_DEFAULT"]);
        assert_eq!(route_to(&t, "GET", Some("api.example.com"), "/x"), Some("B_API"));
        // Case-insensitive host match.
        assert_eq!(route_to(&t, "GET", Some("API.EXAMPLE.COM"), "/x"), Some("B_API"));
        assert_eq!(route_to(&t, "GET", Some("other.com"), "/x"), Some("B_DEFAULT"));
        assert_eq!(route_to(&t, "GET", None, "/x"), Some("B_DEFAULT"));
    }

    #[test]
    fn method_routing() {
        let t = table(&["POST /upload=B_UP", "/upload=B_GET"]);
        assert_eq!(route_to(&t, "POST", None, "/upload"), Some("B_UP"));
        // GET falls through to the method-less exact route.
        assert_eq!(route_to(&t, "GET", None, "/upload"), Some("B_GET"));
    }

    #[test]
    fn wildcard_single_segment() {
        let t = table(&["/files/*=B_FILE"]);
        assert_eq!(route_to(&t, "GET", None, "/files/report.pdf"), Some("B_FILE"));
        // Wildcard is one segment: a nested path does not match.
        assert_eq!(route_to(&t, "GET", None, "/files/2026/report.pdf"), None);
        // Empty segment does not match.
        assert_eq!(route_to(&t, "GET", None, "/files/"), None);
    }

    #[test]
    fn regex_routing() {
        let t = table(&["~^/v[0-9]+/=B_VER", "/=B_DEFAULT"]);
        assert_eq!(route_to(&t, "GET", None, "/v2/users"), Some("B_VER"));
        assert_eq!(route_to(&t, "GET", None, "/vX/users"), Some("B_DEFAULT"));
    }

    #[test]
    fn no_match_returns_none() {
        let t = table(&["/api/health=B"]);
        assert_eq!(route_to(&t, "GET", None, "/nope"), None);
    }

    #[test]
    fn host_scoped_route_more_specific_than_bare() {
        // Same path, but the host-scoped route should win for that host.
        let t = table(&["/api/**=B_BARE", "svc.local/api/**=B_HOST"]);
        assert_eq!(route_to(&t, "GET", Some("svc.local"), "/api/x"), Some("B_HOST"));
        assert_eq!(route_to(&t, "GET", Some("elsewhere"), "/api/x"), Some("B_BARE"));
    }

    // These two exercise the *matcher* half of a spec (path shape, host,
    // method), independent of how the target resolves to a pool — so they call
    // `parse_matchers` directly and use opaque `=B` targets.
    #[test]
    fn parse_errors() {
        assert!(parse_matchers("/no-target").is_err()); // missing '='
        assert!(parse_matchers("/x=").is_err()); // empty target
        assert!(parse_matchers("~[invalid=B").is_err()); // bad regex
        assert!(parse_matchers("noslash=B").is_err()); // no path
    }

    #[test]
    fn parse_shapes() {
        assert!(matches!(parse_matchers("/=B").unwrap().path, PathMatcher::Any));
        assert!(matches!(parse_matchers("/a=B").unwrap().path, PathMatcher::Exact(_)));
        assert!(matches!(parse_matchers("/a/**=B").unwrap().path, PathMatcher::Prefix(_)));
        assert!(matches!(parse_matchers("/a/*=B").unwrap().path, PathMatcher::Wildcard(_)));
        assert!(matches!(parse_matchers("~^/x=B").unwrap().path, PathMatcher::Regex(_)));
        let r = parse_matchers("POST host.com/a=B").unwrap();
        assert_eq!(r.method.as_deref(), Some("POST"));
        assert_eq!(r.host.as_deref(), Some("host.com"));
    }

    // Route resolution (test 14): a target binds to a declared upstream by
    // name (rule 1), a bare host:port auto-wraps into a one-server pool
    // (rule 2), and anything else is a startup error (rule 3).
    #[test]
    fn route_resolution_rules() {
        let mut ups: HashMap<String, Arc<Upstream>> = HashMap::new();
        ups.insert("api".to_string(), Arc::new(Upstream::single("127.0.0.1:9001")));

        // Rule 1: named upstream — the route shares that exact pool's Arc
        // (a refcount bump, not a fresh pool), which is what lets several
        // routes naming one upstream share its live counters.
        let named = resolve_route("/svc/**=api", &ups, true, true, true).unwrap();
        assert!(Arc::ptr_eq(&named.upstream, &ups["api"]));

        // Rule 2: bare host:port auto-wraps.
        let wrapped = resolve_route("/=127.0.0.1:9000", &ups, true, true, true).unwrap();
        assert_eq!(wrapped.upstream.name(), "127.0.0.1:9000");

        // Rule 3: neither a known name nor a valid address.
        assert!(resolve_route("/=not_a_pool", &ups, true, true, true).is_err());
    }

    // 17. Backward compatibility: a spec with no ';' options parses exactly as
    //     before and gets default rules (forwarded headers on).
    #[test]
    fn route_without_options_gets_default_rules() {
        let r = resolve_route("/api/**=127.0.0.1:9001", &HashMap::new(), true, true, true).unwrap();
        assert!(r.rules.strip.is_none());
        assert!(r.rules.forwarded);
        assert_eq!(r.upstream.name(), "127.0.0.1:9001");
    }

    // Options parse, and — the trap — the TARGET must still be correct even
    // though the options contain '='.
    #[test]
    fn route_with_options_parses_target_correctly() {
        let r = resolve_route(
            "/api/**=127.0.0.1:9001;strip=/api;host=b.local",
            &HashMap::new(),
            true,
            true,
            true,
        )
        .unwrap();
        assert_eq!(r.upstream.name(), "127.0.0.1:9001", "target must not absorb the options");
        assert_eq!(r.rules.strip.as_deref(), Some("/api"));
        assert_eq!(r.rules.host.as_deref(), Some("b.local"));
    }

    // --no-forwarded propagates to every route's rules.
    #[test]
    fn no_forwarded_propagates_to_routes() {
        let r = resolve_route("/=127.0.0.1:9001", &HashMap::new(), false, true, true).unwrap();
        assert!(!r.rules.forwarded);
    }

    // A bad rewrite option is a startup error.
    #[test]
    fn route_with_bad_option_errors() {
        assert!(resolve_route("/=127.0.0.1:9001;bogus=1", &HashMap::new(), true, true, true).is_err());
        assert!(
            resolve_route(
                "/=127.0.0.1:9001;set-header=Connection:close",
                &HashMap::new(),
                true,
                true,
                true
            )
            .is_err(),
            "protected header must be rejected at startup"
        );
    }

    // ---- Level 6: option partition and chain wiring ----

    // Level 5 and Level 6 options coexist on one spec: the partition sends each
    // key to its own parser, and neither swallows the other's keys.
    #[test]
    fn l5_and_l6_options_compose() {
        let r = resolve_route(
            "/api/**=127.0.0.1:9002;strip=/api;auth=basic:u:p;rate=10/s",
            &HashMap::new(),
            true,
            true,
            true,
        )
        .unwrap();
        assert!(r.rules.strip.is_some(), "L5 option parsed");
        let d = r.chain.describe();
        assert!(d.contains("auth") && d.contains("ratelimit"), "L6 chain built: {d}");
    }

    // A key belonging to neither family is still a startup error, raised by the
    // partition (not by either sub-parser).
    #[test]
    fn unknown_option_still_errors_after_partition() {
        assert!(resolve_route("/=127.0.0.1:9000;bogus=1", &HashMap::new(), true, true, true).is_err());
    }

    // A route with no middleware options gets the default chain (log +
    // request-id) and no auth/ratelimit.
    #[test]
    fn no_options_gets_default_chain() {
        let r = resolve_route("/=127.0.0.1:9000", &HashMap::new(), true, true, true).unwrap();
        let d = r.chain.describe();
        assert!(d.contains("log") && d.contains("request-id"));
        assert!(!d.contains("auth"));
    }

    // --no-request-id / --no-access-log propagate into the built chain.
    #[test]
    fn no_request_id_flag_omits_it_from_chain() {
        let r = resolve_route("/=127.0.0.1:9000", &HashMap::new(), true, false, true).unwrap();
        let d = r.chain.describe();
        assert!(!d.contains("request-id"), "request-id disabled: {d}");
        assert!(d.contains("log"));
    }
}
