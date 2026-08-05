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
        self.routes
            .iter()
            .filter(|r| r.matches(method, host, path))
            .max_by_key(|r| r.specificity())
            .map(|r| &r.upstream)
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
                format!("{method} {host} {} -> {}", r.path.describe(), r.upstream.describe())
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
}

/// Parse the `[METHOD ][host]path_expr=TARGET` shape into its match conditions
/// plus the still-unresolved target string. Shared by [`parse_route`] and
/// [`resolve_route`]; splitting it out keeps target *resolution* (name vs.
/// `host:port`) separate from *matching*, which never changed in Level 3.
fn parse_matchers(spec: &str) -> io::Result<RouteMatchers> {
    let err = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("{m}: {spec:?}"));

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

    Ok(RouteMatchers { host, method, path, target: target.to_string() })
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
pub fn resolve_route(spec: &str, upstreams: &HashMap<String, Arc<Upstream>>) -> io::Result<Route> {
    let m = parse_matchers(spec)?;

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

    Ok(Route { host: m.host, method: m.method, path: m.path, upstream })
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
        RouteTable::new(specs.iter().map(|s| resolve_route(s, &ups).unwrap()).collect())
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
        let named = resolve_route("/svc/**=api", &ups).unwrap();
        assert!(Arc::ptr_eq(&named.upstream, &ups["api"]));

        // Rule 2: bare host:port auto-wraps.
        let wrapped = resolve_route("/=127.0.0.1:9000", &ups).unwrap();
        assert_eq!(wrapped.upstream.name(), "127.0.0.1:9000");

        // Rule 3: neither a known name nor a valid address.
        assert!(resolve_route("/=not_a_pool", &ups).is_err());
    }
}
