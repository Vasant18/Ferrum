//! Level 6 — the middleware pipeline.
//!
//! Auth, rate limiting, request IDs, and access logging are *policy applied
//! around forwarding*, not forwarding itself. Levels 1–5 grew `serve_one` by
//! adding each feature inline; this module is where cross-cutting policy stops
//! tangling into the core loop and starts stacking like Lego.
//!
//! # Why the trait is synchronous
//!
//! The textbook "onion" middleware (Tower, the knowledge base's own diagram)
//! is `async fn handle(req, next) -> Response`, where `next` invokes the rest
//! of the chain and hands you back a `Response` value to post-process. That
//! signature has two costs we refuse to pay here:
//!
//! 1. **It needs an owned `Response`.** `serve_one` never has one — it reads
//!    the backend's response head and then *streams* the body through a 16 KB
//!    window (`Conn::copy_body_to`). A 2 GB download costs 16 KB of memory
//!    today. An owned-response contract would force us to buffer every body,
//!    throwing away Level 1's flat-memory guarantee and pre-breaking Level 7.
//! 2. **`async fn` in a trait object needs boxing.** `async fn` desugars to
//!    "return a `Future`"; a `dyn` trait needs a known size, so each call
//!    allocates a `Pin<Box<dyn Future>>` (this is what the `async-trait` crate
//!    does for you). Real, and avoidable.
//!
//! So we split the onion into two *synchronous* passes over the head structs:
//!
//! - `on_request` runs **forward** through the chain, before a backend exists.
//! - the exchange streams, untouched, exactly as in Level 5.
//! - `on_response` runs in **reverse** — the onion's "way out" — without ever
//!   owning the body.
//!
//! No async in the trait means no boxed futures and no `async-trait` dep. The
//! one thing we give up is a middleware that itself awaits (e.g. calling an
//! external OIDC endpoint). That is a documented boundary; the trait takes
//! `&self` so any future async middleware can carry its own interior
//! mutability without a signature churn.

pub mod auth;
pub mod observe;
pub mod ratelimit;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::http::{RequestHead, ResponseHead};
use auth::{Auth, Authz, Credential};
use observe::{AccessLog, RequestId};
use ratelimit::{Limiter, RateLimit};

/// The option keys Level 6 owns. Used by the router's option partition to send
/// each `;option` to the right sub-parser (see `rewrite::L5_KEYS`). Note there
/// are more spellings than middleware: `realm` tunes `auth`, `require-user`
/// feeds authz, `burst` tunes the limiter.
pub const L6_KEYS: &[&str] = &[
    "auth",
    "realm",
    "require-user",
    "rate",
    "burst",
    // Level 13: the WAF is configured here because it IS a middleware —
    // same partition, same parser, same chain assembly.
    "waf",
    "waf-threshold",
];

/// One layer of the pipeline. Both phases are synchronous (see the module doc).
///
/// `Send + Sync` because the assembled `Chain` lives inside the
/// `Arc<RouteTable>` that every connection task shares — a middleware is read
/// concurrently from many tasks and never mutated after startup.
pub trait Middleware: Send + Sync {
    /// Stable name for log lines and rejection attribution.
    fn name(&self) -> &'static str;

    /// Inbound half. May mutate the request head or the shared context, and
    /// may short-circuit the whole exchange by returning `Reject`.
    fn on_request(&self, req: &mut RequestHead, ctx: &mut ReqCtx) -> Decision;

    /// Outbound half. Default no-op so request-only middleware stay terse.
    fn on_response(&self, _ctx: &ReqCtx, _resp: &mut ResponseHead) {}
}

/// The verdict a middleware returns on the way in.
pub enum Decision {
    /// Proceed to the next layer (and eventually the backend).
    Continue,
    /// Stop here; send this response instead of forwarding.
    Reject(Rejection),
}

/// A proxy-generated refusal. Carries headers because a bare status is often
/// not a valid response: 401 REQUIRES `WWW-Authenticate` (RFC 9110 §11.6.1),
/// and a 429 without `Retry-After` tells the client nothing actionable.
pub struct Rejection {
    pub status: u16,
    pub reason: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Per-request state that crosses middleware and survives into the response
/// phase. By the time the response comes back the request head has been
/// rewritten by Level 5, so any middleware needing the *original* method /
/// target / host reads them from here, not from the (mutated) head.
pub struct ReqCtx {
    pub peer: SocketAddr,
    pub started: Instant,
    pub method: String,
    pub target: String,
    /// The client's original `Host`, captured before Level 5 rewrites it.
    /// No middleware reads it yet, but it is part of the documented `ReqCtx`
    /// contract — the natural place a future host-aware layer (or a richer
    /// access log) would look, just as `original_host` feeds `X-Forwarded-Host`
    /// on the rewrite side. `#[allow(dead_code)]` for the same reason
    /// `Upstream::from_spec` carries it: a documented seam, not dead weight.
    #[allow(dead_code)]
    pub host: Option<String>,
    /// Set by `RequestId`; read by its own `on_response` and by the log.
    pub request_id: String,
    /// Set by `Auth` on success; read by `Authz`. The one piece of state that
    /// genuinely flows *between* middleware.
    pub identity: Option<String>,
    /// Written by `proxy.rs` after the pool pick; read by the access log.
    pub backend: Option<String>,
    pub upstream: Option<String>,
    /// Name of the middleware that rejected, if any. Log attribution.
    pub rejected_by: Option<&'static str>,
    /// Level 10: per-stage timing stamps, written by `proxy.rs` at the moments
    /// it passes each milestone, read by the access log (as deltas) and the
    /// duration histogram. All are measured from `started`, as `Option` because
    /// a request can end at any stage (a 404 never connects; a rejection never
    /// routes) and the log must distinguish "never happened" from "took 0ms".
    /// Durations-from-start rather than raw `Instant`s so the log's subtraction
    /// can never underflow if a future edit reorders two stamps.
    pub t_route: Option<std::time::Duration>,
    /// Backend connection in hand — freshly dialed or a pool hit. The delta
    /// `t_connect - t_route` is the queue+dial cost; a pool hit shows ~0.
    pub t_connect: Option<std::time::Duration>,
    /// First byte of the backend's response head observed (TTFB). The delta
    /// against `t_connect` is the backend's own think time — the number that
    /// answers "is it us or is it them" at 3 a.m.
    pub t_first_byte: Option<std::time::Duration>,
    /// Whether the backend leg came from the Level 7 idle pool. The access log
    /// carries it because a latency regression that only affects pool *misses*
    /// looks identical to a slow backend unless the log can split the two.
    pub pooled: bool,
    /// Level 11: cache outcome for this exchange — "hit", "miss",
    /// "revalidated", or None when the route doesn't cache / the request
    /// wasn't cacheable. The log's version of the `X-Cache` header.
    pub cache: Option<&'static str>,
    /// Level 13: the WAF's anomaly score, when non-zero on a waf-enabled
    /// route. In the log (never in a response header — no oracle) so an
    /// operator can tune a threshold against real traffic in detect mode.
    pub waf_score: Option<u32>,
}

impl ReqCtx {
    pub fn new(peer: SocketAddr, method: String, target: String, host: Option<String>) -> Self {
        ReqCtx {
            peer,
            // Stamped here, before the chain runs, so the access log's duration
            // covers every layer including the one that stamped it.
            started: Instant::now(),
            method,
            target,
            host,
            request_id: String::new(),
            identity: None,
            backend: None,
            upstream: None,
            rejected_by: None,
            t_route: None,
            t_connect: None,
            t_first_byte: None,
            pooled: false,
            cache: None,
            waf_score: None,
        }
    }
}

/// An ordered stack of middleware. Built once per route at startup; run per
/// request. Not `Clone` (a `Box<dyn Middleware>` isn't) and doesn't need to be
/// — `Route` owns one and is shared through `Arc<RouteTable>`.
pub struct Chain {
    mws: Vec<Box<dyn Middleware>>,
    /// Human-readable summary for the startup banner (e.g.
    /// `log, request-id, ratelimit(5/s burst=5), auth(1 cred)`). Built once
    /// from the config so the banner can show tunables the layer names alone
    /// don't carry.
    summary: String,
}

impl Chain {
    /// Build a chain from its layers, deriving the banner summary from their
    /// names. Production builds the chain through `MiddlewareConfig::build`
    /// (which supplies the richer per-layer summary via `with_summary`), so
    /// this simpler constructor is currently exercised only by the chain unit
    /// tests. Kept public and `#[allow(dead_code)]` — a documented seam, the
    /// same treatment `Upstream::for_test` and `RewriteRules::new` carry — so a
    /// caller assembling an ad-hoc chain has an obvious entry point.
    #[allow(dead_code)]
    pub fn new(mws: Vec<Box<dyn Middleware>>) -> Self {
        let summary = mws.iter().map(|m| m.name()).collect::<Vec<_>>().join(", ");
        Chain { mws, summary }
    }

    fn with_summary(mws: Vec<Box<dyn Middleware>>, summary: String) -> Self {
        Chain { mws, summary }
    }

    /// Run `on_request` forward. On rejection, return the rejecting layer's
    /// index and the response to send. The index tells the caller exactly how
    /// many layers were *entered*, so it can unwind precisely those
    /// `on_response` passes and no more (see `run_response`).
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

    /// Reverse `on_response` for indices `[0, up_to)`. This is the rejection
    /// path. The rejecting layer (index `up_to`) produced the response and does
    /// not post-process its own output; layers after it never ran at all. So a
    /// 401 from `Auth` still gets stamped by `RequestId` and logged by `Log`,
    /// while `Authz` never runs — the onion behaving correctly on the way out.
    pub fn run_response(&self, ctx: &ReqCtx, resp: &mut ResponseHead, up_to: usize) {
        for mw in self.mws[..up_to].iter().rev() {
            mw.on_response(ctx, resp);
        }
    }

    /// Reverse `on_response` over every layer — the non-rejected path, where
    /// all layers were entered.
    pub fn run_response_all(&self, ctx: &ReqCtx, resp: &mut ResponseHead) {
        for mw in self.mws.iter().rev() {
            mw.on_response(ctx, resp);
        }
    }

    /// Banner summary in run order (with per-layer tunables when built from a
    /// `MiddlewareConfig`).
    pub fn describe(&self) -> String {
        self.summary.clone()
    }
}

/// Parsed Level 6 configuration for one route. Built from the route spec's
/// `;options` (the L6 subset) plus the two global on/off flags, then turned
/// into a `Chain` by `build`.
pub struct MiddlewareConfig {
    creds: Vec<Credential>,
    realm: String,
    require_user: Vec<String>,
    /// Tokens/second, if a `rate=` was given.
    rate: Option<f64>,
    /// Bucket capacity. Defaults to one second's worth of `rate` (min 1).
    burst: Option<f64>,
    request_id: bool,
    access_log: bool,
    /// Level 13: `Some(mode)` when `waf=` was given on the route.
    waf: Option<crate::waf::WafMode>,
    waf_threshold: Option<u32>,
}

impl MiddlewareConfig {
    /// Parse the L6 subset of a route's options. `opts` contains only the
    /// segments the router's partition assigned to Level 6 (so an unknown key
    /// is impossible here — the partition already rejected it). The two bools
    /// are the global `--no-request-id` / `--no-access-log` state.
    pub fn from_options(opts: &str, request_id: bool, access_log: bool) -> io::Result<Self> {
        let err =
            |m: String| io::Error::new(io::ErrorKind::InvalidInput, format!("middleware option: {m}"));

        let mut cfg = MiddlewareConfig {
            creds: Vec::new(),
            realm: "ferrum".to_string(),
            require_user: Vec::new(),
            rate: None,
            burst: None,
            request_id,
            access_log,
            waf: None,
            waf_threshold: None,
        };

        for raw in opts.split(';') {
            let opt = raw.trim();
            if opt.is_empty() {
                continue;
            }
            let (key, value) = opt
                .split_once('=')
                .ok_or_else(|| err(format!("{opt:?} must be name=value")))?;
            let (key, value) = (key.trim(), value.trim());
            if value.is_empty() {
                return Err(err(format!("{key} needs a non-empty value")));
            }

            match key {
                "auth" => cfg.creds.push(parse_credential(value, &err)?),
                "realm" => cfg.realm = value.to_string(),
                "require-user" => cfg.require_user.push(value.to_string()),
                "rate" => cfg.rate = Some(parse_rate(value, &err)?),
                "burst" => {
                    let b: f64 = value
                        .parse()
                        .map_err(|_| err(format!("burst {value:?} is not a number")))?;
                    if b < 1.0 {
                        return Err(err(format!("burst must be >= 1, got {value:?}")));
                    }
                    cfg.burst = Some(b);
                }
                "waf" => {
                    cfg.waf = Some(crate::waf::WafMode::parse(value).map_err(err)?);
                }
                "waf-threshold" => {
                    let t: u32 = value
                        .parse()
                        .map_err(|_| err(format!("waf-threshold {value:?} is not a number")))?;
                    if t == 0 {
                        return Err(err("waf-threshold must be >= 1".to_string()));
                    }
                    cfg.waf_threshold = Some(t);
                }
                // Unreachable: the router partition only hands us L6 keys.
                other => return Err(err(format!("unknown option {other:?}"))),
            }
        }

        // Coherence check, same spirit as Level 5's protected-header guardrail:
        // an incoherent config fails at boot, not at 3am. `require-user` with no
        // `auth=` can never populate `ctx.identity`, so authz would 403 every
        // request forever.
        if !cfg.require_user.is_empty() && cfg.creds.is_empty() {
            return Err(err(
                "require-user needs an auth= on the same route (nothing else can set the identity it checks)".to_string(),
            ));
        }
        // A bare `burst=` with no `rate=` configures a limiter with no refill —
        // it would drain once and reject forever. Almost certainly a mistake.
        if cfg.burst.is_some() && cfg.rate.is_none() {
            return Err(err("burst= needs a rate= on the same route".to_string()));
        }
        // Level 13, same spirit: a threshold with no waf= tunes a middleware
        // that will never exist.
        if cfg.waf_threshold.is_some() && cfg.waf.is_none() {
            return Err(err("waf-threshold= needs a waf= on the same route".to_string()));
        }

        Ok(cfg)
    }

    /// Assemble the chain in the fixed order — Log, RequestId, RateLimit, Auth,
    /// Authz — skipping any layer that is disabled or unconfigured. Order is in
    /// code, never config: rate-limit sits OUTSIDE auth so a credential-guessing
    /// flood is refused before any comparison runs.
    pub fn build(&self) -> Chain {
        let mut mws: Vec<Box<dyn Middleware>> = Vec::new();

        if self.access_log {
            // Format comes from the process-wide `--log-plain` toggle (see
            // observe.rs) captured at chain-build time, which is startup.
            mws.push(Box::new(AccessLog {
                plain: observe::plain_mode(),
            }));
        }
        if self.request_id {
            mws.push(Box::new(RequestId::new()));
        }
        if let Some(mode) = self.waf {
            // Level 13, chain position: after request-id (a blocked request
            // still gets its id + log line via the response-phase unwind),
            // BEFORE ratelimit and auth — hostility is refused before it can
            // consume a rate token or trigger a credential comparison. The
            // reputation store is process-wide (set in main): an attacker
            // probing two routes is one offender, not two.
            mws.push(Box::new(crate::waf::Waf {
                mode,
                threshold: self.waf_threshold.unwrap_or(crate::waf::DEFAULT_THRESHOLD),
                reputation: crate::waf::shared_reputation(),
            }));
        }
        if let Some(rate) = self.rate {
            // Default burst = one second of rate, floored at 1 so a sub-1/s
            // rate still admits a single request.
            let burst = self.burst.unwrap_or_else(|| rate.ceil().max(1.0));
            let limiter = Arc::new(Limiter::new(rate, burst));
            mws.push(Box::new(RateLimit::new(limiter)));
        }
        if !self.creds.is_empty() {
            // Move creds into the Auth middleware. `build` takes `&self`, so
            // clone each credential rather than draining the config (a route's
            // config is read once at startup, but keeping it non-destructive
            // keeps `describe` callable afterwards).
            let creds = self.creds.iter().map(clone_credential).collect();
            mws.push(Box::new(Auth {
                creds,
                realm: self.realm.clone(),
            }));
        }
        if !self.require_user.is_empty() {
            mws.push(Box::new(Authz {
                allowed: self.require_user.clone(),
            }));
        }

        // Carry the rich per-layer summary (with rate/burst/cred counts) into
        // the chain so the startup banner shows tunables the bare layer names
        // can't. `describe` here is `MiddlewareConfig::describe`.
        Chain::with_summary(mws, self.describe())
    }

    /// Short fragment for the startup route banner, e.g.
    /// `log, request-id, ratelimit(5/s burst=5), auth(1 cred), authz(1 user)`.
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.access_log {
            parts.push("log".to_string());
        }
        if self.request_id {
            parts.push("request-id".to_string());
        }
        if let Some(rate) = self.rate {
            let burst = self.burst.unwrap_or_else(|| rate.ceil().max(1.0));
            parts.push(format!("ratelimit({rate}/s burst={burst})"));
        }
        if !self.creds.is_empty() {
            parts.push(format!("auth({} cred)", self.creds.len()));
        }
        if !self.require_user.is_empty() {
            parts.push(format!("authz({} user)", self.require_user.len()));
        }
        parts.join(", ")
    }
}

/// Parse `basic:USER:PASS` or `bearer:TOKEN`. Basic splits on the first two
/// colons only, so a password may contain colons; bearer takes the rest
/// verbatim.
fn parse_credential(value: &str, err: &impl Fn(String) -> io::Error) -> io::Result<Credential> {
    let (scheme, rest) = value
        .split_once(':')
        .ok_or_else(|| err(format!("auth {value:?} must be scheme:...")))?;
    match scheme {
        "basic" => {
            let (user, pass) = rest
                .split_once(':')
                .ok_or_else(|| err(format!("auth=basic needs user:pass, got {value:?}")))?;
            if user.is_empty() || pass.is_empty() {
                return Err(err(format!("auth=basic needs a non-empty user and pass, got {value:?}")));
            }
            Ok(Credential::Basic {
                user: user.to_string(),
                pass: pass.to_string(),
            })
        }
        "bearer" => {
            if rest.is_empty() {
                return Err(err("auth=bearer needs a token".to_string()));
            }
            Ok(Credential::Bearer {
                token: rest.to_string(),
                // Label the identity for logs; the token itself is a secret.
                label: "bearer".to_string(),
            })
        }
        other => Err(err(format!("unknown auth scheme {other:?} (want basic or bearer)"))),
    }
}

/// Parse `N/s` or `N/m` into tokens per second. Rejects a zero rate: `rate=0`
/// would reject every request, which is expressed by omitting the option, so a
/// literal 0 is almost certainly a typo.
fn parse_rate(value: &str, err: &impl Fn(String) -> io::Error) -> io::Result<f64> {
    let (n, unit) = value
        .split_once('/')
        .ok_or_else(|| err(format!("rate {value:?} must be N/s or N/m")))?;
    let n: f64 = n
        .trim()
        .parse()
        .map_err(|_| err(format!("rate {value:?} has a non-numeric count")))?;
    if n <= 0.0 {
        return Err(err(format!("rate must be > 0, got {value:?}")));
    }
    match unit.trim() {
        "s" => Ok(n),
        "m" => Ok(n / 60.0),
        other => Err(err(format!("rate unit {other:?} must be s or m"))),
    }
}

fn clone_credential(c: &Credential) -> Credential {
    match c {
        Credential::Basic { user, pass } => Credential::Basic {
            user: user.clone(),
            pass: pass.clone(),
        },
        Credential::Bearer { token, label } => Credential::Bearer {
            token: token.clone(),
            label: label.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Version;
    use std::sync::{Arc, Mutex};

    /// A middleware that appends its label to a shared log on each phase, and
    /// optionally rejects on request. Proves ordering and short-circuiting.
    struct Probe {
        label: &'static str,
        log: Arc<Mutex<Vec<String>>>,
        reject: bool,
    }

    impl Middleware for Probe {
        fn name(&self) -> &'static str {
            self.label
        }
        fn on_request(&self, _req: &mut RequestHead, _ctx: &mut ReqCtx) -> Decision {
            self.log.lock().unwrap().push(format!("req:{}", self.label));
            if self.reject {
                Decision::Reject(Rejection {
                    status: 418,
                    reason: "teapot",
                    headers: vec![],
                    body: String::new(),
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
        RequestHead {
            method: "GET".into(),
            target: "/".into(),
            version: Version::Http11,
            headers: vec![],
        }
    }
    fn resp() -> ResponseHead {
        ResponseHead {
            version: Version::Http11,
            status: 200,
            reason: "OK".into(),
            headers: vec![],
        }
    }
    fn ctx() -> ReqCtx {
        ReqCtx::new("127.0.0.1:1".parse().unwrap(), "GET".into(), "/".into(), None)
    }
    fn probes(log: &Arc<Mutex<Vec<String>>>, rejecter: Option<usize>) -> Chain {
        let labels = ["a", "b", "c"];
        let mws: Vec<Box<dyn Middleware>> = labels
            .iter()
            .enumerate()
            .map(|(i, l)| {
                Box::new(Probe {
                    label: l,
                    log: log.clone(),
                    reject: Some(i) == rejecter,
                }) as Box<dyn Middleware>
            })
            .collect();
        Chain::new(mws)
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
        // On rejection at index 1, unwind on_response for indices 0..1 => "a".
        chain.run_response(&ctx(), &mut resp(), 1);
        assert_eq!(*log.lock().unwrap(), ["resp:a"]);
    }

    // ---- MiddlewareConfig parsing ----

    #[test]
    fn parses_all_l6_options() {
        let c = MiddlewareConfig::from_options(
            "auth=basic:admin:pw;auth=bearer:tok;realm=api;require-user=admin;rate=100/s;burst=200",
            true,
            true,
        )
        .unwrap();
        assert_eq!(c.creds.len(), 2);
        assert_eq!(c.realm, "api");
        assert_eq!(c.require_user, vec!["admin"]);
        assert_eq!(c.rate, Some(100.0));
        assert_eq!(c.burst, Some(200.0));
    }

    #[test]
    fn rate_per_minute() {
        let c = MiddlewareConfig::from_options("rate=60/m", true, true).unwrap();
        assert_eq!(c.rate, Some(1.0)); // 60/min = 1/s
    }

    #[test]
    fn require_user_without_auth_errors() {
        assert!(MiddlewareConfig::from_options("require-user=admin", true, true).is_err());
    }

    #[test]
    fn rate_zero_errors() {
        assert!(MiddlewareConfig::from_options("rate=0/s", true, true).is_err());
    }

    #[test]
    fn burst_zero_errors() {
        assert!(MiddlewareConfig::from_options("rate=10/s;burst=0", true, true).is_err());
    }

    #[test]
    fn malformed_rate_errors() {
        assert!(MiddlewareConfig::from_options("rate=abc", true, true).is_err());
        assert!(MiddlewareConfig::from_options("rate=10/x", true, true).is_err());
    }

    #[test]
    fn unknown_auth_scheme_errors() {
        assert!(MiddlewareConfig::from_options("auth=digest:x:y", true, true).is_err());
    }

    #[test]
    fn basic_without_colon_errors() {
        assert!(MiddlewareConfig::from_options("auth=basic:nocolon", true, true).is_err());
    }

    #[test]
    fn basic_password_may_contain_colon() {
        let c = MiddlewareConfig::from_options("auth=basic:admin:p:ss", true, true).unwrap();
        match &c.creds[0] {
            Credential::Basic { user, pass } => {
                assert_eq!(user, "admin");
                assert_eq!(pass, "p:ss");
            }
            _ => panic!("expected Basic"),
        }
    }

    #[test]
    fn default_burst_is_one_second_of_rate() {
        // `burst` is None until built; the default shows up in describe/build.
        let c = MiddlewareConfig::from_options("rate=50/s", true, true).unwrap();
        assert_eq!(c.burst, None);
        assert!(c.describe().contains("burst=50"));
    }

    #[test]
    fn disabling_request_id_omits_it_from_chain() {
        let c = MiddlewareConfig::from_options("", false, true).unwrap();
        let d = c.describe();
        assert!(d.contains("log"));
        assert!(!d.contains("request-id"));
    }

    #[test]
    fn default_chain_is_log_and_request_id() {
        let c = MiddlewareConfig::from_options("", true, true).unwrap();
        let d = c.describe();
        assert!(d.contains("log") && d.contains("request-id"));
        assert!(!d.contains("auth") && !d.contains("ratelimit"));
    }
}
