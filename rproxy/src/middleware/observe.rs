//! Observability middleware: request IDs and an access log line.
//!
//! Neither can reject a request, so both are ON by default (`--no-request-id`
//! / `--no-access-log` opt out). They are the two halves of "can you see what
//! the proxy did" — a correlation id on every response, and one line per
//! request. Full structured logging / metrics export is Level 10's job; this
//! is deliberately a single `key=value` line.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Process-wide access-log format toggle (`--log-plain`). A global for the
/// same reason `logging::LEVEL` is: format is an operator decision about the
/// whole process's output stream, not a per-route behavior — a stdout that
/// mixes JSON and prose lines is worse than either alone. Set once in `main`
/// before any traffic; chains built afterwards read it.
static PLAIN: AtomicBool = AtomicBool::new(false);

pub fn set_plain(plain: bool) {
    PLAIN.store(plain, Ordering::Relaxed);
}

pub fn plain_mode() -> bool {
    PLAIN.load(Ordering::Relaxed)
}

use super::{Decision, Middleware, ReqCtx};
use crate::http::{self, RequestHead, ResponseHead};

/// A request identifier is valid to adopt from the client if it is short and
/// contains only characters safe to drop into a log line unescaped. It is a
/// client-controlled string that lands in our logs and in the response, so an
/// unvalidated value is a log-injection vector: a CR/LF would forge a whole
/// log entry, and an unbounded length is a cheap amplification.
pub fn valid_request_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Assigns `X-Request-Id`. Honors a valid inbound value (so a trace stitches
/// across proxy hops) and otherwise generates one.
pub struct RequestId {
    counter: Arc<AtomicU64>,
    /// Per-process seed so ids from two different proxy processes don't collide
    /// in a shared log. Rendered as the hex prefix of every id.
    seed: u64,
}

impl RequestId {
    pub fn new() -> Self {
        // Seed from the wall clock at startup. This is process boot, not the
        // async hot path, so `SystemTime` here is fine. Truncating to u64 nanos
        // is plenty of entropy to separate concurrent processes in a log.
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        RequestId {
            counter: Arc::new(AtomicU64::new(0)),
            seed,
        }
    }
}

impl Middleware for RequestId {
    fn name(&self) -> &'static str {
        "request-id"
    }

    fn on_request(&self, req: &mut RequestHead, ctx: &mut ReqCtx) -> Decision {
        let inbound = http::header(&req.headers, "x-request-id");
        ctx.request_id = match inbound {
            Some(v) if valid_request_id(v) => v.to_string(),
            // Absent, oversized, or hostile: mint our own. NOT a UUID — this is
            // a per-process monotonic counter, honest about its scope and
            // costing exactly one atomic increment.
            _ => format!(
                "{:x}-{}",
                self.seed,
                self.counter.fetch_add(1, Ordering::Relaxed)
            ),
        };
        // Set it on the request so the backend sees the same id we log.
        http::set_header(&mut req.headers, "X-Request-Id", &ctx.request_id);
        Decision::Continue
    }

    fn on_response(&self, ctx: &ReqCtx, resp: &mut ResponseHead) {
        // Echo it back so a client can quote the id in a bug report.
        http::set_header(&mut resp.headers, "X-Request-Id", &ctx.request_id);
    }
}

/// Escape a string for placement inside a JSON string literal. The Level 6
/// lesson about log injection, upgraded for Level 10's format change: the
/// request target is attacker-controlled, and in a JSON log the attack is no
/// longer just a forged line — an unescaped `",` breaks out of the string and
/// forges *fields*, and a raw control byte makes the line unparseable, which
/// silently drops it from every `jq` query (an attacker's favorite outcome).
/// Escapes per RFC 8259: quote, backslash, and all controls < 0x20.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A millisecond duration with one decimal, or JSON `null` when the request
/// never reached the stage. `null` rather than 0 or -1: zero is a legitimate
/// measurement (a pool hit really can connect in ~0 ms), and a sentinel
/// number would poison any aggregation that forgot to filter it.
fn opt_ms(d: Option<std::time::Duration>) -> String {
    match d {
        Some(d) => format!("{:.1}", d.as_secs_f64() * 1000.0),
        None => "null".to_string(),
    }
}

/// Emits one access-log line per request, from `on_response` so it sees the
/// final status and the full duration (it is the outermost layer, so its
/// `on_response` runs last).
///
/// Level 10 upgraded the line from `key=value` prose to one JSON object per
/// line (the structured-events pillar): machines aggregate it —
/// `jq 'select(.status>=500)'` replaces regex archaeology. The `plain` flag
/// (`--log-plain`) keeps the old human-readable line for eyeball debugging.
pub struct AccessLog {
    pub plain: bool,
}

impl Middleware for AccessLog {
    fn name(&self) -> &'static str {
        "log"
    }

    fn on_request(&self, _req: &mut RequestHead, _ctx: &mut ReqCtx) -> Decision {
        // Nothing to do inbound — the `started` timestamp is stamped in
        // `ReqCtx::new`, before the chain, so the duration covers every layer.
        Decision::Continue
    }

    fn on_response(&self, ctx: &ReqCtx, resp: &mut ResponseHead) {
        let dur = ctx.started.elapsed();
        let user = ctx.identity.as_deref().unwrap_or("-");
        let upstream = ctx.upstream.as_deref().unwrap_or("-");
        let backend = ctx.backend.as_deref().unwrap_or("-");
        if self.plain {
            let rejected = ctx
                .rejected_by
                .map(|r| format!(" rejected_by={r}"))
                .unwrap_or_default();
            println!(
                "id={} peer={} method={} target={} status={} dur={:.1}ms upstream={} backend={} user={}{}",
                ctx.request_id,
                ctx.peer,
                ctx.method,
                ctx.target,
                resp.status,
                dur.as_secs_f64() * 1000.0,
                upstream,
                backend,
                user,
                rejected,
            );
            return;
        }
        // One JSON object, one line, one write. Assembled by a single
        // `println!` because stdout is shared by every worker thread — the
        // macro locks stdout per call, so one call per line is what keeps
        // concurrent requests from interleaving mid-object. Keys are static,
        // so only VALUES pass through the escaper. `ts` is wall-clock for
        // cross-system correlation; every duration is monotonic-derived —
        // the two-clocks rule from the design doc.
        let rejected = match ctx.rejected_by {
            Some(r) => format!("\"{}\"", json_escape(r)),
            None => "null".to_string(),
        };
        println!(
            "{{\"ts\":\"{ts}\",\"id\":\"{id}\",\"peer\":\"{peer}\",\"method\":\"{method}\",\
             \"target\":\"{target}\",\"status\":{status},\"dur_ms\":{dur_ms},\
             \"route_ms\":{route_ms},\"connect_ms\":{connect_ms},\"ttfb_ms\":{ttfb_ms},\
             \"upstream\":\"{upstream}\",\"backend\":\"{backend}\",\"user\":\"{user}\",\
             \"pooled\":{pooled},\"cache\":{cache},\"rejected_by\":{rejected}}}",
            ts = crate::logging::rfc3339_now(),
            id = json_escape(&ctx.request_id),
            peer = ctx.peer,
            method = json_escape(&ctx.method),
            target = json_escape(&ctx.target),
            status = resp.status,
            dur_ms = format!("{:.1}", dur.as_secs_f64() * 1000.0),
            route_ms = opt_ms(ctx.t_route),
            connect_ms = opt_ms(ctx.t_connect),
            ttfb_ms = opt_ms(ctx.t_first_byte),
            upstream = json_escape(upstream),
            backend = json_escape(backend),
            user = json_escape(user),
            pooled = ctx.pooled,
            cache = match ctx.cache {
                Some(c) => format!("\"{c}\""),
                None => "null".to_string(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{RequestHead, ResponseHead, Version, header};

    fn req_with(headers: Vec<(String, String)>) -> RequestHead {
        RequestHead {
            method: "GET".into(),
            target: "/".into(),
            version: Version::Http11,
            headers,
        }
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
        let mut resp = ResponseHead {
            version: Version::Http11,
            status: 200,
            reason: "OK".into(),
            headers: vec![],
        };
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

    #[test]
    fn json_escape_hostile_target() {
        // The attack the escaper exists for: a request target that tries to
        // break out of the JSON string and forge fields.
        assert_eq!(
            json_escape(r#"/x","status":200,"forged":"y"#),
            r#"/x\",\"status\":200,\"forged\":\"y"#
        );
        assert_eq!(json_escape("a\r\nb"), r"a\r\nb");
        assert_eq!(json_escape("tab\there"), r"tab\there");
        assert_eq!(json_escape("\x01"), "\\u0001");
        assert_eq!(json_escape("clean/path?q=1"), "clean/path?q=1");
        // UTF-8 passes through untouched (JSON strings are Unicode).
        assert_eq!(json_escape("héllo/世界"), "héllo/世界");
    }

    #[test]
    fn opt_ms_null_vs_zero() {
        use std::time::Duration;
        assert_eq!(opt_ms(None), "null");
        assert_eq!(opt_ms(Some(Duration::ZERO)), "0.0");
        assert_eq!(opt_ms(Some(Duration::from_micros(12_340))), "12.3");
    }
}
