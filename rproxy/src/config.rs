//! Level 12: the configuration file — a TOML subset lowered onto the CLI.
//!
//! # The design decision this file IS
//!
//! Ferrum already has a configuration language: eleven levels of CLI flags,
//! route specs, and upstream specs, each with a parser and startup
//! guardrails. A config file that invented a second schema — nested tables
//! for routes, a `[[middleware]]` array, its own duration grammar — would
//! mean every value has two parsers that must agree forever. They wouldn't;
//! config-vs-flag drift is a classic operational bug.
//!
//! So the file is the CLI vocabulary, persisted: `max-conns = 10000` IS
//! `--max-conns 10000`, an `[upstreams]` entry IS an `--upstream NAME=SPEC`,
//! a `routes` element IS a positional route spec. `load()` lowers the file
//! into an argument vector; real CLI args are appended AFTER it, so the
//! existing last-write-wins `match` in `main.rs` implements "CLI overrides
//! file" without a line of precedence logic. One parser per value, forever.
//!
//! # The subset, stated exactly
//!
//! - `key = value` at top level: quoted strings, integers, `true`/`false`.
//! - one `[upstreams]` table: `NAME = "SPEC"` (the `--upstream` grammar).
//! - one `routes` array of strings, single- or multi-line.
//! - `#` comments, blank lines.
//! - NOTHING else: no nested tables, no floats, no datetimes, no dotted
//!   keys, no inline tables. Anything outside the subset is a loud error
//!   with a line number — this parser refuses to half-understand a file.
//!
//! Duplicate keys are an error, not last-wins: a 400-line config where
//! `max-conns` appears twice is drift in progress, and silently honoring
//! the second occurrence is how it stays hidden.
//!
//! Boolean flags lower asymmetrically: `no-access-log = true` emits
//! `--no-access-log`; `= false` emits nothing (the default IS false —
//! stating it is harmless and explicit).

use std::io;
use std::path::Path;

/// Keys whose CLI flags take a value. Everything here becomes `--key VALUE`.
/// The list is the CLI surface as of L11; `main.rs` remains the authority —
/// an unknown key here fails fast in `load`, and a key known here but
/// removed from `main.rs` would fail there, so the two lists cannot drift
/// silently in either direction.
const VALUE_KEYS: &[&str] = &[
    "listen",
    "admin",
    "log-level",
    "backend-timeout",
    "pool-max-idle",
    "pool-idle-timeout",
    "hc-interval",
    "hc-timeout",
    "hc-backoff-base",
    "hc-backoff-max",
    "hc-fail",
    "hc-success",
    "tls-cert",
    "tls-key",
    "tls-client-ca",
    "tls-client-auth",
    "max-conns",
    "max-conns-per-ip",
    "max-body",
    "max-headers",
    "allow-cidr",
    "deny-cidr",
    "cache-max-bytes",
    "cache-max-entries",
    "cache-max-body",
    "drain-timeout",
];

/// Keys whose CLI flags are bare switches. `key = true` emits `--key`.
const SWITCH_KEYS: &[&str] = &[
    "no-forwarded",
    "no-request-id",
    "no-access-log",
    "log-plain",
];

/// Keys that only take effect at startup. A hot reload (SIGHUP) applies
/// routes/upstreams and warns, by name, about changes to any of these —
/// the same line nginx draws: you can reroute live, you cannot re-listen.
pub const STARTUP_ONLY_KEYS: &[&str] = &[
    "listen",
    "admin",
    "log-level",
    "log-plain",
    "tls-cert",
    "tls-key",
    "tls-client-ca",
    "tls-client-auth",
    "max-conns",
    "max-conns-per-ip",
    "cache-max-bytes",
    "cache-max-entries",
    "cache-max-body",
    "drain-timeout",
];

/// A parsed config file, lowered and ready to merge with the real CLI.
#[derive(Debug)]
pub struct FileConfig {
    /// The file's `listen` value, if any — positional on the CLI, so it
    /// cannot ride in `args` and is applied by `main` only when the real
    /// CLI didn't supply its own listen address.
    pub listen: Option<String>,
    /// Everything else, as the flag vector the CLI parser already speaks:
    /// `--upstream NAME=SPEC` pairs, `--flag value` pairs, bare switches,
    /// then route specs (positionals last, matching CLI convention).
    pub args: Vec<String>,
}

fn err(line_no: usize, msg: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("config line {line_no}: {msg}"),
    )
}

/// Read and lower a config file. Errors carry the 1-based line number —
/// a config error message that doesn't say WHERE is a support ticket.
pub fn load(path: &Path) -> io::Result<FileConfig> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        io::Error::new(e.kind(), format!("config {}: {e}", path.display()))
    })?;
    parse(&text)
}

/// The value grammar, typed by shape: `"..."` = string, `true`/`false` =
/// bool, all-digits = integer. Sizes like `64m` and durations like `30s`
/// must be quoted — they are strings to THIS parser; their real grammar
/// lives in `parse_size`/`parse_duration`, which see them unchanged.
enum Value {
    Str(String),
    Bool(bool),
    Int(String), // kept as text: the CLI parser re-parses it anyway
}

fn parse_value(raw: &str, line_no: usize) -> io::Result<Value> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('"') {
        let Some(inner) = rest.strip_suffix('"') else {
            return Err(err(line_no, format!("unterminated string {raw:?}")));
        };
        if inner.contains('"') {
            return Err(err(line_no, "escaped quotes are outside the subset; simplify the value"));
        }
        return Ok(Value::Str(inner.to_string()));
    }
    match raw {
        "true" => Ok(Value::Bool(true)),
        "false" => Ok(Value::Bool(false)),
        _ if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()) => {
            Ok(Value::Int(raw.to_string()))
        }
        _ => Err(err(
            line_no,
            format!("value {raw:?} is not a quoted string, integer, or bool"),
        )),
    }
}

/// Strip a trailing `#` comment — but not inside a quoted string.
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
}

fn parse(text: &str) -> io::Result<FileConfig> {
    #[derive(PartialEq)]
    enum Section {
        Top,
        Upstreams,
    }
    let mut section = Section::Top;
    let mut listen: Option<String> = None;
    let mut upstream_args: Vec<String> = Vec::new();
    let mut flag_args: Vec<String> = Vec::new();
    let mut route_specs: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    // Multi-line `routes = [` accumulator.
    let mut in_routes_array = false;

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        // Inside a multi-line routes array: each line is `"spec",` until `]`.
        if in_routes_array {
            if line == "]" {
                in_routes_array = false;
                continue;
            }
            let item = line.strip_suffix(',').unwrap_or(line).trim();
            match parse_value(item, line_no)? {
                Value::Str(s) => route_specs.push(s),
                _ => return Err(err(line_no, "routes array elements must be quoted strings")),
            }
            continue;
        }

        // Section headers.
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = match name.trim() {
                "upstreams" => Section::Upstreams,
                other => {
                    return Err(err(
                        line_no,
                        format!("unknown section [{other}] (only [upstreams] exists)"),
                    ))
                }
            };
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(err(line_no, format!("expected key = value, got {line:?}")));
        };
        let key = key.trim();
        let value_raw = value.trim();

        // Pragmatic deviation from strict TOML, documented: `routes` is
        // recognized wherever it appears, even below `[upstreams]`. Strict
        // TOML would assign it to the open table — but "declare the pools,
        // then the routes that use them" is the natural writing order, and
        // punishing it with "unknown upstream routes" would be a support
        // ticket, not a lesson.
        if key == "routes" && section == Section::Upstreams {
            if seen.contains(&"routes".to_string()) {
                return Err(err(line_no, "duplicate key \"routes\""));
            }
            seen.push("routes".to_string());
            if value_raw == "[" {
                in_routes_array = true;
                continue;
            }
        }

        match section {
            Section::Upstreams if key != "routes" => {
                // NAME = "SPEC" — exactly the --upstream grammar. Duplicate
                // names are caught downstream by build_routes; duplicates in
                // the same FILE are caught here for the better line number.
                let dup_key = format!("upstream:{key}");
                if seen.contains(&dup_key) {
                    return Err(err(line_no, format!("duplicate upstream {key:?}")));
                }
                seen.push(dup_key);
                match parse_value(value_raw, line_no)? {
                    Value::Str(spec) => {
                        upstream_args.push("--upstream".to_string());
                        upstream_args.push(format!("{key}={spec}"));
                    }
                    _ => return Err(err(line_no, "upstream specs must be quoted strings")),
                }
            }
            _ => {
                if key != "routes" && seen.contains(&key.to_string()) {
                    return Err(err(
                        line_no,
                        format!("duplicate key {key:?} (last-wins hides config drift; remove one)"),
                    ));
                }
                seen.push(key.to_string());

                if key == "routes" {
                    if value_raw == "[" {
                        in_routes_array = true;
                        continue;
                    }
                    // (single-line array below; seen-tracking for routes was
                    // handled at the top for both sections)
                    // Single-line array: routes = ["a", "b"]
                    let Some(inner) = value_raw
                        .strip_prefix('[')
                        .and_then(|v| v.strip_suffix(']'))
                    else {
                        return Err(err(line_no, "routes must be an array: routes = [ ... ]"));
                    };
                    for item in split_array_items(inner) {
                        let item = item.trim();
                        if item.is_empty() {
                            continue;
                        }
                        match parse_value(item, line_no)? {
                            Value::Str(s) => route_specs.push(s),
                            _ => {
                                return Err(err(
                                    line_no,
                                    "routes array elements must be quoted strings",
                                ))
                            }
                        }
                    }
                    continue;
                }
                if key == "listen" {
                    match parse_value(value_raw, line_no)? {
                        Value::Str(s) => listen = Some(s),
                        _ => return Err(err(line_no, "listen must be a quoted string")),
                    }
                    continue;
                }
                if VALUE_KEYS.contains(&key) {
                    let text = match parse_value(value_raw, line_no)? {
                        Value::Str(s) => s,
                        Value::Int(s) => s,
                        Value::Bool(_) => {
                            return Err(err(
                                line_no,
                                format!("{key} takes a value, not a boolean"),
                            ))
                        }
                    };
                    flag_args.push(format!("--{key}"));
                    flag_args.push(text);
                } else if SWITCH_KEYS.contains(&key) {
                    match parse_value(value_raw, line_no)? {
                        Value::Bool(true) => flag_args.push(format!("--{key}")),
                        Value::Bool(false) => {} // the default; stating it is a no-op
                        _ => {
                            return Err(err(
                                line_no,
                                format!("{key} is a switch: true or false"),
                            ))
                        }
                    }
                } else {
                    return Err(err(line_no, format!("unknown key {key:?}")));
                }
            }
        }
    }

    if in_routes_array {
        return Err(err(
            text.lines().count(),
            "routes array is never closed (missing ])",
        ));
    }

    // Assembly order mirrors a well-formed command line: flags, upstream
    // declarations, then positional route specs LAST — `main.rs`'s `match`
    // treats anything unrecognized as a route spec, so a route spec sitting
    // before a `--flag` would be harmless, but keeping CLI conventions makes
    // the lowered vector printable for debugging (`--validate` shows it).
    let mut args = flag_args;
    args.extend(upstream_args);
    args.extend(route_specs);
    Ok(FileConfig { listen, args })
}

/// Split single-line array items on commas OUTSIDE quotes — a route spec
/// legitimately contains commas (`--upstream` server lists ride inside
/// route options? no — but `allow-cidr` values and future specs might, and
/// the quoted-comma case is cheap to get right now rather than debug later).
fn split_array_items(inner: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut in_str = false;
    for c in inner.chars() {
        match c {
            '"' => {
                in_str = !in_str;
                current.push(c);
            }
            ',' if !in_str => {
                items.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        items.push(current);
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> io::Result<FileConfig> {
        parse(text)
    }

    #[test]
    fn full_file_lowers_in_cli_order() {
        let cfg = p(r#"
# ferrum.toml
listen = "127.0.0.1:8080"
admin = "127.0.0.1:9100"     # observability plane
max-conns = 5000
no-access-log = true
log-plain = false

[upstreams]
api = "127.0.0.1:9001,127.0.0.1:9002;health=/health"

routes = [
  "/api/**=api;cache=60",
  "/=api",
]
"#)
        .unwrap();
        assert_eq!(cfg.listen.as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(
            cfg.args,
            vec![
                "--admin",
                "127.0.0.1:9100",
                "--max-conns",
                "5000",
                "--no-access-log",
                "--upstream",
                "api=127.0.0.1:9001,127.0.0.1:9002;health=/health",
                "/api/**=api;cache=60",
                "/=api",
            ]
        );
    }

    #[test]
    fn single_line_routes_array() {
        let cfg = p(r#"routes = ["/a=127.0.0.1:9001", "/b=127.0.0.1:9002"]"#).unwrap();
        assert_eq!(cfg.args, vec!["/a=127.0.0.1:9001", "/b=127.0.0.1:9002"]);
    }

    #[test]
    fn duplicate_key_is_an_error_not_last_wins() {
        let e = p("max-conns = 1\nmax-conns = 2\n").unwrap_err();
        assert!(e.to_string().contains("line 2"), "{e}");
        assert!(e.to_string().contains("duplicate"), "{e}");
    }

    #[test]
    fn duplicate_upstream_is_an_error() {
        let e = p("[upstreams]\napi = \"127.0.0.1:1\"\napi = \"127.0.0.1:2\"\n").unwrap_err();
        assert!(e.to_string().contains("duplicate upstream"), "{e}");
    }

    #[test]
    fn unknown_key_and_section_are_loud() {
        let e = p("max_conns = 1\n").unwrap_err(); // underscore, not hyphen
        assert!(e.to_string().contains("unknown key"), "{e}");
        let e = p("[middleware]\n").unwrap_err();
        assert!(e.to_string().contains("unknown section"), "{e}");
    }

    #[test]
    fn value_shapes() {
        // Bool where a value is required, and vice versa.
        assert!(p("max-conns = true\n").unwrap_err().to_string().contains("takes a value"));
        assert!(p("no-access-log = \"yes\"\n").unwrap_err().to_string().contains("switch"));
        // Sizes/durations are strings to this parser.
        let cfg = p("max-body = \"64m\"\nbackend-timeout = \"30s\"\n").unwrap();
        assert_eq!(cfg.args, vec!["--max-body", "64m", "--backend-timeout", "30s"]);
        // Unquoted non-integer is rejected with the shape rule.
        assert!(p("max-body = 64m\n").unwrap_err().to_string().contains("not a quoted string"));
    }

    #[test]
    fn comments_and_hash_inside_strings() {
        let cfg = p("listen = \"127.0.0.1:8080\" # the front door\n").unwrap();
        assert_eq!(cfg.listen.as_deref(), Some("127.0.0.1:8080"));
        // A # inside quotes is data, not a comment.
        let cfg = p(r##"routes = ["/x=127.0.0.1:9001;realm=a#b"]"##).unwrap();
        assert_eq!(cfg.args, vec!["/x=127.0.0.1:9001;realm=a#b"]);
    }

    #[test]
    fn unterminated_forms() {
        assert!(p("listen = \"127.0.0.1\n").unwrap_err().to_string().contains("unterminated"));
        let e = p("routes = [\n  \"/a=127.0.0.1:9001\",\n").unwrap_err();
        assert!(e.to_string().contains("never closed"), "{e}");
    }

    #[test]
    fn switch_false_is_a_noop() {
        let cfg = p("no-request-id = false\n").unwrap();
        assert!(cfg.args.is_empty());
    }

    #[test]
    fn error_carries_line_number() {
        let e = p("listen = \"ok\"\n\nbogus-key = 1\n").unwrap_err();
        assert!(e.to_string().contains("line 3"), "{e}");
    }
}
