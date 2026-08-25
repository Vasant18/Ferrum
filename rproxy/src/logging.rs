//! Level 10: the error log — leveled diagnostics on stderr.
//!
//! The split this file enforces: the **access log** (observe.rs) is one
//! machine-parseable JSON line per request on stdout; the **error log** is
//! human-readable, leveled, and on stderr. Two streams because they have two
//! audiences — `jq` reads one, a person mid-incident reads the other — and
//! an operator must be able to redirect them independently (`2>errors.log`).
//!
//! Before this level, Ferrum's request path printed unconditionally: every
//! request cost several `println!`s of routing/rewrite/pick diagnostics.
//! Those lines were priceless while *building* levels 2–8 and are noise in
//! operation — the classic reason log levels exist. They are now `debug!`,
//! silent by default, and one `--log-level debug` brings them all back.
//!
//! Hand-rolled rather than the `log`/`tracing` crates, per the Level 10
//! design decision: the mechanism (a global level, macros that check it
//! before formatting) is exactly what those crates do at their core, and it
//! is 60 lines.
//!
//! The level lives in a global `AtomicU8`, set once in `main` before any
//! traffic and read on every log call. A global rather than a threaded
//! parameter for the same reason the crates all make this choice: a log
//! call's *entire value* is that it can appear anywhere — inside `Drop`
//! impls, in the balancer's breaker transitions, three layers deep in a
//! parser — and threading a `&Logger` through every one of those signatures
//! would tax every function in the program for the benefit of none.
//! `Ordering::Relaxed` because the level is write-once-at-boot; no reader
//! orders anything against it.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl Level {
    pub fn parse(s: &str) -> Result<Level, String> {
        match s.to_ascii_lowercase().as_str() {
            "error" => Ok(Level::Error),
            "warn" => Ok(Level::Warn),
            "info" => Ok(Level::Info),
            "debug" => Ok(Level::Debug),
            _ => Err(format!(
                "unknown log level {s:?} (expected error|warn|info|debug)"
            )),
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
        }
    }
}

/// Default `Info`: operational events visible, per-request diagnostics not.
static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

pub fn set_level(l: Level) {
    LEVEL.store(l as u8, Ordering::Relaxed);
}

/// The check the macros do FIRST, before any formatting. This gating is the
/// entire performance story of a log level: a suppressed `debug!` must cost
/// one atomic load and a compare — not a `format!` allocation that gets
/// thrown away. The macro takes `format_args!` lazily, so arguments are not
/// even evaluated unless the level passes.
pub fn enabled(l: Level) -> bool {
    (l as u8) <= LEVEL.load(Ordering::Relaxed)
}

/// The single sink. One `eprintln!` call per line — `eprintln` takes a lock
/// on stderr per call, so a line is never interleaved mid-way with another
/// task's line (the same atomicity the old bare `eprintln!`s relied on).
pub fn emit(l: Level, args: std::fmt::Arguments<'_>) {
    eprintln!("{} {:5} {}", rfc3339_now(), l.tag(), args);
}

/// Current wall-clock time as RFC 3339 UTC with millisecond precision,
/// e.g. `2026-08-25T09:14:02.417Z`. Shared by the error log and the JSON
/// access log (observe.rs) so the two streams correlate line-for-line.
///
/// Hand-rolled calendar math because the alternative is a dependency
/// (`chrono`) for what is genuinely ~15 lines: the days-to-civil-date
/// algorithm below is Howard Hinnant's `civil_from_days`, the same one
/// inside every date library. UTC only — no timezone table, no DST, which
/// is precisely why logs are written in UTC in the first place.
pub fn rfc3339_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339(now.as_secs(), now.subsec_millis())
}

fn rfc3339(unix_secs: u64, millis: u32) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Days since 1970-01-01 → (year, month, day) in the proleptic Gregorian
/// calendar. The shifted-era trick: move the year start to March so leap
/// days land at the *end* of the counting year and the month-length pattern
/// becomes the linear ramp `(153m + 2) / 5`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of 400-year era
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The four macros. `$crate::` paths so call sites just `use` nothing —
/// `crate::error!(...)` works from any module. Each checks `enabled` before
/// touching its arguments (see `enabled` for why that ordering is the point).
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        if $crate::logging::enabled($crate::logging::Level::Error) {
            $crate::logging::emit($crate::logging::Level::Error, format_args!($($arg)*));
        }
    };
}
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        if $crate::logging::enabled($crate::logging::Level::Warn) {
            $crate::logging::emit($crate::logging::Level::Warn, format_args!($($arg)*));
        }
    };
}
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        if $crate::logging::enabled($crate::logging::Level::Info) {
            $crate::logging::emit($crate::logging::Level::Info, format_args!($($arg)*));
        }
    };
}
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::logging::enabled($crate::logging::Level::Debug) {
            $crate::logging::emit($crate::logging::Level::Debug, format_args!($($arg)*));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_ordering_gates_correctly() {
        set_level(Level::Warn);
        assert!(enabled(Level::Error));
        assert!(enabled(Level::Warn));
        assert!(!enabled(Level::Info));
        assert!(!enabled(Level::Debug));
        set_level(Level::Info); // restore the default for other tests
    }

    #[test]
    fn level_parse() {
        assert_eq!(Level::parse("DEBUG").unwrap(), Level::Debug);
        assert_eq!(Level::parse("warn").unwrap(), Level::Warn);
        assert!(Level::parse("verbose").is_err());
    }

    #[test]
    fn rfc3339_known_instants() {
        // 2026-08-25T00:00:00Z == 1787616000 (a known fixed point to pin the
        // civil_from_days math, cross-checked against Python), and the epoch.
        assert_eq!(rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_787_616_000, 7), "2026-08-25T00:00:00.007Z");
        // Leap-year day: 2024-02-29T12:00:00Z == 1709208000.
        assert_eq!(rfc3339(1_709_208_000, 999), "2024-02-29T12:00:00.999Z");
        // Century non-leap boundary handled by the era math: 2100-03-01.
        assert_eq!(rfc3339(4_107_542_400, 0), "2100-03-01T00:00:00.000Z");
    }
}
