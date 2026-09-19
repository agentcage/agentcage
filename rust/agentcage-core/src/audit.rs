//! Audit log parsing, filtering, and formatting.
//!
//! Pure-function module — no subprocess/IO, independently testable.
//!
//! This is a port of `src/agentcage/audit.py`. The proxy addon writes one
//! JSON object per request to stderr; `cage audit` reads them back out of
//! `journalctl` (container/vm) or a bind-mounted `audit.jsonl`
//! (apple-container), filters them, and prints either a table, raw JSON or
//! a summary. Everything in here is on the "decide" side of that: callers
//! hand it lines and get values back.
//!
//! The formatting functions are held to *byte* equality with the Python
//! they replace by `tests/fixtures/golden/shared/audit/*` — see
//! `tests/golden_audit.rs`. That includes the colour escapes and the
//! column widths, oddities and all.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::{Map, Value};

// `AuditEntry`, `AuditFilter` and `AuditSummary` repeat the module name on
// purpose: they are the names the Python module exports and the names the
// port plan's cross-reference table uses. Renaming them to `Entry` /
// `Filter` would make every `audit.py` line harder to find from here.
#[allow(clippy::module_name_repetitions)]
/// Parsed audit log entry.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditEntry {
    /// ISO-8601 timestamp the addon stamped the entry with.
    pub ts: String,
    /// `"inbound"` or `"outbound"`; empty on entries that predate the field.
    pub direction: String,
    /// HTTP method, or a DNS pseudo-method. Case is whatever the proxy wrote.
    pub method: String,
    /// Request host.
    pub host: String,
    /// Full request URL.
    pub url: String,
    /// `"allowed"`, `"flagged"` or `"blocked"`.
    pub decision: String,
    /// Human-readable reason, when the proxy supplied one.
    pub reason: String,
    /// Inspector results, as raw JSON objects.
    ///
    /// Kept as unparsed [`Value`]s rather than a struct so that inspector
    /// fields this version does not know about survive a round trip —
    /// custom inspectors are a documented extension point and may write
    /// anything alongside `name` and `severity`.
    pub inspectors: Vec<Value>,
    /// The whole decoded line, so `--json` can re-emit it untouched.
    pub raw: Value,
    /// Destination port, or 0 when absent.
    pub port: i64,
    /// Request path.
    pub path: String,
    /// Source IP, recorded for inbound (relay) requests.
    pub source: String,
    /// Names of secrets injected into this request.
    pub secrets_injected: Vec<String>,
    /// Names of secrets redacted out of this request.
    pub secrets_redacted: Vec<String>,
}

/// Read a string field, defaulting to `""`.
///
/// Python's `d.get("host", "")` returns whatever is under the key, so a
/// non-string would flow into a `str`-typed field and only blow up later
/// (`len(entry.ts)` on an int). There is no such thing as "later" here, so
/// a wrongly-typed field is treated as absent. No producer writes one and
/// the golden corpus does not cover it.
fn get_str(d: &Map<String, Value>, key: &str) -> String {
    d.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Read a list-of-strings field, defaulting to empty.
///
/// Non-string elements are dropped rather than kept: Python keeps them in
/// the list and then raises `TypeError` from the `", ".join(...)` in
/// [`format_table_row`], which is not behaviour worth reproducing.
fn get_str_list(d: &Map<String, Value>, key: &str) -> Vec<String> {
    d.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

impl AuditEntry {
    /// Build an entry from a decoded audit JSON object.
    ///
    /// Every field is optional: entries written by older proxy builds are
    /// missing `direction`, `port`, `path`, `source` and the secret lists,
    /// and `cage audit` must still render them.
    #[must_use]
    pub fn from_value(d: &Value) -> Self {
        // A non-object cannot reach here through `extract_audit_json`
        // (which requires a leading `{`), but the constructor is public,
        // so one reads as an object with every field missing.
        let empty = Map::new();
        let obj = d.as_object().unwrap_or(&empty);
        Self {
            ts: get_str(obj, "ts"),
            direction: get_str(obj, "direction"),
            method: get_str(obj, "method"),
            host: get_str(obj, "host"),
            url: get_str(obj, "url"),
            decision: get_str(obj, "decision"),
            reason: get_str(obj, "reason"),
            inspectors: obj
                .get("inspectors")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            raw: d.clone(),
            port: obj.get("port").and_then(Value::as_i64).unwrap_or(0),
            path: get_str(obj, "path"),
            source: get_str(obj, "source"),
            secrets_injected: get_str_list(obj, "secrets_injected"),
            secrets_redacted: get_str_list(obj, "secrets_redacted"),
        }
    }
}

/// An inspector result's `name`, or `""` when it has none.
fn inspector_name(insp: &Value) -> &str {
    insp.get("name").and_then(Value::as_str).unwrap_or("")
}

/// An inspector result's `severity`, defaulting to `"info"`.
fn inspector_severity(insp: &Value) -> &str {
    insp.get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info")
}

/// Filter criteria for audit entries.
///
/// Every field is an AND term; the list-valued ones are OR within
/// themselves. An all-empty filter matches everything.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Keep only these decisions (exact match).
    pub decisions: Vec<String>,
    /// Keep only these directions (exact match).
    pub directions: Vec<String>,
    /// Keep entries whose host *contains* any of these (substring match).
    pub hosts: Vec<String>,
    /// Keep entries triggered by any of these inspectors (exact name).
    pub inspectors: Vec<String>,
    /// Keep entries with an inspector at or above this severity.
    pub min_severity: Option<String>,
    /// Keep only these methods (case-insensitive).
    pub methods: Vec<String>,
    /// Drop entries with a timestamp strictly older than this. Honored on
    /// backends whose `audit_argv()` has no native time index
    /// (apple-container's tail), giving `--since` parity with the
    /// journalctl-backed container/vm paths. `None` disables time filtering.
    pub since: Option<Timestamp>,
}

impl AuditFilter {
    /// True if `entry` passes every criterion.
    #[must_use]
    pub fn matches(&self, entry: &AuditEntry) -> bool {
        if !self.decisions.is_empty() && !self.decisions.contains(&entry.decision) {
            return false;
        }
        if !self.directions.is_empty() && !self.directions.contains(&entry.direction) {
            return false;
        }
        if !self.hosts.is_empty() && !self.hosts.iter().any(|h| entry.host.contains(h)) {
            return false;
        }
        if !self.inspectors.is_empty() {
            let entry_inspectors: Vec<&str> = entry.inspectors.iter().map(inspector_name).collect();
            if !self
                .inspectors
                .iter()
                .any(|name| entry_inspectors.contains(&name.as_str()))
            {
                return false;
            }
        }
        if self.min_severity.is_some() && !self.meets_severity(entry) {
            return false;
        }
        if !self.methods.is_empty() {
            let method = entry.method.to_uppercase();
            if !self.methods.iter().any(|m| m.to_uppercase() == method) {
                return false;
            }
        }
        if self.since.is_some() && !self.after_since(entry) {
            return false;
        }
        true
    }

    /// True if the entry is at/after `since`.
    ///
    /// A missing or unparseable timestamp is kept (fail-open), mirroring
    /// `CaptureFilter` in `har.py` so a malformed record is never silently
    /// dropped by a time window.
    fn after_since(&self, entry: &AuditEntry) -> bool {
        if entry.ts.is_empty() {
            return true;
        }
        let Some(entry_ts) = Timestamp::parse_iso(&entry.ts) else {
            return true;
        };
        // Naive timestamps on either side are read as UTC, which is what
        // Python's `replace(tzinfo=timezone.utc)` does to both the entry
        // and the cutoff before comparing. `Timestamp` folds that in at
        // parse time, so there is nothing left to reconcile here.
        let Some(since) = self.since else { return true };
        entry_ts >= since
    }

    fn meets_severity(&self, entry: &AuditEntry) -> bool {
        // The ladder mixes two vocabularies: the inspector severities
        // (debug..critical, the classic order) and the traffic watcher's
        // model-facing enum (info/low/medium/high/critical — see
        // data/proxy/watcher.py _record_finding, which ranks its findings
        // here). Without the low/medium/high entries, a lookup miss
        // scoring 0 would rank a watcher finding the model called "high"
        // BELOW "info" — invisible to every `cage audit --severity
        // warning` query. Ranked on the same scale: low ≙ info, medium ≙
        // warning, high ≙ error; critical is shared.
        // `"debug"` scores 0 like an unknown severity does. It is spelled
        // out anyway because it is a real rung of the ladder, not a
        // fallback, and deleting it would hide that the bottom rung and
        // "I have no idea what this is" are the same number.
        #[allow(clippy::match_same_arms)]
        fn rank(sev: &str) -> u8 {
            match sev {
                "debug" => 0,
                "info" | "low" => 1,
                "warning" | "medium" => 2,
                "error" | "high" => 3,
                "critical" => 4,
                // An unknown severity — including an unknown
                // `--severity` argument — scores 0, which for the
                // threshold means "no filter at all". See below.
                _ => 0,
            }
        }
        let min_ord = self.min_severity.as_deref().map_or(0, rank);
        if min_ord == 0 {
            return true;
        }
        for insp in &entry.inspectors {
            if rank(inspector_severity(insp)) >= min_ord {
                return true;
            }
        }
        // No inspector met the threshold — only pass if no severity filter
        // needed. In practice unreachable as anything but `false`: the
        // `min_ord == 0` early return above already took that branch.
        // Kept in the shape of the original so the two read the same.
        entry.inspectors.is_empty() && min_ord == 0
    }
}

// ── timestamps ───────────────────────────────────────────────

/// An instant, to microsecond resolution, as understood by
/// [`datetime.fromisoformat`].
///
/// # Why this is hand-rolled
///
/// The only thing audit filtering does with a timestamp is compare two of
/// them, and the only producer of `ts` is
/// `datetime.now(timezone.utc).isoformat()` in the proxy addon. A date-time
/// crate would bring a calendar, a locale story and a leap-second opinion
/// to a problem that is one `i64` comparison. See the crate docs on keeping
/// the dependency surface deliberate.
///
/// Naive (offset-less) timestamps are read as UTC. Python reaches the same
/// place by `replace(tzinfo=timezone.utc)`-ing both sides of the comparison
/// in `AuditFilter._after_since`; doing it at parse time means the rest of
/// the module never has to think about it.
///
/// [`datetime.fromisoformat`]: https://docs.python.org/3/library/datetime.html#datetime.datetime.fromisoformat
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    micros: i64,
}

impl Timestamp {
    /// Microseconds since the Unix epoch, UTC.
    #[must_use]
    pub const fn unix_micros(self) -> i64 {
        self.micros
    }

    /// Build a timestamp from microseconds since the Unix epoch, UTC.
    #[must_use]
    pub const fn from_unix_micros(micros: i64) -> Self {
        Self { micros }
    }

    /// Parse an ISO-8601 string the way `CPython` 3.11+'s
    /// `datetime.fromisoformat` does, returning `None` where it would raise
    /// `ValueError`.
    ///
    /// Supported, because `fromisoformat` supports them: extended and basic
    /// calendar dates (`2024-01-01`, `20240101`), ISO week dates
    /// (`2024-W01-1`, `2024W011`, `2024-W01`), *any* single character as
    /// the date/time separator (`T`, a space, or anything else), the time
    /// forms `HH`, `HH:MM`, `HHMM`, `HH:MM:SS`, `HHMMSS`, a `.` or `,`
    /// fraction of any length (digits past the sixth are discarded, not
    /// rounded), and the offsets `Z`, `±HH`, `±HHMM`, `±HH:MM`, `±HHMMSS`,
    /// `±HH:MM:SS` and `±HH:MM:SS.ffffff`.
    ///
    /// Deliberately rejected, also matching `CPython`: a lowercase `z`,
    /// unpadded components (`2024-1-1`), an offset of 24 hours or more,
    /// and a trailing `.` with no digits.
    #[must_use]
    pub fn parse_iso(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        // `fromisoformat` is ASCII-only; bail before indexing bytes.
        if !s.is_ascii() {
            return None;
        }
        let (days, date_len) = parse_iso_date(b)?;
        if b.len() == date_len {
            return Some(Self {
                micros: days.checked_mul(86_400_000_000)?,
            });
        }
        // Any single character separates date from time — CPython does not
        // care whether it is `T`.
        let rest = &b[date_len + 1..];
        let (time_micros, offset_micros) = parse_iso_time(rest)?;
        let micros = days
            .checked_mul(86_400_000_000)?
            .checked_add(time_micros)?
            .checked_sub(offset_micros)?;
        Some(Self { micros })
    }
}

/// Days from 1970-01-01 for a proleptic-Gregorian y/m/d. Howard Hinnant's
/// `days_from_civil`, which is exact for the whole `datetime` range.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`], used only to range-check the year a
/// week date lands in.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

const fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

const fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// True if ISO year `y` has 53 weeks: it does when 1 January is a Thursday,
/// or when it is a Wednesday in a leap year.
fn iso_year_has_53_weeks(y: i64) -> bool {
    // 1970-01-01 was a Thursday, i.e. ISO weekday 4.
    let jan1 = days_from_civil(y, 1, 1);
    let weekday = jan1.rem_euclid(7) + 4; // 1=Mon .. 7=Sun, pre-wrap
    let weekday = (weekday - 1) % 7 + 1;
    weekday == 4 || (weekday == 3 && is_leap(y))
}

/// Parse `n` ASCII digits at `b[at..]`.
fn digits(b: &[u8], at: usize, n: usize) -> Option<i64> {
    let slice = b.get(at..at + n)?;
    if !slice.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut v = 0i64;
    for &c in slice {
        v = v * 10 + i64::from(c - b'0');
    }
    Some(v)
}

/// Parse the date half, returning (days since epoch, bytes consumed).
fn parse_iso_date(b: &[u8]) -> Option<(i64, usize)> {
    // Week dates announce themselves with a `W` in position 4 or 5.
    let week_at = match b.get(4) {
        Some(b'W') => Some(4),
        Some(b'-') if b.get(5) == Some(&b'W') => Some(5),
        _ => None,
    };
    if let Some(w) = week_at {
        return parse_iso_week_date(b, w);
    }
    let year = digits(b, 0, 4)?;
    // Extended `YYYY-MM-DD` or basic `YYYYMMDD`; nothing shorter is legal.
    let (month, day, len) = if b.get(4) == Some(&b'-') {
        if b.get(7) != Some(&b'-') {
            return None;
        }
        (digits(b, 5, 2)?, digits(b, 8, 2)?, 10)
    } else {
        (digits(b, 4, 2)?, digits(b, 6, 2)?, 8)
    };
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    if year < 1 {
        return None;
    }
    Some((days_from_civil(year, month, day), len))
}

/// Parse `YYYY-Www[-D]` / `YYYYWww[D]`, with `W` already located at `w`.
///
/// The weekday is optional and defaults to Monday, which makes finding the
/// end of the date the fiddly part: whatever follows the week number is
/// either the weekday or the date/time separator. `CPython` decides by
/// shape — extended form takes a weekday only behind a `-`, basic form
/// only when the next character is a digit — so `2024-W01T00:00` and
/// `2024W01T00:00` both parse while `2024W01-1` does not.
fn parse_iso_week_date(b: &[u8], w: usize) -> Option<(i64, usize)> {
    let extended = w == 5;
    let year = digits(b, 0, 4)?;
    let week = digits(b, w + 1, 2)?;
    let after_week = w + 3;
    let (day, len) = if extended {
        if b.get(after_week) == Some(&b'-') {
            (digits(b, after_week + 1, 1)?, after_week + 2)
        } else {
            (1, after_week)
        }
    } else if b.get(after_week).is_some_and(u8::is_ascii_digit) {
        (digits(b, after_week, 1)?, after_week + 1)
    } else {
        (1, after_week)
    };
    if !(1..=7).contains(&day) {
        return None;
    }
    if !(1..=53).contains(&week) || (week == 53 && !iso_year_has_53_weeks(year)) {
        return None;
    }
    // Week 1 is the week containing 4 January, so its Monday is 4 January
    // minus that date's zero-based ISO weekday.
    let jan4 = days_from_civil(year, 1, 4);
    let jan4_weekday = (jan4.rem_euclid(7) + 3) % 7; // 0=Mon
    let days = jan4 - jan4_weekday + (week - 1) * 7 + (day - 1);
    let (landed_year, _, _) = civil_from_days(days);
    if !(1..=9999).contains(&landed_year) {
        return None;
    }
    Some((days, len))
}

/// Parse the time half plus optional offset, returning (microseconds into
/// the day, offset microseconds east of UTC).
fn parse_iso_time(b: &[u8]) -> Option<(i64, i64)> {
    // Split the offset off first; `Z` is accepted only uppercase.
    let (time, offset) = match b.iter().position(|&c| c == b'Z' || c == b'+' || c == b'-') {
        Some(i) if b[i] == b'Z' => {
            if i + 1 != b.len() {
                return None;
            }
            (&b[..i], 0)
        }
        Some(i) => (&b[..i], parse_iso_offset(&b[i..])?),
        None => (b, 0),
    };
    let hour = digits(time, 0, 2)?;
    let extended = time.get(2) == Some(&b':');
    let step = usize::from(extended);
    let (minute, second, after) = match time.len() {
        2 => (0, 0, 2),
        n if n >= 4 + step => {
            let minute = digits(time, 2 + step, 2)?;
            if n == 4 + step {
                (minute, 0, 4 + step)
            } else {
                if extended && time.get(5) != Some(&b':') {
                    return None;
                }
                (minute, digits(time, 4 + 2 * step, 2)?, 6 + 2 * step)
            }
        }
        _ => return None,
    };
    let frac = parse_iso_fraction(&time[after.min(time.len())..])?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some((
        hour * 3_600_000_000 + minute * 60_000_000 + second * 1_000_000 + frac,
        offset,
    ))
}

/// Parse a trailing `.`/`,` fraction into microseconds. Digits past the
/// sixth are discarded — `CPython` truncates rather than rounds.
fn parse_iso_fraction(b: &[u8]) -> Option<i64> {
    if b.is_empty() {
        return Some(0);
    }
    if b[0] != b'.' && b[0] != b',' {
        return None;
    }
    let digits_part = &b[1..];
    if digits_part.is_empty() || !digits_part.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut micros = 0i64;
    for i in 0..6 {
        let d = digits_part.get(i).map_or(0, |c| i64::from(c - b'0'));
        micros = micros * 10 + d;
    }
    Some(micros)
}

/// Parse `±HH[:MM[:SS[.ffffff]]]` into microseconds east of UTC.
fn parse_iso_offset(b: &[u8]) -> Option<i64> {
    let sign = match b.first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let body = &b[1..];
    let hour = digits(body, 0, 2)?;
    let extended = body.get(2) == Some(&b':');
    let step = usize::from(extended);
    let (minute, second, after) = match body.len() {
        2 => (0, 0, 2),
        n if n >= 4 + step => {
            let minute = digits(body, 2 + step, 2)?;
            if n == 4 + step {
                (minute, 0, 4 + step)
            } else {
                if extended && body.get(5) != Some(&b':') {
                    return None;
                }
                (minute, digits(body, 4 + 2 * step, 2)?, 6 + 2 * step)
            }
        }
        _ => return None,
    };
    let frac = parse_iso_fraction(&body[after.min(body.len())..])?;
    let magnitude = hour * 3_600_000_000 + minute * 60_000_000 + second * 1_000_000 + frac;
    // `timezone()` rejects an offset of a whole day or more.
    if magnitude >= 86_400_000_000 {
        return None;
    }
    Some(sign * magnitude)
}

// ── line extraction ──────────────────────────────────────────

/// Python's `str.isspace()`, which is what `str.strip()` trims.
///
/// Wider than Rust's `char::is_whitespace`: Python also counts the four
/// ASCII separator controls (U+001C–U+001F). Journald has been known to
/// pass control bytes through, so the difference is not purely theoretical.
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

/// Strip a VM-mode log prefix, if present.
///
/// Matches Python's `^\[(?:proxy|dns):(?:debug|info|warning|error|critical)\]\s*(.*)$`,
/// hand-rolled rather than pulled from a regex crate for one fixed shape.
///
/// The `$`-with-`.` detail is load-bearing and easy to lose: `.` does not
/// match a newline and `$` (no `re.MULTILINE`) only anchors at the end of
/// the string, so a prefixed line that still contains an embedded newline
/// does *not* match — it falls through to the `{` check below and is
/// dropped. Reproduced here by the explicit newline test.
fn strip_vm_prefix(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('[')?;
    let (inside, after) = rest.split_once(']')?;
    let (stream, level) = inside.split_once(':')?;
    if !matches!(stream, "proxy" | "dns") {
        return None;
    }
    if !matches!(level, "debug" | "info" | "warning" | "error" | "critical") {
        return None;
    }
    let after = after.trim_start_matches(char::is_whitespace);
    if after.contains('\n') {
        return None;
    }
    Some(py_strip(after))
}

/// Extract an audit JSON dict from a raw journalctl line.
///
/// Handles both container mode (raw JSON) and VM mode
/// (`[proxy:level] {json}` prefix). Returns `None` for non-audit lines.
#[must_use]
pub fn extract_audit_json(line: &str) -> Option<Value> {
    let line = py_strip(line);
    if line.is_empty() {
        return None;
    }

    // Try VM-mode prefix first
    let line = strip_vm_prefix(line).unwrap_or(line);

    // Must look like JSON
    if !line.starts_with('{') {
        return None;
    }

    let d: Value = serde_json::from_str(line).ok()?;

    // Must have the audit entry signature
    let obj = d.as_object()?;
    if !obj.contains_key("decision") || !obj.contains_key("method") {
        return None;
    }

    Some(d)
}

// ── summary ──────────────────────────────────────────────────

/// Counts keyed by a string, in first-seen order.
///
/// Stands in for `collections.Counter` + `dict`, whose iteration order is
/// insertion order and *is* observable: [`format_summary`] prints the
/// method and decision tallies in the order the entries arrived, and
/// `most_common` breaks ties the same way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrderedCounts(Vec<(String, u64)>);

impl OrderedCounts {
    /// The count recorded for `key`, or 0.
    #[must_use]
    pub fn get(&self, key: &str) -> u64 {
        self.0.iter().find(|(k, _)| k == key).map_or(0, |(_, v)| *v)
    }

    /// Iterate `(key, count)` in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> {
        self.0.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// True when nothing was counted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for OrderedCounts {
    /// Serializes as a JSON object, like the `dict` Python hands back.
    ///
    /// The insertion order kept above is dropped here on purpose: the
    /// corpus writes these with `json.dumps(..., sort_keys=True)`, and
    /// `serde_json`'s `Map` is a `BTreeMap`, which sorts by the same
    /// code-point order Python does.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(self.0.iter().map(|(k, v)| (k, v)))
    }
}

/// Insertion-ordered counter, the mutable side of [`OrderedCounts`].
#[derive(Debug, Default)]
struct Counter {
    order: Vec<(String, u64)>,
    index: HashMap<String, usize>,
}

impl Counter {
    fn bump(&mut self, key: &str) {
        if let Some(&i) = self.index.get(key) {
            self.order[i].1 += 1;
        } else {
            self.index.insert(key.to_owned(), self.order.len());
            self.order.push((key.to_owned(), 1));
        }
    }

    fn into_counts(self) -> OrderedCounts {
        OrderedCounts(self.order)
    }

    /// `Counter.most_common(n)`: highest count first, ties in first-seen
    /// order. `heapq.nlargest` is stable and so is `sort_by`, so the two
    /// agree without any extra tie-break.
    fn most_common(&self, n: usize) -> OrderedCounts {
        let mut items = self.order.clone();
        items.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        items.truncate(n);
        OrderedCounts(items)
    }
}

/// Aggregate statistics from audit entries.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AuditSummary {
    /// Number of entries summarized.
    pub total: usize,
    /// Count per decision, in first-seen order.
    pub decisions: OrderedCounts,
    /// Count per direction, in first-seen order. Entries with no
    /// `direction` are not counted at all.
    pub directions: OrderedCounts,
    /// The ten busiest hosts.
    pub top_hosts: OrderedCounts,
    /// The ten most-blocked hosts.
    pub top_blocked_hosts: OrderedCounts,
    /// The ten most-triggered inspectors.
    pub inspector_triggers: OrderedCounts,
    /// Count per method, in first-seen order. Case is not normalized, so a
    /// proxy that wrote `post` and one that wrote `POST` show up as two
    /// rows — visible in the golden corpus, and arguably a bug, but it is
    /// the Python behaviour.
    pub methods: OrderedCounts,
}

/// Aggregate statistics from audit entries.
#[must_use]
pub fn compute_summary(entries: &[AuditEntry]) -> AuditSummary {
    let mut decisions = Counter::default();
    let mut directions = Counter::default();
    let mut hosts = Counter::default();
    let mut blocked_hosts = Counter::default();
    let mut inspector_triggers = Counter::default();
    let mut methods = Counter::default();

    for e in entries {
        decisions.bump(&e.decision);
        if !e.direction.is_empty() {
            directions.bump(&e.direction);
        }
        hosts.bump(&e.host);
        methods.bump(&e.method);
        if e.decision == "blocked" {
            blocked_hosts.bump(&e.host);
        }
        for insp in &e.inspectors {
            // Note the default: `"unknown"` here, but `""` in the
            // inspector-name *filter*. An unnamed inspector is therefore
            // counted but unselectable.
            let name = insp
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            inspector_triggers.bump(name);
        }
    }

    AuditSummary {
        total: entries.len(),
        decisions: decisions.into_counts(),
        directions: directions.into_counts(),
        top_hosts: hosts.most_common(10),
        top_blocked_hosts: blocked_hosts.most_common(10),
        inspector_triggers: inspector_triggers.most_common(10),
        methods: methods.into_counts(),
    }
}

// ── formatting ───────────────────────────────────────────────

/// SGR colour for each decision, matching `_DECISION_COLORS` in the Python.
///
/// These are the codes `click.style(fg=...)` emits; the reset is click's
/// default `reset=True` tail. Click is not a dependency of this crate and a
/// colour crate would be three constants' worth of overhead, so the escape
/// is written out.
const fn decision_color(decision: &str) -> Option<&'static str> {
    match decision.as_bytes() {
        b"blocked" => Some("31"),
        b"flagged" => Some("33"),
        b"allowed" => Some("32"),
        _ => None,
    }
}

/// Truncate to at most `n` characters, like Python's `s[:n]`.
fn truncate(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// Pad `s` on the right to `width` characters, like Python's `f"{s:<width}"`.
///
/// `format!("{s:<width$}")` would do the same thing; this exists so the
/// column arithmetic below reads as data rather than as a wall of format
/// specifiers, and so the widths sit in one place.
fn ljust(s: &str, width: usize) -> String {
    let len = s.chars().count();
    let mut out = String::with_capacity(s.len() + width.saturating_sub(len));
    out.push_str(s);
    for _ in len..width {
        out.push(' ');
    }
    out
}

/// Return column header for table output.
#[must_use]
pub fn format_table_header() -> String {
    format!(
        "{} {} {} {} {} {} {} REASON",
        ljust("TIMESTAMP", 26),
        ljust("DIRECTION", 10),
        ljust("METHOD", 8),
        ljust("HOST", 25),
        ljust("PORT", 5),
        ljust("PATH", 20),
        ljust("DECISION", 10),
    )
}

/// Format a single audit entry as a table row.
#[must_use]
pub fn format_table_row(entry: &AuditEntry, color: bool) -> String {
    let ts = truncate(&entry.ts, 25);
    let dir_label = match entry.direction.as_str() {
        "inbound" => "INBOUND",
        "outbound" => "OUTBOUND",
        _ => "",
    };
    let method = truncate(&entry.method, 7);
    let host = truncate(&entry.host, 24);
    let port = if entry.port == 0 {
        String::new()
    } else {
        entry.port.to_string()
    };
    let path = truncate(&entry.path, 19);
    let decision = entry.decision.as_str();
    let mut reason = entry.reason.clone();

    if reason.is_empty() && !entry.inspectors.is_empty() {
        // Build reason from inspector results
        let mut parts: Vec<String> = Vec::new();
        for insp in &entry.inspectors {
            let name = inspector_name(insp);
            let r = insp.get("reason").and_then(Value::as_str).unwrap_or("");
            if !name.is_empty() && !r.is_empty() {
                parts.push(format!("{name}: {r}"));
            } else if !r.is_empty() {
                parts.push(r.to_owned());
            }
        }
        reason = parts.join("; ");
    }

    // Append source IP for inbound requests
    if !entry.source.is_empty() {
        reason = if reason.is_empty() {
            format!("source {}", entry.source)
        } else {
            format!("source {}; {reason}", entry.source)
        };
    }

    // Append secret operation indicators
    if !entry.secrets_injected.is_empty() {
        let tag = format!("[injected: {}]", entry.secrets_injected.join(", "));
        reason = if reason.is_empty() {
            tag
        } else {
            format!("{reason}; {tag}")
        };
    }
    if !entry.secrets_redacted.is_empty() {
        let tag = format!("[redacted: {}]", entry.secrets_redacted.join(", "));
        reason = if reason.is_empty() {
            tag
        } else {
            format!("{reason}; {tag}")
        };
    }

    let Some(fg) = (if color {
        decision_color(decision)
    } else {
        None
    }) else {
        return format!(
            "{} {} {} {} {} {} {} {reason}",
            ljust(ts, 26),
            ljust(dir_label, 10),
            ljust(method, 8),
            ljust(host, 25),
            ljust(&port, 5),
            ljust(path, 20),
            ljust(decision, 10),
        );
    };

    // Color just the decision column.
    //
    // Note the DIRECTION column is padded to 4 here and to 10 above. That
    // is not a transcription slip: the Python rebuilds the whole row inside
    // the colour branch and writes `{dir_label:<4}` in it, so every
    // coloured row with a direction is six columns narrower than the header
    // from that point on. It is reproduced because the golden corpus
    // records it; see the port notes for the bug report.
    let colored_decision = format!("\u{1b}[{fg}m{}\u{1b}[0m", ljust(decision, 10));
    format!(
        "{} {} {} {} {} {} {colored_decision} {reason}",
        ljust(ts, 26),
        ljust(dir_label, 4),
        ljust(method, 8),
        ljust(host, 25),
        ljust(&port, 5),
        ljust(path, 20),
    )
}

/// Format `count` as `(NN%)` of `total`, or `""` when there is no total.
///
/// Integer division, floored — Python's `//`. 7 of 8 reads as 87%, not 88%.
fn percent(count: u64, total: usize) -> String {
    if total == 0 {
        String::new()
    } else {
        format!("({}%)", count * 100 / total as u64)
    }
}

/// Format summary statistics as a human-readable report.
///
/// Returns the report without a trailing newline, like `"\n".join(lines)`.
#[must_use]
#[allow(clippy::missing_panics_doc)] // writes into a String, which cannot fail
pub fn format_summary(summary: &AuditSummary) -> String {
    let mut lines: Vec<String> = Vec::new();
    let total = summary.total;
    lines.push(format!("Total entries: {total}"));
    lines.push(String::new());

    // Decisions. Printed from a fixed list rather than from the counter, so
    // the three always appear in severity order and a decision with no hits
    // still shows its zero.
    lines.push("Decisions:".to_owned());
    for d in ["blocked", "flagged", "allowed"] {
        let count = summary.decisions.get(d);
        lines.push(format!(
            "  {} {count:>6}  {}",
            ljust(d, 10),
            percent(count, total)
        ));
    }
    lines.push(String::new());

    // Directions
    if !summary.directions.is_empty() {
        lines.push("Directions:".to_owned());
        for d in ["outbound", "inbound"] {
            let count = summary.directions.get(d);
            if count != 0 {
                lines.push(format!(
                    "  {} {count:>6}  {}",
                    ljust(d, 10),
                    percent(count, total)
                ));
            }
        }
        lines.push(String::new());
    }

    let mut block = |title: &str, counts: &OrderedCounts, width: usize| {
        if counts.is_empty() {
            return;
        }
        lines.push(title.to_owned());
        for (key, count) in counts.iter() {
            lines.push(format!("  {} {count:>6}", ljust(key, width)));
        }
        lines.push(String::new());
    };

    block("Top hosts:", &summary.top_hosts, 40);
    block("Top blocked hosts:", &summary.top_blocked_hosts, 40);
    block("Inspector triggers:", &summary.inspector_triggers, 30);

    // Methods, last and with no trailing blank line.
    if !summary.methods.is_empty() {
        lines.push("Methods:".to_owned());
        for (method, count) in summary.methods.iter() {
            lines.push(format!("  {} {count:>6}", ljust(method, 10)));
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Timestamp::parse_iso` against `datetime.fromisoformat`.
    ///
    /// The golden corpus exercises exactly three timestamp shapes — aware,
    /// naive and unparseable — because that is all `audit.jsonl` contains.
    /// This table is the rest of the surface, and it is not hand-reasoned:
    /// every row was produced by running the string through `CPython`'s
    /// `datetime.fromisoformat` and converting the result to microseconds
    /// since the epoch (naive read as UTC, which is what
    /// `AuditFilter._after_since` does to both sides before comparing).
    /// A `None` is a `ValueError` there.
    #[test]
    fn iso_timestamps_agree_with_cpython() {
        let cases: &[(&str, Option<i64>)] = &[
            // the two shapes the proxy addon actually writes
            ("2024-01-01T00:00:00+00:00", Some(1_704_067_200_000_000)),
            ("2024-02-02T08:30:00", Some(1_706_862_600_000_000)),
            // dates alone, extended and basic
            ("2024-01-01", Some(1_704_067_200_000_000)),
            ("20240101", Some(1_704_067_200_000_000)),
            // any character separates date from time; `Z` only uppercase
            ("2024-01-01 12:34:56", Some(1_704_112_496_000_000)),
            ("2024-01-01x00:00:00", Some(1_704_067_200_000_000)),
            ("2024-01-01T00:00:00Z", Some(1_704_067_200_000_000)),
            ("2024-01-01T00:00:00z", None),
            // partial and basic times
            ("2024-01-01T00", Some(1_704_067_200_000_000)),
            ("2024-01-01T00:00", Some(1_704_067_200_000_000)),
            ("2024-01-01T0000", Some(1_704_067_200_000_000)),
            ("2024-01-01T000000", Some(1_704_067_200_000_000)),
            // fractions: `,` allowed, over six digits truncated
            ("2024-01-01T00:00:00.5", Some(1_704_067_200_500_000)),
            ("2024-01-01T00:00:00,123", Some(1_704_067_200_123_000)),
            ("2024-01-01T00:00:00.1234567", Some(1_704_067_200_123_456)),
            (
                "2024-01-01T00:00:00.123456789012",
                Some(1_704_067_200_123_456),
            ),
            ("2024-01-01T00:00:00.", None),
            // offsets
            ("2024-01-01T00:00:00+0530", Some(1_704_047_400_000_000)),
            ("2024-01-01T00:00:00+05:30", Some(1_704_047_400_000_000)),
            ("2024-01-01T00:00:00-05", Some(1_704_085_200_000_000)),
            ("2024-01-01T00:00:00+00:00:30", Some(1_704_067_170_000_000)),
            (
                "2024-01-01T00:00:00+23:59:59.999999",
                Some(1_703_980_800_000_001),
            ),
            ("2024-01-01T00:00:00+24:00", None),
            ("2024-01-01T00:00:00Z+01:00", None),
            // ISO week dates, including the 53-week rule
            ("2024-W01-1", Some(1_704_067_200_000_000)),
            ("2024W011", Some(1_704_067_200_000_000)),
            ("2024-W01", Some(1_704_067_200_000_000)),
            ("2024W01", Some(1_704_067_200_000_000)),
            ("2024-W01T00:00:00", Some(1_704_067_200_000_000)),
            ("2024W01T00:00:00", Some(1_704_067_200_000_000)),
            ("2024-W01-1T05:00:00", Some(1_704_085_200_000_000)),
            ("2020-W53-1", Some(1_609_113_600_000_000)),
            ("2021-W53-1", None),
            ("2024-W53-1", None),
            ("2024-W00-1", None),
            ("2024-W01-0", None),
            ("2024-W01-8", None),
            ("2024-W011", None),
            ("2024W01-1", None),
            ("2024-W01-", None),
            // range checks
            ("2024-02-29", Some(1_709_164_800_000_000)),
            ("2023-02-29", None),
            ("2024-02-30", None),
            ("2024-13-01", None),
            ("2024-00-01", None),
            ("2024-01-00", None),
            ("2024-01-01T24:00:00", None),
            ("2024-01-01T00:60:00", None),
            ("2024-01-01T00:00:60", None),
            // the ends of datetime's range, and before the epoch
            ("0001-01-01T00:00:00", Some(-62_135_596_800_000_000)),
            ("0001-W01-1", Some(-62_135_596_800_000_000)),
            (
                "9999-12-31T23:59:59.999999+23:59",
                Some(253_402_214_459_999_999),
            ),
            ("1969-12-31T23:59:59+00:00", Some(-1_000_000)),
            // outright junk, including the corpus's own `not-a-timestamp`
            ("not-a-timestamp", None),
            ("", None),
            ("2024-1-1", None),
            ("24-01-01", None),
            ("2024-01-01T", None),
        ];
        for (input, expected) in cases {
            let got = Timestamp::parse_iso(input).map(Timestamp::unix_micros);
            assert_eq!(got, *expected, "parsing {input:?}");
        }
    }

    /// Non-UTF-8-free inputs must not index past a char boundary.
    #[test]
    fn iso_parse_rejects_non_ascii_without_panicking() {
        assert_eq!(Timestamp::parse_iso("２０２４-01-01"), None);
        assert_eq!(Timestamp::parse_iso("2024-01-01Tñ0:00"), None);
    }

    /// Line extraction beyond what the corpus fixture reaches.
    #[test]
    fn extract_rejects_and_accepts_the_right_lines() {
        let audit = r#"{"decision":"allowed","method":"GET"}"#;
        assert!(extract_audit_json(audit).is_some());
        // whitespace-padded, both modes
        assert!(extract_audit_json(&format!("  {audit}  ")).is_some());
        assert!(extract_audit_json(&format!("[proxy:warning] {audit}")).is_some());
        assert!(extract_audit_json(&format!("[dns:info]{audit}")).is_some());
        // an unknown stream or level is not a prefix, so the `[` sinks it
        assert!(extract_audit_json(&format!("[http:info] {audit}")).is_none());
        assert!(extract_audit_json(&format!("[proxy:trace] {audit}")).is_none());
        // the signature keys are both required
        assert!(extract_audit_json(r#"{"decision":"allowed"}"#).is_none());
        assert!(extract_audit_json(r#"{"method":"GET"}"#).is_none());
        // and the line has to be JSON at all
        assert!(extract_audit_json("").is_none());
        assert!(extract_audit_json("   ").is_none());
        assert!(extract_audit_json("podman: no such container").is_none());
        assert!(extract_audit_json(r#"{"decision":"allowed","method":}"#).is_none());
        // a prefixed line carrying a newline does not match the prefix, and
        // then fails the `{` test — see `strip_vm_prefix`
        assert!(extract_audit_json(&format!("[proxy:info] {audit}\n{audit}")).is_none());
    }

    fn entry(json: &str) -> AuditEntry {
        AuditEntry::from_value(&serde_json::from_str(json).expect("valid JSON"))
    }

    /// An entry written by a proxy old enough to lack every optional field.
    #[test]
    fn from_value_tolerates_a_bare_entry() {
        let e = entry(r#"{"decision":"allowed","method":"GET"}"#);
        assert_eq!(e.port, 0);
        assert!(e.direction.is_empty());
        assert!(e.inspectors.is_empty());
        assert!(e.secrets_injected.is_empty());
        // port 0 renders as blank, not as "0"
        assert!(format_table_row(&e, false).contains("           allowed"));
    }

    /// An unknown `--severity` disables the filter rather than rejecting
    /// everything, because the rank lookup misses and scores 0. Worth
    /// pinning: it is the kind of thing a port would "fix" by accident.
    #[test]
    fn unknown_min_severity_is_a_no_op() {
        let e = entry(r#"{"decision":"allowed","method":"GET","inspectors":[]}"#);
        let filt = AuditFilter {
            min_severity: Some("bogus".to_owned()),
            ..Default::default()
        };
        assert!(filt.matches(&e));
    }

    /// A known threshold drops an entry with no inspectors at all.
    #[test]
    fn severity_threshold_drops_uninspected_entries() {
        let e = entry(r#"{"decision":"allowed","method":"GET","inspectors":[]}"#);
        let filt = AuditFilter {
            min_severity: Some("warning".to_owned()),
            ..Default::default()
        };
        assert!(!filt.matches(&e));
    }

    /// `most_common` ties break on first-seen order, not alphabetically.
    #[test]
    fn tied_host_counts_keep_insertion_order() {
        let entries: Vec<AuditEntry> = ["zulu", "alpha", "zulu", "alpha"]
            .iter()
            .map(|h| {
                entry(&format!(
                    r#"{{"decision":"allowed","method":"GET","host":"{h}"}}"#
                ))
            })
            .collect();
        let summary = compute_summary(&entries);
        let hosts: Vec<&str> = summary.top_hosts.iter().map(|(k, _)| k).collect();
        assert_eq!(hosts, ["zulu", "alpha"]);
    }

    /// `most_common(10)` is a cap, and it is the only one.
    #[test]
    fn top_hosts_is_capped_at_ten() {
        let entries: Vec<AuditEntry> = (0..15)
            .map(|i| {
                entry(&format!(
                    r#"{{"decision":"allowed","method":"GET","host":"h{i}.example.com"}}"#
                ))
            })
            .collect();
        let summary = compute_summary(&entries);
        assert_eq!(summary.total, 15);
        assert_eq!(summary.top_hosts.iter().count(), 10);
        // methods are *not* capped, they are a plain dict
        assert_eq!(summary.methods.get("GET"), 15);
    }

    /// Zero entries: percentages collapse to the empty string, the optional
    /// blocks vanish, and the report is three lines plus its blanks. Not in
    /// the corpus, which only ever summarizes a populated log.
    #[test]
    fn empty_summary_renders_without_percentages() {
        let summary = compute_summary(&[]);
        assert_eq!(
            format_summary(&summary),
            "Total entries: 0\n\nDecisions:\n  blocked         0  \
             \n  flagged         0  \n  allowed         0  \n"
        );
    }

    /// Reason synthesis: absent a `reason`, the inspectors supply one, and
    /// source/secret tags append in a fixed order.
    #[test]
    fn table_row_builds_its_reason_column() {
        let e = entry(
            r#"{"decision":"blocked","method":"POST","host":"h","port":443,
                "inspectors":[{"name":"domain","reason":"not allowed"},
                              {"reason":"nameless"},
                              {"name":"quiet"}],
                "source":"10.0.0.1",
                "secrets_injected":["A","B"],"secrets_redacted":["C"]}"#,
        );
        let row = format_table_row(&e, false);
        let reason = row.split_once("blocked").expect("decision column").1;
        assert_eq!(
            reason.trim_start(),
            "source 10.0.0.1; domain: not allowed; nameless; \
             [injected: A, B]; [redacted: C]"
        );
    }

    /// Over-long fields are cut, not wrapped, and the cut is by character.
    #[test]
    fn table_row_truncates_wide_columns() {
        let e = entry(
            r#"{"decision":"allowed","method":"PROPPATCH",
                "host":"a-very-long-hostname.example.com",
                "path":"/a/very/long/path/that/keeps/going",
                "ts":"2024-01-01T00:00:00.123456+00:00"}"#,
        );
        let row = format_table_row(&e, false);
        assert!(row.starts_with("2024-01-01T00:00:00.12345 "), "{row}");
        assert!(row.contains("PROPPAT "), "{row}");
        assert!(row.contains("a-very-long-hostname.exa "), "{row}");
        assert!(row.contains("/a/very/long/path/t "), "{row}");
    }

    /// A decision with no colour assigned takes the *uncoloured* layout,
    /// wide DIRECTION column and all, even with `color = true`.
    #[test]
    fn uncoloured_decision_keeps_the_wide_layout() {
        let e = entry(r#"{"decision":"errored","method":"GET","direction":"outbound"}"#);
        assert_eq!(format_table_row(&e, true), format_table_row(&e, false));
        assert!(format_table_row(&e, true).starts_with(&" ".repeat(26)));
    }
}
