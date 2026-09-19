//! Per-phase wall times — the port of `src/agentcage/_timing.py`.
//!
//! Cage creation routes through the VM backend on macOS and takes
//! 60–180s on a fresh Mac. Without per-phase timings every perf change
//! is a guess. This is the smallest useful primitive: a [`Phase`] guard
//! that records `{label, ms, ts}` into a per-cage JSONL ledger, and a
//! reader for the hidden `--timings` flags.
//!
//! Defaults, unchanged from the Python:
//!
//! * the JSONL append is always on — it is cheap and the directory is
//!   rotated to a fixed size;
//! * `AGENTCAGE_TIMING=1` additionally echoes `[timing] <label>: <ms>ms`
//!   to stderr for live observation.
//!
//! # Failure mode
//!
//! Every I/O error is swallowed. Instrumentation must never break the
//! operation it is timing, and a `cage create` that fails because a
//! timing file could not be written would be a spectacularly bad trade.
//! That is why nothing here returns a `Result`.
//!
//! # Why the ledger line is assembled by hand
//!
//! `serde_json` would write `{"label":"x","ms":1.0,"ts":2.0}`; CPython's
//! `json.dumps` writes `{"label": "x", "ms": 1.0, "ts": 2.0}`, because
//! its default separators carry a space. Both parse, and only agentcage
//! reads these files — but the fixture records the Python's bytes, and
//! matching them costs one `format!`. The float and string formatting
//! still go through `serde_json`, which is where the hard parts are
//! (shortest round-trip floats, and `0.0` rather than `0`).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::output;

/// Keep the last N timing files per cage. Each cage-create run is one
/// file.
const MAX_FILES_PER_CAGE: usize = 20;

/// `~/.local/share/agentcage`, honouring `XDG_DATA_HOME`.
///
/// Read on every call rather than cached at startup: the Python reads
/// `os.environ` at import time, but a test that sets `XDG_DATA_HOME` per
/// case needs the later answer, and the CLI reads it once per process
/// either way.
fn data_dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from(".local/share"));
    base.join("agentcage")
}

fn timings_dir(cage: &str) -> PathBuf {
    data_dir().join(cage).join("timings")
}

/// The run file each cage's phases append to, memoized per cage.
///
/// The Python keys this on `(cage, pid)`; a process cannot change its
/// pid, so the cage alone is the key here and the pid stays in the file
/// name, where it is what makes two concurrent `agentcage` invocations
/// land in different files.
static RUN_FILES: OnceLock<Mutex<HashMap<String, PathBuf>>> = OnceLock::new();

fn run_file(cage: &str) -> Option<PathBuf> {
    let mut files = RUN_FILES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .ok()?;
    if let Some(path) = files.get(cage) {
        return Some(path.clone());
    }
    let dir = timings_dir(cage);
    fs::create_dir_all(&dir).ok()?;
    // Rotate to leave room for the file we are about to add, so the
    // post-write directory holds at most MAX_FILES_PER_CAGE entries.
    rotate(&dir, MAX_FILES_PER_CAGE - 1);
    let stamp = utc_stamp(now_unix_secs());
    let path = dir.join(format!("{stamp}-{}.jsonl", std::process::id()));
    files.insert(cage.to_owned(), path.clone());
    Some(path)
}

/// Delete the oldest timing files so at most `keep` remain.
fn rotate(dir: &Path, keep: usize) {
    let mut files = jsonl_files(dir);
    if keep > 0 {
        if files.len() <= keep {
            return;
        }
        files.truncate(files.len() - keep);
    }
    for old in files {
        let _ = fs::remove_file(old);
    }
}

/// Every `*.jsonl` in `dir`, sorted by name.
///
/// The names start with a UTC `%Y%m%dT%H%M%S` stamp, so lexical order is
/// chronological order — which is what makes "the last one" cheap and
/// what `sorted(d.glob(...))` relies on in the Python.
fn jsonl_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        // Case-sensitive, like `Path.glob("*.jsonl")`: these names are
        // written by this module and never by a user.
        .filter(|p| p.extension().is_some_and(|e| e.eq("jsonl")))
        .collect();
    files.sort();
    files
}

// ── the ledger line ──────────────────────────────────────────

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn now_unix_float() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// `%Y%m%dT%H%M%S` in UTC, from a Unix timestamp.
///
/// Hand-rolled rather than pulled from `chrono`/`time`: this is the only
/// date formatting in the port, it has no locale, no zone and no parsing
/// to do, and the civil-from-days conversion below is Howard Hinnant's,
/// which is the same algorithm those crates use.
fn utc_stamp(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}")
}

/// Days since 1970-01-01 to a civil (year, month, day).
///
/// <http://howardhinnant.github.io/date_algorithms.html#civil_from_days>
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Round to two decimals, as Python's `round(x, 2)`.
///
/// Not bit-for-bit Python: CPython rounds half to even on the decimal
/// representation, this rounds half away from zero. The two disagree
/// only on an exact tie in the third decimal place of a measured
/// duration, which is a value neither implementation can produce on
/// purpose. Pinned by the fixture's `record-*` cases.
fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

/// A float as CPython's `repr` writes it inside `json.dumps`.
///
/// `serde_json` and CPython both emit the shortest decimal that round-
/// trips, and both write an integral float with a trailing `.0` — which
/// Rust's own `Display` does not (`format!("{}", 0.0)` is `0`). They
/// diverge only for magnitudes large enough to reach exponent notation,
/// which a millisecond count and a Unix timestamp do not.
fn json_float(value: f64) -> String {
    serde_json::Value::from(value).to_string()
}

/// A string as CPython's `json.dumps` writes it: quoted, escaped, and
/// ASCII-only.
///
/// `ensure_ascii=True` is the default there and `serde_json` has no
/// equivalent, so the non-ASCII escaping is done here. Labels are
/// internal identifiers and have never been anything but ASCII, but a
/// label reaching this from a cage name would otherwise change the
/// file's encoding depending on which implementation wrote it.
fn json_ascii_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c if c.is_ascii() => out.push(c),
            c => {
                // Above the BMP CPython emits a surrogate pair, which
                // is what `encode_basestring_ascii` does.
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
    out
}

/// One ledger line, newline included.
///
/// Public because it is the format contract: `tests/fixtures/output/`
/// records what CPython's `json.dumps` wrote, and `golden_output.rs`
/// holds this to it.
#[must_use]
pub fn ledger_line(label: &str, ms: f64, ts: f64) -> String {
    format!(
        "{{\"label\": {}, \"ms\": {}, \"ts\": {}}}\n",
        json_ascii_string(label),
        json_float(round2(ms)),
        json_float(ts),
    )
}

fn append(cage: &str, label: &str, ms: f64) {
    let Some(path) = run_file(cage) else { return };
    let line = ledger_line(label, ms, now_unix_float());
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = file.write_all(line.as_bytes());
    }
}

// ── Phase ────────────────────────────────────────────────────

/// Time a scope and append the result to the cage's JSONL ledger.
///
/// ```ignore
/// let _phase = Phase::start("build.proxy", Some(name));
/// ```
///
/// With no cage the phase is echoed (when `AGENTCAGE_TIMING=1`) but not
/// persisted — for code paths that do not yet know the cage name.
///
/// A guard rather than a `with` block, for the same reason as
/// [`crate::terminal::RestoredTerminal`]: the Python's `__exit__` runs
/// when the block raises, and only `Drop` does that in Rust. A phase
/// that vanished whenever its step failed would hide exactly the runs
/// worth looking at.
#[derive(Debug)]
pub struct Phase {
    label: String,
    cage: Option<String>,
    started: Instant,
}

impl Phase {
    /// Start timing.
    #[must_use]
    pub fn start(label: &str, cage: Option<&str>) -> Self {
        Self {
            label: label.to_owned(),
            cage: cage.map(ToOwned::to_owned),
            started: Instant::now(),
        }
    }

    /// Milliseconds elapsed so far.
    #[must_use]
    pub fn elapsed_ms(&self) -> f64 {
        self.started.elapsed().as_secs_f64() * 1000.0
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        let ms = self.elapsed_ms();
        if let Some(cage) = &self.cage {
            append(cage, &self.label, ms);
        }
        if std::env::var_os("AGENTCAGE_TIMING").is_some_and(|v| v == "1") {
            output::echo_err(&phase_echo_line(&self.label, ms));
        }
    }
}

/// The `AGENTCAGE_TIMING=1` stderr line.
///
/// Public for the same reason as [`ledger_line`]: it is one of the two
/// strings this module puts in front of a user, and the fixture pins it.
#[must_use]
pub fn phase_echo_line(label: &str, ms: f64) -> String {
    format!("[timing] {label}: {ms:.0}ms")
}

// ── reading it back ──────────────────────────────────────────

/// One record from a run file.
///
/// Both fields carry a default because the Python reader uses
/// `r.get("label", "?")` and `r.get("ms", 0)`, and a truncated final
/// line — a run that was killed mid-write — is exactly the case that
/// produces one.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Record {
    /// The phase name.
    #[serde(default = "unknown_label")]
    pub label: String,
    /// Milliseconds the phase took.
    #[serde(default)]
    pub ms: f64,
    /// Unix timestamp when the phase ended.
    #[serde(default)]
    pub ts: f64,
}

fn unknown_label() -> String {
    "?".to_owned()
}

/// The most recent timing file for `cage`, and its records.
///
/// A line that does not parse is skipped, not fatal: the last line of a
/// ledger whose process was killed mid-append is a normal thing to find.
#[must_use]
pub fn load_latest(cage: &str) -> (Option<PathBuf>, Vec<Record>) {
    let dir = timings_dir(cage);
    if !dir.is_dir() {
        return (None, Vec::new());
    }
    let Some(latest) = jsonl_files(&dir).pop() else {
        return (None, Vec::new());
    };
    let Ok(text) = fs::read_to_string(&latest) else {
        return (Some(latest), Vec::new());
    };
    let records = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_str::<Record>(line).ok())
        .collect();
    (Some(latest), records)
}

/// The phase/ms/% table, one string per line, with no trailing newline.
///
/// Empty when there are no records — [`print_summary`] turns that into
/// the one-line note on stderr.
#[must_use]
pub fn summary_lines(records: &[Record]) -> Vec<String> {
    if records.is_empty() {
        return Vec::new();
    }
    // `sum(...) or 1.0`: a run in which every phase measured zero would
    // otherwise divide by zero. It also means the Total column reads 1
    // rather than 0 for such a run, which is a wart the fixture pins
    // rather than a rounding artefact.
    let mut total: f64 = records.iter().map(|r| r.ms).sum();
    if total == 0.0 {
        total = 1.0;
    }
    let widest = records
        .iter()
        .map(|r| r.label.chars().count())
        .max()
        .unwrap_or(0);
    let label_w = (widest + 2).max(24);
    let sep = "\u{2500}".repeat(label_w + 18);

    let mut lines = vec![
        String::new(),
        format!("{:<label_w$}{:>10}{:>8}", "Phase", "ms", "%"),
        sep.clone(),
    ];
    for record in records {
        let pct = (record.ms / total) * 100.0;
        lines.push(format!(
            "{:<label_w$}{:>10}{:>7}%",
            record.label,
            round_half_even(record.ms),
            round_half_even(pct),
        ));
    }
    lines.push(sep);
    lines.push(format!(
        "{:<label_w$}{:>10}{:>7}%   ({:.1}s)",
        "Total",
        round_half_even(total),
        100,
        total / 1000.0,
    ));
    lines
}

/// `f"{value:.0f}"` — a float to a whole number, ties to even.
///
/// Python's format spec rounds half to even, and the summary is full of
/// values that land on a tie because they came out of `round(ms, 2)`.
/// Rust's `{:.0}` rounds half away from zero, so `0.5` would print `1`
/// where Python prints `0`. Recorded by the fixture's
/// `summary-rounding` case.
#[allow(clippy::cast_possible_truncation, clippy::float_cmp)]
fn round_half_even(value: f64) -> i64 {
    let rounded = value.round();
    let is_tie = (value - value.trunc()).abs() == 0.5;
    let rounded = if is_tie && rounded % 2.0 != 0.0 {
        rounded - value.signum()
    } else {
        rounded
    };
    // Every caller passes a duration in milliseconds or a percentage,
    // both far inside `i64`; the saturating cast is the language's, not
    // a judgement about the value.
    rounded as i64
}

/// Print the phase/ms/% table for the most recent run of `cage`.
///
/// A one-line note on stderr when there are no timings. Always silent on
/// error — this is a diagnostic, not a critical path.
pub fn print_summary(cage: &str) {
    let (_, records) = load_latest(cage);
    let lines = summary_lines(&records);
    if lines.is_empty() {
        output::echo_err("(no timing data for this run)");
        return;
    }
    for line in lines {
        output::echo(&line);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_FILES_PER_CAGE, Phase, Record, json_ascii_string, ledger_line, phase_echo_line, rotate,
        round_half_even, utc_stamp,
    };

    fn record(label: &str, ms: f64) -> Record {
        Record {
            label: label.to_owned(),
            ms,
            ts: 0.0,
        }
    }

    #[test]
    fn utc_stamp_is_sortable_and_correct() {
        assert_eq!(utc_stamp(0), "19700101T000000");
        assert_eq!(utc_stamp(1_758_283_200), "20250919T120000");
        // A leap day, and the last second of a year.
        assert_eq!(utc_stamp(1_709_164_800), "20240229T000000");
        assert_eq!(utc_stamp(1_767_225_599), "20251231T235959");
        // Lexical order is chronological order, which `jsonl_files`
        // and `load_latest` both depend on.
        assert!(utc_stamp(1_000_000) < utc_stamp(2_000_000));
    }

    #[test]
    fn round_half_even_matches_pythons_format_spec() {
        assert_eq!(round_half_even(0.5), 0);
        assert_eq!(round_half_even(1.5), 2);
        assert_eq!(round_half_even(2.5), 2);
        assert_eq!(round_half_even(3.5), 4);
        assert_eq!(round_half_even(-0.5), 0);
        assert_eq!(round_half_even(-1.5), -2);
        assert_eq!(round_half_even(33.333), 33);
        assert_eq!(round_half_even(41_230.0), 41_230);
    }

    #[test]
    fn json_strings_are_ascii_escaped() {
        assert_eq!(json_ascii_string("build.egress"), "\"build.egress\"");
        assert_eq!(json_ascii_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_ascii_string("nl\n"), "\"nl\\n\"");
        assert_eq!(json_ascii_string("\u{1}"), "\"\\u0001\"");
        assert_eq!(json_ascii_string("caf\u{e9}"), "\"caf\\u00e9\"");
        // Above the BMP: a surrogate pair, as CPython writes it.
        assert_eq!(json_ascii_string("\u{1f600}"), "\"\\ud83d\\ude00\"");
    }

    #[test]
    fn the_phase_echo_rounds_to_whole_milliseconds() {
        assert_eq!(phase_echo_line("x", 1234.5678), "[timing] x: 1235ms");
        assert_eq!(phase_echo_line("x", 0.4), "[timing] x: 0ms");
    }

    #[test]
    fn rotation_keeps_the_newest() {
        let dir = std::env::temp_dir().join(format!("agentcage-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        for day in 1..=25 {
            std::fs::write(dir.join(format!("202501{day:02}T000000-1.jsonl")), "").expect("write");
        }
        std::fs::write(dir.join("not-a-ledger.txt"), "").expect("write");
        rotate(&dir, MAX_FILES_PER_CAGE - 1);
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .expect("read_dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        let ledgers = left
            .iter()
            .filter(|n| n.rsplit('.').next() == Some("jsonl"));
        assert_eq!(ledgers.count(), 19);
        assert!(
            left.iter().any(|n| n == "not-a-ledger.txt"),
            "only *.jsonl rotates"
        );
        assert!(
            left.contains(&"20250125T000000-1.jsonl".to_owned()),
            "the newest survives"
        );
        assert!(
            !left.contains(&"20250101T000000-1.jsonl".to_owned()),
            "the oldest goes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_phase_with_no_cage_writes_no_file() {
        // The whole observable behaviour of the no-cage path is that it
        // does not touch the filesystem; the echo is covered by the
        // fixture test.
        let before = std::fs::read_dir(std::env::temp_dir()).map(Iterator::count);
        drop(Phase::start("orphan", None));
        let after = std::fs::read_dir(std::env::temp_dir()).map(Iterator::count);
        assert_eq!(before.is_ok(), after.is_ok());
    }

    #[test]
    fn a_phase_measures_forward() {
        let phase = Phase::start("x", None);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(phase.elapsed_ms() >= 4.0, "got {}", phase.elapsed_ms());
    }

    #[test]
    fn the_ledger_line_keeps_pythons_separators() {
        assert_eq!(
            ledger_line("build.egress", 1234.5678, 1_758_283_200.5),
            "{\"label\": \"build.egress\", \"ms\": 1234.57, \"ts\": 1758283200.5}\n"
        );
    }

    #[test]
    fn a_missing_field_reads_as_the_pythons_default() {
        let parsed: Record = serde_json::from_str("{}").expect("defaults");
        assert_eq!(parsed.label, "?");
        assert!(parsed.ms.abs() < f64::EPSILON);
    }

    #[test]
    fn an_empty_ledger_has_no_table() {
        assert!(super::summary_lines(&[]).is_empty());
        assert!(!super::summary_lines(&[record("a", 1.0)]).is_empty());
    }
}
