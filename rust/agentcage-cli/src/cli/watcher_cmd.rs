//! `cli.watcher_findings` and `cli.watcher_status` — reading the
//! in-egress traffic watcher's output.
//!
//! The watcher runs inside the egress, re-reads the cage's recent audit
//! and capture after the fact, and writes two files onto the grants
//! volume: `watcher/findings.jsonl` and `watcher/state.json`. These two
//! commands are readers of those files and nothing else — no scan is
//! triggered, no grant is changed.
//!
//! # The three-state read, which is the whole subtlety
//!
//! [`load_output`] answers `Some("")`, `Some(text)` or `None`, and the
//! difference between the first and the last is load-bearing:
//!
//! * `Some("")` — the file is not there. That is the **normal**
//!   pre-first-scan state, and it must read as "nothing yet".
//! * `None` — the read failed. On a `vm` cage that means the guest
//!   could not be reached.
//!
//! Collapsing those two would make an unreachable VM report an
//! all-clear, which for a command whose entire job is surfacing
//! suspicious traffic is the worst possible direction to fail in. The
//! Python's comment on `_load_watcher_output` says exactly this, and
//! `pull_watcher_output`'s exit-42 sentinel exists to keep the two
//! apart over `limactl shell`.

use agentcage_core::config::Config;
use agentcage_core::har::json::{self, DumpOptions, Json};
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE};

/// `_watcher_vol_dir` / `_load_watcher_output` — one output file,
/// isolation-aware.
///
/// `container` and `apple-container` bind the grants volume from the
/// host, so the file is read directly. A `vm` cage's volume is
/// guest-local — Lima's host-to-guest write caching cannot be trusted,
/// see `quadlets.vm_local_grants_dir` — so it comes back over
/// `limactl shell`.
fn load_output(ctx: &Ctx, name: &str, config: &Config, relative: &str) -> Option<String> {
    if config.isolation == "vm" {
        let backend = ctx.backend_for(&config.isolation);
        return backend
            .as_vm()
            .and_then(|vm| vm.pull_watcher_output(name, relative));
    }
    let path = ctx.paths.grants_dir(name).join("watcher").join(relative);
    match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        // `except FileNotFoundError: return ""` — absent is "no scan
        // yet", not a failure.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(String::new()),
        Err(_) => None,
    }
}

/// The cage's stored config, or the refusal both commands share.
fn open_cage(ctx: &Ctx, matches: &ArgMatches) -> Result<(String, Config), std::process::ExitCode> {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    if !ctx.paths.deployment_exists(&name) {
        eprintln!("error: cage '{name}' does not exist");
        return Err(std::process::ExitCode::from(EXIT_FAILURE));
    }
    let config = ctx
        .paths
        .load_deployment_config(&name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            std::process::ExitCode::from(EXIT_FAILURE)
        })?;
    Ok((name, config))
}

/// `watcher findings`.
pub(crate) fn findings(ctx: &Ctx, matches: &ArgMatches) -> std::process::ExitCode {
    let (name, config) = match open_cage(ctx, matches) {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    let Some(text) = load_output(ctx, &name, &config, "findings.jsonl") else {
        eprintln!(
            "error: could not reach the VM for cage '{name}' — the watcher's \
             findings live guest-side. Start the cage and retry."
        );
        return std::process::ExitCode::from(EXIT_FAILURE);
    };

    let severities: Vec<String> = multi(matches, "severities");
    let hosts: Vec<String> = multi(matches, "hosts");
    let max_entries = *matches.get_one::<i64>("max_entries").unwrap_or(&50);
    let as_json = matches.get_flag("as_json");

    // An unparseable line is skipped, not fatal: the file is appended to
    // by a process in another VM and a torn final line is a normal thing
    // to meet, not a reason to show the operator nothing.
    let mut entries: Vec<Json> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(entry) = json::parse(line) else {
            continue;
        };
        if !severities.is_empty() && !severities.contains(&field(&entry, "severity")) {
            continue;
        }
        if !hosts.is_empty() {
            let host = field(&entry, "host");
            if !hosts.iter().any(|wanted| host.contains(wanted.as_str())) {
                continue;
            }
        }
        entries.push(entry);
    }

    if entries.is_empty() {
        println!("(no watcher findings recorded)");
        return std::process::ExitCode::SUCCESS;
    }
    // `entries[-max_entries:]` — the most recent, which for an appended
    // log is the tail.
    if max_entries > 0 {
        let keep = usize::try_from(max_entries).unwrap_or(usize::MAX);
        let start = entries.len().saturating_sub(keep);
        entries.drain(..start);
    }

    if as_json {
        for entry in &entries {
            // Through `har::json::dumps`, not `serde_json`: Python's
            // default separators carry a space after each comma and
            // `serde_json`'s do not, and `cage audit --json` already
            // goes through the same door for the same reason.
            println!("{}", json::dumps(entry, DumpOptions::default()));
        }
        return std::process::ExitCode::SUCCESS;
    }

    // HOST, matching the audit table's column and this command's own
    // `--host` filter: the field really is `host`, and a finding's
    // domain rides it too.
    println!("{:<26} {:<9} {:<30} TITLE", "TIMESTAMP", "SEVERITY", "HOST");
    for entry in &entries {
        println!(
            "{:<26} {:<9} {:<30} {}",
            truncate(&field(entry, "ts"), 25),
            truncate(&field(entry, "severity"), 8),
            truncate(&field(entry, "host"), 29),
            field(entry, "title"),
        );
    }
    println!();
    println!(
        "Details and recommendations are in the JSON output (--json) and the \
         audit stream (`cage audit --inspector watcher`)."
    );
    std::process::ExitCode::SUCCESS
}

/// `watcher status`.
pub(crate) fn status(ctx: &Ctx, matches: &ArgMatches) -> std::process::ExitCode {
    let (name, config) = match open_cage(ctx, matches) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    let watcher = &config.agents.watcher;
    if !watcher.enable {
        println!(
            "The traffic watcher is not enabled for cage '{name}' — add an \
             `agents.watcher:` block to its cage.yaml (see \
             docs/explain/traffic-watcher.md)."
        );
        return std::process::ExitCode::SUCCESS;
    }

    println!("Traffic watcher for cage '{name}': enabled");
    // `:g`, because the config coerces these to float and a plain
    // `interval_seconds: 300` must print `300s`, not `300.0s`.
    println!("  scan interval:   {}s", general(watcher.interval_seconds));
    println!("  lookback window: {}s", general(watcher.window_seconds));
    println!(
        "  auto-revoke:    {}",
        if watcher.auto_revoke {
            "yes"
        } else {
            "no (findings only)"
        }
    );
    println!(
        "  agent:          {} / {}",
        watcher.llm.provider, watcher.llm.model
    );

    let Some(text) = load_output(ctx, &name, &config, "state.json") else {
        println!("  scan state:     (VM unreachable — start the cage and retry)");
        return std::process::ExitCode::SUCCESS;
    };
    if text.trim().is_empty() {
        println!(
            "  scan state:     (no scan yet — the watcher scans on its first \
             interval)"
        );
        return std::process::ExitCode::SUCCESS;
    }
    let Ok(state) = json::parse(&text) else {
        println!("  scan state:     (unreadable — the egress may predate the watcher)");
        return std::process::ExitCode::SUCCESS;
    };

    println!(
        "  last scan:      {}{}",
        field(&state, "last_scan"),
        if truthy(&state, "last_scan_failed") {
            "  [FAILED]"
        } else {
            ""
        }
    );
    println!("  scans run:      {}", number(&state, "scans"));
    println!(
        "  flows in last window: {}",
        number(&state, "flows_last_window")
    );
    println!("  findings total: {}", number(&state, "findings_total"));

    // The actual prompt size against the configured ceiling. The cap
    // alone tells an operator what they are protected from, not what
    // they are spending.
    if let Some(tokens) = state.get("digest_tokens_last_scan").and_then(as_i64) {
        let cap = state.get("max_digest_tokens").and_then(as_i64).unwrap_or(0);
        let budget = if cap == 0 {
            " (no budget — unbounded)".to_owned()
        } else {
            format!(" of {} budget", thousands(cap))
        };
        println!("  digest size:    ~{} tokens{budget}", thousands(tokens));
    }

    // Capture backlog. A tail that cannot keep up analyses ever-staler
    // traffic while every other counter still looks healthy, so surface
    // it rather than making the operator infer it from file sizes.
    if let Some(lag) = state.get("capture_lag_bytes").and_then(as_i64) {
        let size = state
            .get("capture_size_bytes")
            .and_then(as_i64)
            .unwrap_or(0);
        let behind = if lag > 8 * 1024 * 1024 {
            "  [behind]"
        } else {
            ""
        };
        println!(
            "  capture backlog: {} of {}{behind}",
            megabytes(lag),
            megabytes(size)
        );
    }
    std::process::ExitCode::SUCCESS
}

// ── the formatting Python gets from f-strings ────────────────

/// `str(d.get(key, ""))` — a missing key and a null are both `""`.
fn field(entry: &Json, key: &str) -> String {
    match entry.get(key) {
        None | Some(Json::Null) => String::new(),
        Some(Json::Str(text)) => text.clone(),
        Some(other) => json::dumps(other, DumpOptions::default()),
    }
}

/// `str(x)[:n]` — by characters, as Python slices a `str`.
fn truncate(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// `f"{value:g}"` — the shortest form, so `300.0` prints as `300`.
fn general(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e16 {
        format!("{value:.0}")
    } else {
        format!("{value}")
    }
}

/// `f"{n:,}"` — thousands separators.
fn thousands(value: i64) -> String {
    let negative = value < 0;
    let digits = value.unsigned_abs().to_string();
    let mut out = String::new();
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    if negative { format!("-{out}") } else { out }
}

/// `f"{b / (1024 * 1024):.1f} MB"`.
#[allow(clippy::cast_precision_loss)]
fn megabytes(bytes: i64) -> String {
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

/// `st.get(key, 0)` for the three integer counters.
fn number(state: &Json, key: &str) -> String {
    state
        .get(key)
        .and_then(as_i64)
        .map_or_else(|| "0".to_owned(), |value| value.to_string())
}

fn as_i64(value: &Json) -> Option<i64> {
    match value {
        Json::Int(n) => Some(*n),
        #[allow(clippy::cast_possible_truncation)]
        Json::Float(f) => Some(*f as i64),
        _ => None,
    }
}

/// `if st.get(key)` — Python truthiness.
fn truthy(state: &Json, key: &str) -> bool {
    match state.get(key) {
        None | Some(Json::Null | Json::Bool(false)) => false,
        // `BigInt` is grouped with `true` deliberately: an integer too
        // large for `i64` is never zero, and Python's unbounded `int`
        // makes it truthy like any other non-zero number.
        Some(Json::Bool(true) | Json::BigInt(_)) => true,
        Some(Json::Int(n)) => *n != 0,
        Some(Json::Float(f)) => *f != 0.0,
        Some(Json::Str(text)) => !text.is_empty(),
        Some(Json::Array(items)) => !items.is_empty(),
        Some(Json::Object(pairs)) => !pairs.is_empty(),
    }
}

/// `multiple=True` options arrive as a list, empty when absent.
fn multi(matches: &ArgMatches, id: &str) -> Vec<String> {
    matches
        .get_many::<String>(id)
        .map(|values| values.cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use agentcage_core::har::json;

    use super::{general, megabytes, thousands, truncate, truthy};

    /// `f"{value:g}"`: the config coerces these to float, so a plain
    /// `interval_seconds: 300` must print `300s`, not `300.0s`.
    #[test]
    fn general_drops_a_trailing_zero_like_python() {
        assert_eq!(general(300.0), "300");
        assert_eq!(general(7200.0), "7200");
        assert_eq!(general(0.5), "0.5");
        assert_eq!(general(1.25), "1.25");
    }

    /// `f"{n:,}"`, on the boundaries where a hand-rolled grouper goes
    /// wrong.
    #[test]
    fn thousands_groups_like_python() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(7), "7");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(12345), "12,345");
        assert_eq!(thousands(1_000_000), "1,000,000");
        assert_eq!(thousands(-12345), "-12,345");
    }

    /// `f"{b / (1024 * 1024):.1f} MB"` — MiB, despite the label, which
    /// is the Python's arithmetic and not a typo to fix.
    #[test]
    fn megabytes_matches_pythons_arithmetic() {
        assert_eq!(megabytes(0), "0.0 MB");
        assert_eq!(megabytes(9_437_184), "9.0 MB");
        assert_eq!(megabytes(52_428_800), "50.0 MB");
        assert_eq!(megabytes(1_572_864), "1.5 MB");
    }

    /// `str(x)[:n]` counts characters, not bytes — a non-ASCII host or
    /// title must not be cut mid-codepoint.
    #[test]
    fn truncate_counts_characters() {
        assert_eq!(truncate("abcdef", 3), "abc");
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate("héllo-wörld", 5), "héllo");
    }

    /// `if st.get("last_scan_failed")` is Python truthiness, so `0`,
    /// `""` and `[]` are all false and the `[FAILED]` flag stays off.
    #[test]
    fn truthiness_is_pythons() {
        let state = json::parse(
            r#"{"t": true, "f": false, "zero": 0, "one": 1, "empty": "",
                "text": "x", "list": [], "items": [1], "nil": null,
                "huge": 123456789012345678901234567890}"#,
        )
        .expect("valid JSON");
        assert!(truthy(&state, "t"));
        assert!(!truthy(&state, "f"));
        assert!(!truthy(&state, "zero"));
        assert!(truthy(&state, "one"));
        assert!(!truthy(&state, "empty"));
        assert!(truthy(&state, "text"));
        assert!(!truthy(&state, "list"));
        assert!(truthy(&state, "items"));
        assert!(!truthy(&state, "nil"));
        assert!(!truthy(&state, "missing"));
        // An integer too large for `i64` is non-zero and so truthy.
        assert!(truthy(&state, "huge"));
    }
}
