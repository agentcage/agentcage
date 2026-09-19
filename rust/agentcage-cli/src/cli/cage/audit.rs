//! `cage audit` — query, filter and summarize the proxy's audit trail.
//!
//! `cli.py:2903`. Parsing, filtering, the summary and both output
//! formats are all `agentcage-core` (PR C5); what is here is where the
//! lines come from, which on Linux is the egress container's stderr —
//! either out of the journal or out of `podman logs`, per the driver
//! podman actually picked (see
//! [`agentcage_cli::backend::ContainerBackend::audit_argv`]).
//!
//! Note what is *not* here: a file reader. §2.7's first trap —
//! `audit.jsonl` does not exist host-side for a `container` or `vm`
//! cage. Only apple-container has one.

use std::process::ExitCode;

use agentcage_core::audit::{
    AuditEntry, AuditFilter, compute_summary, extract_audit_json, format_summary,
    format_table_header, format_table_row,
};
use agentcage_exec::Command;
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage};

/// The body.
pub(crate) fn main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match run(ctx, matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn run(ctx: &Ctx, matches: &ArgMatches) -> Result<(), ExitCode> {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();

    // The two hidden back-compat aliases resolve first, as `cli.py` does
    // before anything else in the body.
    let max_entries = matches
        .get_one::<i64>("max_entries_compat")
        .or_else(|| matches.get_one::<i64>("max_entries"))
        .copied()
        .unwrap_or(100);
    let as_json = matches.get_flag("as_json") || matches.get_flag("as_json_lines");
    let follow = matches.get_flag("follow");
    let summary = matches.get_flag("summary");
    let no_color = matches.get_flag("no_color");
    let since = matches.get_one::<String>("since").cloned();

    if !ctx.paths.deployment_exists(&name) {
        eprintln!("error: cage '{name}' does not exist");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    ensure_v022_cage(&ctx.paths, &name)?;

    if summary && follow {
        eprintln!("error: --summary and --follow are incompatible");
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    // Post-parse time filtering, applied on every backend rather than
    // only where the reader lacks a native time index: `podman logs` has
    // no journalctl-compatible `--since`, so the flag is not forwarded
    // there and this is the only thing honouring it.
    let mut since_dt = None;
    if let Some(text) = &since {
        let Some(parsed) = agentcage_core::har::parse_since(text) else {
            eprintln!(
                "error: could not parse --since '{text}' \
                 (use 1h, 30m, 7d, or an ISO date)"
            );
            return Err(ExitCode::from(EXIT_FAILURE));
        };
        since_dt = Some(parsed);
    }

    let filter = AuditFilter {
        decisions: many(matches, "decisions"),
        directions: many(matches, "directions"),
        hosts: many(matches, "hosts"),
        inspectors: many(matches, "inspectors"),
        min_severity: matches.get_one::<String>("severity").cloned(),
        methods: many(matches, "methods"),
        since: since_dt.and_then(|dt| agentcage_core::audit::Timestamp::parse_iso(&dt.isoformat())),
    };

    let backend = ctx.backend();
    let argv = backend.audit_argv(
        &name,
        since.as_deref().map(normalize_since).as_deref(),
        follow,
    );
    let command = to_command(&argv);

    if follow {
        return follow_stream(ctx, &command, &filter, as_json, no_color);
    }

    let entries = read_entries(ctx, &command, &filter)?;
    if summary {
        let parsed: Vec<AuditEntry> = entries.iter().map(|(entry, _)| entry.clone()).collect();
        println!("{}", format_summary(&compute_summary(&parsed)));
        return Ok(());
    }

    // `entries[-lines:]` — keep the last N, or all of them at 0.
    let entries = if max_entries > 0 {
        let keep = usize::try_from(max_entries).unwrap_or(usize::MAX);
        let start = entries.len().saturating_sub(keep);
        &entries[start..]
    } else {
        &entries[..]
    };

    if as_json {
        for (_, raw) in entries {
            println!("{raw}");
        }
    } else {
        println!("{}", format_table_header());
        for (entry, _) in entries {
            println!("{}", format_table_row(entry, !no_color));
        }
    }
    Ok(())
}

/// Run the reader to completion and keep the entries that pass.
fn read_entries(
    ctx: &Ctx,
    command: &Command,
    filter: &AuditFilter,
) -> Result<Vec<(AuditEntry, String)>, ExitCode> {
    let output = ctx.runner.run(command).map_err(|error| {
        eprintln!("error: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;
    Ok(output
        .stdout_text()
        .lines()
        .filter_map(parse_line)
        .filter(|(entry, _)| filter.matches(entry))
        .collect())
}

/// `_audit_follow` — stream until the reader ends or the user quits.
fn follow_stream(
    ctx: &Ctx,
    command: &Command,
    filter: &AuditFilter,
    as_json: bool,
    no_color: bool,
) -> Result<(), ExitCode> {
    let mut stream = ctx.runner.stream(command).map_err(|error| {
        eprintln!("error: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;
    if !as_json {
        println!("{}", format_table_header());
    }
    while let Some(line) = stream.next_line() {
        let Some((entry, raw)) = parse_line(&line) else {
            continue;
        };
        if !filter.matches(&entry) {
            continue;
        }
        if as_json {
            println!("{raw}");
        } else {
            println!("{}", format_table_row(&entry, !no_color));
        }
    }
    let _ = stream.terminate();
    Ok(())
}

/// `cli._normalize_since` — `1h` / `30m` / `7d` to journalctl's phrasing.
///
/// An ISO date is passed through, which is what journalctl wants anyway.
#[must_use]
pub(crate) fn normalize_since(since: &str) -> String {
    let digits: String = since.chars().take_while(char::is_ascii_digit).collect();
    let rest = &since[digits.len()..];
    if digits.is_empty() || rest.len() != 1 {
        return since.to_owned();
    }
    match rest.to_ascii_lowercase().as_str() {
        "h" => format!("{digits} hours ago"),
        "m" => format!("{digits} minutes ago"),
        "d" => format!("{digits} days ago"),
        _ => since.to_owned(),
    }
}

/// One reader line, as `(entry, the line --json would print)`.
///
/// Two parses of the same bytes, and the second one is not redundant.
/// `extract_audit_json` decides what *is* an audit entry, and it parses
/// with `serde_json`, whose object is a `BTreeMap` — so re-emitting from
/// it sorts the keys, where Python's `json.dumps(entry.raw)` keeps the
/// order the proxy wrote them in. The second parse goes through
/// `har::json`, which preserves insertion order, so `--json` reproduces
/// the Python byte for byte.
///
/// The substring it re-parses is the line from its first `{` on, which
/// is where both of `extract_audit_json`'s accepted shapes put the
/// object: bare JSON (container mode) and `[proxy:level] {json}` (vm
/// mode). If that parse fails for any reason the sorted re-emit is the
/// fallback — same data, different key order, never a dropped entry.
fn parse_line(line: &str) -> Option<(AuditEntry, String)> {
    let value = extract_audit_json(line)?;
    let entry = AuditEntry::from_value(&value);
    let ordered = line
        .find('{')
        .and_then(|start| agentcage_core::har::json::parse(line[start..].trim_end()).ok())
        .map_or_else(
            || json_line(&entry.raw),
            |document| {
                agentcage_core::har::json::dumps(
                    &document,
                    agentcage_core::har::json::DumpOptions::default(),
                )
            },
        );
    Some((entry, ordered))
}

/// `json.dumps(entry.raw)` — the whole decoded line, re-emitted.
///
/// Through `har::json::dumps` rather than `serde_json::to_string`,
/// because Python's default separators carry a space (`{"a": 1, "b": 2}`)
/// and `serde_json`'s do not. The float formatting is Python's too.
///
/// The fallback of [`parse_line`], where it also explains the key order.
fn json_line(raw: &serde_json::Value) -> String {
    agentcage_core::har::json::dumps(
        &to_core_json(raw),
        agentcage_core::har::json::DumpOptions::default(),
    )
}

/// `serde_json::Value` -> the `Json` tree `dumps` formats.
fn to_core_json(value: &serde_json::Value) -> agentcage_core::har::json::Json {
    use agentcage_core::har::json::Json;
    match value {
        serde_json::Value::Null => Json::Null,
        serde_json::Value::Bool(b) => Json::Bool(*b),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map_or_else(|| Json::Float(n.as_f64().unwrap_or(0.0)), Json::Int),
        serde_json::Value::String(s) => Json::string(s.clone()),
        serde_json::Value::Array(items) => Json::Array(items.iter().map(to_core_json).collect()),
        serde_json::Value::Object(map) => Json::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), to_core_json(value)))
                .collect(),
        ),
    }
}

/// An argv list, as a [`Command`].
fn to_command(argv: &[String]) -> Command {
    let (program, rest) = argv.split_first().expect("audit_argv is never empty");
    Command::new(program.clone())
        .args(rest.iter().cloned())
        .captured()
}

fn many(matches: &ArgMatches, id: &str) -> Vec<String> {
    matches
        .get_many::<String>(id)
        .map(|values| values.cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::normalize_since;

    #[test]
    fn shorthand_durations_become_journalctl_phrases() {
        assert_eq!(normalize_since("1h"), "1 hours ago");
        assert_eq!(normalize_since("30m"), "30 minutes ago");
        assert_eq!(normalize_since("7d"), "7 days ago");
        assert_eq!(normalize_since("7D"), "7 days ago");
        // Anything else is assumed to be an ISO date and passed through.
        assert_eq!(normalize_since("2026-01-01"), "2026-01-01");
        assert_eq!(normalize_since("1w"), "1w");
        assert_eq!(normalize_since(""), "");
    }
}
