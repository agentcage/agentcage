//! `audit.py` port, checked against the golden corpus.
//!
//! PR A3 recorded what the live Python produced from a fixed
//! `audit.jsonl`: the raw-line extraction, the parsed entries, ten
//! filters, and the summary as JSON, as text and as a table in both plain
//! and coloured form. `scripts/gen-golden-corpus.py` (`_write_shared`) is
//! the recipe; this file is the same recipe in Rust, and every assertion
//! is a byte comparison against the committed artifact.
//!
//! Nothing here hardcodes an expected string. The fixture is the oracle:
//! if a `format!` in `audit.rs` loses a space, the file on disk says so.
//! Re-blessing the corpus to make this pass is the wrong move — see
//! `tests/fixtures/golden/README.md`.

use std::path::{Path, PathBuf};

use agentcage_core::audit::{
    AuditEntry, AuditFilter, Timestamp, compute_summary, extract_audit_json, format_summary,
    format_table_header, format_table_row,
};
use serde::Serialize;
use serde_json::{Value, json};

/// `tests/fixtures/golden/` at the repo root, from this crate's manifest.
fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/golden")
        .canonicalize()
        .expect("golden corpus is committed next to the Python tests")
}

fn read_artifact(rel: &str) -> String {
    let path = corpus().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The generator's `_json_text`: `json.dumps(indent=2, sort_keys=True,
/// ensure_ascii=False)` plus a trailing newline.
///
/// `sort_keys` needs no counterpart here — `serde_json::Value` holds its
/// object as a `BTreeMap`, so going through `to_value` sorts every level,
/// including the `raw` payloads and the derived structs.
fn json_text<T: Serialize>(value: &T) -> String {
    let value = serde_json::to_value(value).expect("serializable");
    serde_json::to_string_pretty(&value).expect("printable") + "\n"
}

/// The corpus fixture, split the way Python's `str.splitlines()` splits it.
fn input_lines() -> Vec<String> {
    read_artifact("_inputs/audit.jsonl")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn parsed_entries() -> Vec<AuditEntry> {
    input_lines()
        .iter()
        .filter_map(|line| extract_audit_json(line))
        .map(|d| AuditEntry::from_value(&d))
        .collect()
}

#[test]
fn extract_matches_corpus() {
    let report: Vec<Value> = input_lines()
        .iter()
        .map(|line| json!({"line": line, "parsed": extract_audit_json(line)}))
        .collect();
    assert_eq!(
        json_text(&report),
        read_artifact("shared/audit/extract.json")
    );
}

#[test]
fn entries_match_corpus() {
    assert_eq!(
        json_text(&parsed_entries()),
        read_artifact("shared/audit/entries.json")
    );
}

/// The ten filters the corpus records, by the labels it files them under.
///
/// Kept in the generator's order so the two lists can be diffed by eye;
/// the artifact itself is keyed and sorted.
fn corpus_filters() -> Vec<(&'static str, AuditFilter)> {
    fn of(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }
    vec![
        ("all", AuditFilter::default()),
        (
            "decision-blocked",
            AuditFilter {
                decisions: of(&["blocked"]),
                ..Default::default()
            },
        ),
        (
            "direction-inbound",
            AuditFilter {
                directions: of(&["inbound"]),
                ..Default::default()
            },
        ),
        (
            "host-evil",
            AuditFilter {
                hosts: of(&["evil"]),
                ..Default::default()
            },
        ),
        (
            "inspector-domain",
            AuditFilter {
                inspectors: of(&["domain"]),
                ..Default::default()
            },
        ),
        (
            "method-post-lowercase",
            AuditFilter {
                methods: of(&["post"]),
                ..Default::default()
            },
        ),
        (
            "severity-warning",
            AuditFilter {
                min_severity: Some("warning".to_owned()),
                ..Default::default()
            },
        ),
        (
            "severity-critical",
            AuditFilter {
                min_severity: Some("critical".to_owned()),
                ..Default::default()
            },
        ),
        (
            "severity-high-watcher",
            AuditFilter {
                min_severity: Some("high".to_owned()),
                ..Default::default()
            },
        ),
        (
            "since-2024-03",
            AuditFilter {
                // `datetime(2024, 3, 1, tzinfo=timezone.utc)` in the
                // generator.
                since: Timestamp::parse_iso("2024-03-01T00:00:00+00:00"),
                ..Default::default()
            },
        ),
    ]
}

#[test]
fn filters_match_corpus() {
    let entries = parsed_entries();
    let report: serde_json::Map<String, Value> = corpus_filters()
        .into_iter()
        .map(|(label, filt)| {
            let kept: Vec<&str> = entries
                .iter()
                .filter(|e| filt.matches(e))
                .map(|e| {
                    if e.url.is_empty() {
                        e.host.as_str()
                    } else {
                        e.url.as_str()
                    }
                })
                .collect();
            (label.to_owned(), json!(kept))
        })
        .collect();
    assert_eq!(
        json_text(&report),
        read_artifact("shared/audit/filters.json")
    );
}

#[test]
fn summary_json_matches_corpus() {
    let summary = compute_summary(&parsed_entries());
    assert_eq!(
        json_text(&summary),
        read_artifact("shared/audit/summary.json")
    );
}

#[test]
fn summary_text_matches_corpus() {
    let summary = compute_summary(&parsed_entries());
    assert_eq!(
        format_summary(&summary) + "\n",
        read_artifact("shared/audit/summary.txt")
    );
}

/// Both table artifacts, byte for byte including the SGR escapes.
///
/// The coloured one is the interesting half: it exercises the colour codes
/// and the narrower DIRECTION column the Python's colour branch produces.
#[test]
fn tables_match_corpus() {
    let entries = parsed_entries();
    for (color, artifact) in [(false, "table.txt"), (true, "table-color.txt")] {
        let mut rendered = vec![format_table_header()];
        rendered.extend(entries.iter().map(|e| format_table_row(e, color)));
        assert_eq!(
            rendered.join("\n") + "\n",
            read_artifact(&format!("shared/audit/{artifact}")),
            "{artifact} drifted"
        );
    }
}

/// Every audit artifact the corpus carries is claimed by a test above.
///
/// Without this, a future corpus artifact would be silently unchecked: the
/// tests above each name their own file, and nothing would notice an
/// eleventh appearing beside them.
#[test]
fn every_audit_artifact_is_covered() {
    let mut found: Vec<String> = std::fs::read_dir(corpus().join("shared/audit"))
        .expect("shared/audit exists")
        .map(|e| {
            e.expect("readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            "entries.json",
            "extract.json",
            "filters.json",
            "summary.json",
            "summary.txt",
            "table-color.txt",
            "table.txt",
        ]
    );
}
