//! The HAR port against the golden corpus.
//!
//! `tests/fixtures/golden/shared/har/` was produced by running the
//! Python `har.py` over the committed `_inputs/capture.jsonl` (PR A3;
//! see that directory's README). Those five files are the specification
//! this port is held to, and the comparison is byte-for-byte: the README
//! reserves parsed-value comparison for YAML, and every JSON artifact is
//! compared as text.
//!
//! The corpus harness serializes with
//! `json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)` plus
//! a trailing newline, which is *not* how `cage har` writes a HAR — that
//! is `json.dumps(har, indent=2)`, insertion-ordered and ASCII-escaped.
//! Both forms come out of the same value here, so matching the corpus
//! exercises the builder while [`dumps`] keeps the shipped format.

use std::fs;
use std::path::{Path, PathBuf};

use agentcage_core::har::datetime::DateTime;
use agentcage_core::har::json::{self, DumpOptions, Json};
use agentcage_core::har::{CaptureFilter, capture_to_har_with, parse_since};

/// The version the harness pins `importlib.metadata.version` to, so a
/// release does not churn the corpus.
const GOLDEN_VERSION: &str = "0.0.0-golden";

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/golden")
}

/// `_json_text` from `scripts/gen-golden-corpus.py`.
fn corpus_text(value: &Json) -> String {
    let options = DumpOptions {
        indent: Some(2),
        sort_keys: true,
        ensure_ascii: false,
    };
    json::dumps(value, options) + "\n"
}

fn capture_entries() -> Vec<Json> {
    let path = corpus().join("_inputs/capture.jsonl");
    let text = fs::read_to_string(&path).expect("the corpus ships capture.jsonl");
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| json::parse(line).expect("every capture line is JSON"))
        .collect()
}

#[track_caller]
fn assert_matches_corpus(relative: &str, produced: &str) {
    let path = corpus().join("shared/har").join(relative);
    let expected = fs::read_to_string(&path).expect("the corpus ships this artifact");
    assert_eq!(
        produced, expected,
        "{relative} differs from the golden corpus"
    );
}

/// The eight filters the harness records, in its own order.
fn golden_filters() -> Vec<(&'static str, CaptureFilter)> {
    let strings = |values: &[&str]| values.iter().map(|s| (*s).to_string()).collect();
    vec![
        ("all", CaptureFilter::default()),
        (
            "decision-blocked",
            CaptureFilter {
                decisions: strings(&["blocked"]),
                ..CaptureFilter::default()
            },
        ),
        (
            "direction-outbound",
            CaptureFilter {
                directions: strings(&["outbound"]),
                ..CaptureFilter::default()
            },
        ),
        (
            "host-example-com",
            CaptureFilter {
                hosts: strings(&["example.com"]),
                ..CaptureFilter::default()
            },
        ),
        (
            "method-post-lowercase",
            CaptureFilter {
                methods: strings(&["post"]),
                ..CaptureFilter::default()
            },
        ),
        (
            "min-action-flag",
            CaptureFilter {
                min_action: Some("flag".to_string()),
                ..CaptureFilter::default()
            },
        ),
        (
            "min-action-block",
            CaptureFilter {
                min_action: Some("block".to_string()),
                ..CaptureFilter::default()
            },
        ),
        (
            "since-2024-03",
            CaptureFilter {
                since: DateTime::from_parts((2024, 3, 1), (0, 0, 0, 0), Some(0)),
                ..CaptureFilter::default()
            },
        ),
    ]
}

/// Both views of the whole capture.
#[test]
fn views_match_the_corpus() {
    let entries = capture_entries();
    for view in ["inbound", "outbound"] {
        let har = capture_to_har_with(&entries, view, GOLDEN_VERSION, DateTime::now_utc());
        assert_matches_corpus(&format!("{view}.json"), &corpus_text(&har));
    }
}

/// Which entries each of the eight filters keeps.
#[test]
fn filters_match_the_corpus() {
    let entries = capture_entries();
    let mut report: Vec<(String, Json)> = golden_filters()
        .into_iter()
        .map(|(label, filter)| {
            let kept: Vec<Json> = entries
                .iter()
                .filter(|entry| filter.matches(entry))
                .map(|entry| entry.get("flow_id").cloned().expect("fixture has flow_id"))
                .collect();
            (label.to_string(), Json::Array(kept))
        })
        .collect();
    report.sort_by(|a, b| a.0.cmp(&b.0));
    assert_matches_corpus("filters.json", &corpus_text(&Json::Object(report)));
}

/// A filter and a build together, as `cage har --decision blocked` does
/// it: the blocked entry has an empty `response`, so this is also the
/// only corpus coverage of the stub response branch.
#[test]
fn filtered_har_matches_the_corpus() {
    let entries = capture_entries();
    let filter = CaptureFilter {
        decisions: vec!["blocked".to_string()],
        ..CaptureFilter::default()
    };
    let kept: Vec<Json> = entries
        .iter()
        .filter(|entry| filter.matches(entry))
        .cloned()
        .collect();
    let har = capture_to_har_with(&kept, "outbound", GOLDEN_VERSION, DateTime::now_utc());
    assert_matches_corpus("filtered-blocked.json", &corpus_text(&har));
}

/// `parse_since` over the harness's ten inputs.
///
/// A relative offset is recorded as whole seconds away from "now"
/// rather than as an instant, because that is the only part of it that
/// is reproducible.
#[test]
fn parse_since_matches_the_corpus() {
    let specs = [
        "1h",
        "30m",
        "7d",
        "2024-01-01",
        "2024-01-01T00:00:00+00:00",
        "2024-01-01T00:00:00",
        "not-a-since",
        "",
        "5x",
        "0h",
    ];
    let mut report: Vec<(String, Json)> = specs
        .iter()
        .map(|spec| {
            let value = match parse_since(spec) {
                None => Json::Null,
                Some(parsed) if is_relative(spec) => {
                    let seconds = DateTime::now_utc()
                        .seconds_since(&parsed)
                        .expect("both sides are UTC-aware");
                    Json::Object(vec![("relative_seconds".to_string(), Json::Int(seconds))])
                }
                Some(parsed) => Json::Object(vec![(
                    "absolute".to_string(),
                    Json::Str(parsed.isoformat()),
                )]),
            };
            ((*spec).to_string(), value)
        })
        .collect();
    report.sort_by(|a, b| a.0.cmp(&b.0));
    assert_matches_corpus("parse-since.json", &corpus_text(&Json::Object(report)));
}

/// `re.match(r"^\d+[hHmMdD]$", spec)`, as the harness applies it to pick
/// which shape of report entry to write.
fn is_relative(spec: &str) -> bool {
    let mut chars = spec.chars();
    let Some(unit) = chars.next_back() else {
        return false;
    };
    matches!(unit, 'h' | 'H' | 'm' | 'M' | 'd' | 'D')
        && !chars.as_str().is_empty()
        && chars.as_str().bytes().all(|b| b.is_ascii_digit())
}
