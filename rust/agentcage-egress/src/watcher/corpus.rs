//! The `watcher.json` oracle, replayed against the Rust watcher.
//!
//! Each case names a pure function (or a scripted capture-tail scenario)
//! and carries the value the replaced implementation returned; see
//! `tests/fixtures/egress/gen/watcher.py`. `AGENTCAGE_BLESS=1` rewrites
//! every `expected` with what the Rust returns, for a deliberate change.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use agentcage_core::har::datetime::DateTime;

use super::config::WatcherConfig;
use super::digest::{self, DigestInput};
use super::tail::{CaptureTail, TailLimits};
use super::{prompt, sample};
use crate::config::{Config, Mapping, Value};
use crate::json::{self, DumpOptions, Json};

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/egress/watcher.json")
}

fn json_to_yaml(value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Int(i) => Value::from(*i),
        Json::BigInt(s) | Json::Str(s) => Value::String(s.clone()),
        Json::Float(f) => Value::from(*f),
        Json::Array(items) => Value::Sequence(items.iter().map(json_to_yaml).collect()),
        Json::Object(pairs) => Value::Mapping(
            pairs
                .iter()
                .map(|(k, v)| (Value::String(k.clone()), json_to_yaml(v)))
                .collect::<Mapping>(),
        ),
    }
}

fn config_of(proxy_cfg: &Json) -> Config {
    Config::from_value(json_to_yaml(proxy_cfg)).expect("corpus config is a mapping")
}

fn int(v: Option<&Json>) -> i64 {
    match v {
        Some(Json::Int(i)) => *i,
        other => panic!("expected an int, got {other:?}"),
    }
}

fn strings(v: Option<&Json>) -> Vec<String> {
    match v {
        Some(Json::Array(items)) => items
            .iter()
            .map(|i| i.as_str().expect("string").to_owned())
            .collect(),
        _ => Vec::new(),
    }
}

fn array(v: Option<&Json>) -> Vec<Json> {
    match v {
        Some(Json::Array(items)) => items.clone(),
        _ => Vec::new(),
    }
}

fn usize_of(n: usize) -> Json {
    Json::Int(i64::try_from(n).expect("fits"))
}

fn config_case(input: &Json) -> Json {
    let mut warnings = Vec::new();
    let c = WatcherConfig::parse(
        &config_of(input.get("proxy_cfg").expect("proxy_cfg")),
        &mut |w| warnings.push(Json::string(w)),
    );
    json::object([
        ("interval_seconds", Json::Float(c.interval_seconds)),
        ("window_seconds", Json::Float(c.window_seconds)),
        ("max_flows", usize_of(c.max_flows)),
        ("auto_revoke", Json::Bool(c.auto_revoke)),
        ("dedup_samples", Json::Bool(c.dedup_samples)),
        ("max_digest_tokens", usize_of(c.max_digest_tokens)),
        ("context", Json::Str(c.context)),
        ("provider", Json::Str(c.provider)),
        ("model", Json::Str(c.model)),
        ("api_key", Json::Str(c.api_key)),
        ("timeout_seconds", Json::Float(c.timeout_seconds)),
        ("max_tokens", Json::Int(c.max_tokens)),
        ("base_url", Json::Str(c.base_url)),
        (
            "line_cap",
            Json::Int(i64::try_from(c.line_cap).expect("fits")),
        ),
        ("warnings", Json::Array(warnings)),
    ])
}

fn bytes_of(v: &Json) -> Vec<u8> {
    match v {
        Json::Str(s) => s.as_bytes().to_vec(),
        Json::Object(_) => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(v.get("b64").and_then(Json::as_str).expect("b64"))
                .expect("valid base64")
        }
        other => panic!("bad data {other:?}"),
    }
}

/// A fresh scratch directory under the system temp dir.
pub(super) fn scratch_dir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "agentcage-watcher-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn tail_case(input: &Json) -> Json {
    let dir = scratch_dir("tail");
    let cap = dir.join("capture.jsonl");
    let limits = TailLimits {
        chunk: u64::try_from(int(input.get("chunk"))).expect("u64"),
        max_catchup: u64::try_from(int(input.get("max_catchup"))).expect("u64"),
        line_cap: u64::try_from(int(input.get("line_cap"))).expect("u64"),
    };
    let max_flows = usize::try_from(int(input.get("max_flows"))).expect("usize");
    let window = match input.get("window_seconds") {
        Some(Json::Int(i)) => f64::from(i32::try_from(*i).expect("small")),
        Some(Json::Float(f)) => *f,
        other => panic!("window {other:?}"),
    };
    let now = DateTime::from_isoformat(input.get("now").and_then(Json::as_str).expect("now"))
        .expect("iso");
    let mut tail = CaptureTail::new(Some(cap.clone()), limits);
    let mut out = Vec::new();
    for (n, step) in array(input.get("steps")).iter().enumerate() {
        let data = || bytes_of(step.get("data").expect("data"));
        match step.get("op").and_then(Json::as_str).expect("op") {
            "write" => std::fs::write(&cap, data()).expect("write"),
            "append" => {
                use std::io::Write as _;
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&cap)
                    .expect("open");
                f.write_all(&data()).expect("append");
            }
            "replace" => {
                let other = dir.join(format!("next-{n}.jsonl"));
                std::fs::write(&other, data()).expect("write");
                std::fs::rename(&other, &cap).expect("rename");
            }
            "remove" => std::fs::remove_file(&cap).expect("remove"),
            "read" => {
                let mut warnings = Vec::new();
                let read = tail.read(now, window, max_flows, None, &mut |w| {
                    warnings.push(Json::string(w));
                });
                if step.get("commit") == Some(&Json::Bool(true)) {
                    tail.commit(&read);
                }
                out.push(json::object([
                    ("samples", Json::Array(read.samples)),
                    (
                        "offset",
                        Json::Int(i64::try_from(read.offset).expect("fits")),
                    ),
                    (
                        "skipped",
                        Json::Int(i64::try_from(read.skipped).expect("fits")),
                    ),
                    ("warnings", Json::Array(warnings)),
                ]));
            }
            other => panic!("unknown op {other}"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    Json::Array(out)
}

fn compute(kind: &str, input: &Json) -> Json {
    match kind {
        "config" => config_case(input),
        "redact_headers" => Json::Array(sample::redact_headers(input.get("headers"))),
        "excerpt_body" => Json::Str(sample::excerpt_body(
            input.get("body"),
            input.get("encoding"),
            None,
        )),
        "sample_capture" => sample::sample_capture(
            input.get("entry").expect("entry"),
            input.get("host_hint").and_then(Json::as_str).unwrap_or(""),
            None,
        ),
        "template_path" => Json::Str(digest::template_path(input.get("path"))),
        "dedup_samples" => Json::Array(digest::dedup_samples(
            &array(input.get("samples")),
            usize::try_from(int(input.get("max_bodies"))).expect("usize"),
            None,
        )),
        "est_tokens" => usize_of(digest::est_tokens(input.get("obj").expect("obj"))),
        "fit_to_budget" => Json::Array(digest::fit_to_budget(
            array(input.get("samples")),
            int(input.get("budget")),
            int(input.get("overhead")),
            None,
        )),
        "build_digest" => {
            let audit = array(input.get("audit_entries"));
            let samples = array(input.get("capture_samples"));
            let events = array(input.get("policy_events"));
            let granted = strings(input.get("granted"));
            let baseline = strings(input.get("baseline"));
            digest::build_digest(
                &DigestInput {
                    audit_entries: &audit,
                    capture_samples: &samples,
                    policy_events: &events,
                    granted: &granted,
                    baseline: &baseline,
                    max_flows: int(input.get("max_flows")),
                    dedup: input.get("dedup") != Some(&Json::Bool(false)),
                    max_digest_tokens: input.get("max_digest_tokens").map_or(0, |v| int(Some(v))),
                    ring_saturated: input.get("ring_saturated") == Some(&Json::Bool(true)),
                },
                None,
            )
        }
        "norm_finding" => prompt::normalise_finding(input.get("finding").expect("finding")),
        "is_never_revoke" => Json::Bool(prompt::is_never_revoke(
            input.get("domain").and_then(Json::as_str).expect("domain"),
        )),
        "system_prompt" => {
            let cfg = json::object([(
                "agents",
                json::object([(
                    "watcher",
                    json::object([("context", input.get("context").cloned().expect("context"))]),
                )]),
            )]);
            let c = WatcherConfig::parse(&config_of(&cfg), &mut |_| {});
            Json::Str(prompt::system_prompt(&c.context))
        }
        "review_tool" => {
            let t = prompt::review_tool();
            json::object([
                ("name", Json::Str(t.name)),
                ("description", Json::Str(t.description)),
                ("parameters", t.parameters),
            ])
        }
        "tail" => tail_case(input),
        other => panic!("unknown corpus kind {other}"),
    }
}

fn load(path: &Path) -> Json {
    json::parse(&std::fs::read_to_string(path).expect("corpus readable")).expect("corpus parses")
}

#[test]
fn watcher_corpus() {
    let path = corpus_path();
    let mut corpus = load(&path);
    let bless = std::env::var_os("AGENTCAGE_BLESS").is_some_and(|v| v == "1");
    let mut failures = Vec::new();
    let Some(Json::Array(cases)) = corpus.get("cases").cloned() else {
        panic!("corpus has no cases");
    };
    let mut updated = Vec::with_capacity(cases.len());
    for mut case in cases {
        let kind = case
            .get("kind")
            .and_then(Json::as_str)
            .expect("kind")
            .to_owned();
        let name = case
            .get("name")
            .and_then(Json::as_str)
            .expect("name")
            .to_owned();
        let got = compute(&kind, case.get("input").expect("input"));
        if Some(&got) != case.get("expected") {
            failures.push(format!(
                "{kind}:{name}\n  want {}\n  got  {}",
                json::to_string(case.get("expected").unwrap_or(&Json::Null)),
                json::to_string(&got)
            ));
        }
        case.set("expected", got);
        updated.push(case);
    }
    if bless {
        corpus.set("cases", Json::Array(updated));
        let text = json::dumps(
            &corpus,
            DumpOptions {
                indent: Some(1),
                ..DumpOptions::default()
            },
        );
        std::fs::write(&path, text + "\n").expect("bless write");
        return;
    }
    assert!(
        failures.is_empty(),
        "{} of the watcher corpus cases differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn a_wrong_expectation_is_caught() {
    // Mutation sanity: the comparison in `watcher_corpus` bites.
    let corpus = load(&corpus_path());
    let Some(Json::Array(cases)) = corpus.get("cases") else {
        panic!("no cases");
    };
    let case = cases
        .iter()
        .find(|c| c.get("kind").and_then(Json::as_str) == Some("build_digest"))
        .expect("a digest case");
    let mut wrong = case.get("expected").cloned().expect("expected");
    if let Some(Json::Object(totals)) = match &mut wrong {
        Json::Object(pairs) => pairs
            .iter_mut()
            .find(|(k, _)| k == "totals")
            .map(|(_, v)| v),
        _ => None,
    } {
        totals[0].1 = Json::Int(-1);
    }
    let got = compute("build_digest", case.get("input").expect("input"));
    assert_ne!(got, wrong);
}

#[test]
fn defaults_match_the_agents_defaults_contract() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/contracts/agents_defaults.json");
    let contract = load(&path);
    let cfg = config_of(contract.get("config").expect("config"));
    let c = WatcherConfig::parse(&cfg, &mut |w| panic!("unexpected warning {w}"));
    let mut seen = 0;
    for case in array(contract.get("cases")) {
        let id = case.get("id").and_then(Json::as_str).expect("id");
        let Some(key) = id.strip_prefix("watcher.") else {
            continue;
        };
        let want = case.get("value").expect("value");
        let got = match key {
            "interval_seconds" => Json::Float(c.interval_seconds),
            "window_seconds" => Json::Float(c.window_seconds),
            "max_flows" => usize_of(c.max_flows),
            "auto_revoke" => Json::Bool(c.auto_revoke),
            "dedup_samples" => Json::Bool(c.dedup_samples),
            "max_digest_tokens" => usize_of(c.max_digest_tokens),
            "timeout_seconds" => Json::Float(c.timeout_seconds),
            "max_tokens" => Json::Int(c.max_tokens),
            other => panic!("unmapped watcher default {other}"),
        };
        assert_eq!(&got, want, "watcher default {key}");
        seen += 1;
    }
    assert!(seen >= 6, "the contract lost its watcher cases");
}
