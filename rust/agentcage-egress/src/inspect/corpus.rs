//! The `inspectors.json` oracle, replayed against the Rust inspectors.
//!
//! Each case is a script of steps run against one inspector instance,
//! each step carrying the value the replaced implementation returned
//! (`tests/fixtures/egress/gen/inspectors.py` documents the step
//! vocabulary). `AGENTCAGE_BLESS=1` rewrites every `expect` with what
//! the Rust returns, for a deliberate behaviour change.

use std::path::PathBuf;

use agentcage_core::audit::Timestamp;

use super::Verdict;
use super::domain::{DomainInspector, parse_overlay};
use crate::config::{Mapping, Value};
use crate::json::{self, DumpOptions, Json};

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/egress/inspectors.json")
}

/// A corpus JSON value as the YAML tree a config section would load as.
pub(super) fn json_to_yaml(value: &Json) -> Value {
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
                .collect(),
        ),
    }
}

/// A YAML tree as `json.dumps` would see the Python object it loads as.
pub(super) fn yaml_to_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Number(n) => n
            .as_i64()
            .map_or_else(|| Json::Float(n.as_f64().unwrap_or(f64::NAN)), Json::Int),
        Value::String(s) => Json::string(s),
        Value::Sequence(items) => Json::Array(items.iter().map(yaml_to_json).collect()),
        Value::Mapping(m) => mapping_to_json(m),
        Value::Tagged(t) => Json::string(t.tag.to_string()),
    }
}

fn mapping_to_json(m: &Mapping) -> Json {
    Json::Object(
        m.iter()
            .map(|(k, v)| (agentcage_core::python::str_of(k), yaml_to_json(v)))
            .collect(),
    )
}

pub(super) fn verdict_json(verdict: Option<&Verdict>) -> Json {
    verdict.map_or(Json::Null, |v| {
        json::object([
            ("inspector", Json::string(&v.inspector)),
            ("action", Json::string(v.action.as_str())),
            ("reason", Json::string(&v.reason)),
            ("severity", Json::string(v.severity.as_str())),
        ])
    })
}

fn str_arg<'a>(step: &'a Json, key: &str) -> &'a str {
    step.get(key).and_then(Json::as_str).unwrap_or_default()
}

fn strings(items: Vec<String>) -> Json {
    Json::Array(items.into_iter().map(Json::Str).collect())
}

struct Clock {
    iso: String,
    ts: Timestamp,
}

impl Clock {
    fn at(iso: &str) -> Self {
        Self {
            iso: iso.to_owned(),
            ts: Timestamp::parse_iso(iso).expect("corpus now parses"),
        }
    }
}

fn domain_step(dom: &DomainInspector, clock: &mut Clock, step: &Json) -> Json {
    let host = str_arg(step, "host");
    match str_arg(step, "op") {
        "set_now" => {
            *clock = Clock::at(str_arg(step, "now"));
            Json::Null
        }
        "configure" => {
            dom.configure(&json_to_yaml(step.get("config").unwrap_or(&Json::Null)))
                .expect("corpus configs load");
            Json::Null
        }
        "inspect" => verdict_json(dom.inspect_host_at(host, clock.ts).as_ref()),
        "matches" => Json::Bool(dom.matches(host)),
        "matched_expired" => dom
            .matched_expired_at(host, clock.ts)
            .map_or(Json::Null, Json::Str),
        "is_granted" => Json::Bool(dom.is_granted(host)),
        "is_grant_only" => Json::Bool(dom.is_grant_only(host)),
        "matches_baseline" => Json::Bool(dom.matches_baseline(host)),
        "baseline_active_covers" => {
            Json::Bool(dom.baseline_active_covers_at(str_arg(step, "domain"), clock.ts))
        }
        "grant" => {
            let source = step
                .get("source")
                .and_then(Json::as_str)
                .unwrap_or(super::domain::DEFAULT_GRANT_SOURCE);
            dom.grant_at(
                str_arg(step, "domain"),
                str_arg(step, "expires_at"),
                str_arg(step, "reason"),
                source,
                &clock.iso,
            );
            Json::Null
        }
        "revoke" => Json::Bool(dom.revoke(str_arg(step, "domain"))),
        "drop_expired" => strings(dom.drop_expired_at(str_arg(step, "now_iso"))),
        "granted_entries" => Json::Array(
            dom.granted_entries()
                .iter()
                .map(|(_, e)| mapping_to_json(e))
                .collect(),
        ),
        "baseline_list" => strings(dom.baseline_list()),
        "mode" => dom.mode().map_or(Json::Null, Json::Str),
        "reconcile" => {
            dom.reconcile(&parse_overlay(str_arg(step, "overlay")));
            Json::Null
        }
        "parse_overlay" => Json::Array(
            parse_overlay(str_arg(step, "overlay"))
                .iter()
                .map(mapping_to_json)
                .collect(),
        ),
        other => panic!("unknown domain op {other:?}"),
    }
}

fn run_case(case: &Json) -> Vec<Json> {
    let Some(Json::Array(steps)) = case.get("steps") else {
        panic!("case without steps");
    };
    match str_arg(case, "inspector") {
        "domain" => {
            let dom = DomainInspector::new();
            let mut clock = Clock::at(str_arg(case, "now"));
            steps
                .iter()
                .map(|s| domain_step(&dom, &mut clock, s))
                .collect()
        }
        other => panic!("unknown inspector {other:?}"),
    }
}

#[test]
fn the_corpus_replays() {
    let path = corpus_path();
    let text = std::fs::read_to_string(&path).expect("corpus readable");
    let mut corpus = json::parse(&text).expect("corpus parses");
    let bless = std::env::var_os("AGENTCAGE_BLESS").is_some();
    let mut failures = Vec::new();
    let Some(Json::Array(cases)) = (match &mut corpus {
        Json::Object(pairs) => pairs.iter_mut().find(|(k, _)| k == "cases").map(|(_, v)| v),
        _ => None,
    }) else {
        panic!("corpus has no cases");
    };
    for case in cases.iter_mut() {
        let got = run_case(case);
        let name = str_arg(case, "name").to_owned();
        let Some(Json::Array(steps)) = (match case {
            Json::Object(pairs) => pairs.iter_mut().find(|(k, _)| k == "steps").map(|(_, v)| v),
            _ => None,
        }) else {
            unreachable!("run_case checked the steps");
        };
        for (i, (step, got)) in steps.iter_mut().zip(got).enumerate() {
            if bless {
                step.set("expect", got);
            } else if step.get("expect") != Some(&got) {
                failures.push(format!(
                    "{name} step {i} ({}): expected {}, got {}",
                    str_arg(step, "op"),
                    json::to_string(step.get("expect").unwrap_or(&Json::Null)),
                    json::to_string(&got),
                ));
            }
        }
    }
    if bless {
        std::fs::write(&path, json::dumps(&corpus, DumpOptions::indented()) + "\n")
            .expect("corpus writable");
        return;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_wrong_expectation_fails() {
    // Mutation check: the comparison above must bite on a flipped verdict.
    let text = std::fs::read_to_string(corpus_path()).expect("corpus readable");
    let corpus = json::parse(&text).expect("corpus parses");
    let Some(Json::Array(cases)) = corpus.get("cases") else {
        panic!("corpus has no cases");
    };
    let case = cases
        .iter()
        .find(|c| str_arg(c, "name") == "legacy blocklist")
        .expect("the case exists");
    let got = run_case(case);
    let Some(Json::Array(steps)) = case.get("steps") else {
        panic!("case without steps");
    };
    let i = steps
        .iter()
        .position(|s| str_arg(s, "host") == "evil.com")
        .expect("the step exists");
    assert_ne!(got[i], Json::Null, "the mutated expectation would match");
    assert_eq!(steps[i].get("expect"), Some(&got[i]));
}
