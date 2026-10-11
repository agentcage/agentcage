//! The `inspectors.json` oracle, replayed against the Rust inspectors.
//!
//! Each case is a script of steps run against one inspector instance,
//! each step carrying the value the replaced implementation returned
//! (`tests/fixtures/egress/gen/inspectors.py` documents the step
//! vocabulary). `AGENTCAGE_BLESS=1` rewrites every `expect` with what
//! the Rust returns, for a deliberate behaviour change.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentcage_core::audit::Timestamp;

use super::body_size::BodySizeInspector;
use super::chain::{PluginLoader, SlotKind, build_chain};
use super::content_type::ContentTypeInspector;
use super::domain::{DomainInspector, parse_overlay};
use super::entropy::EntropyInspector;
use super::secrets::SecretsInspector;
use super::{Context, Inspector, Verdict};
use crate::config::{Config, Mapping, Value};
use crate::json::{self, DumpOptions, Json};

fn corpus_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/egress")
        .join(name)
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
            ("metadata", Json::Object(v.metadata.clone())),
        ])
    })
}

/// A corpus body (standard base64, padded).
fn b64_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("corpus bodies are valid base64")
}

/// The bytes of a hidden value: base64 of the bytes reversed.
fn b64r_decode(text: &str) -> Vec<u8> {
    let mut bytes = b64_decode(text);
    bytes.reverse();
    bytes
}

/// A corpus string: plain, or `{"b64r": …}` (base64 of its UTF-8 bytes
/// reversed) for a credential-shaped sample, which as plain text or
/// plain base64 trips repository secret scanners.
fn text(value: Option<&Json>) -> Option<String> {
    match value? {
        Json::Str(s) => Some(s.clone()),
        hidden @ Json::Object(_) => {
            let b64r = hidden.get("b64r").and_then(Json::as_str)?;
            Some(String::from_utf8(b64r_decode(b64r)).expect("hidden text is UTF-8"))
        }
        _ => None,
    }
}

/// A corpus request context (every derived field written out).
fn context(spec: &Json) -> Context {
    let body_bytes = match spec.get("body_b64r") {
        Some(hidden) => hidden.as_str().map(b64r_decode),
        None => spec.get("body_b64").and_then(Json::as_str).map(b64_decode),
    };
    let Some(Json::Array(headers)) = spec.get("headers") else {
        panic!("ctx without headers");
    };
    Context {
        url: text(spec.get("url")).unwrap_or_default(),
        host: str_arg(spec, "host").to_owned(),
        method: str_arg(spec, "method").to_owned(),
        headers: headers
            .iter()
            .map(|h| match h {
                Json::Array(kv) => (
                    kv[0].as_str().unwrap_or_default().to_owned(),
                    text(kv.get(1)).unwrap_or_default(),
                ),
                _ => panic!("bad header"),
            })
            .collect(),
        content_type: str_arg(spec, "content_type").to_owned(),
        body_text: text(spec.get("body_text")),
        body_size: match spec.get("body_size") {
            Some(Json::Int(n)) => usize::try_from(*n).expect("size"),
            _ => panic!("ctx without body_size"),
        },
        body_entropy: match spec.get("body_entropy") {
            Some(Json::Float(f)) => Some(*f),
            #[allow(clippy::cast_precision_loss)]
            Some(Json::Int(i)) => Some(*i as f64),
            _ => None,
        },
        body_bytes,
        prior_results: Vec::new(),
    }
}

fn builtin_steps(kind: &str, steps: &[Json]) -> Vec<Json> {
    let mut inspector: Option<Box<dyn Inspector>> = None;
    steps
        .iter()
        .map(|step| match str_arg(step, "op") {
            "configure" => {
                let cfg = json_to_yaml(step.get("config").unwrap_or(&Json::Null));
                let built: Result<Box<dyn Inspector>, String> = match kind {
                    "body-size" => BodySizeInspector::from_config(&cfg).map(|i| Box::new(i) as _),
                    "entropy" => EntropyInspector::from_config(&cfg).map(|i| Box::new(i) as _),
                    "content-type" => {
                        ContentTypeInspector::from_config(&cfg).map(|i| Box::new(i) as _)
                    }
                    "secrets" => SecretsInspector::from_config(&cfg).map(|i| Box::new(i) as _),
                    other => panic!("unknown inspector {other:?}"),
                };
                match built {
                    Ok(i) => {
                        inspector = Some(i);
                        Json::Null
                    }
                    Err(_) => Json::string("error"),
                }
            }
            "patterns" => {
                let builtins = SecretsInspector::from_config(&Value::Null).expect("defaults");
                Json::Array(
                    builtins
                        .matching_patterns(&text(step.get("text")).unwrap_or_default())
                        .into_iter()
                        .map(Json::string)
                        .collect(),
                )
            }
            "inspect" => {
                let ctx = context(step.get("ctx").expect("inspect step has a ctx"));
                let inspector = inspector.as_ref().expect("configured before inspect");
                verdict_json(inspector.inspect_request(&ctx).as_ref())
            }
            other => panic!("unknown op {other:?}"),
        })
        .collect()
}

/// Plugins as the corpus describes them: path → declared name, or null
/// for one that fails to load.
struct CorpusPlugins(Vec<(String, Option<String>)>);

#[derive(Debug)]
struct StubPlugin(String);

impl Inspector for StubPlugin {
    fn name(&self) -> &str {
        &self.0
    }
    fn inspect_request(&self, _ctx: &Context) -> Option<Verdict> {
        None
    }
}

impl PluginLoader for CorpusPlugins {
    fn declared_name(&self, _entry_name: &str, path: &str) -> Result<String, String> {
        self.0
            .iter()
            .find(|(p, _)| p == path)
            .and_then(|(_, n)| n.clone())
            .ok_or_else(|| format!("cannot load {path}"))
    }

    fn instantiate(&self, path: &str, _config: &Value) -> Result<Arc<dyn Inspector>, String> {
        let name = self.declared_name("", path)?;
        Ok(Arc::new(StubPlugin(name)))
    }
}

fn chain_step(step: &Json) -> Json {
    let config = Config::from_value(json_to_yaml(step.get("config").unwrap_or(&Json::Null)))
        .expect("corpus configs are mappings");
    let plugins = CorpusPlugins(match step.get("plugins") {
        Some(Json::Object(pairs)) => pairs
            .iter()
            .map(|(p, n)| (p.clone(), n.as_str().map(str::to_owned)))
            .collect(),
        _ => Vec::new(),
    });
    let domain = Arc::new(DomainInspector::new());
    let Ok(pending) = build_chain(&config, &domain, &plugins) else {
        return Json::string("error");
    };
    let chain = pending.commit();
    let slots = chain
        .slots()
        .iter()
        .map(|s| {
            let (kind, path) = match &s.kind {
                SlotKind::Builtin => ("builtin", Json::Null),
                SlotKind::Plugin(p) => ("plugin", Json::string(p)),
            };
            Json::Array(vec![
                Json::string(&s.name),
                Json::string(kind),
                path,
                yaml_to_json(&s.config),
            ])
        })
        .collect();
    let relay = chain
        .relay_inspectors()
        .iter()
        .map(|i| Json::string(i.name()))
        .collect();
    json::object([
        ("slots", Json::Array(slots)),
        ("relay", Json::Array(relay)),
        (
            "warnings",
            Json::Array(chain.warnings().iter().map(Json::string).collect()),
        ),
    ])
}

fn whitespace_step(op: &str) -> Json {
    let class = regex::Regex::new(r"^[\s\x1C-\x1F]$").expect("class compiles");
    let base64 = regex::Regex::new(&format!("^[{}]$", super::content_type::BASE64_CLASS))
        .expect("class compiles");
    let chars = (0..=0x10_FFFF_u32).filter_map(char::from_u32);
    let picked: Vec<Json> = match op {
        "isspace" => chars
            .filter(|&c| super::pyconf::py_isspace(c))
            .map(|c| Json::Int(i64::from(u32::from(c))))
            .collect(),
        "re_s" => chars
            .filter(|&c| {
                let mut buf = [0; 4];
                let s = c.encode_utf8(&mut buf);
                // The base64 class must agree with `\s` on whitespace.
                let ws = class.is_match(s);
                assert!(!ws || base64.is_match(s), "base64 class misses {c:?}");
                ws
            })
            .map(|c| Json::Int(i64::from(u32::from(c))))
            .collect(),
        other => panic!("unknown whitespace op {other:?}"),
    };
    Json::Array(picked)
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
        kind @ ("body-size" | "entropy" | "content-type" | "secrets") => builtin_steps(kind, steps),
        "chain" => steps.iter().map(chain_step).collect(),
        "whitespace" => steps
            .iter()
            .map(|s| whitespace_step(str_arg(s, "op")))
            .collect(),
        other => panic!("unknown inspector {other:?}"),
    }
}

#[test]
fn the_inspectors_corpus_replays() {
    replay(&corpus_path("inspectors.json"));
}

#[test]
fn the_secrets_corpus_replays() {
    replay(&corpus_path("secrets.json"));
}

/// Replay every case of the corpus at `path`; with `AGENTCAGE_BLESS`
/// set, rewrite its expectations instead.
fn replay(path: &Path) {
    let text = std::fs::read_to_string(path).expect("corpus readable");
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
        std::fs::write(path, json::dumps(&corpus, DumpOptions::indented()) + "\n")
            .expect("corpus writable");
        return;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_wrong_expectation_fails() {
    // Mutation check: the comparison above must bite on a flipped verdict.
    let text = std::fs::read_to_string(corpus_path("inspectors.json")).expect("corpus readable");
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
