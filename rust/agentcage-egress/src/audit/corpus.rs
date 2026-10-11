//! `tests/fixtures/egress/audit_lines.json`, asserted byte for byte.
//!
//! Each case was recorded from the replaced implementation's audit
//! funnel: the exact line stderr, `audit.jsonl` and the watcher ring
//! received. Here the same input runs through [`AuditWriter`] and the
//! [`records`](super::records) builders.
//!
//! `AGENTCAGE_BLESS=1 cargo test -p agentcage-egress audit_lines_corpus`
//! rewrites the expectations from this implementation (for a deliberate
//! change; update the generator to match until cutover).

use std::sync::Arc;

use agentcage_core::har::datetime::DateTime;

use super::testutil::{Scratch, SharedBuf, arr, blessing, corpus_path, date, int, s, write_corpus};
use super::{
    AuditWriter, Decision, Direction, HttpDecision, Redactor, private_peer_blocked,
    tcp_bypass_blocked, tcp_bypass_target,
};
use crate::inspect::{Action, Severity, Verdict};
use crate::json::{self, Json};

/// The literal redaction the injector does for values that appear only
/// verbatim (the corpus avoids encoded forms, which are the injector's
/// own corpus): each rule's real value becomes its placeholder in every
/// string at any depth, keys untouched.
#[derive(Debug)]
struct Literal(Vec<(String, String)>);

impl Redactor for Literal {
    fn redact(&self, entry: &mut Json) {
        match entry {
            Json::Str(text) => {
                for (real, placeholder) in &self.0 {
                    *text = text.replace(real.as_str(), placeholder);
                }
            }
            Json::Array(items) => items.iter_mut().for_each(|v| self.redact(v)),
            Json::Object(pairs) => pairs.iter_mut().for_each(|(_, v)| self.redact(v)),
            _ => {}
        }
    }
}

thread_local! {
    static NOW: std::cell::Cell<Option<DateTime>> = const { std::cell::Cell::new(None) };
}

fn pinned_now() -> DateTime {
    NOW.with(std::cell::Cell::get).expect("clock not pinned")
}

fn verdicts(items: &[Json]) -> Vec<Verdict> {
    items
        .iter()
        .map(|r| {
            let action = match s(r, "action") {
                "block" => Action::Block,
                "flag" => Action::Flag,
                other => panic!("action {other}"),
            };
            Verdict::new(
                s(r, "name"),
                action,
                s(r, "reason"),
                Severity::parse(s(r, "severity")).unwrap(),
            )
        })
        .collect()
}

fn strings(items: &[Json]) -> Vec<String> {
    items
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

fn lines_json(lines: Vec<String>) -> Json {
    Json::Array(lines.into_iter().map(Json::Str).collect())
}

fn run(kind: &str, input: &Json) -> Json {
    match kind {
        "isoformat" => json::object([(
            "isoformat",
            Json::string(date(arr(input, "parts")).isoformat()),
        )]),
        "tcp_target" => {
            let addr = |key: &str| match input.get(key) {
                Some(Json::Array(pair)) => Some((
                    pair[0].as_str().unwrap().to_owned(),
                    u16::try_from(match pair[1] {
                        Json::Int(p) => p,
                        _ => panic!("port"),
                    })
                    .unwrap(),
                )),
                _ => None,
            };
            let (peer, dst) = (addr("peername"), addr("address"));
            json::object([(
                "target",
                Json::string(tcp_bypass_target(
                    input.get("sni").and_then(Json::as_str),
                    peer.as_ref().map(|(h, p)| (h.as_str(), *p)),
                    dst.as_ref().map(|(h, p)| (h.as_str(), *p)),
                )),
            )])
        }
        _ => run_sinks(kind, input),
    }
}

fn run_sinks(kind: &str, input: &Json) -> Json {
    let dir = Scratch::new("audit-corpus");
    let path = dir.0.join("audit.jsonl");
    let out = SharedBuf::default();
    let ts = date(arr(input, "ts"));
    NOW.with(|now| now.set(Some(ts)));
    let writer = AuditWriter::new(Some(&path))
        .with_stderr(Box::new(out.clone()))
        .with_clock(pinned_now);
    let ring = writer.enable_ring();
    if let Some(Json::Array(rules)) = input.get("rules") {
        writer.set_redactor(Arc::new(Literal(
            rules
                .iter()
                .map(|r| {
                    (
                        s(r, "real_value").to_owned(),
                        s(r, "placeholder").to_owned(),
                    )
                })
                .collect(),
        )));
    }
    match kind {
        "http" => {
            let decision = match s(input, "decision") {
                "allowed" => Decision::Allowed,
                "flagged" => Decision::Flagged,
                "blocked" => Decision::Blocked,
                other => panic!("decision {other}"),
            };
            let direction = match s(input, "direction") {
                "outbound" => Direction::Outbound,
                _ => Direction::Inbound,
            };
            let record = HttpDecision {
                ts,
                direction,
                method: s(input, "method").to_owned(),
                host: s(input, "host").to_owned(),
                port: u16::try_from(int(input, "port")).unwrap(),
                path: s(input, "path").to_owned(),
                url: s(input, "url").to_owned(),
                decision,
                reason: input
                    .get("reason")
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_owned(),
                source: s(input, "source").to_owned(),
                secrets_injected: strings(arr(input, "secrets_injected")),
                secrets_redacted: strings(arr(input, "secrets_redacted")),
                inspectors: verdicts(arr(input, "inspectors")),
            };
            record.emit(&writer, input.get("log_allowed") == Some(&Json::Bool(true)));
        }
        "tcp_bypass_blocked" => writer.write(tcp_bypass_blocked(ts, s(input, "target"))),
        "private_peer_blocked" => writer.write(private_peer_blocked(
            ts,
            s(input, "host"),
            s(input, "peer_ip"),
            s(input, "phase"),
        )),
        "raw" => writer.write(input.get("entry").unwrap().clone()),
        other => panic!("unknown kind {other}"),
    }
    let file = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    json::object([
        ("stderr", lines_json(out.lines())),
        ("file", lines_json(file)),
        (
            "ring",
            lines_json(ring.snapshot().iter().map(json::to_string).collect()),
        ),
    ])
}

#[test]
fn audit_lines_corpus() {
    let name = "audit_lines.json";
    let mut doc = json::parse(&std::fs::read_to_string(corpus_path(name)).unwrap()).unwrap();
    let Some(Json::Array(cases)) = doc.get("cases").cloned() else {
        panic!("no cases")
    };
    assert!(cases.len() > 30, "corpus shrank");
    let mut blessed = Vec::new();
    let mut failures = Vec::new();
    for mut case in cases {
        let got = run(s(&case, "kind"), case.get("input").unwrap());
        if case.get("expected") != Some(&got) {
            failures.push(format!(
                "{}:\n  want {}\n  got  {}",
                s(&case, "id"),
                json::to_string(case.get("expected").unwrap()),
                json::to_string(&got)
            ));
        }
        case.set("expected", got);
        blessed.push(case);
    }
    if blessing() {
        doc.set("cases", Json::Array(blessed));
        write_corpus(name, &doc);
        return;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_wrong_expectation_is_caught() {
    // Mutation sanity check: the comparison above bites on one byte.
    let doc =
        json::parse(&std::fs::read_to_string(corpus_path("audit_lines.json")).unwrap()).unwrap();
    let case = arr(&doc, "cases")
        .iter()
        .find(|c| s(c, "kind") == "tcp_bypass_blocked")
        .unwrap();
    let got = run("tcp_bypass_blocked", case.get("input").unwrap());
    let mut wrong = case.get("expected").unwrap().clone();
    if let Some(Json::Array(lines)) = wrong.get("stderr").cloned() {
        let mutated = lines[0].as_str().unwrap().replacen("\": \"", "\":\"", 1);
        wrong.set("stderr", Json::Array(vec![Json::Str(mutated)]));
    }
    assert_ne!(got, wrong);
    assert_eq!(&got, case.get("expected").unwrap());
}
