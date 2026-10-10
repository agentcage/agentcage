use std::path::Path;

use super::*;
use crate::audit::NoRedaction;
use crate::audit::testutil::{Scratch, arr, blessing, corpus_path, date, int, s, write_corpus};
use crate::inspect::{Action, Severity};

// ── Corpus: tests/fixtures/egress/capture.json ───────────────
//
// `AGENTCAGE_BLESS=1 cargo test -p agentcage-egress capture_corpus`
// rewrites the expectations from this implementation.

thread_local! {
    static NOW: std::cell::Cell<Option<DateTime>> = const { std::cell::Cell::new(None) };
}

fn pinned_now() -> DateTime {
    NOW.with(std::cell::Cell::get).expect("clock not pinned")
}

fn fixed() -> DateTime {
    DateTime::from_parts((2026, 10, 10), (1, 2, 3, 0), Some(0)).unwrap()
}

fn to_yaml(v: &Json) -> Value {
    match v {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Int(i) => Value::Number((*i).into()),
        Json::Float(f) => Value::Number((*f).into()),
        Json::BigInt(_) => panic!("no big ints in capture sections"),
        Json::Str(s) => Value::String(s.clone()),
        Json::Array(items) => Value::Sequence(items.iter().map(to_yaml).collect()),
        Json::Object(pairs) => {
            let mut m = Mapping::new();
            for (k, v) in pairs {
                m.insert(Value::String(k.clone()), to_yaml(v));
            }
            Value::Mapping(m)
        }
    }
}

fn section(v: &Json) -> Mapping {
    match to_yaml(v) {
        Value::Mapping(m) => m,
        _ => panic!("section is not a mapping"),
    }
}

fn bytes(v: &Json) -> Vec<u8> {
    match v {
        Json::Str(s) => s.as_bytes().to_vec(),
        Json::Object(_) => base64::engine::general_purpose::STANDARD
            .decode(s(v, "b64"))
            .unwrap(),
        _ => panic!("not a byte string"),
    }
}

fn headers(v: &[Json]) -> Headers {
    Headers(
        v.iter()
            .map(|pair| match pair {
                Json::Array(kv) => (
                    kv[0].as_str().unwrap().as_bytes().to_vec(),
                    kv[1].as_str().unwrap().as_bytes().to_vec(),
                ),
                _ => panic!("header pair"),
            })
            .collect(),
    )
}

fn decision(text: &str) -> Decision {
    match text {
        "allowed" => Decision::Allowed,
        "flagged" => Decision::Flagged,
        "blocked" => Decision::Blocked,
        other => panic!("decision {other}"),
    }
}

fn direction(text: &str) -> Direction {
    match text {
        "outbound" => Direction::Outbound,
        "inbound" => Direction::Inbound,
        other => panic!("direction {other}"),
    }
}

fn writer_for(dir: &Scratch, section: &Mapping) -> CaptureWriter {
    CaptureWriter::open(
        CaptureSettings::from_section(section).unwrap(),
        &dir.0.join("capture.jsonl"),
    )
    .unwrap()
}

fn compact(v: &Json) -> Json {
    Json::string(json::to_compact_string(v))
}

fn run_settings(case: &Json, input: &Json) -> Json {
    match CaptureSettings::from_section(&section(input.get("section").unwrap())) {
        // The error name is the replaced implementation's exception
        // class, informational only; refusal is what is asserted.
        Err(_) => object([
            ("accepted", Json::Bool(false)),
            (
                "error",
                case.get("expected")
                    .and_then(|e| e.get("error"))
                    .cloned()
                    .unwrap_or(Json::Null),
            ),
        ]),
        Ok(settings) => {
            let pair = |p: &Json| match p {
                Json::Array(dh) => (
                    dh[0].as_str().unwrap().to_owned(),
                    dh[1].as_str().unwrap().to_owned(),
                ),
                _ => panic!("pair"),
            };
            object([
                ("accepted", Json::Bool(true)),
                (
                    "should_capture",
                    Json::Array(
                        arr(input, "should_capture")
                            .iter()
                            .map(pair)
                            .map(|(d, h)| Json::Bool(settings.should_capture(&d, &h)))
                            .collect(),
                    ),
                ),
                (
                    "captures_host",
                    Json::Array(
                        arr(input, "captures_host")
                            .iter()
                            .map(|h| Json::Bool(settings.captures_host(h.as_str().unwrap())))
                            .collect(),
                    ),
                ),
            ])
        }
    }
}

fn run_entry(dir: &Scratch, input: &Json) -> Json {
    NOW.with(|n| n.set(Some(date(arr(input, "ts")))));
    let a = input.get("args").unwrap();
    let entry = CaptureEntry {
        flow_id: s(a, "flow_id").to_owned(),
        direction: direction(s(a, "direction")),
        decision: decision(s(a, "decision")),
        host: s(a, "host").to_owned(),
        method: s(a, "method").to_owned(),
        path: s(a, "path").to_owned(),
        inspectors: a.get("inspectors").unwrap().clone(),
        inbound_req: a.get("inbound_req").unwrap().clone(),
        inbound_resp: a.get("inbound_resp").unwrap().clone(),
        outbound_req: a.get("outbound_req").unwrap().clone(),
        outbound_resp: a.get("outbound_resp").unwrap().clone(),
        ws_messages: match a.get("ws_messages") {
            Some(Json::Array(m)) => m.clone(),
            _ => Vec::new(),
        },
        ws_messages_omitted: a.get("ws_messages_omitted").map_or(0, |_| {
            usize::try_from(int(a, "ws_messages_omitted")).unwrap()
        }),
    };
    let mut w = writer_for(dir, &Mapping::new()).with_clock(pinned_now);
    w.write_entry(&entry).unwrap();
    object([(
        "line",
        Json::string(std::fs::read_to_string(dir.0.join("capture.jsonl")).unwrap()),
    )])
}

fn run(case: &Json) -> Json {
    let input = case.get("input").unwrap();
    let dir = Scratch::new("capture-corpus");
    match s(case, "kind") {
        "settings" => run_settings(case, input),
        "request" => {
            let r = input.get("request").unwrap();
            let req = Request {
                method: s(r, "method").to_owned(),
                scheme: s(r, "scheme").to_owned(),
                host: s(r, "host").to_owned(),
                port: u16::try_from(int(r, "port")).unwrap(),
                path: s(r, "path").to_owned(),
                http_version: s(r, "http_version").to_owned(),
                headers: headers(arr(r, "headers")),
                body: Vec::new(),
            };
            let w = writer_for(&dir, &section(input.get("section").unwrap()));
            let body = bytes(r.get("body").unwrap());
            object([
                ("url", Json::string(req.url())),
                ("snapshot", compact(&w.snapshot_request(&req, &body))),
            ])
        }
        "response" => {
            let w = writer_for(&dir, &section(input.get("section").unwrap()));
            let snapshot = match input.get("response").unwrap() {
                Json::Null => w.snapshot_response(None),
                r => {
                    let resp = Response {
                        status: u16::try_from(int(r, "status")).unwrap(),
                        reason: s(r, "reason").to_owned(),
                        http_version: s(r, "http_version").to_owned(),
                        headers: headers(arr(r, "headers")),
                        body: Vec::new(),
                    };
                    let body = bytes(r.get("body").unwrap());
                    w.snapshot_response(Some((&resp, &body)))
                }
            };
            object([("snapshot", compact(&snapshot))])
        }
        "entry" => run_entry(&dir, input),
        "ws" => {
            let mut w = writer_for(&dir, &section(input.get("section").unwrap()));
            for fr in arr(input, "frames") {
                w.add_ws_frame(
                    fr.get("flow").and_then(Json::as_str).unwrap_or("f"),
                    fr.get("from_client") == Some(&Json::Bool(true)),
                    fr.get("is_text") == Some(&Json::Bool(true)),
                    &bytes(fr.get("content").unwrap()),
                    s(fr, "ts"),
                    fr.get("decision")
                        .and_then(Json::as_str)
                        .map_or(Decision::Allowed, decision),
                );
            }
            let (messages, omitted) = w.pop_ws_buffer("f");
            object([
                ("messages", compact(&Json::Array(messages))),
                ("omitted", Json::Int(i64::try_from(omitted).unwrap())),
            ])
        }
        other => panic!("unknown kind {other}"),
    }
}

#[test]
fn capture_corpus() {
    let name = "capture.json";
    let mut doc = json::parse(&std::fs::read_to_string(corpus_path(name)).unwrap()).unwrap();
    let Some(Json::Array(cases)) = doc.get("cases").cloned() else {
        panic!("no cases")
    };
    assert!(cases.len() > 40, "corpus shrank");
    let mut failures = Vec::new();
    let mut blessed = Vec::new();
    for mut case in cases {
        let got = run(&case);
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
    let doc = json::parse(&std::fs::read_to_string(corpus_path("capture.json")).unwrap()).unwrap();
    let case = arr(&doc, "cases")
        .iter()
        .find(|c| s(c, "kind") == "entry")
        .unwrap();
    let got = run(case);
    let line = s(case.get("expected").unwrap(), "line").replacen(',', ", ", 1);
    assert_ne!(got, object([("line", Json::string(line))]));
    assert_eq!(&got, case.get("expected").unwrap());
}

// ── The writer ───────────────────────────────────────────────

fn plain_entry(host: &str, body: &str) -> CaptureEntry {
    let req = object([("body", Json::string(body))]);
    CaptureEntry {
        flow_id: "f".into(),
        direction: Direction::Outbound,
        decision: Decision::Allowed,
        host: host.into(),
        method: "POST".into(),
        path: "/p".into(),
        inspectors: Json::Array(Vec::new()),
        inbound_req: req.clone(),
        inbound_resp: Json::Object(Vec::new()),
        outbound_req: req,
        outbound_resp: Json::Object(Vec::new()),
        ws_messages: Vec::new(),
        ws_messages_omitted: 0,
    }
}

fn rotating(dir: &Scratch, max_file_size: u64) -> CaptureWriter {
    CaptureWriter::open(
        CaptureSettings {
            max_file_size,
            ..CaptureSettings::default()
        },
        &dir.0.join("capture.jsonl"),
    )
    .unwrap()
}

fn read_lines(path: &Path) -> Vec<Json> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| json::parse(l).unwrap())
        .collect()
}

#[test]
fn the_first_rollover_loses_nothing() {
    let dir = Scratch::new("capture-rot1");
    let mut w = rotating(&dir, 20_000);
    for _ in 0..8 {
        w.write_entry(&plain_entry("api.example.com", &"x".repeat(2048)))
            .unwrap();
    }
    let rotated = dir.0.join("capture.jsonl.1");
    assert!(rotated.is_file());
    let live = dir.0.join("capture.jsonl");
    assert!(std::fs::metadata(&live).unwrap().len() < 20_000);
    assert_eq!(read_lines(&rotated).len() + read_lines(&live).len(), 8);
}

#[test]
fn retention_is_two_generations_keeping_the_recent_tail() {
    let dir = Scratch::new("capture-rot2");
    let mut w = rotating(&dir, 20_000);
    for i in 0..40 {
        w.write_entry(&plain_entry(&format!("h{i:03}.example"), &"x".repeat(2048)))
            .unwrap();
    }
    let kept: Vec<String> = [dir.0.join("capture.jsonl.1"), dir.0.join("capture.jsonl")]
        .iter()
        .flat_map(|p| read_lines(p))
        .map(|e| s(&e, "host").to_owned())
        .collect();
    assert_eq!(kept.last().unwrap(), "h039.example");
    assert!(!kept.iter().any(|h| h == "h000.example"));
    let on_disk: u64 = std::fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().len())
        .sum();
    assert!(on_disk < 3 * 20_000, "unbounded growth: {on_disk}");
}

#[test]
fn zero_disables_rotation() {
    let dir = Scratch::new("capture-rot0");
    let mut w = rotating(&dir, 0);
    for _ in 0..20 {
        w.write_entry(&plain_entry("api.example.com", &"x".repeat(2048)))
            .unwrap();
    }
    assert!(!dir.0.join("capture.jsonl.1").exists());
    assert!(
        std::fs::metadata(dir.0.join("capture.jsonl"))
            .unwrap()
            .len()
            > 20_000
    );
}

#[test]
fn rotation_counts_an_existing_file() {
    let dir = Scratch::new("capture-rot-existing");
    std::fs::write(dir.0.join("capture.jsonl"), "x".repeat(30_000)).unwrap();
    let mut w = rotating(&dir, 20_000);
    w.write_entry(&plain_entry("a.example", "b")).unwrap();
    assert!(dir.0.join("capture.jsonl.1").is_file());
    assert_eq!(
        std::fs::metadata(dir.0.join("capture.jsonl"))
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn ws_message_count_is_bounded_and_the_rest_counted() {
    let dir = Scratch::new("capture-wscount");
    let mut w = writer_for(&dir, &Mapping::new());
    for _ in 0..=WS_MAX_MESSAGES {
        w.add_ws_frame("f", true, true, b"m", "t", Decision::Allowed);
    }
    let (messages, omitted) = w.pop_ws_buffer("f");
    assert_eq!((messages.len(), omitted), (WS_MAX_MESSAGES, 1));
    assert_eq!(w.pop_ws_buffer("f"), (Vec::new(), 0));
}

#[test]
fn an_unlimited_body_still_bounds_a_sockets_total() {
    let dir = Scratch::new("capture-wstotal");
    let mut sec = Mapping::new();
    sec.insert("max_body_size".into(), Value::Number(0.into()));
    let w = writer_for(&dir, &sec);
    assert_eq!(w.ws_total, WS_DEFAULT_TOTAL);
}

#[test]
fn adopting_buffers_carries_the_used_bound() {
    let dir = Scratch::new("capture-adopt");
    let mut sec = Mapping::new();
    sec.insert("max_body_size".into(), Value::Number(4.into()));
    let mut old = writer_for(&dir, &sec);
    old.add_ws_frame("f", true, true, b"abcd", "t", Decision::Allowed);
    let mut new = writer_for(&dir, &sec);
    new.adopt_ws_buffers(&mut old);
    new.add_ws_frame("f", true, true, b"e", "t", Decision::Allowed);
    let (messages, omitted) = new.pop_ws_buffer("f");
    assert_eq!((messages.len(), omitted), (1, 1));
    assert!(old.ws_buffers.is_empty());
}

#[test]
fn negative_sizes_behave_as_the_slices_they_were() {
    let dir = Scratch::new("capture-negative");
    let mut sec = Mapping::new();
    sec.insert("max_body_size".into(), Value::Number((-2).into()));
    sec.insert("max_file_size".into(), Value::Number((-5).into()));
    let mut w = writer_for(&dir, &sec);
    assert_eq!(w.settings().max_file_size, 0);
    let req = Request {
        method: "GET".into(),
        scheme: "http".into(),
        host: "a".into(),
        port: 80,
        path: "/".into(),
        ..Request::default()
    };
    let snap = w.snapshot_request(&req, b"hello");
    assert_eq!(s(&snap, "body"), "hel");
    assert_eq!(snap.get("bodyTruncated"), Some(&Json::Bool(true)));
    // A negative total leaves no room for any frame.
    w.add_ws_frame("f", true, true, b"x", "t", Decision::Allowed);
    assert_eq!(w.pop_ws_buffer("f"), (Vec::new(), 1));
}

#[test]
fn capture_inspectors_are_redacted() {
    #[derive(Debug)]
    struct Hide;
    impl Redactor for Hide {
        fn redact(&self, entry: &mut Json) {
            if let Json::Array(items) = entry {
                for item in items {
                    item.set("reason", Json::string("<hidden>"));
                }
            }
        }
    }
    let v = [Verdict::new(
        "secrets",
        Action::Flag,
        "saw sk-1",
        Severity::Warning,
    )];
    assert_eq!(
        json::to_string(&capture_inspectors(&v, &Hide)),
        r#"[{"name": "secrets", "action": "flag", "reason": "<hidden>", "severity": "warning"}]"#
    );
    assert_eq!(
        capture_inspectors(&v, &NoRedaction),
        crate::audit::inspectors_json(&v)
    );
}

// ── The staging lifecycle ────────────────────────────────────

fn cfg(yaml: &str) -> Config {
    Config::parse("t", yaml).unwrap()
}

fn enabled(dir: &Scratch, extra: &str) -> Capture {
    let c = Capture::new(Some(dir.0.join("capture.jsonl"))).with_clock(fixed);
    assert_eq!(
        c.reconfigure(&cfg(&format!("capture:\n  enable_har: true\n{extra}")))
            .unwrap(),
        Reconfigured::Enabled
    );
    c
}

fn lines(dir: &Scratch) -> Vec<Json> {
    read_lines(&dir.0.join("capture.jsonl"))
}

fn request(host: &str, path: &str) -> Request {
    Request {
        method: "GET".into(),
        scheme: "https".into(),
        host: host.into(),
        port: 443,
        path: path.into(),
        http_version: "HTTP/1.1".into(),
        ..Request::default()
    }
}

fn info(id: &str, host: &str) -> FlowInfo {
    FlowInfo {
        id: id.into(),
        direction: Direction::Outbound,
        decision: Decision::Allowed,
        host: host.into(),
        method: "GET".into(),
        path: "/socket".into(),
    }
}

fn response(status: u16) -> Response {
    Response {
        status,
        reason: if status == 101 {
            "Switching Protocols".into()
        } else {
            "OK".into()
        },
        http_version: "HTTP/1.1".into(),
        ..Response::default()
    }
}

fn stage(c: &Capture, id: &str, host: &str) {
    let req = request(host, "/socket");
    let snap = c.snapshot_request(&req, b"").unwrap();
    c.stage(info(id, host), Json::Array(Vec::new()), snap);
}

fn upgrade(c: &Capture, id: &str, host: &str) {
    stage(c, id, host);
    c.finish_response(id, (&response(101), b""), true);
}

#[test]
fn an_http_flow_is_written_at_its_response_with_the_refreshed_request() {
    let dir = Scratch::new("cap-http");
    let c = enabled(&dir, "");
    let req = request("api.example.com", "/v1?key=PLACEHOLDER");
    let snap = c.snapshot_request(&req, b"{}").unwrap();
    c.stage(
        FlowInfo {
            path: "/v1?key=REAL".into(),
            ..info("h1", "api.example.com")
        },
        Json::Array(Vec::new()),
        snap,
    );
    c.refresh_request("h1", &req, b"{}");
    c.finish_response("h1", (&response(200), b"ok"), false);
    let got = lines(&dir);
    assert_eq!(got.len(), 1);
    assert_eq!(s(&got[0], "path"), "/v1?key=PLACEHOLDER");
    assert_eq!(s(&got[0], "ts"), "2026-10-10T01:02:03+00:00");
    let inbound = got[0].get("inbound").unwrap();
    assert_eq!(inbound, got[0].get("outbound").unwrap());
    assert_eq!(
        s(inbound.get("request").unwrap(), "url"),
        "https://api.example.com/v1?key=PLACEHOLDER"
    );
    assert_eq!(s(inbound.get("response").unwrap(), "body"), "ok");
    assert_eq!(c.pending_len(), 0);
}

#[test]
fn a_websocket_entry_stays_open_at_the_101_and_is_written_at_the_end() {
    let dir = Scratch::new("cap-ws");
    let c = enabled(&dir, "");
    upgrade(&c, "ws-1", "ws.example.com");
    assert!(lines(&dir).is_empty());
    assert_eq!(c.pending_len(), 1);
    c.add_ws_frame(
        "ws-1",
        true,
        true,
        br#"{"op":"hello"}"#,
        "t1",
        Decision::Allowed,
    );
    c.add_ws_frame(
        "ws-1",
        false,
        false,
        b"\x00\xffbin",
        "t2",
        Decision::Allowed,
    );
    c.finish_websocket("ws-1");
    let got = lines(&dir);
    assert_eq!(got.len(), 1);
    let msgs = arr(&got[0], "ws_messages");
    assert_eq!(msgs.len(), 2);
    assert_eq!(s(&msgs[0], "type"), "send");
    assert_eq!(int(&msgs[1], "opcode"), 2);
    assert_eq!(
        s(
            got[0].get("inbound").unwrap().get("response").unwrap(),
            "statusText"
        ),
        "Switching Protocols"
    );
    // Exactly once, and nothing is left behind.
    c.release("ws-1");
    c.finish_websocket("ws-1");
    assert_eq!(lines(&dir).len(), 1);
    assert_eq!(c.pending_len(), 0);
}

#[test]
fn an_errored_websocket_is_written_once_with_its_frames_so_far() {
    let dir = Scratch::new("cap-ws-err");
    let c = enabled(&dir, "");
    upgrade(&c, "ws-1", "ws.example.com");
    c.add_ws_frame("ws-1", true, true, b"a", "t", Decision::Allowed);
    c.release("ws-1");
    c.finish_websocket("ws-1");
    let got = lines(&dir);
    assert_eq!(got.len(), 1);
    assert_eq!(arr(&got[0], "ws_messages").len(), 1);
}

#[test]
fn a_socket_without_frames_is_still_written() {
    let dir = Scratch::new("cap-ws-none");
    let c = enabled(&dir, "");
    upgrade(&c, "ws-1", "ws.example.com");
    c.finish_websocket("ws-1");
    let got = lines(&dir);
    assert_eq!(got.len(), 1);
    assert!(got[0].get("ws_messages").is_none());
    assert!(got[0].get("ws_messages_omitted").is_none());
}

#[test]
fn min_action_is_checked_at_the_write_against_the_escalated_decision() {
    let dir = Scratch::new("cap-ws-min");
    let c = enabled(&dir, "  min_action: flag\n");
    upgrade(&c, "quiet", "ws.example.com");
    c.add_ws_frame("quiet", true, true, b"a", "t", Decision::Allowed);
    c.finish_websocket("quiet");
    assert!(lines(&dir).is_empty());

    upgrade(&c, "loud", "ws.example.com");
    c.add_ws_frame("loud", true, true, b"a", "t", Decision::Flagged);
    c.add_ws_frame("loud", true, true, b"b", "t", Decision::Allowed);
    c.finish_websocket("loud");
    let got = lines(&dir);
    assert_eq!(got.len(), 1);
    assert_eq!(s(&got[0], "decision"), "flagged");
    assert_eq!(s(&arr(&got[0], "ws_messages")[0], "decision"), "flagged");
    assert!(arr(&got[0], "ws_messages")[1].get("decision").is_none());
}

#[test]
fn min_action_block_needs_a_blocked_frame() {
    let dir = Scratch::new("cap-ws-block");
    let c = enabled(&dir, "  min_action: block\n");
    upgrade(&c, "a", "ws.example.com");
    c.add_ws_frame("a", true, true, b"x", "t", Decision::Flagged);
    c.finish_websocket("a");
    assert!(lines(&dir).is_empty());
    upgrade(&c, "b", "ws.example.com");
    c.add_ws_frame("b", true, true, b"x", "t", Decision::Blocked);
    c.finish_websocket("b");
    assert_eq!(s(&lines(&dir)[0], "decision"), "blocked");
}

#[test]
fn an_excluded_domain_buffers_nothing() {
    let dir = Scratch::new("cap-ws-excl");
    let c = enabled(&dir, "  exclude_domains: [ws.example.com]\n");
    upgrade(&c, "ws-1", "ws.example.com");
    assert_eq!(c.pending_len(), 0);
    c.add_ws_frame("ws-1", true, true, b"x", "t", Decision::Allowed);
    assert!(c.lock().writer.as_ref().unwrap().ws_buffers.is_empty());
    c.finish_websocket("ws-1");
    assert!(lines(&dir).is_empty());
}

#[test]
fn a_writer_swapped_mid_socket_writes_the_entry_with_earlier_frames() {
    let dir = Scratch::new("cap-ws-swap");
    let c = enabled(&dir, "");
    upgrade(&c, "ws-1", "ws.example.com");
    c.add_ws_frame("ws-1", true, true, b"before", "t", Decision::Allowed);
    assert_eq!(
        c.reconfigure(&cfg("capture:\n  enable_har: true\n  max_body_size: 3\n"))
            .unwrap(),
        Reconfigured::Enabled
    );
    c.add_ws_frame("ws-1", true, true, b"after", "t", Decision::Allowed);
    c.finish_websocket("ws-1");
    let got = lines(&dir);
    let data: Vec<&str> = arr(&got[0], "ws_messages")
        .iter()
        .map(|m| s(m, "data"))
        .collect();
    // The new writer's 3-byte total was already used up by "before".
    assert_eq!(data, ["before"]);
    assert_eq!(int(&got[0], "ws_messages_omitted"), 1);
}

#[test]
fn capture_disabled_mid_socket_drops_it() {
    let dir = Scratch::new("cap-ws-off");
    let c = enabled(&dir, "");
    upgrade(&c, "ws-1", "ws.example.com");
    assert_eq!(
        c.reconfigure(&cfg("capture:\n  enable_har: false\n"))
            .unwrap(),
        Reconfigured::Disabled
    );
    assert_eq!(c.pending_len(), 0);
    c.add_ws_frame("ws-1", true, true, b"x", "t", Decision::Allowed);
    c.finish_websocket("ws-1");
    assert!(lines(&dir).is_empty());
}

#[test]
fn a_101_without_a_websocket_is_written_at_the_response() {
    let dir = Scratch::new("cap-101");
    let c = enabled(&dir, "");
    stage(&c, "f", "ws.example.com");
    c.finish_response("f", (&response(101), b""), false);
    assert_eq!(lines(&dir).len(), 1);
    assert_eq!(c.pending_len(), 0);
}

#[test]
fn an_errored_http_flow_drops_its_staged_entry_unwritten() {
    let dir = Scratch::new("cap-err");
    let c = enabled(&dir, "");
    stage(&c, "f", "api.example.com");
    assert_eq!(c.pending_len(), 1);
    c.release("f");
    c.release("never-staged");
    assert_eq!(c.pending_len(), 0);
    assert!(lines(&dir).is_empty());
}

#[test]
fn a_request_blocked_flow_reaching_the_response_hook_is_discarded() {
    let dir = Scratch::new("cap-discard");
    let c = enabled(&dir, "");
    stage(&c, "f", "api.example.com");
    c.discard("f");
    c.finish_response("f", (&response(200), b""), false);
    assert!(lines(&dir).is_empty());
}

#[test]
fn a_blocked_request_is_recorded_with_one_snapshot_for_both_views() {
    let dir = Scratch::new("cap-blocked");
    let c = enabled(&dir, "  min_action: block\n");
    let req = request("evil.example", "/x");
    let resp = Response {
        status: 403,
        reason: "Forbidden".into(),
        ..response(403)
    };
    let inspectors = capture_inspectors(
        &[Verdict::new("domain", Action::Block, "no", Severity::Error)],
        &NoRedaction,
    );
    c.record_blocked_request(
        &FlowInfo {
            decision: Decision::Blocked,
            ..info("b", "evil.example")
        },
        inspectors,
        (&req, b"body"),
        Some((&resp, br#"{"blocked": true}"#)),
    );
    let got = lines(&dir);
    assert_eq!(got.len(), 1);
    assert_eq!(s(&got[0], "decision"), "blocked");
    assert_eq!(got[0].get("inbound"), got[0].get("outbound"));
    assert_eq!(arr(&got[0], "inspectors").len(), 1);

    let excluded = Scratch::new("cap-blocked-excl");
    let c = enabled(&excluded, "  exclude_domains: [evil.example]\n");
    c.record_blocked_request(
        &info("b", "evil.example"),
        Json::Array(Vec::new()),
        (&req, b""),
        None,
    );
    assert!(lines(&excluded).is_empty());
}

#[test]
fn a_response_blocked_flow_appends_the_response_verdicts() {
    let dir = Scratch::new("cap-resp-blocked");
    let c = enabled(&dir, "  min_action: block\n");
    let req = request("api.example.com", "/");
    let snap = c.snapshot_request(&req, b"").unwrap();
    let first = capture_inspectors(
        &[Verdict::new("a", Action::Flag, "r1", Severity::Warning)],
        &NoRedaction,
    );
    c.stage(
        FlowInfo {
            decision: Decision::Flagged,
            ..info("r", "api.example.com")
        },
        first,
        snap,
    );
    let more = capture_inspectors(
        &[Verdict::new("b", Action::Block, "r2", Severity::Error)],
        &NoRedaction,
    );
    c.finish_blocked_response("r", more, (&response(403), b"denied"));
    let got = lines(&dir);
    assert_eq!(got.len(), 1, "written regardless of filters");
    assert_eq!(s(&got[0], "decision"), "blocked");
    let names: Vec<&str> = arr(&got[0], "inspectors")
        .iter()
        .map(|i| s(i, "name"))
        .collect();
    assert_eq!(names, ["a", "b"]);
    assert_eq!(c.pending_len(), 0);
}

#[test]
fn reconfigure_is_a_noop_for_an_unchanged_section_and_keeps_the_writer_on_a_bad_one() {
    let dir = Scratch::new("cap-reload");
    let c = enabled(&dir, "  max_body_size: 100\n");
    assert_eq!(
        c.reconfigure(&cfg(
            "logging: {level: debug}\ncapture:\n  max_body_size: 100\n  enable_har: true\n"
        ))
        .unwrap(),
        Reconfigured::Unchanged
    );
    stage(&c, "f", "a.example");
    let bad = cfg("capture:\n  enable_har: true\n  max_body_size: abc\n");
    assert!(matches!(
        c.reconfigure(&bad),
        Err(CaptureError::InvalidSetting {
            key: "max_body_size"
        })
    ));
    assert!(c.is_enabled());
    assert_eq!(c.pending_len(), 1, "staged entries survive a refused edit");
    // The refused section was not recorded, so the same edit is retried.
    assert!(c.reconfigure(&bad).is_err());
}

#[test]
fn capture_needs_both_enable_har_and_a_path() {
    let dir = Scratch::new("cap-paths");
    let none = Capture::new(None);
    assert_eq!(
        none.reconfigure(&cfg("capture:\n  enable_har: true\n"))
            .unwrap(),
        Reconfigured::Disabled
    );
    assert!(!none.is_enabled());
    assert!(none.snapshot_request(&request("a", "/"), b"").is_none());
    none.stage(info("f", "a"), Json::Array(Vec::new()), Json::Null);
    assert_eq!(none.pending_len(), 0);

    let c = enabled(&dir, "");
    assert_eq!(
        c.reconfigure(&cfg("capture: [1]\n")).unwrap(),
        Reconfigured::Disabled
    );
    assert!(!c.is_enabled());
    assert!(!c.should_capture(Decision::Blocked, "a"));
}
