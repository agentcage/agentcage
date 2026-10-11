//! The SMTP relay against `tests/fixtures/egress/smtp.json`, recorded from
//! the Python relay it replaces (see `tests/fixtures/egress/gen/smtp.py`),
//! plus the goodbye on stop this port adds.
//!
//! `AGENTCAGE_BLESS=1 cargo test -p agentcage-egress smtp_corpus`
//! rewrites the corpus with what this relay does.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::audit::MemorySink;
use crate::inspect::Severity;
use crate::json::{self, Json};
use crate::relays::testkit::{
    arr, bless, blessing, boolean, dec, enc, load, merged, text, without_ts, yaml,
};

const CORPUS: &str = "smtp.json";
const USER: &str = "agent@example.com";
const PASS: &str = "real-app-password";

fn set(case: &mut Json, key: &str, value: Json) {
    case.set(key, value);
}

#[test]
fn smtp_corpus_headers_and_addresses() {
    let mut corpus = load(CORPUS);
    let mut failures = Vec::new();
    let bless_now = blessing();
    if let Json::Object(pairs) = &mut corpus {
        for (key, cases) in pairs.iter_mut() {
            let Json::Array(cases) = cases else { continue };
            for case in cases {
                match key.as_str() {
                    "headers" => {
                        let (ct, headers) = message_headers(&dec(case.get("body").unwrap()));
                        let got_ct = Json::Str(ct);
                        let got_h = Json::Array(
                            headers
                                .into_iter()
                                .map(|(k, v)| Json::Array(vec![Json::Str(k), Json::Str(v)]))
                                .collect(),
                        );
                        if bless_now {
                            set(case, "content_type", got_ct);
                            set(case, "headers", got_h);
                        } else if case.get("content_type") != Some(&got_ct)
                            || case.get("headers") != Some(&got_h)
                        {
                            failures.push(format!(
                                "{}: {} {}",
                                json::to_string(case),
                                json::to_string(&got_ct),
                                json::to_string(&got_h)
                            ));
                        }
                    }
                    "addresses" => {
                        let got = extract_address(text(case.get("arg").unwrap()))
                            .map_or(Json::Null, Json::Str);
                        if bless_now {
                            set(case, "address", got);
                        } else if case.get("address") != Some(&got) {
                            failures.push(format!(
                                "{}: {}",
                                json::to_string(case),
                                json::to_string(&got)
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if bless_now {
        bless(CORPUS, &corpus);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ── Test inspectors ─────────────────────────────────────

/// The generator's `MarkerInspector`: a marker check, or a recorder of
/// the contexts it is shown.
#[derive(Debug)]
struct Marker {
    spec: Json,
    name: String,
    contexts: Arc<Mutex<Vec<Json>>>,
}

impl Inspector for Marker {
    fn name(&self) -> &str {
        &self.name
    }

    fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
        if text(self.spec.get("kind").unwrap()) == "recorder" {
            let headers = ctx
                .headers
                .iter()
                .map(|(k, v)| Json::Array(vec![Json::Str(k.clone()), Json::Str(v.clone())]))
                .collect();
            self.contexts.lock().unwrap().push(json::object([
                ("inspector", Json::Str(self.name.clone())),
                ("url", Json::Str(ctx.url.clone())),
                ("host", Json::Str(ctx.host.clone())),
                ("method", Json::Str(ctx.method.clone())),
                ("headers", Json::Array(headers)),
                ("content_type", Json::Str(ctx.content_type.clone())),
                (
                    "body_text",
                    ctx.body_text.clone().map_or(Json::Null, Json::Str),
                ),
                (
                    "body_size",
                    Json::Int(i64::try_from(ctx.body_size).unwrap()),
                ),
                (
                    "body_entropy",
                    ctx.body_entropy.map_or(Json::Null, Json::Float),
                ),
                (
                    "prior",
                    Json::Array(
                        ctx.prior_results
                            .iter()
                            .map(|r| Json::Str(r.inspector.clone()))
                            .collect(),
                    ),
                ),
            ]));
            return None;
        }
        let marker = text(self.spec.get("marker").unwrap());
        if !ctx.body_text.as_deref().is_some_and(|t| t.contains(marker)) {
            return None;
        }
        let action = text(self.spec.get("action").unwrap());
        Some(Verdict::new(
            self.name.clone(),
            if action == "block" {
                Action::Block
            } else {
                Action::Flag
            },
            format!("{action}: {marker}"),
            Severity::parse(
                self.spec
                    .get("severity")
                    .and_then(Json::as_str)
                    .unwrap_or("warning"),
            )
            .unwrap(),
        ))
    }
}

// ── Mock upstream ───────────────────────────────────────

#[derive(Debug, Default)]
struct Recorder {
    commands: Vec<Json>,
    auth_seen: Option<(String, String)>,
    transactions: Vec<Json>,
}

type Rd = Reader<tokio::net::tcp::OwnedReadHalf>;

async fn line(r: &mut Rd) -> Vec<u8> {
    match r.read_line(usize::MAX / 2).await {
        Ok(Line::Data(l)) => l,
        _ => Vec::new(),
    }
}

fn first_address(l: &[u8]) -> String {
    let Some(open) = l.iter().position(|&b| b == b'<') else {
        return String::new();
    };
    let rest = &l[open + 1..];
    match rest.iter().position(|&b| b == b'>') {
        Some(close) if close > 0 => String::from_utf8_lossy(&rest[..close]).into_owned(),
        _ => String::new(),
    }
}

/// The mock submission host of `tests/test_protocol_relays_smtp.py`.
#[allow(clippy::too_many_lines)]
async fn serve_upstream(stream: TcpStream, up: Json, rec: Arc<Mutex<Recorder>>) {
    let (read, mut w) = stream.into_split();
    let mut r = Reader::new(read);
    if boolean(up.get("silent")) {
        while !r.read_some(4096).await.unwrap_or_default().is_empty() {}
        return;
    }
    let reject: Vec<String> = up
        .get("reject_rcpts")
        .map(|v| arr(v).iter().map(|s| text(s).to_owned()).collect())
        .unwrap_or_default();
    let _ = w.write_all(b"220 fake.upstream ESMTP\r\n").await;
    let (mut sender, mut recipients) = (String::new(), Vec::new());
    loop {
        let l = line(&mut r).await;
        if l.is_empty() {
            return;
        }
        rec.lock().unwrap().commands.push(enc(&l));
        let upper = l.to_ascii_uppercase();
        let reply: Vec<u8> = if upper.starts_with(b"EHLO") || upper.starts_with(b"HELO") {
            b"250-fake.upstream\r\n250-AUTH PLAIN LOGIN\r\n250-SIZE 10485760\r\n250 8BITMIME\r\n"
                .to_vec()
        } else if upper.starts_with(b"AUTH PLAIN") {
            let token = String::from_utf8_lossy(&l[b"AUTH PLAIN ".len().min(l.len())..])
                .trim()
                .to_owned();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(token)
                .unwrap_or_default();
            let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
            if parts.len() < 3 {
                b"535 5.7.8 bad auth\r\n".to_vec()
            } else {
                let user = String::from_utf8_lossy(parts[1]).into_owned();
                let pwd = String::from_utf8_lossy(parts[2]).into_owned();
                rec.lock().unwrap().auth_seen = Some((user.clone(), pwd.clone()));
                if boolean(up.get("echo_auth")) {
                    [
                        b"535-5.7.8 rejected: ",
                        trim_crlf(&l),
                        b"\r\n535 5.7.8 password ",
                        pwd.as_bytes(),
                        b" is wrong\r\n",
                    ]
                    .concat()
                } else if boolean(up.get("fail_auth")) || user != USER || pwd != PASS {
                    b"535 5.7.8 bad credentials\r\n".to_vec()
                } else {
                    b"235 2.7.0 authenticated\r\n".to_vec()
                }
            }
        } else if upper.starts_with(b"MAIL FROM") {
            sender = first_address(&l);
            recipients.clear();
            b"250 2.1.0 ok\r\n".to_vec()
        } else if upper.starts_with(b"RCPT TO") {
            let rcpt = first_address(&l);
            if reject.contains(&rcpt) {
                b"550 5.7.1 upstream-reject\r\n".to_vec()
            } else {
                recipients.push(rcpt);
                b"250 2.1.5 ok\r\n".to_vec()
            }
        } else if upper.starts_with(b"DATA") {
            if boolean(up.get("reject_data")) {
                b"554 5.7.0 no data today\r\n".to_vec()
            } else {
                let _ = w.write_all(b"354 end with .\r\n").await;
                let mut body = Vec::new();
                loop {
                    let ln = line(&mut r).await;
                    if ln.is_empty() || ln == b".\r\n" || ln == b".\n" {
                        break;
                    }
                    body.extend_from_slice(if ln.starts_with(b"..") { &ln[1..] } else { &ln });
                }
                rec.lock().unwrap().transactions.push(json::object([
                    ("sender", Json::Str(sender.clone())),
                    (
                        "recipients",
                        Json::Array(recipients.iter().map(|r| Json::Str(r.clone())).collect()),
                    ),
                    ("data", enc(&body)),
                ]));
                b"250 2.0.0 queued as ABC123\r\n".to_vec()
            }
        } else if upper.starts_with(b"RSET") {
            sender.clear();
            recipients.clear();
            b"250 2.0.0 ok\r\n".to_vec()
        } else if upper.starts_with(b"QUIT") {
            let _ = w.write_all(b"221 2.0.0 bye\r\n").await;
            return;
        } else if upper.starts_with(b"NOOP") {
            b"250 2.0.0 ok\r\n".to_vec()
        } else {
            b"502 5.5.1 unknown\r\n".to_vec()
        };
        let _ = w.write_all(&reply).await;
    }
}

fn entry(policy: &Json, port: u16) -> Value {
    let base = json::parse(&format!(
        r#"{{"name": "test-smtp", "type": "smtp", "listen": "127.0.0.1:0",
            "upstream": {{"host": "127.0.0.1", "port": {port}, "tls": false}},
            "auth": {{"type": "smtp-plain", "user_source": "env:TEST_SMTP_USER",
                      "password_source": "env:TEST_SMTP_PASS"}},
            "policy": {{"sender_allowlist": [], "recipient_allowlist": {{"addresses": [], "domains": []}},
                        "max_message_bytes": 5242880, "max_recipients": 10,
                        "send_rate_limit": "100/min", "conn_rate_limit": "100/min"}}}}"#
    ))
    .unwrap();
    let pol = merged(base.get("policy").unwrap().clone(), policy);
    let mut e = base;
    e.set("policy", pol);
    yaml(&e)
}

async fn read_response(r: &mut Rd) -> Json {
    let mut lines = Vec::new();
    loop {
        let l =
            match tokio::time::timeout(Duration::from_secs(5), r.read_line(usize::MAX / 2)).await {
                Ok(Ok(Line::Data(l))) => l,
                _ => Vec::new(),
            };
        if l.is_empty() {
            lines.push(Json::string("<eof>"));
            return Json::Array(lines);
        }
        let more = l.get(3) == Some(&b'-');
        lines.push(enc(&l));
        if !more {
            return Json::Array(lines);
        }
    }
}

fn seconds(v: Option<&Json>) -> Duration {
    match v {
        Some(Json::Float(f)) => Duration::from_secs_f64(*f),
        Some(Json::Int(n)) => Duration::from_secs(u64::try_from(*n).unwrap()),
        _ => Duration::ZERO,
    }
}

#[allow(clippy::too_many_lines)] // one recorded session, step by step
async fn run_session(case: &Json) -> Json {
    let up = case.get("upstream").cloned().unwrap();
    let rec = Arc::new(Mutex::new(Recorder::default()));
    let (up_port, server) = if boolean(up.get("unreachable")) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        (l.local_addr().unwrap().port(), None)
    } else {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (up, rec) = (up.clone(), rec.clone());
        (
            port,
            Some(tokio::spawn(async move {
                loop {
                    let (s, _) = listener.accept().await.unwrap();
                    tokio::spawn(serve_upstream(s, up.clone(), rec.clone()));
                }
            })),
        )
    };
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let inspectors: Vec<Arc<dyn Inspector>> = arr(case.get("inspectors").unwrap())
        .iter()
        .map(|spec| {
            Arc::new(Marker {
                name: text(spec.get("name").unwrap()).to_owned(),
                spec: spec.clone(),
                contexts: contexts.clone(),
            }) as Arc<dyn Inspector>
        })
        .collect();
    let sink = Arc::new(MemorySink::default());
    let settings = RelaySettings {
        log_allowed: boolean(case.get("log_allowed")),
        inspectors: inspectors.into(),
    };
    let cfg = SmtpConfig::parse(&entry(case.get("policy").unwrap(), up_port)).unwrap();
    let relay = SmtpRelay::with_credentials(cfg, USER.into(), PASS.into(), sink.clone(), &settings)
        .unwrap();
    relay.start().await.unwrap();
    let port = relay.local_addr().await.unwrap().port();
    let (r, mut w) = TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap()
        .into_split();
    let mut r = Reader::new(r);
    let greeting = read_response(&mut r).await;
    let mut steps = Vec::new();
    for step in arr(case.get("steps").unwrap()) {
        tokio::time::sleep(seconds(step.get("sleep"))).await;
        if let Some(data) = step.get("send") {
            let _ = w.write_all(&dec(data)).await;
        }
        if boolean(step.get("new_client")) {
            let (r2, _w2) = TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap()
                .into_split();
            let mut r2 = Reader::new(r2);
            steps.push(Json::Array(vec![read_response(&mut r2).await]));
            continue;
        }
        let n = step.get("responses").map_or(1, crate::relays::testkit::int);
        let mut got = Vec::new();
        for _ in 0..n {
            got.push(read_response(&mut r).await);
        }
        steps.push(Json::Array(got));
    }
    drop((r, w));
    tokio::time::sleep(Duration::from_millis(100)).await;
    relay.stop().await;
    if let Some(task) = server {
        task.abort();
    }
    let mut audit: Vec<Json> = sink.entries().iter().map(without_ts).collect();
    if boolean(case.get("mask_error")) {
        for e in &mut audit {
            if e.get("error").is_some() {
                e.set("error", Json::string("<masked>"));
            }
        }
    }
    let rec = rec.lock().unwrap();
    let contexts = contexts.lock().unwrap().clone();
    json::object([
        ("greeting", greeting),
        ("steps", Json::Array(steps)),
        (
            "upstream",
            json::object([
                ("commands", Json::Array(rec.commands.clone())),
                (
                    "auth_seen",
                    rec.auth_seen.clone().map_or(Json::Null, |(u, p)| {
                        Json::Array(vec![Json::Str(u), Json::Str(p)])
                    }),
                ),
                ("transactions", Json::Array(rec.transactions.clone())),
            ]),
        ),
        ("audit", Json::Array(audit)),
        ("contexts", Json::Array(contexts)),
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn smtp_corpus_sessions() {
    let mut corpus = load(CORPUS);
    let mut failures = Vec::new();
    let Json::Object(pairs) = &mut corpus else {
        panic!()
    };
    let sessions = &mut pairs.iter_mut().find(|(k, _)| k == "sessions").unwrap().1;
    let Json::Array(sessions) = sessions else {
        panic!()
    };
    for case in sessions.iter_mut() {
        let got = run_session(case).await;
        if case.get("expect") != Some(&got) {
            if blessing() {
                case.set("expect", got);
            } else {
                failures.push(format!(
                    "{}\n  want {}\n  got  {}",
                    text(case.get("name").unwrap()),
                    json::to_string(case.get("expect").unwrap()),
                    json::to_string(&got)
                ));
            }
        }
    }
    if blessing() {
        bless(CORPUS, &corpus);
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Stopping the relay ends an idle session with `421` (the Python relay
/// cut the connection).
#[tokio::test]
async fn stop_sends_421_to_open_sessions() {
    let cfg = SmtpConfig::parse(&entry(&Json::Object(Vec::new()), 1)).unwrap();
    let sink = Arc::new(MemorySink::default());
    let relay = SmtpRelay::with_credentials(
        cfg,
        USER.into(),
        PASS.into(),
        sink,
        &RelaySettings::default(),
    )
    .unwrap();
    relay.start().await.unwrap();
    let port = relay.local_addr().await.unwrap().port();
    let (r, _w) = TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap()
        .into_split();
    let mut r = Reader::new(r);
    let _ = read_response(&mut r).await;
    relay.stop().await;
    assert_eq!(
        json::to_string(&read_response(&mut r).await),
        r#"["421 4.3.2 relay shutting down\r\n"]"#
    );
}

#[test]
fn credentials_must_resolve() {
    let cfg = SmtpConfig::parse(&entry(&Json::Object(Vec::new()), 1)).unwrap();
    let err = SmtpRelay::with_credentials(
        cfg,
        String::new(),
        PASS.into(),
        Arc::new(MemorySink::default()),
        &RelaySettings::default(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        "smtp relay test-smtp: credentials not resolved (user_source='env:TEST_SMTP_USER', password_source='env:TEST_SMTP_PASS')"
    );
    let e =
        yaml(&json::parse(r#"{"name": "x", "auth": {"user_source": "cmd:pass show"}}"#).unwrap());
    assert_eq!(
        SmtpRelay::new(
            &e,
            Arc::new(MemorySink::default()),
            &RelaySettings::default()
        )
        .unwrap_err(),
        "unsupported relay credential source: 'cmd:pass show'"
    );
}
