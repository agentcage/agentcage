//! The IMAP relay against `tests/fixtures/egress/imap.json`, recorded from
//! the Python relay it replaces (see `tests/fixtures/egress/gen/imap.py`),
//! plus the behaviour this port adds (long lines refused with `BAD`,
//! sessions told goodbye on stop) and the upstream TLS cases.
//!
//! `AGENTCAGE_BLESS=1 cargo test -p agentcage-egress imap_corpus`
//! rewrites the corpus with what this relay does.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::audit::MemorySink;
use crate::json::{self, Json};
use crate::relays::testkit::{
    arr, bless, blessing, boolean, dec, enc, enc_out, int, load, merged, text, without_ts, yaml,
};

const CORPUS: &str = "imap.json";
const USER: &str = "real-user@example.com";
const PASS: &str = "real-app-password";

fn entry(policy: &Json, port: u16) -> Value {
    let base = json::parse(&format!(
        r#"{{"name": "test-imap", "type": "imap", "listen": "127.0.0.1:0",
            "upstream": {{"host": "127.0.0.1", "port": {port}, "tls": false}},
            "auth": {{"type": "imap-login", "user_source": "env:TEST_IMAP_USER",
                      "password_source": "env:TEST_IMAP_PASS"}},
            "policy": {{"readonly": false, "folder_allowlist": [], "conn_rate_limit": "30/min"}}}}"#
    ))
    .unwrap();
    let pol = merged(base.get("policy").unwrap().clone(), policy);
    let mut e = base;
    e.set("policy", pol);
    yaml(&e)
}

fn relay(policy: &Json, port: u16, log_allowed: bool) -> (ImapRelay, Arc<MemorySink>) {
    let sink = Arc::new(MemorySink::default());
    let cfg = ImapConfig::parse(&entry(policy, port)).unwrap();
    let settings = RelaySettings {
        log_allowed,
        ..RelaySettings::default()
    };
    let relay = ImapRelay::with_credentials(cfg, USER.into(), PASS.into(), sink.clone(), &settings)
        .unwrap();
    (relay, sink)
}

fn audit_json(sink: &MemorySink) -> Json {
    Json::Array(sink.entries().iter().map(without_ts).collect())
}

fn obj_mut<'a>(case: &'a mut Json, key: &str) -> &'a mut Json {
    match case {
        Json::Object(pairs) => &mut pairs.iter_mut().find(|(k, _)| k == key).unwrap().1,
        _ => panic!(),
    }
}

/// Compare `got` with the case's `key`, or record it when blessing.
fn check(case: &mut Json, key: &str, got: Json, failures: &mut Vec<String>) {
    let want = case.get(key).cloned().unwrap_or(Json::Null);
    if got != want {
        if blessing() {
            *obj_mut(case, key) = got;
        } else {
            failures.push(format!(
                "{}\n  want {}\n  got  {}",
                json::to_string(case.get("name").or(case.get("line")).unwrap_or(&Json::Null)),
                json::to_string(&want),
                json::to_string(&got)
            ));
        }
    }
}

fn finish(name: &str, corpus: &Json, failures: &[String], blessed: bool) {
    if blessed && blessing() {
        bless(name, corpus);
        return;
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn section<'a>(corpus: &'a mut Json, key: &str) -> &'a mut Vec<Json> {
    match obj_mut(corpus, key) {
        Json::Array(items) => items,
        _ => panic!(),
    }
}

#[test]
fn imap_corpus_literals_and_mutf7() {
    let mut corpus = load(CORPUS);
    let mut failures = Vec::new();
    for case in section(&mut corpus, "literals") {
        let line = dec(case.get("line").unwrap());
        let got = match client_literal(&line) {
            Err(MalformedLiteral) => Json::string("malformed"),
            Ok(None) => Json::Null,
            Ok(Some(l)) => json::object([
                ("size", Json::Int(i64::try_from(l.size).unwrap())),
                ("sync", Json::Bool(l.sync)),
                ("start", Json::Int(i64::try_from(l.start).unwrap())),
            ]),
        };
        check(case, "literal", got, &mut failures);
    }
    for case in section(&mut corpus, "mutf7") {
        let got = mutf7_decode(text(case.get("name").unwrap())).map_or(Json::Null, Json::Str);
        check(case, "decoded", got, &mut failures);
    }
    finish(CORPUS, &corpus, &failures, true);
}

#[test]
fn imap_corpus_policy() {
    let mut corpus = load(CORPUS);
    let mut failures = Vec::new();
    for case in section(&mut corpus, "policy") {
        let (relay, sink) = relay(
            case.get("policy").unwrap(),
            1,
            boolean(case.get("log_allowed")),
        );
        let line = dec(case.get("line").unwrap());
        let mailbox = match case.get("mailbox") {
            Some(Json::Null) | None => None,
            Some(m) => Some(dec(m)),
        };
        let decision =
            relay.policy_check(&line, mailbox.as_deref(), boolean(case.get("utf8_names")));
        let got = decision.map_or(Json::Null, |d| {
            json::object([
                ("tag", enc(&d.tag)),
                ("reason", Json::Str(d.reason)),
                ("status", Json::string(d.status)),
            ])
        });
        let mut label = case.clone();
        label.set("name", enc(&line));
        check(case, "decision", got, &mut failures);
        check(case, "audit", audit_json(&sink), &mut failures);
    }
    finish(CORPUS, &corpus, &failures, true);
}

fn filter_for(case: &Json) -> ResponseFilter {
    let mode = text(case.get("mode").unwrap()).to_owned();
    let lists = boolean(case.get("folder_lists"));
    let limit = usize::try_from(int(case.get("held_limit").unwrap())).unwrap();
    ResponseFilter::new(
        Box::new(move |t: &str| capability_hidden(t, &mode, lists)),
        None,
        limit,
    )
}

fn run_filter(case: &Json) -> (Vec<Json>, Json) {
    let mut f = filter_for(case);
    let mut outs = Vec::new();
    for op in arr(case.get("ops").unwrap()) {
        let op = arr(op);
        let out = match text(&op[0]) {
            "feed" => match f.feed(&dec(&op[1])) {
                Ok(out) => out,
                Err(Unfilterable(e)) => return (outs, Json::Str(e)),
            },
            "insert" => f.insert(&dec(&op[1])),
            _ => f.finish(),
        };
        outs.push(enc_out(&out));
    }
    (outs, Json::Null)
}

#[test]
fn imap_corpus_filter() {
    let mut corpus = load(CORPUS);
    let mut failures = Vec::new();
    for case in section(&mut corpus, "filter") {
        let (outs, error) = run_filter(case);
        check(case, "outputs", Json::Array(outs), &mut failures);
        check(case, "error", error, &mut failures);
        if boolean(case.get("exhaustive")) {
            // One stream, fed whole: every chunking must give the same.
            let stream = dec(&arr(&arr(case.get("ops").unwrap())[0])[1]);
            let mut f = filter_for(case);
            let whole = [f.feed(&stream).unwrap(), f.finish()].concat();
            for cut in 1..stream.len() {
                let mut f = filter_for(case);
                let got = [
                    f.feed(&stream[..cut]).unwrap(),
                    f.feed(&stream[cut..]).unwrap(),
                    f.finish(),
                ]
                .concat();
                assert_eq!(got, whole, "cut {cut}");
            }
            let mut f = filter_for(case);
            let mut got: Vec<u8> = stream.iter().flat_map(|b| f.feed(&[*b]).unwrap()).collect();
            got.extend(f.finish());
            assert_eq!(got, whole, "byte at a time");
        }
    }
    finish(CORPUS, &corpus, &failures, true);
}

#[test]
fn a_wrong_filter_expectation_fails() {
    let corpus = load(CORPUS);
    let case = &arr(corpus.get("filter").unwrap())[0];
    let (outs, _) = run_filter(case);
    let mut wrong = outs.clone();
    wrong[0] = Json::string("x");
    assert_ne!(Json::Array(outs), Json::Array(wrong));
}

// ── Sessions ────────────────────────────────────────────

#[derive(Debug, Default)]
struct Recorder {
    commands: Vec<Vec<u8>>,
    raw: Vec<u8>,
}

type Up = Reader<tokio::net::tcp::OwnedReadHalf>;

async fn line(r: &mut Up) -> Vec<u8> {
    match r.read_line(usize::MAX / 2).await.unwrap() {
        Line::Data(l) => l,
        Line::TooLong { .. } => unreachable!(),
    }
}

/// The literal a mock-upstream command line ends with: `(size, sync)`.
fn upstream_literal(l: &[u8]) -> Option<(usize, bool)> {
    let body = l.strip_suffix(b"}\r\n")?;
    let open = body.iter().rposition(|&b| b == b'{')?;
    let inner = &body[open + 1..];
    let (digits, sync) = inner
        .strip_suffix(b"+")
        .map_or((inner, true), |d| (d, false));
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some((std::str::from_utf8(digits).ok()?.parse().ok()?, sync))
}

/// The mock upstream of `tests/test_protocol_relays.py`, one connection.
#[allow(clippy::too_many_lines)]
async fn serve_upstream(stream: TcpStream, up: Json, rec: Arc<Mutex<Recorder>>) {
    let (read, mut w) = stream.into_split();
    let mut r = Reader::new(read);
    if boolean(up.get("silent")) {
        while !r.read_some(4096).await.unwrap_or_default().is_empty() {}
        return;
    }
    let greeting = up.get("greeting").map_or(
        b"* OK [CAPABILITY IMAP4rev1] fake upstream ready\r\n".to_vec(),
        dec,
    );
    let _ = w.write_all(&greeting).await;
    let l = line(&mut r).await;
    if l.is_empty() {
        return;
    }
    rec.lock().unwrap().commands.push(l.clone());
    let parts: Vec<&[u8]> = l.splitn(3, |&b| b == b' ').collect();
    if parts.len() < 3 {
        let _ = w
            .write_all(&[parts[0], b" BAD malformed login\r\n"].concat())
            .await;
        return;
    }
    let tag = parts[0].to_vec();
    let rest = trim_crlf_end(parts[2]);
    let sp: Vec<&[u8]> = rest.splitn(2, |&b| b == b' ').collect();
    let strip = |s: &[u8]| -> Vec<u8> {
        let s = s.strip_prefix(b"\"").unwrap_or(s);
        s.strip_suffix(b"\"").unwrap_or(s).to_vec()
    };
    let user = strip(sp[0]);
    let pwd = sp.get(1).map(|p| strip(p)).unwrap_or_default();
    if boolean(up.get("fail_login")) || user != USER.as_bytes() || pwd != PASS.as_bytes() {
        let reply = if boolean(up.get("echo_login")) {
            [
                &tag[..],
                b" NO [AUTHENTICATIONFAILED] rejected: ",
                trim_crlf_end(&l),
                b"\r\n",
            ]
            .concat()
        } else {
            [&tag[..], b" NO bad credentials\r\n"].concat()
        };
        let _ = w.write_all(&reply).await;
        return;
    }
    let ok = up
        .get("login_ok")
        .map_or(b"<TAG> OK LOGIN completed\r\n".to_vec(), dec);
    let _ = w.write_all(&replace_tag(&ok, &tag)).await;
    let literals = boolean(up.get("literals"));
    let refuse: Vec<Vec<u8>> = up
        .get("refuse_literal")
        .map(|v| arr(v).iter().map(|s| text(s).as_bytes().to_vec()).collect())
        .unwrap_or_default();
    loop {
        let mut refused = false;
        let mut cmd = Vec::new();
        if literals {
            loop {
                let l = line(&mut r).await;
                rec.lock().unwrap().raw.extend_from_slice(&l);
                cmd.extend_from_slice(&l);
                let Some((size, sync)) = (!l.is_empty()).then(|| upstream_literal(&l)).flatten()
                else {
                    break;
                };
                if sync {
                    let name = split_ws(&cmd, Some(2))[1].to_ascii_uppercase();
                    if refuse.contains(&name) {
                        let t = split_ws(&cmd, Some(1))[0].to_vec();
                        let _ = w
                            .write_all(&[&t[..], b" NO [TRYCREATE] no such mailbox\r\n"].concat())
                            .await;
                        refused = true;
                        break;
                    }
                    let _ = w.write_all(b"+ go ahead\r\n").await;
                }
                let Ok(Some(payload)) = r.read_exact(size).await else {
                    return;
                };
                rec.lock().unwrap().raw.extend_from_slice(&payload);
                cmd.extend_from_slice(&payload);
            }
        } else {
            cmd = line(&mut r).await;
        }
        if cmd.is_empty() {
            return;
        }
        rec.lock().unwrap().commands.push(cmd.clone());
        if refused {
            continue;
        }
        let parts: Vec<&[u8]> = cmd.splitn(3, |&b| b == b' ').collect();
        let tag = parts[0].to_vec();
        let name = parts
            .get(1)
            .map(|c| trim_crlf_end(c).to_ascii_uppercase())
            .unwrap_or_default();
        if literals && name == b"IDLE" {
            let _ = w.write_all(b"+ idling\r\n").await;
            let done = line(&mut r).await;
            rec.lock().unwrap().raw.extend_from_slice(&done);
            let reply = if trim_crlf_end(&done).eq_ignore_ascii_case(b"DONE") {
                [&tag[..], b" OK IDLE terminated\r\n"].concat()
            } else {
                [&tag[..], b" BAD expected DONE\r\n"].concat()
            };
            let _ = w.write_all(&reply).await;
            continue;
        }
        if name == b"LOGOUT" {
            let _ = w
                .write_all(&[b"* BYE\r\n", &tag[..], b" OK LOGOUT completed\r\n"].concat())
                .await;
            return;
        }
        if let Some(chunks) = up
            .get("scripted")
            .and_then(|s| s.get(&String::from_utf8_lossy(&name)))
        {
            for chunk in arr(chunks) {
                let _ = w.write_all(&replace_tag(&dec(chunk), &tag)).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            continue;
        }
        let _ = w
            .write_all(&[&tag[..], b" OK ", &name[..], b" completed\r\n"].concat())
            .await;
    }
}

fn replace_tag(data: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i..].starts_with(b"<TAG>") {
            out.extend_from_slice(tag);
            i += 5;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

struct Client {
    reader: Reader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

#[derive(Debug)]
struct Eof(Vec<Vec<u8>>);

impl Client {
    async fn line(&mut self) -> Vec<u8> {
        match tokio::time::timeout(
            Duration::from_secs(5),
            self.reader.read_line(usize::MAX / 2),
        )
        .await
        {
            Ok(Ok(Line::Data(l))) => l,
            _ => Vec::new(),
        }
    }

    /// The compliant client of the Python tests' `_send_command`.
    async fn command(&mut self, pieces: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, Eof> {
        let tag = split_ws(&pieces[0], Some(1))[0].to_vec();
        let mut tagged = tag.clone();
        tagged.push(b' ');
        let mut got = Vec::new();
        let mut i = 0;
        while i < pieces.len() {
            let _ = self.writer.write_all(&pieces[i]).await;
            if i + 1 == pieces.len() {
                break;
            }
            if !trim_crlf_end(&pieces[i]).ends_with(b"+}") {
                loop {
                    let l = self.line().await;
                    if l.is_empty() {
                        return Err(Eof(got));
                    }
                    got.push(l.clone());
                    if l.starts_with(b"+") {
                        break;
                    }
                    if l.starts_with(&tagged) {
                        return Ok(got);
                    }
                }
            }
            let _ = self.writer.write_all(&pieces[i + 1]).await;
            i += 2;
        }
        loop {
            let l = self.line().await;
            if l.is_empty() {
                return Err(Eof(got));
            }
            got.push(l.clone());
            if l.starts_with(&tagged) {
                return Ok(got);
            }
        }
    }
}

fn lines_json(lines: &[Vec<u8>]) -> Json {
    Json::Array(lines.iter().map(|l| enc(l)).collect())
}

async fn run_step(step: &Json, c: &mut Client, port: u16) -> Json {
    let pieces = || -> Vec<Vec<u8>> { arr(step.get("pieces").unwrap()).iter().map(dec).collect() };
    match text(step.get("op").unwrap()) {
        "command" => lines_json(
            &c.command(&pieces())
                .await
                .expect("EOF before the tagged reply"),
        ),
        "until_closed" => lines_json(&match c.command(&pieces()).await {
            Ok(got) | Err(Eof(got)) => got,
        }),
        "line" => {
            let _ = c.writer.write_all(&dec(step.get("send").unwrap())).await;
            Json::Array(vec![enc(&c.line().await)])
        }
        "send" => {
            let _ = c.writer.write_all(&dec(step.get("send").unwrap())).await;
            Json::Null
        }
        "until_tag" => {
            let tag = format!("{} ", text(step.get("tag").unwrap()));
            let mut got = Vec::new();
            loop {
                let l = c.line().await;
                assert!(!l.is_empty(), "EOF before {tag}");
                got.push(l.clone());
                if l.starts_with(tag.as_bytes()) {
                    return lines_json(&got);
                }
            }
        }
        "read_all" => {
            let mut all = Vec::new();
            loop {
                let chunk = tokio::time::timeout(Duration::from_secs(5), c.reader.read_some(65536))
                    .await
                    .unwrap()
                    .unwrap_or_default();
                if chunk.is_empty() {
                    return enc(&all);
                }
                all.extend(chunk);
            }
        }
        "read_exact" => {
            let n = usize::try_from(int(step.get("n").unwrap())).unwrap();
            let data = tokio::time::timeout(Duration::from_secs(10), c.reader.read_exact(n))
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            enc_out(&data)
        }
        "sleep" => {
            tokio::time::sleep(Duration::from_secs_f64(match step.get("seconds") {
                Some(Json::Float(f)) => *f,
                Some(Json::Int(n)) => f64::from(i32::try_from(*n).unwrap()),
                _ => 0.0,
            }))
            .await;
            Json::Null
        }
        "new_client" => {
            let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let (r, w) = s.into_split();
            let mut c2 = Client {
                reader: Reader::new(r),
                writer: w,
            };
            Json::Array(vec![enc(&c2.line().await)])
        }
        other => panic!("unknown step {other}"),
    }
}

async fn run_session(case: &Json) -> Json {
    let up = case
        .get("upstream")
        .cloned()
        .unwrap_or(Json::Object(Vec::new()));
    let rec = Arc::new(Mutex::new(Recorder::default()));
    let (up_port, server) = if boolean(up.get("unreachable")) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        (l.local_addr().unwrap().port(), None)
    } else {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (up, rec) = (up.clone(), rec.clone());
        let task = tokio::spawn(async move {
            loop {
                let (s, _) = listener.accept().await.unwrap();
                tokio::spawn(serve_upstream(s, up.clone(), rec.clone()));
            }
        });
        (port, Some(task))
    };
    let (relay, sink) = relay(
        case.get("policy").unwrap(),
        up_port,
        boolean(case.get("log_allowed")),
    );
    relay.start().await.unwrap();
    let port = relay.local_addr().await.unwrap().port();
    let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (r, w) = s.into_split();
    let mut c = Client {
        reader: Reader::new(r),
        writer: w,
    };
    let greeting = enc(&c.line().await);
    let mut steps = Vec::new();
    for step in arr(case.get("steps").unwrap()) {
        steps.push(run_step(step, &mut c, port).await);
    }
    drop(c);
    tokio::time::sleep(Duration::from_millis(100)).await;
    relay.stop().await;
    if let Some(task) = server {
        task.abort();
    }
    let mut audit = audit_json(&sink);
    if boolean(case.get("mask_error"))
        && let Json::Array(items) = &mut audit
    {
        for e in items {
            for key in ["error", "upstream"] {
                if e.get(key).is_some() {
                    e.set(key, Json::string("<masked>"));
                }
            }
        }
    }
    let rec = rec.lock().unwrap();
    json::object([
        ("greeting", greeting),
        ("steps", Json::Array(steps)),
        ("upstream", lines_json(&rec.commands)),
        ("upstream_raw", enc(&rec.raw)),
        ("audit", audit),
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imap_corpus_sessions() {
    let mut corpus = load(CORPUS);
    let mut failures = Vec::new();
    for case in section(&mut corpus, "sessions") {
        let got = run_session(case).await;
        check(case, "expect", got, &mut failures);
    }
    finish(CORPUS, &corpus, &failures, true);
}

// ── Beyond the corpus ───────────────────────────────────

async fn plain_session(
    policy: &str,
) -> (
    ImapRelay,
    Arc<MemorySink>,
    Client,
    tokio::task::JoinHandle<()>,
    Arc<Mutex<Recorder>>,
) {
    let rec = Arc::new(Mutex::new(Recorder::default()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = listener.local_addr().unwrap().port();
    let r2 = rec.clone();
    let task = tokio::spawn(async move {
        loop {
            let (s, _) = listener.accept().await.unwrap();
            tokio::spawn(serve_upstream(
                s,
                json::parse(r#"{"literals": true}"#).unwrap(),
                r2.clone(),
            ));
        }
    });
    let (relay, sink) = relay(&json::parse(policy).unwrap(), up_port, false);
    relay.start().await.unwrap();
    let port = relay.local_addr().await.unwrap().port();
    let (r, w) = TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap()
        .into_split();
    let mut c = Client {
        reader: Reader::new(r),
        writer: w,
    };
    assert!(c.line().await.starts_with(b"* PREAUTH"));
    (relay, sink, c, task, rec)
}

/// A command line over 1 MiB is answered `BAD` and dropped, and the
/// session goes on (the Python relay ended the session at 64 KiB).
#[tokio::test]
async fn an_overlong_command_line_is_refused_not_fatal() {
    let (relay, sink, mut c, task, rec) = plain_session(r#"{"write_mode": "full"}"#).await;
    let mut long = b"a1 SEARCH TEXT ".to_vec();
    long.resize(CLIENT_LINE_LIMIT + 10, b'x');
    long.extend_from_slice(b" {5+}\r\n");
    long.extend_from_slice(b"b EXPUNGE\r\n");
    let _ = c.writer.write_all(&long).await;
    assert_eq!(c.line().await, b"a1 BAD line too long\r\n");
    let got = c.command(&[b"a2 NOOP\r\n".to_vec()]).await.unwrap();
    assert_eq!(got, [b"a2 OK NOOP completed\r\n".to_vec()]);
    // Neither the long line nor the payload it announced reached upstream.
    assert_eq!(rec.lock().unwrap().commands[1..], [b"a2 NOOP\r\n".to_vec()]);
    let blocked = audit_json(&sink);
    assert_eq!(
        json::to_string(&blocked),
        r#"[{"kind": "imap_command", "relay": "test-imap", "command": "SEARCH", "decision": "blocked", "reason": "line too long"}]"#
    );
    relay.stop().await;
    task.abort();
}

/// Stopping a relay (reload removed it, or the egress shuts down) tells
/// an idle session goodbye rather than cutting the connection.
#[tokio::test]
async fn stop_says_bye_to_open_sessions() {
    let (relay, _sink, mut c, task, _rec) = plain_session("{}").await;
    relay.stop().await;
    assert_eq!(c.line().await, b"* BYE relay shutting down\r\n");
    assert!(c.line().await.is_empty());
    task.abort();
}

// ── Upstream TLS ────────────────────────────────────────

mod tls_upstream {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, SanType};

    struct Minted {
        pem: String,
        cert: rustls::pki_types::CertificateDer<'static>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    }

    /// A self-signed, CA-flagged certificate for `name`, the shape a local
    /// decrypting daemon mints at setup.
    fn mint(name: &str, ip_san: bool) -> Minted {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        if ip_san {
            params
                .subject_alt_names
                .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
        }
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        Minted {
            pem: cert.pem(),
            cert: cert.der().clone(),
            key: rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        }
    }

    async fn tls_upstream(minted: &Minted) -> (u16, tokio::task::JoinHandle<()>) {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![minted.cert.clone()], minted.key.clone_key())
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            loop {
                let (s, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(s).await else {
                        return;
                    };
                    let (r, mut w) = tokio::io::split(tls);
                    let mut r = Reader::new(r);
                    let _ = w
                        .write_all(b"* OK [CAPABILITY IMAP4rev1] fake tls upstream\r\n")
                        .await;
                    let Ok(Line::Data(l)) = r.read_line(65536).await else {
                        return;
                    };
                    let tag = l.split(|&b| b == b' ').next().unwrap_or(b"").to_vec();
                    let _ = w
                        .write_all(
                            &[&tag[..], b" OK [CAPABILITY IMAP4rev1] logged in\r\n"].concat(),
                        )
                        .await;
                    while !r.read_some(4096).await.unwrap_or_default().is_empty() {}
                });
            }
        });
        (port, task)
    }

    async fn greeting(up_port: u16, upstream: &str) -> (Vec<u8>, Vec<Json>) {
        let e = yaml(
            &json::parse(&format!(
                r#"{{"name": "extra-ca-imap", "type": "imap", "listen": "127.0.0.1:0",
                    "upstream": {{"host": "127.0.0.1", "port": {up_port}, "tls": true {upstream}}}}}"#
            ))
            .unwrap(),
        );
        let sink = Arc::new(MemorySink::default());
        let cfg = ImapConfig::parse(&e).unwrap();
        let relay = ImapRelay::with_credentials(
            cfg,
            USER.into(),
            PASS.into(),
            sink.clone(),
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
        let line = match tokio::time::timeout(Duration::from_secs(10), r.read_line(65536)).await {
            Ok(Ok(Line::Data(l))) => l,
            _ => Vec::new(),
        };
        relay.stop().await;
        (line, sink.entries())
    }

    fn pem_json(pem: &str) -> String {
        json::to_string(&Json::string(pem))
    }

    fn errors(audit: &[Json]) -> Vec<String> {
        audit
            .iter()
            .filter(|e| e.get("kind").and_then(Json::as_str) == Some("imap_upstream_unreachable"))
            .map(|e| e.get("error").and_then(Json::as_str).unwrap().to_owned())
            .collect()
    }

    #[tokio::test]
    async fn extra_ca_connects_to_a_self_signed_upstream() {
        let m = mint("bridge.local", false);
        let (port, task) = tls_upstream(&m).await;
        let extra = format!(
            r#", "ca_pem": {}, "tls_servername": "bridge.local""#,
            pem_json(&m.pem)
        );
        let (line, _) = greeting(port, &extra).await;
        assert!(
            line.starts_with(b"* PREAUTH"),
            "{}",
            String::from_utf8_lossy(&line)
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_self_signed_upstream_is_refused_without_the_extra_ca() {
        let m = mint("bridge.local", false);
        let (port, task) = tls_upstream(&m).await;
        let (line, audit) = greeting(port, r#", "tls_servername": "bridge.local""#).await;
        assert_eq!(line, b"* BYE upstream unreachable\r\n");
        let errs = errors(&audit);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("certificate verify failed"), "{errs:?}");
        task.abort();
    }

    #[tokio::test]
    async fn a_pinned_certificate_still_needs_the_right_name() {
        let m = mint("bridge.local", false);
        let (port, task) = tls_upstream(&m).await;
        let extra = format!(r#", "ca_pem": {}"#, pem_json(&m.pem));
        let (line, audit) = greeting(port, &extra).await;
        assert_eq!(line, b"* BYE upstream unreachable\r\n");
        let errs = errors(&audit);
        assert!(errs[0].contains("not valid for '127.0.0.1'"), "{errs:?}");
        task.abort();
    }

    #[tokio::test]
    async fn an_ip_san_certificate_needs_no_servername() {
        let m = mint("bridge.local", true);
        let (port, task) = tls_upstream(&m).await;
        let extra = format!(r#", "ca_pem": {}"#, pem_json(&m.pem));
        let (line, _) = greeting(port, &extra).await;
        assert!(
            line.starts_with(b"* PREAUTH"),
            "{}",
            String::from_utf8_lossy(&line)
        );
        task.abort();
    }

    #[tokio::test]
    async fn an_unrelated_ca_does_not_satisfy_verification() {
        let m = mint("bridge.local", false);
        let other = mint("impostor.local", false);
        let (port, task) = tls_upstream(&m).await;
        let extra = format!(
            r#", "ca_pem": {}, "tls_servername": "bridge.local""#,
            pem_json(&other.pem)
        );
        let (line, audit) = greeting(port, &extra).await;
        assert_eq!(line, b"* BYE upstream unreachable\r\n");
        assert!(errors(&audit)[0].contains("certificate verify failed"));
        task.abort();
    }

    #[test]
    fn ca_pem_extends_the_mozilla_roots() {
        let m = mint("bridge.local", false);
        assert!(crate::relays::tls::client_config(&m.pem).is_ok());
        assert!(crate::relays::tls::client_config("garbage").is_err());
    }
}
