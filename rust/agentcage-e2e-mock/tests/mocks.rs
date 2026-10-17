//! The mocks over real sockets, asserting the exact bytes and fields the
//! e2e phase scripts depend on.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use agentcage_e2e_mock::log::LogDir;
use agentcage_e2e_mock::{httpbin, imap, llm, serve_forever, smtp, tls, ws};
use serde_json::{Value, json};
use sha2::Digest as _;

/// Serve `handler` on an ephemeral loopback port; return the address.
fn spawn<F>(handler: F) -> String
where
    F: Fn(TcpStream) -> std::io::Result<()> + Send + Sync + Clone + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || serve_forever(&listener, handler));
    addr
}

fn connect(addr: &str) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn log_dir(name: &str) -> (Arc<LogDir>, PathBuf) {
    let dir =
        std::env::temp_dir().join(format!("agentcage-e2e-mock-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    (Arc::new(LogDir::create(&dir).unwrap()), dir)
}

fn read_log(dir: &Path, file: &str) -> String {
    std::fs::read_to_string(dir.join(file)).unwrap_or_default()
}

/// Send `raw`, read until the server closes, return status line and body.
fn http_exchange(addr: &str, raw: &str) -> (String, String) {
    let mut s = connect(addr);
    s.write_all(raw.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap();
    (head.lines().next().unwrap().to_owned(), body.to_owned())
}

#[test]
fn httpbin_answers_get_post_put_and_refuses_the_rest() {
    let addr = spawn(httpbin::handle);
    let (status, body) = http_exchange(&addr, "GET /get?a=1 HTTP/1.1\r\nHost: httpbin.org\r\n\r\n");
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert_eq!(body, r#"{"ok": true, "path": "/get?a=1", "method": "GET"}"#);
    let (status, body) = http_exchange(
        &addr,
        "POST /post HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
    );
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert_eq!(body, r#"{"ok": true, "path": "/post", "method": "POST"}"#);
    let (_, body) = http_exchange(&addr, "PUT /put HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(body, r#"{"ok": true, "path": "/put", "method": "PUT"}"#);
    let (status, _) = http_exchange(&addr, "DELETE /x HTTP/1.1\r\n\r\n");
    assert_eq!(status, "HTTP/1.1 501 Not Implemented");
    // /ws without an Upgrade header is an ordinary path.
    let (_, body) = http_exchange(&addr, "GET /ws HTTP/1.1\r\n\r\n");
    assert_eq!(body, r#"{"ok": true, "path": "/ws", "method": "GET"}"#);
}

fn masked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [0x11u8, 0x22, 0x33, 0x44];
    let mut out = vec![0x80 | opcode, 0x80 | u8::try_from(payload.len()).unwrap()];
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

#[test]
fn websocket_echo_with_digest_ping_and_close() {
    let addr = spawn(httpbin::handle);
    let mut s = connect(&addr);
    s.write_all(
        b"GET /ws?x=1 HTTP/1.1\r\nHost: httpbin.org\r\nUpgrade: WebSocket\r\n\
          Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          Sec-WebSocket-Version: 13\r\n\r\n",
    )
    .unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut head = String::new();
    loop {
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    assert!(head.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));

    s.write_all(&masked_frame(0x1, b"e2e-ws-hello")).unwrap();
    let (op, payload) = ws::read_frame(&mut r).unwrap().unwrap();
    assert_eq!(op, 0x1);
    let reply: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(reply["echo"], "e2e-ws-hello");
    // The digest as `sha256sum` prints it: lowercase hex of the bytes.
    let want: String = sha2::Sha256::digest(b"e2e-ws-hello")
        .iter()
        .fold(String::new(), |s, b| s + &format!("{b:02x}"));
    assert_eq!(reply["sha256"], want);
    assert_eq!(payload, ws::reply(b"e2e-ws-hello").as_bytes());

    s.write_all(&masked_frame(0x9, b"pp")).unwrap();
    assert_eq!(
        ws::read_frame(&mut r).unwrap().unwrap(),
        (0xA, b"pp".to_vec())
    );

    s.write_all(&masked_frame(0x8, &[0x03, 0xE8, b'b', b'y', b'e']))
        .unwrap();
    assert_eq!(
        ws::read_frame(&mut r).unwrap().unwrap(),
        (0x8, vec![0x03, 0xE8])
    );
    assert!(ws::read_frame(&mut r).unwrap().is_none());
}

#[test]
fn imap_session_and_log() {
    let (log, dir) = log_dir("imap");
    let addr = spawn(move |s| imap::handle(s, &log));
    let s = connect(&addr);
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut w = s;
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    assert_eq!(line, "* OK mock IMAP ready\r\n");
    w.write_all(b"a1 LOGIN \"u\" \"p\"\r\na2 FETCH 1 BODY[]\r\na3 LOGOUT\r\n")
        .unwrap();
    let mut rest = String::new();
    r.read_to_string(&mut rest).unwrap();
    assert_eq!(
        rest,
        format!(
            "a1 OK LOGIN completed\r\n* 1 FETCH (UID 1 BODY[] {{111}}\r\n{})\r\n\
             a2 OK FETCH completed\r\n* BYE bye\r\na3 OK LOGOUT completed\r\n",
            imap::MESSAGE
        )
    );
    assert_eq!(
        read_log(&dir, "imap.log"),
        "a1 LOGIN \"u\" \"p\"\na2 FETCH 1 BODY[]\na3 LOGOUT\n"
    );
}

fn smtp_session(addr: &str, script: &[&str], abort_after_data: Option<&str>) -> Vec<String> {
    let s = connect(addr);
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut w = s;
    let mut replies = Vec::new();
    let read_reply = |r: &mut BufReader<TcpStream>| {
        let mut all = String::new();
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap() == 0 {
                break;
            }
            all.push_str(&line);
            if line.as_bytes().get(3) == Some(&b' ') {
                break;
            }
        }
        all
    };
    replies.push(read_reply(&mut r));
    for cmd in script {
        w.write_all(format!("{cmd}\r\n").as_bytes()).unwrap();
        replies.push(read_reply(&mut r));
        if *cmd == "DATA"
            && let Some(partial) = abort_after_data
        {
            w.write_all(partial.as_bytes()).unwrap();
            return replies;
        }
    }
    replies
}

#[test]
fn smtp_delivers_complete_messages_only() {
    let (log, dir) = log_dir("smtp");
    let addr = spawn(move |s| smtp::handle(s, &log));
    let replies = smtp_session(
        &addr,
        &[
            "EHLO probe",
            "MAIL FROM:<agent@example.com>",
            "RCPT TO:<bob@example.com>",
            "DATA",
            "Subject: e2e\r\n\r\nline one\r\n..dotted\r\n.",
            "BOGUS",
            "QUIT",
        ],
        None,
    );
    assert_eq!(
        replies,
        [
            "220 mock ESMTP ready\r\n",
            "250-mock\r\n250-AUTH PLAIN LOGIN\r\n250-8BITMIME\r\n250 SIZE 10485760\r\n",
            "250 2.1.0 ok\r\n",
            "250 2.1.5 ok\r\n",
            "354 go ahead\r\n",
            "250 2.0.0 queued\r\n",
            "502 5.5.2 unknown\r\n",
            "221 2.0.0 bye\r\n",
        ]
    );
    assert_eq!(
        read_log(&dir, "smtp.jsonl"),
        "{\"from\": \"<agent@example.com>\", \"to\": [\"<bob@example.com>\"], \
         \"body\": \"Subject: e2e\\n\\nline one\\n.dotted\"}\n"
    );

    // Disconnect half way through DATA: nothing more is recorded.
    smtp_session(
        &addr,
        &["EHLO probe", "MAIL FROM:<a@b>", "RCPT TO:<c@d>", "DATA"],
        Some("Subject: e2e\r\n\r\ne2e-aborted-message\r\n"),
    );
    thread::sleep(Duration::from_millis(300));
    assert!(!read_log(&dir, "smtp.jsonl").contains("e2e-aborted-message"));
    assert!(read_log(&dir, "smtp.log").contains("MAIL FROM:<a@b>\n"));
}

#[test]
fn llm_over_http() {
    let (log, dir) = log_dir("llm");
    let addr = spawn(move |s| llm::handle(s, &log));
    let prompt = json!({"domain_requested": "example.net"}).to_string();
    let body = json!({
        "model": "stub-model",
        "tool_choice": {"type": "tool", "name": "decide"},
        "messages": [{"role": "user", "content": prompt}],
    })
    .to_string();
    let (status, resp) = http_exchange(
        &addr,
        &format!(
            "POST /v1/messages HTTP/1.1\r\nHost: x\r\nx-api-key: e2e-llm-key-27182\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    );
    assert_eq!(status, "HTTP/1.1 200 OK");
    let resp: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(resp["content"][0]["name"], "decide");
    assert_eq!(resp["content"][0]["input"]["decision"], "grant");
    let logged = read_log(&dir, "llm.jsonl");
    // The exact substrings phase 9 greps for (9.13).
    assert!(logged.contains(r#""tool": "decide""#), "{logged}");
    assert!(logged.contains(r#""domain": "example.net""#), "{logged}");
    assert!(
        logged.contains(r#""x_api_key": "e2e-llm-key-27182""#),
        "{logged}"
    );
}

#[test]
fn tls_presents_the_generated_certificate() {
    let (config, cert) = tls::server_config().unwrap();
    let addr = spawn(move |s| tls::handle(s, &config));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(tls::NAME).unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(client), name).unwrap();
    let mut stream = rustls::StreamOwned::new(conn, connect(&addr));
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: pt.e2e.test\r\n\r\n")
        .unwrap();
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    let out = String::from_utf8(out).unwrap();
    assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
    assert!(out.ends_with("\r\n\r\n{\"passthrough\": true}"), "{out}");
    let peer = stream.conn.peer_certificates().unwrap()[0].clone();
    assert_eq!(peer, cert);
    // The issuer O the cage-side probe reports (9.21), as DER bytes.
    let der = peer.as_ref();
    assert!(
        der.windows(tls::ISSUER_O.len())
            .any(|w| w == tls::ISSUER_O.as_bytes())
    );
}
