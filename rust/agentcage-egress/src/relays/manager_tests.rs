//! Relay start and reload, ported from the replaced implementation's
//! `test_addon_reload_relays_capture.py` and `test_addon_relays.py`.
//!
//! Credentials come from `env:HOME` and `env:PATH`, which every test
//! environment has: the egress resolves relay credentials by name, and
//! these tests cannot set environment variables (`set_var` is unsafe).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::audit::MemorySink;
use crate::inspect::{Action, Context, Severity, Verdict};
use crate::relays::{Line, Reader};

/// A permissive IMAP upstream: OK to LOGIN and to every command.
async fn upstream() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let (s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (r, mut w) = s.into_split();
                let mut r = Reader::new(r);
                let _ = w.write_all(b"* OK [CAPABILITY IMAP4rev1] fake\r\n").await;
                while let Ok(Line::Data(l)) = r.read_line(65536).await {
                    if l.is_empty() {
                        return;
                    }
                    let parts: Vec<&[u8]> = l.splitn(3, |&b| b == b' ').collect();
                    let cmd = parts
                        .get(1)
                        .map(|c| c.trim_ascii_end().to_ascii_uppercase())
                        .unwrap_or_default();
                    let _ = w
                        .write_all(&[parts[0], b" OK ", &cmd, b" completed\r\n"].concat())
                        .await;
                }
            });
        }
    });
    (port, task)
}

fn imap_entry(up: u16, name: &str, listen: &str, extra_policy: &str) -> String {
    format!(
        "  - name: {name}\n    type: imap\n    listen: \"{listen}\"\n    upstream: {{host: 127.0.0.1, port: {up}, tls: false}}\n    auth: {{type: imap-login, user_source: \"env:HOME\", password_source: \"env:PATH\"}}\n    policy: {{{extra_policy}}}\n"
    )
}

fn config(entries: &[String]) -> Config {
    let mut text = String::from("domains:\n  allow: [example.com]\n");
    if !entries.is_empty() {
        text.push_str("protocol_relays:\n");
        for e in entries {
            text.push_str(e);
        }
    }
    Config::parse("t", &text).unwrap()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn port_of(m: &RelayManager, name: &str) -> u16 {
    m.relay(name).unwrap().local_addr().await.unwrap().port()
}

struct Client(
    Reader<tokio::net::tcp::OwnedReadHalf>,
    tokio::net::tcp::OwnedWriteHalf,
);

impl Client {
    async fn open(port: u16) -> Self {
        let (r, w) = TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap()
            .into_split();
        let mut c = Self(Reader::new(r), w);
        assert!(c.line().await.starts_with(b"* PREAUTH"));
        c
    }

    async fn line(&mut self) -> Vec<u8> {
        match tokio::time::timeout(Duration::from_secs(5), self.0.read_line(1 << 20)).await {
            Ok(Ok(Line::Data(l))) => l,
            _ => Vec::new(),
        }
    }

    async fn tagged(&mut self, command: &[u8]) -> Vec<u8> {
        let _ = self.1.write_all(command).await;
        let tag = [command.split(|&b| b == b' ').next().unwrap(), b" "].concat();
        loop {
            let l = self.line().await;
            if l.is_empty() || l.starts_with(&tag) {
                return l;
            }
        }
    }
}

async fn select(port: u16, folder: &str) -> Vec<u8> {
    let mut c = Client::open(port).await;
    c.tagged(format!("a1 SELECT {folder}\r\n").as_bytes()).await
}

fn kinds(sink: &MemorySink, kind: &str) -> Vec<String> {
    sink.entries()
        .iter()
        .filter(|e| e.get("kind").and_then(Json::as_str) == Some(kind))
        .map(|e| crate::json::to_string(e.get("relay").unwrap()))
        .collect()
}

fn settings() -> RelaySettings {
    RelaySettings::default()
}

#[tokio::test]
async fn a_relay_added_on_reload_starts() {
    let (up, task) = upstream().await;
    let sink = Arc::new(MemorySink::default());
    let mut m = RelayManager::new(sink.clone());
    m.sync(&config(&[]), &settings()).await;
    assert!(m.relay("mail").is_none());
    m.sync(
        &config(&[imap_entry(up, "mail", "127.0.0.1:0", "")]),
        &settings(),
    )
    .await;
    let port = port_of(&m, "mail").await;
    assert!(select(port, "INBOX").await.starts_with(b"a1 OK"));
    m.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn a_removed_relay_stops_and_says_bye() {
    let (up, task) = upstream().await;
    let sink = Arc::new(MemorySink::default());
    let mut m = RelayManager::new(sink.clone());
    let keep = imap_entry(up, "keep", "127.0.0.1:0", "");
    m.sync(
        &config(&[keep.clone(), imap_entry(up, "drop", "127.0.0.1:0", "")]),
        &settings(),
    )
    .await;
    let port = port_of(&m, "drop").await;
    let mut session = Client::open(port).await;
    m.sync(&config(&[keep]), &settings()).await;
    assert!(m.relay("drop").is_none());
    assert_eq!(m.relays().len(), 1);
    assert_eq!(session.line().await, b"* BYE relay shutting down\r\n");
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    m.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn a_changed_relay_restarts_with_its_new_policy_on_the_same_port() {
    let (up, task) = upstream().await;
    let sink = Arc::new(MemorySink::default());
    let mut m = RelayManager::new(sink.clone());
    let listen = format!("127.0.0.1:{}", free_port());
    m.sync(&config(&[imap_entry(up, "mail", &listen, "")]), &settings())
        .await;
    let old = m.relay("mail").unwrap();
    let port = port_of(&m, "mail").await;
    assert!(select(port, "Trash").await.starts_with(b"a1 OK"));
    m.sync(
        &config(&[imap_entry(up, "mail", &listen, "folder_allowlist: [INBOX]")]),
        &settings(),
    )
    .await;
    let new = m.relay("mail").unwrap();
    assert!(!Arc::ptr_eq(&old, &new));
    assert!(old.local_addr().await.is_none());
    assert!(
        kinds(&sink, "relay_start_failed").is_empty(),
        "{:?}",
        sink.entries()
    );
    assert_eq!(port_of(&m, "mail").await, port);
    let reply = select(port, "Trash").await;
    assert_eq!(reply, b"a1 NO SELECT Trash not in folder_allowlist\r\n");
    m.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn an_unchanged_relay_is_not_restarted() {
    let (up, task) = upstream().await;
    let sink = Arc::new(MemorySink::default());
    let mut m = RelayManager::new(sink.clone());
    let mail = imap_entry(up, "mail", "127.0.0.1:0", "");
    m.sync(&config(std::slice::from_ref(&mail)), &settings())
        .await;
    let relay = m.relay("mail").unwrap();
    let mut session = Client::open(port_of(&m, "mail").await).await;
    m.sync(
        &config(&[mail, imap_entry(up, "other", "127.0.0.1:0", "")]),
        &settings(),
    )
    .await;
    assert!(Arc::ptr_eq(&relay, &m.relay("mail").unwrap()));
    assert!(session.tagged(b"a1 NOOP\r\n").await.starts_with(b"a1 OK"));
    assert!(m.relay("other").is_some());
    m.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn an_invalid_relay_is_audited_and_spares_the_others() {
    let (up, task) = upstream().await;
    let sink = Arc::new(MemorySink::default());
    let mut m = RelayManager::new(sink.clone());
    let good = imap_entry(up, "good", "127.0.0.1:0", "");
    m.sync(&config(std::slice::from_ref(&good)), &settings())
        .await;
    let relay = m.relay("good").unwrap();
    m.sync(
        &config(&[good, "  - {name: bad, type: imap}\n".to_owned()]),
        &settings(),
    )
    .await;
    assert_eq!(kinds(&sink, "relay_config_invalid"), [r#""bad""#]);
    let record = crate::json::to_string(&sink.entries()[0]);
    assert_eq!(
        record,
        r#"{"kind": "relay_config_invalid", "relay": "bad", "error": "protocol_relays entry requires name/type/listen (got name='bad', type='imap', listen='')"}"#
    );
    assert!(m.relay("bad").is_none());
    assert!(Arc::ptr_eq(&relay, &m.relay("good").unwrap()));
    m.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn a_relay_that_cannot_be_built_is_audited() {
    let (up, task) = upstream().await;
    let sink = Arc::new(MemorySink::default());
    let mut m = RelayManager::new(sink.clone());
    let entry = imap_entry(up, "mail", "127.0.0.1:0", "")
        .replace("env:PATH", "env:AGENTCAGE_TEST_SURELY_UNSET");
    m.sync(&config(&[entry]), &settings()).await;
    assert_eq!(kinds(&sink, "relay_init_failed"), [r#""mail""#]);
    assert_eq!(
        sink.entries()[0].get("error").and_then(Json::as_str),
        Some(
            "imap relay mail: credentials not resolved (user_source='env:HOME', password_source='env:AGENTCAGE_TEST_SURELY_UNSET')"
        )
    );
    assert!(m.relay("mail").is_none());
    m.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn a_relay_that_cannot_start_is_audited_and_retried() {
    let (up, task) = upstream().await;
    let sink = Arc::new(MemorySink::default());
    let mut m = RelayManager::new(sink.clone());
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = format!("127.0.0.1:{}", blocker.local_addr().unwrap().port());
    m.sync(&config(&[imap_entry(up, "mail", &listen, "")]), &settings())
        .await;
    assert_eq!(kinds(&sink, "relay_start_failed"), [r#""mail""#]);
    assert!(m.relay("mail").is_none());
    drop(blocker);
    // The same entry again: not "unchanged", because the failed relay was
    // forgotten.
    m.sync(&config(&[imap_entry(up, "mail", &listen, "")]), &settings())
        .await;
    assert!(m.relay("mail").unwrap().local_addr().await.is_some());
    m.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn a_duplicate_name_is_refused_and_the_first_entry_wins() {
    let (up, task) = upstream().await;
    let sink = Arc::new(MemorySink::default());
    let mut m = RelayManager::new(sink.clone());
    m.sync(
        &config(&[
            imap_entry(up, "mail", "127.0.0.1:0", ""),
            imap_entry(up, "mail", "127.0.0.1:0", "folder_allowlist: [INBOX]"),
        ]),
        &settings(),
    )
    .await;
    assert_eq!(kinds(&sink, "relay_config_invalid"), [r#""mail""#]);
    assert_eq!(
        sink.entries()[0].get("error").and_then(Json::as_str),
        Some("duplicate relay name 'mail'")
    );
    assert_eq!(m.relays().len(), 1);
    assert!(
        select(port_of(&m, "mail").await, "Trash")
            .await
            .starts_with(b"a1 OK")
    );
    m.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn a_kept_relay_follows_the_allowed_requests_flip() {
    let (up, task) = upstream().await;
    let sink = Arc::new(MemorySink::default());
    let mut m = RelayManager::new(sink.clone());
    let cfg = config(&[imap_entry(up, "mail", "127.0.0.1:0", "")]);
    m.sync(&cfg, &settings()).await;
    let mut session = Client::open(port_of(&m, "mail").await).await;
    session.tagged(b"a1 NOOP\r\n").await;
    assert!(kinds(&sink, "imap_command").is_empty());
    let on = RelaySettings {
        log_allowed: true,
        ..RelaySettings::default()
    };
    m.sync(&cfg, &on).await;
    session.tagged(b"a2 NOOP\r\n").await;
    assert_eq!(kinds(&sink, "imap_command"), [r#""mail""#]);
    m.shutdown().await;
    task.abort();
}

#[derive(Debug)]
struct BlockAll;

impl crate::inspect::Inspector for BlockAll {
    fn name(&self) -> &'static str {
        "reload-marker"
    }
    fn inspect_request(&self, _ctx: &Context) -> Option<Verdict> {
        Some(Verdict::new(
            "reload-marker",
            Action::Block,
            "marked",
            Severity::Critical,
        ))
    }
}

/// A kept SMTP relay takes the reload's chain: the next message is judged
/// by it, without a restart.
#[tokio::test]
async fn a_kept_smtp_relay_takes_the_new_chain() {
    let sink = Arc::new(MemorySink::default());
    let mut m = RelayManager::new(sink.clone());
    let entry = "  - name: out\n    type: smtp\n    listen: \"127.0.0.1:0\"\n    upstream: {host: 127.0.0.1, port: 1, tls: false}\n    auth: {user_source: \"env:HOME\", password_source: \"env:PATH\"}\n".to_owned();
    let cfg = config(&[entry]);
    m.sync(&cfg, &settings()).await;
    let relay = m.relay("out").unwrap();
    let chained = RelaySettings {
        log_allowed: false,
        inspectors: vec![Arc::new(BlockAll) as Arc<dyn crate::inspect::Inspector>].into(),
    };
    m.sync(&cfg, &chained).await;
    assert!(Arc::ptr_eq(&relay, &m.relay("out").unwrap()));
    let port = relay.local_addr().await.unwrap().port();
    let (r, mut w) = TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap()
        .into_split();
    let mut r = Reader::new(r);
    w.write_all(b"EHLO x\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<d@e.f>\r\nDATA\r\nhi\r\n.\r\n")
        .await
        .unwrap();
    let mut last = Vec::new();
    for _ in 0..12 {
        match tokio::time::timeout(Duration::from_secs(5), r.read_line(65536)).await {
            Ok(Ok(Line::Data(l))) if !l.is_empty() => last = l,
            _ => break,
        }
        if last.starts_with(b"550") {
            break;
        }
    }
    assert_eq!(last, b"550 5.7.0 marked\r\n");
    m.shutdown().await;
}

#[test]
fn the_credentials_digest_is_over_the_resolved_values() {
    use sha2::{Digest, Sha256};
    let entry = crate::config::Config::parse(
        "t",
        "name: x\nauth: {user_source: \"env:HOME\", password_source: \"env:PATH\"}\n",
    )
    .unwrap();
    let home = std::env::var("HOME").unwrap();
    let path = std::env::var("PATH").unwrap();
    let want = crate::relays::testkit::hex(&Sha256::digest(format!("{home}\0{path}").as_bytes()));
    assert_eq!(credentials_digest(entry.raw()), want);
    // A refused scheme contributes "" rather than failing the reload.
    let refused = crate::config::Config::parse("t", "auth: {user_source: \"cmd:x\"}\n").unwrap();
    let empty = crate::relays::testkit::hex(&Sha256::digest(b"\0"));
    assert_eq!(credentials_digest(refused.raw()), empty);
}
