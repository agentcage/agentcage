//! SMTP relay: a stateful TCP proxy that holds the upstream password,
//! authenticates on the cage's behalf, gates senders and recipients, and
//! runs the egress's inspector chain on every `DATA` payload before
//! forwarding it.
//!
//! Without it, an SMTP-able cage is a wide-open exfiltration channel. The
//! relay closes it with `recipient_allowlist` (`RCPT TO` denied unless the
//! address or its domain matches), `sender_allowlist`, the inspector chain
//! over the assembled message (a leaked API key in a mail body blocks the
//! message), and size, recipient and rate caps.
//!
//! The relay-side state machine:
//!
//! ```text
//! CONNECT         -> 220 greeting
//! EHLO/HELO       -> 250 capability list (no STARTTLS)
//! AUTH PLAIN/...  -> 235 (forged; the relay authenticates upstream)
//! MAIL FROM:<a>   -> sender_allowlist; 250 / 550
//! RCPT TO:<a>     -> recipient_allowlist; per recipient 250 / 550
//! DATA            -> 354; body to "\r\n.\r\n"; size cap, inspectors,
//!                    then delivered upstream
//! RSET            -> 250; transaction cleared
//! NOOP / VRFY     -> 250 / 252
//! QUIT            -> 221; close
//! ```
//!
//! The upstream connection is opened lazily, on the first message that
//! passes policy, and reused for the rest of the session; it
//! authenticates once with `AUTH PLAIN`. Upstream TLS is implicit (port
//! 465) or none; there is no STARTTLS.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

use super::imap::{entry_mapping, mapping_or_empty, parse_upstream, py_list};
use super::{
    Line, Listener, RateLimiter, Reader, RelaySettings, SessionError, Upstream, audit, bytes_repr,
    relay_log, s,
};
use crate::audit::AuditSink;
use crate::config::{Mapping, Value};
use crate::inspect::{Action, Context, Inspector, Phase, Verdict, run_chain, shannon_entropy};
use crate::json::Json;
use agentcage_core::python::{repr_str, type_name};

const LOGGER: &str = "agentcage.relays.smtp";

/// Inspectors skipped when every recipient is on the allowlist, unless
/// the policy names its own set.
const DEFAULT_BYPASS: &[&str] = &["secrets", "entropy", "content-type"];

// ── Config ──────────────────────────────────────────────

/// The relay's view of its `protocol_relays` entry.
#[derive(Clone, Debug)]
pub(crate) struct SmtpConfig {
    pub(crate) name: String,
    pub(crate) listen: String,
    pub(crate) upstream: Upstream,
    pub(crate) user_source: String,
    pub(crate) password_source: String,
    pub(crate) sender_allowlist: Vec<String>,
    pub(crate) recipient_addresses: Vec<String>,
    pub(crate) recipient_domains: Vec<String>,
    pub(crate) max_message_bytes: i64,
    pub(crate) max_recipients: i64,
    pub(crate) conn_rate_limit: String,
    pub(crate) send_rate_limit: String,
    pub(crate) idle_timeout_seconds: i64,
    pub(crate) bypass: Vec<String>,
}

/// `[s.lower() for s in (value or [])]`.
fn lowered(value: Option<&Value>) -> Result<Vec<String>, String> {
    let Some(v) = value.filter(|v| agentcage_core::yaml::python_bool(v)) else {
        return Ok(Vec::new());
    };
    let items: Vec<&Value> = match v {
        Value::Sequence(items) => items.iter().collect(),
        Value::Mapping(m) => m.keys().collect(),
        Value::String(text) => {
            return Ok(text.chars().map(|c| c.to_lowercase().collect()).collect());
        }
        other => return Err(format!("'{}' object is not iterable", type_name(other))),
    };
    items
        .into_iter()
        .map(|item| match item {
            Value::String(text) => Ok(text.to_lowercase()),
            other => Err(format!(
                "'{}' object has no attribute 'lower'",
                type_name(other)
            )),
        })
        .collect()
}

impl SmtpConfig {
    pub(crate) fn parse(entry: &Value) -> Result<Self, String> {
        let entry = entry_mapping(entry)?;
        let name = super::str_or(entry.get("name"), "");
        let listen = super::str_or(entry.get("listen"), "");
        let upstream = parse_upstream(entry)?;
        let auth = mapping_or_empty(entry.get("auth"))?;
        let policy = mapping_or_empty(entry.get("policy"))?;
        let pget = |key: &str| policy.and_then(|p| p.get(key));
        // A bare list is shorthand for `{addresses: [...]}`.
        let rcpt = match pget("recipient_allowlist") {
            Some(Value::Sequence(items)) if !items.is_empty() => {
                let mut m = Mapping::new();
                m.insert(
                    Value::String("addresses".into()),
                    Value::Sequence(items.clone()),
                );
                Some(m)
            }
            other => mapping_or_empty(other)?.cloned(),
        };
        let rget = |key: &str| rcpt.as_ref().and_then(|r| r.get(key));
        let sender_allowlist = lowered(pget("sender_allowlist"))?;
        let recipient_addresses = lowered(rget("addresses"))?;
        let recipient_domains = lowered(rget("domains"))?;
        let int_or = |key: &str, default: i64| match pget(key) {
            Some(v) => super::py_int(v),
            None => Ok(default),
        };
        let max_message_bytes = int_or("max_message_bytes", 5_242_880)?;
        let max_recipients = int_or("max_recipients", 10)?;
        let conn_rate_limit = super::str_or(pget("conn_rate_limit"), "30/min");
        let send_rate_limit = super::str_or(pget("send_rate_limit"), "20/hour");
        // One per-read idle timeout for every line (RFC 5321 §4.5.3.2
        // minimums are 5 minutes for commands), so a silent cage cannot
        // pin a connection slot. 0 disables it.
        let idle_timeout_seconds = int_or("idle_timeout_seconds", 300)?;
        let bypass = if policy.is_some_and(|p| p.contains_key("bypass_inspectors_for_allowlisted"))
        {
            py_list(pget("bypass_inspectors_for_allowlisted"))?
        } else {
            DEFAULT_BYPASS.iter().map(|s| (*s).to_owned()).collect()
        };
        Ok(Self {
            name,
            listen,
            upstream,
            user_source: super::str_or(auth.and_then(|a| a.get("user_source")), ""),
            password_source: super::str_or(auth.and_then(|a| a.get("password_source")), ""),
            sender_allowlist,
            recipient_addresses,
            recipient_domains,
            max_message_bytes,
            max_recipients,
            conn_rate_limit,
            send_rate_limit,
            idle_timeout_seconds,
            bypass,
        })
    }
}

// ── Pure helpers ────────────────────────────────────────

/// The address in a `MAIL FROM:` / `RCPT TO:` argument: the first
/// `<...>`, else a bare address with an `@` (RFC 5321 lenient handling).
#[must_use]
pub fn extract_address(arg: &str) -> Option<String> {
    // `<([^>]+)>`, searched: the first `<` followed by at least one
    // non-`>` and a `>` (an empty `<>` moves on to the next `<`).
    let mut from = 0;
    while let Some(open) = arg[from..].find('<').map(|i| i + from) {
        let rest = &arg[open + 1..];
        match rest.find('>') {
            Some(0) => from = open + 1,
            Some(close) => {
                return Some(
                    rest[..close]
                        .trim_matches(super::is_py_str_space)
                        .to_owned(),
                );
            }
            None => break,
        }
    }
    let s = arg.trim_matches(super::is_py_str_space);
    (!s.is_empty() && s.contains('@')).then(|| s.to_owned())
}

/// `text` with each non-empty credential replaced by `[redacted]`.
fn without_credentials(text: &str, credentials: &[&str]) -> String {
    let mut text = text.to_owned();
    for value in credentials {
        if !value.is_empty() {
            text = text.replace(value, "[redacted]");
        }
    }
    text
}

/// The content type and header list the inspector chain sees for a
/// message, read the way Python's `email` package (policy `compat32`)
/// reads one: header lines up to the first line that is neither a header
/// nor a continuation, continuation lines joined with their line breaks
/// kept, a leading `From ` envelope line skipped, non-ASCII bytes shown
/// as U+FFFD; the content type lower-cased without its parameters,
/// `text/plain` when absent or not `type/subtype`.
#[must_use]
pub fn message_headers(body: &[u8]) -> (String, Vec<(String, String)>) {
    let lines = split_universal_lines(body);
    let mut header_lines: Vec<&[u8]> = Vec::new();
    for line in &lines {
        if !header_line(line) {
            break;
        }
        header_lines.push(line);
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut current: Vec<&[u8]> = Vec::new();
    let flush = |current: &mut Vec<&[u8]>, headers: &mut Vec<(String, String)>| {
        if current.is_empty() {
            return;
        }
        let first = current[0];
        let colon = first.iter().position(|&b| b == b':').unwrap_or(first.len());
        let name = text_of(&first[..colon]);
        let mut value: Vec<u8> = first.get(colon + 1..).unwrap_or(&[]).to_vec();
        for more in &current[1..] {
            value.extend_from_slice(more);
        }
        let start = value
            .iter()
            .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            .unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|b| !matches!(b, b'\r' | b'\n'))
            .map_or(0, |i| i + 1)
            .max(start);
        headers.push((name, text_of(&value[start..end])));
        current.clear();
    };
    let count = header_lines.len();
    for (lineno, line) in header_lines.iter().enumerate() {
        if matches!(line[0], b' ' | b'\t') {
            if !current.is_empty() {
                current.push(line);
            }
            continue;
        }
        flush(&mut current, &mut headers);
        if line.starts_with(b"From ") {
            if lineno + 1 == count && lineno != 0 {
                break;
            }
            continue;
        }
        if line.first() == Some(&b':') {
            continue;
        }
        current.push(line);
    }
    flush(&mut current, &mut headers);

    let content_type = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map_or_else(
            || "text/plain".to_owned(),
            |(_, v)| {
                let ctype = v
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim_matches(super::is_py_str_space)
                    .to_lowercase();
                if ctype.matches('/').count() == 1 {
                    ctype
                } else {
                    "text/plain".to_owned()
                }
            },
        );
    (content_type, headers)
}

/// Bytes as text the way `compat32` shows a header: ASCII as is, every
/// other byte U+FFFD.
fn text_of(data: &[u8]) -> String {
    super::ascii_lossy(data)
}

/// `headerRE` of Python's feed parser: an envelope `From `, a field name
/// (printable ASCII but `:`) and a colon, or a continuation.
fn header_line(line: &[u8]) -> bool {
    if line.starts_with(b"From ") || matches!(line.first(), Some(b' ' | b'\t')) {
        return true;
    }
    let name_end = line
        .iter()
        .position(|&b| !(0x21..=0x7e).contains(&b) || b == b':')
        .unwrap_or(line.len());
    line.get(name_end) == Some(&b':')
}

/// Lines with their endings, split at CRLF, CR or LF.
fn split_universal_lines(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'\n' => {
                out.push(&data[start..=i]);
                start = i + 1;
            }
            b'\r' => {
                let end = if data.get(i + 1) == Some(&b'\n') {
                    i + 2
                } else {
                    i + 1
                };
                out.push(&data[start..end]);
                start = end;
                i = end;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    if start < data.len() {
        out.push(&data[start..]);
    }
    out
}

/// Split `data` at CRLF, CR or LF keeping the endings (`bytes.splitlines`).
fn splitlines_keepends(data: &[u8]) -> Vec<&[u8]> {
    split_universal_lines(data)
}

/// The inspection context for one message.
fn message_context(body: &[u8], upstream_host: &str) -> Context {
    let (content_type, headers) = message_headers(body);
    Context {
        url: String::new(),
        host: upstream_host.to_owned(),
        method: "SMTP_DATA".to_owned(),
        headers,
        content_type,
        body_bytes: Some(body.to_vec()),
        body_text: Some(String::from_utf8_lossy(body).into_owned()),
        body_size: body.len(),
        body_entropy: (!body.is_empty()).then(|| shannon_entropy(body)),
        prior_results: Vec::new(),
    }
}

// ── The relay ───────────────────────────────────────────

/// One SMTP relay: one listener, one upstream.
#[derive(Debug)]
pub struct SmtpRelay {
    inner: Arc<Inner>,
    listener: Listener,
}

#[derive(Debug)]
struct Inner {
    cfg: SmtpConfig,
    user: String,
    password: String,
    conn_limiter: RateLimiter,
    send_limiter: RateLimiter,
    audit: Arc<dyn AuditSink>,
    log_allowed: AtomicBool,
    inspectors: Mutex<Arc<[Arc<dyn Inspector>]>>,
}

impl SmtpRelay {
    /// Build a relay from its `protocol_relays` entry, resolving its
    /// credentials now.
    ///
    /// # Errors
    ///
    /// The entry does not read as an SMTP relay, a credential is missing
    /// or uses a refused scheme, or a rate spec does not parse.
    pub fn new(
        entry: &Value,
        audit: Arc<dyn AuditSink>,
        settings: &RelaySettings,
    ) -> Result<Self, String> {
        let cfg = SmtpConfig::parse(entry)?;
        let user = super::resolve_credential(&cfg.user_source)?;
        let password = super::resolve_credential(&cfg.password_source)?;
        Self::with_credentials(cfg, user, password, audit, settings)
    }

    /// [`Self::new`] with the credentials already resolved.
    pub(crate) fn with_credentials(
        cfg: SmtpConfig,
        user: String,
        password: String,
        audit: Arc<dyn AuditSink>,
        settings: &RelaySettings,
    ) -> Result<Self, String> {
        if user.is_empty() || password.is_empty() {
            return Err(format!(
                "smtp relay {}: credentials not resolved (user_source={}, password_source={})",
                cfg.name,
                repr_str(&cfg.user_source),
                repr_str(&cfg.password_source)
            ));
        }
        let limiter = |spec: &str| {
            super::parse_rate_limit(spec)
                .map(|(max, window)| RateLimiter::new(max, window))
                .ok_or_else(|| format!("invalid rate spec: {}", repr_str(spec)))
        };
        let conn_limiter = limiter(&cfg.conn_rate_limit)?;
        let send_limiter = limiter(&cfg.send_rate_limit)?;
        Ok(Self {
            inner: Arc::new(Inner {
                cfg,
                user,
                password,
                conn_limiter,
                send_limiter,
                audit,
                log_allowed: AtomicBool::new(settings.log_allowed),
                inspectors: Mutex::new(Arc::clone(&settings.inspectors)),
            }),
            listener: Listener::default(),
        })
    }

    /// The relay's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.inner.cfg.name
    }

    /// Take a reload's settings without restarting. The chain is swapped
    /// whole: a `DATA` inspection already running keeps the chain it
    /// started with, the next one sees the new chain.
    pub fn update_settings(&self, settings: &RelaySettings) {
        self.inner
            .log_allowed
            .store(settings.log_allowed, Ordering::Relaxed);
        *self
            .inner
            .inspectors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::clone(&settings.inspectors);
    }

    /// Bind the listener and start serving.
    ///
    /// # Errors
    ///
    /// The listen address is invalid or cannot be bound.
    pub async fn start(&self) -> Result<(), String> {
        self.listener
            .start(&self.inner.cfg.listen, Arc::clone(&self.inner))
            .await?;
        let cfg = &self.inner.cfg;
        relay_log!(
            info,
            LOGGER,
            "smtp relay {} listening on {} -> {}:{} (senders={:?}, rcpt-domains={:?}, max-bytes={}, max-rcpt={})",
            cfg.name,
            cfg.listen,
            cfg.upstream.host,
            cfg.upstream.port,
            cfg.sender_allowlist,
            cfg.recipient_domains,
            cfg.max_message_bytes,
            cfg.max_recipients
        );
        Ok(())
    }

    /// Close the listener and end every session with `421`.
    pub async fn stop(&self) {
        self.listener.stop().await;
    }

    /// The bound address, once started.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        self.listener.local_addr().await
    }
}

impl super::Handler for Inner {
    fn handle(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        shutdown: watch::Receiver<bool>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move { self.handle_client(stream, peer, shutdown).await })
    }
}

type ClientReader = Reader<tokio::net::tcp::OwnedReadHalf>;
type ClientWriter = tokio::net::tcp::OwnedWriteHalf;

/// One `MAIL FROM` … `DATA` cycle.
#[derive(Debug, Default)]
struct Transaction {
    sender: String,
    recipients: Vec<String>,
    /// An inspector flagged the body: its delivery record is written
    /// whatever `log_allowed` says.
    flagged: bool,
}

/// What a client read produced.
enum Read {
    Line(Vec<u8>),
    Timeout,
    Shutdown,
}

/// `line` ending in CRLF.
async fn write_line(w: &mut ClientWriter, line: &[u8]) -> Result<(), SessionError> {
    let mut out = line.to_vec();
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    w.write_all(&out).await?;
    Ok(())
}

fn recipients_json(list: &[String]) -> Json {
    Json::Array(list.iter().map(|r| s(r.as_str())).collect())
}

impl Inner {
    fn emit(&self, fields: Vec<(&str, Json)>) {
        audit(self.audit.as_ref(), fields);
    }

    async fn handle_client(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        shutdown: watch::Receiver<bool>,
    ) {
        let (read, mut write) = stream.into_split();
        if !self.conn_limiter.take() {
            relay_log!(
                warning,
                LOGGER,
                "smtp relay {}: connection rate limit, refusing {}:{}",
                self.cfg.name,
                peer.ip(),
                peer.port()
            );
            let _ = write.write_all(b"421 connection rate limit\r\n").await;
            let _ = write.shutdown().await;
            return;
        }
        let mut reader = Reader::new(read);
        let mut upstream: Option<UpstreamSmtp> = None;
        let result = self
            .session(&mut reader, &mut write, &mut upstream, shutdown)
            .await;
        if let Some(up) = upstream.take() {
            up.close().await;
        }
        if let Err(e) = result
            && !e.is_disconnect()
        {
            relay_log!(
                error,
                LOGGER,
                "smtp relay {}: session error from {}:{}: {}",
                self.cfg.name,
                peer.ip(),
                peer.port(),
                e
            );
        }
        let _ = write.shutdown().await;
    }

    /// Read one line from the cage under the idle timeout, or notice the
    /// relay stopping.
    async fn read(
        &self,
        reader: &mut ClientReader,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<Read, SessionError> {
        tokio::select! {
            r = super::with_idle_timeout(self.cfg.idle_timeout_seconds, reader.read_line(super::STREAM_LINE_LIMIT)) => match r {
                Err(_) => Ok(Read::Timeout),
                Ok(Ok(Line::Data(line))) => Ok(Read::Line(line)),
                Ok(Ok(Line::TooLong { .. })) => Err(super::line_too_long()),
                Ok(Err(e)) => Err(e.into()),
            },
            _ = shutdown.wait_for(|stop| *stop) => Ok(Read::Shutdown),
        }
    }

    #[allow(clippy::too_many_lines)] // the state machine, in the replaced implementation's order
    async fn session(
        &self,
        reader: &mut ClientReader,
        w: &mut ClientWriter,
        upstream: &mut Option<UpstreamSmtp>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), SessionError> {
        write_line(w, b"220 agentcage-smtp-relay ready").await?;
        let mut helo_seen = false;
        let mut txn = Transaction::default();
        let name = self.cfg.name.as_str();
        loop {
            let line = match self.read(reader, &mut shutdown).await? {
                Read::Line(line) => line,
                Read::Shutdown => {
                    let _ = write_line(w, b"421 4.3.2 relay shutting down").await;
                    return Ok(());
                }
                Read::Timeout => {
                    relay_log!(
                        info,
                        LOGGER,
                        "smtp relay {name}: cage idle for {}s, closing",
                        self.cfg.idle_timeout_seconds
                    );
                    self.emit(vec![
                        ("kind", s("smtp_session")),
                        ("relay", s(name)),
                        ("decision", s("closed")),
                        ("reason", s("cage idle timeout")),
                    ]);
                    let _ = write_line(w, b"421 4.4.2 idle timeout, closing connection").await;
                    return Ok(());
                }
            };
            if line.is_empty() {
                return Ok(());
            }
            // Commands are case-insensitive; arguments may not be.
            let stripped = trim_crlf(&line);
            let (cmd_b, arg_b) = match stripped.iter().position(|&b| b == b' ') {
                Some(i) => (&stripped[..i], &stripped[i + 1..]),
                None => (stripped, &b""[..]),
            };
            let cmd = super::ascii_lossy(&cmd_b.to_ascii_uppercase());
            let arg = String::from_utf8_lossy(arg_b).into_owned();
            let arg_upper = arg.to_uppercase();

            if cmd == "EHLO" || cmd == "HELO" {
                helo_seen = true;
                txn = Transaction::default();
                self.send_ehlo_response(w, cmd == "EHLO").await?;
                continue;
            }
            if !helo_seen {
                write_line(w, b"503 HELO/EHLO first").await?;
                continue;
            }
            match cmd.as_str() {
                "AUTH" => {
                    // The relay authenticates upstream itself; forge the
                    // success, absorbing the continuation lines LOGIN and
                    // the continuation form of PLAIN send.
                    self.emit(vec![
                        ("kind", s("smtp_command")),
                        ("relay", s(name)),
                        ("command", s("AUTH")),
                        ("decision", s("intercepted")),
                        ("reason", s("client AUTH on relay-authed connection")),
                    ]);
                    let prompts: &[&[u8]] = if arg_upper.starts_with("LOGIN") {
                        &[b"334 VXNlcm5hbWU6", b"334 UGFzc3dvcmQ6"]
                    } else if arg_upper == "PLAIN" {
                        &[b"334 "]
                    } else {
                        &[]
                    };
                    for prompt in prompts {
                        write_line(w, prompt).await?;
                        match self.read(reader, &mut shutdown).await? {
                            Read::Line(l) if !l.is_empty() => {}
                            _ => return Ok(()),
                        }
                    }
                    write_line(w, b"235 2.7.0 already authenticated (relay)").await?;
                }
                "NOOP" => write_line(w, b"250 OK").await?,
                "RSET" => {
                    txn = Transaction::default();
                    if let Some(up) = upstream.as_mut() {
                        up.rset().await;
                    }
                    write_line(w, b"250 OK").await?;
                }
                "QUIT" => {
                    write_line(w, b"221 2.0.0 agentcage signing off").await?;
                    return Ok(());
                }
                "VRFY" => {
                    write_line(w, b"252 cannot VRFY user, but will accept for delivery").await?;
                }
                "MAIL" => {
                    if !arg_upper.starts_with("FROM:") {
                        write_line(w, b"501 syntax: MAIL FROM:<address>").await?;
                        continue;
                    }
                    let sender =
                        extract_address(char_slice(&arg, 5).trim_matches(super::is_py_str_space));
                    if let Some(reason) = self.sender_decision(sender.as_deref()) {
                        write_line(w, format!("550 {reason}").as_bytes()).await?;
                        continue;
                    }
                    txn = Transaction {
                        sender: sender.unwrap_or_default(),
                        ..Transaction::default()
                    };
                    write_line(w, b"250 2.1.0 sender ok").await?;
                }
                "RCPT" => {
                    if !arg_upper.starts_with("TO:") {
                        write_line(w, b"501 syntax: RCPT TO:<address>").await?;
                        continue;
                    }
                    if txn.sender.is_empty() {
                        write_line(w, b"503 MAIL FROM first").await?;
                        continue;
                    }
                    if i64::try_from(txn.recipients.len()).unwrap_or(i64::MAX)
                        >= self.cfg.max_recipients
                    {
                        self.emit(vec![
                            ("kind", s("smtp_command")),
                            ("relay", s(name)),
                            ("command", s("RCPT")),
                            ("decision", s("blocked")),
                            (
                                "reason",
                                s(format!(
                                    "max_recipients ({}) exceeded",
                                    self.cfg.max_recipients
                                )),
                            ),
                        ]);
                        write_line(w, b"452 4.5.3 too many recipients").await?;
                        continue;
                    }
                    let rcpt =
                        extract_address(char_slice(&arg, 3).trim_matches(super::is_py_str_space));
                    if let Some(reason) = self.recipient_decision(rcpt.as_deref()) {
                        write_line(w, format!("550 5.7.1 {reason}").as_bytes()).await?;
                        continue;
                    }
                    txn.recipients.push(rcpt.unwrap_or_default());
                    write_line(w, b"250 2.1.5 recipient ok").await?;
                }
                "DATA" => {
                    if !self
                        .data(reader, w, upstream, &mut txn, &mut shutdown)
                        .await?
                    {
                        return Ok(());
                    }
                }
                // Unknown commands (HELP, EXPN, ...) are answered, never
                // passed through.
                _ => write_line(w, b"502 5.5.1 command not implemented").await?,
            }
        }
    }

    /// The `DATA` command; `false` ends the session.
    #[allow(clippy::too_many_lines)] // one transaction, in the replaced implementation's order
    async fn data(
        &self,
        reader: &mut ClientReader,
        w: &mut ClientWriter,
        upstream: &mut Option<UpstreamSmtp>,
        txn: &mut Transaction,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<bool, SessionError> {
        let name = self.cfg.name.as_str();
        if txn.sender.is_empty() || txn.recipients.is_empty() {
            write_line(w, b"503 need MAIL FROM and at least one RCPT TO").await?;
            return Ok(true);
        }
        if !self.send_limiter.take() {
            self.emit(vec![
                ("kind", s("smtp_command")),
                ("relay", s(name)),
                ("command", s("DATA")),
                ("decision", s("blocked")),
                ("reason", s("send_rate_limit exceeded")),
            ]);
            write_line(w, b"451 4.7.0 send rate limit exceeded").await?;
            return Ok(true);
        }
        write_line(w, b"354 end data with <CR><LF>.<CR><LF>").await?;
        let (body, oversize) = match self.read_data(reader, shutdown).await? {
            DataRead::Body(body, oversize) => (body, oversize),
            DataRead::Shutdown => {
                self.send_limiter.release();
                let _ = write_line(w, b"421 4.3.2 relay shutting down").await;
                return Ok(false);
            }
            DataRead::Eof(size) => {
                // No end-of-data line, so no message: a truncated body is
                // never delivered. The replaced implementation delivered
                // what it had read. Nothing of this transaction has gone
                // upstream yet (delivery starts after the body is read),
                // so there is nothing to abort there.
                self.send_limiter.release();
                self.emit(vec![
                    ("kind", s("smtp_data_aborted")),
                    ("relay", s(name)),
                    ("decision", s("blocked")),
                    ("reason", s("cage disconnected before end of data")),
                    ("sender", s(&txn.sender)),
                    ("recipients", recipients_json(&txn.recipients)),
                    ("size", Json::Int(i64::try_from(size).unwrap_or(i64::MAX))),
                ]);
                *txn = Transaction::default();
                return Ok(false);
            }
            DataRead::Timeout => {
                // The message never made it through: the slot is not used.
                self.send_limiter.release();
                self.emit(vec![
                    ("kind", s("smtp_command")),
                    ("relay", s(name)),
                    ("command", s("DATA")),
                    ("decision", s("blocked")),
                    ("reason", s("DATA reception idle timeout")),
                ]);
                write_line(w, b"451 4.4.2 DATA reception timed out").await?;
                *txn = Transaction::default();
                return Ok(true);
            }
        };
        let size = Json::Int(i64::try_from(body.len()).unwrap_or(i64::MAX));
        if oversize {
            self.send_limiter.release();
            self.emit(vec![
                ("kind", s("smtp_command")),
                ("relay", s(name)),
                ("command", s("DATA")),
                ("decision", s("blocked")),
                (
                    "reason",
                    s(format!(
                        "message exceeds max_message_bytes ({})",
                        self.cfg.max_message_bytes
                    )),
                ),
                ("size", size),
            ]);
            write_line(w, b"552 5.3.4 message size exceeds limit").await?;
            *txn = Transaction::default();
            return Ok(true);
        }
        if let Some(block) = self.run_inspectors(&body, txn).await? {
            // A blocked message gives its slot back, so a misbehaving
            // client doesn't burn its quota on never-delivered attempts.
            self.send_limiter.release();
            self.emit(vec![
                ("kind", s("smtp_data")),
                ("relay", s(name)),
                ("decision", s("blocked")),
                ("reason", s(&block.reason)),
                ("inspector", s(&block.inspector)),
                ("severity", s(block.severity.as_str())),
                ("sender", s(&txn.sender)),
                ("recipients", recipients_json(&txn.recipients)),
                ("size", size),
            ]);
            let mut reply = b"550 5.7.0 ".to_vec();
            reply.extend_from_slice(block.reason.as_bytes());
            write_line(w, &reply).await?;
            *txn = Transaction::default();
            return Ok(true);
        }
        // The upstream opens lazily: no handshake for a transaction that
        // never gets past policy.
        let delivered = async {
            if upstream.is_none() {
                *upstream = Some(self.connect_upstream().await?);
            }
            match upstream.as_mut() {
                Some(up) => up.deliver(&txn.sender, &txn.recipients, &body).await,
                None => Err(String::new()),
            }
        }
        .await;
        let (status, accepted, rejected) = match delivered {
            Ok(result) => result,
            Err(e) => {
                relay_log!(
                    error,
                    LOGGER,
                    "smtp relay {name}: upstream delivery failed: {e}"
                );
                self.send_limiter.release();
                self.emit(vec![
                    ("kind", s("smtp_data")),
                    ("relay", s(name)),
                    ("decision", s("upstream_error")),
                    ("error", s(e)),
                    ("sender", s(&txn.sender)),
                    ("recipients", recipients_json(&txn.recipients)),
                ]);
                // 451 (transient, channel stays open) rather than 421, so
                // the cage's mailer can retry on the same session; the
                // broken upstream goes and the next message opens anew.
                write_line(w, b"451 4.4.0 upstream temporarily unavailable").await?;
                if let Some(up) = upstream.take() {
                    up.close().await;
                }
                *txn = Transaction::default();
                return Ok(true);
            }
        };
        // Like an allowed IMAP command, the delivery record follows
        // `logging.allowed_requests`; a flagged message's delivery is
        // always recorded next to its `smtp_data_flag` record.
        if self.log_allowed.load(Ordering::Relaxed) || txn.flagged {
            self.emit(vec![
                ("kind", s("smtp_data")),
                ("relay", s(name)),
                ("decision", s("allowed")),
                ("sender", s(&txn.sender)),
                ("recipients", recipients_json(&accepted)),
                ("recipients_rejected_upstream", recipients_json(&rejected)),
                ("size", size),
                ("upstream_status", s(&status)),
            ]);
        }
        write_line(w, format!("250 2.0.0 ok ({status})").as_bytes()).await?;
        *txn = Transaction::default();
        Ok(true)
    }

    async fn send_ehlo_response(
        &self,
        w: &mut ClientWriter,
        is_ehlo: bool,
    ) -> Result<(), SessionError> {
        // No STARTTLS (plaintext inside the egress). AUTH is advertised
        // although the relay authenticates upstream itself: many clients
        // refuse to send without any AUTH method on offer. Whatever the
        // client sends is intercepted, never forwarded.
        if !is_ehlo {
            w.write_all(b"250 agentcage-smtp-relay\r\n").await?;
            return Ok(());
        }
        let size = format!("SIZE {}", self.cfg.max_message_bytes);
        let lines: [&[u8]; 7] = [
            b"agentcage-smtp-relay",
            b"AUTH PLAIN LOGIN",
            b"8BITMIME",
            size.as_bytes(),
            b"PIPELINING",
            b"ENHANCEDSTATUSCODES",
            b"SMTPUTF8",
        ];
        let mut out = Vec::new();
        for (i, payload) in lines.iter().enumerate() {
            out.extend_from_slice(b"250");
            out.push(if i + 1 < lines.len() { b'-' } else { b' ' });
            out.extend_from_slice(payload);
            out.extend_from_slice(b"\r\n");
        }
        w.write_all(&out).await?;
        Ok(())
    }

    /// Read the message to the end-of-data line, dot-unstuffing (RFC 5321
    /// §4.5.2). Past `max_message_bytes` the body is truncated and the
    /// rest drained, so the next command starts in step.
    async fn read_data(
        &self,
        reader: &mut ClientReader,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<DataRead, SessionError> {
        let max = usize::try_from(self.cfg.max_message_bytes).unwrap_or(0);
        let mut body = Vec::new();
        let mut oversize = false;
        loop {
            let line = match self.read(reader, shutdown).await? {
                Read::Line(line) => line,
                Read::Timeout => return Ok(DataRead::Timeout),
                Read::Shutdown => return Ok(DataRead::Shutdown),
            };
            if line.is_empty() {
                return Ok(DataRead::Eof(body.len()));
            }
            if line == b".\r\n" || line == b".\n" {
                break;
            }
            let line = if line.starts_with(b"..") {
                &line[1..]
            } else {
                &line[..]
            };
            if !oversize {
                body.extend_from_slice(line);
                if body.len() > max {
                    oversize = true;
                }
            }
        }
        Ok(DataRead::Body(body, oversize))
    }

    fn sender_decision(&self, sender: Option<&str>) -> Option<String> {
        let name = self.cfg.name.as_str();
        let Some(sender) = sender.filter(|s| !s.is_empty()) else {
            self.emit(vec![
                ("kind", s("smtp_command")),
                ("relay", s(name)),
                ("command", s("MAIL")),
                ("decision", s("blocked")),
                ("reason", s("missing sender")),
            ]);
            return Some("missing or malformed sender".to_owned());
        };
        if self.cfg.sender_allowlist.is_empty()
            || self.cfg.sender_allowlist.contains(&sender.to_lowercase())
        {
            return None;
        }
        self.emit(vec![
            ("kind", s("smtp_command")),
            ("relay", s(name)),
            ("command", s("MAIL")),
            ("decision", s("blocked")),
            ("sender", s(sender)),
            ("reason", s("sender not in sender_allowlist")),
        ]);
        Some(format!("sender {sender} not permitted"))
    }

    fn recipient_decision(&self, rcpt: Option<&str>) -> Option<String> {
        let name = self.cfg.name.as_str();
        let Some(rcpt) = rcpt.filter(|r| !r.is_empty()) else {
            self.emit(vec![
                ("kind", s("smtp_command")),
                ("relay", s(name)),
                ("command", s("RCPT")),
                ("decision", s("blocked")),
                ("reason", s("missing recipient")),
            ]);
            return Some("missing or malformed recipient".to_owned());
        };
        let addrs = &self.cfg.recipient_addresses;
        let domains = &self.cfg.recipient_domains;
        if addrs.is_empty() && domains.is_empty() {
            return None;
        }
        let rl = rcpt.to_lowercase();
        if addrs.contains(&rl) {
            return None;
        }
        let domain = rl.rsplit_once('@').map_or("", |(_, d)| d);
        if domains
            .iter()
            .any(|d| domain == d || domain.ends_with(&format!(".{d}")))
        {
            return None;
        }
        self.emit(vec![
            ("kind", s("smtp_command")),
            ("relay", s(name)),
            ("command", s("RCPT")),
            ("decision", s("blocked")),
            ("recipient", s(rcpt)),
            ("reason", s("recipient not in recipient_allowlist")),
        ]);
        Some(format!("recipient {rcpt} not permitted"))
    }

    /// Run the inspector chain over the message; the first `block`, or
    /// `None`.
    ///
    /// With a recipient allowlist set (every surviving recipient passed
    /// it), the inspectors named in `bypass_inspectors_for_allowlisted`
    /// are skipped, so forwarded mail with keys or attachments reaches a
    /// trusted recipient. The chain runs on a blocking thread, and is
    /// read once, up front: a reload may swap it meanwhile.
    async fn run_inspectors(
        &self,
        body: &[u8],
        txn: &mut Transaction,
    ) -> Result<Option<Verdict>, SessionError> {
        let inspectors = Arc::clone(
            &*self
                .inspectors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if inspectors.is_empty() {
            return Ok(None);
        }
        let allowlisted =
            !self.cfg.recipient_addresses.is_empty() || !self.cfg.recipient_domains.is_empty();
        let bypass: Vec<String> = if allowlisted {
            self.cfg.bypass.clone()
        } else {
            Vec::new()
        };
        let mut ctx = message_context(body, &self.cfg.upstream.host);
        let chain = Arc::clone(&inspectors);
        let skip_names = bypass.clone();
        let results = tokio::task::spawn_blocking(move || {
            run_chain(&chain, &mut ctx, Phase::Request, &|i: &dyn Inspector| {
                skip_names.iter().any(|b| b == i.name())
            })
        })
        .await
        .map_err(|e| SessionError::Other(format!("inspector chain failed: {e}")))?;
        if let Some(block) = results.iter().find(|r| r.action == Action::Block) {
            return Ok(Some(block.clone()));
        }
        let flagged: Vec<&Verdict> = results
            .iter()
            .filter(|r| r.action == Action::Flag)
            .collect();
        txn.flagged = !flagged.is_empty();
        let name = self.cfg.name.as_str();
        for r in flagged {
            self.emit(vec![
                ("kind", s("smtp_data_flag")),
                ("relay", s(name)),
                // What `cage audit -d flagged` filters on.
                ("decision", s("flagged")),
                ("inspector", s(&r.inspector)),
                ("reason", s(&r.reason)),
                ("severity", s(r.severity.as_str())),
                ("sender", s(&txn.sender)),
                ("recipients", recipients_json(&txn.recipients)),
            ]);
        }
        let mut bypassed: Vec<String> = inspectors
            .iter()
            .map(|i| i.name().to_owned())
            .filter(|n| bypass.contains(n))
            .collect();
        if !bypassed.is_empty() {
            bypassed.sort();
            self.emit(vec![
                ("kind", s("smtp_data_bypass")),
                ("relay", s(name)),
                (
                    "bypassed",
                    Json::Array(bypassed.into_iter().map(Json::Str).collect()),
                ),
                ("sender", s(&txn.sender)),
                ("recipients", recipients_json(&txn.recipients)),
                ("reason", s("all recipients in allowlist")),
            ]);
        }
        Ok(None)
    }

    async fn connect_upstream(&self) -> Result<UpstreamSmtp, String> {
        let stream = self.cfg.upstream.connect().await?;
        let (read, write) = tokio::io::split(stream);
        let mut up = UpstreamSmtp {
            reader: Reader::new(read),
            writer: write,
            relay_name: self.cfg.name.clone(),
            user: self.user.clone(),
            password: self.password.clone(),
            idle_timeout: self.cfg.idle_timeout_seconds,
        };
        if let Err(e) = up.handshake().await {
            // Don't leak the socket when EHLO or AUTH fails.
            let _ = up.writer.shutdown().await;
            return Err(e);
        }
        Ok(up)
    }
}

/// What reading a message body produced.
enum DataRead {
    /// The body up to the end-of-data line, and whether it overflowed.
    Body(Vec<u8>, bool),
    /// The cage hung up before the end-of-data line; the bytes read.
    Eof(usize),
    Timeout,
    Shutdown,
}

/// Python's `arg[n:]` on a `str`: by characters, not bytes.
fn char_slice(text: &str, n: usize) -> &str {
    text.char_indices().nth(n).map_or("", |(i, _)| &text[i..])
}

fn trim_crlf(data: &[u8]) -> &[u8] {
    let end = data
        .iter()
        .rposition(|&b| b != b'\r' && b != b'\n')
        .map_or(0, |i| i + 1);
    &data[..end]
}

// ── The upstream client ─────────────────────────────────

/// A thin SMTP client for the upstream: EHLO and `AUTH PLAIN` at the
/// handshake, then transactions. Every read shares the cage side's idle
/// timeout, so a silent upstream cannot pin the session.
struct UpstreamSmtp {
    reader: Reader<tokio::io::ReadHalf<Box<dyn super::Stream>>>,
    writer: tokio::io::WriteHalf<Box<dyn super::Stream>>,
    relay_name: String,
    user: String,
    password: String,
    idle_timeout: i64,
}

impl UpstreamSmtp {
    async fn readline(&mut self) -> Result<Vec<u8>, String> {
        match super::with_idle_timeout(
            self.idle_timeout,
            self.reader.read_line(super::STREAM_LINE_LIMIT),
        )
        .await
        {
            Err(_) => Err(String::new()),
            Ok(Ok(Line::Data(line))) => Ok(line),
            Ok(Ok(Line::TooLong { .. })) => Err(super::line_too_long().to_string()),
            Ok(Err(e)) => Err(e.to_string()),
        }
    }

    /// A (possibly multi-line) reply: `(code, text lines joined by LF)`.
    async fn read_response(&mut self) -> Result<(i64, String), String> {
        let mut parts = Vec::new();
        loop {
            let line = self.readline().await?;
            if line.is_empty() {
                return Err("upstream closed".to_owned());
            }
            let code = std::str::from_utf8(&line[..line.len().min(3)])
                .ok()
                .and_then(super::py_int_text)
                .ok_or_else(|| format!("malformed upstream response: {}", bytes_repr(&line)))?;
            let sep = line.get(3).copied();
            let text = String::from_utf8_lossy(line.get(4..).unwrap_or(&[])).into_owned();
            parts.push(text.trim_end_matches(['\r', '\n']).to_owned());
            if sep != Some(b'-') {
                return Ok((code, parts.join("\n")));
            }
        }
    }

    async fn command(&mut self, line: &[u8]) -> Result<(i64, String), String> {
        let mut out = line.to_vec();
        if !out.ends_with(b"\r\n") {
            out.extend_from_slice(b"\r\n");
        }
        write_all(&mut self.writer, &out).await?;
        self.read_response().await
    }

    async fn handshake(&mut self) -> Result<(), String> {
        let (code, _) = self.read_response().await?;
        if !(200..400).contains(&code) {
            return Err(format!("upstream greeting code {code}"));
        }
        // An FQDN-ish name: some MTAs reject empty or IP HELOs.
        let (code, text) = self.command(b"EHLO agentcage.local").await?;
        if code != 250 {
            return Err(format!("upstream EHLO rejected: {code} {text}"));
        }
        let mut raw = vec![0u8];
        raw.extend_from_slice(self.user.as_bytes());
        raw.push(0);
        raw.extend_from_slice(self.password.as_bytes());
        let token = base64::engine::general_purpose::STANDARD.encode(raw);
        let password = self.password.clone();
        let creds = [token.as_str(), password.as_str()];
        // Logged and audited, so never with the credential in it, should
        // the server quote the AUTH line back.
        let (code, text) = self
            .command(format!("AUTH PLAIN {token}").as_bytes())
            .await
            .map_err(|e| without_credentials(&e, &creds))?;
        if code != 235 {
            return Err(format!(
                "upstream AUTH failed: {}",
                without_credentials(&format!("{code} {text}"), &creds)
            ));
        }
        Ok(())
    }

    async fn rset(&mut self) {
        let _ = self.command(b"RSET").await;
    }

    /// `MAIL FROM` / `RCPT TO` / `DATA` upstream: `(status, accepted,
    /// rejected)`. A refused `MAIL FROM`, every recipient refused, or a
    /// refused body is an error, not a partial delivery.
    async fn deliver(
        &mut self,
        sender: &str,
        recipients: &[String],
        body: &[u8],
    ) -> Result<(String, Vec<String>, Vec<String>), String> {
        let (code, text) = self
            .command(format!("MAIL FROM:<{sender}>").as_bytes())
            .await?;
        if code != 250 {
            return Err(format!("upstream MAIL FROM rejected: {code} {text}"));
        }
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for rcpt in recipients {
            let (code, text) = self.command(format!("RCPT TO:<{rcpt}>").as_bytes()).await?;
            if (200..300).contains(&code) {
                accepted.push(rcpt.clone());
            } else {
                rejected.push(rcpt.clone());
                relay_log!(
                    warning,
                    LOGGER,
                    "smtp relay {}: upstream rejected RCPT {rcpt}: {code} {text}",
                    self.relay_name
                );
            }
        }
        if accepted.is_empty() {
            self.command(b"RSET").await?;
            return Err("upstream rejected all recipients".to_owned());
        }
        let (code, text) = self.command(b"DATA").await?;
        if code != 354 {
            return Err(format!("upstream DATA rejected: {code} {text}"));
        }
        let mut stuffed = Vec::with_capacity(body.len() + 16);
        for line in splitlines_keepends(body) {
            if line.starts_with(b".") {
                stuffed.push(b'.');
            }
            stuffed.extend_from_slice(line);
        }
        if !stuffed.ends_with(b"\r\n") {
            stuffed.extend_from_slice(b"\r\n");
        }
        stuffed.extend_from_slice(b".\r\n");
        write_all(&mut self.writer, &stuffed).await?;
        let (code, text) = self.read_response().await?;
        if !(200..300).contains(&code) {
            return Err(format!("upstream DATA body rejected: {code} {text}"));
        }
        Ok((format!("upstream {code} {text}"), accepted, rejected))
    }

    async fn close(mut self) {
        let _ = self.command(b"QUIT").await;
        let _ = self.writer.shutdown().await;
    }
}

async fn write_all<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<(), String> {
    w.write_all(data).await.map_err(|e| e.to_string())?;
    w.flush().await.map_err(|e| e.to_string())
}

#[cfg(test)]
#[path = "smtp_tests.rs"]
mod tests;
