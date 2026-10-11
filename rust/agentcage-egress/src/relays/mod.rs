//! The IMAP and SMTP protocol relays.
//!
//! The HTTP pipeline can only inject a credential that travels over
//! HTTP. Mail is different: IMAP and SMTP are stateful line protocols
//! with their own authentication exchanges, and yet the trust property
//! has to be the same. The cage holds no real credential; it talks
//! plaintext to a listener in the egress, and the relay opens the
//! authenticated upstream connection on its behalf, applying policy at
//! command granularity on the way through.
//!
//! * [`imap`]: `PREAUTH` greeting, `LOGIN` injected upstream, write
//!   modes, folder allow/deny lists, literal tracking, capability
//!   filtering.
//! * [`smtp`]: sender and recipient allowlists, size, recipient and rate
//!   caps, and the inspector chain on every `DATA` payload.
//! * [`tls`]: the upstream TLS policy both share.
//! * [`manager`]: starts the relays from the config and re-syncs them on
//!   every reload, diffing by relay name.
//!
//! Each relay is a tokio TCP listener inside the egress process, so it
//! shares the egress's secret lookup ([`crate::secret_lookup`]) and its
//! audit pipeline ([`crate::audit`]).

pub mod imap;
pub mod manager;
pub mod smtp;
pub mod tls;
pub mod validate;

#[cfg(test)]
mod testkit;

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::audit::AuditSink;
use crate::config::Value;
use crate::inspect::Inspector;
use crate::json::Json;
use agentcage_core::python::{repr_str, type_name};

/// The settings a running relay takes from every config reload without
/// restarting: whether allowed traffic is logged, and the inspector
/// chain (used by the SMTP relay only).
#[derive(Clone, Debug, Default)]
pub struct RelaySettings {
    /// `logging.allowed_requests`: write a record for allowed commands
    /// and deliveries.
    pub log_allowed: bool,
    /// The relay inspector chain, already adjusted for relays (the
    /// inspector chain's `relay_inspectors()`: no domain inspector, the
    /// secrets inspector blocking by default). Swapped as a whole, so a
    /// `DATA` inspection already running keeps the chain it started
    /// with.
    pub inspectors: Arc<[Arc<dyn Inspector>]>,
}

// ── Logging ─────────────────────────────────────────────

/// A log line from a relay, to stderr.
///
/// The relays' operational log (connection refused, upstream failed, a
/// command blocked) is not an audit record and has no consumer beyond a
/// human reading `podman logs`; the audit records are the contract.
/// Debug-level messages are dropped.
macro_rules! relay_log {
    (debug, $($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
    ($level:ident, $logger:expr, $($arg:tt)*) => {
        eprintln!("{} {}: {}", stringify!($level), $logger, format_args!($($arg)*))
    };
}
pub(crate) use relay_log;

// ── Audit ───────────────────────────────────────────────

/// Emit one relay audit record, `fields` in order. No `ts`: the audit
/// writer appends it after the other fields, as the replaced
/// implementation's writer did for every relay record.
pub(crate) fn audit(sink: &dyn AuditSink, fields: Vec<(&str, Json)>) {
    sink.emit(crate::json::object(fields));
}

/// `Json::Str` shorthand.
pub(crate) fn s(text: impl Into<String>) -> Json {
    Json::Str(text.into())
}

// ── Rate limiting ───────────────────────────────────────

/// Why a rate spec was refused.
pub(crate) fn parse_rate_limit(spec: &str) -> Option<(usize, Duration)> {
    if !agentcage_core::relays::is_rate_limit(spec) {
        return None;
    }
    let space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c');
    let (count, unit) = spec.trim_matches(space).split_once('/')?;
    let count: usize = count.trim_end_matches(space).parse().ok()?;
    let secs = match unit.trim_start_matches(space).to_ascii_lowercase().as_str() {
        "sec" | "s" => 1,
        "min" | "m" => 60,
        "hour" | "h" => 3600,
        _ => return None,
    };
    Some((count, Duration::from_secs(secs)))
}

/// A sliding-window rate limiter.
///
/// `take` reserves a slot up front, so a burst of concurrent attempts
/// cannot all slip under the cap before any of them completes; `release`
/// gives the most recent one back when the attempt did not count (the
/// SMTP relay counts upstream-accepted deliveries, not attempts).
#[derive(Debug)]
pub(crate) struct RateLimiter {
    max: usize,
    window: Duration,
    stamps: Mutex<Vec<Instant>>,
}

impl RateLimiter {
    pub(crate) fn new(max: usize, window: Duration) -> Self {
        Self {
            max,
            window,
            stamps: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn take(&self) -> bool {
        let now = Instant::now();
        let mut stamps = self
            .stamps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stamps.retain(|t| now.duration_since(*t) < self.window);
        if stamps.len() >= self.max {
            return false;
        }
        stamps.push(now);
        true
    }

    pub(crate) fn release(&self) {
        self.stamps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop();
    }
}

// ── Python-compatible text helpers ──────────────────────

/// `bytes.isspace()` for one byte: Python's ASCII whitespace set, which
/// has the vertical tab `u8::is_ascii_whitespace` leaves out.
pub(crate) fn is_py_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c')
}

/// `str.isspace()` for one char: Unicode whitespace plus the four ASCII
/// separators (`\x1c`–`\x1f`) Python counts and Rust does not.
pub(crate) fn is_py_str_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// `data.split(None, maxsplit)` as byte ranges: runs of ASCII whitespace
/// separate fields; with `maxsplit`, the last field is the rest of the
/// input after the whitespace in front of it, trailing whitespace kept.
pub(crate) fn split_ws_ranges(data: &[u8], maxsplit: Option<usize>) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = data.len();
    loop {
        while i < n && is_py_space(data[i]) {
            i += 1;
        }
        if i >= n {
            break;
        }
        if maxsplit.is_some_and(|m| out.len() == m) {
            out.push((i, n));
            break;
        }
        let start = i;
        while i < n && !is_py_space(data[i]) {
            i += 1;
        }
        out.push((start, i));
    }
    out
}

/// `data.split(None, maxsplit)`.
pub(crate) fn split_ws(data: &[u8], maxsplit: Option<usize>) -> Vec<&[u8]> {
    split_ws_ranges(data, maxsplit)
        .into_iter()
        .map(|(a, b)| &data[a..b])
        .collect()
}

/// `text.split()` on a `str`.
pub(crate) fn split_str_ws(text: &str) -> Vec<&str> {
    text.split(is_py_str_space)
        .filter(|t| !t.is_empty())
        .collect()
}

/// `data.decode("ascii", errors="replace")`.
pub(crate) fn ascii_lossy(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if b.is_ascii() {
                char::from(b)
            } else {
                '\u{fffd}'
            }
        })
        .collect()
}

/// `repr(data)` of a Python `bytes`, for log lines.
pub(crate) fn bytes_repr(data: &[u8]) -> String {
    let quote = if data.contains(&b'\'') && !data.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from("b");
    out.push(quote);
    for &b in data {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ if char::from(b) == quote => {
                out.push('\\');
                out.push(quote);
            }
            0x20..=0x7e => out.push(char::from(b)),
            _ => {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out.push(quote);
    out
}

/// Python's `int(value)` on a YAML value, with its error messages.
pub(crate) fn py_int(value: &Value) -> Result<i64, String> {
    match value {
        Value::Bool(b) => Ok(i64::from(*b)),
        Value::Number(n) => n
            .as_i64()
            .or_else(|| {
                #[allow(clippy::cast_possible_truncation)]
                n.as_f64()
                    .filter(|f| f.is_finite())
                    .map(|f| f.trunc() as i64)
            })
            .ok_or_else(|| "cannot convert float NaN or infinity to integer".to_owned()),
        Value::String(text) => py_int_text(text)
            .ok_or_else(|| format!("invalid literal for int() with base 10: {}", repr_str(text))),
        other => Err(format!(
            "int() argument must be a string, a bytes-like object or a real number, not '{}'",
            type_name(other)
        )),
    }
}

/// `int(text)` for a base-10 literal: surrounding whitespace, a sign,
/// and single underscores between digits.
pub(crate) fn py_int_text(text: &str) -> Option<i64> {
    let t = text.trim_matches(is_py_str_space);
    let (neg, digits) = match t.as_bytes().first()? {
        b'-' => (true, &t[1..]),
        b'+' => (false, &t[1..]),
        _ => (false, t),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    let value: i64 = digits.replace('_', "").parse().ok()?;
    Some(if neg { -value } else { value })
}

/// `str(mapping.get(key) or default)`.
pub(crate) fn str_or(value: Option<&Value>, default: &str) -> String {
    match value {
        Some(v) if agentcage_core::yaml::python_bool(v) => agentcage_core::python::str_of(v),
        _ => default.to_owned(),
    }
}

/// Resolve one relay credential source, with the replaced
/// implementation's error text (`repr` quoting, not Rust's).
pub(crate) fn resolve_credential(source: &str) -> Result<String, String> {
    crate::secret_lookup::resolve_credential(source)
        .map_err(|_| format!("unsupported relay credential source: {}", repr_str(source)))
}

// ── Buffered reads with Python `StreamReader` semantics ─

/// asyncio's default `StreamReader` line limit: a line whose LF lies
/// past this offset ends the session.
pub(crate) const STREAM_LINE_LIMIT: usize = 64 * 1024;

/// What [`Reader::read_line`] got.
#[derive(Debug)]
pub(crate) enum Line {
    /// A line up to and including its LF, or what was left before EOF
    /// (empty at EOF).
    Data(Vec<u8>),
    /// A line over the limit, read and dropped through its LF (or EOF).
    /// `head` is its first bytes, `tail` its last ones, LF included.
    TooLong {
        /// The first [`TOO_LONG_KEEP`] bytes.
        head: Vec<u8>,
        /// The last 64 bytes.
        tail: Vec<u8>,
    },
}

/// How much of the start of an over-long line [`Line::TooLong`] keeps.
pub(crate) const TOO_LONG_KEEP: usize = 1024;

/// A buffered reader over one side of a connection.
///
/// One buffer serves line reads, exact reads and raw chunk reads, so
/// bytes read ahead by one kind of read are seen by the next: a server
/// that sends its first response in the same segment as its greeting
/// loses nothing.
#[derive(Debug)]
pub(crate) struct Reader<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            pos: 0,
            eof: false,
        }
    }

    fn buffered(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    async fn fill(&mut self) -> std::io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        // Read straight into the buffer's spare room: a stack buffer here
        // would sit in every session future.
        self.buf.reserve(16 * 1024);
        let n = self.inner.read_buf(&mut self.buf).await?;
        if n == 0 {
            self.eof = true;
            return Ok(false);
        }
        Ok(true)
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        out
    }

    /// Read one line of at most `limit` bytes before its LF.
    pub(crate) async fn read_line(&mut self, limit: usize) -> std::io::Result<Line> {
        let mut scanned = 0;
        loop {
            let avail = self.buffered();
            if let Some(i) = avail[scanned..].iter().position(|&b| b == b'\n') {
                let at = scanned + i;
                if at > limit {
                    return self.drop_line(at + 1).await;
                }
                return Ok(Line::Data(self.take(at + 1)));
            }
            scanned = avail.len();
            if scanned > limit {
                return self.drop_line(0).await;
            }
            if !self.fill().await? {
                let n = self.buffered().len();
                return Ok(Line::Data(self.take(n)));
            }
        }
    }

    /// Drop an over-long line: `through` is the length to its LF when
    /// already buffered, 0 to read on until one arrives (or EOF).
    async fn drop_line(&mut self, through: usize) -> std::io::Result<Line> {
        fn keep(data: &[u8], head: &mut Vec<u8>, tail: &mut Vec<u8>) {
            if head.len() < TOO_LONG_KEEP {
                let take = (TOO_LONG_KEEP - head.len()).min(data.len());
                head.extend_from_slice(&data[..take]);
            }
            tail.extend_from_slice(data);
            if tail.len() > 64 {
                tail.drain(..tail.len() - 64);
            }
        }
        let mut head = Vec::new();
        let mut tail = Vec::new();
        if through > 0 {
            let data = self.take(through);
            keep(&data, &mut head, &mut tail);
            return Ok(Line::TooLong { head, tail });
        }
        loop {
            let avail = self.buffered();
            if let Some(i) = avail.iter().position(|&b| b == b'\n') {
                let data = self.take(i + 1);
                keep(&data, &mut head, &mut tail);
                return Ok(Line::TooLong { head, tail });
            }
            let n = avail.len();
            let data = self.take(n);
            keep(&data, &mut head, &mut tail);
            if !self.fill().await? {
                return Ok(Line::TooLong { head, tail });
            }
        }
    }

    /// `readexactly(n)`: `None` when EOF comes first.
    pub(crate) async fn read_exact(&mut self, n: usize) -> std::io::Result<Option<Vec<u8>>> {
        while self.buffered().len() < n {
            if !self.fill().await? {
                return Ok(None);
            }
        }
        Ok(Some(self.take(n)))
    }

    /// `read(max)`: whatever is buffered or arrives next, at most `max`
    /// bytes; empty at EOF.
    pub(crate) async fn read_some(&mut self, max: usize) -> std::io::Result<Vec<u8>> {
        if self.buffered().is_empty() && !self.fill().await? {
            return Ok(Vec::new());
        }
        let n = self.buffered().len().min(max);
        Ok(self.take(n))
    }
}

/// An error that ends a session: logged as `session error`, unless it
/// is a reset or a broken pipe, which are a client going away.
#[derive(Debug)]
pub(crate) enum SessionError {
    /// The socket failed.
    Io(std::io::Error),
    /// A read timed out where the replaced implementation let the
    /// timeout propagate (its message was empty).
    Timeout,
    /// Anything else, with its message.
    Other(String),
}

impl From<std::io::Error> for SessionError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Timeout => Ok(()),
            Self::Other(m) => f.write_str(m),
        }
    }
}

impl SessionError {
    /// Whether this is the client simply going away.
    pub(crate) fn is_disconnect(&self) -> bool {
        matches!(self, Self::Io(e) if matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
        ))
    }
}

/// A line over the stream limit, as the replaced implementation's reader
/// worded it.
pub(crate) fn line_too_long() -> SessionError {
    SessionError::Other("Separator is found, but chunk is longer than limit".to_owned())
}

/// Run `fut` under the relay's idle timeout; 0 or less disables it.
pub(crate) async fn with_idle_timeout<T>(
    secs: i64,
    fut: impl std::future::Future<Output = T>,
) -> Result<T, tokio::time::error::Elapsed> {
    match u64::try_from(secs) {
        Ok(secs) if secs > 0 => tokio::time::timeout(Duration::from_secs(secs), fut).await,
        _ => Ok(fut.await),
    }
}

// ── Upstream connections ────────────────────────────────

/// A connected upstream, plaintext or TLS.
pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Where a relay connects, and how.
#[derive(Clone, Debug)]
pub(crate) struct Upstream {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) tls: bool,
    pub(crate) ca_pem: String,
    pub(crate) tls_servername: String,
}

impl Upstream {
    /// `host:port`, as audit records name it.
    pub(crate) fn display(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Connect, and complete the TLS handshake when `tls` is on.
    ///
    /// The error text goes into audit records, so it is a sentence, not
    /// a debug dump.
    pub(crate) async fn connect(&self) -> Result<Box<dyn Stream>, String> {
        let config = if self.tls {
            Some(tls::client_config(&self.ca_pem)?)
        } else {
            None
        };
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| connect_error(&e, &self.host, self.port))?;
        let Some(config) = config else {
            return Ok(Box::new(tcp));
        };
        let name = if self.tls_servername.is_empty() {
            &self.host
        } else {
            &self.tls_servername
        };
        tls::handshake(config, name, tcp).await
    }
}

fn connect_error(e: &std::io::Error, host: &str, port: u16) -> String {
    match e.raw_os_error() {
        Some(code) => format!("[Errno {code}] Connect call failed ('{host}', {port})"),
        None => e.to_string(),
    }
}

/// The C library's message for an OS error, lower-cased as asyncio
/// words bind failures (`address already in use`).
fn strerror_lower(e: &std::io::Error) -> String {
    let text = e.to_string();
    let text = text.split(" (os error").next().unwrap_or(&text);
    text.to_lowercase()
}

// ── Listeners and session tracking ──────────────────────

/// How long `stop` waits for sessions to say goodbye before cutting
/// them off.
const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// A relay's protocol half: what to do with one accepted connection.
pub(crate) trait Handler: Send + Sync + 'static {
    /// Serve one client. `shutdown` turns true when the relay stops; the
    /// session says goodbye (`* BYE`, `421`) where the protocol allows and
    /// returns.
    fn handle(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        shutdown: watch::Receiver<bool>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
}

#[derive(Debug)]
struct Running {
    accept: JoinHandle<()>,
    addr: SocketAddr,
    sessions: Arc<Mutex<JoinSet<()>>>,
    shutdown: watch::Sender<bool>,
}

/// A relay's listener and its live sessions.
#[derive(Debug, Default)]
pub(crate) struct Listener {
    running: tokio::sync::Mutex<Option<Running>>,
}

/// Split `listen` (`host:port`) the way the replaced implementation did:
/// at the last colon, an empty host meaning every address.
pub(crate) fn parse_listen(listen: &str) -> Result<(String, u16), String> {
    let (host, port) = listen.rsplit_once(':').unwrap_or(("", listen));
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid listen address: {}", repr_str(listen)));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| "bind(): port must be 0-65535.".to_owned())?;
    let host = if host.is_empty() { "0.0.0.0" } else { host };
    Ok((host.to_owned(), port))
}

impl Listener {
    /// Bind `listen` and serve every connection with `handler`.
    pub(crate) async fn start<H: Handler>(
        &self,
        listen: &str,
        handler: Arc<H>,
    ) -> Result<(), String> {
        let (host, port) = parse_listen(listen)?;
        let listener = TcpListener::bind((host.as_str(), port))
            .await
            .map_err(|e| match e.raw_os_error() {
                Some(code) => format!(
                    "[Errno {code}] error while attempting to bind on address ('{host}', {port}): {}",
                    strerror_lower(&e)
                ),
                None => e.to_string(),
            })?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let sessions = Arc::new(Mutex::new(JoinSet::new()));
        let (shutdown, _) = watch::channel(false);
        let accept = {
            let sessions = Arc::clone(&sessions);
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, peer)) = listener.accept().await else {
                        // EMFILE and friends: back off rather than spin.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    };
                    let session = Arc::clone(&handler).handle(stream, peer, shutdown.subscribe());
                    let mut set = sessions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    // Reap finished sessions so the set holds live ones only.
                    while set.try_join_next().is_some() {}
                    set.spawn(session);
                }
            })
        };
        *self.running.lock().await = Some(Running {
            accept,
            addr,
            sessions,
            shutdown,
        });
        Ok(())
    }

    /// The bound address, once started.
    pub(crate) async fn local_addr(&self) -> Option<SocketAddr> {
        self.running.lock().await.as_ref().map(|r| r.addr)
    }

    /// Close the listener, tell every session to finish, and wait for
    /// them (cutting off any that outlast [`DRAIN_GRACE`]). The port is
    /// free when this returns.
    pub(crate) async fn stop(&self) {
        let Some(running) = self.running.lock().await.take() else {
            return;
        };
        running.accept.abort();
        let _ = running.accept.await;
        let _ = running.shutdown.send(true);
        let mut set = std::mem::take(
            &mut *running
                .sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let drained = tokio::time::timeout(DRAIN_GRACE, async {
            while set.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            set.abort_all();
            while set.join_next().await.is_some() {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_matches_python() {
        assert_eq!(
            split_ws(b"a b  c \r\n", Some(2)),
            [&b"a"[..], b"b", b"c \r\n"]
        );
        assert_eq!(split_ws(b"a b   ", Some(2)), [&b"a"[..], b"b"]);
        assert_eq!(split_ws(b"  ", None), Vec::<&[u8]>::new());
        assert_eq!(split_ws(b"\x0ba\x0cb", None), [&b"a"[..], b"b"]);
    }

    #[test]
    fn rate_specs_parse() {
        assert_eq!(
            parse_rate_limit("30/min"),
            Some((30, Duration::from_secs(60)))
        );
        assert_eq!(
            parse_rate_limit(" 5 / H "),
            Some((5, Duration::from_secs(3600)))
        );
        assert_eq!(parse_rate_limit("5/day"), None);
    }

    #[test]
    fn limiter_caps_and_releases() {
        let l = RateLimiter::new(2, Duration::from_secs(60));
        assert!(l.take() && l.take() && !l.take());
        l.release();
        assert!(l.take());
    }

    #[test]
    fn listen_addresses() {
        assert_eq!(
            parse_listen("127.0.0.1:143").unwrap(),
            ("127.0.0.1".into(), 143)
        );
        assert_eq!(parse_listen(":25").unwrap(), ("0.0.0.0".into(), 25));
        assert_eq!(
            parse_listen("nope").unwrap_err(),
            "invalid listen address: 'nope'"
        );
    }

    #[test]
    fn python_int() {
        assert_eq!(py_int_text(" 1_000 "), Some(1000));
        assert_eq!(py_int_text("1__0"), None);
        assert_eq!(py_int_text("-3"), Some(-3));
        assert_eq!(bytes_repr(b"a'\r\n\x00"), "b\"a'\\r\\n\\x00\"");
    }

    #[tokio::test]
    async fn reader_lines_and_limits() {
        let data: &[u8] = b"one\ntwo\r\nxxxxxxxxxx{5}\r\nlast";
        let mut r = Reader::new(data);
        assert!(matches!(r.read_line(100).await.unwrap(), Line::Data(l) if l == b"one\n"));
        assert!(matches!(r.read_line(100).await.unwrap(), Line::Data(l) if l == b"two\r\n"));
        match r.read_line(5).await.unwrap() {
            Line::TooLong { head, tail } => {
                assert_eq!(head, b"xxxxxxxxxx{5}\r\n");
                assert_eq!(tail, b"xxxxxxxxxx{5}\r\n");
            }
            Line::Data(l) => panic!("{l:?}"),
        }
        assert!(matches!(r.read_line(100).await.unwrap(), Line::Data(l) if l == b"last"));
        assert!(matches!(r.read_line(100).await.unwrap(), Line::Data(l) if l.is_empty()));
    }
}
