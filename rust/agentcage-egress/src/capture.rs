//! The capture writer: `capture.jsonl`, one compact JSON line per flow,
//! with rotation, `min_action` and domain filters.
//!
//! Each line records a flow's request and response twice, as the
//! `inbound` (what the cage saw) and `outbound` (what went on the wire)
//! views `cage har` reads. Both views hold the same redacted content: the
//! request is snapshotted with placeholders before injection and replaced
//! after the upstream send by the request redacted back to placeholders,
//! and the response is snapshotted after its secrets were redacted. So no
//! real secret, minted token or literal secret the cage sent ever reaches
//! the file, which the cage can read.
//!
//! Two layers:
//!
//! * [`CaptureWriter`] is the file: snapshots, filters, entry lines,
//!   rotation, and per-flow WebSocket frame buffers.
//! * [`Capture`] is what the pipeline holds: the live writer (rebuilt on
//!   reload when the `capture` section changes), plus each in-flight
//!   flow's staged entry between the request and response hooks, and a
//!   WebSocket entry held open from its 101 until the socket ends.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use agentcage_core::har::datetime::DateTime;
use base64::Engine as _;

use crate::audit::{Decision, Direction, Redactor, inspectors_json};
use crate::config::{self, Config, Mapping, Value};
use crate::inspect::Verdict;
use crate::json::{self, Json, object};
use crate::message::{Headers, Request, Response};

/// `capture.max_body_size` when unset: each body (and each WebSocket
/// frame) is cut to this many bytes. 0 means no limit.
pub const DEFAULT_MAX_BODY_SIZE: i64 = 10_485_760;

/// `capture.max_file_size` when unset: the file rolls over to `.1` past
/// this many bytes. 0 disables rotation.
pub const DEFAULT_MAX_FILE_SIZE: i64 = 134_217_728;

/// Per-flow bound on buffered WebSocket frames.
///
/// A WebSocket's entry is written when the socket ends, so every frame it
/// records sits in memory until then, and a socket can stay open for
/// hours. On top of the per-frame `max_body_size` cut, one flow keeps at
/// most this many frames and at most `max_body_size` bytes of frame data
/// in total ([`WS_DEFAULT_TOTAL`] when `max_body_size` is 0: an unlimited
/// body still ends, a socket need not). Frames past either bound are
/// counted, not kept, and the entry reports them as
/// `ws_messages_omitted`. The sizes keep a WebSocket entry inside the
/// watcher's single-line cap.
pub const WS_MAX_MESSAGES: usize = 4096;

/// A flow's WebSocket frame-data total when `max_body_size` is 0.
pub const WS_DEFAULT_TOTAL: i64 = 10_485_760;

/// The lowest decision `min_action` lets through.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum MinAction {
    /// Record everything (also what an unknown value means).
    #[default]
    All,
    /// Flagged and blocked flows only.
    Flag,
    /// Blocked flows only.
    Block,
}

impl MinAction {
    /// `str(cfg.get("min_action") or "all")`, with the old documented
    /// spellings (`allowed`, `flagged`, `blocked`) as aliases. Any other
    /// value records everything, as it always did (the host rejects
    /// unknown values before they get here).
    fn from_value(value: Option<&Value>) -> Self {
        match config::as_str(value) {
            Some("flag" | "flagged") => Self::Flag,
            Some("block" | "blocked") => Self::Block,
            _ => Self::All,
        }
    }

    fn level(self) -> u8 {
        match self {
            Self::All => 0,
            Self::Flag => 1,
            Self::Block => 2,
        }
    }
}

fn decision_level(decision: &str) -> u8 {
    match decision {
        "flagged" => 1,
        "blocked" => 2,
        _ => 0,
    }
}

/// Why a `capture` section was refused. The live writer is kept.
#[derive(Debug)]
pub enum CaptureError {
    /// A size key is not an integer (`int(x)` would have raised).
    InvalidSetting {
        /// The key.
        key: &'static str,
    },
    /// The file could not be opened.
    Io(std::io::Error),
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSetting { key } => write!(f, "capture.{key} is not an integer"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CaptureError {}

/// The `capture` section, parsed with the replaced implementation's
/// coercions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureSettings {
    /// Per-body cut in bytes; 0 = unlimited. Negative values behave as a
    /// Python slice end would (cut that many bytes off the end), which is
    /// what the replaced implementation did with them.
    pub max_body_size: i64,
    /// `min_action`.
    pub min_action: MinAction,
    /// Only these hosts (and their subdomains), when non-empty.
    pub domains: Vec<String>,
    /// Never these hosts (and their subdomains).
    pub exclude_domains: Vec<String>,
    /// Rotation threshold in bytes; 0 = never rotate.
    pub max_file_size: u64,
}

impl Default for CaptureSettings {
    fn default() -> Self {
        Self {
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            min_action: MinAction::All,
            domains: Vec::new(),
            exclude_domains: Vec::new(),
            max_file_size: DEFAULT_MAX_FILE_SIZE.unsigned_abs(),
        }
    }
}

impl CaptureSettings {
    /// Parse a `capture` section.
    ///
    /// # Errors
    ///
    /// `max_body_size` or `max_file_size` is present but not something
    /// `int()` accepts (null included).
    pub fn from_section(section: &Mapping) -> Result<Self, CaptureError> {
        let int = |key: &'static str, default: i64| match config::mget(section, key) {
            None => Ok(default),
            Some(v) => config::as_i64(Some(v)).ok_or(CaptureError::InvalidSetting { key }),
        };
        Ok(Self {
            max_body_size: int("max_body_size", DEFAULT_MAX_BODY_SIZE)?,
            min_action: MinAction::from_value(config::mget(section, "min_action")),
            domains: config::str_list(config::mget(section, "domains")),
            exclude_domains: config::str_list(config::mget(section, "exclude_domains")),
            max_file_size: int("max_file_size", DEFAULT_MAX_FILE_SIZE)?
                .max(0)
                .unsigned_abs(),
        })
    }

    /// Whether a flow with `decision` to `host` is recorded: `min_action`,
    /// then the domain filters.
    #[must_use]
    pub fn should_capture(&self, decision: &str, host: &str) -> bool {
        decision_level(decision) >= self.min_action.level() && self.captures_host(host)
    }

    /// The domain filters alone. A WebSocket's decision can still escalate
    /// after its upgrade, so at the 101 only this half is final.
    #[must_use]
    pub fn captures_host(&self, host: &str) -> bool {
        if !self.domains.is_empty() && !self.domains.iter().any(|d| domain_matches(d, host)) {
            return false;
        }
        !self.exclude_domains.iter().any(|d| domain_matches(d, host))
    }
}

/// `host` is `pattern` or a subdomain of it (case-sensitive, as before).
fn domain_matches(pattern: &str, host: &str) -> bool {
    host == pattern
        || host
            .strip_suffix(pattern)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// `content[:n]` with Python slice semantics for a negative `n`.
fn py_prefix(content: &[u8], n: i64) -> &[u8] {
    let len = content.len();
    let end = if n >= 0 {
        usize::try_from(n).unwrap_or(usize::MAX).min(len)
    } else {
        len.saturating_sub(usize::try_from(n.unsigned_abs()).unwrap_or(usize::MAX))
    };
    &content[..end]
}

fn len_i64(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn headers_json(headers: &Headers) -> Json {
    Json::Array(
        headers
            .to_strings()
            .into_iter()
            .map(|(k, v)| Json::Array(vec![Json::Str(k), Json::Str(v)]))
            .collect(),
    )
}

/// Object fields in order, spliced into a snapshot.
type Fields = Vec<(String, Json)>;

#[derive(Debug, Default)]
struct WsBuffer {
    messages: Vec<Json>,
    data_bytes: i64,
    omitted: usize,
}

/// One complete capture entry, as [`CaptureWriter::write_entry`] writes
/// it.
#[derive(Clone, Debug, PartialEq)]
pub struct CaptureEntry {
    /// The flow's id.
    pub flow_id: String,
    /// Outbound or inbound.
    pub direction: Direction,
    /// The decision (a WebSocket's escalated by its frames).
    pub decision: Decision,
    /// The request host.
    pub host: String,
    /// The request method.
    pub method: String,
    /// The request path and query.
    pub path: String,
    /// The verdicts, as [`capture_inspectors`] lists them.
    pub inspectors: Json,
    /// The cage-side request snapshot.
    pub inbound_req: Json,
    /// The cage-side response snapshot.
    pub inbound_resp: Json,
    /// The wire-side request snapshot.
    pub outbound_req: Json,
    /// The wire-side response snapshot.
    pub outbound_resp: Json,
    /// A WebSocket's recorded frames (omitted from the line when empty).
    pub ws_messages: Vec<Json>,
    /// Frames past the bounds (omitted from the line when 0).
    pub ws_messages_omitted: usize,
}

/// `capture.jsonl` itself.
pub struct CaptureWriter {
    settings: CaptureSettings,
    path: PathBuf,
    rotated: PathBuf,
    file: Option<File>,
    size: u64,
    ws_buffers: HashMap<String, WsBuffer>,
    ws_total: i64,
    clock: fn() -> DateTime,
}

impl std::fmt::Debug for CaptureWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureWriter")
            .field("path", &self.path)
            .field("settings", &self.settings)
            .field("size", &self.size)
            .field("ws_flows", &self.ws_buffers.len())
            .finish_non_exhaustive()
    }
}

impl CaptureWriter {
    /// Open `path` for appending (its directory created if missing).
    ///
    /// # Errors
    ///
    /// The directory or file cannot be created or opened.
    pub fn open(settings: CaptureSettings, path: &Path) -> Result<Self, CaptureError> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(CaptureError::Io)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(CaptureError::Io)?;
        let size = file.metadata().map_or(0, |m| m.len());
        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        let ws_total = if settings.max_body_size == 0 {
            WS_DEFAULT_TOTAL
        } else {
            settings.max_body_size
        };
        Ok(Self {
            settings,
            path: path.to_owned(),
            rotated: PathBuf::from(rotated),
            file: Some(file),
            size,
            ws_buffers: HashMap::new(),
            ws_total,
            clock: DateTime::now_utc,
        })
    }

    /// Stamp entries from `clock` instead of the system clock (tests).
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> DateTime) -> Self {
        self.clock = clock;
        self
    }

    /// The settings this writer was built from.
    #[must_use]
    pub fn settings(&self) -> &CaptureSettings {
        &self.settings
    }

    /// See [`CaptureSettings::should_capture`].
    #[must_use]
    pub fn should_capture(&self, decision: &str, host: &str) -> bool {
        self.settings.should_capture(decision, host)
    }

    /// See [`CaptureSettings::captures_host`].
    #[must_use]
    pub fn captures_host(&self, host: &str) -> bool {
        self.settings.captures_host(host)
    }

    /// A body as `(text, encoding, truncated, original size)`: cut to
    /// `max_body_size`, then UTF-8 text if it decodes (a cut through a
    /// character makes it binary), else standard base64.
    fn encode_body(&self, content: &[u8]) -> (String, Option<&'static str>, bool, usize) {
        let original = content.len();
        let max = self.settings.max_body_size;
        let (kept, truncated) = if max != 0 && len_i64(original) > max {
            (py_prefix(content, max), true)
        } else {
            (content, false)
        };
        match std::str::from_utf8(kept) {
            Ok(text) => (text.to_owned(), None, truncated, original),
            Err(_) => (
                base64::engine::general_purpose::STANDARD.encode(kept),
                Some("base64"),
                truncated,
                original,
            ),
        }
    }

    fn body_fields(&self, content: &[u8]) -> (Fields, Fields) {
        let (body, encoding, truncated, original) = self.encode_body(content);
        let head = vec![
            ("body".to_owned(), Json::Str(body)),
            (
                "bodyEncoding".to_owned(),
                encoding.map_or(Json::Null, Json::string),
            ),
            ("bodySize".to_owned(), Json::Int(len_i64(content.len()))),
        ];
        let tail = if truncated {
            vec![
                ("bodyTruncated".to_owned(), Json::Bool(true)),
                ("bodyOriginalSize".to_owned(), Json::Int(len_i64(original))),
            ]
        } else {
            Vec::new()
        };
        (head, tail)
    }

    /// A request snapshot: `{method, url, httpVersion, headers: [[k, v],
    /// …], body, bodyEncoding, bodySize, [bodyTruncated,
    /// bodyOriginalSize]}`. `content` is the decoded body (Content-Encoding
    /// removed).
    #[must_use]
    pub fn snapshot_request(&self, req: &Request, content: &[u8]) -> Json {
        let (body, tail) = self.body_fields(content);
        let mut pairs = vec![
            ("method".to_owned(), Json::string(req.method.clone())),
            ("url".to_owned(), Json::string(req.url())),
            (
                "httpVersion".to_owned(),
                Json::string(req.http_version.clone()),
            ),
            ("headers".to_owned(), headers_json(&req.headers)),
        ];
        pairs.extend(body);
        pairs.extend(tail);
        Json::Object(pairs)
    }

    /// A response snapshot: `{status, statusText, httpVersion, headers,
    /// body, bodyEncoding, bodySize, mimeType, [bodyTruncated,
    /// bodyOriginalSize]}`, or `{}` when there is no response. `content`
    /// is the decoded body.
    #[must_use]
    pub fn snapshot_response(&self, resp: Option<(&Response, &[u8])>) -> Json {
        let Some((resp, content)) = resp else {
            return Json::Object(Vec::new());
        };
        let (body, tail) = self.body_fields(content);
        let mut pairs = vec![
            ("status".to_owned(), Json::Int(i64::from(resp.status))),
            ("statusText".to_owned(), Json::string(resp.reason.clone())),
            (
                "httpVersion".to_owned(),
                Json::string(resp.http_version.clone()),
            ),
            ("headers".to_owned(), headers_json(&resp.headers)),
        ];
        pairs.extend(body);
        pairs.push((
            "mimeType".to_owned(),
            Json::string(resp.headers.get("content-type").unwrap_or_default()),
        ));
        pairs.extend(tail);
        Json::Object(pairs)
    }

    /// The entry as a JSON object, stamped `ts`.
    fn entry_json(entry: &CaptureEntry, ts: &DateTime) -> Json {
        let mut out = object([
            ("ts", Json::string(ts.isoformat())),
            ("flow_id", Json::string(entry.flow_id.clone())),
            ("direction", Json::string(entry.direction.as_str())),
            ("decision", Json::string(entry.decision.as_str())),
            ("host", Json::string(entry.host.clone())),
            ("method", Json::string(entry.method.clone())),
            ("path", Json::string(entry.path.clone())),
            ("inspectors", entry.inspectors.clone()),
            (
                "inbound",
                object([
                    ("request", entry.inbound_req.clone()),
                    ("response", entry.inbound_resp.clone()),
                ]),
            ),
            (
                "outbound",
                object([
                    ("request", entry.outbound_req.clone()),
                    ("response", entry.outbound_resp.clone()),
                ]),
            ),
        ]);
        if !entry.ws_messages.is_empty() {
            out.set("ws_messages", Json::Array(entry.ws_messages.clone()));
        }
        if entry.ws_messages_omitted != 0 {
            out.set(
                "ws_messages_omitted",
                Json::Int(len_i64(entry.ws_messages_omitted)),
            );
        }
        out
    }

    /// Append one entry as a compact JSON line, then rotate if the file
    /// passed `max_file_size`.
    ///
    /// # Errors
    ///
    /// The write failed.
    pub fn write_entry(&mut self, entry: &CaptureEntry) -> std::io::Result<()> {
        let mut line = json::to_compact_string(&Self::entry_json(entry, &(self.clock)()));
        line.push('\n');
        let file = match self.file.as_mut() {
            Some(file) => file,
            None => self.file.insert(open_append(&self.path)?),
        };
        file.write_all(line.as_bytes())?;
        file.flush()?;
        // The size is tracked from what was written rather than stat()ed
        // per entry.
        self.size += u64::try_from(line.len()).unwrap_or(u64::MAX);
        self.maybe_rotate();
        Ok(())
    }

    /// Roll the file over once it passes `max_file_size`, keeping one
    /// generation (`capture.jsonl.1`), so the on-disk ceiling is twice the
    /// cap. Rename + reopen: the watcher's tail tracks `(dev, ino)` and
    /// treats the new inode as a reset, and `cage har` reads `.1` before
    /// the live file, so neither loses the older half.
    fn maybe_rotate(&mut self) {
        if self.settings.max_file_size == 0 || self.size < self.settings.max_file_size {
            return;
        }
        drop(self.file.take());
        if let Err(e) = std::fs::rename(&self.path, &self.rotated) {
            // Keep appending rather than drop capture entirely.
            eprintln!("agentcage: capture rotation failed: {e}");
        }
        match open_append(&self.path) {
            Ok(file) => self.file = Some(file),
            Err(e) => eprintln!("agentcage: capture reopen failed: {e}"),
        }
        self.size = 0;
    }

    /// Record one WebSocket message for `flow_id`, within the flow's
    /// bounds.
    ///
    /// `content` must already be in its capture form (redacted by the
    /// caller); `ts` is the frame's arrival time, `isoformat()`ted. Text
    /// messages are stored as text (opcode 1, a character cut in half by
    /// the bound becoming U+FFFD); binary ones (opcode 2) as text when
    /// they decode as UTF-8, else base64 with `dataEncoding`. Data past
    /// `max_body_size`, or past what is left of the flow's total, is cut
    /// and marked `dataTruncated`; a message arriving with nothing left,
    /// or past [`WS_MAX_MESSAGES`], is only counted.
    pub fn add_ws_frame(
        &mut self,
        flow_id: &str,
        from_client: bool,
        is_text: bool,
        content: &[u8],
        ts: &str,
        decision: Decision,
    ) {
        let max_body = self.settings.max_body_size;
        let total = self.ws_total;
        let buf = self.ws_buffers.entry(flow_id.to_owned()).or_default();
        let room = total - buf.data_bytes;
        if buf.messages.len() >= WS_MAX_MESSAGES || room <= 0 {
            buf.omitted += 1;
            return;
        }
        let limit = if max_body == 0 {
            room
        } else {
            max_body.min(room)
        };
        let kept = py_prefix(content, limit);
        let mut msg = object([
            (
                "type",
                Json::string(if from_client { "send" } else { "receive" }),
            ),
            ("ts", Json::string(ts)),
            ("opcode", Json::Int(if is_text { 1 } else { 2 })),
        ]);
        if is_text {
            msg.set("data", Json::string(String::from_utf8_lossy(kept)));
        } else if let Ok(text) = std::str::from_utf8(kept) {
            msg.set("data", Json::string(text));
        } else {
            msg.set(
                "data",
                Json::string(base64::engine::general_purpose::STANDARD.encode(kept)),
            );
            msg.set("dataEncoding", Json::string("base64"));
        }
        if kept.len() < content.len() {
            msg.set("dataTruncated", Json::Bool(true));
            msg.set("dataOriginalSize", Json::Int(len_i64(content.len())));
        }
        if decision != Decision::Allowed {
            msg.set("decision", Json::string(decision.as_str()));
        }
        buf.data_bytes += len_i64(kept.len());
        buf.messages.push(msg);
    }

    /// Take a flow's buffered WebSocket messages and how many were
    /// omitted (`([], 0)` for a flow with none).
    pub fn pop_ws_buffer(&mut self, flow_id: &str) -> (Vec<Json>, usize) {
        self.ws_buffers
            .remove(flow_id)
            .map_or_else(Default::default, |b| (b.messages, b.omitted))
    }

    /// Take over `other`'s buffered WebSocket frames: a reload replaced
    /// the writer while sockets were open, and the new one must write
    /// their entries. Each buffer keeps what it already used of its
    /// bound; frames from here on are measured against this writer's
    /// limits.
    pub fn adopt_ws_buffers(&mut self, other: &mut Self) {
        self.ws_buffers.extend(other.ws_buffers.drain());
    }
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// A capture entry's `inspectors`: the verdicts as audit lists them, each
/// reason redacted as an audit record is. `capture.jsonl` is readable by
/// the cage, and a response inspector's reason can quote a secret the
/// server echoed (it sees the response before it is redacted).
#[must_use]
pub fn capture_inspectors(results: &[Verdict], redactor: &dyn Redactor) -> Json {
    let mut inspectors = inspectors_json(results);
    redactor.redact(&mut inspectors);
    inspectors
}

/// The identity of a flow's capture entry, read from the request when it
/// is staged (or recorded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowInfo {
    /// The flow's id, unique for the life of the process.
    pub id: String,
    /// Outbound or inbound.
    pub direction: Direction,
    /// The request's decision.
    pub decision: Decision,
    /// The request host.
    pub host: String,
    /// The request method.
    pub method: String,
    /// The request path and query.
    pub path: String,
}

#[derive(Debug)]
struct Pending {
    info: FlowInfo,
    inspectors: Json,
    inbound_req: Json,
    outbound_req: Json,
    inbound_resp: Json,
    outbound_resp: Json,
    websocket: bool,
}

impl Pending {
    fn entry(&self, ws_messages: Vec<Json>, ws_messages_omitted: usize) -> CaptureEntry {
        CaptureEntry {
            flow_id: self.info.id.clone(),
            direction: self.info.direction,
            decision: self.info.decision,
            host: self.info.host.clone(),
            method: self.info.method.clone(),
            path: self.info.path.clone(),
            inspectors: self.inspectors.clone(),
            inbound_req: self.inbound_req.clone(),
            inbound_resp: self.inbound_resp.clone(),
            outbound_req: self.outbound_req.clone(),
            outbound_resp: self.outbound_resp.clone(),
            ws_messages,
            ws_messages_omitted,
        }
    }
}

/// How [`Capture::reconfigure`] left the writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reconfigured {
    /// The `capture` section is the one the live writer was built from.
    Unchanged,
    /// Capture is off.
    Disabled,
    /// A writer was (re)built from the new section.
    Enabled,
}

#[derive(Debug, Default)]
struct State {
    writer: Option<CaptureWriter>,
    section: Option<Mapping>,
    pending: HashMap<String, Pending>,
}

impl State {
    fn write(&mut self, entry: &CaptureEntry) {
        if let Some(writer) = self.writer.as_mut()
            && let Err(e) = writer.write_entry(entry)
        {
            eprintln!("agentcage: capture write failed: {e}");
        }
    }
}

/// The pipeline's handle on capture: the live writer and every in-flight
/// flow's staged entry.
///
/// The request hook stages a flow's entry ([`Capture::stage`]); the
/// response hook completes and writes it
/// ([`Capture::finish_response`]), or keeps a WebSocket's entry open
/// until the socket ends ([`Capture::finish_websocket`]); a flow that
/// errors before its response is released ([`Capture::release`]) so no
/// staged snapshot outlives its flow.
#[derive(Debug)]
pub struct Capture {
    path: Option<PathBuf>,
    clock: fn() -> DateTime,
    state: Mutex<State>,
}

impl Capture {
    /// A capture handle writing to `$AGENTCAGE_CAPTURE` (unset or empty:
    /// capture can never be enabled). Disabled until
    /// [`reconfigure`](Self::reconfigure).
    #[must_use]
    pub fn from_env() -> Self {
        Self::new(
            std::env::var_os("AGENTCAGE_CAPTURE")
                .filter(|p| !p.is_empty())
                .map(PathBuf::from),
        )
    }

    /// A capture handle writing to `path` (`None`: never enabled).
    #[must_use]
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            clock: DateTime::now_utc,
            state: Mutex::new(State::default()),
        }
    }

    /// Stamp entries from `clock` (tests).
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> DateTime) -> Self {
        self.clock = clock;
        self
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Build, rebuild or drop the writer from the config's `capture`
    /// section. Called on load and on every reload.
    ///
    /// A no-op when the section equals the one the live writer was built
    /// from, so an unrelated edit never reopens the file. Disabled
    /// (`enable_har` off, or no capture path): the writer is closed and
    /// every staged entry dropped. Enabled or changed: the new writer is
    /// built before the old one is closed, so a bad edit keeps the working
    /// writer (and is retried on the next edit); staged entries are kept
    /// and complete under the new writer, which adopts the open
    /// WebSockets' buffered frames.
    ///
    /// # Errors
    ///
    /// The new section was refused; the previous writer (if any) stays.
    pub fn reconfigure(&self, cfg: &Config) -> Result<Reconfigured, CaptureError> {
        let section = match cfg.get("capture") {
            Some(Value::Mapping(m)) => m.clone(),
            Some(other) if config::truthy(other) => {
                eprintln!(
                    "agentcage: capture config is not a mapping (got {}) — capture disabled",
                    python_type_name(other)
                );
                Mapping::new()
            }
            _ => Mapping::new(),
        };
        let mut state = self.lock();
        if state.section.as_ref() == Some(&section) {
            return Ok(Reconfigured::Unchanged);
        }
        let enabled = config::mget(&section, "enable_har").is_some_and(config::truthy);
        let Some(path) = self.path.clone().filter(|_| enabled) else {
            if state.writer.take().is_some() {
                eprintln!("agentcage: capture disabled");
            }
            state.pending.clear();
            state.section = Some(section);
            return Ok(Reconfigured::Disabled);
        };
        let built = CaptureSettings::from_section(&section)
            .and_then(|settings| CaptureWriter::open(settings, &path));
        let mut writer = match built {
            Ok(writer) => writer.with_clock(self.clock),
            Err(e) => {
                eprintln!("agentcage: cannot init capture: {e}");
                return Err(e);
            }
        };
        if let Some(mut old) = state.writer.take() {
            writer.adopt_ws_buffers(&mut old);
        }
        state.writer = Some(writer);
        state.section = Some(section);
        eprintln!("agentcage: capture enabled → {}", path.display());
        Ok(Reconfigured::Enabled)
    }

    /// Whether a writer is live.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.lock().writer.is_some()
    }

    /// How many flows have a staged or open entry (bounded-state checks).
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.lock().pending.len()
    }

    /// The live writer's filters for a flow; `false` while disabled.
    #[must_use]
    pub fn should_capture(&self, decision: Decision, host: &str) -> bool {
        self.lock()
            .writer
            .as_ref()
            .is_some_and(|w| w.should_capture(decision.as_str(), host))
    }

    /// Snapshot a request with the live writer's limits, `None` while
    /// disabled. The request hook takes this before injection, so it
    /// holds placeholders.
    #[must_use]
    pub fn snapshot_request(&self, req: &Request, content: &[u8]) -> Option<Json> {
        self.lock()
            .writer
            .as_ref()
            .map(|w| w.snapshot_request(req, content))
    }

    /// Record a request blocked by the request-side chain, never
    /// forwarded: one entry with the same request (and the 403 response)
    /// in both views, written now if the filters pass for `blocked`.
    ///
    /// `req` must already be redacted (a literal secret the cage sent
    /// swapped for its placeholder); the caller can check
    /// [`should_capture`](Self::should_capture) first to skip that work.
    pub fn record_blocked_request(
        &self,
        flow: &FlowInfo,
        inspectors: Json,
        req: (&Request, &[u8]),
        response: Option<(&Response, &[u8])>,
    ) {
        let mut state = self.lock();
        let Some(writer) = state.writer.as_ref() else {
            return;
        };
        if !writer.should_capture(Decision::Blocked.as_str(), &flow.host) {
            return;
        }
        let request = writer.snapshot_request(req.0, req.1);
        let response = writer.snapshot_response(response);
        let entry = CaptureEntry {
            flow_id: flow.id.clone(),
            direction: flow.direction,
            decision: Decision::Blocked,
            host: flow.host.clone(),
            method: flow.method.clone(),
            path: flow.path.clone(),
            inspectors,
            inbound_req: request.clone(),
            inbound_resp: response.clone(),
            outbound_req: request,
            outbound_resp: response,
            ws_messages: Vec::new(),
            ws_messages_omitted: 0,
        };
        state.write(&entry);
    }

    /// Stage an allowed or flagged request's entry for the response hook
    /// to complete. `request` is the snapshot taken before injection
    /// ([`snapshot_request`](Self::snapshot_request)); it stands for both
    /// views until [`refresh_request`](Self::refresh_request) replaces it.
    /// A no-op while disabled.
    pub fn stage(&self, flow: FlowInfo, inspectors: Json, request: Json) {
        let mut state = self.lock();
        if state.writer.is_none() {
            return;
        }
        state.pending.insert(
            flow.id.clone(),
            Pending {
                info: flow,
                inspectors,
                inbound_req: request.clone(),
                outbound_req: request,
                inbound_resp: Json::Object(Vec::new()),
                outbound_resp: Json::Object(Vec::new()),
                websocket: false,
            },
        );
    }

    /// Drop a flow's staged entry without writing it (a request-blocked
    /// flow reaching the response hook).
    pub fn discard(&self, flow_id: &str) {
        self.lock().pending.remove(flow_id);
    }

    /// Replace a staged entry's request, for both views, with the request
    /// redacted after the upstream send, and refresh its `path` and
    /// `host` from it: the request hook read them after injection, so a
    /// rule that injects into the URL had its secret there.
    pub fn refresh_request(&self, flow_id: &str, redacted: &Request, content: &[u8]) {
        let mut state = self.lock();
        let State {
            writer, pending, ..
        } = &mut *state;
        let (Some(writer), Some(staged)) = (writer.as_ref(), pending.get_mut(flow_id)) else {
            return;
        };
        let snapshot = writer.snapshot_request(redacted, content);
        staged.inbound_req = snapshot.clone();
        staged.outbound_req = snapshot;
        staged.info.path.clone_from(&redacted.path);
        staged.info.host.clone_from(&redacted.host);
    }

    /// Complete a flow whose response the response-side chain blocked:
    /// the entry is written as `blocked` (no filter check, as before),
    /// with `inspectors` (the response chain's, already through
    /// [`capture_inspectors`]) appended to the request's, and `response`
    /// (the redacted 403 the cage got) in both views.
    pub fn finish_blocked_response(
        &self,
        flow_id: &str,
        inspectors: Json,
        response: (&Response, &[u8]),
    ) {
        let mut state = self.lock();
        let Some(mut pending) = state.pending.remove(flow_id) else {
            return;
        };
        let Some(writer) = state.writer.as_ref() else {
            return;
        };
        let snapshot = writer.snapshot_response(Some(response));
        if let (Json::Array(mine), Json::Array(more)) = (&mut pending.inspectors, inspectors) {
            mine.extend(more);
        }
        pending.info.decision = Decision::Blocked;
        pending.inbound_resp = snapshot.clone();
        pending.outbound_resp = snapshot;
        state.write(&pending.entry(Vec::new(), 0));
    }

    /// Complete a flow at its (redacted) response.
    ///
    /// A plain HTTP flow is written now if the filters pass. The 101 of a
    /// WebSocket upgrade arrives before any frame, so its entry is kept
    /// open with both HTTP halves for [`add_ws_frame`](Self::add_ws_frame)
    /// and [`finish_websocket`](Self::finish_websocket); only the domain
    /// filters are final at the 101 (the decision can still escalate).
    pub fn finish_response(
        &self,
        flow_id: &str,
        response: (&Response, &[u8]),
        websocket_upgrade: bool,
    ) {
        let mut state = self.lock();
        let Some(mut pending) = state.pending.remove(flow_id) else {
            return;
        };
        let Some(writer) = state.writer.as_ref() else {
            return;
        };
        let snapshot = writer.snapshot_response(Some(response));
        if websocket_upgrade {
            if writer.captures_host(&pending.info.host) {
                pending.inbound_resp = snapshot.clone();
                pending.outbound_resp = snapshot;
                pending.websocket = true;
                state.pending.insert(flow_id.to_owned(), pending);
            }
        } else if writer.should_capture(pending.info.decision.as_str(), &pending.info.host) {
            pending.inbound_resp = snapshot.clone();
            pending.outbound_resp = snapshot;
            state.write(&pending.entry(Vec::new(), 0));
        }
    }

    /// Record one WebSocket message on the flow's open entry (a no-op for
    /// a flow without one) and escalate the entry's decision to the worst
    /// of its frames'.
    ///
    /// `recorded` is the message as it arrived with every secret swapped
    /// for its placeholder: for a cage-to-world message the placeholder
    /// form the cage sent, never the injected value; a dropped message is
    /// redacted the same way. `ts` is its arrival time, taken before the
    /// inspectors ran.
    pub fn add_ws_frame(
        &self,
        flow_id: &str,
        from_client: bool,
        is_text: bool,
        recorded: &[u8],
        ts: &str,
        decision: Decision,
    ) {
        let mut state = self.lock();
        let State {
            writer, pending, ..
        } = &mut *state;
        let (Some(writer), Some(staged)) = (writer.as_mut(), pending.get_mut(flow_id)) else {
            return;
        };
        if !staged.websocket {
            return;
        }
        writer.add_ws_frame(flow_id, from_client, is_text, recorded, ts, decision);
        staged.info.decision = staged.info.decision.max(decision);
    }

    /// Write a flow's open WebSocket entry with the frames recorded so
    /// far, then release everything the flow holds.
    ///
    /// Called when the socket ends, cleanly or not; whichever of this and
    /// [`release`](Self::release) comes first writes the entry and the
    /// other finds nothing. `min_action` is applied here, against the
    /// decision the frames escalated. The entry goes to whichever writer
    /// is live now, so one swapped in by a reload (it adopted the frames)
    /// still records it.
    pub fn finish_websocket(&self, flow_id: &str) {
        let mut state = self.lock();
        let State {
            writer, pending, ..
        } = &mut *state;
        let mut entry = None;
        if let (Some(w), Some(staged)) = (writer.as_mut(), pending.get(flow_id))
            && staged.websocket
        {
            let (messages, omitted) = w.pop_ws_buffer(flow_id);
            if w.should_capture(staged.info.decision.as_str(), &staged.info.host) {
                entry = Some(staged.entry(messages, omitted));
            }
        }
        if let Some(entry) = entry {
            state.write(&entry);
        }
        Self::release_locked(&mut state, flow_id);
    }

    /// The flow ended in an error (upstream refused or reset, client gone,
    /// body cap, internal failure) before or after its response.
    ///
    /// A staged HTTP entry is dropped, not written: there is no response
    /// half to pair it with and the audit log already has the decision. An
    /// open WebSocket entry has both halves and is written with its frames
    /// so far ([`finish_websocket`](Self::finish_websocket)). Either way
    /// nothing the flow staged outlives it.
    pub fn release(&self, flow_id: &str) {
        self.finish_websocket(flow_id);
    }

    fn release_locked(state: &mut State, flow_id: &str) {
        state.pending.remove(flow_id);
        if let Some(writer) = state.writer.as_mut() {
            writer.pop_ws_buffer(flow_id);
        }
    }
}

fn python_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Sequence(_) => "list",
        Value::Mapping(_) => "dict",
        Value::Tagged(_) => "object",
    }
}

#[cfg(test)]
mod tests;
