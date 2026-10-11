//! IMAP relay: a stateful TCP proxy that injects the `LOGIN` credentials
//! and enforces a command and folder policy.
//!
//! Threat model: the cage holds no IMAP credentials. It connects in
//! plaintext, with no client auth (the cage network is single-tenant), to
//! a listener in the egress. The relay holds the upstream credentials in
//! its own memory only, opens an authenticated (normally TLS) connection
//! to the real server, and bridges the post-auth byte stream, applying
//! policy to every command from the cage.
//!
//! Handshake: the relay greets the cage with `* PREAUTH ...`, IMAP's
//! signal that the connection is already authenticated. A `LOGIN` or
//! `AUTHENTICATE` the cage sends anyway is answered locally and never
//! reaches the upstream.
//!
//! Upstream TLS is implicit (port 993) or none; there is no STARTTLS.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, watch};
use unicode_normalization::UnicodeNormalization;

use super::{
    Line, Listener, Reader, RelaySettings, SessionError, Upstream, ascii_lossy, audit, bytes_repr,
    relay_log, s, split_str_ws, split_ws, split_ws_ranges,
};
use crate::audit::AuditSink;
use crate::config::{Mapping, Value};
use agentcage_core::python::repr_str;

const LOGGER: &str = "agentcage.relays.imap";

// ── Policy tables ───────────────────────────────────────

/// Commands that mutate mailbox state, refused in `write_mode: none`.
///
/// `CLOSE` is here because RFC 3501 §6.4.2 makes it expunge every
/// `\Deleted` message in the selected mailbox; refusing `STORE` stops this
/// relay from setting the flag, not another client sharing the mailbox.
/// `REPLACE` (RFC 8508) is an atomic `APPEND` plus `EXPUNGE`. `SETQUOTA`
/// (RFC 9208) and `SETANNOTATION` (Cyrus) change account and mailbox
/// settings; RFC 5257 message annotations are written with `STORE`,
/// already refused whole.
const DENY_COMMANDS_READONLY: &[&str] = &[
    "APPEND",
    "REPLACE",
    "DELETE",
    "STORE",
    "EXPUNGE",
    "CLOSE",
    "CREATE",
    "RENAME",
    "MOVE",
    "SETMETADATA",
    "SETANNOTATION",
    "SETQUOTA",
    "SETACL",
    "DELETEACL",
    "COPY",
];

/// Commands refused in `write_mode: organise`: everything that destroys
/// mail or restructures the mailbox. `MOVE`, `COPY` and `STORE` are absent
/// on purpose (filing and flagging are the point of the mode); so is
/// `CREATE`, since making a folder is recoverable. `CLOSE` expunges as a
/// side effect (RFC 3501 §6.4.2); `RENAME` can silently break the
/// server-side filters that refer to folders by name; `APPEND` fabricates
/// mail; `REPLACE` is `APPEND` plus `EXPUNGE`. Annotation writes through
/// `STORE ... ANNOTATION` are refused by [`store_writes_annotation`].
const DENY_COMMANDS_ORGANISE: &[&str] = &[
    "EXPUNGE",
    "CLOSE",
    "APPEND",
    "REPLACE",
    "DELETE",
    "RENAME",
    "SETMETADATA",
    "SETANNOTATION",
    "SETQUOTA",
    "SETACL",
    "DELETEACL",
];

/// `UID` forms refused in `organise`. `UID STORE`/`COPY`/`MOVE` stay
/// allowed; the `\Deleted` flag is filtered by [`store_adds_deleted`].
const UID_DENY_ORGANISE: &[&str] = &["EXPUNGE", "REPLACE"];

/// `UID` subcommands that write. `UID FETCH` and `UID SEARCH` are reads,
/// and clients use them for everything because UIDs are stable.
const UID_WRITE_SUBCOMMANDS: &[&str] = &["STORE", "COPY", "MOVE", "EXPUNGE", "REPLACE"];

/// Commands refused in every `write_mode`, `full` included, because each
/// would take the byte stream out of the relay's sight: `COMPRESS`
/// (RFC 4978) switches both directions to DEFLATE; `STARTTLS` would let
/// the cage negotiate TLS end to end; `UNAUTHENTICATE` (RFC 8437) drops
/// the session back to the state where those become possible.
const REFUSED_COMMANDS: &[(&str, &str)] = &[
    ("COMPRESS", "relay cannot inspect a compressed stream"),
    ("STARTTLS", "relay cannot inspect a TLS stream"),
    ("UNAUTHENTICATE", "relay session stays authenticated"),
];

/// Capabilities never advertised, because their command is refused.
const STRIPPED_CAPABILITIES: &[&str] = &["STARTTLS", "UNAUTHENTICATE"];
/// Capability prefixes hidden the same way (`COMPRESS=DEFLATE`, and any
/// mechanism a server adds later).
const STRIPPED_CAPABILITY_PREFIXES: &[&str] = &["COMPRESS="];
/// Also hidden unless `write_mode` is `full`.
const STRIPPED_CAPABILITIES_RESTRICTED: &[&str] = &["REPLACE"];
/// Also hidden while a folder list is set: their commands report on
/// mailboxes other than the selected one (see [`folder_side_door`]).
const STRIPPED_CAPABILITIES_FOLDERS: &[&str] = &["LIST-STATUS", "MULTISEARCH", "NOTIFY"];

/// Commands whose mailbox argument the folder lists judge: those that
/// open or report on a folder, and those that change or remove it.
/// `LIST`/`LSUB` are excluded (discovery); the destinations of `COPY`,
/// `MOVE`, `APPEND`, the new name of a `RENAME` and the folder a `CREATE`
/// makes are not checked either: filing mail reads nothing, and denying
/// Trash so that "delete" can only mean "move to Trash" must keep working.
const MAILBOX_ARG_COMMANDS: &[&str] = &[
    "SELECT",
    "EXAMINE",
    "STATUS",
    "GETQUOTAROOT",
    "GETMETADATA",
    "SETMETADATA",
    "GETANNOTATION",
    "SETANNOTATION",
    "GETACL",
    "MYRIGHTS",
    "LISTRIGHTS",
    "SETACL",
    "DELETEACL",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "DELETE",
    "RENAME",
];

/// Of those, the commands whose later arguments are strings a client may
/// send as literals.
const LATER_STRING_ARGS: &[&str] = &[
    "GETMETADATA",
    "SETMETADATA",
    "GETANNOTATION",
    "SETANNOTATION",
    "LISTRIGHTS",
    "SETACL",
    "DELETEACL",
    "RENAME",
];

/// Commands in which the mailbox `""` names the server itself (RFC 5464
/// §3.2), not a folder.
const SERVER_MAILBOX_COMMANDS: &[&str] = &[
    "GETMETADATA",
    "SETMETADATA",
    "GETANNOTATION",
    "SETANNOTATION",
];

const BARE_CR: &str = "bare CR in command line";
const NUL: &str = "NUL in command line";

/// Longest mailbox name read ahead from a literal to judge it.
const MAX_MAILBOX_LITERAL: u64 = 1024;

/// `ENABLE` arguments after which the upstream may read mailbox names as
/// UTF-8 (RFC 6855, RFC 9051) instead of modified UTF-7.
const UTF8_ENABLES: &[&[u8]] = &[b"UTF8=ACCEPT", b"IMAP4REV2"];

/// How much of one upstream response line the filter holds back before
/// streaming the rest raw, in the replaced implementation. It has to be
/// well above the longest line the cage can send, because the upstream
/// echoes the cage's tag in front of a `[CAPABILITY ...]` code.
pub const HELD_LINE_LIMIT: usize = 256 * 1024;

/// The held-line limit this relay runs with: four times
/// [`CLIENT_LINE_LIMIT`], for the reason [`HELD_LINE_LIMIT`] gives.
pub const RELAY_HELD_LINE_LIMIT: usize = 4 * CLIENT_LINE_LIMIT;

/// Longest command line the cage may send, LF excluded. The replaced
/// implementation ended the session at its stream reader's 64 KiB; this
/// relay accepts 1 MiB and answers a longer line with `BAD` (plan §5.8).
pub const CLIENT_LINE_LIMIT: usize = 1024 * 1024;

const LITERAL_TAIL_BYTES: usize = 64;

/// Status words of an untagged status response (RFC 3501 §7.1).
const STATUS_WORDS: &[&[u8]] = &[b"OK", b"NO", b"BAD", b"BYE", b"PREAUTH"];
/// Status words that complete a command in a tagged response.
const COMPLETION_WORDS: &[&[u8]] = &[b"OK", b"NO", b"BAD"];

/// Largest literal the cage may send. Literal bytes are streamed through,
/// never held, so this bounds what one command pushes at the upstream.
pub const MAX_LITERAL_BYTES: u64 = 64 * 1024 * 1024;

fn contains(set: &[&str], item: &str) -> bool {
    set.contains(&item)
}

// ── Pure helpers ────────────────────────────────────────

/// A literal announced at the end of one line from the cage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Literal {
    /// Payload bytes that follow the line.
    pub size: u64,
    /// Synchronising (`{n}`): the cage waits for `+` before the payload.
    pub sync: bool,
    /// Offset of `{` in the line.
    pub start: usize,
}

/// A line ending in something brace-shaped that is not a literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MalformedLiteral;

/// The literal `line` announces at its end (RFC 3501 §4.3): `{n}`,
/// `{n+}` (RFC 7888), each optionally `~`-prefixed (RFC 3516 literal8).
///
/// # Errors
///
/// [`MalformedLiteral`] for anything else in braces at the end of the
/// line (`{5-}`, `{ 5}`, `{}`): a lenient upstream might read it as a
/// literal while the relay reads a complete line, so it is refused. The
/// size is not range-checked here.
pub fn client_literal(line: &[u8]) -> Result<Option<Literal>, MalformedLiteral> {
    if !line.ends_with(b"}\r\n") && !line.ends_with(b"}\n") {
        return Ok(None);
    }
    let Some(brace) = line.iter().rposition(|&b| b == b'{') else {
        return Ok(None);
    };
    let mut body = &line[brace + 1..line.len() - 1];
    if let Some(b) = body.strip_suffix(b"\r") {
        body = b;
    }
    let Some(inner) = body.strip_suffix(b"}") else {
        return Ok(None);
    };
    let (digits, sync) = match inner.strip_suffix(b"+") {
        Some(d) => (d, false),
        None => (inner, true),
    };
    if !digits.is_empty() && digits.iter().all(u8::is_ascii_digit) {
        // A count with more digits than any sane size is simply too large.
        let size = if digits.len() <= 18 {
            std::str::from_utf8(digits)
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(u64::MAX)
        } else {
            MAX_LITERAL_BYTES + 1
        };
        return Ok(Some(Literal {
            size,
            sync,
            start: brace,
        }));
    }
    if inner
        .iter()
        .any(|&b| matches!(b, b'{' | b'}' | b'\r' | b'\n'))
    {
        return Ok(None);
    }
    Err(MalformedLiteral)
}

/// `line` with its literal announced as synchronising (`{n+}` → `{n}`).
fn synchronising(line: &[u8], lit: Literal) -> Vec<u8> {
    if lit.sync {
        return line.to_vec();
    }
    let eol: &[u8] = if line.ends_with(b"\r\n") {
        b"\r\n"
    } else {
        b"\n"
    };
    let mut out = line[..lit.start].to_vec();
    out.extend_from_slice(format!("{{{}}}", lit.size).as_bytes());
    out.extend_from_slice(eol);
    out
}

/// RFC 3501 §9 `tag`: printable ASCII except `(){%*"\+`. Refusing other
/// tags keeps the relay's view of the stream and the upstream's in step:
/// a `+` or `*` tag echoed back would read as a continuation request or
/// an untagged response.
#[must_use]
pub fn valid_tag(tag: &[u8]) -> bool {
    !tag.is_empty()
        && tag
            .iter()
            .all(|&b| (0x21..0x7f).contains(&b) && !b"(){%*\"\\+".contains(&b))
}

/// Why a line from the cage may not be relayed at all: a CR other than
/// the one before the LF (a server ending lines at a bare CR would run
/// two commands where the relay checked one), or a NUL (a server reading
/// C strings would stop there). Literal bytes never pass through here.
#[must_use]
pub fn line_fault(line: &[u8]) -> Option<&'static str> {
    let body = line.strip_suffix(b"\r\n").unwrap_or(line);
    if body.contains(&b'\r') {
        return Some(BARE_CR);
    }
    if body.contains(&0) {
        return Some(NUL);
    }
    None
}

/// `line` ending in CRLF where it ends in a bare LF, so a server ending
/// lines at CRLF only sees the same command boundaries the relay did.
fn crlf(line: &[u8]) -> Vec<u8> {
    if line.ends_with(b"\n") && !line.ends_with(b"\r\n") {
        let mut out = line[..line.len() - 1].to_vec();
        out.extend_from_slice(b"\r\n");
        return out;
    }
    line.to_vec()
}

/// `name` with control characters replaced by `?`, for echoing a mailbox
/// name inside one reply or log line.
fn printable(name: &str) -> String {
    name.chars()
        .map(|c| {
            if (c as u32) < 0x20 || c as u32 == 0x7f {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Whether a capability token must not be advertised to the cage. One
/// rule for the `PREAUTH` greeting and every capability list the upstream
/// sends later.
#[must_use]
pub fn capability_hidden(token: &str, write_mode: &str, folder_lists: bool) -> bool {
    let t = token.to_uppercase();
    if contains(STRIPPED_CAPABILITIES, &t)
        || STRIPPED_CAPABILITY_PREFIXES
            .iter()
            .any(|p| t.starts_with(p))
    {
        return true;
    }
    if folder_lists && contains(STRIPPED_CAPABILITIES_FOLDERS, &t) {
        return true;
    }
    write_mode != "full" && contains(STRIPPED_CAPABILITIES_RESTRICTED, &t)
}

/// Decode a modified UTF-7 mailbox name (RFC 3501 §5.1.3), or `None`
/// when it is not valid modified UTF-7. Lenient where the meaning is
/// clear (nonzero padding bits): the result only finds more names a deny
/// entry should catch.
#[must_use]
pub fn mutf7_decode(name: &str) -> Option<String> {
    if !name.is_ascii() {
        return None;
    }
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    let mut out = String::new();
    let mut i = 0;
    while i < name.len() {
        let Some(amp) = name[i..].find('&').map(|p| p + i) else {
            out.push_str(&name[i..]);
            break;
        };
        out.push_str(&name[i..amp]);
        let end = name[amp + 1..].find('-').map(|p| p + amp + 1)?;
        let run = &name[amp + 1..end];
        if run.is_empty() {
            out.push('&');
        } else {
            if !run
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b',')
                || run.len() % 4 == 1
            {
                return None;
            }
            let raw = engine.decode(run.replace(',', "/")).ok()?;
            if raw.len() % 2 != 0 {
                return None;
            }
            let units = raw.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]]));
            for c in char::decode_utf16(units) {
                out.push(c.ok()?);
            }
        }
        i = end + 1;
    }
    Some(out)
}

/// The canonical form two spellings of one mailbox name compare in: NFC,
/// case-folded (servers disagree on the case of special-use names, and
/// INBOX is case-insensitive), NFC again.
#[must_use]
pub fn fold(name: &str) -> String {
    let nfc: String = name.nfc().collect();
    caseless::default_case_fold_str(&nfc).nfc().collect()
}

/// Every canonical name the upstream might take `name` for: as written
/// (UTF-8) and, when valid modified UTF-7, decoded.
fn name_forms(name: &str) -> HashSet<String> {
    let mut forms = HashSet::from([fold(name)]);
    if let Some(decoded) = mutf7_decode(name) {
        forms.insert(fold(&decoded));
    }
    forms
}

/// The canonical name a server not reading UTF-8 names takes `name` for.
fn server_reading(name: &str) -> String {
    fold(&mutf7_decode(name).unwrap_or_else(|| name.to_owned()))
}

/// Split `data` on runs of ASCII whitespace and parentheses
/// (`re.split(rb"[\s()]+", data)`), keeping empty edge fields.
fn split_ws_parens(data: &[u8]) -> Vec<&[u8]> {
    let sep = |b: u8| super::is_py_space(b) || b == b'(' || b == b')';
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < data.len() {
        if sep(data[i]) {
            out.push(&data[start..i]);
            while i < data.len() && sep(data[i]) {
                i += 1;
            }
            start = i;
        } else {
            i += 1;
        }
    }
    out.push(&data[start..]);
    out
}

/// Whether a `STORE` would add the `\Deleted` flag. `-FLAGS` removes it
/// (un-deleting) and is always allowed.
fn store_adds_deleted(args: &[u8]) -> bool {
    let upper = args.to_ascii_uppercase();
    let Some(i) = upper.windows(5).position(|w| w == b"FLAGS") else {
        return false;
    };
    if i > 0 && upper[i - 1] == b'-' {
        return false;
    }
    upper[i + 5..].windows(8).any(|w| w == b"\\DELETED")
}

/// Whether a `STORE` writes RFC 5257 message annotations: any
/// `ANNOTATION` token, wherever it sits.
fn store_writes_annotation(args: &[u8]) -> bool {
    split_ws_parens(&args.to_ascii_uppercase())
        .iter()
        .any(|w| *w == b"ANNOTATION")
}

/// The command a line from the cage starts, as audit records name it:
/// upper-cased, `UID` resolved to its subcommand (`UID STORE`).
#[must_use]
pub fn command_name(line: &[u8]) -> String {
    let parts = split_ws(line, Some(2));
    if parts.len() < 2 {
        return String::new();
    }
    let cmd = ascii_lossy(&parts[1].to_ascii_uppercase());
    if cmd == "UID" {
        let sub = parts
            .get(2)
            .and_then(|rest| split_ws(rest, Some(1)).first().copied())
            .unwrap_or(b"");
        let sub = ascii_lossy(&sub.to_ascii_uppercase());
        return if sub.is_empty() {
            "UID".to_owned()
        } else {
            format!("UID {sub}")
        };
    }
    cmd
}

/// Quote an IMAP string (RFC 3501 §4.3 `quoted`).
fn quote(value: &str) -> Vec<u8> {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = vec![b'"'];
    out.extend_from_slice(escaped.as_bytes());
    out.push(b'"');
    out
}

/// Whether `line` is an `ENABLE` asking for UTF-8 mailbox names.
fn enables_utf8_names(line: &[u8]) -> bool {
    let parts = split_ws(line, None);
    parts.len() >= 3
        && parts[1].eq_ignore_ascii_case(b"ENABLE")
        && parts[2..]
            .iter()
            .any(|p| UTF8_ENABLES.contains(&p.to_ascii_uppercase().as_slice()))
}

fn announces_literal(line: &[u8]) -> bool {
    !matches!(client_literal(line), Ok(None))
}

/// Why `cmd` is refused while a folder list is set: a `LIST` with
/// `RETURN (STATUS ...)` (RFC 5819), `ESEARCH` over several mailboxes
/// (RFC 7377) and `NOTIFY SET` (RFC 5465) report on folders the lists
/// never judged.
fn folder_side_door(cmd: &str, args: &[u8]) -> Option<&'static str> {
    match cmd {
        "LIST" | "LSUB" => {
            let upper = args.to_ascii_uppercase();
            let words = split_ws_parens(&upper);
            let ret = words.iter().position(|w| *w == b"RETURN")?;
            words[ret..]
                .contains(&&b"STATUS"[..])
                .then_some("STATUS in LIST with folder lists set")
        }
        "ESEARCH" => Some("multi-mailbox search with folder lists set"),
        "NOTIFY" => {
            let first = split_ws(args, Some(1)).first().copied().unwrap_or(b"");
            (!first.eq_ignore_ascii_case(b"NONE")).then_some("NOTIFY with folder lists set")
        }
        _ => None,
    }
}

/// Where the mailbox argument of `cmd` starts in `args`, or `None` if
/// what comes before it does not parse. Only `GETMETADATA` (RFC 5464)
/// may put an options list in front of it.
fn mailbox_offset(cmd: &str, args: &[u8]) -> Option<usize> {
    if cmd != "GETMETADATA" || !args.starts_with(b"(") {
        return Some(0);
    }
    let close = args.iter().position(|&b| b == b')')?;
    if args[1..close].iter().any(|b| b"\"\\{(".contains(b)) {
        return None;
    }
    let rest = &args[close + 1..];
    if !matches!(rest.first(), Some(b' ' | b'\t')) {
        return None;
    }
    let trimmed = rest
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(rest.len());
    Some(args.len() - (rest.len() - trimmed))
}

/// The mailbox argument as written on `line`, or `None` if it isn't there
/// to read.
fn line_mailbox(cmd: &str, line: &[u8], args: &[u8]) -> Option<String> {
    let offset = mailbox_offset(cmd, args)?;
    let rest = &args[offset..];
    if announces_literal(line) {
        // A literal the relay didn't read ahead. Where a later argument
        // can be a string it can be that, as long as the mailbox is
        // written out in front of it; an atom with a `{` in it is not.
        if !contains(LATER_STRING_ARGS, cmd) {
            return None;
        }
        let first = rest
            .split(|&b| b == b' ' || b == b'\t')
            .next()
            .unwrap_or(b"");
        if !rest.starts_with(b"\"") && first.contains(&b'{') {
            return None;
        }
    }
    extract_mailbox(rest)
}

/// A mailbox name as sent, decoded; `None` unless it is valid UTF-8.
fn decode_mailbox(raw: &[u8]) -> Option<String> {
    String::from_utf8(raw.to_vec()).ok()
}

/// The first IMAP atom or quoted string of `args`.
#[must_use]
pub fn extract_mailbox(args: &[u8]) -> Option<String> {
    let start = args
        .iter()
        .position(|&b| !super::is_py_space(b))
        .unwrap_or(args.len());
    let mut s = &args[start..];
    while let Some(rest) = s.strip_suffix(b"\r").or_else(|| s.strip_suffix(b"\n")) {
        s = rest;
    }
    if s.is_empty() {
        return None;
    }
    if s[0] == b'"' {
        let mut i = 1;
        let mut buf = Vec::new();
        while i < s.len() {
            let c = s[i];
            if c == b'\\' && i + 1 < s.len() {
                buf.push(s[i + 1]);
                i += 2;
                continue;
            }
            if c == b'"' {
                return decode_mailbox(&buf);
            }
            buf.push(c);
            i += 1;
        }
        return None;
    }
    if s[0] == b'{' {
        return None;
    }
    let end = s
        .iter()
        .position(|&b| b == b' ' || b == b'\t')
        .unwrap_or(s.len());
    decode_mailbox(&s[..end])
}

// ── Config ──────────────────────────────────────────────

/// `x.get(key) or {}`, with Python's complaint when a truthy value is not
/// a mapping.
pub(crate) fn mapping_or_empty(value: Option<&Value>) -> Result<Option<&Mapping>, String> {
    match value {
        Some(Value::Mapping(m)) => Ok(Some(m)),
        Some(v) if agentcage_core::yaml::python_bool(v) => Err(format!(
            "'{}' object has no attribute 'get'",
            agentcage_core::python::type_name(v)
        )),
        _ => Ok(None),
    }
}

fn mget<'a>(m: Option<&'a Mapping>, key: &str) -> Option<&'a Value> {
    m.and_then(|m| m.get(key))
}

/// `list(value or [])`, each item as `str(item)`.
pub(crate) fn py_list(value: Option<&Value>) -> Result<Vec<String>, String> {
    let Some(v) = value.filter(|v| agentcage_core::yaml::python_bool(v)) else {
        return Ok(Vec::new());
    };
    match v {
        Value::Sequence(items) => Ok(items.iter().map(agentcage_core::python::str_of).collect()),
        Value::String(text) => Ok(text.chars().map(String::from).collect()),
        Value::Mapping(m) => Ok(m.keys().map(agentcage_core::python::str_of).collect()),
        other => Err(format!(
            "'{}' object is not iterable",
            agentcage_core::python::type_name(other)
        )),
    }
}

/// The relay's view of its `protocol_relays` entry, read with the
/// replaced implementation's coercions (`str(x or "")`, `bool(...)`,
/// `int(...)`).
#[derive(Clone, Debug)]
pub(crate) struct ImapConfig {
    pub(crate) name: String,
    pub(crate) listen: String,
    pub(crate) upstream: Upstream,
    pub(crate) user_source: String,
    pub(crate) password_source: String,
    pub(crate) write_mode: String,
    pub(crate) folder_allowlist: Vec<String>,
    pub(crate) folder_denylist: Vec<String>,
    pub(crate) conn_rate_limit: String,
    pub(crate) idle_timeout_seconds: i64,
}

/// Read an entry's `upstream` section, shared by both relays.
pub(crate) fn parse_upstream(entry: &Mapping) -> Result<Upstream, String> {
    let up = mapping_or_empty(entry.get("upstream"))?;
    let port = match mget(up, "port") {
        Some(v) if agentcage_core::yaml::python_bool(v) => super::py_int(v)?,
        _ => 0,
    };
    Ok(Upstream {
        host: super::str_or(mget(up, "host"), ""),
        port: u16::try_from(port).unwrap_or(0),
        tls: mget(up, "tls").is_none_or(agentcage_core::yaml::python_bool),
        ca_pem: super::str_or(mget(up, "ca_pem"), ""),
        tls_servername: super::str_or(mget(up, "tls_servername"), ""),
    })
}

/// `entry` as a mapping, or Python's complaint.
pub(crate) fn entry_mapping(entry: &Value) -> Result<&Mapping, String> {
    match entry {
        Value::Mapping(m) => Ok(m),
        other => Err(format!(
            "'{}' object has no attribute 'get'",
            agentcage_core::python::type_name(other)
        )),
    }
}

impl ImapConfig {
    pub(crate) fn parse(entry: &Value) -> Result<Self, String> {
        let entry = entry_mapping(entry)?;
        let upstream = parse_upstream(entry)?;
        let auth = mapping_or_empty(entry.get("auth"))?;
        let policy = mapping_or_empty(entry.get("policy"))?;
        let readonly = mget(policy, "readonly").is_some_and(agentcage_core::yaml::python_bool);
        // write_mode is the expressive form; readonly the older boolean.
        // An explicit write_mode wins.
        let mut mode = super::str_or(mget(policy, "write_mode"), "")
            .trim_matches(super::is_py_str_space)
            .to_lowercase();
        if mode.is_empty() {
            if readonly { "none" } else { "full" }.clone_into(&mut mode);
        }
        let folder_allowlist = py_list(mget(policy, "folder_allowlist"))?;
        let folder_denylist = py_list(mget(policy, "folder_denylist"))?;
        let conn_rate_limit = super::str_or(mget(policy, "conn_rate_limit"), "30/min");
        // Per-read idle timeout, 30 minutes by default so RFC 2177 IDLE
        // heartbeats (every ~29 minutes) don't trip it; 0 disables it.
        let idle = match mget(policy, "idle_timeout_seconds") {
            Some(v) => super::py_int(v)?,
            None => 1800,
        };
        Ok(Self {
            name: super::str_or(entry.get("name"), ""),
            listen: super::str_or(entry.get("listen"), ""),
            upstream,
            user_source: super::str_or(mget(auth, "user_source"), ""),
            password_source: super::str_or(mget(auth, "password_source"), ""),
            write_mode: mode,
            folder_allowlist,
            folder_denylist,
            conn_rate_limit,
            idle_timeout_seconds: idle,
        })
    }
}

// ── The relay ───────────────────────────────────────────

/// A refusal the relay answers itself: `<tag> <status> <reason>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The tag to answer with (`*` for an invalid one).
    pub tag: Vec<u8>,
    /// The human-readable text after the status word.
    pub reason: String,
    /// `OK` (a LOGIN answered locally), `NO` (policy), `BAD` (unparseable).
    pub status: &'static str,
}

/// One IMAP relay: one listener, one upstream.
#[derive(Debug)]
pub struct ImapRelay {
    inner: Arc<Inner>,
    listener: Listener,
}

#[derive(Debug)]
struct Inner {
    cfg: ImapConfig,
    user: String,
    password: String,
    rate: super::RateLimiter,
    audit: Arc<dyn AuditSink>,
    log_allowed: AtomicBool,
    folder_lists: bool,
    deny_forms: HashSet<String>,
    allow_forms: HashSet<String>,
}

impl ImapRelay {
    /// Build a relay from its `protocol_relays` entry, resolving its
    /// credentials now (a reload notices a rotated one by digest and
    /// rebuilds the relay).
    ///
    /// # Errors
    ///
    /// The entry does not read as an IMAP relay, a credential is missing
    /// or uses a refused scheme, or the rate spec does not parse; the
    /// message goes into the `relay_init_failed` record.
    pub fn new(
        entry: &Value,
        audit: Arc<dyn AuditSink>,
        settings: &RelaySettings,
    ) -> Result<Self, String> {
        let cfg = ImapConfig::parse(entry)?;
        let user = super::resolve_credential(&cfg.user_source)?;
        let password = super::resolve_credential(&cfg.password_source)?;
        Self::with_credentials(cfg, user, password, audit, settings)
    }

    /// [`Self::new`] with the credentials already resolved.
    pub(crate) fn with_credentials(
        cfg: ImapConfig,
        user: String,
        password: String,
        audit: Arc<dyn AuditSink>,
        settings: &RelaySettings,
    ) -> Result<Self, String> {
        if user.is_empty() || password.is_empty() {
            return Err(format!(
                "imap relay {}: credentials not resolved (user_source={}, password_source={})",
                cfg.name,
                repr_str(&cfg.user_source),
                repr_str(&cfg.password_source)
            ));
        }
        let (max, window) = super::parse_rate_limit(&cfg.conn_rate_limit).ok_or_else(|| {
            format!(
                "invalid conn_rate_limit: {}",
                repr_str(&cfg.conn_rate_limit)
            )
        })?;
        let folder_lists = !cfg.folder_allowlist.is_empty() || !cfg.folder_denylist.is_empty();
        let deny_forms = cfg
            .folder_denylist
            .iter()
            .flat_map(|d| name_forms(d))
            .collect();
        let allow_forms = cfg
            .folder_allowlist
            .iter()
            .flat_map(|a| name_forms(a))
            .collect();
        Ok(Self {
            inner: Arc::new(Inner {
                cfg,
                user,
                password,
                rate: super::RateLimiter::new(max, window),
                audit,
                log_allowed: AtomicBool::new(settings.log_allowed),
                folder_lists,
                deny_forms,
                allow_forms,
            }),
            listener: Listener::default(),
        })
    }

    /// The relay's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.inner.cfg.name
    }

    /// Take a reload's settings without restarting, so open sessions (a
    /// long IDLE) survive. Only `log_allowed` applies to IMAP.
    pub fn update_settings(&self, settings: &RelaySettings) {
        self.inner
            .log_allowed
            .store(settings.log_allowed, Ordering::Relaxed);
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
            "imap relay {} listening on {} -> {}:{} (write={}, folders={:?}, denied={:?})",
            cfg.name,
            cfg.listen,
            cfg.upstream.host,
            cfg.upstream.port,
            cfg.write_mode,
            cfg.folder_allowlist,
            cfg.folder_denylist
        );
        Ok(())
    }

    /// Close the listener and end every session with `* BYE`.
    pub async fn stop(&self) {
        self.listener.stop().await;
    }

    /// The bound address, once started.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        self.listener.local_addr().await
    }

    /// The policy check on one command line (exposed for the corpus).
    #[must_use]
    pub fn policy_check(
        &self,
        line: &[u8],
        mailbox: Option<&[u8]>,
        utf8_names: bool,
    ) -> Option<Decision> {
        self.inner.policy_check(line, mailbox, utf8_names)
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

type UpReader = Reader<tokio::io::ReadHalf<Box<dyn super::Stream>>>;
type UpWriter = tokio::io::WriteHalf<Box<dyn super::Stream>>;
type ClientReader = Reader<tokio::net::tcp::OwnedReadHalf>;

/// How the authentication phase ended.
enum Auth {
    /// Logged in; the capabilities captured on the way.
    Ready(Vec<String>),
    /// Refused; the cage already has its `* BYE`.
    Refused,
}

impl Inner {
    fn emit(&self, fields: Vec<(&str, crate::json::Json)>) {
        audit(self.audit.as_ref(), fields);
    }

    async fn handle_client(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        shutdown: watch::Receiver<bool>,
    ) {
        let (read, mut write) = stream.into_split();
        if !self.rate.take() {
            relay_log!(
                warning,
                LOGGER,
                "imap relay {}: connection rate limit hit, refusing {}:{}",
                self.cfg.name,
                peer.ip(),
                peer.port()
            );
            let _ = write.write_all(b"* BYE rate limit\r\n").await;
            let _ = write.shutdown().await;
            return;
        }
        let mut reader = Reader::new(read);
        if let Err(e) = self.proxy_session(&mut reader, &mut write, shutdown).await
            && !e.is_disconnect()
        {
            relay_log!(
                error,
                LOGGER,
                "imap relay {}: session error from {}:{}: {}",
                self.cfg.name,
                peer.ip(),
                peer.port(),
                e
            );
        }
        let _ = write.shutdown().await;
    }

    async fn proxy_session(
        &self,
        client_reader: &mut ClientReader,
        client_writer: &mut tokio::net::tcp::OwnedWriteHalf,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), SessionError> {
        let upstream = match self.cfg.upstream.connect().await {
            Ok(stream) => stream,
            Err(e) => {
                relay_log!(
                    warning,
                    LOGGER,
                    "imap relay {}: upstream {} unreachable: {}",
                    self.cfg.name,
                    self.cfg.upstream.display(),
                    e
                );
                self.emit(vec![
                    ("kind", s("imap_upstream_unreachable")),
                    ("relay", s(&self.cfg.name)),
                    ("upstream", s(self.cfg.upstream.display())),
                    ("error", s(e)),
                ]);
                let _ = client_writer
                    .write_all(b"* BYE upstream unreachable\r\n")
                    .await;
                return Ok(());
            }
        };
        let (up_read, mut up_write) = tokio::io::split(upstream);
        let mut up_reader = Reader::new(up_read);
        let result = self
            .bridge(
                client_reader,
                client_writer,
                &mut up_reader,
                &mut up_write,
                &mut shutdown,
            )
            .await;
        let _ = up_write.shutdown().await;
        result
    }

    async fn bridge(
        &self,
        client_reader: &mut ClientReader,
        client_writer: &mut tokio::net::tcp::OwnedWriteHalf,
        up_reader: &mut UpReader,
        up_write: &mut UpWriter,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<(), SessionError> {
        let caps = match self
            .authenticate_upstream(up_reader, up_write, client_writer)
            .await?
        {
            Auth::Ready(caps) => caps,
            Auth::Refused => return Ok(()),
        };
        let advertised = self.client_capability_string(&caps);
        if !advertised.is_ascii() {
            return Err(SessionError::Other(
                "'ascii' codec can't encode character '\\ufffd': ordinal not in range(128)"
                    .to_owned(),
            ));
        }
        client_writer
            .write_all(
                format!("* PREAUTH [CAPABILITY {advertised}] agentcage relay ready\r\n").as_bytes(),
            )
            .await?;

        // Whether the upstream may read mailbox names as UTF-8: from the
        // start on a server that only speaks IMAP4rev2 or UTF-8, else once
        // the cage has asked it to.
        let upper: HashSet<String> = caps.iter().map(|c| c.to_uppercase()).collect();
        let mut state = SessionState {
            utf8_names: upper.contains("UTF8=ONLY")
                || (upper.contains("IMAP4REV2") && !upper.contains("IMAP4REV1")),
        };

        let tracker = Arc::new(Tracker::default());
        let observer = Arc::clone(&tracker);
        let mode = self.cfg.write_mode.clone();
        let folder_lists = self.folder_lists;
        let filter = ResponseFilter::new(
            Box::new(move |t: &str| capability_hidden(t, &mode, folder_lists)),
            Some(Box::new(move |line: &[u8]| observer.observe(line))),
            RELAY_HELD_LINE_LIMIT,
        );
        let out = ClientOutput {
            inner: tokio::sync::Mutex::new((client_writer, filter)),
        };
        let stopping = tokio::select! {
            () = self.pipe_client_to_upstream(client_reader, up_write, &out, &tracker, &mut state) => false,
            () = self.pipe_upstream_to_client(up_reader, &out) => false,
            stop = shutdown.wait_for(|stop| *stop) => stop.is_ok(),
        };
        if stopping {
            bye(&out, b"relay shutting down").await;
        }
        Ok(())
    }

    /// Read one upstream line under the idle timeout.
    async fn read_upstream_line(
        &self,
        reader: &mut UpReader,
    ) -> Result<Option<Vec<u8>>, SessionError> {
        match super::with_idle_timeout(
            self.cfg.idle_timeout_seconds,
            reader.read_line(super::STREAM_LINE_LIMIT),
        )
        .await
        {
            Err(_) => Ok(None),
            Ok(Ok(Line::Data(line))) => Ok(Some(line)),
            Ok(Ok(Line::TooLong { .. })) => Err(super::line_too_long()),
            Ok(Err(e)) => Err(e.into()),
        }
    }

    async fn authenticate_upstream(
        &self,
        up_reader: &mut UpReader,
        up_write: &mut UpWriter,
        client_writer: &mut tokio::net::tcp::OwnedWriteHalf,
    ) -> Result<Auth, SessionError> {
        let mut caps: Vec<String> = Vec::new();
        // The greeting often carries `[CAPABILITY ...]`; capture it so the
        // PREAUTH greeting can advertise the same features.
        let Some(greeting) = self.read_upstream_line(up_reader).await? else {
            relay_log!(
                warning,
                LOGGER,
                "imap relay {}: upstream silent for {}s, giving up",
                self.cfg.name,
                self.cfg.idle_timeout_seconds
            );
            client_writer
                .write_all(b"* BYE upstream silent\r\n")
                .await?;
            return Ok(Auth::Refused);
        };
        if !greeting.starts_with(b"* OK") {
            relay_log!(
                error,
                LOGGER,
                "imap relay {}: unexpected greeting: {}",
                self.cfg.name,
                bytes_repr(&greeting)
            );
            client_writer
                .write_all(b"* BYE upstream rejected\r\n")
                .await?;
            return Ok(Auth::Refused);
        }
        capture_capabilities(&greeting, &mut caps);

        let mut login = b"a001 LOGIN ".to_vec();
        login.extend_from_slice(&quote(&self.user));
        login.push(b' ');
        login.extend_from_slice(&quote(&self.password));
        login.extend_from_slice(b"\r\n");
        up_write.write_all(&login).await?;
        up_write.flush().await?;

        loop {
            // A timeout here ends the session without a BYE, as before.
            let line = self
                .read_upstream_line(up_reader)
                .await?
                .ok_or(SessionError::Timeout)?;
            if line.is_empty() {
                client_writer
                    .write_all(b"* BYE upstream closed\r\n")
                    .await?;
                return Ok(Auth::Refused);
            }
            if let Some(rest) = line.strip_prefix(b"a001 ") {
                let status = rest.split(|&b| b == b' ').next().unwrap_or(b"");
                if status.eq_ignore_ascii_case(b"OK") {
                    // A [CAPABILITY] code here overrides the greeting's
                    // list (RFC 3501 §6.2.3).
                    capture_capabilities(&line, &mut caps);
                    relay_log!(
                        info,
                        LOGGER,
                        "imap relay {}: upstream authenticated as {}",
                        self.cfg.name,
                        self.user
                    );
                    if caps.is_empty() {
                        self.fetch_capabilities(up_reader, up_write, &mut caps)
                            .await?;
                    }
                    return Ok(Auth::Ready(caps));
                }
                // Logged, so never with the password in it, should the
                // server quote the LOGIN line back.
                let mut reply = String::from_utf8_lossy(trim_ascii_end(&line)).into_owned();
                let quoted = String::from_utf8_lossy(&quote(&self.password)).into_owned();
                for value in [quoted.as_str(), self.password.as_str()] {
                    reply = reply.replace(value, "[redacted]");
                }
                relay_log!(
                    warning,
                    LOGGER,
                    "imap relay {}: upstream LOGIN failed: {}",
                    self.cfg.name,
                    reply
                );
                client_writer.write_all(b"* BYE auth failed\r\n").await?;
                return Ok(Auth::Refused);
            }
            capture_capabilities(&line, &mut caps);
        }
    }

    /// Ask for `CAPABILITY` when neither the greeting nor the LOGIN OK
    /// carried one.
    async fn fetch_capabilities(
        &self,
        up_reader: &mut UpReader,
        up_write: &mut UpWriter,
        caps: &mut Vec<String>,
    ) -> Result<(), SessionError> {
        up_write.write_all(b"a002 CAPABILITY\r\n").await?;
        up_write.flush().await?;
        loop {
            let line = self
                .read_upstream_line(up_reader)
                .await?
                .ok_or(SessionError::Timeout)?;
            if line.is_empty() {
                return Ok(());
            }
            capture_capabilities(&line, caps);
            if line.starts_with(b"a002 ") {
                return Ok(());
            }
        }
    }

    /// The capability list advertised to the cage: the upstream's minus
    /// what [`capability_hidden`] hides, `IMAP4rev1` ensured.
    fn client_capability_string(&self, caps: &[String]) -> String {
        if caps.is_empty() {
            return "IMAP4rev1".to_owned();
        }
        let mut out: Vec<&str> = caps
            .iter()
            .map(String::as_str)
            .filter(|t| !capability_hidden(t, &self.cfg.write_mode, self.folder_lists))
            .collect();
        if !out.iter().any(|t| t.to_uppercase() == "IMAP4REV1") {
            out.insert(0, "IMAP4rev1");
        }
        out.join(" ")
    }

    async fn pipe_client_to_upstream(
        &self,
        client_reader: &mut ClientReader,
        up_write: &mut UpWriter,
        out: &ClientOutput<'_>,
        tracker: &Tracker,
        state: &mut SessionState,
    ) {
        loop {
            let line = match client_reader.read_line(CLIENT_LINE_LIMIT).await {
                Ok(Line::Data(line)) if line.is_empty() => return,
                Ok(Line::Data(line)) => line,
                Ok(Line::TooLong { head, tail }) => match self
                    .refuse_long_line(&head, &tail, client_reader, out)
                    .await
                {
                    Ok(true) => continue,
                    _ => return,
                },
                Err(_) => return,
            };
            match self
                .relay_command(line, client_reader, up_write, out, tracker, state)
                .await
            {
                Ok(true) => {}
                _ => return,
            }
        }
    }

    /// A command line over [`CLIENT_LINE_LIMIT`]: already read and
    /// dropped, never forwarded; answered `BAD`, and a `{n+}` payload it
    /// announced dropped as well.
    async fn refuse_long_line(
        &self,
        head: &[u8],
        tail: &[u8],
        client_reader: &mut ClientReader,
        out: &ClientOutput<'_>,
    ) -> Result<bool, SessionError> {
        let tag = split_ws(head, Some(1)).first().copied().unwrap_or(b"");
        let tag: &[u8] = if valid_tag(tag) { tag } else { b"*" };
        relay_log!(
            warning,
            LOGGER,
            "imap relay {}: blocked command line over {} bytes",
            self.cfg.name,
            CLIENT_LINE_LIMIT
        );
        self.emit(vec![
            ("kind", s("imap_command")),
            ("relay", s(&self.cfg.name)),
            ("command", s(command_name(head))),
            ("decision", s("blocked")),
            ("reason", s("line too long")),
        ]);
        let mut reply = tag.to_vec();
        reply.extend_from_slice(b" BAD line too long\r\n");
        out.relay_reply(&reply).await?;
        let lit = client_literal(tail).unwrap_or(None);
        self.discard_command(client_reader, out, lit).await
    }

    /// Relay one command whose first line is `line`; `false` ends the
    /// session.
    ///
    /// A command is one line unless it carries literals: a line ending in
    /// `{n}` is followed by n bytes of payload and then the rest of the
    /// command. Payload is data, streamed through byte for byte and never
    /// policy-checked; the first line always is, before anything of the
    /// command is forwarded.
    ///
    /// That only holds while the relay and the upstream agree on where each
    /// literal starts and ends, so every literal goes upstream as a
    /// synchronising one, and its payload is forwarded only after the
    /// upstream answered that very line with `+`. A `{n+}` from the cage
    /// is announced upstream as `{n}` and the upstream's `+` swallowed; a
    /// refusal drops the payload the cage already sent. A command the
    /// relay refuses itself never reaches the upstream: for `{n}` the
    /// relay's answer stands in for the `+`, for `{n+}` the payload is
    /// read and dropped.
    ///
    /// A mailbox name the folder lists must judge may itself be a literal
    /// (`SELECT {5}`); the relay then reads it first (sending the `+`
    /// itself for `{n}`) and swallows the upstream's later `+`.
    #[allow(clippy::too_many_lines)] // one function, as in the replaced implementation: the literal steps read in order
    async fn relay_command(
        &self,
        mut line: Vec<u8>,
        client_reader: &mut ClientReader,
        up_write: &mut UpWriter,
        out: &ClientOutput<'_>,
        tracker: &Tracker,
        state: &mut SessionState,
    ) -> Result<bool, SessionError> {
        let mut lit = client_literal(&line).unwrap_or(None);
        let mut name: Option<Vec<u8>> = None;
        if let Some(l) = lit
            && self.literal_mailbox(&line, l)
        {
            tracker.settle(0).await;
            if l.sync {
                out.relay_reply(b"+ Ready for the mailbox name\r\n").await?;
            }
            let size = usize::try_from(l.size).unwrap_or(usize::MAX);
            match client_reader.read_exact(size).await? {
                Some(bytes) => name = Some(bytes),
                None => return Ok(false),
            }
        }
        if let Some(decision) = self.policy_check(&line, name.as_deref(), state.utf8_names) {
            reply(out, &decision).await?;
            if name.is_some() {
                return self.discard_rest(client_reader, out).await;
            }
            return self.discard_command(client_reader, out, lit).await;
        }
        if enables_utf8_names(&line) {
            // Set before the upstream agreed: errs towards checking both
            // readings of a name for longer than needed.
            state.utf8_names = true;
        }

        let tag = split_ws(&line, Some(1))
            .first()
            .map(|t| t.to_vec())
            .unwrap_or_default();
        let command = command_name(&line);
        let counted = split_ws(&line, Some(2)).len() >= 2;
        let mut first = true;
        loop {
            let Some(l) = lit else {
                up_write.write_all(&crlf(&line)).await?;
                up_write.flush().await?;
                if first && counted {
                    tracker.sent(&tag);
                }
                return Ok(true);
            };
            if !first && l.size > MAX_LITERAL_BYTES {
                // Part of this command is already upstream: there is no
                // refusing it cleanly any more.
                self.audit_literal_too_large(&command);
                bye(out, b"literal too large").await;
                return Ok(false);
            }
            // The next `+` or tagged response must be this literal's: no
            // other command may be outstanding.
            tracker.settle(usize::from(!first)).await;
            if !first && tracker.outstanding() != 1 {
                relay_log!(
                    warning,
                    LOGGER,
                    "imap relay {}: upstream completed a command before its last literal, closing session",
                    self.cfg.name
                );
                bye(out, b"protocol error").await;
                return Ok(false);
            }
            let verdict = tracker.expect_continuation(&tag, l.sync && name.is_none());
            if first {
                tracker.sent(&tag);
            }
            up_write.write_all(&crlf(&synchronising(&line, l))).await?;
            up_write.flush().await?;
            if !verdict.await.unwrap_or(false) {
                // Refused upstream; its tagged response is on its way.
                if name.is_some() {
                    return self.discard_rest(client_reader, out).await;
                }
                return self.discard_command(client_reader, out, lit).await;
            }
            if let Some(bytes) = name.take() {
                up_write.write_all(&bytes).await?;
                up_write.flush().await?;
            } else if !copy_exactly(client_reader, Some(&mut *up_write), l.size).await? {
                return Ok(false);
            }
            line = match client_reader.read_line(CLIENT_LINE_LIMIT).await? {
                Line::Data(next) if next.is_empty() => return Ok(false),
                Line::Data(next) => next,
                Line::TooLong { .. } => {
                    self.audit_inside_command(&command, "line too long");
                    bye(out, b"line too long").await;
                    return Ok(false);
                }
            };
            first = false;
            if let Some(fault) = line_fault(&line) {
                relay_log!(
                    warning,
                    LOGGER,
                    "imap relay {}: {} inside a command, closing session",
                    self.cfg.name,
                    fault
                );
                self.audit_inside_command(&command, fault);
                bye(out, fault.as_bytes()).await;
                return Ok(false);
            }
            let Ok(next) = client_literal(&line) else {
                relay_log!(
                    warning,
                    LOGGER,
                    "imap relay {}: malformed literal inside a command, closing session",
                    self.cfg.name
                );
                self.audit_inside_command(&command, "malformed literal");
                bye(out, b"malformed literal").await;
                return Ok(false);
            };
            lit = next;
        }
    }

    fn audit_inside_command(&self, command: &str, reason: &str) {
        self.emit(vec![
            ("kind", s("imap_command")),
            ("relay", s(&self.cfg.name)),
            ("command", s(command)),
            ("decision", s("blocked")),
            ("reason", s(reason)),
        ]);
    }

    /// [`Self::discard_command`] for a command whose literal the relay
    /// already read: drop the line after it, and on from there.
    async fn discard_rest(
        &self,
        client_reader: &mut ClientReader,
        out: &ClientOutput<'_>,
    ) -> Result<bool, SessionError> {
        let line = match client_reader.read_line(CLIENT_LINE_LIMIT).await? {
            Line::Data(line) if line.is_empty() => return Ok(false),
            Line::Data(line) => line,
            Line::TooLong { tail, .. } => tail,
        };
        match client_literal(&line) {
            Ok(lit) => self.discard_command(client_reader, out, lit).await,
            Err(MalformedLiteral) => Ok(true),
        }
    }

    /// Whether `line` is one of [`MAILBOX_ARG_COMMANDS`] whose mailbox
    /// argument is the literal it announces, and the folder lists need to
    /// see that name.
    fn literal_mailbox(&self, line: &[u8], lit: Literal) -> bool {
        if !self.folder_lists || lit.size > MAX_MAILBOX_LITERAL || line_fault(line).is_some() {
            return false;
        }
        let parts = split_ws_ranges(line, Some(2));
        if parts.len() < 3 || !valid_tag(&line[parts[0].0..parts[0].1]) {
            return false;
        }
        let cmd = ascii_lossy(&line[parts[1].0..parts[1].1].to_ascii_uppercase());
        if !contains(MAILBOX_ARG_COMMANDS, &cmd) {
            return false;
        }
        let args_start = parts[2].0;
        let Some(offset) = mailbox_offset(&cmd, &line[args_start..]) else {
            return false;
        };
        lit.start == args_start + offset
    }

    /// Drop the rest of a command that will not reach the upstream: a
    /// `{n+}` payload the cage sends unasked, then the line after it, and
    /// on while those lines end in `{n+}` too. At a `{n}` the cage waits
    /// for a `+` that never comes, so what follows is its next command.
    async fn discard_command(
        &self,
        client_reader: &mut ClientReader,
        out: &ClientOutput<'_>,
        mut lit: Option<Literal>,
    ) -> Result<bool, SessionError> {
        while let Some(l) = lit.filter(|l| !l.sync) {
            if l.size > MAX_LITERAL_BYTES {
                bye(out, b"literal too large").await;
                return Ok(false);
            }
            if !copy_exactly(client_reader, None::<&mut UpWriter>, l.size).await? {
                return Ok(false);
            }
            let line = match client_reader.read_line(CLIENT_LINE_LIMIT).await? {
                Line::Data(line) if line.is_empty() => return Ok(false),
                Line::Data(line) => line,
                Line::TooLong { tail, .. } => tail,
            };
            match client_literal(&line) {
                Ok(next) => lit = next,
                Err(MalformedLiteral) => return Ok(true),
            }
        }
        Ok(true)
    }

    fn audit_literal_too_large(&self, command: &str) {
        relay_log!(
            warning,
            LOGGER,
            "imap relay {}: blocked literal over {} bytes",
            self.cfg.name,
            MAX_LITERAL_BYTES
        );
        self.audit_inside_command(command, "literal too large");
    }

    async fn pipe_upstream_to_client(&self, up_reader: &mut UpReader, out: &ClientOutput<'_>) {
        loop {
            let Ok(chunk) = up_reader.read_some(8192).await else {
                return;
            };
            match out.upstream_bytes(&chunk).await {
                Ok(()) => {}
                Err(OutputError::Unfilterable(reason)) => {
                    relay_log!(
                        warning,
                        LOGGER,
                        "imap relay {}: closing session: {}",
                        self.cfg.name,
                        reason
                    );
                    self.emit(vec![
                        ("kind", s("imap_response")),
                        ("relay", s(&self.cfg.name)),
                        ("decision", s("blocked")),
                        ("reason", s(reason)),
                    ]);
                    return;
                }
                Err(OutputError::Io) => return,
            }
            if chunk.is_empty() {
                return;
            }
        }
    }

    fn blocked(&self, command: &str, reason: &str) {
        self.emit(vec![
            ("kind", s("imap_command")),
            ("relay", s(&self.cfg.name)),
            ("command", s(command)),
            ("decision", s("blocked")),
            ("reason", s(reason)),
        ]);
    }

    /// The decision on one command line: `None` lets it through.
    ///
    /// `mailbox` is a name the cage sent as a literal, read ahead;
    /// `utf8_names` says whether the upstream may read names as UTF-8.
    #[allow(clippy::too_many_lines)] // one function, in the replaced implementation's order: the order is observable
    fn policy_check(
        &self,
        line: &[u8],
        mailbox: Option<&[u8]>,
        utf8_names: bool,
    ) -> Option<Decision> {
        let name = &self.cfg.name;
        // Before anything else reads the line: past a bare CR or a NUL,
        // the relay and the upstream may not agree on what it is.
        if let Some(fault) = line_fault(line) {
            let tag = split_ws(line, Some(1)).first().copied().unwrap_or(b"");
            relay_log!(warning, LOGGER, "imap relay {name}: blocked {fault}");
            self.blocked(&command_name(line), fault);
            return Some(Decision {
                tag: if valid_tag(tag) {
                    tag.to_vec()
                } else {
                    b"*".to_vec()
                },
                reason: fault.to_owned(),
                status: "BAD",
            });
        }

        // Split on runs of whitespace: an upstream lenient about doubled
        // or leading spaces would run `a1  EXPUNGE` as EXPUNGE.
        let parts = split_ws(line, Some(2));
        let &tag = parts.first()?;
        if !valid_tag(tag) {
            // Answered untagged, and logged by length only: a bare base64
            // SASL line reads as an invalid tag, and its text is a
            // credential.
            relay_log!(
                warning,
                LOGGER,
                "imap relay {name}: blocked line with invalid tag ({} bytes)",
                tag.len()
            );
            self.blocked(&command_name(line), "invalid tag");
            return Some(Decision {
                tag: b"*".to_vec(),
                reason: "invalid command tag".to_owned(),
                status: "BAD",
            });
        }
        if parts.len() < 2 {
            return None;
        }
        let cmd = ascii_lossy(&parts[1].to_ascii_uppercase());
        let args: &[u8] = parts.get(2).copied().unwrap_or(b"");
        let effective = command_name(line);
        let deny = |reason: String, status: &'static str| {
            Some(Decision {
                tag: tag.to_vec(),
                reason,
                status,
            })
        };

        if cmd == "LOGIN" || cmd == "AUTHENTICATE" {
            relay_log!(
                info,
                LOGGER,
                "imap relay {name}: client sent {cmd} on PREAUTH'd connection — responding OK no-op"
            );
            self.emit(vec![
                ("kind", s("imap_command")),
                ("relay", s(name)),
                ("command", s(&cmd)),
                ("decision", s("intercepted")),
                ("reason", s("client login on PREAUTH'd connection")),
            ]);
            return deny(
                "already authenticated (relay handled login)".to_owned(),
                "OK",
            );
        }

        if let Some((_, why)) = REFUSED_COMMANDS.iter().find(|(c, _)| *c == cmd) {
            relay_log!(warning, LOGGER, "imap relay {name}: blocked {cmd} ({why})");
            self.blocked(&cmd, why);
            return deny(format!("{cmd} not permitted ({why})"), "NO");
        }

        if self.cfg.write_mode != "full" {
            let sub = if cmd == "UID" {
                effective.split_once(' ').map_or("", |(_, sub)| sub)
            } else {
                ""
            };
            let wire = if self.cfg.write_mode == "none" {
                "readonly"
            } else {
                "write_mode organise"
            };
            let mut reason = None;
            if self.cfg.write_mode == "none" {
                if contains(DENY_COMMANDS_READONLY, &cmd) || contains(UID_WRITE_SUBCOMMANDS, sub) {
                    reason = Some("readonly policy");
                }
            } else if contains(DENY_COMMANDS_ORGANISE, &cmd) || contains(UID_DENY_ORGANISE, sub) {
                reason = Some("write_mode organise");
            } else if cmd == "STORE" || sub == "STORE" {
                // Filing and flagging are allowed; marking mail deleted is
                // not, so an expunge never has anything to destroy.
                if store_adds_deleted(args) {
                    reason = Some("write_mode organise (\\Deleted flag)");
                } else if store_writes_annotation(args) {
                    reason = Some("write_mode organise (annotation)");
                }
            }
            if let Some(reason) = reason {
                relay_log!(
                    warning,
                    LOGGER,
                    "imap relay {name}: blocked {effective} ({reason})"
                );
                self.blocked(&effective, reason);
                return deny(format!("{effective} not permitted ({wire})"), "NO");
            }
        }

        if self.folder_lists
            && let Some(why) = folder_side_door(&cmd, args)
        {
            relay_log!(warning, LOGGER, "imap relay {name}: blocked {cmd} ({why})");
            self.blocked(&cmd, why);
            return deny(format!("{cmd} not permitted ({why})"), "NO");
        }

        if contains(MAILBOX_ARG_COMMANDS, &cmd) && self.folder_lists {
            let parsed = match mailbox {
                Some(raw) => decode_mailbox(raw),
                None => line_mailbox(&cmd, line, args),
            };
            let Some(mailbox) = parsed else {
                relay_log!(
                    warning,
                    LOGGER,
                    "imap relay {name}: {cmd} with unparseable mailbox: {}",
                    bytes_repr(args)
                );
                self.blocked(&cmd, "mailbox not parseable");
                return deny(format!("{cmd} mailbox not parseable"), "NO");
            };
            let reason = if mailbox.is_empty() && contains(SERVER_MAILBOX_COMMANDS, &cmd) {
                None // the server's own annotations
            } else {
                self.mailbox_denial_reason(&mailbox, utf8_names)
            };
            if let Some(reason) = reason {
                let shown = printable(&mailbox);
                relay_log!(
                    warning,
                    LOGGER,
                    "imap relay {name}: blocked {cmd} on {shown} ({reason})"
                );
                self.emit(vec![
                    ("kind", s("imap_command")),
                    ("relay", s(name)),
                    ("command", s(&cmd)),
                    ("mailbox", s(&mailbox)),
                    ("decision", s("blocked")),
                    ("reason", s(reason)),
                ]);
                return deny(format!("{cmd} {shown} {reason}"), "NO");
            }
        }

        match client_literal(line) {
            Err(MalformedLiteral) => {
                relay_log!(
                    warning,
                    LOGGER,
                    "imap relay {name}: blocked {effective} with malformed literal"
                );
                self.blocked(&effective, "malformed literal");
                return deny("malformed literal".to_owned(), "BAD");
            }
            Ok(Some(lit)) if lit.size > MAX_LITERAL_BYTES => {
                self.audit_literal_too_large(&effective);
                return deny(
                    format!("[TOOBIG] literal larger than {MAX_LITERAL_BYTES} bytes"),
                    "NO",
                );
            }
            Ok(_) => {}
        }

        // Allowed commands are logged only when the operator opted in
        // (`logging.allowed_requests`), as on the HTTP path: IDLE and sync
        // flows make this high-volume.
        if self.log_allowed.load(Ordering::Relaxed) {
            relay_log!(info, LOGGER, "imap relay {name}: allowed {effective}");
            self.emit(vec![
                ("kind", s("imap_command")),
                ("relay", s(name)),
                ("command", s(&effective)),
                ("decision", s("allowed")),
            ]);
        }
        None
    }

    /// Why this mailbox may not be opened, or `None` if it may.
    ///
    /// Denial wins over the allowlist. Names compare in canonical form
    /// ([`fold`]), in every spelling the upstream might read them in: a
    /// deny entry matches if any reading of the name matches any reading
    /// of the entry; the allowlist admits a name only in the reading the
    /// upstream will use (decoded modified UTF-7 until UTF-8 names may be
    /// on, then only if every reading is allowed). Matching is exact
    /// otherwise: no wildcards, no hierarchy.
    fn mailbox_denial_reason(&self, mailbox: &str, utf8_names: bool) -> Option<&'static str> {
        let forms = name_forms(mailbox);
        if forms.iter().any(|f| self.deny_forms.contains(f)) {
            return Some("denied by folder_denylist");
        }
        if !self.cfg.folder_allowlist.is_empty() {
            let allowed = if utf8_names {
                forms.iter().all(|f| self.allow_forms.contains(f))
            } else {
                self.allow_forms.contains(&server_reading(mailbox))
            };
            if !allowed {
                return Some("not in folder_allowlist");
            }
        }
        None
    }
}

fn trim_ascii_end(data: &[u8]) -> &[u8] {
    let end = data
        .iter()
        .rposition(|&b| !super::is_py_space(b))
        .map_or(0, |i| i + 1);
    &data[..end]
}

/// Pull a capability list out of a server response line: the bracketed
/// `[CAPABILITY ...]` response code anywhere in the line (authoritative),
/// or an untagged `* CAPABILITY ...`. A tagged response without brackets
/// (`a002 OK CAPABILITY completed`) is not an advertisement.
fn capture_capabilities(line: &[u8], caps: &mut Vec<String>) {
    let text = ascii_lossy(line);
    let upper = text.to_ascii_uppercase();
    if let Some(idx) = upper.find("[CAPABILITY") {
        let after = &text[idx + "[CAPABILITY".len()..];
        let Some(end) = after.find(']') else {
            return;
        };
        let tokens = split_str_ws(&after[..end]);
        if !tokens.is_empty() {
            *caps = tokens.into_iter().map(str::to_owned).collect();
        }
        return;
    }
    let stripped = text.trim_start_matches(super::is_py_str_space);
    if stripped.to_ascii_uppercase().starts_with("* CAPABILITY ") {
        let payload = stripped["* CAPABILITY ".len()..].replace(['\r', '\n'], " ");
        let tokens = split_str_ws(&payload);
        if !tokens.is_empty() {
            *caps = tokens.into_iter().map(str::to_owned).collect();
        }
    }
}

/// Move exactly `n` bytes from `reader` to `writer` (`None` drops them),
/// a chunk at a time; `false` if the reader hits EOF first.
async fn copy_exactly<W: AsyncWrite + Unpin>(
    reader: &mut ClientReader,
    mut writer: Option<&mut W>,
    mut n: u64,
) -> Result<bool, SessionError> {
    while n > 0 {
        let want = usize::try_from(n.min(65_536)).unwrap_or(65_536);
        let chunk = reader.read_some(want).await?;
        if chunk.is_empty() {
            return Ok(false);
        }
        n -= chunk.len() as u64;
        if let Some(w) = writer.as_deref_mut() {
            w.write_all(&chunk).await?;
            w.flush().await?;
        }
    }
    Ok(true)
}

async fn reply(out: &ClientOutput<'_>, decision: &Decision) -> Result<(), SessionError> {
    let mut line = decision.tag.clone();
    line.push(b' ');
    line.extend_from_slice(decision.status.as_bytes());
    line.push(b' ');
    line.extend_from_slice(decision.reason.as_bytes());
    line.extend_from_slice(b"\r\n");
    out.relay_reply(&line).await
}

/// Say why the session is ending. Held back like any relay reply while
/// an upstream response is half sent, and dropped rather than waited for.
async fn bye(out: &ClientOutput<'_>, reason: &[u8]) {
    let mut line = b"* BYE ".to_vec();
    line.extend_from_slice(reason);
    line.extend_from_slice(b"\r\n");
    let _ = out.relay_reply(&line).await;
}

/// What the client pipe remembers about one session.
#[derive(Debug)]
struct SessionState {
    utf8_names: bool,
}

// ── Upstream → client filtering ─────────────────────────

/// A reason a response could not be filtered: the session closes rather
/// than leak an unfiltered capability list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unfilterable(pub String);

/// Which response a line is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Capability,
    Data,
    Status,
}

/// The hidden-capability predicate.
pub type HiddenFn = Box<dyn Fn(&str) -> bool + Send + Sync>;
/// Shown the first line of every response; `false` drops that response.
pub type ObserveFn = Box<dyn FnMut(&[u8]) -> bool + Send>;

/// Remove hidden capabilities from the upstream → client byte stream.
///
/// Capability lists reach the cage as an untagged `* CAPABILITY ...` and
/// as a `[CAPABILITY ...]` code in a status response; both are single
/// lines, so the filter works a line at a time. But a message body
/// arrives as a literal (`{n}` CRLF, then n raw bytes) that may well hold
/// a line reading `* CAPABILITY ...`, which is mail and must reach the
/// cage byte-exact. So literals are tracked and passed through as they
/// arrive, never buffered; outside them only the current partial line is
/// held until its LF. A line longer than the held-line limit is flushed
/// and the rest streamed raw, unless it is one the filter must rewrite,
/// which closes the session instead.
///
/// Literals are honoured only in untagged data responses, where the
/// grammar puts strings in quotes or literals; status, tagged and `+`
/// lines carry free text that may echo the cage, and a `{n}` there must
/// not make the filter wave the next n bytes through.
///
/// Outside literals every line goes to the cage ending in CRLF and with
/// every other CR replaced by a space, so a client that ends lines at a
/// bare CR or LF reads the same structure the filter did. Literal bytes
/// are never touched.
#[allow(clippy::struct_excessive_bools)] // the stream position is several independent flags
pub struct ResponseFilter {
    hidden: HiddenFn,
    observe: Option<ObserveFn>,
    held_limit: usize,
    held: Vec<u8>,
    streaming: bool,
    tail: Vec<u8>,
    cr: bool,
    literal: u64,
    continuing: bool,
    data: bool,
    inserts: Vec<u8>,
}

impl std::fmt::Debug for ResponseFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseFilter")
            .field("held", &self.held.len())
            .field("streaming", &self.streaming)
            .field("literal", &self.literal)
            .finish_non_exhaustive()
    }
}

/// A response line, or the start of one, as the cage gets it.
fn clean_line(line: &[u8]) -> Vec<u8> {
    let replace = |b: &[u8]| -> Vec<u8> {
        b.iter()
            .map(|&c| if c == b'\r' { b' ' } else { c })
            .collect()
    };
    if !line.ends_with(b"\n") {
        return replace(line);
    }
    let body = line
        .strip_suffix(b"\r\n")
        .unwrap_or(&line[..line.len() - 1]);
    let mut out = replace(body);
    out.extend_from_slice(b"\r\n");
    out
}

/// `{n}` CRLF (or LF) at the end of the last bytes of a response line.
fn literal_tail(tail: &[u8]) -> Option<u64> {
    let window = &tail[tail.len().saturating_sub(LITERAL_TAIL_BYTES)..];
    let mut body = window.strip_suffix(b"\n")?;
    if let Some(b) = body.strip_suffix(b"\r") {
        body = b;
    }
    let body = body.strip_suffix(b"}")?;
    let digits_start = body
        .iter()
        .rposition(|b| !b.is_ascii_digit())
        .map_or(0, |i| i + 1);
    if digits_start == body.len() || digits_start == 0 || body[digits_start - 1] != b'{' {
        return None;
    }
    let digits = std::str::from_utf8(&body[digits_start..]).ok()?;
    Some(digits.parse().unwrap_or(u64::MAX))
}

impl ResponseFilter {
    /// A filter hiding what `hidden` says, showing response starts to
    /// `observe`, and holding at most `held_limit` bytes of one line.
    #[must_use]
    pub fn new(hidden: HiddenFn, observe: Option<ObserveFn>, held_limit: usize) -> Self {
        Self {
            hidden,
            observe,
            held_limit,
            held: Vec::new(),
            streaming: false,
            tail: Vec::new(),
            cr: false,
            literal: 0,
            continuing: false,
            data: false,
            inserts: Vec::new(),
        }
    }

    /// Whether everything forwarded so far ends with a complete response.
    #[must_use]
    pub fn at_boundary(&self) -> bool {
        !(self.streaming || self.literal > 0 || self.continuing)
    }

    /// Place relay-made whole responses in the stream: returned when they
    /// can go out now, otherwise kept (in order) until the response in
    /// progress is complete.
    pub fn insert(&mut self, data: &[u8]) -> Vec<u8> {
        if !self.inserts.is_empty() || !self.at_boundary() {
            self.inserts.extend_from_slice(data);
            return Vec::new();
        }
        data.to_vec()
    }

    fn flush_inserts(&mut self, out: &mut Vec<u8>) {
        if !self.inserts.is_empty() && self.at_boundary() {
            out.append(&mut self.inserts);
        }
    }

    fn observed(&mut self, line: &[u8]) -> bool {
        self.observe.as_mut().is_none_or(|f| f(line))
    }

    /// Filter one chunk from the upstream.
    ///
    /// # Errors
    ///
    /// [`Unfilterable`] when a line the filter has to rewrite outgrows the
    /// held-line limit.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<u8>, Unfilterable> {
        let mut out = Vec::new();
        let n = chunk.len();
        let mut i = 0;
        while i < n {
            if self.literal > 0 {
                let take = usize::try_from(self.literal)
                    .unwrap_or(usize::MAX)
                    .min(n - i);
                out.extend_from_slice(&chunk[i..i + take]);
                self.literal -= take as u64;
                i += take;
                continue;
            }
            let nl = chunk[i..].iter().position(|&b| b == b'\n').map(|p| p + i);
            let end = nl.map_or(n, |p| p + 1);
            let piece = &chunk[i..end];
            i = end;
            if self.streaming {
                let piece = self.stream_piece(piece, nl.is_some());
                out.extend_from_slice(&piece);
                self.tail.extend_from_slice(&piece);
                let cut = self.tail.len().saturating_sub(LITERAL_TAIL_BYTES);
                self.tail.drain(..cut);
                if nl.is_some() {
                    self.streaming = false;
                    let tail = std::mem::take(&mut self.tail);
                    self.end_line(&tail);
                    self.flush_inserts(&mut out);
                }
                continue;
            }
            self.held.extend_from_slice(piece);
            if nl.is_some() {
                let line = clean_line(&self.held);
                self.held.clear();
                let starting = !self.continuing;
                let kind = self.classify(&line);
                if !starting || self.observed(&line) {
                    out.extend_from_slice(&self.rewrite(&line, kind));
                }
                self.end_line(&line);
                self.flush_inserts(&mut out);
            } else if self.held.len() > self.held_limit {
                let held = std::mem::take(&mut self.held);
                let line = self.stream_piece(&held, false);
                let starting = !self.continuing;
                let kind = self.classify(&line);
                if kind == Kind::Capability
                    || (kind == Kind::Status
                        && line
                            .to_ascii_uppercase()
                            .windows(11)
                            .any(|w| w == b"[CAPABILITY"))
                {
                    return Err(Unfilterable(format!(
                        "upstream capability line longer than {} bytes",
                        self.held_limit
                    )));
                }
                if starting && self.observe.is_some() && !self.observed(&line) {
                    return Err(Unfilterable(format!(
                        "upstream continuation request longer than {} bytes",
                        self.held_limit
                    )));
                }
                out.extend_from_slice(&line);
                self.streaming = true;
                self.tail = line[line.len().saturating_sub(LITERAL_TAIL_BYTES)..].to_vec();
            }
        }
        Ok(out)
    }

    /// Flush a last line the upstream never terminated (at EOF), and relay
    /// replies still held, if the stream ends where they fit.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.streaming && !self.held.is_empty() {
            let held = std::mem::take(&mut self.held);
            let line = clean_line(&held);
            let kind = self.classify(&line);
            out.extend_from_slice(&self.rewrite(&line, kind));
            self.end_line(&line);
        } else if self.streaming && self.cr {
            self.cr = false;
            out.push(b' '); // no LF came after it
        }
        self.flush_inserts(&mut out);
        out
    }

    /// [`clean_line`] for one piece of a line streamed raw: a CR the last
    /// piece ended in goes in front, and a CR this one ends in is held
    /// back unless the piece ends the line.
    fn stream_piece(&mut self, piece: &[u8], ends_line: bool) -> Vec<u8> {
        let mut piece = piece.to_vec();
        if self.cr {
            piece.insert(0, b'\r');
            self.cr = false;
        }
        if ends_line {
            return clean_line(&piece);
        }
        if piece.ends_with(b"\r") {
            self.cr = true;
            piece.pop();
        }
        piece
            .iter()
            .map(|&c| if c == b'\r' { b' ' } else { c })
            .collect()
    }

    fn classify(&mut self, line: &[u8]) -> Kind {
        if self.continuing {
            return Kind::Data;
        }
        let head = line[..line.len().min(13)].to_ascii_uppercase();
        let head = trim_crlf_end(&head);
        if head == b"* CAPABILITY" || head == b"* CAPABILITY " {
            self.data = false;
            return Kind::Capability;
        }
        let words = split_ws(line, Some(2));
        self.data = words.len() >= 2
            && words[0] == b"*"
            && !STATUS_WORDS.contains(&words[1].to_ascii_uppercase().as_slice());
        if self.data { Kind::Data } else { Kind::Status }
    }

    fn end_line(&mut self, tail: &[u8]) {
        let literal = if self.data { literal_tail(tail) } else { None };
        if let Some(n) = literal {
            self.literal = n;
            self.continuing = true;
        } else {
            self.continuing = false;
            self.data = false;
        }
    }

    fn rewrite(&self, line: &[u8], kind: Kind) -> Vec<u8> {
        if kind == Kind::Data {
            return line.to_vec();
        }
        let body = trim_crlf_end(line);
        let eol = &line[body.len()..];
        let (start, close) = if kind == Kind::Capability {
            (b"* CAPABILITY".len(), body.len())
        } else {
            let upper = body.to_ascii_uppercase();
            let Some(idx) = upper.windows(11).position(|w| w == b"[CAPABILITY") else {
                return line.to_vec();
            };
            let start = idx + 11;
            if !matches!(body.get(start), Some(b' ' | b']')) {
                return line.to_vec(); // another response code that merely starts alike
            }
            let close = body[start..]
                .iter()
                .position(|&b| b == b']')
                .map_or(body.len(), |p| p + start);
            (start, close)
        };
        let mut out = body[..start].to_vec();
        for token in split_ws(&body[start..close], None) {
            if !(self.hidden)(&ascii_lossy(token)) {
                out.push(b' ');
                out.extend_from_slice(token);
            }
        }
        out.extend_from_slice(&body[close..]);
        out.extend_from_slice(eol);
        out
    }
}

fn trim_crlf_end(data: &[u8]) -> &[u8] {
    let end = data
        .iter()
        .rposition(|&b| b != b'\r' && b != b'\n')
        .map_or(0, |i| i + 1);
    &data[..end]
}

/// Why writing to the cage failed.
#[derive(Debug)]
enum OutputError {
    /// The cage's socket failed; the session ends quietly.
    Io,
    Unfilterable(String),
}

/// The one way bytes reach the cage once the session is bridged.
///
/// Two pipes write to the cage: the upstream's responses and the relay's
/// own replies. Commands are pipelined, so a reply can be ready while the
/// upstream is half way through a response, say inside a FETCH literal,
/// where it would become part of the message body. So a relay reply goes
/// out only between complete upstream responses, held by the filter
/// until the response in progress ends. Feeding the filter and writing
/// its output happen under one lock, so what the filter believes has
/// been sent is what the socket was given.
struct ClientOutput<'a> {
    inner: tokio::sync::Mutex<(&'a mut tokio::net::tcp::OwnedWriteHalf, ResponseFilter)>,
}

impl ClientOutput<'_> {
    /// Forward upstream bytes (empty at EOF).
    async fn upstream_bytes(&self, chunk: &[u8]) -> Result<(), OutputError> {
        let mut guard = self.inner.lock().await;
        let (writer, filter) = &mut *guard;
        let out = if chunk.is_empty() {
            filter.finish()
        } else {
            filter
                .feed(chunk)
                .map_err(|Unfilterable(r)| OutputError::Unfilterable(r))?
        };
        if !out.is_empty() {
            writer.write_all(&out).await.map_err(|_| OutputError::Io)?;
        }
        Ok(())
    }

    /// Send a reply the relay made itself, at the next boundary.
    async fn relay_reply(&self, data: &[u8]) -> Result<(), SessionError> {
        let mut guard = self.inner.lock().await;
        let (writer, filter) = &mut *guard;
        let out = filter.insert(data);
        if !out.is_empty() {
            writer.write_all(&out).await?;
        }
        Ok(())
    }
}

// ── What the upstream still owes ────────────────────────

/// What the upstream still owes the relay, shared by the two pipes.
///
/// For each literal it forwards, the client pipe needs to know whether
/// the upstream answered the announcing line with `+` (send the literal)
/// or a tagged response (the command is over). Only the upstream pipe
/// sees responses, so it shows every response's first line to
/// [`Tracker::observe`]. A `+` has no tag, so it is only unambiguous when
/// nothing else outstanding could ask for one (an IDLE, another literal):
/// before forwarding a literal line, the client pipe waits until every
/// other command it forwarded has had its tagged response.
#[derive(Debug)]
struct Tracker {
    state: Mutex<TrackerState>,
    count: watch::Sender<usize>,
}

#[derive(Debug, Default)]
struct TrackerState {
    outstanding: HashMap<Vec<u8>, usize>,
    count: usize,
    waiter: Option<(Vec<u8>, oneshot::Sender<bool>, bool)>,
}

impl Default for Tracker {
    fn default() -> Self {
        Self {
            state: Mutex::new(TrackerState::default()),
            count: watch::channel(0).0,
        }
    }
}

impl Tracker {
    fn lock(&self) -> std::sync::MutexGuard<'_, TrackerState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn outstanding(&self) -> usize {
        self.lock().count
    }

    /// A command with `tag` was forwarded; the upstream owes a reply.
    fn sent(&self, tag: &[u8]) {
        let mut st = self.lock();
        *st.outstanding.entry(tag.to_vec()).or_insert(0) += 1;
        st.count += 1;
        let count = st.count;
        drop(st);
        self.count.send_replace(count);
    }

    /// Wait until at most `allowed` forwarded commands are unanswered.
    async fn settle(&self, allowed: usize) {
        let mut rx = self.count.subscribe();
        let _ = rx.wait_for(|c| *c <= allowed).await;
    }

    /// The upstream's answer to a literal of command `tag`: `true` for
    /// `+` (forwarded to the cage only when `forward`), `false` for the
    /// tagged response.
    fn expect_continuation(&self, tag: &[u8], forward: bool) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        self.lock().waiter = Some((tag.to_vec(), tx, forward));
        rx
    }

    /// See the first line of an upstream response; `false` drops it.
    fn observe(&self, line: &[u8]) -> bool {
        let mut st = self.lock();
        if line.first() == Some(&b'+') {
            let Some((_, tx, forward)) = st.waiter.take() else {
                return true; // IDLE's, or one the cage asked for itself
            };
            let _ = tx.send(true);
            return forward;
        }
        let words = split_ws(line, Some(2));
        if words.len() < 2
            || words[0] == b"*"
            || !COMPLETION_WORDS.contains(&words[1].to_ascii_uppercase().as_slice())
        {
            return true;
        }
        let tag = words[0].to_vec();
        let n = st.outstanding.get(&tag).copied().unwrap_or(0);
        if n > 0 {
            if n == 1 {
                st.outstanding.remove(&tag);
            } else {
                st.outstanding.insert(tag.clone(), n - 1);
            }
            st.count -= 1;
            self.count.send_replace(st.count);
        }
        if st.waiter.as_ref().is_some_and(|(t, _, _)| *t == tag)
            && let Some((_, tx, _)) = st.waiter.take()
        {
            let _ = tx.send(false);
        }
        true
    }
}

#[cfg(test)]
#[path = "imap_tests.rs"]
mod tests;
