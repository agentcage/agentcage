//! Secret injection and redaction: placeholder → real value on the way
//! out for hosts in `inject_to`, real value → placeholder everywhere a
//! record is kept, Basic-auth aware, in literal and encoded forms.
//!
//! The cage only ever holds placeholders (`agentcage:secret:<ENV>:<hex>`).
//! On a request to a host a rule's `inject_to` covers, the placeholder is
//! swapped for the rule's real value, or for the value its transform
//! derives (a minted access token). Strict mode, the default, only touches
//! credential-bearing headers (a name containing `auth`, `key` or `token`,
//! or listed in `inject_headers`), including inside `Authorization:
//! Basic`; `inject_body: true` also rewrites the URL (which may re-target
//! the request), every header and the body.
//!
//! The other direction is redaction: every real value, and every token a
//! transform minted that may still be live, is swapped back to its
//! placeholder in responses, in what capture stores, in WebSocket frames
//! and in every audit record. Redaction also matches each secret's
//! *encoded* forms — percent-encoded (either hex case, `+` for a space),
//! JSON-escaped, and inside a standard or URL-safe base64 blob at any byte
//! offset — and writes the placeholder in the same encoding, so a server
//! echoing a URL or a header in an error body cannot carry the value back
//! to the cage (see [`SecretForms`]).
//!
//! Before anything is mutated, [`Injector::check_injection_policy`] blocks
//! a request that carries a real value (in any of those forms) to a host
//! outside its rule's `inject_to`, and flags a placeholder sent where it
//! will not be injected.
//!
//! Headers are read the way the pipeline's multidict reads them: one value
//! per distinct name, duplicates folded with `", "`; writing a header
//! collapses its duplicates into that one folded value at the first
//! occurrence's position. Bodies are read with their Content-Encoding
//! removed; a body that was rewritten is sent identity-encoded, with
//! `Content-Encoding` dropped and `Content-Length` fixed. An unmodified
//! body is forwarded byte for byte.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use memchr::memmem;
use regex::bytes::{Captures, Regex};

use crate::config::{self, Mapping, Value};
use crate::inspect::{Action, Severity, Verdict};
use crate::json::Json;
use crate::message::{Headers, Request, Response};
use crate::text::DecodeError;
use crate::transforms::{Transform, TransformError};

/// The keyword stems that make a header credential-bearing under strict
/// injection (matched as case-insensitive substrings of its name).
///
/// Almost every API's auth header contains one (`Authorization`,
/// `x-api-key`, `x-goog-api-key`, `private-token`, `x-auth-token`,
/// `ocp-apim-subscription-key`, …). The match only matters where a rule's
/// unique placeholder already sits, so a broad match cannot put a secret
/// anywhere the agent did not. Headers without a stem (Honeycomb's
/// `x-honeycomb-team`) go in a rule's `inject_headers`.
pub const AUTH_HEADER_KEYWORDS: [&str; 3] = ["auth", "key", "token"];

/// The inspector name injection-policy verdicts carry.
pub const INSPECTOR_NAME: &str = "secret-injector";

// ── Errors ───────────────────────────────────────────────

/// Why a request could not be injected or redacted. The pipeline fails
/// closed on either (plan D1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InjectError {
    /// The body's Content-Encoding could not be removed.
    Body(DecodeError),
    /// Rewriting the URL produced one that does not parse.
    Url(String),
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Body(e) => write!(f, "{e}"),
            Self::Url(e) => write!(f, "invalid URL after rewrite: {e}"),
        }
    }
}

impl std::error::Error for InjectError {}

impl From<DecodeError> for InjectError {
    fn from(e: DecodeError) -> Self {
        Self::Body(e)
    }
}

// ── Base64 ───────────────────────────────────────────────

/// Standard base64, padded.
#[must_use]
pub(crate) fn b64_encode_std(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_value(c: u8) -> Option<u32> {
    Some(u32::from(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    }))
}

/// `base64.b64decode(data, validate=True)`: the standard alphabet only,
/// exactly the padding the length needs, nothing after it; stray low bits
/// in the last character are ignored.
#[must_use]
pub(crate) fn b64_decode_strict(data: &[u8]) -> Option<Vec<u8>> {
    let pads = data.iter().rev().take_while(|&&c| c == b'=').count();
    let body = &data[..data.len() - pads];
    let needed = match body.len() % 4 {
        0 => 0,
        1 => return None,
        2 => 2,
        _ => 1,
    };
    if pads != needed {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in body {
        acc = (acc << 6) | b64_value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            #[allow(clippy::cast_possible_truncation)]
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// [`b64_decode_strict`] for text.
#[must_use]
pub(crate) fn b64_decode_std(text: &str) -> Option<Vec<u8>> {
    b64_decode_strict(text.as_bytes())
}

fn std_to_url(data: &mut [u8]) {
    for b in data {
        match *b {
            b'+' => *b = b'-',
            b'/' => *b = b'_',
            _ => {}
        }
    }
}

fn url_to_std(data: &mut [u8]) {
    for b in data {
        match *b {
            b'-' => *b = b'+',
            b'_' => *b = b'/',
            _ => {}
        }
    }
}

// ── Byte helpers ─────────────────────────────────────────

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    memmem::find(haystack, needle).is_some()
}

/// `haystack.replace(needle, with)`: every non-overlapping occurrence,
/// left to right. `needle` is never empty here.
fn replace_all(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(haystack.len());
    let mut last = 0;
    for i in memmem::find_iter(haystack, needle) {
        if i < last {
            continue;
        }
        out.extend_from_slice(&haystack[last..i]);
        out.extend_from_slice(with);
        last = i + needle.len();
    }
    out.extend_from_slice(&haystack[last..]);
    out
}

/// The distinct header names (first spelling, first-seen order) with their
/// folded values: what iterating the multidict's keys / values gives.
fn header_items(headers: &Headers) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (k, v) in &headers.0 {
        if let Some((_, folded)) = out
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case(k))
        {
            folded.extend_from_slice(b", ");
            folded.extend_from_slice(v);
        } else {
            out.push((k.clone(), v.clone()));
        }
    }
    out
}

/// `headers[name] = value` by raw name: the first occurrence keeps its
/// position and spelling, the others are dropped.
fn set_header(headers: &mut Headers, name: &[u8], value: Vec<u8>) {
    let mut value = Some(value);
    headers.0.retain_mut(|(k, v)| {
        if !k.eq_ignore_ascii_case(name) {
            return true;
        }
        match value.take() {
            Some(new) => {
                *v = new;
                true
            }
            None => false,
        }
    });
    if let Some(new) = value {
        headers.0.push((name.to_vec(), new));
    }
}

/// Store a rewritten body: identity-encoded, `Content-Encoding` removed,
/// `Content-Length` fixed (left alone under `Transfer-Encoding`).
fn store_body(headers: &mut Headers, body: &mut Vec<u8>, new: Vec<u8>) {
    headers.remove("content-encoding");
    if !headers.contains("transfer-encoding") {
        headers.set("content-length", new.len().to_string());
    }
    *body = new;
}

/// A message body read lazily (decoding only when a check reaches it, as
/// the replaced implementation did) and written back once.
#[derive(Default)]
struct LazyBody {
    decoded: Option<Vec<u8>>,
    modified: bool,
}

impl LazyBody {
    fn get(&mut self, headers: &Headers, raw: &[u8]) -> Result<&[u8], DecodeError> {
        if self.decoded.is_none() {
            self.decoded = Some(crate::text::decoded_body(headers, raw)?.into_owned());
        }
        Ok(self.decoded.as_deref().unwrap_or_default())
    }

    fn set(&mut self, new: Vec<u8>) {
        self.decoded = Some(new);
        self.modified = true;
    }

    fn finish(self, headers: &mut Headers, body: &mut Vec<u8>) {
        if self.modified {
            store_body(headers, body, self.decoded.unwrap_or_default());
        }
    }
}

// ── Basic auth ───────────────────────────────────────────

/// Rewrite `find` → `replace` inside an HTTP Basic credential.
///
/// A literal match cannot reach a placeholder (or a secret) inside
/// `Authorization: Basic base64("user:<secret>")`, which is how git over
/// HTTPS sends its token. The credential is decoded (strict base64, then
/// UTF-8), substituted and re-encoded; the scheme's spelling is kept.
/// `None` when the value is not Basic, does not decode, or does not hold
/// `find`.
#[must_use]
pub fn rewrite_basic_auth(value: &[u8], find: &[u8], replace: &[u8]) -> Option<Vec<u8>> {
    let space = memchr::memchr(b' ', value)?;
    let (scheme, rest) = (&value[..space], &value[space + 1..]);
    if !scheme.eq_ignore_ascii_case(b"basic") {
        return None;
    }
    let rest = std::str::from_utf8(rest).ok()?;
    let decoded = b64_decode_std(rest.trim_matches(crate::text::py_is_space))?;
    std::str::from_utf8(&decoded).ok()?;
    if !contains(&decoded, find) {
        return None;
    }
    let mut out = scheme.to_vec();
    out.push(b' ');
    out.extend_from_slice(b64_encode_std(&replace_all(&decoded, find, replace)).as_bytes());
    Some(out)
}

// ── Encoded forms of a secret ────────────────────────────

/// Characters no common encoder escapes (RFC 3986 unreserved minus `~`,
/// which form encoding does escape): matched only literally.
fn unescaped(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_')
}

/// Shortest value whose base64 forms are matched: its cores are at least
/// 10 characters, too long to turn up by chance.
const B64_MIN_BYTES: usize = 8;

fn b64_std_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

fn b64_url_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// A regex for `number` in `width` hex digits, either case.
fn hex_class(number: u32, width: usize) -> String {
    format!("{number:0width$X}")
        .chars()
        .map(|d| {
            if d.is_ascii_alphabetic() {
                format!("[{d}{}]", d.to_ascii_lowercase())
            } else {
                d.to_string()
            }
        })
        .collect()
}

/// The regex for one character of a secret, every way it may be spelled,
/// and whether it has a spelling besides the literal.
fn char_pattern(ch: char) -> (String, bool) {
    let mut buf = [0u8; 4];
    let raw = ch.encode_utf8(&mut buf).as_bytes();
    let literal = regex::escape(ch.encode_utf8(&mut [0u8; 4]));
    if raw.len() == 1 && unescaped(raw[0]) {
        return (literal, false);
    }
    let mut alts = vec![
        literal,
        raw.iter().fold(String::new(), |mut out, &b| {
            out.push('%');
            out.push_str(&hex_class(u32::from(b), 2));
            out
        }),
    ];
    if ch == ' ' {
        alts.push(r"\+".into());
    }
    let mut units = [0u16; 2];
    alts.push(
        ch.encode_utf16(&mut units)
            .iter()
            .fold(String::new(), |mut out, &u| {
                out.push_str(r"\\u");
                out.push_str(&hex_class(u32::from(u), 4));
                out
            }),
    );
    let short = match ch {
        '"' => Some(r#"\""#),
        '\\' => Some(r"\\"),
        '/' => Some(r"\/"),
        '\u{8}' => Some(r"\b"),
        '\u{c}' => Some(r"\f"),
        '\n' => Some(r"\n"),
        '\r' => Some(r"\r"),
        '\t' => Some(r"\t"),
        _ => None,
    };
    if let Some(short) = short {
        alts.push(regex::escape(short));
    }
    (format!("(?:{})", alts.join("|")), true)
}

/// The base64 characters fixed by `raw` alone at each of the three byte
/// alignments, in the standard and the URL-safe alphabet.
fn base64_cores(raw: &[u8]) -> Vec<Vec<u8>> {
    let mut cores: Vec<Vec<u8>> = Vec::new();
    for shift in 0..3usize {
        let mut padded = vec![0u8; shift];
        padded.extend_from_slice(raw);
        let enc = b64_encode_std(&padded).into_bytes();
        let start = (8 * shift).div_ceil(6);
        let end = 8 * (shift + raw.len()) / 6;
        let core = enc[start..end].to_vec();
        let mut url = core.clone();
        std_to_url(&mut url);
        for c in [core, url] {
            if !cores.contains(&c) {
                cores.push(c);
            }
        }
    }
    cores
}

/// `blob` (base64 characters, no padding) re-encoded with `raw` in its
/// decoded bytes replaced by `ph_raw`; `None` when it does not decode to
/// bytes holding `raw`. Up to three leading characters that are not part
/// of the blob are tolerated (kept as they are).
fn replace_in_base64(
    blob: &[u8],
    raw: &[u8],
    ph_raw: &[u8],
    urlsafe: bool,
    padded: bool,
) -> Option<Vec<u8>> {
    for off in 0..4 {
        let mut body = blob.get(off..).unwrap_or_default();
        let mut tail: &[u8] = b"";
        if body.len() % 4 == 1 {
            tail = &body[body.len() - 1..];
            body = &body[..body.len() - 1];
        }
        let mut std = body.to_vec();
        if urlsafe {
            url_to_std(&mut std);
        }
        std.resize(std.len() + (4 - std.len() % 4) % 4, b'=');
        let Some(decoded) = b64_decode_strict(&std) else {
            continue;
        };
        if !contains(&decoded, raw) {
            continue;
        }
        let mut enc = b64_encode_std(&replace_all(&decoded, raw, ph_raw)).into_bytes();
        if urlsafe {
            std_to_url(&mut enc);
        }
        if !padded {
            while enc.last() == Some(&b'=') {
                enc.pop();
            }
        }
        let mut out = blob[..off.min(blob.len())].to_vec();
        out.extend_from_slice(&enc);
        out.extend_from_slice(tail);
        return Some(out);
    }
    None
}

/// `data` with every base64 blob that contains `core` and decodes to
/// bytes holding `raw` re-encoded with `ph_raw` in its place, and how
/// many were.
fn rewrite_base64(mut data: Vec<u8>, core: &[u8], raw: &[u8], ph_raw: &[u8]) -> (Vec<u8>, usize) {
    let mut count = 0;
    let mut pos = 0;
    while let Some(found) = data.get(pos..).and_then(|rest| memmem::find(rest, core)) {
        let i = pos + found;
        pos = i + 1;
        for (is_char, urlsafe) in [
            (b64_std_char as fn(u8) -> bool, false),
            (b64_url_char, true),
        ] {
            let mut start = i;
            while start > 0 && is_char(data[start - 1]) {
                start -= 1;
            }
            let mut end = i + core.len();
            while end < data.len() && is_char(data[end]) {
                end += 1;
            }
            let mut pad_end = end;
            while pad_end < data.len() && pad_end - end < 2 && data[pad_end] == b'=' {
                pad_end += 1;
            }
            // Re-encoded padded if the blob was, and when it needed no
            // padding (a multiple of four characters): standard base64 is
            // padded (`Authorization: Basic`), URL-safe usually not (JWT).
            let padded = pad_end > end || (!urlsafe && (end - start) % 4 == 0);
            if let Some(new) = replace_in_base64(&data[start..end], raw, ph_raw, urlsafe, padded) {
                let mut out = data[..start].to_vec();
                out.extend_from_slice(&new);
                out.extend_from_slice(&data[pad_end..]);
                pos = start + new.len();
                data = out;
                count += 1;
                break;
            }
        }
    }
    (data, count)
}

static PERCENT_ESCAPE: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new("%[0-9A-Fa-f]{2}").expect("static regex"));
static LOWER_HEX_ESCAPE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new("%(?:[a-f][0-9a-fA-F]|[0-9A-F][a-f])").expect("static regex")
});

/// One secret value with what matching its derived forms needs, built
/// once per value and cached by the [`Injector`].
///
/// The forms (plan §5.4, Phase 0a.32):
///
/// * escaped: every character either literal or as one of its escapes —
///   `%XX` per UTF-8 byte (either hex case), `+` for a space, a JSON
///   `\uXXXX` (a surrogate pair past the BMP) or JSON short escape.
///   Letters, digits and `-._`, which no common encoder escapes, match only
///   literally; that makes the value's longest run of them an anchor
///   every match contains, so the pattern only runs on content holding it.
/// * base64: the value at any byte offset of a standard or URL-safe blob,
///   padded or not, found by the three alignment cores, for values of at
///   least 8 bytes.
///
/// The placeholder takes the match's encoding: percent-encoded (same hex
/// case) where it used `%XX` or `+`, JSON-escaped where it used a
/// backslash escape, literal otherwise.
#[derive(Debug)]
pub struct SecretForms {
    value: String,
    placeholder: String,
    name: String,
    pattern: Option<Regex>,
    anchor: Option<Vec<u8>>,
    b64_cores: Vec<Vec<u8>>,
    ph_percent: Vec<u8>,
    ph_json: Vec<u8>,
}

impl SecretForms {
    /// The forms of `value`, redacted to `placeholder`, for rule `name`.
    ///
    /// # Panics
    ///
    /// Never in practice: the pattern is built from escaped literals.
    #[must_use]
    pub fn new(value: &str, placeholder: &str, name: &str) -> Self {
        let raw = value.as_bytes();
        let parts: Vec<(String, bool)> = value.chars().map(char_pattern).collect();
        let (mut pattern, mut anchor) = (None, None);
        if parts.iter().any(|(_, escapable)| *escapable) {
            let source: String = parts.iter().map(|(p, _)| p.as_str()).collect();
            pattern = Some(Regex::new(&source).expect("escaped secret pattern"));
            // The first longest run of never-escaped characters.
            let mut best: &[u8] = b"";
            for run in raw.split(|&b| !unescaped(b)) {
                if run.len() > best.len() {
                    best = run;
                }
            }
            anchor = (!best.is_empty()).then(|| best.to_vec());
        }
        let b64_cores = if raw.len() >= B64_MIN_BYTES {
            base64_cores(raw)
        } else {
            Vec::new()
        };
        let mut ph_percent = Vec::new();
        for b in placeholder.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~') {
                ph_percent.push(b);
            } else {
                ph_percent.extend_from_slice(format!("%{b:02X}").as_bytes());
            }
        }
        let quoted = crate::json::to_string(&Json::string(placeholder));
        let ph_json = quoted.as_bytes()[1..quoted.len() - 1].to_vec();
        Self {
            value: value.to_owned(),
            placeholder: placeholder.to_owned(),
            name: name.to_owned(),
            pattern,
            anchor,
            b64_cores,
            ph_percent,
            ph_json,
        }
    }

    /// The rule name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    fn raw(&self) -> &[u8] {
        self.value.as_bytes()
    }

    fn ph_raw(&self) -> &[u8] {
        self.placeholder.as_bytes()
    }

    fn has_derived(&self) -> bool {
        self.pattern.is_some() || !self.b64_cores.is_empty()
    }

    /// The placeholder in the encoding of an escaped-form match `m`.
    fn placeholder_for(&self, m: &[u8]) -> Vec<u8> {
        let plus_for_space = contains(self.raw(), b" ")
            && !contains(m, b" ")
            && !contains(&m.to_ascii_uppercase(), b"%20")
            && !contains(&m.to_ascii_lowercase(), b"\\u0020");
        if PERCENT_ESCAPE.is_match(m) || plus_for_space {
            if LOWER_HEX_ESCAPE.is_match(m) {
                // Every `%XX` of the placeholder in lower-case hex; its
                // other characters are unreserved and stay as they are.
                let mut out = self.ph_percent.clone();
                let mut i = 0;
                while i + 2 < out.len() {
                    if out[i] == b'%' {
                        out[i + 1] = out[i + 1].to_ascii_lowercase();
                        out[i + 2] = out[i + 2].to_ascii_lowercase();
                        i += 3;
                    } else {
                        i += 1;
                    }
                }
                return out;
            }
            return self.ph_percent.clone();
        }
        if contains(m, b"\\") {
            return self.ph_json.clone();
        }
        self.ph_raw().to_vec()
    }

    fn redact_derived(&self, data: Vec<u8>) -> (Vec<u8>, bool) {
        let mut data = data;
        let mut found = false;
        if let Some(pattern) = &self.pattern {
            if self.anchor.as_deref().is_none_or(|a| contains(&data, a)) {
                let mut n = 0usize;
                let replaced = pattern.replace_all(&data, |caps: &Captures<'_>| {
                    n += 1;
                    self.placeholder_for(&caps[0])
                });
                if n > 0 {
                    data = replaced.into_owned();
                    found = true;
                }
            }
        }
        for core in &self.b64_cores {
            if contains(&data, core) {
                let (new, n) = rewrite_base64(data, core, self.raw(), self.ph_raw());
                data = new;
                found = found || n > 0;
            }
        }
        (data, found)
    }

    /// `data` with the literal and every derived form replaced by the
    /// placeholder; `None` when nothing matched.
    #[must_use]
    pub fn redact(&self, data: &[u8]) -> Option<Vec<u8>> {
        let mut found = false;
        let mut out = if contains(data, self.raw()) {
            found = true;
            replace_all(data, self.raw(), self.ph_raw())
        } else {
            data.to_vec()
        };
        if self.has_derived() {
            let (new, derived) = self.redact_derived(out);
            out = new;
            found = found || derived;
        }
        found.then_some(out)
    }

    /// [`SecretForms::redact`] for text.
    #[must_use]
    pub fn redact_text(&self, text: &str) -> Option<String> {
        self.redact(text.as_bytes()).map(|b| {
            String::from_utf8(b)
                .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
        })
    }

    /// Whether `data` holds the literal or a derived form.
    #[must_use]
    pub fn occurs(&self, data: &[u8]) -> bool {
        contains(data, self.raw()) || (self.has_derived() && self.redact_derived(data.to_vec()).1)
    }
}

// ── URL re-parse ─────────────────────────────────────────

/// `urllib.parse.urlsplit`, for the URLs the pipeline writes and the
/// audience it validates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct UrlParts {
    pub(crate) scheme: String,
    pub(crate) netloc: String,
    pub(crate) path: String,
    pub(crate) query: Option<String>,
    pub(crate) fragment: Option<String>,
}

impl UrlParts {
    fn host_and_port(&self) -> (&str, Option<&str>) {
        let hostinfo = self
            .netloc
            .rsplit_once('@')
            .map_or(self.netloc.as_str(), |(_, h)| h);
        if let Some(rest) = hostinfo.strip_prefix('[') {
            match rest.split_once(']') {
                Some((host, after)) => (host, after.strip_prefix(':')),
                None => (rest, None),
            }
        } else {
            match hostinfo.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (hostinfo, None),
            }
        }
    }

    /// `.hostname`: lower-cased, brackets removed, `None` when empty.
    pub(crate) fn hostname(&self) -> Option<String> {
        let (host, _) = self.host_and_port();
        (!host.is_empty()).then(|| host.to_lowercase())
    }
}

/// Split a URL the way `urlsplit` does (the scheme lower-cased; tabs and
/// newlines removed; leading C0 controls and spaces stripped).
pub(crate) fn urlsplit(url: &str) -> UrlParts {
    let cleaned: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = cleaned.as_str();
    let mut parts = UrlParts::default();
    if let Some(i) = rest.find(':') {
        let scheme = &rest[..i];
        let valid = scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if valid {
            parts.scheme = scheme.to_ascii_lowercase();
            rest = &rest[i + 1..];
        }
    }
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        after[..end].clone_into(&mut parts.netloc);
        rest = &after[end..];
    }
    if let Some((before, fragment)) = rest.split_once('#') {
        parts.fragment = Some(fragment.to_owned());
        rest = before;
    }
    if let Some((before, query)) = rest.split_once('?') {
        parts.query = Some(query.to_owned());
        rest = before;
    }
    rest.clone_into(&mut parts.path);
    parts
}

/// A DNS name or address literal the pipeline accepts as a request host.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 255 || !host.is_ascii() {
        return false;
    }
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    trimmed.split('.').all(label_ok) || host.parse::<std::net::IpAddr>().is_ok()
}

/// Assign `url` to the request, as setting the URL did: scheme, host,
/// port and path re-parsed (the port defaulting from the scheme), and a
/// `Host` header, if present, rewritten to `host[:port]`.
fn set_url(req: &mut Request, url: &str) -> Result<(), String> {
    let parts = urlsplit(url);
    let host = parts.hostname().ok_or("no hostname given")?;
    if !is_valid_host(&host) {
        return Err(format!("invalid host {host:?}"));
    }
    let port = match parts.host_and_port().1 {
        None | Some("") => None,
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => Some(
            p.parse::<u16>()
                .map_err(|_| format!("port out of range: {p}"))?,
        ),
        Some(p) => return Err(format!("port could not be cast to an integer: {p:?}")),
    };
    let port = match port {
        Some(p) if p != 0 => p,
        _ if parts.scheme == "https" => 443,
        _ => 80,
    };
    // urlparse splits `;params` off the last path segment and
    // urlunparse drops empty params, query and fragment.
    let (mut path, params) = {
        let from = parts.path.rfind('/').unwrap_or(0);
        match parts.path[from..].find(';') {
            Some(i) => (
                parts.path[..from + i].to_owned(),
                parts.path[from + i + 1..].to_owned(),
            ),
            None => (parts.path.clone(), String::new()),
        }
    };
    if !params.is_empty() {
        path = format!("{path};{params}");
    }
    if let Some(q) = parts.query.as_deref().filter(|q| !q.is_empty()) {
        path = format!("{path}?{q}");
    }
    if let Some(f) = parts.fragment.as_deref().filter(|f| !f.is_empty()) {
        path = format!("{path}#{f}");
    }
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.is_ascii() {
        return Err("non-ASCII path".into());
    }
    req.scheme = parts.scheme;
    req.host = host;
    req.port = port;
    req.path = path;
    if req.headers.contains("host") {
        let default = matches!(
            (req.scheme.as_str(), req.port),
            ("http", 80) | ("https", 443)
        );
        let shown = if req.host.contains(':') {
            format!("[{}]", req.host)
        } else {
            req.host.clone()
        };
        let value = if default {
            shown
        } else {
            format!("{shown}:{}", req.port)
        };
        req.headers.set("host", value);
    }
    Ok(())
}

// ── Rules ────────────────────────────────────────────────

/// One injection rule, resolved.
#[derive(Debug)]
pub struct Rule {
    /// The secret's env name, e.g. `ANTHROPIC_API_KEY`.
    pub name: String,
    /// The placeholder the cage holds. Never empty.
    pub placeholder: String,
    /// The resolved secret. Never empty. With a transform, this is the
    /// underlying credential (kept so its literal bytes are still blocked).
    pub real_value: String,
    /// Lower-cased domains the value is injected for (suffix match);
    /// empty means never.
    pub inject_to: Vec<String>,
    /// The transform's config name, or `""`.
    pub transform: String,
    /// The live transform, if any.
    pub transform_impl: Option<Arc<dyn Transform>>,
    /// Loose mode: inject into the URL, every header, the body and
    /// WebSocket frames too.
    pub inject_body: bool,
    /// Extra credential-bearing header names (case-insensitive).
    pub inject_headers: Vec<String>,
    /// The last two derived values, for a transform that does not list
    /// its own.
    recent: Mutex<Vec<String>>,
}

impl Rule {
    /// A static rule (no transform). `inject_to` is taken as given;
    /// [`Injector::configure`] lower-cases it, matching hosts does not.
    #[must_use]
    pub fn new(name: &str, placeholder: &str, real_value: &str, inject_to: &[&str]) -> Self {
        Self {
            name: name.to_owned(),
            placeholder: placeholder.to_owned(),
            real_value: real_value.to_owned(),
            inject_to: inject_to.iter().map(|d| (*d).to_owned()).collect(),
            transform: String::new(),
            transform_impl: None,
            inject_body: false,
            inject_headers: Vec::new(),
            recent: Mutex::new(Vec::new()),
        }
    }

    /// The same rule with `inject_body` set.
    #[must_use]
    pub fn with_inject_body(mut self, on: bool) -> Self {
        self.inject_body = on;
        self
    }

    /// The same rule with extra credential header names.
    #[must_use]
    pub fn with_inject_headers(mut self, headers: &[&str]) -> Self {
        self.inject_headers = headers.iter().map(|h| (*h).to_owned()).collect();
        self
    }

    /// The same rule with a transform.
    #[must_use]
    pub fn with_transform(mut self, name: &str, transform: Arc<dyn Transform>) -> Self {
        name.clone_into(&mut self.transform);
        self.transform_impl = Some(transform);
        self
    }

    /// Whether `name` is a credential-bearing header this rule injects
    /// into under the strict default.
    #[must_use]
    pub fn is_auth_header(&self, name: &str) -> bool {
        let n = name.to_lowercase();
        AUTH_HEADER_KEYWORDS.iter().any(|kw| n.contains(kw))
            || self
                .inject_headers
                .iter()
                .any(|extra| n == extra.to_lowercase())
    }

    /// The transform's value for the wire.
    fn derive_value(&self, transform: &dyn Transform) -> Result<String, TransformError> {
        let value = transform.get_value()?;
        if transform.active_values().is_none() {
            let mut recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
            if recent.first() != Some(&value) {
                let previous = recent.first().cloned();
                *recent = std::iter::once(value.clone()).chain(previous).collect();
            }
        }
        Ok(value)
    }

    /// Values the transform produced that may still be on the wire (none
    /// without a transform).
    #[must_use]
    pub fn minted_values(&self) -> Vec<String> {
        let Some(transform) = &self.transform_impl else {
            return Vec::new();
        };
        let values = transform.active_values().unwrap_or_else(|| {
            self.recent
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        });
        values
            .into_iter()
            .filter(|v| !v.is_empty() && *v != self.real_value)
            .collect()
    }

    fn the_value(&self) -> Option<String> {
        match &self.transform_impl {
            Some(transform) => match self.derive_value(transform.as_ref()) {
                Ok(v) => Some(v),
                Err(e) => {
                    eprintln!(
                        "secret_injection: transform {} ({}) failed: {e} — leaving placeholder in place",
                        self.transform, self.name
                    );
                    None
                }
            },
            None => Some(self.real_value.clone()),
        }
    }
}

/// Suffix match on dot boundaries, case-insensitive: `example.com`
/// covers itself and every subdomain, never `notexample.com`.
#[must_use]
pub fn domain_matches(host: &str, domains: &[String]) -> bool {
    let host = host.to_lowercase();
    let parts: Vec<&str> = host.split('.').collect();
    (0..parts.len()).any(|i| {
        let suffix = parts[i..].join(".");
        domains.contains(&suffix)
    })
}

// ── The injector ─────────────────────────────────────────

#[derive(Debug, Default)]
struct RuleSet {
    rules: Vec<Arc<Rule>>,
    redact_to: Vec<String>,
}

type TransformKey = (String, String, String, String);
type FormsKey = (String, String, String);

/// Builds a transform: `(name, secret, transform_config)`.
pub type TransformFactory<'a> =
    &'a dyn Fn(&str, &str, &Value) -> Result<Arc<dyn Transform>, TransformError>;

/// Secret injection and redaction over the live rule set.
///
/// Shared by every flow (`Arc<Injector>`); [`Injector::configure`] swaps
/// the rules in place on reload, keeping each unchanged rule's transform
/// (its cached token, rate bucket and minted tokens) and keeping a
/// replaced transform's still-valid tokens redacted until they expire.
#[derive(Debug, Default)]
pub struct Injector {
    state: RwLock<Arc<RuleSet>>,
    transforms: Mutex<HashMap<TransformKey, Arc<dyn Transform>>>,
    /// Rules dropped or replaced by a reload whose transform minted a
    /// token that is still valid: it may be on a flow in flight or echoed
    /// back later, so it stays a secret until it expires.
    retired: Mutex<Vec<Arc<Rule>>>,
    forms: Mutex<HashMap<FormsKey, Arc<SecretForms>>>,
}

impl Injector {
    /// An injector with no rules.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An injector holding `rules` as given (no secret lookup).
    #[must_use]
    pub fn with_rules(rules: Vec<Rule>, redact_to: &[&str]) -> Self {
        let inj = Self::new();
        *inj.state.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(RuleSet {
            rules: rules.into_iter().map(Arc::new).collect(),
            redact_to: redact_to.iter().map(|d| d.to_lowercase()).collect(),
        });
        inj
    }

    fn snapshot(&self) -> Arc<RuleSet> {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The live rules.
    #[must_use]
    pub fn rules(&self) -> Vec<Arc<Rule>> {
        self.snapshot().rules.clone()
    }

    /// The `redact_to` domains, lower-cased.
    #[must_use]
    pub fn redact_to(&self) -> Vec<String> {
        self.snapshot().redact_to.clone()
    }

    /// Load the `secret_injection` section (a mapping with `rules` and
    /// `redact_to`, or a bare rule list), resolving every secret through
    /// [`crate::secret_lookup::read_secret`] and building transforms with
    /// [`crate::transforms::build`].
    pub fn configure(&self, section: Option<&Value>) {
        self.configure_with(
            section,
            &crate::secret_lookup::read_secret,
            &crate::transforms::build,
        );
    }

    /// [`Injector::configure`] with an explicit secret lookup and
    /// transform factory.
    ///
    /// A rule is skipped (with a log line) when its placeholder is empty
    /// (an empty needle would match everywhere), its secret resolves to
    /// `""` (unset or tombstoned: never fall back to a stale value), or its
    /// transform fails to build.
    pub fn configure_with(
        &self,
        section: Option<&Value>,
        lookup: &dyn Fn(&str) -> String,
        build: TransformFactory<'_>,
    ) {
        let empty = Vec::new();
        let (entries, redact_to): (&Vec<Value>, Vec<String>) = match section {
            Some(Value::Mapping(m)) => (
                match m.get("rules") {
                    Some(Value::Sequence(s)) => s,
                    _ => &empty,
                },
                config::str_list(m.get("redact_to"))
                    .iter()
                    .map(|d| d.to_lowercase())
                    .collect(),
            ),
            Some(Value::Sequence(s)) => (s, Vec::new()),
            _ => (&empty, Vec::new()),
        };

        let previous: Vec<Arc<Rule>> = {
            let state = self.snapshot();
            let retired = self.retired.lock().unwrap_or_else(PoisonError::into_inner);
            state.rules.iter().chain(retired.iter()).cloned().collect()
        };
        let mut old_transforms = std::mem::take(
            &mut *self
                .transforms
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        let mut new_transforms: HashMap<TransformKey, Arc<dyn Transform>> = HashMap::new();
        let mut rules = Vec::new();
        for entry in entries {
            let Value::Mapping(entry) = entry else {
                eprintln!("secret_injection: rule is not a mapping, skipping");
                continue;
            };
            if let Some(rule) = build_rule(
                entry,
                lookup,
                build,
                &mut old_transforms,
                &mut new_transforms,
            ) {
                rules.push(Arc::new(rule));
            }
        }

        let live: Vec<&Arc<dyn Transform>> = rules
            .iter()
            .filter_map(|r| r.transform_impl.as_ref())
            .collect();
        let retired: Vec<Arc<Rule>> = previous
            .into_iter()
            .filter(|r| {
                r.transform_impl
                    .as_ref()
                    .is_some_and(|t| !live.iter().any(|l| Arc::ptr_eq(l, t)))
                    && !r.minted_values().is_empty()
            })
            .collect();

        *self
            .transforms
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = new_transforms;
        *self.retired.lock().unwrap_or_else(PoisonError::into_inner) = retired;
        *self.state.write().unwrap_or_else(PoisonError::into_inner) =
            Arc::new(RuleSet { rules, redact_to });
        // Build each value's derived forms now rather than on the first
        // flow, and drop those of values no longer configured.
        self.redaction_forms();
    }

    fn has_anything(&self, state: &RuleSet) -> bool {
        !state.rules.is_empty()
            || !self
                .retired
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
    }

    /// Retired rules that still have a valid minted token; the rest are
    /// forgotten here.
    fn live_retired(&self) -> Vec<Arc<Rule>> {
        let mut retired = self.retired.lock().unwrap_or_else(PoisonError::into_inner);
        retired.retain(|r| !r.minted_values().is_empty());
        retired.clone()
    }

    /// `(rule, token)` for every valid minted token, live rules first.
    fn minted(&self, state: &RuleSet) -> Vec<(Arc<Rule>, String)> {
        state
            .rules
            .iter()
            .cloned()
            .chain(self.live_retired())
            .flat_map(|rule| {
                rule.minted_values()
                    .into_iter()
                    .map(move |v| (rule.clone(), v))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn forms_for(&self, value: &str, placeholder: &str, name: &str) -> Arc<SecretForms> {
        let key = (value.to_owned(), placeholder.to_owned(), name.to_owned());
        let mut cache = self.forms.lock().unwrap_or_else(PoisonError::into_inner);
        cache
            .entry(key)
            .or_insert_with(|| Arc::new(SecretForms::new(value, placeholder, name)))
            .clone()
    }

    /// The forms of every value redaction swaps back to a placeholder —
    /// each rule's real value and each live minted token (also a retired
    /// rule's) — longest value first (in characters, ties in rule order),
    /// so a value that is a substring of another never splits it. Forms of
    /// values no longer secret are dropped from the cache.
    fn redaction_forms(&self) -> Vec<Arc<SecretForms>> {
        let state = self.snapshot();
        let mut targets: Vec<(String, String, String)> = Vec::new();
        let mut push = |value: &str, rule: &Rule| {
            if !value.is_empty() && !targets.iter().any(|(v, _, _)| v == value) {
                targets.push((
                    value.to_owned(),
                    rule.placeholder.clone(),
                    rule.name.clone(),
                ));
            }
        };
        for rule in &state.rules {
            push(&rule.real_value, rule);
        }
        for (rule, token) in self.minted(&state) {
            push(&token, &rule);
        }
        targets.sort_by_key(|(v, _, _)| std::cmp::Reverse(v.chars().count()));
        let forms: Vec<Arc<SecretForms>> = targets
            .iter()
            .map(|(v, p, n)| self.forms_for(v, p, n))
            .collect();
        let mut cache = self.forms.lock().unwrap_or_else(PoisonError::into_inner);
        *cache = forms
            .iter()
            .map(|f| {
                (
                    (f.value.clone(), f.placeholder.clone(), f.name.clone()),
                    f.clone(),
                )
            })
            .collect();
        forms
    }

    // ── Policy ──

    /// Whether `forms`' value is in the request: in the URL, a header
    /// (also inside a Basic credential) or the body.
    fn find_value(
        req: &Request,
        body: &mut LazyBody,
        forms: &SecretForms,
    ) -> Result<bool, DecodeError> {
        if forms.occurs(req.url().as_bytes()) {
            return Ok(true);
        }
        for (_, v) in header_items(&req.headers) {
            if forms.occurs(&v) || rewrite_basic_auth(&v, forms.raw(), forms.raw()).is_some() {
                return Ok(true);
            }
        }
        let content = body.get(&req.headers, &req.body)?;
        Ok(!content.is_empty() && forms.occurs(content))
    }

    /// Whether `rule`'s placeholder is in the request (also inside a Basic
    /// credential, so the Basic-aware substitution is reached).
    fn find_placeholder(
        req: &Request,
        body: &mut LazyBody,
        rule: &Rule,
    ) -> Result<bool, DecodeError> {
        let ph = rule.placeholder.as_bytes();
        if contains(req.url().as_bytes(), ph) {
            return Ok(true);
        }
        for (_, v) in header_items(&req.headers) {
            if contains(&v, ph) || rewrite_basic_auth(&v, ph, ph).is_some() {
                return Ok(true);
            }
        }
        let content = body.get(&req.headers, &req.body)?;
        Ok(!content.is_empty() && contains(content, ph))
    }

    fn literal_block(rule: &Rule, host: &str, what: &str) -> Verdict {
        Verdict::new(
            INSPECTOR_NAME,
            Action::Block,
            format!(
                "literal secret value {} found in outbound {what} to {host}",
                rule.name
            ),
            Severity::Critical,
        )
    }

    fn minted_block(rule: &Rule, host: &str, what: &str) -> Verdict {
        Verdict::new(
            INSPECTOR_NAME,
            Action::Block,
            format!(
                "literal secret value {} (a token its {} transform minted) found in outbound {what} to {host}",
                rule.name, rule.transform
            ),
            Severity::Critical,
        )
    }

    fn placeholder_flag(rule: &Rule, host: &str) -> Verdict {
        Verdict::new(
            INSPECTOR_NAME,
            Action::Flag,
            format!(
                "placeholder {} sent to unauthorized domain {host}",
                rule.name
            ),
            Severity::Error,
        )
    }

    /// Check the request against the rules without modifying it.
    ///
    /// Block when a real value (in any of its forms) heads for a host
    /// outside its rule's `inject_to`, or anywhere at all for a rule with
    /// a transform (the cage never legitimately holds the underlying
    /// credential); block a minted token outside `inject_to`; flag a
    /// placeholder sent where it will not be injected. `redact_to` hosts
    /// are not checked.
    ///
    /// # Errors
    ///
    /// The body had to be read and its Content-Encoding cannot be removed.
    pub fn check_injection_policy(&self, req: &Request) -> Result<Option<Verdict>, DecodeError> {
        let state = self.snapshot();
        if !self.has_anything(&state) {
            return Ok(None);
        }
        let host = req.host.to_lowercase();
        if !state.redact_to.is_empty() && domain_matches(&host, &state.redact_to) {
            return Ok(None);
        }
        let mut body = LazyBody::default();
        for rule in &state.rules {
            let forms = self.forms_for(&rule.real_value, &rule.placeholder, &rule.name);
            if Self::find_value(req, &mut body, &forms)? {
                if rule.transform_impl.is_none()
                    && !rule.inject_to.is_empty()
                    && domain_matches(&host, &rule.inject_to)
                {
                    continue;
                }
                return Ok(Some(Self::literal_block(rule, &host, "request")));
            }
        }
        for (rule, token) in self.minted(&state) {
            let forms = self.forms_for(&token, &rule.placeholder, &rule.name);
            if !Self::find_value(req, &mut body, &forms)? {
                continue;
            }
            if !rule.inject_to.is_empty() && domain_matches(&host, &rule.inject_to) {
                continue;
            }
            return Ok(Some(Self::minted_block(&rule, &host, "request")));
        }
        for rule in &state.rules {
            if !Self::find_placeholder(req, &mut body, rule)? {
                continue;
            }
            if rule.inject_to.is_empty() || !domain_matches(&host, &rule.inject_to) {
                return Ok(Some(Self::placeholder_flag(rule, &host)));
            }
        }
        Ok(None)
    }

    // ── Injection ──

    /// Replace placeholders with real values for every rule whose
    /// `inject_to` covers the request's host; on a `redact_to` host,
    /// redact real values instead. Returns the names acted on.
    ///
    /// A rule with a transform calls it here (possibly a blocking mint);
    /// a transform failure leaves that rule's placeholder in place.
    ///
    /// # Errors
    ///
    /// The body could not be decoded, or a rewritten URL does not parse.
    pub fn inject_request(&self, req: &mut Request) -> Result<Vec<String>, InjectError> {
        let state = self.snapshot();
        if !self.has_anything(&state) {
            return Ok(Vec::new());
        }
        let host = req.host.to_lowercase();
        if !state.redact_to.is_empty() && domain_matches(&host, &state.redact_to) {
            return self.redact_request(req);
        }
        let mut body = LazyBody::default();
        let result = Self::inject_rules(&state, &host, req, &mut body);
        body.finish(&mut req.headers, &mut req.body);
        result
    }

    fn inject_rules(
        state: &RuleSet,
        host: &str,
        req: &mut Request,
        body: &mut LazyBody,
    ) -> Result<Vec<String>, InjectError> {
        let mut names = Vec::new();
        for rule in &state.rules {
            if !Self::find_placeholder(req, body, rule)? {
                continue;
            }
            if rule.inject_to.is_empty() || !domain_matches(host, &rule.inject_to) {
                continue;
            }
            let Some(value) = rule.the_value() else {
                continue;
            };
            let mut injected = false;
            if rule.inject_body {
                // Setting the URL re-parses it, host included: a
                // placeholder in the host name was judged by inject_to
                // and every inspector as the placeholder host, and the
                // request now goes to the host the value names. Current
                // behaviour, pinned by a test, not a decision.
                let url = req.url();
                if url.contains(&rule.placeholder) {
                    set_url(req, &url.replace(&rule.placeholder, &value))
                        .map_err(InjectError::Url)?;
                    injected = true;
                }
            }
            let (ph, value) = (rule.placeholder.as_bytes(), value.as_bytes());
            if rule.inject_body {
                for (k, v) in header_items(&req.headers) {
                    if contains(&v, ph) {
                        set_header(&mut req.headers, &k, replace_all(&v, ph, value));
                        injected = true;
                    }
                }
                let content = body.get(&req.headers, &req.body)?;
                if !content.is_empty() && contains(content, ph) {
                    let new = replace_all(content, ph, value);
                    body.set(new);
                    injected = true;
                }
            } else {
                for (k, v) in header_items(&req.headers) {
                    if !rule.is_auth_header(&String::from_utf8_lossy(&k)) {
                        continue;
                    }
                    if contains(&v, ph) {
                        set_header(&mut req.headers, &k, replace_all(&v, ph, value));
                        injected = true;
                    } else if let Some(new) = rewrite_basic_auth(&v, ph, value) {
                        set_header(&mut req.headers, &k, new);
                        injected = true;
                    }
                }
            }
            if injected {
                names.push(rule.name.clone());
            }
        }
        Ok(names)
    }

    // ── Redaction ──

    /// Swap every secret (real values and live minted tokens, in every
    /// form) in the request's URL, headers (also inside a Basic
    /// credential) and body back to its placeholder. Used for `redact_to`
    /// hosts at injection time and on every request before capture stores
    /// it. Returns the names of the rules whose values were found.
    ///
    /// # Errors
    ///
    /// The body could not be decoded, or the redacted URL does not parse.
    pub fn redact_request(&self, req: &mut Request) -> Result<Vec<String>, InjectError> {
        let mut body = LazyBody::default();
        let result = self.redact_request_values(req, &mut body);
        body.finish(&mut req.headers, &mut req.body);
        result
    }

    fn redact_request_values(
        &self,
        req: &mut Request,
        body: &mut LazyBody,
    ) -> Result<Vec<String>, InjectError> {
        let mut names: Vec<String> = Vec::new();
        for forms in self.redaction_forms() {
            let mut found = false;
            if let Some(url) = forms.redact_text(&req.url()) {
                set_url(req, &url).map_err(InjectError::Url)?;
                found = true;
            }
            found |= redact_headers(&mut req.headers, &forms);
            let content = body.get(&req.headers, &req.body)?;
            if !content.is_empty() {
                if let Some(new) = forms.redact(content) {
                    body.set(new);
                    found = true;
                }
            }
            if found && !names.contains(&forms.name) {
                names.push(forms.name.clone());
            }
        }
        Ok(names)
    }

    /// Swap every secret in the response's headers and body back to its
    /// placeholder, regardless of host. Returns the names found.
    ///
    /// # Errors
    ///
    /// The body could not be decoded (only read when there is a secret to
    /// look for).
    pub fn redact_response(&self, resp: &mut Response) -> Result<Vec<String>, DecodeError> {
        let mut names: Vec<String> = Vec::new();
        let mut body = LazyBody::default();
        let result = (|| {
            for forms in self.redaction_forms() {
                let mut found = redact_headers(&mut resp.headers, &forms);
                let content = body.get(&resp.headers, &resp.body)?;
                if !content.is_empty() {
                    if let Some(new) = forms.redact(content) {
                        body.set(new);
                        found = true;
                    }
                }
                if found && !names.contains(&forms.name) {
                    names.push(forms.name.clone());
                }
            }
            Ok(())
        })();
        body.finish(&mut resp.headers, &mut resp.body);
        result.map(|()| names)
    }

    /// `text` with every secret, in every form, swapped for its rule's
    /// placeholder, and the names of the rules whose secrets were found.
    #[must_use]
    pub fn redact_text(&self, text: &str) -> (String, Vec<String>) {
        let mut names: Vec<String> = Vec::new();
        if !self.has_anything(&self.snapshot()) {
            return (text.to_owned(), names);
        }
        let mut text = text.to_owned();
        for forms in self.redaction_forms() {
            if let Some(new) = forms.redact_text(&text) {
                text = new;
                if !names.contains(&forms.name) {
                    names.push(forms.name.clone());
                }
            }
        }
        (text, names)
    }

    /// [`Injector::redact_text`] without the names.
    #[must_use]
    pub fn redact_str(&self, text: &str) -> String {
        self.redact_text(text).0
    }

    /// Redact every string value in `record`, at any depth (object keys
    /// are left alone): what every audit record and capture inspector
    /// reason goes through before any sink.
    pub fn redact_json(&self, record: &mut Json) {
        fn walk(value: &mut Json, targets: &[Arc<SecretForms>]) {
            match value {
                Json::Str(s) => {
                    for forms in targets {
                        if let Some(new) = forms.redact_text(s) {
                            *s = new;
                        }
                    }
                }
                Json::Array(items) => items.iter_mut().for_each(|v| walk(v, targets)),
                Json::Object(pairs) => pairs.iter_mut().for_each(|(_, v)| walk(v, targets)),
                _ => {}
            }
        }
        if !self.has_anything(&self.snapshot()) {
            return;
        }
        let targets = self.redaction_forms();
        if targets.is_empty() {
            return;
        }
        walk(record, &targets);
    }

    // ── WebSocket ──

    /// [`Injector::check_injection_policy`] for one outbound WebSocket
    /// message.
    #[must_use]
    pub fn check_ws_injection_policy(&self, content: &[u8], host: &str) -> Option<Verdict> {
        let state = self.snapshot();
        if !self.has_anything(&state) {
            return None;
        }
        let host = host.to_lowercase();
        if !state.redact_to.is_empty() && domain_matches(&host, &state.redact_to) {
            return None;
        }
        for rule in &state.rules {
            if self
                .forms_for(&rule.real_value, &rule.placeholder, &rule.name)
                .occurs(content)
            {
                if rule.transform_impl.is_none()
                    && !rule.inject_to.is_empty()
                    && domain_matches(&host, &rule.inject_to)
                {
                    continue;
                }
                return Some(Self::literal_block(rule, &host, "WebSocket frame"));
            }
        }
        for (rule, token) in self.minted(&state) {
            if !self
                .forms_for(&token, &rule.placeholder, &rule.name)
                .occurs(content)
            {
                continue;
            }
            if !rule.inject_to.is_empty() && domain_matches(&host, &rule.inject_to) {
                continue;
            }
            return Some(Self::minted_block(&rule, &host, "WebSocket frame"));
        }
        for rule in &state.rules {
            if !contains(content, rule.placeholder.as_bytes()) {
                continue;
            }
            if rule.inject_to.is_empty() || !domain_matches(&host, &rule.inject_to) {
                return Some(Self::placeholder_flag(rule, &host));
            }
        }
        None
    }

    /// Inject into one outbound WebSocket message: only rules with
    /// `inject_body` (strict injection has no header to target here), for
    /// hosts in their `inject_to`; on a `redact_to` host, redact instead.
    #[must_use]
    pub fn inject_ws_content(&self, content: &[u8], host: &str) -> (Vec<u8>, Vec<String>) {
        let state = self.snapshot();
        if !self.has_anything(&state) {
            return (content.to_vec(), Vec::new());
        }
        let host = host.to_lowercase();
        if !state.redact_to.is_empty() && domain_matches(&host, &state.redact_to) {
            return self.redact_ws_content(content);
        }
        let mut content = content.to_vec();
        let mut names = Vec::new();
        for rule in &state.rules {
            let ph = rule.placeholder.as_bytes();
            if !rule.inject_body || !contains(&content, ph) {
                continue;
            }
            if rule.inject_to.is_empty() || !domain_matches(&host, &rule.inject_to) {
                continue;
            }
            let Some(value) = rule.the_value() else {
                continue;
            };
            content = replace_all(&content, ph, value.as_bytes());
            names.push(rule.name.clone());
        }
        (content, names)
    }

    /// Redact every secret in one WebSocket message.
    #[must_use]
    pub fn redact_ws_content(&self, content: &[u8]) -> (Vec<u8>, Vec<String>) {
        let mut content = content.to_vec();
        let mut names: Vec<String> = Vec::new();
        for forms in self.redaction_forms() {
            if let Some(new) = forms.redact(&content) {
                content = new;
                if !names.contains(&forms.name) {
                    names.push(forms.name.clone());
                }
            }
        }
        (content, names)
    }
}

impl crate::audit::Redactor for Injector {
    fn redact(&self, entry: &mut Json) {
        self.redact_json(entry);
    }
}

/// Redact one secret in every header (literal and encoded forms, else
/// inside a Basic credential); whether any changed.
fn redact_headers(headers: &mut Headers, forms: &SecretForms) -> bool {
    let mut found = false;
    for (k, v) in header_items(headers) {
        if let Some(new) = forms.redact(&v) {
            set_header(headers, &k, new);
            found = true;
        } else if let Some(new) = rewrite_basic_auth(&v, forms.raw(), forms.ph_raw()) {
            set_header(headers, &k, new);
            found = true;
        }
    }
    found
}

/// `str(value)` for a config scalar.
fn py_str(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(if *b { "True" } else { "False" }.into()),
        _ => None,
    }
}

/// A stable spelling of a config value with mapping keys sorted, for
/// telling an unchanged `transform_config` from a changed one.
fn canonical(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("{s:?}"),
        Value::Sequence(items) => format!(
            "[{}]",
            items.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        Value::Mapping(m) => {
            let mut pairs: Vec<String> = m
                .iter()
                .map(|(k, v)| format!("{}:{}", canonical(k), canonical(v)))
                .collect();
            pairs.sort();
            format!("{{{}}}", pairs.join(","))
        }
        Value::Tagged(t) => canonical(&t.value),
    }
}

fn build_rule(
    entry: &Mapping,
    lookup: &dyn Fn(&str) -> String,
    build: TransformFactory<'_>,
    old_transforms: &mut HashMap<TransformKey, Arc<dyn Transform>>,
    new_transforms: &mut HashMap<TransformKey, Arc<dyn Transform>>,
) -> Option<Rule> {
    let env_name = config::as_str(entry.get("env"))
        .unwrap_or_default()
        .to_owned();
    let placeholder = config::as_str(entry.get("placeholder"))
        .unwrap_or_default()
        .to_owned();
    if placeholder.is_empty() {
        eprintln!("secret_injection: rule {env_name} has no placeholder, skipping");
        return None;
    }
    let inject_to: Vec<String> = config::str_list(entry.get("inject_to"))
        .iter()
        .map(|d| d.to_lowercase())
        .collect();
    let real_value = lookup(&env_name);
    if real_value.is_empty() {
        eprintln!(
            "secret_injection: no value for {env_name} (unset, or staged file empty/unreadable), skipping rule"
        );
        return None;
    }
    let inject_body = entry.get("inject_body").is_some_and(config::truthy);
    let inject_headers: Vec<String> = match entry.get("inject_headers") {
        Some(Value::Sequence(items)) => items
            .iter()
            .filter_map(py_str)
            .map(|h| h.trim_matches(crate::text::py_is_space).to_owned())
            .collect(),
        _ => Vec::new(),
    };
    let transform = config::as_str(entry.get("transform"))
        .unwrap_or_default()
        .to_owned();
    let mut transform_impl = None;
    if !transform.is_empty() {
        let tcfg = match entry.get("transform_config") {
            Some(v) if config::truthy(v) => v.clone(),
            _ => Value::Mapping(Mapping::new()),
        };
        let key = (
            env_name.clone(),
            transform.clone(),
            canonical(&tcfg),
            real_value.clone(),
        );
        let instance = match new_transforms
            .get(&key)
            .cloned()
            .or_else(|| old_transforms.remove(&key))
        {
            Some(instance) => instance,
            None => match build(&transform, &real_value, &tcfg) {
                Ok(instance) => instance,
                Err(e) => {
                    eprintln!(
                        "secret_injection: transform {transform} for {env_name} failed to initialize: {e} — skipping rule"
                    );
                    return None;
                }
            },
        };
        new_transforms.insert(key, instance.clone());
        transform_impl = Some(instance);
    }
    Some(Rule {
        name: env_name,
        placeholder,
        real_value,
        inject_to,
        transform,
        transform_impl,
        inject_body,
        inject_headers,
        recent: Mutex::new(Vec::new()),
    })
}

#[cfg(test)]
mod tests;
