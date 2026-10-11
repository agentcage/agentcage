//! Body decoding: Content-Encoding removal and `get_text` (the charset
//! rules inspectors see the body through).
//!
//! Two layers, each the replaced implementation's to the byte (pinned by
//! `tests/fixtures/egress/get_text.json`):
//!
//! * [`decoded_body`] removes the `Content-Encoding`: `gzip` (which also
//!   accepts a zlib stream, and tolerates a truncated one), `deflate`
//!   (zlib, else raw), `deflateraw`, `br`, `zstd`, `identity` and `none`.
//!   Anything else, including stacked encodings (`gzip, br`) and
//!   `x-gzip`, is an error: the Python egress raised too, and the pipeline
//!   fails closed on it (plan D1).
//! * [`get_text`] turns the decoded body into text the way
//!   `get_text(strict=False)` did: a byte-order mark wins, then the
//!   `charset` parameter, then `utf-8` for JSON, HTML (unless a `<meta>`
//!   names a charset), XML (unless the declaration does), JavaScript and
//!   CSS (unless `@charset` does), else `latin-1`; `gb2312` / `gbk` read as
//!   GB 18030. A charset that is unknown, or that the body is not valid
//!   in, falls back to UTF-8 with every undecodable byte as U+FFFD (the
//!   Python fallback surrogate-escaped them, which a Rust `String` cannot
//!   hold; one replacement per byte keeps lengths and positions the
//!   same).
//!
//! Charset names resolve the way CPython's codec registry resolves them
//! (lower-cased, punctuation runs folded to `_`, then its alias table),
//! restricted to the codecs listed in [`SUPPORTED_CODECS`]: the Unicode
//! encodings, ASCII, Latin-1, the Windows code pages 1250-1258, ISO 8859
//! parts 2-10 and 13-16, KOI8-R/U and GB 18030. A name CPython knows but
//! that is not on that list (`Shift_JIS`, `Big5`, `EUC-*`, …) falls back like an
//! unknown one. A charset naming a byte-to-byte codec (`identity`, `gzip`,
//! `base64`, …), which made the Python method return bytes instead of
//! text, is treated as unknown too.

use std::borrow::Cow;

use crate::message::Headers;

// ── Content-Encoding ─────────────────────────────────────

/// Why a body's `Content-Encoding` could not be removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The encoding is not one the egress decodes (stacked encodings
    /// included).
    Unsupported(String),
    /// The body is not valid in its declared encoding.
    Corrupt {
        /// The (lower-cased) encoding.
        encoding: String,
        /// What was wrong.
        detail: String,
    },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(e) => write!(f, "unsupported Content-Encoding {e:?}"),
            Self::Corrupt { encoding, detail } => {
                write!(f, "invalid {encoding} body: {detail}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// The body with its `Content-Encoding` removed.
///
/// No header, or an empty one, returns `raw` untouched. Duplicate
/// headers are folded with `", "` first, so two of them are a stacked
/// encoding and an error.
///
/// # Errors
///
/// The encoding is unsupported or the body is corrupt in it.
pub fn decoded_body<'a>(headers: &Headers, raw: &'a [u8]) -> Result<Cow<'a, [u8]>, DecodeError> {
    match headers.get("content-encoding") {
        Some(ce) if !ce.is_empty() => decode_content(raw, &ce),
        _ => Ok(Cow::Borrowed(raw)),
    }
}

/// [`decoded_body`], or `raw` itself when it cannot be decoded: the
/// lenient view (`get_content(strict=False)`) that `get_text` starts
/// from.
#[must_use]
pub fn decoded_body_lenient<'a>(headers: &Headers, raw: &'a [u8]) -> Cow<'a, [u8]> {
    decoded_body(headers, raw).unwrap_or(Cow::Borrowed(raw))
}

/// Remove one named Content-Encoding (matched case-insensitively).
///
/// # Errors
///
/// As [`decoded_body`].
pub fn decode_content<'a>(raw: &'a [u8], encoding: &str) -> Result<Cow<'a, [u8]>, DecodeError> {
    let encoding = encoding.to_lowercase();
    let corrupt = |detail: String| DecodeError::Corrupt {
        encoding: encoding.clone(),
        detail,
    };
    match encoding.as_str() {
        "none" | "identity" => Ok(Cow::Borrowed(raw)),
        "gzip" => decode_gzip(raw).map(Cow::Owned).map_err(corrupt),
        "deflate" | "deflateraw" => decode_deflate(raw).map(Cow::Owned).map_err(corrupt),
        "br" => decode_brotli(raw).map(Cow::Owned).map_err(corrupt),
        "zstd" => decode_zstd(raw).map(Cow::Owned).map_err(corrupt),
        _ => Err(DecodeError::Unsupported(encoding.clone())),
    }
}

/// Raw DEFLATE: the decoded bytes, and the input length consumed if the
/// final block was reached (`None` when the input ran out first).
fn inflate_raw(input: &[u8]) -> Result<(Vec<u8>, Option<usize>), String> {
    use flate2::{Decompress, FlushDecompress, Status};

    let mut d = Decompress::new(false);
    let mut out: Vec<u8> = Vec::with_capacity(input.len().saturating_mul(4).max(64));
    loop {
        if out.len() == out.capacity() {
            out.reserve(out.len().max(1024));
        }
        let (in_before, out_before) = (d.total_in(), d.total_out());
        let consumed = usize::try_from(in_before).map_err(|e| e.to_string())?;
        let status = d
            .decompress_vec(&input[consumed..], &mut out, FlushDecompress::None)
            .map_err(|e| e.to_string())?;
        if status == Status::StreamEnd {
            let consumed = usize::try_from(d.total_in()).map_err(|e| e.to_string())?;
            return Ok((out, Some(consumed)));
        }
        let progressed = d.total_in() != in_before || d.total_out() != out_before;
        if !progressed && out.len() < out.capacity() {
            return Ok((out, None));
        }
    }
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += u32::from(x);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

/// A zlib stream. `lenient` is the streaming decoder's view (a stream
/// cut short decodes as far as it goes, the checksum unchecked); strict
/// is the one-shot decoder's (it must be complete).
fn inflate_zlib(input: &[u8], lenient: bool) -> Result<Vec<u8>, String> {
    let truncated = |out: Vec<u8>| {
        if lenient {
            Ok(out)
        } else {
            Err("incomplete or truncated stream".to_owned())
        }
    };
    if input.len() < 2 {
        return truncated(Vec::new());
    }
    let (cmf, flg) = (input[0], input[1]);
    if (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
        return Err("incorrect header check".into());
    }
    if cmf & 0x0f != 8 {
        return Err("unknown compression method".into());
    }
    if (cmf >> 4) + 8 > 15 {
        return Err("invalid window size".into());
    }
    if flg & 0x20 != 0 {
        return Err("stream needs a preset dictionary".into());
    }
    let (out, end) = inflate_raw(&input[2..])?;
    let Some(end) = end else {
        return truncated(out);
    };
    let trailer = &input[2 + end..];
    if trailer.len() < 4 {
        return truncated(out);
    }
    let want = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    if adler32(&out) != want {
        return Err("incorrect data check".into());
    }
    Ok(out)
}

/// `gzip`: zlib's automatic header detection, streaming. A gzip member
/// or a zlib stream; only the first member is read, trailing bytes are
/// ignored, and a stream cut short (even mid-header) decodes as far as it
/// goes without an error.
fn decode_gzip(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() < 2 {
        return Ok(Vec::new());
    }
    if input[..2] != [0x1f, 0x8b] {
        return inflate_zlib(input, true);
    }
    let Some(body) = gzip_header_len(input)? else {
        return Ok(Vec::new());
    };
    let (out, end) = inflate_raw(&input[body..])?;
    let Some(end) = end else { return Ok(out) };
    let trailer = &input[body + end..];
    if trailer.len() >= 4 {
        let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&out);
        if hasher.finalize() != crc {
            return Err("incorrect data check".into());
        }
    }
    if trailer.len() >= 8 {
        let size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
        // ISIZE is the length modulo 2^32.
        #[allow(clippy::cast_possible_truncation)]
        if size != out.len() as u32 {
            return Err("incorrect length check".into());
        }
    }
    Ok(out)
}

/// The length of a gzip member header, `None` when `input` ends inside
/// it.
fn gzip_header_len(input: &[u8]) -> Result<Option<usize>, String> {
    if input.len() < 3 {
        return Ok(None);
    }
    if input[2] != 8 {
        return Err("unknown compression method".into());
    }
    let Some(&flags) = input.get(3) else {
        return Ok(None);
    };
    if flags & 0xe0 != 0 {
        return Err("unknown header flags set".into());
    }
    let mut pos = 10;
    if input.len() < pos {
        return Ok(None);
    }
    if flags & 0x04 != 0 {
        let Some(len) = input.get(pos..pos + 2) else {
            return Ok(None);
        };
        pos += 2 + usize::from(u16::from_le_bytes([len[0], len[1]]));
        if input.len() < pos {
            return Ok(None);
        }
    }
    for flag in [0x08, 0x10] {
        if flags & flag != 0 {
            let Some(nul) = memchr::memchr(0, &input[pos..]) else {
                return Ok(None);
            };
            pos += nul + 1;
        }
    }
    if flags & 0x02 != 0 {
        let Some(crc) = input.get(pos..pos + 2) else {
            return Ok(None);
        };
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&input[..pos]);
        #[allow(clippy::cast_possible_truncation)]
        let want = hasher.finalize() as u16;
        if u16::from_le_bytes([crc[0], crc[1]]) != want {
            return Err("header crc mismatch".into());
        }
        pos += 2;
    }
    Ok(Some(pos))
}

/// `deflate`: a complete zlib stream, else a complete raw DEFLATE
/// stream (servers send both under this name); trailing bytes ignored.
fn decode_deflate(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(out) = inflate_zlib(input, false) {
        return Ok(out);
    }
    match inflate_raw(input)? {
        (out, Some(_)) => Ok(out),
        (_, None) => Err("incomplete or truncated stream".into()),
    }
}

/// `br`: one complete stream, nothing after it.
fn decode_brotli(input: &[u8]) -> Result<Vec<u8>, String> {
    use brotli_decompressor::{BrotliDecompressStream, BrotliResult, BrotliState, StandardAlloc};

    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut state = BrotliState::new(
        StandardAlloc::default(),
        StandardAlloc::default(),
        StandardAlloc::default(),
    );
    // The reference decoder refuses the large-window extension unless
    // asked for it, and nothing asks.
    state.large_window = false;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let (mut avail_in, mut in_off, mut total) = (input.len(), 0usize, 0usize);
    loop {
        let (mut avail_out, mut out_off) = (buf.len(), 0usize);
        let result = BrotliDecompressStream(
            &mut avail_in,
            &mut in_off,
            input,
            &mut avail_out,
            &mut out_off,
            &mut buf,
            &mut total,
            &mut state,
        );
        out.extend_from_slice(&buf[..out_off]);
        match result {
            BrotliResult::NeedsMoreOutput => {}
            BrotliResult::ResultSuccess if avail_in == 0 => return Ok(out),
            BrotliResult::ResultSuccess => return Err("trailing data after the stream".into()),
            BrotliResult::NeedsMoreInput => return Err("truncated stream".into()),
            BrotliResult::ResultFailure => return Err("corrupt stream".into()),
        }
    }
}

/// `zstd`: every frame in turn (skippable ones skipped), checksums
/// verified. Input that ends inside a frame stops there without an error,
/// as the streaming reader did; the cut frame's output is dropped (the
/// reader kept the blocks it had completed, which differs only for a
/// frame of more than one block).
fn decode_zstd(input: &[u8]) -> Result<Vec<u8>, String> {
    use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

    let mut out = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let Some(magic) = rest.get(..4) else {
            return Err("trailing bytes after the last frame".into());
        };
        let magic = u32::from_le_bytes([magic[0], magic[1], magic[2], magic[3]]);
        if magic & 0xffff_fff0 == 0x184d_2a50 {
            let Some(len) = rest.get(4..8) else {
                return Ok(out);
            };
            let len = u32::from_le_bytes([len[0], len[1], len[2], len[3]]) as usize;
            let Some(next) = rest.get(8 + len..) else {
                return Ok(out);
            };
            rest = next;
            continue;
        }
        let mut cursor = rest;
        let mut frame_decoder = FrameDecoder::new();
        let result = frame_decoder
            .reset(&mut cursor)
            .map_err(|e| e.to_string())
            .and_then(|()| {
                frame_decoder
                    .decode_blocks(&mut cursor, BlockDecodingStrategy::All)
                    .map_err(|e| e.to_string())
            });
        if let Err(e) = result {
            if cursor.is_empty() {
                // Ran out of input inside the frame: truncated.
                return Ok(out);
            }
            return Err(e);
        }
        // The running hash covers only what has been collected, so
        // collect before comparing.
        let frame = frame_decoder.collect().unwrap_or_default();
        if let (Some(want), Some(got)) = (
            frame_decoder.get_checksum_from_data(),
            frame_decoder.get_calculated_checksum(),
        ) {
            if want != got {
                return Err("checksum mismatch".into());
            }
        }
        out.extend(frame);
        rest = cursor;
    }
    Ok(out)
}

// ── get_text ─────────────────────────────────────────────

/// The body as inspectors read it: `get_text(strict=False)` over the
/// leniently decoded body (see the module docs).
#[must_use]
pub fn get_text(headers: &Headers, raw: &[u8]) -> String {
    let content = decoded_body_lenient(headers, raw);
    let content_type = headers.get("content-type").unwrap_or_default();
    decode_text(&content_type, &content)
}

/// Decode an already Content-Encoding-free body with the charset rules
/// of `get_text`.
#[must_use]
pub fn decode_text(content_type: &str, content: &[u8]) -> String {
    let charset = infer_charset(content_type, content);
    decode_charset(content, &charset).unwrap_or_else(|| utf8_replacing_each_byte(content))
}

/// Python `str.isspace` for one character: the Unicode `White_Space`
/// characters plus the four ASCII separators U+001C-U+001F.
pub(crate) fn py_is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `(type, subtype, params)` of a Content-Type value, or `None` without
/// a `/`. Parameters keep the last value of a repeated name, and names
/// are case-sensitive.
/// A parsed Content-Type: type, subtype and parameters in order.
type ContentType = (String, String, Vec<(String, String)>);

fn parse_content_type(value: &str) -> Option<ContentType> {
    let (main, params) = match value.split_once(';') {
        Some((m, p)) => (m, Some(p)),
        None => (value, None),
    };
    let (kind, sub) = main.split_once('/')?;
    let mut out: Vec<(String, String)> = Vec::new();
    for clause in params.into_iter().flat_map(|p| p.split(';')) {
        if let Some((k, v)) = clause.split_once('=') {
            let (k, v) = (k.trim_matches(py_is_space), v.trim_matches(py_is_space));
            match out.iter_mut().find(|(name, _)| name == k) {
                Some(slot) => v.clone_into(&mut slot.1),
                None => out.push((k.to_owned(), v.to_owned())),
            }
        }
    }
    Some((kind.to_lowercase(), sub.to_lowercase(), out))
}

fn ascii_only(bytes: &[u8]) -> String {
    bytes
        .iter()
        .filter(|b| b.is_ascii())
        .map(|&b| char::from(b))
        .collect()
}

static HTML_META: std::sync::LazyLock<regex::bytes::Regex> = std::sync::LazyLock::new(|| {
    regex::bytes::Regex::new(r#"(?i-u)<meta[^>]+charset=['"]?([^'">]+)"#).expect("static regex")
});
static XML_DECL: std::sync::LazyLock<regex::bytes::Regex> = std::sync::LazyLock::new(|| {
    regex::bytes::Regex::new(r#"(?i-u)<\?xml[^?>]+encoding=['"]([^'"?>]+)"#).expect("static regex")
});
static CSS_CHARSET: std::sync::LazyLock<regex::bytes::Regex> = std::sync::LazyLock::new(|| {
    regex::bytes::Regex::new(r#"(?i-u)\A@charset "([^"]+)";"#).expect("static regex")
});

/// The charset `get_text` decodes `content` with, given its
/// Content-Type (the name as found; resolution happens when decoding).
#[must_use]
pub fn infer_charset(content_type: &str, content: &[u8]) -> String {
    let mut enc: Option<String> = if content.starts_with(b"\x00\x00\xfe\xff") {
        Some("utf-32be".into())
    } else if content.starts_with(b"\xff\xfe\x00\x00") {
        Some("utf-32le".into())
    } else if content.starts_with(b"\xfe\xff") {
        Some("utf-16be".into())
    } else if content.starts_with(b"\xff\xfe") {
        Some("utf-16le".into())
    } else if content.starts_with(b"\xef\xbb\xbf") {
        Some("utf-8-sig".into())
    } else {
        parse_content_type(content_type).and_then(|(_, _, params)| {
            params
                .into_iter()
                .find(|(k, _)| k == "charset")
                .map(|(_, v)| v)
        })
    };
    let unset = |e: &Option<String>| e.as_deref().is_none_or(str::is_empty);
    let from = |re: &regex::bytes::Regex| {
        re.captures(content)
            .and_then(|c| c.get(1))
            .map_or_else(|| "utf8".to_owned(), |m| ascii_only(m.as_bytes()))
    };
    if unset(&enc) && content_type.contains("json") {
        enc = Some("utf8".into());
    }
    if unset(&enc) && content_type.contains("html") {
        enc = Some(from(&HTML_META));
    }
    if unset(&enc) && content_type.contains("xml") {
        enc = Some(from(&XML_DECL));
    }
    if unset(&enc) && (content_type.contains("javascript") || content_type.contains("ecmascript")) {
        enc = Some("utf8".into());
    }
    if unset(&enc) && content_type.contains("text/css") {
        enc = Some(from(&CSS_CHARSET));
    }
    let enc = match enc {
        Some(e) if !e.is_empty() => e,
        _ => "latin-1".to_owned(),
    };
    let lower = enc.to_lowercase();
    if lower == "gb2312" || lower == "gbk" {
        "gb18030".to_owned()
    } else {
        enc
    }
}

/// UTF-8, every byte of an invalid sequence replaced by its own U+FFFD.
fn utf8_replacing_each_byte(content: &[u8]) -> String {
    let mut out = String::with_capacity(content.len());
    for chunk in content.utf8_chunks() {
        out.push_str(chunk.valid());
        for _ in chunk.invalid() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    }
    out
}

// ── Codecs ───────────────────────────────────────────────

/// The codecs `get_text` decodes natively, by the name CPython's
/// registry gives them (`codecs.lookup(x).name`).
pub const SUPPORTED_CODECS: &[&str] = &[
    "ascii",
    "cp1250",
    "cp1251",
    "cp1252",
    "cp1253",
    "cp1254",
    "cp1255",
    "cp1256",
    "cp1257",
    "cp1258",
    "gb18030",
    "iso8859-1",
    "iso8859-10",
    "iso8859-13",
    "iso8859-14",
    "iso8859-15",
    "iso8859-16",
    "iso8859-2",
    "iso8859-3",
    "iso8859-4",
    "iso8859-5",
    "iso8859-6",
    "iso8859-7",
    "iso8859-8",
    "iso8859-9",
    "koi8-r",
    "koi8-u",
    "utf-16",
    "utf-16-be",
    "utf-16-le",
    "utf-32",
    "utf-32-be",
    "utf-32-le",
    "utf-8",
    "utf-8-sig",
];

/// CPython's codec module names (`encodings.<module>`) for the supported
/// codecs, with the name each module's codec reports.
const MODULES: &[(&str, &str)] = &[
    ("ascii", "ascii"),
    ("cp1250", "cp1250"),
    ("cp1251", "cp1251"),
    ("cp1252", "cp1252"),
    ("cp1253", "cp1253"),
    ("cp1254", "cp1254"),
    ("cp1255", "cp1255"),
    ("cp1256", "cp1256"),
    ("cp1257", "cp1257"),
    ("cp1258", "cp1258"),
    ("gb18030", "gb18030"),
    ("iso8859_10", "iso8859-10"),
    ("iso8859_13", "iso8859-13"),
    ("iso8859_14", "iso8859-14"),
    ("iso8859_15", "iso8859-15"),
    ("iso8859_16", "iso8859-16"),
    ("iso8859_2", "iso8859-2"),
    ("iso8859_3", "iso8859-3"),
    ("iso8859_4", "iso8859-4"),
    ("iso8859_5", "iso8859-5"),
    ("iso8859_6", "iso8859-6"),
    ("iso8859_7", "iso8859-7"),
    ("iso8859_8", "iso8859-8"),
    ("iso8859_9", "iso8859-9"),
    ("koi8_r", "koi8-r"),
    ("koi8_u", "koi8-u"),
    ("latin_1", "iso8859-1"),
    ("utf_16", "utf-16"),
    ("utf_16_be", "utf-16-be"),
    ("utf_16_le", "utf-16-le"),
    ("utf_32", "utf-32"),
    ("utf_32_be", "utf-32-be"),
    ("utf_32_le", "utf-32-le"),
    ("utf_8", "utf-8"),
    ("utf_8_sig", "utf-8-sig"),
];

/// CPython's `encodings.aliases` entries that lead to a supported module.
const ALIASES: &[(&str, &str)] = &[
    ("1250", "cp1250"),
    ("1251", "cp1251"),
    ("1252", "cp1252"),
    ("1253", "cp1253"),
    ("1254", "cp1254"),
    ("1255", "cp1255"),
    ("1256", "cp1256"),
    ("1257", "cp1257"),
    ("1258", "cp1258"),
    ("646", "ascii"),
    ("8859", "latin_1"),
    ("ansi_x3.4_1968", "ascii"),
    ("ansi_x3.4_1986", "ascii"),
    ("ansi_x3_4_1968", "ascii"),
    ("arabic", "iso8859_6"),
    ("asmo_708", "iso8859_6"),
    ("cp367", "ascii"),
    ("cp65001", "utf_8"),
    ("cp819", "latin_1"),
    ("csascii", "ascii"),
    ("csisolatin1", "latin_1"),
    ("csisolatin2", "iso8859_2"),
    ("csisolatin3", "iso8859_3"),
    ("csisolatin4", "iso8859_4"),
    ("csisolatin5", "iso8859_9"),
    ("csisolatin6", "iso8859_10"),
    ("csisolatinarabic", "iso8859_6"),
    ("csisolatincyrillic", "iso8859_5"),
    ("csisolatingreek", "iso8859_7"),
    ("csisolatinhebrew", "iso8859_8"),
    ("cskoi8r", "koi8_r"),
    ("cyrillic", "iso8859_5"),
    ("ecma_114", "iso8859_6"),
    ("ecma_118", "iso8859_7"),
    ("elot_928", "iso8859_7"),
    ("gb18030_2000", "gb18030"),
    ("greek", "iso8859_7"),
    ("greek8", "iso8859_7"),
    ("hebrew", "iso8859_8"),
    ("ibm367", "ascii"),
    ("ibm819", "latin_1"),
    ("iso646_us", "ascii"),
    ("iso8859", "latin_1"),
    ("iso8859_1", "latin_1"),
    ("iso_646.irv_1991", "ascii"),
    ("iso_8859_1", "latin_1"),
    ("iso_8859_10", "iso8859_10"),
    ("iso_8859_10_1992", "iso8859_10"),
    ("iso_8859_13", "iso8859_13"),
    ("iso_8859_14", "iso8859_14"),
    ("iso_8859_14_1998", "iso8859_14"),
    ("iso_8859_15", "iso8859_15"),
    ("iso_8859_16", "iso8859_16"),
    ("iso_8859_16_2001", "iso8859_16"),
    ("iso_8859_1_1987", "latin_1"),
    ("iso_8859_2", "iso8859_2"),
    ("iso_8859_2_1987", "iso8859_2"),
    ("iso_8859_3", "iso8859_3"),
    ("iso_8859_3_1988", "iso8859_3"),
    ("iso_8859_4", "iso8859_4"),
    ("iso_8859_4_1988", "iso8859_4"),
    ("iso_8859_5", "iso8859_5"),
    ("iso_8859_5_1988", "iso8859_5"),
    ("iso_8859_6", "iso8859_6"),
    ("iso_8859_6_1987", "iso8859_6"),
    ("iso_8859_7", "iso8859_7"),
    ("iso_8859_7_1987", "iso8859_7"),
    ("iso_8859_8", "iso8859_8"),
    ("iso_8859_8_1988", "iso8859_8"),
    ("iso_8859_9", "iso8859_9"),
    ("iso_8859_9_1989", "iso8859_9"),
    ("iso_celtic", "iso8859_14"),
    ("iso_ir_100", "latin_1"),
    ("iso_ir_101", "iso8859_2"),
    ("iso_ir_109", "iso8859_3"),
    ("iso_ir_110", "iso8859_4"),
    ("iso_ir_126", "iso8859_7"),
    ("iso_ir_127", "iso8859_6"),
    ("iso_ir_138", "iso8859_8"),
    ("iso_ir_144", "iso8859_5"),
    ("iso_ir_148", "iso8859_9"),
    ("iso_ir_157", "iso8859_10"),
    ("iso_ir_199", "iso8859_14"),
    ("iso_ir_226", "iso8859_16"),
    ("iso_ir_6", "ascii"),
    ("l1", "latin_1"),
    ("l10", "iso8859_16"),
    ("l2", "iso8859_2"),
    ("l3", "iso8859_3"),
    ("l4", "iso8859_4"),
    ("l5", "iso8859_9"),
    ("l6", "iso8859_10"),
    ("l7", "iso8859_13"),
    ("l8", "iso8859_14"),
    ("l9", "iso8859_15"),
    ("latin", "latin_1"),
    ("latin1", "latin_1"),
    ("latin10", "iso8859_16"),
    ("latin2", "iso8859_2"),
    ("latin3", "iso8859_3"),
    ("latin4", "iso8859_4"),
    ("latin5", "iso8859_9"),
    ("latin6", "iso8859_10"),
    ("latin7", "iso8859_13"),
    ("latin8", "iso8859_14"),
    ("latin9", "iso8859_15"),
    ("u16", "utf_16"),
    ("u32", "utf_32"),
    ("u8", "utf_8"),
    ("unicodebigunmarked", "utf_16_be"),
    ("unicodelittleunmarked", "utf_16_le"),
    ("us", "ascii"),
    ("us_ascii", "ascii"),
    ("utf", "utf_8"),
    ("utf16", "utf_16"),
    ("utf32", "utf_32"),
    ("utf8", "utf_8"),
    ("utf8_ucs2", "utf_8"),
    ("utf8_ucs4", "utf_8"),
    ("utf_16be", "utf_16_be"),
    ("utf_16le", "utf_16_le"),
    ("utf_32be", "utf_32_be"),
    ("utf_32le", "utf_32_le"),
    ("windows_1250", "cp1250"),
    ("windows_1251", "cp1251"),
    ("windows_1252", "cp1252"),
    ("windows_1253", "cp1253"),
    ("windows_1254", "cp1254"),
    ("windows_1255", "cp1255"),
    ("windows_1256", "cp1256"),
    ("windows_1257", "cp1257"),
    ("windows_1258", "cp1258"),
];

/// Charset names that the decoding helper looked up in its own
/// Content-Encoding table first (byte-to-byte, never text).
const BYTE_CODECS: &[&str] = &[
    "none",
    "identity",
    "gzip",
    "deflate",
    "deflateraw",
    "br",
    "zstd",
];

/// The supported codec `label` resolves to, by CPython's lookup: the
/// label lower-cased, then every run of characters other than ASCII
/// letters, digits and `.` folded to one `_` (leading and trailing runs
/// dropped), then the alias table, then the module name itself.
#[must_use]
pub fn resolve_codec(label: &str) -> Option<&'static str> {
    if label.contains('\0') {
        return None;
    }
    let lower = label.to_lowercase();
    let mut norm = String::with_capacity(lower.len());
    let mut punct = false;
    for b in lower.bytes() {
        if b.is_ascii_alphanumeric() || b == b'.' {
            if punct && !norm.is_empty() {
                norm.push('_');
            }
            norm.push(char::from(b.to_ascii_lowercase()));
            punct = false;
        } else {
            punct = true;
        }
    }
    let alias = |name: &str| ALIASES.iter().find(|(a, _)| *a == name).map(|(_, m)| *m);
    let aliased = alias(&norm).or_else(|| alias(&norm.replace('.', "_")));
    let mut candidates = Vec::with_capacity(2);
    candidates.extend(aliased);
    candidates.push(norm.as_str());
    candidates
        .into_iter()
        .filter(|m| !m.is_empty() && !m.contains('.'))
        .find_map(|m| MODULES.iter().find(|(name, _)| *name == m).map(|(_, c)| *c))
}

/// Decode `content` with the charset `label`, strictly: `None` when the
/// label is unknown (or a byte codec) or `content` is not valid in it.
#[must_use]
pub fn decode_charset(content: &[u8], label: &str) -> Option<String> {
    if BYTE_CODECS.contains(&label.to_lowercase().as_str()) {
        return None;
    }
    decode_with_codec(content, resolve_codec(label)?)
}

fn decode_with_codec(content: &[u8], codec: &str) -> Option<String> {
    match codec {
        "utf-8" => std::str::from_utf8(content).ok().map(str::to_owned),
        "utf-8-sig" => {
            let body = content.strip_prefix(b"\xef\xbb\xbf").unwrap_or(content);
            std::str::from_utf8(body).ok().map(str::to_owned)
        }
        "ascii" => content
            .is_ascii()
            .then(|| content.iter().map(|&b| char::from(b)).collect()),
        "iso8859-1" => Some(content.iter().map(|&b| char::from(b)).collect()),
        "utf-16" => {
            let (body, big) = match content {
                [0xff, 0xfe, rest @ ..] => (rest, false),
                [0xfe, 0xff, rest @ ..] => (rest, true),
                _ => (content, false),
            };
            decode_utf16(body, big)
        }
        "utf-16-le" => decode_utf16(content, false),
        "utf-16-be" => decode_utf16(content, true),
        "utf-32" => {
            let (body, big) = match content {
                [0xff, 0xfe, 0, 0, rest @ ..] => (rest, false),
                [0, 0, 0xfe, 0xff, rest @ ..] => (rest, true),
                _ => (content, false),
            };
            decode_utf32(body, big)
        }
        "utf-32-le" => decode_utf32(content, false),
        "utf-32-be" => decode_utf32(content, true),
        "gb18030" => decode_gb18030(content),
        other => {
            let table = single_byte_table(other)?;
            content.iter().map(|&b| table[usize::from(b)]).collect()
        }
    }
}

fn decode_utf16(content: &[u8], big: bool) -> Option<String> {
    if content.len() % 2 != 0 {
        return None;
    }
    let units = content.chunks_exact(2).map(|p| {
        if big {
            u16::from_be_bytes([p[0], p[1]])
        } else {
            u16::from_le_bytes([p[0], p[1]])
        }
    });
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()
}

fn decode_utf32(content: &[u8], big: bool) -> Option<String> {
    if content.len() % 4 != 0 {
        return None;
    }
    content
        .chunks_exact(4)
        .map(|q| {
            let q = [q[0], q[1], q[2], q[3]];
            char::from_u32(if big {
                u32::from_be_bytes(q)
            } else {
                u32::from_le_bytes(q)
            })
        })
        .collect()
}

/// The 256 characters of a single-byte codec (`None` where CPython's
/// codec rejects the byte), from `encoding_rs`'s tables corrected where
/// the WHATWG encodings it implements differ from CPython's: the
/// Windows code pages leave their unassigned 0x80-0x9F bytes undefined
/// instead of passing them through as C1 controls, ISO 8859-9 is not
/// windows-1254 (it keeps the C1 controls), and KOI8-U is not KOI8-RU.
fn single_byte_table(codec: &str) -> Option<[Option<char>; 256]> {
    let (encoding, windows) = match codec {
        "cp1250" => (encoding_rs::WINDOWS_1250, true),
        "cp1251" => (encoding_rs::WINDOWS_1251, true),
        "cp1252" => (encoding_rs::WINDOWS_1252, true),
        "cp1253" => (encoding_rs::WINDOWS_1253, true),
        "cp1254" => (encoding_rs::WINDOWS_1254, true),
        "cp1255" => (encoding_rs::WINDOWS_1255, true),
        "cp1256" => (encoding_rs::WINDOWS_1256, true),
        "cp1257" => (encoding_rs::WINDOWS_1257, true),
        "cp1258" => (encoding_rs::WINDOWS_1258, true),
        "iso8859-2" => (encoding_rs::ISO_8859_2, false),
        "iso8859-3" => (encoding_rs::ISO_8859_3, false),
        "iso8859-4" => (encoding_rs::ISO_8859_4, false),
        "iso8859-5" => (encoding_rs::ISO_8859_5, false),
        "iso8859-6" => (encoding_rs::ISO_8859_6, false),
        "iso8859-7" => (encoding_rs::ISO_8859_7, false),
        "iso8859-8" => (encoding_rs::ISO_8859_8, false),
        "iso8859-9" => (encoding_rs::WINDOWS_1254, false),
        "iso8859-10" => (encoding_rs::ISO_8859_10, false),
        "iso8859-13" => (encoding_rs::ISO_8859_13, false),
        "iso8859-14" => (encoding_rs::ISO_8859_14, false),
        "iso8859-15" => (encoding_rs::ISO_8859_15, false),
        "iso8859-16" => (encoding_rs::ISO_8859_16, false),
        "koi8-r" => (encoding_rs::KOI8_R, false),
        "koi8-u" => (encoding_rs::KOI8_U, false),
        _ => return None,
    };
    let mut table = [None; 256];
    for (byte, slot) in (0u8..=255).zip(table.iter_mut()) {
        let c = encoding
            .decode_without_bom_handling_and_without_replacement(&[byte])
            .and_then(|s| s.chars().next());
        let c1 = (0x80..=0x9f).contains(&byte);
        *slot = match (codec, byte) {
            // Unassigned in the code page; WHATWG passes it through.
            _ if windows && c1 && c == Some(char::from(byte)) => None,
            ("cp1255", 0xca) => None,
            ("iso8859-9", _) if c1 => Some(char::from(byte)),
            ("koi8-u", 0xae) => Some('\u{255d}'),
            ("koi8-u", 0xbe) => Some('\u{256c}'),
            _ => c,
        };
    }
    Some(table)
}

/// GB 18030 two- and four-byte sequences CPython (GB 18030-2005) maps
/// differently from `encoding_rs` (the WHATWG encoding, which follows the
/// 2022 edition and a few WHATWG choices).
const GB18030_2005: &[(&[u8], char)] = &[
    (b"\xa3\xa0", '\u{e5e5}'),
    (b"\xa6\xd9", '\u{e78d}'),
    (b"\xa6\xda", '\u{e78e}'),
    (b"\xa6\xdb", '\u{e78f}'),
    (b"\xa6\xdc", '\u{e790}'),
    (b"\xa6\xdd", '\u{e791}'),
    (b"\xa6\xde", '\u{e792}'),
    (b"\xa6\xdf", '\u{e793}'),
    (b"\xa6\xec", '\u{e794}'),
    (b"\xa6\xed", '\u{e795}'),
    (b"\xa6\xf3", '\u{e796}'),
    (b"\xa8\xbc", '\u{e7c7}'),
    (b"\xfe\x59", '\u{e81e}'),
    (b"\xfe\x61", '\u{e826}'),
    (b"\xfe\x66", '\u{e82b}'),
    (b"\xfe\x67", '\u{e82c}'),
    (b"\xfe\x6d", '\u{e832}'),
    (b"\xfe\x7e", '\u{e843}'),
    (b"\xfe\x90", '\u{e854}'),
    (b"\xfe\xa0", '\u{e864}'),
    (b"\x81\x35\xf4\x37", '\u{1e3f}'),
];

/// GB 18030 as CPython decodes it: `encoding_rs` for every run of
/// sequences, with the [`GB18030_2005`] sequences and the lone `0x80`
/// (which WHATWG reads as `€` and CPython rejects) handled here.
fn decode_gb18030(content: &[u8]) -> Option<String> {
    let mut out = String::with_capacity(content.len());
    let mut run_start = 0;
    let mut pos = 0;
    let flush = |out: &mut String, run: &[u8]| -> Option<()> {
        let text = encoding_rs::GB18030.decode_without_bom_handling_and_without_replacement(run)?;
        out.push_str(&text);
        Some(())
    };
    while pos < content.len() {
        let b = content[pos];
        let len = match b {
            0x80 => return None,
            0x81..=0xfe => match content.get(pos + 1) {
                Some(0x30..=0x39) => 4,
                _ => 2,
            },
            _ => 1,
        };
        let seq = &content[pos..(pos + len).min(content.len())];
        if let Some(&(_, c)) = GB18030_2005.iter().find(|(s, _)| *s == seq) {
            flush(&mut out, &content[run_start..pos])?;
            out.push(c);
            run_start = pos + len;
        }
        pos += len;
    }
    flush(&mut out, &content[run_start..])?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{Json, parse};

    fn corpus() -> Json {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/egress/get_text.json"
        );
        parse(&std::fs::read_to_string(path).expect("get_text.json")).expect("valid JSON")
    }

    pub(crate) fn bytes_of(v: &Json) -> Vec<u8> {
        match v {
            Json::Str(s) => s.as_bytes().to_vec(),
            _ => crate::inject::b64_decode_std(v.get("b64").and_then(Json::as_str).unwrap())
                .expect("fixture base64"),
        }
    }

    fn headers_of(v: &Json) -> Headers {
        let Json::Array(pairs) = v else {
            panic!("headers")
        };
        Headers(
            pairs
                .iter()
                .map(|p| {
                    let Json::Array(kv) = p else { panic!("pair") };
                    (
                        kv[0].as_str().unwrap().as_bytes().to_vec(),
                        kv[1].as_str().unwrap().as_bytes().to_vec(),
                    )
                })
                .collect(),
        )
    }

    fn items<'a>(c: &'a Json, key: &str) -> &'a [Json] {
        match c.get(key) {
            Some(Json::Array(a)) => a,
            _ => panic!("{key}"),
        }
    }

    #[test]
    fn corpus_cases_decode_like_python() {
        let c = corpus();
        let mut failures = Vec::new();
        for case in items(&c, "cases") {
            let name = case.get("name").and_then(Json::as_str).unwrap();
            let headers = headers_of(case.get("headers").unwrap());
            let body = bytes_of(case.get("body").unwrap());
            let want_decoded = match case.get("decoded") {
                Some(Json::Null) | None => None,
                Some(v) => Some(bytes_of(v)),
            };
            let got_decoded = decoded_body(&headers, &body).ok().map(Cow::into_owned);
            if got_decoded != want_decoded {
                failures.push(format!(
                    "{name}: decoded {:?} want {:?}",
                    got_decoded.as_ref().map(Vec::len),
                    want_decoded.as_ref().map(Vec::len)
                ));
            }
            let want_text = case.get("text").and_then(Json::as_str).unwrap();
            let got_text = get_text(&headers, &body);
            if got_text != want_text {
                failures.push(format!("{name}: text {got_text:?} want {want_text:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn codec_labels_resolve_like_python() {
        let c = corpus();
        let mut failures = Vec::new();
        for case in items(&c, "labels") {
            let label = case.get("label").and_then(Json::as_str).unwrap();
            let want = case.get("codec").and_then(Json::as_str);
            let got = resolve_codec(label);
            let ok = match (got, want) {
                (Some(g), Some(w)) => g == w,
                (Some(_), None) => false,
                (None, Some(w)) => !SUPPORTED_CODECS.contains(&w),
                (None, None) => true,
            };
            if !ok {
                failures.push(format!("{label:?}: {got:?} want {want:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn single_byte_tables_match_python() {
        let c = corpus();
        for case in items(&c, "tables") {
            let codec = case.get("codec").and_then(Json::as_str).unwrap();
            assert!(SUPPORTED_CODECS.contains(&codec), "{codec}");
            for (byte, want) in (0u8..=255).zip(items(case, "table")) {
                let want = match want {
                    Json::Int(cp) => char::from_u32(u32::try_from(*cp).unwrap()),
                    _ => None,
                };
                let got = decode_with_codec(&[byte], codec).and_then(|s| s.chars().next());
                assert_eq!(got, want, "{codec} byte {byte:#04x}");
            }
        }
    }

    #[test]
    fn multibyte_samples_match_python() {
        let c = corpus();
        for case in items(&c, "multibyte") {
            let codec = case.get("codec").and_then(Json::as_str).unwrap();
            let data = bytes_of(case.get("bytes").unwrap());
            let want = case.get("text").and_then(Json::as_str);
            assert_eq!(
                decode_with_codec(&data, codec).as_deref(),
                want,
                "{codec} {data:02x?}"
            );
        }
    }

    #[test]
    fn every_supported_codec_is_reachable_by_its_own_name() {
        for codec in SUPPORTED_CODECS {
            assert_eq!(resolve_codec(codec), Some(*codec));
        }
    }

    #[test]
    fn fallback_replaces_each_invalid_byte() {
        assert_eq!(
            utf8_replacing_each_byte(b"a\xe2\x82b\xff"),
            "a\u{fffd}\u{fffd}b\u{fffd}"
        );
    }
}
