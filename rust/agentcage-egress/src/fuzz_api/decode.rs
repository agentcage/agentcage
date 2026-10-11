//! Content-Encoding removal, streaming against one-shot, and charset
//! decoding.
//!
//! A streamed response is decoded by [`StreamDecoder`] before it is
//! redacted; a buffered one by [`decode_content`]. The streaming module
//! promises the same bytes for every input the one-shot decoder accepts
//! (one documented exception: a `deflate` body that starts like zlib is
//! never retried as raw DEFLATE), and an error wherever the one-shot
//! decoder refuses. The output limit per call must hold too: it is what
//! keeps a decompression bomb from being inflated in one piece.

use std::io::Write as _;

use crate::message::Headers;
use crate::text::stream::{StreamCodec, StreamDecoder, StreamEncoding};
use crate::text::{DecodeError, decode_content, decode_text, get_text};

use super::{Input, pieces};

const ENCODINGS: [&str; 8] = [
    "gzip",
    "deflate",
    "deflateraw",
    "br",
    "zstd",
    "identity",
    "GZip",
    "x-unknown",
];

const CONTENT_TYPES: [&str; 10] = [
    "text/plain; charset=utf-8",
    "application/json",
    "text/html; charset=\"iso-8859-1\"",
    "text/plain; charset=utf-16",
    "text/plain; charset=gb18030",
    "text/css; charset=cp1252",
    "text/plain; charset=utf-32-be",
    "application/x-www-form-urlencoded",
    "text/plain; charset=bogus",
    "",
];

/// `payload` compressed for `encoding` by a real encoder (gzip and
/// deflate each in both container shapes their decoders accept), so the
/// success paths are reached; `None` for encodings with no encoder here.
fn compress(encoding: &str, payload: &[u8], shape: u8) -> Option<Vec<u8>> {
    let level = flate2::Compression::new(u32::from(shape >> 1) % 10);
    let zlib = || {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), level);
        e.write_all(payload).ok()?;
        e.finish().ok()
    };
    match (encoding.to_ascii_lowercase().as_str(), shape & 1) {
        ("gzip", 0) => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), level);
            e.write_all(payload).ok()?;
            e.finish().ok()
        }
        ("gzip" | "deflate" | "deflateraw", 1) => zlib(),
        ("deflate" | "deflateraw", _) => {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), level);
            e.write_all(payload).ok()?;
            e.finish().ok()
        }
        _ => None,
    }
}

/// Decode `raw` with the streaming decoder, fed in `sizes` pieces with
/// `limit` bytes of output per call.
fn streamed(
    codec: StreamCodec,
    raw: &[u8],
    sizes: &[usize],
    limit: usize,
) -> Result<Vec<u8>, DecodeError> {
    // The most one call may exceed its limit by (one internal block).
    const SLACK: usize = 256 * 1024;
    let mut d = StreamDecoder::new(codec);
    let mut out = Vec::new();
    for piece in pieces(raw, sizes) {
        let mut rest = piece;
        while !rest.is_empty() {
            let before = out.len();
            let used = d.decode(rest, &mut out, limit)?;
            assert!(out.len() - before <= limit.max(1) + SLACK);
            assert!(used <= rest.len());
            rest = &rest[used..];
        }
    }
    loop {
        let before = out.len();
        d.decode(&[], &mut out, limit)?;
        if out.len() == before {
            break;
        }
    }
    d.finish()?;
    Ok(out)
}

/// The two decoders agree.
pub fn decode(data: &[u8]) {
    let mut input = Input::new(data);
    let encoding = ENCODINGS[input.below(ENCODINGS.len())];
    let content_type = CONTENT_TYPES[input.below(CONTENT_TYPES.len())];
    let mode = input.byte();
    let limit = 1 + usize::from(input.byte()) * 64;
    let sizes = input.piece_sizes();
    let cut = u16::from_le_bytes([input.byte(), input.byte()]);
    let flip = u16::from_le_bytes([input.byte(), input.byte()]);
    let payload = input.rest();

    // Odd modes compress the payload first, then maybe damage it.
    let compressed = (mode & 1 == 1)
        .then(|| compress(encoding, payload, mode >> 1))
        .flatten();
    let mut raw = compressed.clone().unwrap_or_else(|| payload.to_vec());
    let damaged = compressed.is_some() && mode & 0x40 != 0;
    if damaged {
        if mode & 0x80 != 0 {
            raw.truncate(usize::from(cut) % (raw.len() + 1));
        } else if !raw.is_empty() {
            let at = usize::from(flip) % raw.len();
            raw[at] ^= 1 << (flip >> 13);
        }
    }

    let whole = decode_content(&raw, encoding).map(std::borrow::Cow::into_owned);
    if compressed.is_some() && !damaged {
        assert_eq!(
            whole.as_deref().ok(),
            Some(payload),
            "a real encoder's {encoding} output does not decode back"
        );
    }

    if let StreamEncoding::Codec(codec) = StreamEncoding::of(Some(encoding)) {
        let stream = streamed(codec, &raw, &sizes, limit);
        match (&whole, &stream) {
            (Ok(a), Ok(b)) => assert!(a == b, "{encoding}: the decoders disagree"),
            (Err(_), Err(_)) => {}
            (Ok(_), Err(e)) => {
                // The documented exception: a deflate body whose first
                // two bytes are a valid zlib header is decoded as zlib
                // only.
                let zlib_header = raw.len() >= 2
                    && (u16::from(raw[0]) << 8 | u16::from(raw[1])) % 31 == 0
                    && raw[0] & 0x0f == 8;
                assert!(
                    codec == StreamCodec::Deflate && zlib_header,
                    "{encoding}: the streaming decoder refuses what the one-shot accepts: {e}"
                );
            }
            (Err(e), Ok(_)) => {
                panic!("{encoding}: the streaming decoder accepts what the one-shot refuses ({e})")
            }
        }
    }

    // The text inspectors read, for any header combination.
    let mut headers = Headers::new();
    headers.add("Content-Encoding", encoding);
    headers.add("Content-Type", content_type);
    let _ = get_text(&headers, &raw);
    let _ = decode_text(content_type, payload);
}
