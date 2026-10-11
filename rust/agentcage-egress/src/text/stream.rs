//! Content-Encoding removal for a body that arrives in chunks: the
//! streaming counterpart of [`decode_content`](super::decode_content) for
//! `gzip`, `deflate` / `deflateraw` and `br`, producing the same bytes for
//! every input the one-shot decoder accepts.
//!
//! Output is produced a bounded piece at a time ([`StreamDecoder::decode`]
//! takes an output limit), so a small compressed chunk that expands a
//! thousandfold is relayed in pieces with backpressure, never inflated
//! whole in memory.
//!
//! Where the one-shot decoder tolerates a cut-short stream (`gzip`, and a
//! zlib stream under `gzip`), so does this one. Where it is strict
//! (`deflate`, `br`), the error comes at the end of the body, after the
//! decoded bytes so far have been relayed: the caller aborts the exchange
//! then. One difference on corrupt input: a `deflate` body whose first two
//! bytes form a valid zlib header is decoded as zlib only; the one-shot
//! decoder retried a failed zlib parse as raw DEFLATE.

use flate2::{Decompress, FlushDecompress, Status};

use super::DecodeError;

/// A Content-Encoding the streaming decoder handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamCodec {
    /// `gzip` (a gzip member, or a zlib stream; cut-short tolerated).
    Gzip,
    /// `deflate` / `deflateraw` (a complete zlib or raw DEFLATE stream).
    Deflate,
    /// `br` (one complete stream, nothing after it).
    Brotli,
}

/// What a `Content-Encoding` header value means for streaming.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamEncoding {
    /// No encoding to remove (`identity`, `none`, absent or empty).
    Identity,
    /// Decodable as it streams.
    Codec(StreamCodec),
    /// Not decodable as it streams (`zstd`, stacked or unknown
    /// encodings): the body must be buffered whole.
    Buffered,
}

impl StreamEncoding {
    /// Classify a `Content-Encoding` value (`None`: no header).
    #[must_use]
    pub fn of(content_encoding: Option<&str>) -> Self {
        let Some(ce) = content_encoding.filter(|ce| !ce.is_empty()) else {
            return Self::Identity;
        };
        match ce.to_lowercase().as_str() {
            "none" | "identity" => Self::Identity,
            "gzip" => Self::Codec(StreamCodec::Gzip),
            "deflate" | "deflateraw" => Self::Codec(StreamCodec::Deflate),
            "br" => Self::Codec(StreamCodec::Brotli),
            _ => Self::Buffered,
        }
    }
}

/// zlib's Adler-32, kept running.
#[derive(Clone, Copy, Debug)]
struct Adler {
    a: u32,
    b: u32,
}

impl Adler {
    fn new() -> Self {
        Self { a: 1, b: 0 }
    }

    fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(5552) {
            for &x in chunk {
                self.a += u32::from(x);
                self.b += self.a;
            }
            self.a %= 65521;
            self.b %= 65521;
        }
    }

    fn value(self) -> u32 {
        (self.b << 16) | self.a
    }
}

/// The zlib header checks of [`super::inflate_zlib`].
fn zlib_header(cmf: u8, flg: u8) -> Result<(), String> {
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
    Ok(())
}

/// The checksum a DEFLATE body is followed by.
#[derive(Debug)]
enum Check {
    /// gzip: CRC-32 and ISIZE, checked as far as the trailer goes.
    Gzip(crc32fast::Hasher, u64),
    /// zlib: Adler-32.
    Zlib(Adler),
    /// Raw DEFLATE (strict: the final block must be reached).
    Raw,
}

/// The brotli decoder's state.
type BrotliState = brotli_decompressor::BrotliState<
    brotli_decompressor::StandardAlloc,
    brotli_decompressor::StandardAlloc,
    brotli_decompressor::StandardAlloc,
>;

enum State {
    /// Collecting the first bytes (the gzip header, the zlib header).
    Head(Vec<u8>),
    /// Inflating.
    Inflate(Box<Decompress>, Check),
    /// After the final block: the trailer so far.
    Trailer(Vec<u8>, Check),
    /// Decoding brotli.
    Brotli(
        Box<
            brotli_decompressor::BrotliState<
                brotli_decompressor::StandardAlloc,
                brotli_decompressor::StandardAlloc,
                brotli_decompressor::StandardAlloc,
            >,
        >,
    ),
    /// The stream is complete; anything after it is ignored (gzip,
    /// deflate) or an error (brotli).
    Done,
}

/// Removes one Content-Encoding from a body handed over in chunks.
pub struct StreamDecoder {
    codec: StreamCodec,
    state: State,
    /// Whether any input was seen (an empty body decodes to nothing).
    seen: bool,
}

impl std::fmt::Debug for StreamDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamDecoder")
            .field("codec", &self.codec)
            .finish_non_exhaustive()
    }
}

impl StreamDecoder {
    /// A decoder for `codec`.
    #[must_use]
    pub fn new(codec: StreamCodec) -> Self {
        let state = match codec {
            StreamCodec::Brotli => {
                let mut state = brotli_decompressor::BrotliState::new(
                    brotli_decompressor::StandardAlloc::default(),
                    brotli_decompressor::StandardAlloc::default(),
                    brotli_decompressor::StandardAlloc::default(),
                );
                state.large_window = false;
                State::Brotli(Box::new(state))
            }
            _ => State::Head(Vec::new()),
        };
        Self {
            codec,
            state,
            seen: false,
        }
    }

    fn name(&self) -> &'static str {
        match self.codec {
            StreamCodec::Gzip => "gzip",
            StreamCodec::Deflate => "deflate",
            StreamCodec::Brotli => "br",
        }
    }

    fn corrupt(&self, detail: impl Into<String>) -> DecodeError {
        DecodeError::Corrupt {
            encoding: self.name().to_owned(),
            detail: detail.into(),
        }
    }

    /// Decode from `input`, appending at most `limit` bytes to `out`;
    /// returns how much of `input` was consumed. Call again with the rest
    /// until it is all consumed, then with an empty `input` until no more
    /// output comes (the decoder may hold decoded bytes the limit kept
    /// back), and [`StreamDecoder::finish`] at the end of the body.
    ///
    /// # Errors
    ///
    /// The stream is corrupt.
    pub fn decode(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<usize, DecodeError> {
        if !input.is_empty() {
            self.seen = true;
        }
        let state = std::mem::replace(&mut self.state, State::Done);
        let (state, consumed) = self.step(state, input, out, limit.max(1))?;
        self.state = state;
        Ok(consumed)
    }

    fn step(
        &self,
        state: State,
        input: &[u8],
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<(State, usize), DecodeError> {
        match state {
            State::Head(mut head) => {
                let prior = head.len();
                let take = input.len().min(64 * 1024);
                head.extend_from_slice(&input[..take]);
                match self.start(&head)? {
                    None => Ok((State::Head(head), take)),
                    Some((mut state, body_at)) => {
                        // Only the header is consumed from `input`; the
                        // body bytes after it are the caller's to hand
                        // over again. A raw DEFLATE body's first byte may
                        // have arrived alone, before the header could be
                        // judged: inflate it now.
                        if prior > body_at {
                            let mut rest = &head[body_at..prior];
                            while !rest.is_empty() {
                                let (next, used) = self.step(state, rest, out, limit)?;
                                state = next;
                                rest = &rest[used..];
                            }
                        }
                        Ok((state, body_at.max(prior) - prior))
                    }
                }
            }
            State::Inflate(mut d, mut check) => {
                // decompress_vec fills spare capacity only: a buffer of
                // exactly the allowed size bounds the output.
                let mut buf = Vec::with_capacity(limit.min(256 * 1024));
                let in_before = d.total_in();
                let status = d
                    .decompress_vec(input, &mut buf, FlushDecompress::None)
                    .map_err(|e| self.corrupt(e.to_string()))?;
                let consumed = usize::try_from(d.total_in() - in_before).unwrap_or(input.len());
                out.extend_from_slice(&buf);
                let produced = &buf[..];
                match &mut check {
                    Check::Gzip(crc, size) => {
                        crc.update(produced);
                        *size += produced.len() as u64;
                    }
                    Check::Zlib(adler) => adler.update(produced),
                    Check::Raw => {}
                }
                if status == Status::StreamEnd {
                    let state = if matches!(check, Check::Raw) {
                        State::Done
                    } else {
                        State::Trailer(Vec::new(), check)
                    };
                    return Ok((state, consumed));
                }
                Ok((State::Inflate(d, check), consumed))
            }
            State::Trailer(trailer, check) => self.trailer(trailer, check, input),
            State::Brotli(state) => self.brotli(state, input, out, limit),
            State::Done => {
                if self.codec == StreamCodec::Brotli && !input.is_empty() {
                    return Err(self.corrupt("trailing data after the stream"));
                }
                Ok((State::Done, input.len()))
            }
        }
    }

    /// After the final block: collect and check the trailer.
    fn trailer(
        &self,
        mut trailer: Vec<u8>,
        check: Check,
        input: &[u8],
    ) -> Result<(State, usize), DecodeError> {
        let need = match check {
            Check::Gzip(..) => 8,
            _ => 4,
        };
        let take = (need - trailer.len()).min(input.len());
        trailer.extend_from_slice(&input[..take]);
        if trailer.len() < need {
            // A gzip CRC is checked as soon as it is complete.
            if let Check::Gzip(crc, _) = &check {
                if trailer.len() >= 4 {
                    self.check_crc(crc, &trailer)?;
                }
            }
            return Ok((State::Trailer(trailer, check), take));
        }
        match &check {
            Check::Gzip(crc, size) => {
                self.check_crc(crc, &trailer)?;
                let want = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
                // ISIZE is the length modulo 2^32.
                #[allow(clippy::cast_possible_truncation)]
                if want != *size as u32 {
                    return Err(self.corrupt("incorrect length check"));
                }
            }
            Check::Zlib(adler) => {
                let want = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
                if adler.value() != want {
                    return Err(self.corrupt("incorrect data check"));
                }
            }
            Check::Raw => {}
        }
        Ok((State::Done, take))
    }

    fn brotli(
        &self,
        mut state: Box<BrotliState>,
        input: &[u8],
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<(State, usize), DecodeError> {
        use brotli_decompressor::{BrotliDecompressStream, BrotliResult};
        let room = limit.min(256 * 1024);
        let mut buf = vec![0u8; room];
        let (mut avail_in, mut in_off) = (input.len(), 0usize);
        let (mut avail_out, mut out_off, mut total) = (buf.len(), 0usize, 0usize);
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
            BrotliResult::NeedsMoreOutput | BrotliResult::NeedsMoreInput => {
                Ok((State::Brotli(state), in_off))
            }
            BrotliResult::ResultSuccess if avail_in == 0 => Ok((State::Done, in_off)),
            BrotliResult::ResultSuccess => Err(self.corrupt("trailing data after the stream")),
            BrotliResult::ResultFailure => Err(self.corrupt("corrupt stream")),
        }
    }

    fn check_crc(&self, crc: &crc32fast::Hasher, trailer: &[u8]) -> Result<(), DecodeError> {
        let want = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        if crc.clone().finalize() != want {
            return Err(self.corrupt("incorrect data check"));
        }
        Ok(())
    }

    /// Whether `head` holds enough to start the body: the state to start
    /// in and where in `head` the compressed data begins.
    fn start(&self, head: &[u8]) -> Result<Option<(State, usize)>, DecodeError> {
        if head.len() < 2 {
            return Ok(None);
        }
        let raw = || Box::new(Decompress::new(false));
        match self.codec {
            StreamCodec::Gzip if head[..2] == [0x1f, 0x8b] => {
                match super::gzip_header_len(head).map_err(|e| self.corrupt(e))? {
                    None => Ok(None),
                    Some(n) => Ok(Some((
                        State::Inflate(raw(), Check::Gzip(crc32fast::Hasher::new(), 0)),
                        n,
                    ))),
                }
            }
            StreamCodec::Gzip => {
                zlib_header(head[0], head[1]).map_err(|e| self.corrupt(e))?;
                Ok(Some((State::Inflate(raw(), Check::Zlib(Adler::new())), 2)))
            }
            StreamCodec::Deflate => Ok(Some(if zlib_header(head[0], head[1]).is_ok() {
                (State::Inflate(raw(), Check::Zlib(Adler::new())), 2)
            } else {
                (State::Inflate(raw(), Check::Raw), 0)
            })),
            StreamCodec::Brotli => unreachable!("brotli has no head state"),
        }
    }

    /// The body ended.
    ///
    /// # Errors
    ///
    /// The stream is incomplete where the one-shot decoder requires it to
    /// be complete (`deflate`, `br`).
    pub fn finish(&mut self) -> Result<(), DecodeError> {
        if !self.seen {
            return Ok(());
        }
        let strict = match &self.state {
            State::Done => false,
            // A gzip (or zlib-under-gzip) stream cut short decodes as far
            // as it goes.
            _ if self.codec == StreamCodec::Gzip => false,
            State::Head(head) if self.codec == StreamCodec::Deflate && head.len() < 2 => {
                // One byte of deflate: neither a zlib nor a complete raw
                // stream.
                true
            }
            _ => true,
        };
        if strict {
            let detail = if self.codec == StreamCodec::Brotli {
                "truncated stream"
            } else {
                "incomplete or truncated stream"
            };
            return Err(self.corrupt(detail));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut e, data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut e, data).unwrap();
        e.finish().unwrap()
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut e, data).unwrap();
        e.finish().unwrap()
    }

    fn streamed(
        codec: StreamCodec,
        input: &[u8],
        step: usize,
        limit: usize,
    ) -> Result<Vec<u8>, DecodeError> {
        let mut d = StreamDecoder::new(codec);
        let mut out = Vec::new();
        for chunk in input.chunks(step.max(1)) {
            let mut rest = chunk;
            while !rest.is_empty() {
                let before = out.len();
                let used = d.decode(rest, &mut out, limit)?;
                assert!(out.len() - before <= limit.max(1) + 256 * 1024);
                rest = &rest[used..];
            }
        }
        // Drain what is still buffered inside the inflater.
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

    #[test]
    fn streamed_decoding_matches_the_one_shot_decoder() {
        let mut data = Vec::new();
        for i in 0..200_000u32 {
            data.extend_from_slice(format!("line {i} {}\n", i % 7).as_bytes());
        }
        let cases: Vec<(StreamCodec, &str, Vec<u8>)> = vec![
            (StreamCodec::Gzip, "gzip", gzip(&data)),
            (StreamCodec::Gzip, "gzip", zlib(&data)),
            (StreamCodec::Deflate, "deflate", zlib(&data)),
            (StreamCodec::Deflate, "deflate", raw_deflate(&data)),
            (StreamCodec::Gzip, "gzip", gzip(b"")),
            (StreamCodec::Deflate, "deflate", Vec::new()),
        ];
        for (codec, name, enc) in cases {
            let want = super::super::decode_content(&enc, name)
                .unwrap()
                .into_owned();
            for step in [1, 7, 4096, enc.len().max(1)] {
                for limit in [1, 1000, 64 * 1024] {
                    if step == 1 && enc.len() > 100_000 && limit == 1 {
                        continue;
                    }
                    let got = streamed(codec, &enc, step, limit).unwrap();
                    assert!(got == want, "{name} step {step} limit {limit}");
                }
            }
        }
    }

    #[test]
    fn truncation_and_corruption_follow_the_one_shot_decoder() {
        let data = b"hello hello hello hello hello world".repeat(100);
        let gz = gzip(&data);
        // gzip cut short: decodes as far as it goes, no error.
        let cut = &gz[..gz.len() / 2];
        let want = super::super::decode_content(cut, "gzip")
            .unwrap()
            .into_owned();
        assert_eq!(streamed(StreamCodec::Gzip, cut, 5, 100).unwrap(), want);
        // Cut inside the header: nothing, no error.
        assert_eq!(streamed(StreamCodec::Gzip, &gz[..5], 1, 100).unwrap(), b"");
        // A bad CRC is an error.
        let mut bad = gz.clone();
        let n = bad.len();
        bad[n - 6] ^= 0xff;
        assert!(super::super::decode_content(&bad, "gzip").is_err());
        assert!(streamed(StreamCodec::Gzip, &bad, 9, 100).is_err());
        // deflate must be complete.
        let z = zlib(&data);
        assert!(streamed(StreamCodec::Deflate, &z[..z.len() - 2], 9, 100).is_err());
        assert!(streamed(StreamCodec::Deflate, &raw_deflate(&data)[..10], 3, 100).is_err());
        // Trailing bytes after a gzip member are ignored.
        let mut trailing = gz.clone();
        trailing.extend_from_slice(b"garbage");
        assert_eq!(
            streamed(StreamCodec::Gzip, &trailing, 13, 1000).unwrap(),
            data
        );
    }

    #[test]
    fn brotli_streams_and_must_be_complete() {
        // A brotli stream from the one-shot decoder's own test corpus is
        // not at hand; build one with the reference encoder's simplest
        // form: an empty, last meta-block (0x3b = WBITS 22 header + ISLAST
        // + ISLASTEMPTY).
        let empty = [0x3b];
        assert_eq!(
            super::super::decode_content(&empty, "br").unwrap().as_ref(),
            b""
        );
        assert_eq!(streamed(StreamCodec::Brotli, &empty, 1, 10).unwrap(), b"");
        let mut trailing = empty.to_vec();
        trailing.push(0);
        assert!(streamed(StreamCodec::Brotli, &trailing, 1, 10).is_err());
        assert!(streamed(StreamCodec::Brotli, &[0x0b], 1, 10).is_err());
    }

    #[test]
    fn corpus_bodies_decode_as_the_one_shot_decoder_does() {
        use crate::json::Json;
        let corpus = super::super::tests::corpus();
        let Some(Json::Array(cases)) = corpus.get("cases") else {
            panic!("cases")
        };
        let mut checked = 0;
        for case in cases {
            let headers = super::super::tests::headers_of(case.get("headers").unwrap());
            let StreamEncoding::Codec(codec) =
                StreamEncoding::of(headers.get("content-encoding").as_deref())
            else {
                continue;
            };
            let body = super::super::tests::bytes_of(case.get("body").unwrap());
            let want = super::super::decoded_body(&headers, &body);
            for step in [1, 3, body.len().max(1)] {
                let got = streamed(codec, &body, step, 7);
                match &want {
                    Ok(want) => assert_eq!(got.as_deref().ok(), Some(want.as_ref()), "{case:?}"),
                    Err(_) => assert!(got.is_err(), "{case:?}"),
                }
            }
            checked += 1;
        }
        assert!(checked >= 10, "{checked}");
    }

    #[test]
    fn encodings_are_classified_for_streaming() {
        assert_eq!(StreamEncoding::of(None), StreamEncoding::Identity);
        assert_eq!(StreamEncoding::of(Some("")), StreamEncoding::Identity);
        assert_eq!(
            StreamEncoding::of(Some("Identity")),
            StreamEncoding::Identity
        );
        assert_eq!(
            StreamEncoding::of(Some("GZIP")),
            StreamEncoding::Codec(StreamCodec::Gzip)
        );
        assert_eq!(
            StreamEncoding::of(Some("br")),
            StreamEncoding::Codec(StreamCodec::Brotli)
        );
        assert_eq!(StreamEncoding::of(Some("zstd")), StreamEncoding::Buffered);
        assert_eq!(
            StreamEncoding::of(Some("gzip, br")),
            StreamEncoding::Buffered
        );
        assert_eq!(StreamEncoding::of(Some("x-gzip")), StreamEncoding::Buffered);
    }
}
