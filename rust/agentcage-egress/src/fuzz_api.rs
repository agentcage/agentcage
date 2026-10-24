//! Entry points for the fuzz targets under `fuzz/` (cargo-fuzz).
//!
//! Not part of the crate's API: compiled only with the `fuzzing` feature
//! (which the fuzz crate turns on) and in this crate's own tests. Each
//! function takes the fuzzer's raw bytes, drives the code that parses
//! untrusted input with them, and panics when a property the egress relies
//! on does not hold — so the harness logic lives here, next to the
//! `pub(crate)` code it exercises, rather than widening that code's
//! visibility, and the committed seeds and regression inputs replay on a
//! stable toolchain as ordinary unit tests (see the tests at the bottom).
//!
//! The targets, one per function:
//!
//! * [`h1_request`] / [`h1_response`]: HTTP/1 head parsing, the
//!   request-smuggling checks, body framing, the buffered body reader
//!   against the incremental one, and re-encoding.
//! * [`tls_detect`]: `ClientHello` parsing and plaintext classification.
//! * [`imap`] / [`smtp`]: the relays' line, literal, mailbox, address,
//!   header and DATA handling.
//! * [`redact_stream`]: streaming redaction against buffered redaction.
//! * `decode`: streaming Content-Encoding removal against the one-shot
//!   decoder, and charset decoding.
//! * `config`: loading arbitrary config text and handing it to every
//!   section's parser.

mod config;
mod decode;
mod redact;
mod relays;

pub use config::config;
pub use decode::decode;
pub use redact::redact_stream;
pub use relays::{imap, smtp};

/// HTTP/1 request heads and bodies; see `proxy::fuzz`.
pub fn h1_request(data: &[u8]) {
    crate::proxy::fuzz::h1_request(data);
}

/// HTTP/1 response heads and bodies; see `proxy::fuzz`.
pub fn h1_response(data: &[u8]) {
    crate::proxy::fuzz::h1_response(data);
}

/// TLS `ClientHello` parsing and plaintext protocol detection; see
/// `proxy::fuzz`.
pub fn tls_detect(data: &[u8]) {
    crate::proxy::fuzz::tls_detect(data);
}

/// A cursor over the fuzzer's bytes: harness parameters are taken from
/// the front, and running out yields zeros rather than failing, so every
/// input is a valid one.
#[derive(Debug)]
pub(crate) struct Input<'a> {
    data: &'a [u8],
}

impl<'a> Input<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(crate) fn byte(&mut self) -> u8 {
        match self.data.split_first() {
            Some((&b, rest)) => {
                self.data = rest;
                b
            }
            None => 0,
        }
    }

    /// A number below `n` (`n > 0`).
    pub(crate) fn below(&mut self, n: usize) -> usize {
        usize::from(self.byte()) % n
    }

    /// Up to `n` bytes.
    pub(crate) fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, rest) = self.data.split_at(n.min(self.data.len()));
        self.data = rest;
        head
    }

    /// Everything left.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.data)
    }

    /// How a byte stream is cut into reads: four piece sizes, cycled.
    /// A zero byte means "everything at once".
    pub(crate) fn piece_sizes(&mut self) -> Vec<usize> {
        (0..4)
            .map(|_| match self.byte() {
                0 => usize::MAX,
                b => usize::from(b),
            })
            .collect()
    }
}

/// `data` cut at the cycled `sizes` (see [`Input::piece_sizes`]).
pub(crate) fn pieces<'d>(data: &'d [u8], sizes: &[usize]) -> Vec<&'d [u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    let mut i = 0;
    while !rest.is_empty() {
        let n = sizes[i % sizes.len()].min(rest.len());
        let (piece, tail) = rest.split_at(n);
        out.push(piece);
        rest = tail;
        i += 1;
    }
    out
}

/// An in-memory stream that hands its bytes out a piece at a time (the
/// way a socket delivers segments) and swallows whatever is written.
#[derive(Debug)]
pub(crate) struct PieceStream {
    data: Vec<u8>,
    pos: usize,
    sizes: Vec<usize>,
    next: usize,
}

impl PieceStream {
    pub(crate) fn new(data: Vec<u8>, sizes: Vec<usize>) -> Self {
        Self {
            data,
            pos: 0,
            sizes,
            next: 0,
        }
    }
}

impl tokio::io::AsyncRead for PieceStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = &mut *self;
        let left = this.data.len() - this.pos;
        if left > 0 {
            let size = this.sizes[this.next % this.sizes.len()];
            this.next += 1;
            let n = size.min(left).min(buf.remaining());
            buf.put_slice(&this.data[this.pos..this.pos + n]);
            this.pos += n;
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for PieceStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Run `f` to completion on this thread's runtime (one per thread, built
/// once: a runtime per input would dominate the fuzzer's time).
pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    thread_local! {
        static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a current-thread runtime");
    }
    RUNTIME.with(|rt| rt.block_on(f))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    /// Every committed input for `target`: the seeds the fuzzer starts
    /// from and the inputs that once found a bug.
    fn inputs(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz");
        let mut out = Vec::new();
        for dir in ["seeds", "regressions"] {
            let Ok(entries) = std::fs::read_dir(root.join(dir).join(target)) else {
                continue;
            };
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_file() {
                    let data = std::fs::read(&path).unwrap();
                    out.push((path, data));
                }
            }
        }
        out.sort();
        out
    }

    fn replay(target: &str, run: fn(&[u8])) {
        let inputs = inputs(target);
        assert!(!inputs.is_empty(), "no committed inputs for {target}");
        for (path, data) in inputs {
            let caught = std::panic::catch_unwind(|| run(&data));
            assert!(caught.is_ok(), "{target} fails on {}", path.display());
        }
    }

    #[test]
    fn h1_request_inputs_replay() {
        replay("h1_request", super::h1_request);
    }

    #[test]
    fn h1_response_inputs_replay() {
        replay("h1_response", super::h1_response);
    }

    #[test]
    fn tls_detect_inputs_replay() {
        replay("tls_detect", super::tls_detect);
    }

    #[test]
    fn imap_inputs_replay() {
        replay("imap", super::imap);
    }

    #[test]
    fn smtp_inputs_replay() {
        replay("smtp", super::smtp);
    }

    #[test]
    fn redact_stream_inputs_replay() {
        replay("redact_stream", super::redact_stream);
    }

    #[test]
    fn decode_inputs_replay() {
        replay("decode", super::decode);
    }

    #[test]
    fn config_inputs_replay() {
        replay("config", super::config);
    }
}
