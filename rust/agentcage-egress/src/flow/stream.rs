//! The response side of a streamed flow: Content-Encoding removal,
//! redaction and the capture tee, applied to the body as it arrives.
//!
//! A response is streamed when no rule needs its body whole (see
//! [`Pipeline::stream_plan`](super::Pipeline)): the head gets exactly what
//! the buffered path gives it (the request redacted back for the records,
//! the response headers redacted), then:
//!
//! * nothing to redact and nothing to capture: the body goes on as it
//!   came, chunk by chunk, with its own framing (pure passthrough);
//! * capture only: the body still goes on unchanged; a copy of its first
//!   `max_body_size` decoded bytes is kept for the capture entry;
//! * redaction: the body is decoded (when it has a Content-Encoding) and
//!   redacted by [`StreamRedactor`] — byte for byte what the buffered path
//!   makes of it — and goes on identity-encoded without a length. The
//!   buffered path sends a body identity-encoded only when redaction
//!   rewrote it; a streamed compressed body is always decoded, since
//!   whether a secret is in it is only known at its end.
//!
//! Every piece is bounded: a decoded piece is at most [`PIECE`] bytes, so
//! a compressed chunk that expands a thousandfold goes out in pieces as
//! the client takes them.

use std::sync::Arc;

use bytes::Bytes;

use crate::audit::{self, AuditSink as _, Direction as AuditDirection};
use crate::engine::Engine;
use crate::inject::{SecretForms, StreamRedactor};
use crate::message::{Request, Response};
use crate::proxy::{ResponseStream, StreamOutcome};
use crate::text::stream::{StreamCodec, StreamDecoder};

use agentcage_core::har::datetime::DateTime;

/// The most decoded bytes produced per step.
const PIECE: usize = 64 * 1024;

/// What the capture entry keeps of a streamed body.
#[derive(Debug)]
struct Tee {
    /// The first bytes, up to `limit`.
    kept: Vec<u8>,
    limit: usize,
    total: usize,
    /// For a body forwarded encoded: a decoder for the capture's view,
    /// and the raw bytes to fall back to (the lenient view) if it fails.
    side: Option<SideDecode>,
}

#[derive(Debug)]
struct SideDecode {
    decoder: StreamDecoder,
    raw: Vec<u8>,
    raw_total: usize,
    failed: bool,
}

impl Tee {
    fn keep(kept: &mut Vec<u8>, limit: usize, data: &[u8]) {
        let room = limit.saturating_sub(kept.len());
        kept.extend_from_slice(&data[..room.min(data.len())]);
    }

    /// Record bytes as the client gets them (already decoded unless a
    /// side decoder is set).
    fn record(&mut self, data: &[u8]) {
        let Some(side) = self.side.as_mut() else {
            Self::keep(&mut self.kept, self.limit, data);
            self.total += data.len();
            return;
        };
        Self::keep(&mut side.raw, self.limit, data);
        side.raw_total += data.len();
        if side.failed {
            return;
        }
        let mut rest = data;
        let mut out = Vec::new();
        loop {
            out.clear();
            let Ok(used) = side.decoder.decode(rest, &mut out, PIECE) else {
                side.failed = true;
                return;
            };
            rest = &rest[used..];
            Self::keep(&mut self.kept, self.limit, &out);
            self.total += out.len();
            if out.is_empty() && (rest.is_empty() || used == 0) {
                return;
            }
        }
    }

    /// The kept bytes and the total, at the end of the body.
    fn finish(mut self) -> (Vec<u8>, usize) {
        match self.side.take() {
            None => (self.kept, self.total),
            Some(mut side) => {
                if !side.failed && side.decoder.finish().is_ok() {
                    (self.kept, self.total)
                } else {
                    (side.raw, side.raw_total)
                }
            }
        }
    }
}

/// One streamed response.
pub(super) struct PipelineStream {
    engine: Arc<Engine>,
    flow_id: String,
    direction: AuditDirection,
    /// The request as recorded (redacted back to placeholders), for an
    /// abort's audit record.
    req: Request,
    /// The head as the client gets it, for the capture entry.
    head: Response,
    passthrough: bool,
    decoder: Option<StreamDecoder>,
    redactor: Option<StreamRedactor>,
    tee: Option<Tee>,
    /// The input chunk being worked through, and how far.
    input: Option<(Bytes, usize)>,
    /// Pieces ready for the client.
    ready: std::collections::VecDeque<Bytes>,
    ended: bool,
    /// The decoder and redactor have been flushed after the end.
    flushed: bool,
}

/// How a response is streamed, decided at its head.
pub(super) struct Plan {
    /// Decode this Content-Encoding (redaction needs the decoded body).
    pub(super) decode: Option<StreamCodec>,
    /// Redact with this.
    pub(super) redactor: Option<StreamRedactor>,
    /// Keep this much of the body for the capture entry, decoding it on
    /// the side with this codec when it goes on encoded.
    pub(super) capture: Option<(usize, Option<StreamCodec>)>,
}

impl PipelineStream {
    pub(super) fn new(
        engine: Arc<Engine>,
        flow_id: String,
        direction: AuditDirection,
        req: Request,
        head: Response,
        plan: Plan,
    ) -> Self {
        let passthrough = plan.redactor.is_none() && plan.decode.is_none();
        let tee = plan.capture.map(|(limit, side)| Tee {
            kept: Vec::new(),
            limit,
            total: 0,
            side: side.map(|codec| SideDecode {
                decoder: StreamDecoder::new(codec),
                raw: Vec::new(),
                raw_total: 0,
                failed: false,
            }),
        });
        Self {
            engine,
            flow_id,
            direction,
            req,
            head,
            passthrough,
            decoder: plan.decode.map(StreamDecoder::new),
            redactor: plan.redactor,
            tee,
            input: None,
            ready: std::collections::VecDeque::new(),
            ended: false,
            flushed: false,
        }
    }

    /// Redact (when redacting) one decoded piece into `ready`.
    fn emit(&mut self, piece: Bytes) -> Result<(), String> {
        match self.redactor.as_mut() {
            Some(redactor) => {
                let mut out = Vec::new();
                redactor.push(piece, &mut out).map_err(|e| e.to_string())?;
                self.ready.extend(out.into_iter().filter(|p| !p.is_empty()));
            }
            None if !piece.is_empty() => self.ready.push_back(piece),
            None => {}
        }
        Ok(())
    }

    /// Work through the current input until something is ready or it is
    /// used up.
    fn work(&mut self) -> Result<(), String> {
        while self.ready.is_empty() {
            let Some((chunk, at)) = self.input.take() else {
                return Ok(());
            };
            let Some(decoder) = self.decoder.as_mut() else {
                self.emit(chunk.slice(at..))?;
                continue;
            };
            let mut out = Vec::new();
            let used = decoder
                .decode(&chunk[at..], &mut out, PIECE)
                .map_err(|e| e.to_string())?;
            let at = at + used;
            // Keep the chunk while it has input left, or while the decoder
            // still gives output for it (it may hold some back).
            if at < chunk.len() || !out.is_empty() {
                self.input = Some((chunk, at));
            }
            self.emit(Bytes::from(out))?;
        }
        Ok(())
    }

    /// After the end: drain the decoder, check it is complete, release
    /// what the redactor holds.
    fn flush(&mut self) -> Result<(), String> {
        if let Some(decoder) = self.decoder.as_mut() {
            let mut out = Vec::new();
            decoder
                .decode(&[], &mut out, PIECE)
                .map_err(|e| e.to_string())?;
            if !out.is_empty() {
                return self.emit(Bytes::from(out));
            }
            decoder.finish().map_err(|e| e.to_string())?;
        }
        if let Some(redactor) = self.redactor.as_mut() {
            let mut out = Vec::new();
            redactor.finish(&mut out);
            self.ready.extend(out.into_iter().filter(|p| !p.is_empty()));
        }
        self.flushed = true;
        Ok(())
    }
}

impl ResponseStream for PipelineStream {
    fn passthrough(&self) -> bool {
        self.passthrough
    }

    fn push(&mut self, chunk: Bytes) {
        if !chunk.is_empty() {
            self.input = Some((chunk, 0));
        }
    }

    fn end(&mut self) {
        self.ended = true;
    }

    fn next_out(&mut self) -> Result<Option<Bytes>, String> {
        self.work()?;
        while self.ready.is_empty() && self.ended && self.input.is_none() && !self.flushed {
            self.flush()?;
            self.work()?;
        }
        let piece = self.ready.pop_front();
        if let (Some(piece), Some(tee)) = (&piece, self.tee.as_mut()) {
            tee.record(piece);
        }
        Ok(piece)
    }

    fn held(&self) -> usize {
        self.redactor.as_ref().map_or(0, StreamRedactor::held)
            + self.tee.as_ref().map_or(0, |t| t.kept.capacity())
    }

    fn close(self: Box<Self>, outcome: StreamOutcome) {
        let engine = &self.engine;
        match outcome {
            StreamOutcome::Completed => match self.tee {
                Some(tee) => {
                    let (kept, total) = tee.finish();
                    engine.capture.finish_streamed_response(
                        &self.flow_id,
                        &self.head,
                        &kept,
                        total,
                    );
                }
                None => engine.capture.release(&self.flow_id),
            },
            StreamOutcome::UpstreamFailed(reason) | StreamOutcome::Refused(reason) => {
                engine.capture.release(&self.flow_id);
                engine.audit.emit(audit::upstream_error(
                    DateTime::now_utc(),
                    &self.req,
                    self.direction,
                    &reason,
                ));
            }
            StreamOutcome::ClientGone => engine.capture.release(&self.flow_id),
        }
    }
}

/// Redact the response head with `forms`, as the buffered path redacts
/// headers.
pub(super) fn redact_head(head: &mut Response, forms: &[Arc<SecretForms>]) {
    let _ = crate::inject::Injector::redact_headers_with(&mut head.headers, forms);
}
