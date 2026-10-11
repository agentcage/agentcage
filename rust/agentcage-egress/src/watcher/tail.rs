//! The incremental tail of `capture.jsonl`.
//!
//! Torn-tail safe, rotation safe and chunked:
//!
//! * bytes are read raw and the offset only advances past lines that end
//!   in a newline, so an in-flight write's partial last line is re-read
//!   whole next time. A line still unterminated past the line cap is not
//!   in flight but oversized; it is dropped (one lost sample) so it cannot
//!   stall the tail forever;
//! * the file is identified by `(st_dev, st_ino)` as well as its size:
//!   rotation to a same-sized file is an identity change, truncation is a
//!   size below the offset, and either resets to offset 0 — a full-file
//!   scan filtered to the window. The filter stays armed for every tick
//!   needed to catch up to the size seen at the reset, not just the first
//!   chunk;
//! * at most one chunk is read per tick (more only to chase a single line
//!   longer than a chunk), and a tail that has fallen more than
//!   [`TailLimits::max_catchup`] behind jumps to the live end and reports
//!   the skipped span rather than analysing ever-staler traffic.
//!
//! A read only *stages* the new offset. [`CaptureTail::commit`] applies it
//! once the scan that consumed the samples succeeded, so a failed scan
//! re-reads the same bytes and no evidence is lost to an LLM hiccup.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::PathBuf;

use agentcage_core::har::datetime::DateTime;

use crate::json::{self, Json};

use super::ScanRng;
use super::config::CAP_READ_CHUNK;
use super::pyval;
use super::sample::sample_capture;

/// How far the tail may fall behind before it skips to the live end: a
/// body-heavy cage writes faster than one chunk per interval is read.
pub const MAX_CATCHUP_BYTES: u64 = 16 * CAP_READ_CHUNK;

/// The sizes the tail works with. Fixed in production; tests shrink them
/// to exercise chunking on small files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailLimits {
    /// Bytes read per tick.
    pub chunk: u64,
    /// Lag past which the tail skips ahead.
    pub max_catchup: u64,
    /// Longest line waited for (see `WatcherConfig::line_cap`).
    pub line_cap: u64,
}

impl TailLimits {
    /// The production chunk and catch-up bounds with `line_cap`.
    #[must_use]
    pub fn new(line_cap: u64) -> Self {
        Self {
            chunk: CAP_READ_CHUNK,
            max_catchup: MAX_CATCHUP_BYTES,
            line_cap,
        }
    }
}

/// `(st_dev, st_ino)`.
pub type FileId = (u64, u64);

/// One read's result, staged until [`CaptureTail::commit`].
#[derive(Clone, Debug, PartialEq)]
pub struct TailRead {
    /// Samples from the complete lines read, newest `max_flows` kept.
    pub samples: Vec<Json>,
    /// The offset just past the last complete line consumed.
    pub offset: u64,
    /// The identity of the file that was read.
    pub file_id: FileId,
    /// Bytes skipped by a catch-up jump on this read.
    pub skipped: u64,
}

/// The tail's cursor over one capture path.
#[derive(Clone, Debug)]
pub struct CaptureTail {
    path: Option<PathBuf>,
    limits: TailLimits,
    offset: Option<u64>,
    file_id: Option<FileId>,
    // The size a reset needs to catch up to before the window filter can
    // stop applying; `None` when no reset is in flight.
    reset_target: Option<u64>,
    // Bytes skipped by the latest read, kept between reads as the
    // replaced implementation did (a read of a missing file leaves it).
    skipped: u64,
}

impl CaptureTail {
    /// A tail over `path` (`None`: capture is off, every read is empty).
    #[must_use]
    pub fn new(path: Option<PathBuf>, limits: TailLimits) -> Self {
        Self {
            path: path.filter(|p| !p.as_os_str().is_empty()),
            limits,
            offset: None,
            file_id: None,
            reset_target: None,
            skipped: 0,
        }
    }

    /// The capture path, if any.
    #[must_use]
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    /// The committed offset (`None` before the first commit).
    #[must_use]
    pub fn offset(&self) -> Option<u64> {
        self.offset
    }

    /// Change the limits (a reload's new line cap), keeping the cursor.
    pub fn set_limits(&mut self, limits: TailLimits) {
        self.limits = limits;
    }

    fn unchanged(&self) -> TailRead {
        TailRead {
            samples: Vec::new(),
            offset: self.offset.unwrap_or(0),
            file_id: self.file_id.unwrap_or((0, 0)),
            skipped: self.skipped,
        }
    }

    /// Read new complete lines into samples, staging the new offset.
    ///
    /// `window_seconds` filters a reset scan; `max_flows` caps the
    /// samples; `warn` receives the operator-facing warnings.
    pub fn read(
        &mut self,
        now: DateTime,
        window_seconds: f64,
        max_flows: usize,
        mut rng: Option<&mut ScanRng>,
        warn: &mut dyn FnMut(&str),
    ) -> TailRead {
        let Some(path) = self.path.clone() else {
            return self.unchanged();
        };
        let meta = match std::fs::metadata(&path) {
            Ok(m) if m.is_file() => m,
            _ => return self.unchanged(),
        };
        let size = meta.len();
        let file_id = file_id(&meta);
        let mut offset = match self.offset {
            Some(o) if Some(file_id) == self.file_id && o <= size => o,
            _ => {
                self.reset_target = Some(size);
                0
            }
        };
        self.skipped = 0;
        if size - offset > self.limits.max_catchup {
            let target = size.saturating_sub(self.limits.chunk);
            self.skipped = target - offset;
            offset = target;
            // The skipped span is unanalysed, so the window filter means
            // nothing for it: land in incremental mode.
            self.reset_target = None;
        }
        let apply_filter = self.reset_target.is_some_and(|t| offset < t);
        let staged = |samples, offset, skipped| TailRead {
            samples,
            offset,
            file_id,
            skipped,
        };
        let chunk = (size - offset).min(self.limits.chunk);
        if chunk == 0 {
            return staged(Vec::new(), offset, self.skipped);
        }
        let data = match read_chunk(&path, offset, chunk, size, self.limits) {
            Ok(d) => d,
            Err(e) => {
                warn(&format!("agentcage: watcher cannot read capture: {e}"));
                return self.unchanged();
            }
        };
        if data.is_empty() {
            return staged(Vec::new(), offset, self.skipped);
        }
        let mut lines: Vec<&[u8]> = data.split(|b| *b == b'\n').collect();
        let mut partial_len = 0;
        if !data.ends_with(b"\n") {
            let partial = lines.pop().unwrap_or_default();
            if partial.len() as u64 >= self.limits.line_cap {
                // Oversized, not in flight. Measured on the line, never on
                // the whole read: a backlog larger than the cap ends its
                // read mid-line, and testing the read dropped one complete
                // entry per chunk boundary.
                warn(&format!(
                    "agentcage: watcher dropping oversized capture line (>{} bytes, no newline found)",
                    self.limits.line_cap
                ));
            } else {
                partial_len = partial.len();
            }
        }
        let new_offset = offset + (data.len() - partial_len) as u64;
        let cutoff = cutoff(now, window_seconds);
        let mut samples = Vec::new();
        for raw in lines {
            if raw.trim_ascii().is_empty() {
                continue;
            }
            let Ok(entry) = json::parse(&String::from_utf8_lossy(raw)) else {
                continue; // corrupt line: skipped, still consumed
            };
            if !matches!(entry, Json::Object(_)) {
                continue;
            }
            if apply_filter && !in_window(&entry, cutoff) {
                continue;
            }
            samples.push(sample_capture(&entry, "", rng.as_deref_mut()));
        }
        if samples.len() > max_flows {
            samples.drain(..samples.len() - max_flows);
        }
        staged(samples, new_offset, self.skipped)
    }

    /// Commit a successful scan's staged position, retiring the reset
    /// target once the committed offset has caught up to it — the filter
    /// must stay armed until those bytes were analysed, not merely read.
    pub fn commit(&mut self, read: &TailRead) {
        self.offset = Some(read.offset);
        self.file_id = Some(read.file_id);
        if self.reset_target.is_some_and(|t| read.offset >= t) {
            self.reset_target = None;
        }
    }
}

#[cfg(unix)]
fn file_id(meta: &std::fs::Metadata) -> FileId {
    use std::os::unix::fs::MetadataExt as _;
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
fn file_id(_meta: &std::fs::Metadata) -> FileId {
    (0, 0)
}

/// One chunk from `offset`, extended past the chunk bound only while it
/// holds no complete line at all — a single line longer than a chunk —
/// and never past the line cap.
fn read_chunk(
    path: &std::path::Path,
    offset: u64,
    chunk: u64,
    size: u64,
    limits: TailLimits,
) -> std::io::Result<Vec<u8>> {
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut data = Vec::new();
    (&mut f).take(chunk).read_to_end(&mut data)?;
    while !data.is_empty()
        && !data.contains(&b'\n')
        && offset + (data.len() as u64) < size
        && (data.len() as u64) < limits.line_cap
    {
        let want = limits.chunk.min(size - offset - data.len() as u64);
        let before = data.len();
        (&mut f).take(want).read_to_end(&mut data)?;
        if data.len() == before {
            break;
        }
    }
    Ok(data)
}

/// `now - timedelta(seconds=window)`, microsecond-exact like `timedelta`.
fn cutoff(now: DateTime, window_seconds: f64) -> Option<DateTime> {
    #[allow(clippy::cast_possible_truncation)]
    let micros = (window_seconds * 1e6).round_ties_even() as i64;
    now.checked_sub_micros(micros)
}

/// A reset scan keeps an entry only when its `ts` parses (naive read as
/// UTC) and is not before the cutoff.
fn in_window(entry: &Json, cutoff: Option<DateTime>) -> bool {
    let Some(ts) = pyval::truthy(entry.get("ts")) else {
        return false;
    };
    let Some(dt) = DateTime::from_isoformat(&pyval::py_str(ts)) else {
        return false;
    };
    match cutoff {
        Some(c) => dt.assume_utc().lt(&c) == Some(false),
        None => true,
    }
}
