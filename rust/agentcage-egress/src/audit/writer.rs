//! The real audit sink: stderr, `audit.jsonl` (capped) and the watcher
//! ring, every record redacted first.

use std::fs::{File, OpenOptions};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use agentcage_core::har::datetime::DateTime;

use super::{AuditSink, NoRedaction, Redactor, WatcherRing};
use crate::json::{self, Json};

/// Where `audit.jsonl` goes when `AGENTCAGE_AUDIT_LOG` is unset.
pub const DEFAULT_AUDIT_LOG: &str = "/var/log/agentcage/audit.jsonl";

/// The hard cap on `audit.jsonl`.
///
/// The caged agent can reach the control endpoints (introspection is
/// unauthenticated by design) and every request writes a record, so an
/// uncapped file is a disk-fill vector against the egress container. Past
/// the cap records still go to stderr (journald rotates its own) and the
/// file is left alone.
pub const AUDIT_CAP_BYTES: u64 = 16 * 1024 * 1024;

struct AuditFile {
    file: File,
    capped: bool,
}

/// The audit funnel every producer writes through.
///
/// One line per record, `json.dumps` byte for byte, to stderr always, to
/// `audit.jsonl` until [`AUDIT_CAP_BYTES`], and into the watcher ring
/// while the watcher is enabled. Every record is redacted through the
/// installed [`Redactor`] before any of the three sees it: stderr ends up
/// in the host's journal and `audit.jsonl` stays on disk, so neither may
/// hold a value the egress injects, and the watcher sends what it scans to
/// an LLM.
pub struct AuditWriter {
    redactor: RwLock<Arc<dyn Redactor>>,
    stderr: Mutex<Box<dyn Write + Send>>,
    file: Mutex<Option<AuditFile>>,
    ring: RwLock<Option<Arc<WatcherRing>>>,
    clock: fn() -> DateTime,
    cap: u64,
}

impl std::fmt::Debug for AuditWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditWriter")
            .field("file", &self.lock_file().is_some())
            .field("ring", &self.ring().is_some())
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

impl AuditWriter {
    /// A writer for `$AGENTCAGE_AUDIT_LOG` (default
    /// [`DEFAULT_AUDIT_LOG`]); an empty value means stderr only.
    #[must_use]
    pub fn from_env() -> Self {
        let path = std::env::var_os("AGENTCAGE_AUDIT_LOG")
            .map_or_else(|| PathBuf::from(DEFAULT_AUDIT_LOG), PathBuf::from);
        if path.as_os_str().is_empty() {
            Self::new(None)
        } else {
            Self::new(Some(&path))
        }
    }

    /// A writer appending to `path` (its directory created if missing),
    /// or stderr only for `None`.
    ///
    /// A file that cannot be opened is reported on stderr and left out:
    /// the records still reach stderr, which is the primary contract.
    #[must_use]
    pub fn new(path: Option<&Path>) -> Self {
        let file = path.and_then(|path| match open_append(path) {
            Ok(file) => Some(AuditFile {
                file,
                capped: false,
            }),
            Err(e) => {
                log(&format!(
                    "agentcage: cannot open audit log {}: {e}",
                    path.display()
                ));
                None
            }
        });
        Self {
            redactor: RwLock::new(Arc::new(NoRedaction)),
            stderr: Mutex::new(Box::new(std::io::stderr())),
            file: Mutex::new(file),
            ring: RwLock::new(None),
            clock: DateTime::now_utc,
            cap: AUDIT_CAP_BYTES,
        }
    }

    /// Send the stderr copy of every line to `out` instead (tests and the
    /// scenario harness).
    #[must_use]
    pub fn with_stderr(mut self, out: Box<dyn Write + Send>) -> Self {
        self.stderr = Mutex::new(out);
        self
    }

    /// Stamp records that arrive without a `ts` from `clock` instead of
    /// the system clock.
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> DateTime) -> Self {
        self.clock = clock;
        self
    }

    /// Cap `audit.jsonl` at `cap` bytes instead of [`AUDIT_CAP_BYTES`].
    #[must_use]
    pub fn with_cap(mut self, cap: u64) -> Self {
        self.cap = cap;
        self
    }

    /// Redact every record through `redactor` from now on. Called on
    /// load and on every reload, when the injection rules change.
    pub fn set_redactor(&self, redactor: Arc<dyn Redactor>) {
        *self
            .redactor
            .write()
            .unwrap_or_else(PoisonError::into_inner) = redactor;
    }

    /// Start copying records into the watcher ring, creating it if there
    /// is none, and return it.
    ///
    /// An existing ring is kept: a watcher rebuilt by a reload (a new
    /// interval or model) must not drop the fresh-traffic history the old
    /// one was holding.
    pub fn enable_ring(&self) -> Arc<WatcherRing> {
        let mut ring = self.ring.write().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(ring.get_or_insert_with(|| Arc::new(WatcherRing::new())))
    }

    /// Stop copying records into the watcher ring and drop it (the
    /// watcher was disabled).
    pub fn disable_ring(&self) {
        *self.ring.write().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// The watcher ring, while the watcher is enabled.
    #[must_use]
    pub fn ring(&self) -> Option<Arc<WatcherRing>> {
        self.ring
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn lock_file(&self) -> std::sync::MutexGuard<'_, Option<AuditFile>> {
        self.file.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn redact(&self, entry: &mut Json) {
        let redactor = Arc::clone(&self.redactor.read().unwrap_or_else(PoisonError::into_inner));
        redactor.redact(entry);
    }

    fn ring_ingest(&self, entry: &Json) {
        if let Some(ring) = self.ring() {
            ring.push(entry.clone());
        }
    }

    /// Write one record to every sink.
    ///
    /// The record is redacted first; a record without `ts` gets one
    /// appended (after its own fields, where the replaced implementation
    /// put it). The file write is skipped once the file has passed the
    /// cap, checked before each write, so the file can overrun the cap by
    /// at most one line; the file then stays capped for the life of the
    /// process.
    pub fn write(&self, mut entry: Json) {
        self.redact(&mut entry);
        if entry.get("ts").is_none() {
            entry.set("ts", Json::string((self.clock)().isoformat()));
        }
        self.ring_ingest(&entry);
        let mut line = json::to_string(&entry);
        line.push('\n');
        {
            let mut stderr = self.stderr.lock().unwrap_or_else(PoisonError::into_inner);
            // One write per line so concurrent records never interleave;
            // a failed stderr write has nowhere else to be reported.
            let _ = stderr.write_all(line.as_bytes());
            let _ = stderr.flush();
        }
        let mut file = self.lock_file();
        let Some(audit) = file.as_mut() else {
            return;
        };
        if !audit.capped && audit.file.stream_position().is_ok_and(|pos| pos > self.cap) {
            audit.capped = true;
            log(&format!(
                "agentcage: audit log at cap ({} bytes); file writes suspended \
                 (stderr only) — rotate the file to resume",
                self.cap
            ));
        }
        if !audit.capped {
            let _ = audit.file.write_all(line.as_bytes());
            let _ = audit.file.flush();
        }
    }

    /// Redact one record and copy it into the watcher ring only.
    pub fn write_ring_only(&self, mut entry: Json) {
        self.redact(&mut entry);
        self.ring_ingest(&entry);
    }
}

impl AuditSink for AuditWriter {
    fn emit(&self, entry: Json) {
        self.write(entry);
    }

    fn emit_ring_only(&self, entry: Json) {
        self.write_ring_only(entry);
    }
}

fn open_append(path: &Path) -> std::io::Result<File> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    // Position at the end now, so the cap check sees the existing size
    // before the first write (an append-mode file starts at offset 0
    // until something is written).
    file.seek(std::io::SeekFrom::End(0))?;
    Ok(file)
}

/// An operator-facing diagnostic: a plain (non-JSON) stderr line, which
/// the host's audit reader skips.
fn log(message: &str) {
    eprintln!("{message}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testutil::{Scratch, SharedBuf};
    use crate::json::object;

    fn fixed() -> DateTime {
        DateTime::from_parts((2026, 10, 10), (1, 2, 3, 0), Some(0)).unwrap()
    }

    fn entry(n: i64) -> Json {
        object([("kind", Json::string("relay_x")), ("n", Json::Int(n))])
    }

    #[test]
    fn a_record_without_ts_gets_one_appended_on_every_sink() {
        let dir = Scratch::new("audit-ts");
        let path = dir.0.join("sub/audit.jsonl");
        let out = SharedBuf::default();
        let w = AuditWriter::new(Some(&path))
            .with_stderr(Box::new(out.clone()))
            .with_clock(fixed);
        let ring = w.enable_ring();
        w.write(entry(1));
        let want = r#"{"kind": "relay_x", "n": 1, "ts": "2026-10-10T01:02:03+00:00"}"#;
        assert_eq!(out.lines(), [want]);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), format!("{want}\n"));
        assert_eq!(json::to_string(&ring.snapshot()[0]), want);
    }

    #[test]
    fn the_file_caps_past_the_limit_but_stderr_keeps_going() {
        let dir = Scratch::new("audit-cap");
        let path = dir.0.join("audit.jsonl");
        let out = SharedBuf::default();
        let w = AuditWriter::new(Some(&path))
            .with_stderr(Box::new(out.clone()))
            .with_clock(fixed)
            .with_cap(100);
        for n in 0..5 {
            w.write(entry(n));
        }
        // Each line is 63 bytes: the check runs before each write and
        // trips once the position is past 100, so two lines land (the
        // second overrunning the cap) and the rest are stderr only.
        let file = std::fs::read_to_string(&path).unwrap();
        assert_eq!(file.lines().count(), 2, "{file}");
        assert_eq!(out.lines().len(), 5);
        // Truncating the file does not resume writes: capped stays capped.
        std::fs::write(&path, "").unwrap();
        w.write(entry(9));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    #[test]
    fn an_existing_file_counts_toward_the_cap() {
        let dir = Scratch::new("audit-existing");
        let path = dir.0.join("audit.jsonl");
        std::fs::write(&path, "x".repeat(200)).unwrap();
        let w = AuditWriter::new(Some(&path))
            .with_stderr(Box::new(SharedBuf::default()))
            .with_cap(100);
        w.write(entry(1));
        assert_eq!(std::fs::read_to_string(&path).unwrap().len(), 200);
    }

    #[test]
    fn an_unopenable_file_degrades_to_stderr_only() {
        let dir = Scratch::new("audit-bad");
        let blocker = dir.0.join("file");
        std::fs::write(&blocker, "").unwrap();
        let out = SharedBuf::default();
        let w = AuditWriter::new(Some(&blocker.join("audit.jsonl")))
            .with_stderr(Box::new(out.clone()))
            .with_clock(fixed);
        w.write(entry(1));
        assert_eq!(out.lines().len(), 1);
    }

    #[derive(Debug)]
    struct Upper;
    impl Redactor for Upper {
        fn redact(&self, entry: &mut Json) {
            if let Json::Object(pairs) = entry {
                for (_, v) in pairs {
                    if let Json::Str(s) = v {
                        *s = s.to_uppercase();
                    }
                }
            }
        }
    }

    #[test]
    fn redaction_runs_before_ts_and_before_every_sink_including_ring_only() {
        let out = SharedBuf::default();
        let w = AuditWriter::new(None)
            .with_stderr(Box::new(out.clone()))
            .with_clock(fixed);
        w.set_redactor(Arc::new(Upper));
        let ring = w.enable_ring();
        w.write(object([("kind", Json::string("x"))]));
        w.write_ring_only(object([("host", Json::string("a.example"))]));
        // The ts was added after redaction (not upper-cased).
        assert_eq!(
            out.lines(),
            [r#"{"kind": "X", "ts": "2026-10-10T01:02:03+00:00"}"#]
        );
        let ring = ring.snapshot();
        assert_eq!(ring.len(), 2);
        assert_eq!(json::to_string(&ring[1]), r#"{"host": "A.EXAMPLE"}"#);
    }

    #[test]
    fn the_ring_survives_re_enabling_and_goes_away_when_disabled() {
        let w = AuditWriter::new(None).with_stderr(Box::new(SharedBuf::default()));
        assert!(w.ring().is_none());
        w.write(entry(1));
        let ring = w.enable_ring();
        w.write(entry(2));
        assert!(Arc::ptr_eq(&ring, &w.enable_ring()));
        assert_eq!(ring.len(), 1);
        w.disable_ring();
        assert!(w.ring().is_none());
        w.write(entry(3));
        assert_eq!(ring.len(), 1);
    }
}
