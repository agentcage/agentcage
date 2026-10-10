//! Audit records.
//!
//! Every decision the egress makes is one JSON line. The line goes to
//! stderr (the host reads it back through journald or `podman logs`; that
//! is the primary contract), to `/var/log/agentcage/audit.jsonl` until it
//! reaches 16 MiB (apple-container reads this one), and to the traffic
//! watcher's in-memory ring. Every record of every kind is redacted
//! before it reaches any sink: a real secret value or a live minted token
//! anywhere in it becomes the rule's placeholder.
//!
//! Producers (the request pipeline, the Policy API, the relays, the
//! watcher) depend only on [`AuditSink`], so each can be tested with a
//! recording sink.

use crate::json::Json;

/// Somewhere audit records go.
///
/// `emit` takes the record as an insertion-ordered JSON object, with the
/// fields in the order the record kind defines; the sink adds nothing but
/// redaction.
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    /// Record one entry.
    fn emit(&self, entry: Json);
}

/// A sink that keeps every record in memory, for tests.
#[derive(Debug, Default)]
pub struct MemorySink {
    entries: std::sync::Mutex<Vec<Json>>,
}

impl MemorySink {
    /// Everything emitted so far, in order.
    ///
    /// # Panics
    ///
    /// The lock was poisoned by a panicking emitter.
    #[must_use]
    pub fn entries(&self) -> Vec<Json> {
        self.entries
            .lock()
            .expect("audit memory sink poisoned")
            .clone()
    }
}

impl AuditSink for MemorySink {
    fn emit(&self, entry: Json) {
        self.entries
            .lock()
            .expect("audit memory sink poisoned")
            .push(entry);
    }
}
