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
//! recording sink. [`AuditWriter`] is the real sink; [`records`] builds
//! the record kinds the request pipeline emits, field for field and in
//! the order the replaced implementation wrote them; [`WatcherRing`] is
//! the bounded buffer the watcher drains.

pub mod records;
mod ring;
mod writer;

pub use records::{
    Decision, Direction, HttpDecision, config_reload_failed, inspectors_json, log_allowed,
    private_peer_blocked, relay_failure, tcp_bypass_blocked, tcp_bypass_target, upstream_error,
};
pub use ring::{Drained, RING_MAX, WatcherRing};
pub use writer::{AUDIT_CAP_BYTES, AuditWriter, DEFAULT_AUDIT_LOG};

use crate::json::Json;

/// Somewhere audit records go.
///
/// `emit` takes the record as an insertion-ordered JSON object, with the
/// fields in the order the record kind defines; the sink adds nothing but
/// redaction (and a trailing `ts` when the producer left it out).
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    /// Record one entry on every sink.
    fn emit(&self, entry: Json);

    /// Record one entry for the traffic watcher only, never on the
    /// durable sinks (stderr, `audit.jsonl`).
    ///
    /// This is where a plain allowed request goes while
    /// `logging.allowed_requests` is off: the operator chose not to keep
    /// it, but exfiltration and beacons live in allowed traffic, so the
    /// watcher must still see it (see [`HttpDecision::emit`]). A sink
    /// without a watcher drops it, which is the default.
    fn emit_ring_only(&self, entry: Json) {
        let _ = entry;
    }
}

/// Swaps every secret in an audit record for its rule's placeholder.
///
/// Implemented by the secret injector, which knows the live rules and
/// minted tokens: in each string value at any depth (object keys are left
/// alone), each rule's real value and each live minted token, in every
/// encoded form the injector matches, becomes the rule's placeholder.
/// Every audit record and every capture `inspectors` list passes through
/// it before reaching a sink.
pub trait Redactor: Send + Sync + std::fmt::Debug {
    /// Redact `entry` in place.
    fn redact(&self, entry: &mut Json);
}

/// A [`Redactor`] with nothing to redact: no injection rules.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRedaction;

impl Redactor for NoRedaction {
    fn redact(&self, _entry: &mut Json) {}
}

/// A sink that keeps every record in memory, for tests.
#[derive(Debug, Default)]
pub struct MemorySink {
    entries: std::sync::Mutex<Vec<Json>>,
    ring_only: std::sync::Mutex<Vec<Json>>,
}

impl MemorySink {
    /// Everything emitted to every sink so far, in order.
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

    /// Everything emitted to the watcher only so far, in order.
    ///
    /// # Panics
    ///
    /// The lock was poisoned by a panicking emitter.
    #[must_use]
    pub fn ring_only(&self) -> Vec<Json> {
        self.ring_only
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

    fn emit_ring_only(&self, entry: Json) {
        self.ring_only
            .lock()
            .expect("audit memory sink poisoned")
            .push(entry);
    }
}

#[cfg(test)]
mod corpus;
#[cfg(test)]
pub(crate) mod testutil;
