//! The traffic watcher's audit ring.
//!
//! Every audit record (including allowed requests the durable log
//! suppresses) is copied here while the watcher is enabled, and the
//! watcher drains it each scan. It only has to bridge scan intervals plus
//! a failed scan's retry backlog (`capture.jsonl` carries the durable
//! history), so it is bounded: the oldest entry is evicted silently when
//! it is full.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use crate::json::Json;

/// The ring's bound.
pub const RING_MAX: usize = 5000;

/// The bounded, ingestion-ordered buffer of audit records the watcher
/// scans.
#[derive(Debug)]
pub struct WatcherRing {
    entries: Mutex<VecDeque<Json>>,
    capacity: usize,
}

/// One drain's result.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Drained {
    /// The drained records, oldest first, without the watcher's own.
    pub entries: Vec<Json>,
    /// Whether the ring was at its bound before the drain: entries were
    /// very likely evicted unseen, by a busy cage or by chaff pushed
    /// through to age evidence out. The watcher reports it as an evasion
    /// indicator.
    pub saturated: bool,
}

impl Default for WatcherRing {
    fn default() -> Self {
        Self::new()
    }
}

impl WatcherRing {
    /// An empty ring bounded at [`RING_MAX`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(RING_MAX)
    }

    /// An empty ring bounded at `capacity`.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(capacity.min(RING_MAX))),
            capacity,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<Json>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The bound.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many records are buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether nothing is buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// A copy of the buffered records, oldest first.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Json> {
        self.lock().iter().cloned().collect()
    }

    /// Append one record, evicting the oldest when full.
    pub fn push(&self, entry: Json) {
        if self.capacity == 0 {
            return;
        }
        let mut entries = self.lock();
        while entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Take up to `max` records from the front, in ingestion order.
    ///
    /// Records whose `kind` starts with `watcher_` are consumed and
    /// discarded, not counted: feeding the watcher's own audit back to it
    /// would let one failed scan's noise become the next scan's evidence.
    /// Ingestion order rather than a timestamp cursor means a
    /// future-dated record can never hide real traffic, and an
    /// unparseable timestamp is consumed exactly once.
    pub fn drain(&self, max: usize) -> Drained {
        let mut entries = self.lock();
        let saturated = !entries.is_empty() && entries.len() >= self.capacity;
        let mut out = Vec::new();
        while out.len() < max {
            let Some(entry) = entries.pop_front() else {
                break;
            };
            let own = entry
                .get("kind")
                .and_then(Json::as_str)
                .is_some_and(|k| k.starts_with("watcher_"));
            if !own {
                out.push(entry);
            }
        }
        Drained {
            entries: out,
            saturated,
        }
    }

    /// Return a failed scan's drained batch to the front, in its original
    /// order.
    ///
    /// The batch is older than anything still buffered, so when there is
    /// not room for all of it, it is trimmed to the room left, keeping its
    /// own most recent tail: live traffic that arrived during the failed
    /// scan is never displaced by the stale retry.
    pub fn push_back(&self, batch: Vec<Json>) {
        let mut entries = self.lock();
        let room = self.capacity.saturating_sub(entries.len());
        if room == 0 {
            return;
        }
        let skip = batch.len().saturating_sub(room);
        for entry in batch.into_iter().skip(skip).rev() {
            entries.push_front(entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::object;

    fn named(n: &str) -> Json {
        object([("n", Json::string(n))])
    }

    fn names(ring: &WatcherRing) -> Vec<String> {
        ring.snapshot()
            .iter()
            .map(|e| e.get("n").and_then(Json::as_str).unwrap_or("").to_owned())
            .collect()
    }

    #[test]
    fn push_evicts_the_oldest_at_the_bound() {
        let ring = WatcherRing::with_capacity(3);
        for n in ["a", "b", "c", "d"] {
            ring.push(named(n));
        }
        assert_eq!(names(&ring), ["b", "c", "d"]);
        assert_eq!(WatcherRing::new().capacity(), 5000);
    }

    #[test]
    fn drain_is_bounded_ordered_skips_own_records_and_reports_saturation() {
        let ring = WatcherRing::with_capacity(4);
        ring.push(named("a"));
        ring.push(object([("kind", Json::string("watcher_scan"))]));
        ring.push(named("b"));
        ring.push(named("c"));
        let drained = ring.drain(2);
        assert!(drained.saturated);
        assert_eq!(drained.entries, vec![named("a"), named("b")]);
        assert_eq!(names(&ring), ["c"]);
        let drained = ring.drain(10);
        assert!(!drained.saturated);
        assert_eq!(drained.entries, vec![named("c")]);
        assert!(!ring.drain(10).saturated, "an empty ring is not saturated");
    }

    #[test]
    fn push_back_keeps_the_newest_live_entries_over_the_stale_batch() {
        let ring = WatcherRing::with_capacity(5);
        for n in ["live-1", "live-2", "live-3"] {
            ring.push(named(n));
        }
        ring.push_back(["old-1", "old-2", "old-3", "old-4"].map(named).to_vec());
        assert_eq!(
            names(&ring),
            ["old-3", "old-4", "live-1", "live-2", "live-3"]
        );
    }

    #[test]
    fn push_back_is_a_noop_when_full_of_live_entries() {
        let ring = WatcherRing::with_capacity(3);
        for n in ["live-1", "live-2", "live-3"] {
            ring.push(named(n));
        }
        ring.push_back(vec![named("old-1")]);
        assert_eq!(names(&ring), ["live-1", "live-2", "live-3"]);
    }
}
