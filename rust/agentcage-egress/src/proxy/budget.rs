//! A process-wide budget for buffered body bytes.
//!
//! Bodies are buffered whole (plan D6), and the per-body cap
//! ([`super::TransportSettings::max_body`]) alone does not bound the
//! process: a handful of concurrent large bodies, each under the cap, can
//! together exhaust the address space the supervisor allows (`prlimit
//! --as`), and a failed allocation aborts the whole egress — every
//! connection of the cage with it. Every buffered body therefore holds a
//! [`Reservation`] against one shared [`BodyBudget`], grown as the body
//! grows and released when the reservation drops (when the exchange's
//! buffers are gone). A body that would take the total past the limit
//! waits up to [`WAIT`] for other flows to release theirs, then is
//! refused: fail closed, one flow, with a 503.
//!
//! The first [`FREE_BYTES`] of each body are counted but never refused,
//! so ordinary small requests keep working while large transfers have
//! the budget exhausted.
//!
//! A reader that does not buffer whole can reserve per chunk with
//! [`Reservation::reserve_more`] and give bytes back with
//! [`Reservation::shrink_to`] once it has passed them on.

use std::collections::TryReserveError;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

/// The default budget: 1 GiB of buffered body bytes in flight.
pub const DEFAULT_BODY_BUDGET: usize = 1024 * 1024 * 1024;

/// Bytes of each body that are never refused.
pub(crate) const FREE_BYTES: usize = 1024 * 1024;

/// How long a body over budget waits for other flows to release theirs
/// before it is refused.
pub(crate) const WAIT: Duration = Duration::from_secs(2);

/// The shared counter.
#[derive(Debug)]
pub(crate) struct BodyBudget {
    used: AtomicUsize,
    limit: usize,
    /// Woken whenever bytes are released, for reservations waiting.
    released: Notify,
    wait: Duration,
}

impl BodyBudget {
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Self::with_wait(limit, WAIT)
    }

    pub(crate) fn with_wait(limit: usize, wait: Duration) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicUsize::new(0),
            limit,
            released: Notify::new(),
            wait,
        })
    }

    /// The configured limit.
    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// Bytes currently reserved (tests, diagnostics).
    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    fn release(&self, n: usize) {
        if n > 0 {
            self.used.fetch_sub(n, Ordering::AcqRel);
            self.released.notify_waiters();
        }
    }
}

/// What one body holds against the budget; released on drop.
#[derive(Debug)]
pub(crate) struct Reservation {
    budget: Arc<BodyBudget>,
    held: usize,
}

impl Reservation {
    pub(crate) fn new(budget: &Arc<BodyBudget>) -> Self {
        Self {
            budget: Arc::clone(budget),
            held: 0,
        }
    }

    /// The budget's limit.
    pub(crate) fn limit(&self) -> usize {
        self.budget.limit
    }

    /// Grow the reservation to `total` bytes now, without waiting;
    /// `false` (nothing changed) when that would exceed the budget.
    pub(crate) fn try_grow_to(&mut self, total: usize) -> bool {
        if total <= self.held {
            return true;
        }
        let extra = total - self.held;
        if total <= FREE_BYTES {
            self.budget.used.fetch_add(extra, Ordering::AcqRel);
            self.held = total;
            return true;
        }
        let limit = self.budget.limit;
        let used = &self.budget.used;
        let mut current = used.load(Ordering::Acquire);
        let granted = loop {
            let Some(next) = current.checked_add(extra).filter(|&next| next <= limit) else {
                break false;
            };
            match used.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break true,
                Err(seen) => current = seen,
            }
        };
        if granted {
            self.held = total;
        }
        granted
    }

    /// Grow the reservation to `total` bytes, waiting up to the budget's
    /// bounded wait for other flows to release bytes; `false` (nothing
    /// changed) when it still does not fit.
    pub(crate) async fn grow_to(&mut self, total: usize) -> bool {
        if self.try_grow_to(total) {
            return true;
        }
        // More than the whole budget never fits: refuse at once.
        if total > self.budget.limit.max(FREE_BYTES) {
            return false;
        }
        let budget = Arc::clone(&self.budget);
        let deadline = tokio::time::Instant::now() + budget.wait;
        loop {
            // Registered before the re-check, so a release between the
            // check and the wait is not missed.
            let notified = budget.released.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.try_grow_to(total) {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.try_grow_to(total);
            }
        }
    }

    /// Reserve `n` more bytes (a streaming reader, per chunk).
    #[allow(dead_code)] // The streaming body path's entry point.
    pub(crate) async fn reserve_more(&mut self, n: usize) -> bool {
        self.grow_to(self.held.saturating_add(n)).await
    }

    /// Give back everything above `total` bytes.
    #[allow(dead_code)] // The streaming body path's release point.
    pub(crate) fn shrink_to(&mut self, total: usize) {
        if total < self.held {
            self.budget.release(self.held - total);
            self.held = total;
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.release(self.held);
    }
}

/// The capacity [`grow_vec`] gives `body` for `extra` more bytes: a
/// quarter more rather than double, so a body of unknown length never
/// holds (or, during a reallocation, briefly maps) twice its size.
fn grown_capacity(len: usize, extra: usize) -> usize {
    len.saturating_add(extra.max(len / 4).max(64 * 1024))
}

/// Make room in `body` for `extra` more bytes, fallibly, growing to
/// [`grown_capacity`].
pub(crate) fn grow_vec(body: &mut Vec<u8>, extra: usize) -> Result<(), TryReserveError> {
    if body.capacity() - body.len() >= extra {
        return Ok(());
    }
    body.try_reserve_exact(grown_capacity(body.len(), extra) - body.len())
}

impl Reservation {
    /// Make room in `body` for `extra` more bytes: the capacity it grows
    /// to reserved first (waiting as [`Reservation::grow_to`] does), then
    /// allocated fallibly. `false` when either is refused.
    pub(crate) async fn make_room(&mut self, body: &mut Vec<u8>, extra: usize) -> bool {
        if body.capacity() - body.len() >= extra {
            return true;
        }
        self.grow_to(grown_capacity(body.len(), extra)).await && grow_vec(body, extra).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_are_bounded_and_released() {
        let budget = BodyBudget::new(10 * FREE_BYTES);
        let mut a = Reservation::new(&budget);
        assert!(a.try_grow_to(6 * FREE_BYTES));
        let mut b = Reservation::new(&budget);
        assert!(!b.try_grow_to(5 * FREE_BYTES));
        // Small bodies are never refused.
        assert!(b.try_grow_to(FREE_BYTES));
        assert_eq!(budget.used(), 7 * FREE_BYTES);
        drop(a);
        assert!(b.try_grow_to(9 * FREE_BYTES));
        b.shrink_to(2 * FREE_BYTES);
        assert_eq!(budget.used(), 2 * FREE_BYTES);
        drop(b);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn a_waiting_reservation_gets_released_bytes() {
        let budget = BodyBudget::with_wait(4 * FREE_BYTES, Duration::from_secs(5));
        let mut a = Reservation::new(&budget);
        assert!(a.grow_to(3 * FREE_BYTES).await);
        let waiter = {
            let budget = Arc::clone(&budget);
            tokio::spawn(async move {
                let mut b = Reservation::new(&budget);
                b.grow_to(3 * FREE_BYTES).await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(a);
        assert!(waiter.await.unwrap());
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn exhaustion_is_refused_after_the_bounded_wait() {
        let budget = BodyBudget::with_wait(4 * FREE_BYTES, Duration::from_millis(30));
        let mut a = Reservation::new(&budget);
        assert!(a.grow_to(3 * FREE_BYTES).await);
        let mut b = Reservation::new(&budget);
        let started = std::time::Instant::now();
        assert!(!b.grow_to(2 * FREE_BYTES).await);
        assert!(started.elapsed() >= Duration::from_millis(30));
        // Nothing changed for the refused reservation.
        assert_eq!(budget.used(), 3 * FREE_BYTES);
        // More than the whole budget is refused without waiting.
        let started = std::time::Instant::now();
        assert!(!b.grow_to(5 * FREE_BYTES).await);
        assert!(started.elapsed() < Duration::from_millis(30));
        assert!(b.reserve_more(FREE_BYTES).await);
        assert_eq!(budget.used(), 4 * FREE_BYTES);
    }

    #[test]
    fn vectors_grow_by_a_quarter() {
        let mut v = vec![0u8; 1 << 20];
        v.shrink_to_fit();
        grow_vec(&mut v, 1).unwrap();
        assert!(v.capacity() >= (1 << 20) + (1 << 18));
        assert!(v.capacity() < 2 << 20);
        let cap = v.capacity();
        grow_vec(&mut v, 10).unwrap();
        assert_eq!(v.capacity(), cap, "room left: no reallocation");
    }
}
