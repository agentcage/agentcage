//! `ensure_patches` refreshes ONE directory shared by every cage.
//!
//! `patches_work_dir` is `<data>/agentcage/patches` — not per cage — and
//! the refresh deletes the `nested` tree and copies it back. Two
//! concurrent `cage create`s interleave that into a copy landing in a
//! directory the other has just removed, and whichever one loses dies
//! with `could not materialize the build context: No such file or
//! directory` naming a path nobody wrote.
//!
//! That is not hypothetical: it is what `tests/e2e/run.sh` produced on a
//! CI runner, where phases 3, 5 and 6 each deploy a cage in parallel.
//! Phases 3 and 5 passed and 6 did not.
//!
//! `flock` is per *descriptor*, not per process, so threads that each
//! open the lock file contend exactly as separate processes do — which
//! is what makes this a real test of the guard rather than a test of
//! Rust's borrow checker.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentcage_cli::services;
use agentcage_state::{Paths, TestDir};

/// Eight threads refreshing at once, twelve times each.
///
/// Without the lock this fails within the first round or two; the count
/// is deliberately more than enough rather than the minimum that
/// reproduces, because a race that reproduces "usually" is a test that
/// passes "usually".
#[test]
fn concurrent_refreshes_do_not_race_on_the_shared_patches_directory() {
    let dir = TestDir::new("patches-race");
    let paths = Arc::new(Paths::under(dir.path()));
    let failures = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|scope| {
        for _ in 0..8 {
            let paths = Arc::clone(&paths);
            let failures = Arc::clone(&failures);
            scope.spawn(move || {
                for _ in 0..12 {
                    if services::ensure_patches(&paths).is_err() {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });

    assert_eq!(
        failures.load(Ordering::Relaxed),
        0,
        "concurrent ensure_patches calls raced on the shared patches directory"
    );
}
