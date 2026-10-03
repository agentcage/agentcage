//! A throwaway directory, and why there is no `tempfile` dependency.
//!
//! Every reader and writer in this crate is about a real filesystem, so
//! its tests need a real directory to point at — and so will D3's
//! secret stores, D6-D12's command tests and Track E's backends, which
//! is why this is `pub` rather than `#[cfg(test)]`.
//!
//! It is thirty lines instead of a crate because that is all it has to
//! be. `tempfile` brings `getrandom`, `cfg-if` and `fastrand` for a
//! guarantee this does not need: nothing here has to be unpredictable,
//! only unique, and a PID plus a monotonic counter plus a caller-chosen
//! label is unique among the things that can collide — concurrent test
//! binaries and `cargo test`'s own threads.
//!
//! What it does share with `tempfile` is the part that matters: the
//! directory is removed when the value is dropped, including on a
//! panicking assertion, so a failed run does not leave state behind for
//! the next one to read.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A directory under `$TMPDIR` that deletes itself when dropped.
#[derive(Debug)]
pub struct TestDir {
    path: PathBuf,
}

impl TestDir {
    /// Create one, named after `label` so a leaked directory says which
    /// test leaked it.
    ///
    /// # Panics
    ///
    /// If the directory cannot be created. A test that cannot get a
    /// scratch directory has nothing useful left to assert.
    #[must_use]
    pub fn new(label: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("agentcage-{label}-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", path.display()));
        Self { path }
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The directory, joined with `relative`.
    #[must_use]
    pub fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.path.join(relative)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
