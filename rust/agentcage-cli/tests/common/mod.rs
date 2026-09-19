//! Shared plumbing for PR D3's test binaries.
//!
//! An integration test is its own crate, so this is `mod common;` in
//! each binary that wants it rather than a library. Not every binary
//! uses every helper, hence the blanket `dead_code` allow -- the same
//! arrangement `agentcage-core/tests/common/mod.rs` uses.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use agentcage_core::config::types::{Config, SecretsConfig};

/// The repository root, from this crate's manifest directory.
pub(crate) fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// PR A7's frozen state snapshot for 0.40.1.
pub(crate) fn state_fixture_root() -> PathBuf {
    repo_root().join("tests/fixtures/state-compat/0.40.1")
}

/// One cage's deployment directory inside that snapshot.
///
/// `$XDG_CONFIG_HOME/agentcage/cages/<name>/`, which is what
/// `state.deployment_dir` answers and what every store here is handed
/// as `state_dir`.
pub(crate) fn deployment_dir(cage: &str) -> PathBuf {
    state_fixture_root()
        .join("xdg-config/agentcage/cages")
        .join(cage)
}

/// A throwaway directory, removed when the value drops.
///
/// `tempfile` is not in this workspace's dependency tree and this PR is
/// not the place to add one: three tests need a writable directory and
/// nothing needs the crate's security properties, because these paths
/// are created by the test process under its own temp dir and the files
/// written into them carry fixture strings rather than credentials.
#[derive(Debug)]
pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create one, named after `label` and this process.
    pub(crate) fn new(label: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("agentcage-d3-{label}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("temp dir");
        Self { path }
    }

    /// The directory itself.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A config with `isolation` and the `secrets:` block set, and
/// everything else defaulted.
pub(crate) fn config(isolation: &str, backend: &str, scope: &str, allow_plaintext: bool) -> Config {
    Config {
        isolation: isolation.to_owned(),
        secrets: SecretsConfig {
            backend: backend.to_owned(),
            scope: scope.to_owned(),
            allow_plaintext,
        },
        ..Config::default()
    }
}
