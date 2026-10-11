//! Shared helpers for the e2e harness tests: a scratch directory, fake
//! commands on a temp `PATH`, and running bash with a timeout.
//!
//! The harness tests drive the real `tests/e2e` shell scripts with every
//! host-specific command replaced by a shim, so the paths they cover can
//! run on any CI host without touching podman, systemd or a keychain.

#![allow(dead_code)] // each test binary uses a different subset

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// The repository root (this crate lives at `rust/agentcage-e2e-mock`).
pub(crate) fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// `tests/e2e` in the repository.
pub(crate) fn e2e_dir() -> PathBuf {
    repo_root().join("tests/e2e")
}

/// A directory removed on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    /// A fresh, empty directory under the system temp dir.
    pub(crate) fn new(tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "agentcage-e2e-harness-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    /// The directory.
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Write an executable `#!/bin/sh` script `name` with `body` into `dir`.
pub(crate) fn write_shim(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write shim");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod shim");
    path
}

/// What a script run produced.
#[derive(Debug)]
pub(crate) struct Run {
    /// Exit code (-1 when killed by a signal or the timeout).
    pub(crate) code: i32,
    /// Captured stdout.
    pub(crate) stdout: String,
    /// Captured stderr.
    pub(crate) stderr: String,
}

impl Run {
    /// stdout and stderr together, for assertion messages.
    pub(crate) fn both(&self) -> String {
        format!(
            "--- stdout ---\n{}\n--- stderr ---\n{}",
            self.stdout, self.stderr
        )
    }
}

/// Run `bash ARGS...` with `bindir` first on `PATH`, `REPO_ROOT` set, and
/// `env` applied on top; kill it after `timeout`.
pub(crate) fn run_bash(
    args: &[&str],
    bindir: &Path,
    env: &[(&str, String)],
    timeout: Duration,
) -> Run {
    let path = format!(
        "{}:{}",
        bindir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::new("bash");
    cmd.args(args)
        .env("PATH", path)
        .env("REPO_ROOT", repo_root())
        // The binary under test must never be a real one reached by
        // accident; tests that need it set their own.
        .env_remove("E2E_MOCK_BIN")
        .env_remove("AGENTCAGE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn bash");
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().expect("wait").is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("collect output");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Run a bash snippet (`bash -c SCRIPT`) as [`run_bash`] does.
pub(crate) fn run_snippet(script: &str, bindir: &Path, env: &[(&str, String)]) -> Run {
    run_bash(&["-c", script], bindir, env, Duration::from_secs(30))
}
