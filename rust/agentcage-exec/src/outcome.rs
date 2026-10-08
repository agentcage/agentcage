//! What came back: [`Output`], [`ExitStatus`] and [`ExecError`].
//!
//! The one design decision in this module is that **a process that ran
//! and exited non-zero is a success as far as the runner is concerned**.
//! `podman image exists` answers by exiting 1. `podman network rm`
//! exiting 1 is how an already-removed network looks. `container system
//! status` is called with `check=False` precisely so its exit code can be
//! read. If the runner folded those into `Err`, every one of those
//! callers would start by unwrapping the error back into a status, and
//! the interesting distinction -- *could the binary be run at all* --
//! would be buried under the uninteresting one.
//!
//! So [`ExecError`] means the command did not run, or did not finish, or
//! that a caller explicitly asked for `check=True` via [`Output::check`].

use std::fmt;
use std::io;
use std::time::Duration;

/// How a child process finished.
///
/// `std::process::ExitStatus` would do, except that it cannot be
/// constructed portably, which makes it useless to a fake. This carries
/// the two numbers agentcage actually reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExitStatus {
    /// The exit code, or `None` if the child died from a signal.
    pub code: Option<i32>,
    /// The signal that killed the child, or `None` if it exited normally.
    pub signal: Option<i32>,
}

impl ExitStatus {
    /// A normal exit with this code.
    #[must_use]
    pub fn exited(code: i32) -> Self {
        Self {
            code: Some(code),
            signal: None,
        }
    }

    /// A death by signal.
    #[must_use]
    pub fn killed(signal: i32) -> Self {
        Self {
            code: None,
            signal: Some(signal),
        }
    }

    /// Exit code zero.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// The exit code, or `fallback` for a signal death.
    #[must_use]
    pub fn code_or(&self, fallback: i32) -> i32 {
        self.code.unwrap_or(fallback)
    }

    /// The status a shell would report: `128 + signum` for a signal death.
    ///
    /// `terminal.py::exit_status` exists to do exactly this, because
    /// `cage exec` used to `os.execvp` and operators scripted against the
    /// shell convention. Keep it.
    #[must_use]
    pub fn shell_code(&self) -> i32 {
        match (self.code, self.signal) {
            (_, Some(sig)) => 128 + sig,
            (Some(code), None) => code,
            (None, None) => 0,
        }
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.code, self.signal) {
            (_, Some(sig)) => write!(f, "killed by signal {sig}"),
            (Some(code), None) => write!(f, "exit {code}"),
            (None, None) => f.write_str("exit (unknown)"),
        }
    }
}

impl From<std::process::ExitStatus> for ExitStatus {
    fn from(status: std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt as _;
        Self {
            code: status.code(),
            signal: status.signal(),
        }
    }
}

/// A finished process: its status and whatever was captured.
///
/// `stdout` and `stderr` are empty for streams that were inherited,
/// discarded or redirected to a file -- there was nothing to capture,
/// which is the same thing `subprocess.CompletedProcess` reports.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Output {
    /// How the process finished.
    pub status: ExitStatus,
    /// Captured stdout, plus stderr when the command merged them.
    pub stdout: Vec<u8>,
    /// Captured stderr, empty when the command merged it into stdout.
    pub stderr: Vec<u8>,
}

impl Output {
    /// A successful run that produced this stdout and no stderr.
    ///
    /// The shape most stubs want.
    #[must_use]
    pub fn ok(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            status: ExitStatus::exited(0),
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    /// A run that exited with `code` and produced this stderr.
    #[must_use]
    pub fn failed(code: i32, stderr: impl Into<Vec<u8>>) -> Self {
        Self {
            status: ExitStatus::exited(code),
            stdout: Vec::new(),
            stderr: stderr.into(),
        }
    }

    /// Exit code zero.
    #[must_use]
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// Captured stdout as text, replacing invalid UTF-8.
    ///
    /// Lossy on purpose. The Python passes `text=True`, which decodes
    /// with the locale encoding and raises on failure; raising here would
    /// turn a podman version that emits one stray byte into a crash in
    /// `cage list`. Every caller of this either parses JSON (which will
    /// fail on its own terms) or matches a known token.
    #[must_use]
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Captured stderr as text, replacing invalid UTF-8.
    #[must_use]
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// `stdout.strip()`.
    #[must_use]
    pub fn stdout_trimmed(&self) -> String {
        self.stdout_text().trim().to_string()
    }

    /// `stdout.strip().splitlines()`, empty when stdout is blank.
    ///
    /// Python's `"".strip().splitlines()` is `[]`, and Rust's
    /// `"".lines()` is also empty, but `"\n".trim()` is `""` whose
    /// `lines()` is empty too -- so the two agree without special casing.
    #[must_use]
    pub fn stdout_lines(&self) -> Vec<String> {
        let text = self.stdout_text();
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }
        trimmed.lines().map(str::to_string).collect()
    }

    /// `check=True`: turn a non-zero exit into an error.
    ///
    /// `program` is only used to name the command in the error.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] when the status is not a clean exit 0.
    pub fn check(self, program: &str) -> Result<Self, ExecError> {
        if self.success() {
            return Ok(self);
        }
        Err(ExecError::Failed {
            program: program.to_string(),
            status: self.status,
            stderr: truncate_for_message(&self.stderr_text()),
        })
    }
}

/// Why a command could not be run, could not finish, or was checked and
/// found wanting.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExecError {
    /// The binary is not installed, or not on `PATH`.
    ///
    /// The distinction the Python leans on in three separate places:
    /// `registry.py` prints "skopeo is not installed" and degrades to no
    /// version pinning; `apple_container/cli.py` raises with a download
    /// URL; `systemd.py` turns every unit operation into a no-op because
    /// a macOS host has no `systemctl`. All three want "missing", not
    /// "failed".
    NotFound {
        /// The program that could not be found.
        program: String,
    },
    /// The binary exists but this process may not execute it.
    PermissionDenied {
        /// The program that could not be executed.
        program: String,
    },
    /// The fork or exec failed for some other reason.
    Spawn {
        /// The program that could not be started.
        program: String,
        /// The underlying OS error.
        source: io::Error,
    },
    /// The process started, but reading or writing its pipes failed.
    Io {
        /// The program whose stream failed.
        program: String,
        /// The underlying OS error.
        source: io::Error,
    },
    /// The process outlived its [`crate::Command::timeout`] and was killed.
    Timeout {
        /// The program that ran too long.
        program: String,
        /// The limit it exceeded.
        after: Duration,
    },
    /// The process ran and succeeded, but its output was not what the
    /// caller could read.
    ///
    /// `podman info --format json`, `podman inspect`, `container
    /// inspect`, `limactl list --json` and `skopeo list-tags` all answer
    /// in JSON, and the Python lets `json.JSONDecodeError` -- or an
    /// `IndexError` from `[0]` on an empty array -- escape. Giving that
    /// a variant here keeps the crate to one error type, which matters
    /// because every wrapper returns it.
    Parse {
        /// The program whose output could not be read.
        program: String,
        /// What went wrong.
        detail: String,
    },
    /// The process ran, exited non-zero, and a caller asked for
    /// [`Output::check`].
    Failed {
        /// The program that failed.
        program: String,
        /// How it finished.
        status: ExitStatus,
        /// Its stderr, truncated for the message.
        stderr: String,
    },
}

impl ExecError {
    /// Shorthand for the missing-binary case.
    #[must_use]
    pub fn not_found(program: impl Into<String>) -> Self {
        Self::NotFound {
            program: program.into(),
        }
    }

    /// Whether this is the missing-binary case.
    ///
    /// The one bit most callers want, and the reason
    /// [`ExecError::NotFound`] is a variant rather than an `io::Error`
    /// kind buried in [`ExecError::Spawn`].
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// The program this error is about.
    #[must_use]
    pub fn program(&self) -> &str {
        match self {
            Self::NotFound { program }
            | Self::PermissionDenied { program }
            | Self::Spawn { program, .. }
            | Self::Io { program, .. }
            | Self::Timeout { program, .. }
            | Self::Parse { program, .. }
            | Self::Failed { program, .. } => program,
        }
    }

    /// Classify a spawn failure.
    ///
    /// `ErrorKind::NotFound` from an exec is what Python surfaces as
    /// `FileNotFoundError`, so the two map onto each other exactly.
    pub(crate) fn from_spawn(program: &str, source: io::Error) -> Self {
        match source.kind() {
            io::ErrorKind::NotFound => Self::not_found(program),
            io::ErrorKind::PermissionDenied => Self::PermissionDenied {
                program: program.to_string(),
            },
            _ => Self::Spawn {
                program: program.to_string(),
                source,
            },
        }
    }
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { program } => {
                write!(f, "{program}: command not found")
            }
            Self::PermissionDenied { program } => {
                write!(f, "{program}: permission denied")
            }
            Self::Spawn { program, source } => {
                write!(f, "{program}: could not start: {source}")
            }
            Self::Io { program, source } => {
                write!(f, "{program}: i/o error: {source}")
            }
            Self::Timeout { program, after } => {
                write!(f, "{program}: timed out after {}s", after.as_secs_f32())
            }
            Self::Parse { program, detail } => {
                write!(f, "{program}: unreadable output: {detail}")
            }
            Self::Failed {
                program,
                status,
                stderr,
            } if stderr.is_empty() => write!(f, "{program}: {status}"),
            Self::Failed {
                program,
                status,
                stderr,
            } => write!(f, "{program}: {status}: {stderr}"),
        }
    }
}

impl std::error::Error for ExecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn { source, .. } | Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Keep an error message to one screen.
///
/// A failing `podman build` can emit megabytes of stderr, and the
/// interesting part is the tail -- the last error, not the first layer.
fn truncate_for_message(stderr: &str) -> String {
    const LIMIT: usize = 2000;
    let trimmed = stderr.trim();
    if trimmed.len() <= LIMIT {
        return trimmed.to_string();
    }
    let tail: String = trimmed
        .chars()
        .rev()
        .take(LIMIT)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("[...] {tail}")
}

#[cfg(test)]
mod tests {
    use super::{ExecError, ExitStatus, Output};

    #[test]
    fn shell_code_follows_the_128_plus_signum_convention() {
        assert_eq!(ExitStatus::exited(0).shell_code(), 0);
        assert_eq!(ExitStatus::exited(7).shell_code(), 7);
        // SIGINT
        assert_eq!(ExitStatus::killed(2).shell_code(), 130);
        // SIGTERM
        assert_eq!(ExitStatus::killed(15).shell_code(), 143);
    }

    #[test]
    fn a_non_zero_exit_is_not_an_error_until_checked() {
        let out = Output::failed(1, "no such image");
        assert!(!out.success());
        let err = out.check("podman").unwrap_err();
        assert!(matches!(err, ExecError::Failed { .. }));
        assert!(err.to_string().contains("exit 1"));
        assert!(err.to_string().contains("no such image"));
    }

    #[test]
    fn not_found_is_distinguishable() {
        let missing = ExecError::not_found("skopeo");
        assert!(missing.is_not_found());
        assert_eq!(missing.program(), "skopeo");
        assert!(
            !ExecError::Failed {
                program: "skopeo".into(),
                status: ExitStatus::exited(1),
                stderr: String::new(),
            }
            .is_not_found()
        );
    }

    #[test]
    fn stdout_lines_matches_pythons_strip_splitlines() {
        assert_eq!(Output::ok("").stdout_lines(), Vec::<String>::new());
        assert_eq!(Output::ok("\n").stdout_lines(), Vec::<String>::new());
        assert_eq!(Output::ok("   ").stdout_lines(), Vec::<String>::new());
        assert_eq!(Output::ok("a\nb\n").stdout_lines(), ["a", "b"]);
    }

    #[test]
    fn a_huge_stderr_is_truncated_from_the_front() {
        let stderr = format!("{}THE-ACTUAL-ERROR", "x".repeat(5000));
        let err = Output::failed(1, stderr).check("podman").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("THE-ACTUAL-ERROR"), "kept the tail");
        assert!(msg.len() < 2200, "len {}", msg.len());
    }
}
