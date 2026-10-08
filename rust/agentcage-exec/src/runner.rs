//! The seam itself: [`CommandRunner`] and [`LineStream`].

use std::fmt;
use std::path::PathBuf;

use crate::command::Command;
use crate::outcome::{ExecError, ExitStatus, Output};

/// Somewhere to run a [`Command`].
///
/// Implemented twice: by [`crate::SystemRunner`], which forks, and by
/// [`crate::FakeRunner`], which records. Every wrapper in
/// [`crate::tools`] holds a `&dyn CommandRunner` and nothing else, so
/// swapping the fake in is a constructor argument rather than a patch.
///
/// `Send + Sync` because `run.py`'s proxy monitor runs a `podman logs -f`
/// on a background thread while the interactive session owns the
/// foreground, so a runner has to be shareable. `Debug` because a
/// wrapper holding one should stay printable.
///
/// # Three methods, and why not fewer
///
/// [`CommandRunner::run`] and [`CommandRunner::stream`] are the two
/// genuinely different shapes: run-to-completion, and
/// consume-while-running. Collapsing them would mean either buffering a
/// `journalctl -f` that never ends, or making every captured call deal
/// with a stream it does not want.
///
/// [`CommandRunner::which`] is here rather than being a free function
/// because "is this binary installed?" is the same question as "can this
/// command run?", and three call sites answer it *before* spawning
/// anything: `systemd.py` no-ops when `systemctl` is absent,
/// `apple_container/cli.py` searches three candidate paths for
/// `container`, and `secret_resolver.py` gates the whole systemd-creds
/// backend on `shutil.which("systemd-creds")`. Leaving it off the trait
/// would mean the fake could stub the command but not the probe, and the
/// no-systemd branch -- the one that only ever runs on macOS, where CI
/// has no runner -- would be untestable on Linux. It is on the trait so
/// that branch is reachable from a Linux test.
pub trait CommandRunner: fmt::Debug + Send + Sync {
    /// Run `command` to completion.
    ///
    /// A non-zero exit is **not** an error; see [`crate::outcome`]. Use
    /// [`Output::check`] for `check=True`.
    ///
    /// # Errors
    ///
    /// [`ExecError::NotFound`] when the binary is missing,
    /// [`ExecError::Timeout`] when it outlives
    /// [`Command::timeout`], and [`ExecError::Spawn`] /
    /// [`ExecError::Io`] for everything else that went wrong around the
    /// process rather than inside it.
    fn run(&self, command: &Command) -> Result<Output, ExecError>;

    /// Start `command` and read its stdout line by line while it runs.
    ///
    /// The `subprocess.Popen(cmd, stdout=PIPE)` + `for line in
    /// proc.stdout` shape, which `cage audit`, `cage audit -f`,
    /// `cage logs --level=...` and the interactive proxy monitor all use
    /// to filter a stream that may never end.
    ///
    /// `command`'s stdout disposition is ignored -- streaming implies a
    /// pipe. [`Command::merge_stderr`] is honoured, and is what the audit
    /// paths need, since the addon writes its JSON to stderr.
    ///
    /// # Errors
    ///
    /// As [`CommandRunner::run`], for the spawn. Failures *while*
    /// reading end the stream rather than being returned here.
    fn stream(&self, command: &Command) -> Result<Box<dyn LineStream>, ExecError>;

    /// Resolve `program` on `PATH`, as `shutil.which` does.
    ///
    /// `None` means "not installed", which several callers treat as a
    /// reason to degrade rather than to fail.
    fn which(&self, program: &str) -> Option<PathBuf>;

    /// Whether `program` is installed.
    ///
    /// Sugar for `which(..).is_some()`; provided so the common case
    /// reads like the Python it replaces.
    fn has(&self, program: &str) -> bool {
        self.which(program).is_some()
    }
}

/// A running child whose stdout is being read a line at a time.
///
/// Dropping one without [`LineStream::wait`] leaves the child to be
/// reaped by the implementation; [`crate::SystemRunner`]'s drop kills it,
/// because the alternative -- a `journalctl -f` outliving the `cage
/// audit` that started it -- is a leak an operator would notice.
pub trait LineStream: fmt::Debug + Send {
    /// The next line of the child's stdout, without its trailing newline.
    ///
    /// `None` at end of stream, which includes the child exiting and a
    /// read error. Blocks until a line is available.
    fn next_line(&mut self) -> Option<String>;

    /// Ask the child to stop, with `SIGTERM`.
    ///
    /// `_audit_follow` ends with `proc.terminate()`, and the signal
    /// matters: these children are `journalctl -f` and, on the VM
    /// backend, `limactl shell` wrapping an ssh client. A `SIGKILL` there
    /// leaves the remote end of the ssh session running.
    ///
    /// # Errors
    ///
    /// [`ExecError::Io`] if the signal could not be delivered. A child
    /// that has already exited is not an error.
    fn terminate(&mut self) -> Result<(), ExecError>;

    /// Reap the child and report how it finished.
    ///
    /// # Errors
    ///
    /// [`ExecError::Io`] if the wait failed.
    fn wait(&mut self) -> Result<ExitStatus, ExecError>;

    /// Drain the rest of the stream into a vector.
    ///
    /// Sugar for the `cage audit` batch paths, which read to EOF and
    /// then `wait()`.
    fn collect_lines(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        while let Some(line) = self.next_line() {
            lines.push(line);
        }
        lines
    }
}
