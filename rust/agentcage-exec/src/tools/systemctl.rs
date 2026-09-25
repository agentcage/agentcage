//! `systemctl --user` -- the port of `src/agentcage/systemd.py`.
//!
//! Two things carry over from the Python and neither is obvious.
//!
//! **Every operation is a no-op when `systemctl` is absent.** macOS has
//! no systemd, and a container-backed cage created on Linux can still be
//! cleaned up from a Mac; without the guard those paths die with
//! `FileNotFoundError`. The check is [`CommandRunner::which`] rather
//! than "try it and catch not-found", because that is what the Python
//! does (`shutil.which`) and because it keeps the no-op decision
//! inspectable -- [`crate::FakeRunner::stub_missing`] reaches the macOS
//! branch from a Linux test runner, which is the only way it gets
//! covered at all.
//!
//! **The `runuser` prefix is the same as podman's**, and for a related
//! reason: under `sudo`, `systemctl --user` would otherwise talk to
//! root's user instance instead of the invoking operator's, where the
//! cage's units are not.

use crate::command::Command;
use crate::outcome::ExecError;
use crate::runner::CommandRunner;
use crate::tools::Elevation;

/// The systemctl CLI, scoped to the user instance.
#[derive(Debug)]
pub struct Systemctl<'a> {
    runner: &'a dyn CommandRunner,
    elevation: Elevation,
}

impl<'a> Systemctl<'a> {
    /// A systemctl wrapper that detects elevation from the environment.
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Self::with_elevation(runner, Elevation::detect())
    }

    /// A systemctl wrapper with an explicit [`Elevation`].
    #[must_use]
    pub fn with_elevation(runner: &'a dyn CommandRunner, elevation: Elevation) -> Self {
        Self { runner, elevation }
    }

    /// Whether this host has systemd at all.
    ///
    /// `systemd.py::_systemctl_available`.
    #[must_use]
    pub fn available(&self) -> bool {
        self.runner.has("systemctl")
    }

    /// The base command: `systemctl --user`, with the elevation prefix.
    #[must_use]
    pub fn base(&self) -> Command {
        self.elevation.command("systemctl").arg("--user")
    }

    /// Run `systemctl --user <args>` unless systemd is absent.
    ///
    /// `Ok(false)` means the host has no systemd and nothing ran.
    fn run_unit_op<I, S>(&self, args: I) -> Result<bool, ExecError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if !self.available() {
            return Ok(false);
        }
        self.runner
            .run(&self.base().args(args))?
            .check("systemctl")?;
        Ok(true)
    }

    /// `systemctl --user daemon-reload`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn daemon_reload(&self) -> Result<bool, ExecError> {
        self.run_unit_op(["daemon-reload"])
    }

    /// `systemctl --user start <name>`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn start_unit(&self, name: &str) -> Result<bool, ExecError> {
        self.run_unit_op(["start", name])
    }

    /// `systemctl --user stop <name>`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn stop_unit(&self, name: &str) -> Result<bool, ExecError> {
        self.run_unit_op(["stop", name])
    }

    /// `systemctl --user restart <name>`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn restart_unit(&self, name: &str) -> Result<bool, ExecError> {
        self.run_unit_op(["restart", name])
    }

    /// `systemctl --user enable <name>`.
    ///
    /// Only native `.service` units need this. A quadlet-generated unit
    /// is activated by the systemd generator; a hand-written one's
    /// `[Install] WantedBy=` names a symlink that nothing creates unless
    /// `enable` is called. The Python notes it has no live caller and is
    /// kept for parity and legacy cleanup; same here.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn enable_unit(&self, name: &str) -> Result<bool, ExecError> {
        self.run_unit_op(["enable", name])
    }

    /// `systemctl --user disable <name>`.
    ///
    /// The undo of [`Systemctl::enable_unit`], and note that `disable`
    /// alone does not stop a running instance -- the legacy cleanup path
    /// uses `disable --now` for that.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn disable_unit(&self, name: &str) -> Result<bool, ExecError> {
        self.run_unit_op(["disable", name])
    }

    /// The host's major systemd version, or 0 when it cannot be read.
    ///
    /// `secret_resolver.py::_systemd_version`, which gates the whole
    /// systemd-creds backend on `>= 250`. Note what it does *not* do:
    /// no `--user`, no `runuser` prefix, and every failure -- missing
    /// binary, non-zero exit, unparseable first line -- collapses to 0,
    /// because the only question being asked is "is this host new
    /// enough", and every way of failing to answer means no.
    ///
    /// The first line is `systemd 256 (256.11-1-arch)`; the second field
    /// is the number.
    #[must_use]
    pub fn systemd_version(&self) -> u32 {
        let Ok(out) = self
            .runner
            .run(&Command::new("systemctl").arg("--version").captured())
        else {
            return 0;
        };
        out.stdout_text()
            .split_whitespace()
            .nth(1)
            .and_then(|n| n.parse().ok())
            .unwrap_or(0)
    }
}
