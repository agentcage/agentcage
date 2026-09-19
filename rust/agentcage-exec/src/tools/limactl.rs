//! `limactl` -- the port of `src/agentcage/lima/instance.py`.
//!
//! Four of the six commands carry a flag that exists because of a bug
//! somebody hit, and the comments in the Python say which. They are
//! repeated at each method, because a flag whose reason is not written
//! down is a flag somebody removes.

use serde_json::Value;

use crate::command::Command;
use crate::outcome::{ExecError, Output};
use crate::runner::CommandRunner;

/// A Lima VM instance for one cage.
///
/// Named `agentcage-<cage>`, as `LimaInstance.__init__` does.
#[derive(Debug)]
pub struct LimaInstance<'a> {
    runner: &'a dyn CommandRunner,
    name: String,
}

impl<'a> LimaInstance<'a> {
    /// The instance for `cage_name`.
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner, cage_name: &str) -> Self {
        Self {
            runner,
            name: format!("agentcage-{cage_name}"),
        }
    }

    /// The Lima instance name, `agentcage-<cage>`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `limactl create --yes --name=<instance> <config_path>`.
    ///
    /// `--yes` skips `limactl create`'s interactive "Proceed with the
    /// current configuration / Open an editor" survey. Lima only shows
    /// it when a TTY is attached, so without the flag the first
    /// interactive `agentcage run` on a fresh machine hangs on a prompt
    /// hidden behind the "Starting cage..." spinner.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn create(&self, config_path: &str) -> Result<(), ExecError> {
        self.check(
            &Command::new("limactl")
                .args(["create", "--yes"])
                .arg(format!("--name={}", self.name))
                .arg(config_path),
        )
    }

    /// `limactl start <instance>`, in its own process group.
    ///
    /// `limactl start` daemonizes internally: it forks the hostagent,
    /// waits for SSH, the guest agent and the boot scripts, then exits,
    /// leaving the hostagent running. The Python uses
    /// `start_new_session=True` so the daemon does not inherit pipe
    /// descriptors from Python's subprocess machinery, which would
    /// otherwise keep `limactl start` from completing. See
    /// [`Command::new_process_group`] for the one difference between
    /// that and what this does.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn start(&self) -> Result<(), ExecError> {
        self.check(
            &Command::new("limactl")
                .args(["start", &self.name])
                .new_process_group(),
        )
    }

    /// `limactl stop <instance>`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn stop(&self) -> Result<(), ExecError> {
        self.check(&Command::new("limactl").args(["stop", &self.name]))
    }

    /// `limactl delete --force <instance>`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn delete(&self) -> Result<(), ExecError> {
        self.check(&Command::new("limactl").args(["delete", "--force", &self.name]))
    }

    /// The `limactl shell` command that runs `command` in the guest.
    ///
    /// Returned rather than run so that callers which need to stream it
    /// -- `cage logs` on the VM backend wraps `journalctl -f` in exactly
    /// this -- can hand it to [`CommandRunner::stream`], and so that E1
    /// can assert on it directly.
    ///
    /// `--workdir /` pins the guest cwd. By default `limactl shell`
    /// mirrors the *host* cwd inside the VM, which only the explicitly
    /// mounted `~/.config/agentcage` and `~/.local/share/agentcage`
    /// paths can satisfy; every other invocation prints a spurious
    /// `cd: <path>: No such file or directory` and runs from `$HOME`
    /// anyway.
    ///
    /// `--tty=false` keeps SSH from allocating a PTY. Without it, piping
    /// stdin while stdout is a terminal makes Lima default to a PTY, and
    /// the kernel line discipline cooks the stream -- CR/LF translation
    /// and control-character handling -- which silently mangles secret
    /// values fed to `podman secret create -` in the guest. This is the
    /// VM backend's whole secret-delivery path, so the flag is not
    /// cosmetic.
    #[must_use]
    pub fn shell_command(&self, command: &[String]) -> Command {
        Command::new("limactl")
            .args(["shell", "--workdir", "/", "--tty=false", &self.name, "--"])
            .args(command.iter().cloned())
    }

    /// Run `command` in the guest and capture its output.
    ///
    /// `check` mirrors `subprocess.run(check=...)`: the Python's
    /// `LimaInstance.exec` defaults to `check=True`, and the VM podman
    /// wrapper passes `check=False` for the calls whose failure is an
    /// answer.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit when `check` is set.
    pub fn exec(&self, command: &[String], check: bool) -> Result<Output, ExecError> {
        let out = self.runner.run(&self.shell_command(command).captured())?;
        if check { out.check("limactl") } else { Ok(out) }
    }

    /// Run `command` in the guest with `input` on stdin.
    ///
    /// The path `VmPodman.secret_create` takes: the value goes down the
    /// pipe, through ssh, into the guest's `podman secret create -`. It
    /// is never an argument at either end.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn exec_with_secret(&self, command: &[String], input: &str) -> Result<Output, ExecError> {
        self.runner
            .run(&self.shell_command(command).captured().stdin_secret(input))?
            .check("limactl")
    }

    /// `limactl list --json <instance>`, parsed.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] if the instance does not exist,
    /// [`ExecError::Parse`] if the answer is not JSON.
    pub fn list_json(&self) -> Result<Value, ExecError> {
        let out = self
            .runner
            .run(
                &Command::new("limactl")
                    .args(["list", "--json", &self.name])
                    .captured(),
            )?
            .check("limactl")?;
        serde_json::from_str(out.stdout_text().trim()).map_err(|e| ExecError::Parse {
            program: "limactl".to_string(),
            detail: e.to_string(),
        })
    }

    /// Whether the instance's status is `Running`.
    ///
    /// Both failure modes -- a non-zero exit and unparseable JSON --
    /// answer "no", which is what `except (CalledProcessError,
    /// JSONDecodeError)` does.
    ///
    /// # Errors
    ///
    /// Only if `limactl` itself could not be run.
    pub fn is_running(&self) -> Result<bool, ExecError> {
        match self.list_json() {
            Ok(data) => Ok(data.get("status").and_then(Value::as_str) == Some("Running")),
            Err(e) if e.is_not_found() => Err(e),
            Err(_) => Ok(false),
        }
    }

    /// Whether the instance exists, in any state.
    ///
    /// # Errors
    ///
    /// Only if `limactl` itself could not be run.
    pub fn exists(&self) -> Result<bool, ExecError> {
        match self.list_json() {
            Ok(_) => Ok(true),
            Err(e) if e.is_not_found() => Err(e),
            Err(_) => Ok(false),
        }
    }

    /// Run a command with `check=True` and discard its output.
    fn check(&self, command: &Command) -> Result<(), ExecError> {
        self.runner.run(command)?.check("limactl")?;
        Ok(())
    }
}
