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

/// Podman inside the guest — `lima/podman.py`'s `VmPodman`.
///
/// The `vm` backend has no host podman to talk to: the store, the
/// images and the containers all live inside the Lima guest, so every
/// operation the CLI would run against `podman` is the same argv
/// wrapped in a `limactl shell`. The Python spells that by holding a
/// `LimaInstance` and calling `exec`, and this does the same, so the
/// two flags [`LimaInstance::shell_command`] documents — `--workdir /`
/// and `--tty=false` — cover these calls as well. The second one is not
/// optional here: [`VmPodman::secret_create`] pipes a credential
/// through ssh, and a PTY's line discipline would rewrite it.
///
/// Mirrors the subset of [`super::podman::Podman`] the CLI's secret
/// paths use, which is what lets `secret_store.py` take either object.
#[derive(Debug)]
pub struct VmPodman<'a> {
    instance: LimaInstance<'a>,
}

impl<'a> VmPodman<'a> {
    /// Podman in the guest that runs `cage_name`.
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner, cage_name: &str) -> Self {
        Self {
            instance: LimaInstance::new(runner, cage_name),
        }
    }

    /// The Lima instance this routes through.
    #[must_use]
    pub fn instance(&self) -> &LimaInstance<'a> {
        &self.instance
    }

    /// `podman pull <image>` in the guest, as a bool.
    ///
    /// # Errors
    ///
    /// Only if `limactl` itself could not be run.
    pub fn pull(&self, image: &str) -> Result<bool, ExecError> {
        Ok(self.exec(&["podman", "pull", image], false)?.success())
    }

    /// `podman image inspect <image>` in the guest, first element.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] when the image is unknown,
    /// [`ExecError::Parse`] when the answer is not a non-empty JSON
    /// array — the Python's `json.loads(...)[0]`, whose `IndexError`
    /// this variant stands in for.
    pub fn image_inspect(&self, image: &str) -> Result<Value, ExecError> {
        let out = self.exec(&["podman", "image", "inspect", image], true)?;
        let value: Value =
            serde_json::from_str(out.stdout_text().trim()).map_err(|e| ExecError::Parse {
                program: "podman".to_string(),
                detail: e.to_string(),
            })?;
        value
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .ok_or_else(|| ExecError::Parse {
                program: "podman".to_string(),
                detail: "expected a non-empty JSON array".to_string(),
            })
    }

    /// `podman secret ls` in the guest, leniently.
    ///
    /// # Errors
    ///
    /// Only if `limactl` itself could not be run.
    pub fn secret_list(&self, prefix: &str) -> Result<Vec<String>, ExecError> {
        let out = self.exec(&SECRET_LS, false)?;
        Ok(crate::tools::podman::parse_secret_list(&out, prefix))
    }

    /// `podman secret ls` in the guest, failing on a listing failure.
    ///
    /// The distinction is issue #262's, and on this backend it is the
    /// one that matters most: the guest's store can only be read while
    /// the guest runs, so "the listing failed" and "the store is empty"
    /// are states the `Secret=` gate has to tell apart. A failure here
    /// sends the caller back to emit-everything; an empty list would
    /// drop every directive.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit. The Python raises a
    /// `RuntimeError` reading `podman secret ls failed in VM: <stderr
    /// or stdout>`; the text is carried in the error's `stderr` field
    /// rather than the message, because every caller in the port
    /// swallows this error rather than printing it.
    pub fn secret_list_strict(&self, prefix: &str) -> Result<Vec<String>, ExecError> {
        let out = self.exec(&SECRET_LS, false)?;
        if !out.success() {
            let stderr = out.stderr_text();
            let detail = if stderr.trim().is_empty() {
                out.stdout_text()
            } else {
                stderr
            };
            return Err(ExecError::Failed {
                program: "podman secret ls in VM".to_string(),
                status: out.status,
                stderr: detail.trim().to_string(),
            });
        }
        Ok(crate::tools::podman::parse_secret_list(&out, prefix))
    }

    /// `podman secret inspect <name>` in the guest, as a bool.
    ///
    /// # Errors
    ///
    /// Only if `limactl` itself could not be run.
    pub fn secret_exists(&self, name: &str) -> Result<bool, ExecError> {
        Ok(self
            .exec(&["podman", "secret", "inspect", name], false)?
            .success())
    }

    /// `podman secret create <name> -` in the guest, value on stdin.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn secret_create(&self, name: &str, value: &str) -> Result<(), ExecError> {
        self.instance.exec_with_secret(
            &["podman", "secret", "create", name, "-"].map(str::to_string),
            value,
        )?;
        Ok(())
    }

    /// `podman secret inspect --showsecret --format {{.SecretData}}`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] when there is no such secret.
    pub fn secret_read(&self, name: &str) -> Result<String, ExecError> {
        let out = self.exec(
            &[
                "podman",
                "secret",
                "inspect",
                "--showsecret",
                "--format",
                "{{.SecretData}}",
                name,
            ],
            true,
        )?;
        Ok(out.stdout_trimmed())
    }

    /// `podman secret rm <name>` in the guest, reporting success.
    ///
    /// # Errors
    ///
    /// Only if `limactl` itself could not be run.
    pub fn secret_remove(&self, name: &str) -> Result<bool, ExecError> {
        Ok(self
            .exec(&["podman", "secret", "rm", name], false)?
            .success())
    }

    /// One guest command, from borrowed parts.
    fn exec(&self, command: &[&str], check: bool) -> Result<Output, ExecError> {
        let owned: Vec<String> = command.iter().map(|part| (*part).to_string()).collect();
        self.instance.exec(&owned, check)
    }
}

/// The listing argv, shared by the lenient and strict listers.
const SECRET_LS: [&str; 6] = [
    "podman",
    "secret",
    "ls",
    "--noheading",
    "--format",
    "{{.Name}}",
];

impl crate::tools::podman::SecretLister for VmPodman<'_> {
    fn secret_list(&self, prefix: &str) -> Result<Vec<String>, ExecError> {
        Self::secret_list(self, prefix)
    }

    fn secret_list_strict(&self, prefix: &str) -> Result<Vec<String>, ExecError> {
        Self::secret_list_strict(self, prefix)
    }
}
