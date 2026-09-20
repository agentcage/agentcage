//! `systemd-creds` -- the seam half of
//! `src/agentcage/secret_resolver.py`.
//!
//! Two invocations, one of which is a probe of the other.
//!
//! The value goes on **stdin** in both, and the output file is an
//! argument: `systemd-creds [--user] encrypt --name <NAME> - <OUT>`.
//! The `-` is the input, and it is what keeps the credential off
//! `/proc/<pid>/cmdline`. Note also what `--name` carries: the *env
//! variable name*, not the value -- systemd binds the decrypted
//! credential to that name at unit start, and it is not secret.
//!
//! Scope is not a detail. `--user` encrypts with the per-user key and
//! needs no polkit round trip; without it, systemd uses the host key or
//! TPM2, which on a host with an active graphical session routes a
//! polkit prompt to the desktop user -- a service user encrypting a
//! secret would hang waiting for a dialog nobody is looking at. So
//! `secrets.scope: auto` prefers `user` when the invoker is not root and
//! user-scoped encryption actually works, and only then falls back to
//! `system`.

use std::time::Duration;

use crate::command::Command;
use crate::outcome::ExecError;
use crate::runner::CommandRunner;

/// The encryption key `systemd-creds` should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// `--user`: the per-user key. No polkit prompt.
    User,
    /// No flag: the host key or TPM2.
    System,
}

impl Scope {
    /// The flag this scope contributes, if any.
    #[must_use]
    pub fn flag(self) -> Option<&'static str> {
        match self {
            Self::User => Some("--user"),
            Self::System => None,
        }
    }

    /// The `secrets.scope` spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::System => "system",
        }
    }
}

/// The real encryption's time limit.
///
/// 30 seconds: TPM2 operations occasionally block on hardware -- a slow
/// chip, or contention with another process -- and the Python turns the
/// timeout into a message that says so, rather than an unexplained hang
/// during `secret set`.
pub const ENCRYPT_TIMEOUT: Duration = Duration::from_secs(30);

/// The capability probe's time limit.
///
/// 5 seconds, shorter than [`ENCRYPT_TIMEOUT`] because this one runs
/// during backend detection, before the operator has been told anything
/// is happening.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The name the probe encrypts under.
pub const PROBE_NAME: &str = "_probe";

/// The minimum systemd version with usable `systemd-creds`.
pub const MIN_SYSTEMD_VERSION: u32 = 250;

/// The `systemd-creds` CLI.
#[derive(Debug)]
pub struct SystemdCreds<'a> {
    runner: &'a dyn CommandRunner,
}

impl<'a> SystemdCreds<'a> {
    /// A `systemd-creds` wrapper.
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Self { runner }
    }

    /// Whether the binary is installed at all.
    #[must_use]
    pub fn installed(&self) -> bool {
        self.runner.has("systemd-creds")
    }

    /// `systemd-creds [--user] encrypt --name <name> - <out_path>`.
    ///
    /// The value is not in this argv; it goes on stdin, which is what
    /// the `-` says.
    #[must_use]
    pub fn encrypt_command(scope: Scope, name: &str, out_path: &str, value: &str) -> Command {
        let mut cmd = Command::new("systemd-creds");
        if let Some(flag) = scope.flag() {
            cmd = cmd.arg(flag);
        }
        cmd.args(["encrypt", "--name", name, "-", out_path])
            .captured()
            .stdin_secret(value)
            .timeout(ENCRYPT_TIMEOUT)
    }

    /// `systemd-creds decrypt <path> -`.
    ///
    /// The one *read* direction, and it exists for one caller: the
    /// `vm` backend bridges a cage's `.cred` blobs into the guest's
    /// podman store, which means decrypting them on the host and
    /// piping the plaintext through `limactl shell`
    /// (`vm.py::_bridge_secrets`). Nothing on the container backend
    /// decrypts host-side — there the Quadlet's
    /// `LoadCredentialEncrypted` does it at unit start, which is why
    /// this is not the mirror of [`SystemdCreds::encrypt`].
    ///
    /// No scope flag. `systemd-creds decrypt` picks the key from the
    /// blob's own header, so passing `--user` here would only be able
    /// to make a decryptable blob undecryptable.
    ///
    /// The trailing `-` writes to stdout, which is where the caller
    /// takes the plaintext from. It is never an argument and never a
    /// file.
    #[must_use]
    pub fn decrypt_command(path: &str) -> Command {
        Command::new("systemd-creds")
            .args(["decrypt", path, "-"])
            .captured()
            .timeout(ENCRYPT_TIMEOUT)
    }

    /// Decrypt the blob at `path` and return its plaintext.
    ///
    /// # Errors
    ///
    /// [`ExecError::Timeout`] after [`ENCRYPT_TIMEOUT`],
    /// [`ExecError::Failed`] on a non-zero exit — which is what a blob
    /// encrypted with a key this host no longer has looks like.
    pub fn decrypt(&self, path: &str) -> Result<String, ExecError> {
        let out = self
            .runner
            .run(&Self::decrypt_command(path))?
            .check("systemd-creds")?;
        Ok(out.stdout_text())
    }

    /// `systemd-creds [--user] encrypt --name _probe - -`.
    ///
    /// Encrypts a literal to stdout and throws the result away; the only
    /// question is whether it worked.
    #[must_use]
    pub fn probe_command(scope: Scope) -> Command {
        let mut cmd = Command::new("systemd-creds");
        if let Some(flag) = scope.flag() {
            cmd = cmd.arg(flag);
        }
        cmd.args(["encrypt", "--name", PROBE_NAME, "-", "-"])
            .captured()
            .stdin_text("probe")
            .timeout(PROBE_TIMEOUT)
    }

    /// Encrypt `value` into `out_path`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Timeout`] after [`ENCRYPT_TIMEOUT`],
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn encrypt(
        &self,
        scope: Scope,
        name: &str,
        out_path: &str,
        value: &str,
    ) -> Result<(), ExecError> {
        self.runner
            .run(&Self::encrypt_command(scope, name, out_path, value))?
            .check("systemd-creds")?;
        Ok(())
    }

    /// Whether encryption works in this scope.
    ///
    /// Every failure -- missing binary, non-zero exit, timeout -- is
    /// `false`, which is what `except Exception: return False` does. The
    /// question is a capability, and any way of not answering it means
    /// the capability is not there.
    #[must_use]
    pub fn works(&self, scope: Scope) -> bool {
        self.runner
            .run(&Self::probe_command(scope))
            .is_ok_and(|out| out.success())
    }

    /// The scope `secrets.scope: auto` should resolve to, or `None` when
    /// neither works.
    ///
    /// `user` first when the invoker is not root, then `system`. Root
    /// skips the user probe entirely: root's per-user key is not the
    /// operator's, so a credential encrypted with it would be
    /// undecryptable by the unit that needs it.
    #[must_use]
    pub fn detect_scope(&self, non_root: bool) -> Option<Scope> {
        if non_root && self.works(Scope::User) {
            return Some(Scope::User);
        }
        if self.works(Scope::System) {
            return Some(Scope::System);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{Scope, SystemdCreds};

    #[test]
    fn the_system_scope_has_no_flag() {
        let cmd = SystemdCreds::encrypt_command(
            Scope::System,
            "API_KEY",
            "/var/lib/agentcage/c/creds/API_KEY.cred",
            "hunter2",
        );
        assert_eq!(
            cmd.argv(),
            [
                "systemd-creds",
                "encrypt",
                "--name",
                "API_KEY",
                "-",
                "/var/lib/agentcage/c/creds/API_KEY.cred"
            ]
        );
    }

    #[test]
    fn the_user_scope_inserts_the_flag_before_encrypt() {
        let cmd = SystemdCreds::encrypt_command(Scope::User, "K", "/out.cred", "v");
        assert_eq!(cmd.argv()[..3], ["systemd-creds", "--user", "encrypt"]);
    }

    /// The point of the whole module: the value is on stdin, and no
    /// rendering of the command can show it.
    #[test]
    fn the_value_never_touches_argv() {
        let cmd = SystemdCreds::encrypt_command(Scope::User, "K", "/out.cred", "hunter2");
        assert!(!cmd.argv().iter().any(|a| a.contains("hunter2")));
        assert_eq!(cmd.stdin_bytes_ref(), Some(&b"hunter2"[..]));
        assert!(!format!("{cmd:?}").contains("hunter2"));
    }

    #[test]
    fn the_probe_writes_to_stdout_and_is_not_secret() {
        let cmd = SystemdCreds::probe_command(Scope::User);
        assert_eq!(
            cmd.argv(),
            [
                "systemd-creds",
                "--user",
                "encrypt",
                "--name",
                "_probe",
                "-",
                "-"
            ]
        );
        // "probe" is a literal, so it stays legible in a failure dump.
        assert!(format!("{cmd:?}").contains("probe"));
    }
}
