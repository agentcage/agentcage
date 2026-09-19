//! `security`(1) -- the argv half of `KeychainStore` in
//! `src/agentcage/secret_store.py`.
//!
//! # The one place agentcage puts a secret in argv
//!
//! The project's rule is that secret material travels on stdin.
//! `podman secret create <name> -` honours it. `systemd-creds encrypt
//! --name <k> - <out>` honours it. `VmPodman.secret_create` honours it
//! through two hops -- `limactl shell` into ssh into `podman secret
//! create -` -- and `--tty=false` is there so the pipe survives the
//! journey. The placeholder scheme exists so that even the cage's own
//! `-e` environment carries a placeholder rather than a value.
//!
//! `secret_store.py:226` does not:
//!
//! ```text
//! security add-generic-password -s agentcage -a <cage>.<KEY> -w <CLEARTEXT> -U
//! ```
//!
//! For as long as that child runs, the credential is in
//! `/proc/<pid>/cmdline` -- or, on the Mac where this actually runs, in
//! `ps -ww` output -- readable by any process of the same user, and by
//! root. On a multi-user Mac, or one with any agent that samples the
//! process table, that is a real disclosure. `KeychainStore.get` is
//! fine: its `-w` takes no value and asks for the password rather than
//! supplying one. Only `set` is affected, and so is the write probe,
//! which passes the harmless literal `x`.
//!
//! # What this module does about it
//!
//! It reproduces the argv exactly, and marks the value with
//! [`Command::secret_arg`] so it is redacted from every `Debug`,
//! `Display` and [`crate::FakeRunner`] dump in this crate. The exposure
//! to `ps` is unchanged, because that is a property of `execve`, not of
//! how this crate prints things.
//!
//! It does not unilaterally switch to stdin. `security(1)`'s behaviour
//! when `-w` is given without a value -- it prompts, and what it does
//! with a non-tty stdin is not documented -- can only be settled on a
//! Mac, and `KeychainStore` is PR E2b's, which is gated on exactly that
//! hardware. Changing the argv here, on a Linux box, against no test
//! that can run it, would be a guess dressed as a fix. E2b should make
//! the call with a keychain in front of it; [`AddPassword::stdin_note`]
//! is where the finding is written down so it cannot be missed.

use crate::command::Command;
use crate::outcome::ExecError;
use crate::runner::CommandRunner;

/// The keychain service namespace for every agentcage secret.
pub const SERVICE: &str = "agentcage";

/// The macOS System keychain: root-owned, unlocked at boot, usable
/// headless.
pub const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

/// The throwaway account name the write probe uses.
pub const PROBE_ACCOUNT: &str = "__agentcage_probe__";

/// Which keychain to talk to, and whether it needs `sudo`.
///
/// `KeychainStore._target` picks between these in a fixed order: the
/// login keychain if it is genuinely writable, else the System keychain
/// if passwordless `sudo` already works, else fail closed. It never
/// prompts for a sudo password -- `sudo -n` is the whole point, so that
/// a narrow `NOPASSWD: /usr/bin/security` rule is enough and blanket
/// passwordless sudo is not required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeychainTarget {
    /// Prefix the command with `sudo -n`.
    pub sudo: bool,
    /// The keychain path, appended last. `None` means the default
    /// (login) keychain.
    pub keychain: Option<String>,
}

impl KeychainTarget {
    /// The user's login keychain, no `sudo`.
    #[must_use]
    pub fn login() -> Self {
        Self {
            sudo: false,
            keychain: None,
        }
    }

    /// The System keychain, via `sudo -n`.
    #[must_use]
    pub fn system() -> Self {
        Self {
            sudo: true,
            keychain: Some(SYSTEM_KEYCHAIN.to_string()),
        }
    }

    /// `security <args> [keychain]`, with the `sudo -n` prefix applied.
    ///
    /// The keychain path goes last, after every flag, which is where
    /// `security(1)` expects it and where the Python appends it.
    #[must_use]
    pub fn command<I, S>(&self, args: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let base = if self.sudo {
            Command::new("sudo").args(["-n", "security"])
        } else {
            Command::new("security")
        };
        let cmd = base.args(args);
        match &self.keychain {
            Some(path) => cmd.arg(path),
            None => cmd,
        }
    }
}

/// An `add-generic-password` invocation.
///
/// A named type rather than a method argument list because the
/// cleartext has to be threaded through [`Command::secret_arg`], and a
/// caller should have to see that.
#[derive(Debug)]
pub struct AddPassword;

impl AddPassword {
    /// Why this command's value is on the wrong channel.
    ///
    /// Left as a constant so that grepping for it finds the finding and
    /// not just a comment. See the module docs.
    #[must_use]
    pub const fn stdin_note() -> &'static str {
        "security add-generic-password takes the cleartext in argv (-w <value>), \
         which is visible in `ps` for the life of the child. Every other secret \
         path in agentcage uses stdin. Moving this one needs a Mac to verify \
         security(1)'s behaviour with a bare -w; see PR E2b."
    }
}

/// The `security` CLI.
#[derive(Debug)]
pub struct Security<'a> {
    runner: &'a dyn CommandRunner,
}

impl<'a> Security<'a> {
    /// A `security` wrapper.
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Self { runner }
    }

    /// The account name for a cage's key: `<cage>.<KEY>`.
    #[must_use]
    pub fn account(cage: &str, key: &str) -> String {
        format!("{cage}.{key}")
    }

    /// `security add-generic-password -s agentcage -a <account> -w <value> -U`.
    ///
    /// `-U` updates an existing item instead of failing on a duplicate.
    ///
    /// The value is a [`Command::secret_arg`], so it is redacted
    /// everywhere this crate prints a command -- and it is still in
    /// argv, which is the problem described in the module docs and in
    /// [`AddPassword::stdin_note`].
    #[must_use]
    pub fn add_command(target: &KeychainTarget, account: &str, value: &str) -> Command {
        target
            .command(["add-generic-password", "-s", SERVICE, "-a", account, "-w"])
            .secret_arg(value)
            .arg("-U")
    }

    /// `security find-generic-password -s agentcage -a <account> -w`.
    ///
    /// The bare `-w` here asks for the password to be *printed*, not
    /// supplied, so nothing secret is in this argv.
    #[must_use]
    pub fn find_command(target: &KeychainTarget, account: &str) -> Command {
        target.command(["find-generic-password", "-s", SERVICE, "-a", account, "-w"])
    }

    /// `security delete-generic-password -s agentcage -a <account>`.
    #[must_use]
    pub fn delete_command(target: &KeychainTarget, account: &str) -> Command {
        target.command(["delete-generic-password", "-s", SERVICE, "-a", account])
    }

    /// Store `value` under `account`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] when `security` refuses -- typically
    /// because the keychain is locked, which
    /// [`interaction_blocked`] identifies.
    pub fn add(
        &self,
        target: &KeychainTarget,
        account: &str,
        value: &str,
    ) -> Result<(), ExecError> {
        let cmd = Self::add_command(target, account, value).captured();
        self.runner.run(&cmd)?.check("security")?;
        Ok(())
    }

    /// Read `account`'s value, or `None` when there is no such item.
    ///
    /// # Errors
    ///
    /// Only if `security` itself could not be run. `KeychainStore.get`
    /// treats every non-zero exit as absence.
    pub fn find(
        &self,
        target: &KeychainTarget,
        account: &str,
    ) -> Result<Option<String>, ExecError> {
        let out = self
            .runner
            .run(&Self::find_command(target, account).captured())?;
        if !out.success() {
            return Ok(None);
        }
        // `r.stdout.rstrip("\n")` -- not `.strip()`: a password may
        // legitimately end in whitespace, and only the line terminator
        // `security` adds should come off.
        Ok(Some(out.stdout_text().trim_end_matches('\n').to_string()))
    }

    /// Delete `account`, ignoring failure.
    ///
    /// # Errors
    ///
    /// Only if `security` itself could not be run.
    pub fn delete(&self, target: &KeychainTarget, account: &str) -> Result<bool, ExecError> {
        Ok(self
            .runner
            .run(&Self::delete_command(target, account).captured())?
            .success())
    }

    /// Whether secrets can really be written to `target`.
    ///
    /// Adds a throwaway item and deletes it again. A *read* probe is not
    /// enough: the login keychain answers reads over a headless SSH
    /// session and then refuses writes with "interaction is not
    /// allowed", so only an actual add reflects whether this target is
    /// usable.
    ///
    /// The probe's own `-w x` is a literal, not a credential.
    ///
    /// # Errors
    ///
    /// Only if `security` itself could not be run.
    pub fn writable(&self, target: &KeychainTarget) -> Result<bool, ExecError> {
        let add = target
            .command([
                "add-generic-password",
                "-s",
                SERVICE,
                "-a",
                PROBE_ACCOUNT,
                "-w",
                "x",
                "-U",
            ])
            .captured();
        if !self.runner.run(&add)?.success() {
            return Ok(false);
        }
        self.runner
            .run(&Self::delete_command(target, PROBE_ACCOUNT).captured())?;
        Ok(true)
    }
}

/// Whether `security` refused because no GUI session could be prompted.
///
/// `secret_store.py::_security_interaction_blocked`. The distinction
/// drives the fall-through from the login keychain to the System
/// keychain, so it is the difference between a headless Mac working and
/// a headless Mac failing closed.
#[must_use]
pub fn interaction_blocked(stderr: &str) -> bool {
    stderr.to_lowercase().contains("interaction is not allowed")
}

#[cfg(test)]
mod tests {
    use super::{KeychainTarget, Security, interaction_blocked};

    #[test]
    fn the_login_target_has_no_prefix_and_no_keychain() {
        assert_eq!(
            Security::find_command(&KeychainTarget::login(), "cage.KEY").argv(),
            [
                "security",
                "find-generic-password",
                "-s",
                "agentcage",
                "-a",
                "cage.KEY",
                "-w"
            ]
        );
    }

    #[test]
    fn the_system_target_adds_sudo_n_and_the_keychain_path() {
        assert_eq!(
            Security::delete_command(&KeychainTarget::system(), "cage.KEY").argv(),
            [
                "sudo",
                "-n",
                "security",
                "delete-generic-password",
                "-s",
                "agentcage",
                "-a",
                "cage.KEY",
                "/Library/Keychains/System.keychain"
            ]
        );
    }

    /// The finding, pinned: the cleartext really is in argv, and this
    /// crate really does keep it out of anything it prints.
    #[test]
    fn the_add_command_carries_the_cleartext_but_never_prints_it() {
        let cmd = Security::add_command(&KeychainTarget::login(), "cage.KEY", "hunter2");
        assert_eq!(
            cmd.argv(),
            [
                "security",
                "add-generic-password",
                "-s",
                "agentcage",
                "-a",
                "cage.KEY",
                "-w",
                "hunter2",
                "-U"
            ]
        );
        assert_eq!(cmd.argv_redacted()[7], "<redacted>");
        assert!(!format!("{cmd:?}").contains("hunter2"));
        assert!(!cmd.display().contains("hunter2"));
    }

    #[test]
    fn the_account_name_is_cage_dot_key() {
        assert_eq!(Security::account("myapp", "API_KEY"), "myapp.API_KEY");
    }

    #[test]
    fn interaction_blocked_is_case_insensitive() {
        assert!(interaction_blocked(
            "SecKeychainItemCreateFromContent: User interaction is not allowed."
        ));
        assert!(interaction_blocked("INTERACTION IS NOT ALLOWED"));
        assert!(!interaction_blocked("The specified item already exists."));
        assert!(!interaction_blocked(""));
    }
}
