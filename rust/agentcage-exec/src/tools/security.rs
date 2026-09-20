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
//! For as long as that child runs, the credential is in `ps -axww`
//! output. On macOS that is `KERN_PROCARGS2`, which XNU's
//! `sysctl_procargsx` refuses to a *different* uid -- so, unlike
//! Linux's world-readable `/proc/<pid>/cmdline`, this is a same-user
//! and root exposure rather than a world-readable one. On the laptop
//! this runs on, "same user" is every other agent session, every MCP
//! server, every `npm` postinstall and anything that samples the
//! process table. That is a real disclosure. `KeychainStore.get` is
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
//! It does not unilaterally switch channels. [`PasswordChannel`] is the
//! seam: [`SHIPPED_PASSWORD_CHANNEL`] is `Argv` and stays `Argv` until
//! someone with a Mac has run `tests/keychain_stdin_probe.rs`.
//!
//! # What PR E2b established about the fix
//!
//! PR D1 left the obvious candidate open: a bare `-w`, value on stdin.
//! E2b researched it against Apple's own sources rather than guessing,
//! and the candidate is **refuted**. What follows is established from
//! shipping source, not inferred.
//!
//! **A bare `-w` does not read stdin.** `SecurityTool/macOS/keychain_add.c`
//! parses with a leading-colon `getopt` string and routes a missing
//! `-w` argument to `promptForPasswordData`, which calls `getpass(3)`.
//! Apple's `getpass` is `readpassphrase(..., RPP_ECHO_OFF)`, and
//! `readpassphrase` opens `/dev/tty` first, falling back to `STDIN_FILENO`
//! only when that open *fails* -- which happens when the process has no
//! controlling terminal at all, not when stdin happens to be a pipe.
//! There is no `isatty` check anywhere in `keychain_add.c`. So the same
//! pipeline succeeds under `launchd` or `ssh` without `-t` and hangs on
//! a developer's terminal.
//!
//! **It also prompts twice** -- "password data for new item:" then
//! "retype password for new item:" -- and compares, so a one-line pipe
//! is wrong even where the pipe is read.
//!
//! **And it fails silently.** `readpassphrase` returns its buffer
//! unless `read` returned `-1`; EOF returns `0`. So on EOF `getpass`
//! hands back `""`, the two prompts both get `""`, they match, and
//! `security` **stores an empty password and exits 0**. A "fix" with
//! that failure mode is worse than the exposure it closes.
//!
//! Two more limits of that path: `_PASSWORD_LEN` is 128, so a longer
//! secret is truncated without warning, and only a *trailing* `-w`
//! prompts at all -- `-w -a acct` stores the literal `-a`.
//!
//! # The channel that does work
//!
//! `security -i` reads command *lines* from stdin, splits them in
//! process, and dispatches to the same `keychain_add_generic_password`.
//! The kernel's argv -- the thing `ps` reads via `KERN_PROCARGS2` --
//! stays `security -i`. `SecurityTool/macOS/security.c` even suppresses
//! its `security>` prompt when `!isatty(0)`, so the piped case is
//! designed for.
//!
//! That is [`PasswordChannel::Interactive`], and it is written here,
//! reachable, and asserted as far as a Linux box can assert it. It is
//! **not shipped**, because "the argv is right" is not "the keychain
//! got the bytes": the quoting is ours (`split_line` treats `\` as an
//! escape *inside* single quotes, unlike a POSIX shell), and only a
//! round trip against a real keychain settles it. Its two hazards --
//! a 4096-byte line buffer whose overflow is parsed as the next
//! command, and a reader that breaks on `\n` -- are refusals here, not
//! truncations; see [`InteractiveRefusal`].
//!
//! # The better fix, and why it is not this PR
//!
//! Stop shelling out. `SecItemAdd`/`SecItemUpdate` through the Security
//! framework is what `git-credential-osxkeychain` does: no argv, no
//! line buffer, no quoting surface, real `OSStatus` errors. That is a
//! new dependency and a new platform-specific code path -- a bigger
//! decision than a port PR should make on its own, and it is written
//! down in [`AddPassword::how_to_settle_it`] so it is on the table when
//! someone makes it.
//!
//! # Sources
//!
//! Everything above marked established comes from shipping source, not
//! from a blog post or an answer site:
//!
//! * `apple-oss-distributions/Security`, `SecurityTool/macOS/keychain_add.c`
//!   -- the `":a:c:C:D:G:j:l:s:p:w:X:UAT:h"` getopt string, the `case
//!   ':'` branch, and `promptForPasswordData`'s two `getpass` calls.
//! * `apple-oss-distributions/Security`, `SecurityTool/macOS/security.c`
//!   -- `do_interactive`, `MAX_LINE_LEN 4096`, `MAX_ARGS 32`,
//!   `split_line`, and the `isatty(0)` that suppresses the prompt.
//!   `SecurityTool/macOS/readline.c` is its 40-line reader; it is not
//!   GNU readline.
//! * `apple-oss-distributions/Security`, `SecurityTool/macOS/security.1`
//!   -- "`-w password` Specify password to be added. Put at end of
//!   command to be prompted (recommended)". The man page never mentions
//!   stdin, and there is no `-w -`, no fd form, and no file form; `-X`
//!   is hex *in argv* and so is not an escape either.
//! * `apple-oss-distributions/Libc`, `gen/FreeBSD/readpassphrase.c` and
//!   `gen/FreeBSD/getpass.3` -- the `/dev/tty`-then-stdin fallback,
//!   `RPP_ECHO_OFF` without `RPP_STDIN` or `RPP_REQUIRE_TTY`, the
//!   `return(nr == -1 ? NULL : buf)` that turns EOF into `""`, and
//!   `_PASSWORD_LEN` 128.
//! * `apple-oss-distributions/xnu`, `bsd/kern/kern_sysctl.c` --
//!   `sysctl_procargsx`'s uid check.
//! * `git/git`, `contrib/credential/osxkeychain/git-credential-osxkeychain.c`
//!   -- `SecItemAdd`/`SecItemUpdate` and `getline` on stdin, with no
//!   `execv` of `/usr/bin/security` anywhere in the file. The reference
//!   design.
//!
//! No CVE or Apple advisory covers the argv exposure; it is treated as
//! a CLI-design limitation. Detection vendors do rule on the read side
//! (MITRE ATT&CK T1555.001), which is further evidence that `security`
//! argv is routinely observable.

use std::fmt;

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

/// The write probe's password. A literal, not a credential.
pub const PROBE_VALUE: &str = "x";

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
        self.with_keychain(self.base().args(args))
    }

    /// `security`, or `sudo -n security`, with no arguments yet.
    ///
    /// Split out of [`KeychainTarget::command`] because
    /// `add-generic-password` has to interleave a
    /// [`Command::secret_arg`] -- or a stdin payload -- between its
    /// flags, and the keychain path still has to land after *all* of
    /// them.
    fn base(&self) -> Command {
        if self.sudo {
            Command::new("sudo").args(["-n", "security"])
        } else {
            Command::new("security")
        }
    }

    /// Append the keychain path, if this target has one.
    ///
    /// Last, after every flag *and* every flag's value. Anything
    /// appended after this call lands behind the path, which is exactly
    /// how the System-keychain `add` argv came out scrambled before PR
    /// E2b -- `-w /Library/Keychains/System.keychain <CLEARTEXT> -U`,
    /// which would have stored the keychain path as the password and
    /// handed the credential to `security` as a positional argument.
    /// See `the_system_keychain_add_keeps_the_path_last`.
    fn with_keychain(&self, cmd: Command) -> Command {
        match &self.keychain {
            Some(path) => cmd.arg(path),
            None => cmd,
        }
    }
}

/// Which channel `add-generic-password` carries the cleartext on.
///
/// **This enum is the seam.** [`SHIPPED_PASSWORD_CHANNEL`] is what
/// agentcage actually runs and it is [`PasswordChannel::Argv`]: the
/// Python's behaviour, the known exposure, deliberately unchanged.
/// [`PasswordChannel::Interactive`] is the prepared fix -- written,
/// reachable and asserted -- but not shipped, because the last mile is
/// a round trip against a real keychain and there is no Mac here.
///
/// There is no bare-`-w`-on-stdin variant. That was the obvious
/// candidate and PR E2b's research **refuted** it; see the module docs.
///
/// Settling it is **one line**: change [`SHIPPED_PASSWORD_CHANNEL`].
/// Every consumer -- [`Security::add`], [`Security::writable`] and the
/// CLI's `KeychainStore` -- already reads the channel from there rather
/// than hard-coding a shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PasswordChannel {
    /// `-w <cleartext>`. The value is an argv element, and therefore in
    /// `ps` for the life of the child. **This is what ships.**
    #[default]
    Argv,
    /// `security -i`, with the whole `add-generic-password` command
    /// line -- value included -- written to the child's stdin.
    ///
    /// `security(1)`'s interactive mode reads command lines from stdin
    /// and splits them **in process**. The kernel's argv, the one `ps`
    /// reads, stays `security -i`. **Not shipped**; see
    /// [`PasswordChannel`] and [`AddPassword::how_to_settle_it`].
    Interactive,
}

/// The channel agentcage actually uses today.
///
/// One `const`, one decision. A Mac owner who has run the probe in
/// `tests/keychain_stdin_probe.rs` flips this and nothing else.
pub const SHIPPED_PASSWORD_CHANNEL: PasswordChannel = PasswordChannel::Argv;

/// `security(1)`'s interactive line buffer, from `SecurityTool/macOS/security.c`:
/// `#define MAX_LINE_LEN 4096`.
///
/// A longer line is **silently truncated at 4095 bytes**, and the
/// remainder stays in stdin and is parsed as the next command -- which
/// both corrupts the item and prints a fragment of the secret to stderr
/// as `unknown command`. So the channel refuses rather than truncates.
pub const MAX_INTERACTIVE_LINE: usize = 4096;

/// Why a value cannot travel on [`PasswordChannel::Interactive`].
///
/// Both cases are properties of `security -i`'s line-oriented reader,
/// not of the keychain, and both are silent corruption if they are not
/// caught here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractiveRefusal {
    /// The value contains `\n` or `\r`. `security -i`'s reader breaks
    /// on both, so the tail of the value would be read as a command.
    LineTerminator,
    /// The command line would exceed [`MAX_INTERACTIVE_LINE`].
    TooLong {
        /// The length the line came to.
        len: usize,
    },
}

impl fmt::Display for InteractiveRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTerminator => f.write_str(
                "this secret contains a line terminator, which `security -i` \
                 cannot carry: its reader breaks on \\n and \\r and would run \
                 the rest of the value as a command",
            ),
            Self::TooLong { len } => write!(
                f,
                "this secret makes a {len}-byte `security -i` command line, over \
                 the {MAX_INTERACTIVE_LINE}-byte buffer; `security` would truncate \
                 it silently and echo the remainder to stderr"
            ),
        }
    }
}

/// An `add-generic-password` invocation.
///
/// A named type rather than a method argument list because the
/// cleartext has to be threaded through [`Command::secret_arg`] or onto
/// stdin, and a caller should have to see that.
#[derive(Debug)]
pub struct AddPassword;

impl AddPassword {
    /// Quote a value for `security -i`'s `split_line`.
    ///
    /// `split_line` (`SecurityTool/macOS/security.c`) treats `'` and
    /// `"` as quotes and `\` as an escape **in both quoted and unquoted
    /// state**. Single quotes plus `\` -> `\\` and `'` -> `\'` is
    /// therefore exact, and unlike POSIX shell quoting a backslash
    /// inside single quotes *is* significant, which is the trap.
    #[must_use]
    pub fn quote(value: &str) -> String {
        let mut out = String::with_capacity(value.len() + 2);
        out.push('\'');
        for ch in value.chars() {
            if ch == '\\' || ch == '\'' {
                out.push('\\');
            }
            out.push(ch);
        }
        out.push('\'');
        out
    }

    /// The command line a [`PasswordChannel::Interactive`] `add` writes
    /// to stdin, newline-terminated.
    ///
    /// The same arguments as the argv form, in the same order, with the
    /// keychain path still last -- `security -i` hands the split line to
    /// the very same `keychain_add_generic_password`, so the parsing
    /// rules do not change.
    ///
    /// # Errors
    ///
    /// [`InteractiveRefusal`] for a value this channel cannot carry
    /// without silently corrupting it.
    pub fn interactive_line(
        target: &KeychainTarget,
        account: &str,
        value: &str,
    ) -> Result<String, InteractiveRefusal> {
        if value.contains('\n') || value.contains('\r') {
            return Err(InteractiveRefusal::LineTerminator);
        }
        let mut line = format!(
            "add-generic-password -s {SERVICE} -a {} -w {} -U",
            Self::quote(account),
            Self::quote(value),
        );
        if let Some(path) = &target.keychain {
            line.push(' ');
            line.push_str(&Self::quote(path));
        }
        line.push('\n');
        if line.len() > MAX_INTERACTIVE_LINE {
            return Err(InteractiveRefusal::TooLong { len: line.len() });
        }
        Ok(line)
    }

    /// Why this command's value is on the wrong channel.
    ///
    /// Left as a function rather than a comment so that grepping for
    /// the finding lands on something the compiler keeps honest. See
    /// the module docs.
    #[must_use]
    pub const fn stdin_note() -> &'static str {
        "security add-generic-password takes the cleartext in argv (-w <value>), \
         which is visible in `ps` to any process of the same user and to root \
         for the life of the child. Every other secret path in agentcage uses \
         stdin. Piping to a bare -w does NOT fix it -- that path is getpass(3), \
         which reads /dev/tty -- so the fix is PasswordChannel::Interactive, \
         which is written and reachable but not shipped: it still needs one \
         round trip against a real keychain. See AddPassword::how_to_settle_it."
    }

    /// What a Mac owner has to do to settle it, in order.
    ///
    /// Written down here so the procedure travels with the code rather
    /// than with a PR description nobody will find again.
    #[must_use]
    pub const fn how_to_settle_it() -> &'static str {
        "On a Mac with an unlocked login keychain:\n\
         1. cargo test -p agentcage-exec --test keychain_stdin_probe -- --ignored --nocapture\n\
         2. Read what it prints. It writes through PasswordChannel::Interactive \
            (`security -i`, the command line on stdin), reads the value back with \
            `security find-generic-password -w`, and compares -- including a value \
            full of quotes and backslashes, which is where the quoting is decided. \
            It also demonstrates, in the same run, that piping to a bare `-w` is \
            NOT a fix.\n\
         3. If every round trip is exact, change SHIPPED_PASSWORD_CHANNEL to \
            PasswordChannel::Interactive. That is the whole fix.\n\
         4. If a round trip is not exact, leave SHIPPED_PASSWORD_CHANNEL alone and \
            record what it printed here. The exposure is known and bounded; a \
            guess that corrupts `cage secret set` on macOS is worse.\n\
         5. Either way, mirror the decision onto secret_store.py:226, which is the \
            code that is actually shipping today.\n\
         The better fix, and a bigger decision than this PR: stop shelling out. \
         SecItemAdd/SecItemUpdate through the Security framework is what \
         git-credential-osxkeychain does, and it has no argv, no 4096-byte line, \
         no quoting surface and real OSStatus errors."
    }
}

/// The `security` CLI.
#[derive(Debug)]
pub struct Security<'a> {
    runner: &'a dyn CommandRunner,
    channel: PasswordChannel,
}

impl<'a> Security<'a> {
    /// A `security` wrapper on the shipped password channel.
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Self {
            runner,
            channel: SHIPPED_PASSWORD_CHANNEL,
        }
    }

    /// The same wrapper, forced onto a particular
    /// [`PasswordChannel`].
    ///
    /// For the Mac probe and for tests that assert both shapes.
    /// Production never calls this: it takes the channel from
    /// [`SHIPPED_PASSWORD_CHANNEL`], which is the one place the
    /// decision lives.
    #[must_use]
    pub fn with_password_channel(mut self, channel: PasswordChannel) -> Self {
        self.channel = channel;
        self
    }

    /// Which channel this wrapper puts the cleartext on.
    #[must_use]
    pub fn password_channel(&self) -> PasswordChannel {
        self.channel
    }

    /// The account name for a cage's key: `<cage>.<KEY>`.
    #[must_use]
    pub fn account(cage: &str, key: &str) -> String {
        format!("{cage}.{key}")
    }

    /// An [`InteractiveRefusal`], as the error a caller already
    /// handles.
    ///
    /// [`ExecError::Failed`] rather than a new variant: the CLI turns
    /// it into `keychain add failed: <reason>`, which is the message an
    /// operator wants, and the reason really is "this add cannot
    /// succeed". The command has not run, so the status is synthetic --
    /// noted here rather than hidden. A shipping
    /// [`PasswordChannel::Interactive`] should give this its own
    /// variant; [`ExecError`] is `#[non_exhaustive]` precisely so it
    /// can.
    fn refused(refusal: InteractiveRefusal) -> ExecError {
        ExecError::Failed {
            program: "security".to_string(),
            status: crate::outcome::ExitStatus::exited(1),
            stderr: refusal.to_string(),
        }
    }

    /// `security add-generic-password -s agentcage -a <account> -w <value> -U`,
    /// on the shipped channel.
    ///
    /// `-U` updates an existing item instead of failing on a duplicate.
    ///
    /// The value is a [`Command::secret_arg`], so it is redacted
    /// everywhere this crate prints a command -- and it is still in
    /// argv, which is the problem described in the module docs and in
    /// [`AddPassword::stdin_note`].
    ///
    /// # Errors
    ///
    /// Nothing, while [`SHIPPED_PASSWORD_CHANNEL`] is
    /// [`PasswordChannel::Argv`] -- that channel refuses no value.
    /// Fallible anyway, because the whole point of the seam is that the
    /// const changes, and a `Result` here is what makes that change
    /// compile-checked rather than a latent panic.
    pub fn add_command(
        target: &KeychainTarget,
        account: &str,
        value: &str,
    ) -> Result<Command, InteractiveRefusal> {
        Self::add_command_via(SHIPPED_PASSWORD_CHANNEL, target, account, value)
    }

    /// The same command on an explicit [`PasswordChannel`].
    ///
    /// The two shapes:
    ///
    /// ```text
    /// Argv:         security add-generic-password -s agentcage -a A -w <CLEARTEXT> -U [keychain]
    /// Interactive:  security -i
    ///               with `add-generic-password -s agentcage -a 'A' -w '<CLEARTEXT>' -U ['keychain']`
    ///               on stdin
    /// ```
    ///
    /// The keychain path is last in both -- in argv for the first, on
    /// the stdin line for the second -- because `security -i` hands its
    /// split line to the same parser.
    ///
    /// # Errors
    ///
    /// [`InteractiveRefusal`], on the interactive channel only, for a
    /// value its line-oriented reader would silently corrupt.
    pub fn add_command_via(
        channel: PasswordChannel,
        target: &KeychainTarget,
        account: &str,
        value: &str,
    ) -> Result<Command, InteractiveRefusal> {
        Self::add_argv(channel, target, account, value, true)
    }

    /// `add-generic-password`, with `secret` saying whether `value` is
    /// credential material.
    ///
    /// [`Security::writable`]'s probe passes `false`: its `-w x` is a
    /// literal, and marking it secret would redact a constant out of
    /// every argv assertion for no gain.
    fn add_argv(
        channel: PasswordChannel,
        target: &KeychainTarget,
        account: &str,
        value: &str,
        secret: bool,
    ) -> Result<Command, InteractiveRefusal> {
        Ok(match channel {
            PasswordChannel::Argv => {
                let flags = target.base().args([
                    "add-generic-password",
                    "-s",
                    SERVICE,
                    "-a",
                    account,
                    "-w",
                ]);
                let cmd = if secret {
                    flags.secret_arg(value).arg("-U")
                } else {
                    flags.arg(value).arg("-U")
                };
                target.with_keychain(cmd)
            }
            PasswordChannel::Interactive => {
                // `-i` and nothing else. The keychain path, the account
                // and the value are all on the stdin line, so
                // `with_keychain` deliberately does not apply here.
                let line = AddPassword::interactive_line(target, account, value)?;
                let cmd = target.base().arg("-i");
                if secret {
                    cmd.stdin_secret(line)
                } else {
                    cmd.stdin_text(line)
                }
            }
        })
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
        let cmd = Self::add_command_via(self.channel, target, account, value)
            .map_err(Self::refused)?
            .captured();
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
    /// The probe's own `-w x` is a literal, not a credential, so it
    /// stays a plain argument on both channels.
    ///
    /// It does follow [`Security::password_channel`], though. If the
    /// probe kept using argv while `set` moved to stdin, a Mac could
    /// report the keychain available and then fail every `secret set`;
    /// the probe has to exercise the shape production will use.
    ///
    /// # Errors
    ///
    /// Only if `security` itself could not be run.
    pub fn writable(&self, target: &KeychainTarget) -> Result<bool, ExecError> {
        let add = Self::add_argv(self.channel, target, PROBE_ACCOUNT, PROBE_VALUE, false)
            .map_err(Self::refused)?
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
    use super::SYSTEM_KEYCHAIN;
    use super::{
        AddPassword, InteractiveRefusal, KeychainTarget, MAX_INTERACTIVE_LINE, PasswordChannel,
        SHIPPED_PASSWORD_CHANNEL, Security, interaction_blocked,
    };
    use crate::command::Stdin;

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
        let cmd = Security::add_command(&KeychainTarget::login(), "cage.KEY", "hunter2").unwrap();
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

    /// **The ordering bug PR E2b found and fixed.**
    ///
    /// `KeychainTarget::command` appends the keychain path, so anything
    /// chained *after* that call lands behind it. `add_command` used to
    /// chain `.secret_arg(value).arg("-U")` onto `target.command(...)`,
    /// which on the System-keychain target produced
    ///
    /// ```text
    /// sudo -n security add-generic-password -s agentcage -a A \
    ///      -w /Library/Keychains/System.keychain <CLEARTEXT> -U
    /// ```
    ///
    /// -- the keychain path stored as the password, the credential
    /// handed to `security` as a positional argument, and `-U` after
    /// both. The login target hid it, because its keychain is `None`
    /// and nothing was appended. Every previous argv assertion for
    /// `add` used the login target.
    ///
    /// The Python is `argv + ["-w", value, "-U"]` and then
    /// `argv.append(kc)`, so this is a port-fidelity fix, not a
    /// behaviour change: no `-w` on any channel may be followed by the
    /// keychain path.
    #[test]
    fn the_system_keychain_add_keeps_the_path_last() {
        let argv = Security::add_command_via(
            PasswordChannel::Argv,
            &KeychainTarget::system(),
            "acme.K",
            "hunter2",
        )
        .unwrap()
        .argv();
        assert_eq!(
            argv.last().map(String::as_str),
            Some(SYSTEM_KEYCHAIN),
            "the keychain path must be the last argument"
        );
        // `-w` is followed by the value, never by the keychain path.
        let after_w = argv.iter().position(|a| a == "-w").expect("a -w") + 1;
        assert_ne!(
            argv[after_w], SYSTEM_KEYCHAIN,
            "`-w` swallowed the keychain path"
        );
        assert_eq!(
            argv.iter().filter(|a| *a == SYSTEM_KEYCHAIN).count(),
            1,
            "the path appears once, at the end"
        );

        // And on the interactive channel it is last on the *line*.
        let line =
            AddPassword::interactive_line(&KeychainTarget::system(), "acme.K", "hunter2").unwrap();
        assert_eq!(
            line,
            "add-generic-password -s agentcage -a 'acme.K' -w 'hunter2' -U \
             '/Library/Keychains/System.keychain'\n"
        );

        assert_eq!(
            Security::add_command(&KeychainTarget::system(), "acme.K", "hunter2")
                .unwrap()
                .argv(),
            [
                "sudo",
                "-n",
                "security",
                "add-generic-password",
                "-s",
                "agentcage",
                "-a",
                "acme.K",
                "-w",
                "hunter2",
                "-U",
                SYSTEM_KEYCHAIN,
            ]
        );
    }

    /// The decision is still unmade, and this is what says so.
    ///
    /// If it is ever made, this test is the thing that fails -- which
    /// is the point. Flipping `SHIPPED_PASSWORD_CHANNEL` without
    /// having run the probe on a Mac should not be quiet.
    #[test]
    fn the_shipped_channel_is_still_argv() {
        assert_eq!(SHIPPED_PASSWORD_CHANNEL, PasswordChannel::Argv);
        assert_eq!(
            Security::new(&crate::FakeRunner::new()).password_channel(),
            PasswordChannel::Argv
        );
        assert!(AddPassword::stdin_note().contains("not shipped"));
        assert!(AddPassword::how_to_settle_it().contains("keychain_stdin_probe"));
    }

    /// The prepared fix, asserted on Linux so that the only thing a Mac
    /// has to establish is what the keychain does with it -- not
    /// whether the command this crate would build is the right one.
    #[test]
    fn the_interactive_channel_moves_the_value_off_argv() {
        let cmd = Security::add_command_via(
            PasswordChannel::Interactive,
            &KeychainTarget::login(),
            "acme.K",
            "hunter2",
        )
        .unwrap();
        assert_eq!(
            cmd.argv(),
            ["security", "-i"],
            "the kernel's argv, which is what `ps` reads"
        );
        assert_eq!(cmd.secret_arg_indices(), [] as [usize; 0]);
        assert_eq!(
            cmd.stdin_bytes_ref(),
            Some(b"add-generic-password -s agentcage -a 'acme.K' -w 'hunter2' -U\n".as_slice())
        );
        assert!(
            matches!(cmd.stdin_spec(), Stdin::Bytes { secret: true, .. }),
            "and marked secret, so nothing prints it"
        );
        assert!(!format!("{cmd:?}").contains("hunter2"));
        assert!(!cmd.display().contains("hunter2"));
    }

    /// `split_line` treats `\\` as an escape **inside** quotes, unlike a
    /// POSIX shell. A value full of quotes and backslashes is where
    /// that difference bites, so it is spelled out rather than trusted.
    #[test]
    fn the_interactive_line_escapes_quotes_and_backslashes() {
        assert_eq!(AddPassword::quote("plain"), "'plain'");
        assert_eq!(AddPassword::quote("it's"), r"'it\'s'");
        assert_eq!(AddPassword::quote(r"a\b"), r"'a\\b'");
        assert_eq!(AddPassword::quote(r#"a"b"#), r#"'a"b'"#);
        assert_eq!(AddPassword::quote(""), "''");

        let line =
            AddPassword::interactive_line(&KeychainTarget::login(), "acme.K", r"p'w\x").unwrap();
        assert_eq!(
            line,
            "add-generic-password -s agentcage -a 'acme.K' -w 'p\\'w\\\\x' -U\n"
        );
    }

    /// The two ways `security -i` would silently corrupt a value, both
    /// refused rather than truncated.
    ///
    /// Its reader breaks on `\n` and `\r` and leaves the remainder in
    /// stdin to be parsed as the next command -- which both stores the
    /// wrong bytes and echoes a fragment of the secret to stderr as
    /// `unknown command`. And its line buffer is 4096 bytes, with the
    /// same consequence on overflow.
    #[test]
    fn the_interactive_channel_refuses_what_it_cannot_carry() {
        let login = KeychainTarget::login();
        assert_eq!(
            AddPassword::interactive_line(&login, "acme.K", "two\nlines"),
            Err(InteractiveRefusal::LineTerminator)
        );
        assert_eq!(
            AddPassword::interactive_line(&login, "acme.K", "carriage\rreturn"),
            Err(InteractiveRefusal::LineTerminator)
        );

        let long = "A".repeat(MAX_INTERACTIVE_LINE);
        assert!(matches!(
            AddPassword::interactive_line(&login, "acme.K", &long),
            Err(InteractiveRefusal::TooLong { .. })
        ));

        // The refusal reaches a caller as a failed add, with the reason
        // in the place the CLI already prints.
        let fake = crate::FakeRunner::new();
        let err = Security::new(&fake)
            .with_password_channel(PasswordChannel::Interactive)
            .add(&login, "acme.K", "two\nlines")
            .unwrap_err();
        assert!(err.to_string().contains("line terminator"), "{err}");
        assert_eq!(fake.call_count(), 0, "nothing ran");
    }

    /// The probe follows the channel, so `available()` cannot pass on a
    /// shape `set` would not use -- but its `x` stays a plain argument,
    /// because it is a literal and redacting it would blank a constant
    /// out of every argv assertion.
    #[test]
    fn the_write_probe_follows_the_channel_but_is_not_a_secret() {
        let fake = crate::FakeRunner::new();
        fake.push(crate::fake::Reply::success());
        fake.push(crate::fake::Reply::success());
        Security::new(&fake)
            .with_password_channel(PasswordChannel::Interactive)
            .writable(&KeychainTarget::login())
            .unwrap();
        let add = fake.call(0);
        assert_eq!(add.raw_argv(), ["security", "-i"]);
        assert_eq!(
            add.stdin_bytes(),
            Some(
                b"add-generic-password -s agentcage -a '__agentcage_probe__' -w 'x' -U\n"
                    .as_slice()
            )
        );
        assert_eq!(*add.command.secret_arg_indices(), [] as [usize; 0]);
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
