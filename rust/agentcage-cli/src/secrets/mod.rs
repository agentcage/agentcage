//! Where a cage's secrets come from, and where they are kept.
//!
//! The port of two Python modules that only make sense together:
//!
//! | Python | here |
//! | :-- | :-- |
//! | `secret_resolver.py` | [`resolver`] -- read a value out of a `source:` scheme, and drive `systemd-creds` |
//! | `secret_store.py` | [`store`] -- the four at-rest backends, and the fail-closed choice between them |
//!
//! The parse-time halves of `secret_resolver` are *not* here:
//! `validate_env_name`, `validate_source` and the `secrets.backend` /
//! `secrets.scope` enum checks landed with PR C2 in
//! [`agentcage_core::config::secret`], because they are pure value
//! checks that `load_config` makes and the golden corpus pins their
//! messages. What is left -- and what this module is -- is everything
//! that needs the outside world: an environment variable, a subprocess,
//! a file.
//!
//! # The one rule
//!
//! **A secret value travels on stdin, never in argv.** Anything in argv
//! is readable through `/proc/<pid>/cmdline`, and on macOS through
//! `ps -ww`, by any process of the same user and by root, for as long as
//! the child lives. [`agentcage_exec::Command::stdin_secret`] is the
//! right channel and every store here uses it -- with one exception,
//! reproduced deliberately and described in
//! [`agentcage_exec::tools::security`]: `security add-generic-password`
//! takes the cleartext as `-w <value>`. PR D1 found it, marked it with
//! [`agentcage_exec::Command::secret_arg`] so it is redacted from every
//! dump this workspace produces, and pinned it in a test. PR D3 does not
//! undo either. Moving that value to stdin needs a Mac to observe what
//! `security(1)` does with a bare `-w` and a non-tty stdin; that is PR
//! E2b's call to make, with a keychain in front of it.
//!
//! # A second path, found by this PR, which is not this module's
//!
//! D1 audited the secret *stores* and found one violation. Auditing the
//! rest of the tree turned up a second, on a path no store touches:
//! **`container.env:` values are `os.path.expandvars`-expanded and then
//! put in argv.**
//!
//! `quadlets.py:781` expands `${VAR}` in every `container.env` entry
//! while generating the unit. On the container and vm backends that
//! becomes `Environment="KEY=<expanded>"` in the quadlet
//! (`templates/cage.container.j2:43`), which podman's system generator
//! turns into `podman run --env KEY=<cleartext>`; on apple-container
//! `apple_container.py:1324` expands it, persists it to the unit's
//! metadata JSON, and re-emits it as `container run … -e
//! KEY=<cleartext>` at every `start()` (`apple_container.py:1763`). The
//! vm backend additionally base64s the generated quadlet into a
//! `bash -c` argv on both sides of `limactl shell` (`vm.py:786`), and
//! base64 is not encryption.
//!
//! It is narrower than it sounds, because `config.py:1101` already
//! strips any `container.env` key that is also a `secret_injection`
//! env, with a comment saying exactly why. So a *declared* secret never
//! reaches it. The gap is the undeclared one -- an operator who writes
//! `env: {GITHUB_TOKEN: "$GITHUB_TOKEN"}` and no rule gets no warning
//! and a cleartext credential in the process table and in a unit file
//! on disk.
//!
//! Nothing here fixes it: `container.env` expansion is PR C8's module
//! (quadlets) and PR E2/E3's (the apple backend), and the fix is a
//! policy decision -- warn, refuse, or route it through the placeholder
//! scheme -- rather than a porting question. It is written down here
//! because this is where the rule it breaks is stated.
//!
//! One more, on the operator's side rather than agentcage's:
//! `agentcage cage create -s KEY=VALUE` and `run --set-secret
//! KEY=VALUE` put the cleartext in **agentcage's own** argv and in the
//! shell history. The bare-`KEY` form prompts with `hide_input=True`
//! instead, and nothing steers an operator towards it.
//!
//! The rule extends past argv, because a credential leaks just as well
//! through a `Debug` impl, a log line or a panic message. So:
//!
//! * [`resolver::Resolution::Resolved`] carries the cleartext and prints
//!   as `<redacted N bytes>`.
//! * [`SecretError`] is built from names, paths and exit codes. No
//!   variant is constructed from a secret value, and
//!   `tests/secrets_redaction.rs` walks every error path to check it.
//! * [`resolver::Environment`]'s test double prints its keys, not its
//!   values.
//!
//! # What holds the pieces together
//!
//! [`resolver::SecretHost`] is the host's secret facilities: the
//! `CommandRunner` to shell out with, the environment to read, whether
//! the invoker is root, and the two memoized capability answers
//! (`detect_default_backend`, `detect_default_scope`) that Python gets
//! from `functools.lru_cache`. The stores borrow one.
//!
//! [`store::resolve_store`] is the fail-closed choice between the four
//! backends. It is the function to read first if you are trying to work
//! out which store a given `cage.yaml` gets.

pub mod resolver;
pub mod store;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

pub use resolver::{Backend, Environment, MapEnv, Resolution, SecretHost, SystemEnv};
pub use store::{
    ApplePlaintextStore, KeychainStore, PlaintextStore, Platform, PodmanSecrets, SecretStore,
    SystemdCredsStore, plaintext_store_for, resolve_store,
};

/// Why a secret could not be resolved, stored or retrieved.
///
/// Python raises two types here and `cli._store_secret` catches them in
/// one `except (SecretStoreError, ValueError)`, so the split does no
/// work at the call sites that matter. It is kept as two *variants*
/// rather than two types because one place does read it:
/// `resolve_store` raises only `SecretStoreError`, and `_store_secret`
/// answers that with a different message and a different hint than a
/// failure to store. [`SecretError::is_store_error`] is that question.
///
/// # No variant carries a secret
///
/// Every message is built from a key name, a path, an exit code or a
/// child's stderr. That is a property worth stating because it is what
/// makes `{e}` safe at the ~20 call sites in `cli.py` that interpolate
/// one into operator-facing output.
///
/// The child's stderr is the interesting case, and it is Python's
/// behaviour reproduced rather than a choice made here: a `cmd:` source
/// whose command writes a credential to *its own stderr* puts it in the
/// message. `secret_resolver.resolve` does exactly that
/// (`command failed (exit {rc}): {r.stderr.strip()}`), and agentcage
/// cannot tell a diagnostic from a leak. Keeping the message is the
/// compatible choice; the alternative -- dropping the stderr -- turns
/// every misconfigured `cmd:` source into an unexplained failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum SecretError {
    /// `SecretStoreError`: a backend is unavailable, refused, or was
    /// asked for something it does not do.
    Store(String),
    /// `ValueError`: a source could not be resolved, or a scope is not
    /// usable.
    Value(String),
    /// A file under the deployment directory could not be read or
    /// written.
    ///
    /// Python lets `OSError` escape from `ApplePlaintextStore._save`
    /// and from `encrypt_secret`'s `mkdir`, and swallows it in the two
    /// readers. Both behaviours survive; this variant is the escaping
    /// half.
    Io {
        /// The file that failed.
        path: PathBuf,
        /// What the OS said.
        source: io::Error,
    },
}

impl SecretError {
    /// A `SecretStoreError`, from anything string-like.
    pub fn store(message: impl Into<String>) -> Self {
        Self::Store(message.into())
    }

    /// A `ValueError`, from anything string-like.
    pub fn value(message: impl Into<String>) -> Self {
        Self::Value(message.into())
    }

    /// An I/O failure against `path`.
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Whether this is the `SecretStoreError` half.
    ///
    /// `cli._store_secret` branches on it: a `resolve_store` refusal
    /// gets the "refusing to store secret" message plus the how-to-fix
    /// paragraph, while a failure from `store.set` may fall back to
    /// plaintext when the operator opted in.
    #[must_use]
    pub fn is_store_error(&self) -> bool {
        matches!(self, Self::Store(_))
    }

    /// The message, without the path prefix an I/O error adds.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Store(m) | Self::Value(m) => m.clone(),
            Self::Io { source, .. } => source.to_string(),
        }
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(m) | Self::Value(m) => f.write_str(m),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for SecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// `p.is_file()`, which is what every reader here gates on.
///
/// Python's `Path.is_file()` answers False for a missing path, a
/// directory and a broken symlink alike, and never raises. `std`'s
/// `Path::is_file` has the same three answers for the same reason, so
/// this is only here to name the intent at the call sites.
pub(crate) fn is_file(path: &Path) -> bool {
    path.is_file()
}
