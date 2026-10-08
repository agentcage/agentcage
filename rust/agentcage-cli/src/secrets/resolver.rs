//! `secret_resolver.py`, minus the parse-time checks C2 already took.
//!
//! Five jobs:
//!
//! 1. **Resolve a `source:` scheme into a value** ([`SecretHost::resolve`]).
//!    `env:` reads the host environment, `cmd:` runs a shell command and
//!    takes its stdout, `systemd-creds:` asserts a `.cred` blob exists
//!    and leaves the decryption to the unit, `podman:` and the empty
//!    scheme mean "already in the store".
//! 2. **Materialize every rule's secret before the unit starts**
//!    ([`SecretHost::resolve_and_populate`]).
//! 3. **Decide whether this host can encrypt at all**
//!    ([`SecretHost::default_backend`]).
//! 4. **Decide which key to encrypt with** ([`SecretHost::default_scope`],
//!    [`SecretHost::resolve_scope`]).
//! 5. **Encrypt** ([`SecretHost::encrypt_secret`]).
//!
//! # Three things the Python does that a straight transcription loses
//!
//! **`functools.lru_cache`.** `detect_default_backend`, `detect_default_scope`
//! and `_systemd_creds_works` are each cached for the life of the
//! process, which is load-bearing rather than decorative: without it,
//! `SystemdCredsStore.available()` re-runs a `systemd-creds encrypt`
//! probe on every call, and `secret set` calls it more than once. A
//! process-global cache in Rust would be a `static` that tests could not
//! reset, so the memo lives on [`SecretHost`] instead -- one per run,
//! one per test.
//!
//! **`os.environ`.** Reading it is easy; *controlling* it from a test is
//! not, because `std::env::set_var` is `unsafe` under the 2024 edition
//! and this workspace forbids `unsafe` outright. So the environment is a
//! trait ([`Environment`]) with a real implementation and a map-backed
//! double, which also means an `env:` test does not mutate global state
//! that another test in the same binary can observe.
//!
//! **`click.echo(..., err=True)`.** The non-strict path prints warnings
//! and continues. Printing from here would make the behaviour
//! untestable without capturing stderr, so the warnings are *returned*
//! ([`Populated::warnings`]) and the command layer prints them with
//! [`crate::output::echo_err`]. The text is unchanged.

use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use agentcage_core::config::types::Config;
use agentcage_exec::tools::creds::{MIN_SYSTEMD_VERSION, Scope, SystemdCreds};
use agentcage_exec::tools::systemctl::Systemctl;
use agentcage_exec::{Command, CommandRunner, ExecError};

use super::SecretError;
use super::store::PodmanSecrets;

/// Somewhere to read environment variables from.
///
/// Exists because `std::env::set_var` is `unsafe` in the 2024 edition
/// and `[workspace.lints.rust] unsafe_code = "forbid"` cannot be
/// overridden -- so an `env:` source could not otherwise be tested at
/// all. Injecting it also keeps `env:` tests from racing each other
/// through the process-wide environment.
pub trait Environment: fmt::Debug {
    /// `os.environ.get(name)`.
    fn get(&self, name: &str) -> Option<String>;
}

/// The real environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEnv;

impl Environment for SystemEnv {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// A fixed environment, for tests.
///
/// Its `Debug` prints the variable *names* and not their values: an
/// `env:` test necessarily puts a credential-shaped string in here, and
/// a failing assertion in a test that holds one should not print it.
#[derive(Default, Clone)]
pub struct MapEnv {
    vars: BTreeMap<String, String>,
}

impl MapEnv {
    /// An empty environment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set one variable.
    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.vars.insert(name.into(), value.into());
        self
    }
}

impl fmt::Debug for MapEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapEnv")
            .field("names", &self.vars.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Environment for MapEnv {
    fn get(&self, name: &str) -> Option<String> {
        self.vars.get(name).cloned()
    }
}

/// What `detect_default_backend` answers.
///
/// Not the same vocabulary as `secrets.backend` in `cage.yaml`: this is
/// a capability probe with two outcomes, and `"podman"` here means "no
/// encrypting backend", which is why `resolve_store`'s fail-closed
/// branch reads it as a refusal rather than as a choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `systemd-creds` is installed, new enough, and can encrypt.
    SystemdCreds,
    /// It cannot. Values would have to go to the podman store in
    /// cleartext.
    Podman,
}

impl Backend {
    /// The string `detect_default_backend` returns.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SystemdCreds => "systemd-creds",
            Self::Podman => "podman",
        }
    }
}

/// What resolving one `source:` produced.
///
/// # The `Debug` impl is part of the contract
///
/// [`Resolution::Resolved`] carries cleartext. A derived `Debug` would
/// put it in every `unwrap()` panic, every `assert_eq!` failure and
/// every `{:?}` a future caller reaches for. This one prints a byte
/// count, the same way [`agentcage_exec::Command`] handles a secret
/// stdin payload. Tests that need the value ask for it with
/// [`Resolution::value`].
#[derive(Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The value is in hand; the caller creates the podman secret.
    Resolved(String),
    /// A `.cred` blob is on disk and the unit decrypts it at start.
    QuadletHandled,
    /// The secret is already in the podman store.
    Existing,
}

impl Resolution {
    /// The cleartext, for the one caller that has to have it.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        match self {
            Self::Resolved(v) => Some(v),
            _ => None,
        }
    }

    /// `ResolveAction`'s string value, which is what the Python enum
    /// carries and what a log line should say instead of the value.
    #[must_use]
    pub fn action(&self) -> &'static str {
        match self {
            Self::Resolved(_) => "resolved",
            Self::QuadletHandled => "quadlet",
            Self::Existing => "existing",
        }
    }
}

impl fmt::Debug for Resolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolved(v) => write!(f, "Resolved(<{} redacted bytes>)", v.len()),
            Self::QuadletHandled => f.write_str("QuadletHandled"),
            Self::Existing => f.write_str("Existing"),
        }
    }
}

/// What [`SecretHost::resolve_and_populate`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Populated {
    /// Env names that were materialized, which the caller adds to
    /// `provided_keys` so they survive the rule-strip filter.
    pub resolved: BTreeSet<String>,
    /// Non-fatal failures, in encounter order, for the `strict=False`
    /// path. Already carrying the `warning: ` prefix Python's
    /// `click.echo` line has, so the caller only chooses a stream.
    pub warnings: Vec<String>,
}

/// The host's secret facilities: a runner, an environment, and the two
/// memoized capability answers.
///
/// One per process in production, one per test. Holding the memo here
/// rather than in a `static` is what makes
/// [`SecretHost::default_backend`] assertable: a test can pin the exact
/// probe sequence, and a second test in the same binary is not affected
/// by the first one's answer.
#[derive(Debug)]
pub struct SecretHost<'a> {
    runner: &'a dyn CommandRunner,
    env: &'a dyn Environment,
    non_root: bool,
    backend: OnceCell<Backend>,
    scope: OnceCell<Option<Scope>>,
}

impl<'a> SecretHost<'a> {
    /// A host with an explicit "is the invoker non-root" answer.
    ///
    /// Taken as an argument rather than read here so a Linux CI runner
    /// can exercise the root branch, which otherwise only happens under
    /// `sudo`.
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner, env: &'a dyn Environment, non_root: bool) -> Self {
        Self {
            runner,
            env,
            non_root,
            backend: OnceCell::new(),
            scope: OnceCell::new(),
        }
    }

    /// A host that reads the real euid.
    ///
    /// `os.geteuid() != 0`. The check is not about permission to run
    /// `systemd-creds` -- root may -- but about *whose* per-user key
    /// would be used: root's is not the operator's, and a credential
    /// encrypted with it could not be decrypted by the user unit that
    /// needs it.
    #[must_use]
    pub fn detect(runner: &'a dyn CommandRunner, env: &'a dyn Environment) -> Self {
        Self::new(runner, env, !nix::unistd::Uid::effective().is_root())
    }

    /// The runner this host shells out with.
    #[must_use]
    pub fn runner(&self) -> &'a dyn CommandRunner {
        self.runner
    }

    // ── capability detection ─────────────────────────────────

    /// `detect_default_backend` -- the best available backend.
    ///
    /// Three conditions in the Python's order, and the order is what a
    /// test pins: the binary must exist, `systemctl --version` must
    /// report at least [`MIN_SYSTEMD_VERSION`], and some scope must
    /// actually encrypt. The last one is not redundant with the first
    /// two: a container host with no TPM, no host key and a root
    /// invoker has a perfectly modern `systemd-creds` that cannot
    /// encrypt anything.
    pub fn default_backend(&self) -> Backend {
        *self.backend.get_or_init(|| {
            let creds = SystemdCreds::new(self.runner);
            if creds.installed()
                && Systemctl::new(self.runner).systemd_version() >= MIN_SYSTEMD_VERSION
                && self.default_scope().is_some()
            {
                Backend::SystemdCreds
            } else {
                Backend::Podman
            }
        })
    }

    /// `detect_default_scope` -- the key `secrets.scope: auto` picks.
    ///
    /// `user` first for a non-root invoker, because the per-user key
    /// needs no polkit round trip; the host key otherwise. `None` when
    /// neither works, which is the fail-closed signal
    /// [`SecretHost::default_backend`] reads.
    pub fn default_scope(&self) -> Option<Scope> {
        *self
            .scope
            .get_or_init(|| SystemdCreds::new(self.runner).detect_scope(self.non_root))
    }

    /// `resolve_scope` -- a configured scope made concrete.
    ///
    /// # Errors
    ///
    /// [`SecretError::Value`] for a scope outside `auto`/`user`/`system`,
    /// and for `auto` on a host where neither key works.
    pub fn resolve_scope(&self, configured: &str) -> Result<Scope, SecretError> {
        match configured {
            "user" => return Ok(Scope::User),
            "system" => return Ok(Scope::System),
            "auto" => {}
            other => {
                return Err(SecretError::value(format!(
                    "invalid secrets.scope: {}",
                    agentcage_core::python::repr_str(other)
                )));
            }
        }
        self.default_scope().ok_or_else(|| {
            SecretError::value(
                "systemd-creds encryption is not usable in either user or \
                 system scope on this host",
            )
        })
    }

    // ── encryption ───────────────────────────────────────────

    /// `encrypt_secret` -- write `<state_dir>/creds/<name>.cred`.
    ///
    /// The value goes on stdin; `--name` carries the *env variable
    /// name*, which systemd binds the decrypted credential to at unit
    /// start and which is not secret. Returns the path written, as the
    /// Python does.
    ///
    /// # Errors
    ///
    /// [`SecretError::Value`] for a scope that is not `user` or
    /// `system`, for the 30s timeout, and for a non-zero exit;
    /// [`SecretError::Io`] when `creds/` could not be created.
    pub fn encrypt_secret(
        &self,
        name: &str,
        value: &str,
        state_dir: &Path,
        scope: Scope,
    ) -> Result<PathBuf, SecretError> {
        let creds_dir = state_dir.join("creds");
        std::fs::create_dir_all(&creds_dir).map_err(|e| SecretError::io(&creds_dir, e))?;
        let out_path = creds_dir.join(format!("{name}.cred"));

        let out = out_path.to_string_lossy().into_owned();
        match SystemdCreds::new(self.runner).encrypt(scope, name, &out, value) {
            Ok(()) => Ok(out_path),
            Err(ExecError::Timeout { .. }) => Err(SecretError::value(
                "systemd-creds encrypt timed out after 30s \
                 (TPM2 may be unavailable or contended)",
            )),
            Err(ExecError::Failed { stderr, .. }) => Err(SecretError::value(format!(
                "systemd-creds encrypt failed: {stderr}"
            ))),
            // `subprocess.run` on a missing binary raises
            // `FileNotFoundError`, which `encrypt_secret` does not
            // catch -- it escapes as-is. Nothing here is reachable
            // without `detect_default_backend` having found the binary
            // first, so this is the "impossible, but say so" arm.
            Err(other) => Err(SecretError::value(format!(
                "systemd-creds encrypt failed: {other}"
            ))),
        }
    }

    // ── resolution ───────────────────────────────────────────

    /// `resolve` -- one `source:` scheme into a [`Resolution`].
    ///
    /// # Errors
    ///
    /// [`SecretError::Value`] for an unset environment variable, an
    /// empty or failing `cmd:`, a missing `.cred` file, or a scheme
    /// that is not one of the five. The last one is unreachable through
    /// a parsed config, because `validate_source` rejects it at
    /// `cage create` time -- it is kept because the Python keeps it,
    /// and because `resolve` is also reachable from a hand-built rule.
    pub fn resolve(
        &self,
        source: &str,
        env_name: &str,
        state_dir: &Path,
    ) -> Result<Resolution, SecretError> {
        // `source.partition(":")` -- the scheme is everything before the
        // first colon and the argument is everything after it, which for
        // `cmd:` means a command containing colons survives intact.
        let (scheme, arg) = match source.split_once(':') {
            Some((scheme, arg)) => (scheme, arg),
            None => (source, ""),
        };

        match scheme {
            "env" => {
                // `arg or env_name`: `env:` with nothing after it reads
                // the variable the rule is named for.
                let var = if arg.is_empty() { env_name } else { arg };
                self.env
                    .get(var)
                    .map(Resolution::Resolved)
                    .ok_or_else(|| SecretError::value(format!("env var '{var}' not set")))
            }
            "cmd" => self.run_cmd_source(arg),
            "systemd-creds" => {
                let cred_file = state_dir.join("creds").join(format!("{env_name}.cred"));
                if !cred_file.exists() {
                    return Err(SecretError::value(format!(
                        "encrypted credential not found: {}",
                        cred_file.display()
                    )));
                }
                Ok(Resolution::QuadletHandled)
            }
            "podman" => Ok(Resolution::Existing),
            "" if source.is_empty() => Ok(Resolution::Existing),
            other => Err(SecretError::value(format!(
                "unknown secret source scheme: '{other}'"
            ))),
        }
    }

    /// `subprocess.run(arg, shell=True, capture_output=True, timeout=30)`.
    ///
    /// `shell=True` on POSIX is `/bin/sh -c <command>`, so that is the
    /// argv -- not the caller's `$SHELL`, and not an argv split here.
    /// The command is operator-authored config, and running it through a
    /// shell is the documented behaviour of the `cmd:` scheme (`pass
    /// show x | head -1` has to work).
    ///
    /// Note what is *not* secret: the command itself is in argv, and
    /// visible in `ps`. That is inherent to the scheme -- an operator
    /// who writes the credential into the command line rather than
    /// having the command fetch it has published it themselves.
    fn run_cmd_source(&self, command: &str) -> Result<Resolution, SecretError> {
        if command.trim().is_empty() {
            return Err(SecretError::value(
                "cmd: source requires a command after 'cmd:'",
            ));
        }
        let cmd = Command::new("/bin/sh")
            .args(["-c", command])
            .captured()
            .timeout(CMD_TIMEOUT);
        let out = match self.runner.run(&cmd) {
            Ok(out) => out,
            Err(ExecError::Timeout { .. }) => {
                return Err(SecretError::value(format!(
                    "command timed out after 30s: {command}"
                )));
            }
            Err(other) => {
                // `subprocess.run` raising anything but `TimeoutExpired`
                // escapes `resolve` uncaught; the caller's
                // `except ValueError` does not see it. There is no
                // Rust equivalent of "escapes uncaught", so it becomes
                // a `ValueError` naming the failure.
                return Err(SecretError::value(format!("command failed: {other}")));
            }
        };
        if !out.success() {
            return Err(SecretError::value(format!(
                "command failed (exit {}): {}",
                out.status.code_or(-1),
                out.stderr_text().trim()
            )));
        }
        // `.rstrip("\n")`, which takes *every* trailing newline, not
        // one, and leaves other trailing whitespace alone -- a password
        // may legitimately end in a space.
        Ok(Resolution::Resolved(
            out.stdout_text().trim_end_matches('\n').to_string(),
        ))
    }

    /// `resolve_and_populate` -- materialize every rule and both agent
    /// API keys into the podman store.
    ///
    /// Returns the env names that were handled, so the caller can keep
    /// them out of the rule-strip filter.
    ///
    /// # Why the agents are in here
    ///
    /// Neither `agents.decider.api_key` nor `agents.watcher.api_key` is
    /// a `secret_injection` rule -- both are egress-only and never
    /// injected into cage traffic -- but `quadlets` emits a `Secret=`
    /// directive for each, and `_boot_resolvable` green-lights `env:`
    /// and `cmd:` schemes *because* this function is expected to
    /// materialize them. Drop this loop and the egress unit references
    /// a podman secret nobody creates, the container dies at start with
    /// `no such secret`, and the whole cage goes with it.
    ///
    /// # Errors
    ///
    /// With `strict`, [`SecretError::Value`] on the first resolution
    /// failure, so `cage create` / `cage start` abort before the unit is
    /// launched with a missing secret. Without it, failures become
    /// [`Populated::warnings`]. A podman failure is always an error:
    /// `strict` is about *resolution*, and the Python's `try` covers
    /// only the `resolve` call.
    pub fn resolve_and_populate(
        &self,
        podman: &dyn PodmanSecrets,
        cfg: &Config,
        deploy_name: &str,
        state_dir: &Path,
        skip: &BTreeSet<String>,
        strict: bool,
    ) -> Result<Populated, SecretError> {
        let mut out = Populated::default();

        for rule in &cfg.secret_injection {
            let source = rule.source.as_str();
            if source.is_empty() || skip.contains(&rule.env) {
                continue;
            }
            let result = match self.resolve(source, &rule.env, state_dir) {
                Ok(result) => result,
                Err(e) => {
                    if strict {
                        return Err(SecretError::value(format!(
                            "failed to resolve secret '{}': {e}",
                            rule.env
                        )));
                    }
                    out.warnings
                        .push(format!("warning: failed to resolve {}: {e}", rule.env));
                    continue;
                }
            };
            Self::store_resolution(podman, deploy_name, &rule.env, &result, &mut out.resolved)?;
        }

        for (enabled, api_key, label) in [
            (
                cfg.agents.decider.enable,
                cfg.agents.decider.llm.api_key.as_str(),
                "agents.decider",
            ),
            (
                cfg.agents.watcher.enable,
                cfg.agents.watcher.llm.api_key.as_str(),
                "agents.watcher",
            ),
        ] {
            if !enabled {
                continue;
            }
            self.resolve_agent_api_key(
                podman,
                api_key,
                label,
                deploy_name,
                state_dir,
                skip,
                strict,
                &mut out,
            )?;
        }

        Ok(out)
    }

    /// `_resolve_agent_api_key` -- one agent's `api_key` source.
    ///
    /// The env name is the *argument* of the scheme, not a rule's
    /// `env:` -- `env:OPENROUTER_API_KEY` names `OPENROUTER_API_KEY`.
    /// A source with no argument at all (a bare `FOO`, or an empty
    /// string) is skipped, which is the Python's `if not arg`.
    #[allow(clippy::too_many_arguments)]
    fn resolve_agent_api_key(
        &self,
        podman: &dyn PodmanSecrets,
        source: &str,
        label: &str,
        deploy_name: &str,
        state_dir: &Path,
        skip: &BTreeSet<String>,
        strict: bool,
        out: &mut Populated,
    ) -> Result<(), SecretError> {
        let arg = source.split_once(':').map_or("", |(_, arg)| arg);
        if arg.is_empty() || skip.contains(arg) || out.resolved.contains(arg) {
            return Ok(());
        }
        let result = match self.resolve(source, arg, state_dir) {
            Ok(result) => result,
            Err(e) => {
                if strict {
                    return Err(SecretError::value(format!(
                        "failed to resolve {label} api_key '{arg}': {e}"
                    )));
                }
                out.warnings.push(format!(
                    "warning: failed to resolve {label} api_key {arg}: {e}"
                ));
                return Ok(());
            }
        };
        Self::store_resolution(podman, deploy_name, arg, &result, &mut out.resolved)
    }

    /// The two branches both call sites share: a resolved value becomes
    /// a podman secret, a quadlet-handled one is only recorded.
    fn store_resolution(
        podman: &dyn PodmanSecrets,
        deploy_name: &str,
        env: &str,
        result: &Resolution,
        resolved: &mut BTreeSet<String>,
    ) -> Result<(), SecretError> {
        match result {
            Resolution::Resolved(value) => {
                let full = format!("{deploy_name}.{env}");
                replace_podman_secret(podman, &full, value)?;
                resolved.insert(env.to_string());
            }
            Resolution::QuadletHandled => {
                resolved.insert(env.to_string());
            }
            Resolution::Existing => {}
        }
        Ok(())
    }
}

/// The `cmd:` scheme's time limit.
///
/// 30 seconds, and it is the operator's command being waited on -- a
/// `pass show` that prompts for a passphrase would otherwise hang
/// `cage start` forever.
pub const CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `if podman.secret_exists(f): podman.secret_remove(f)` then
/// `podman.secret_create(f, value)`.
///
/// The three-call shape appears five times in the Python and is
/// load-bearing: `podman secret create` fails on a duplicate name, so
/// an update is a remove followed by a create, and the remove is
/// conditional because removing a missing secret is also a failure.
///
/// # Errors
///
/// [`SecretError::Store`] naming the podman failure.
pub(crate) fn replace_podman_secret(
    podman: &dyn PodmanSecrets,
    full: &str,
    value: &str,
) -> Result<(), SecretError> {
    if podman
        .secret_exists(full)
        .map_err(|e| SecretError::store(e.to_string()))?
    {
        podman
            .secret_remove(full)
            .map_err(|e| SecretError::store(e.to_string()))?;
    }
    podman
        .secret_create(full, value)
        .map_err(|e| SecretError::store(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{Backend, MapEnv, Resolution, SecretHost};
    use agentcage_exec::{FakeRunner, Reply};
    use std::path::Path;

    #[test]
    fn a_resolved_value_never_prints() {
        let resolution = Resolution::Resolved("hunter2".to_string());
        let rendered = format!("{resolution:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert_eq!(rendered, "Resolved(<7 redacted bytes>)");
        assert_eq!(resolution.value(), Some("hunter2"));
        assert_eq!(resolution.action(), "resolved");
    }

    #[test]
    fn the_test_environment_prints_names_not_values() {
        let env = MapEnv::new().with("TOKEN", "hunter2");
        let rendered = format!("{env:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("TOKEN"), "{rendered}");
    }

    #[test]
    fn an_env_source_with_no_argument_uses_the_rule_name() {
        let fake = FakeRunner::new();
        let env = MapEnv::new().with("GH_TOKEN", "t");
        let host = SecretHost::new(&fake, &env, true);
        assert_eq!(
            host.resolve("env:", "GH_TOKEN", Path::new("/nope"))
                .unwrap(),
            Resolution::Resolved("t".to_string())
        );
        assert_eq!(fake.call_count(), 0, "no subprocess for an env: source");
    }

    #[test]
    fn an_unset_env_var_names_the_variable_and_not_the_rule() {
        let fake = FakeRunner::new();
        let env = MapEnv::new();
        let host = SecretHost::new(&fake, &env, true);
        let err = host
            .resolve("env:REAL_NAME", "RULE_NAME", Path::new("/nope"))
            .unwrap_err();
        assert_eq!(err.to_string(), "env var 'REAL_NAME' not set");
    }

    #[test]
    fn the_backend_probe_runs_in_the_pythons_order() {
        let fake = FakeRunner::new();
        fake.stub_which("systemd-creds", "/usr/bin/systemd-creds");
        fake.push(Reply::ok("systemd 256 (256.11-1-arch)\n"));
        fake.push(Reply::success());
        let env = MapEnv::new();
        let host = SecretHost::new(&fake, &env, true);

        assert_eq!(host.default_backend(), Backend::SystemdCreds);
        assert_eq!(host.default_backend().as_str(), "systemd-creds");
        fake.assert_argv(&[
            &["systemctl", "--version"],
            &[
                "systemd-creds",
                "--user",
                "encrypt",
                "--name",
                "_probe",
                "-",
                "-",
            ],
        ]);
        assert_eq!(fake.which_lookups(), ["systemd-creds"]);

        // Memoized: the second call probes nothing.
        assert_eq!(host.default_backend(), Backend::SystemdCreds);
        assert_eq!(fake.call_count(), 2);
    }

    #[test]
    fn an_old_systemd_short_circuits_before_the_probe() {
        let fake = FakeRunner::new();
        fake.stub_which("systemd-creds", "/usr/bin/systemd-creds");
        fake.push(Reply::ok("systemd 249 (249.11)\n"));
        let env = MapEnv::new();
        let host = SecretHost::new(&fake, &env, true);
        assert_eq!(host.default_backend(), Backend::Podman);
        fake.assert_argv(&[&["systemctl", "--version"]]);
    }

    #[test]
    fn a_missing_binary_short_circuits_before_systemctl() {
        let fake = FakeRunner::new();
        fake.stub_missing("systemd-creds");
        let env = MapEnv::new();
        let host = SecretHost::new(&fake, &env, true);
        assert_eq!(host.default_backend(), Backend::Podman);
        assert_eq!(fake.call_count(), 0);
    }

    #[test]
    fn root_never_probes_the_per_user_key() {
        let fake = FakeRunner::new();
        fake.push(Reply::success());
        let env = MapEnv::new();
        let host = SecretHost::new(&fake, &env, false);
        assert_eq!(host.default_scope().unwrap().as_str(), "system");
        fake.assert_argv(&[&["systemd-creds", "encrypt", "--name", "_probe", "-", "-"]]);
    }

    #[test]
    fn an_explicit_scope_needs_no_probe() {
        let fake = FakeRunner::new();
        let env = MapEnv::new();
        let host = SecretHost::new(&fake, &env, true);
        assert_eq!(host.resolve_scope("user").unwrap().as_str(), "user");
        assert_eq!(host.resolve_scope("system").unwrap().as_str(), "system");
        assert_eq!(
            host.resolve_scope("nonsense").unwrap_err().to_string(),
            "invalid secrets.scope: 'nonsense'"
        );
        assert_eq!(fake.call_count(), 0);
    }

    #[test]
    fn auto_with_no_usable_key_is_a_refusal_not_a_guess() {
        let fake = FakeRunner::new();
        fake.push(Reply::failed(1, "Failed to encrypt"));
        fake.push(Reply::failed(1, "Failed to encrypt"));
        let env = MapEnv::new();
        let host = SecretHost::new(&fake, &env, true);
        assert_eq!(
            host.resolve_scope("auto").unwrap_err().to_string(),
            "systemd-creds encryption is not usable in either user or system scope on this host"
        );
    }
}
