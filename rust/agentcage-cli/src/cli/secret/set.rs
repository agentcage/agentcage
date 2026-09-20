//! `agentcage secret set NAME KEY` — store a value, and make it take
//! effect.
//!
//! `cli.py:3813`, plus `cli._store_secret` (`cli.py:131`) and
//! `cli._declare_injection_rule` (`cli.py:3769`), which live here
//! because this is their only interesting caller — `cage create -s` is
//! the other, and it calls into [`SecretWriter`] below.
//!
//! # Where the value comes from
//!
//! Not from argv. `secret set` takes the cage and the key as
//! arguments; the value arrives on stdin, or from a terminal read with
//! echo off when stdin is a tty. There is no `--value`, deliberately,
//! and adding one would put every credential this tool handles into the
//! operator's shell history.
//!
//! The one place that shape is *not* honoured is `cage create
//! -s KEY=VALUE`, which is pre-existing, operator-facing, and
//! documented as such in [`agentcage_cli::secrets`]. It is reproduced,
//! not extended: nothing new in this PR accepts a value as an argument.

use std::io::{IsTerminal as _, Read as _};
use std::path::PathBuf;
use std::process::ExitCode;

use agentcage_core::config::Config;
use agentcage_core::yaml::{Mapping, Value};
use agentcage_exec::CommandRunner;
use agentcage_exec::tools::podman::Podman;
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE};
use crate::cli::secret::{check_cage, load_config, require_container};
use agentcage_cli::secrets::{
    Environment, Platform, SecretHost, plaintext_store_for, resolve_store,
};

/// `cli._store_secret` — persist a value at rest through the cage's
/// configured backend, fail-closed.
///
/// Held as a struct rather than a free function because `cage create
/// -s` sets several secrets in a row and the capability probes behind
/// [`SecretHost`] (is there a working `systemd-creds`? which scope?)
/// are memoized per host, not per key.
pub(crate) struct SecretWriter<'a> {
    host: SecretHost<'a>,
    podman: Podman<'a>,
    config: &'a Config,
    name: &'a str,
    state_dir: PathBuf,
}

impl<'a> SecretWriter<'a> {
    /// A writer for one cage.
    pub(crate) fn new(
        runner: &'a dyn CommandRunner,
        env: &'a dyn Environment,
        config: &'a Config,
        name: &'a str,
        state_dir: PathBuf,
    ) -> Self {
        Self {
            host: SecretHost::detect(runner, env),
            podman: Podman::new(runner),
            config,
            name,
            state_dir,
        }
    }

    /// The `source:` scheme declared for `key`, or the empty string.
    ///
    /// It is what decides the store: a rule that says
    /// `source: systemd-creds:` gets the creds store *by name*, which —
    /// as PR D3 pinned — skips the availability probe that selecting
    /// the same store automatically would have run.
    fn source_scheme(&self, key: &str) -> &str {
        self.config
            .secret_injection
            .iter()
            .find(|rule| rule.env == key)
            .map_or("", |rule| rule.source.split(':').next().unwrap_or_default())
    }

    /// Store `value` for `key`, printing what `cli._store_secret`
    /// prints.
    ///
    /// # Errors
    ///
    /// [`EXIT_FAILURE`] when no store will take it, or when the chosen
    /// store failed and no fallback was permitted. The messages are
    /// built from the key name, the store name and the store's own
    /// error — never from `value`.
    pub(crate) fn set(&self, key: &str, value: &str) -> Result<(), ExitCode> {
        let store = resolve_store(
            self.config,
            &self.host,
            Some(&self.podman),
            self.source_scheme(key),
            Platform::host(),
        )
        .map_err(|error| {
            eprintln!(
                "error: refusing to store secret '{key}': {}",
                error.message()
            );
            eprintln!(
                "  Fix: enable an encrypting backend (Linux: systemd-creds with a \
                 TPM2/host/per-user key; macOS: an unlocked login keychain or \
                 passwordless sudo for the System keychain) or, to accept \
                 unencrypted at-rest storage, set `secrets:\\n  allow_plaintext: \
                 true` in cage.yaml."
            );
            ExitCode::from(EXIT_FAILURE)
        })?;

        let full = format!("{}.{key}", self.name);
        let mut store = store;
        if let Err(error) = store.set(self.name, key, value, &self.state_dir) {
            // An encrypting backend failed at runtime (TPM2 contention,
            // a locked keychain). Fall back only when it was allowed.
            if self.config.secrets.allow_plaintext && store.name() != "plaintext" {
                eprintln!(
                    "warning: {} storage failed: {}",
                    store.name(),
                    error.message()
                );
                store = plaintext_store_for(self.config, Some(&self.podman));
                if let Err(error) = store.set(self.name, key, value, &self.state_dir) {
                    eprintln!("error: failed to store secret '{key}': {}", error.message());
                    return Err(ExitCode::from(EXIT_FAILURE));
                }
            } else {
                eprintln!("error: failed to store secret '{key}': {}", error.message());
                return Err(ExitCode::from(EXIT_FAILURE));
            }
        }

        match store.name() {
            "plaintext" => {
                eprintln!("warning: secret '{full}' stored UNENCRYPTED at rest.");
                println!("Secret '{full}' set (unencrypted).");
            }
            "systemd-creds" => println!("Secret '{key}' encrypted with systemd-creds."),
            "keychain" => println!("Secret '{key}' stored in the macOS keychain."),
            other => println!("Secret '{full}' set ({other})."),
        }
        Ok(())
    }
}

/// The body.
pub(crate) fn main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match run(ctx, matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn run(ctx: &Ctx, matches: &ArgMatches) -> Result<(), ExitCode> {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    let key = matches
        .get_one::<String>("key")
        .expect("required by the parser")
        .clone();
    let placeholder_opt = matches
        .get_one::<String>("placeholder_opt")
        .cloned()
        .unwrap_or_default();
    let inject_to: Vec<String> = matches
        .get_many::<String>("inject_to")
        .map(|values| values.cloned().collect())
        .unwrap_or_default();
    // `--placeholder` and `--inject-to` are only meaningful on a rule
    // that is about to be written, so either one implies `--declare`.
    let declare =
        matches.get_flag("declare") || !placeholder_opt.is_empty() || !inject_to.is_empty();

    check_cage(ctx, &name, true)?;
    if declare {
        declare_injection_rule(ctx, &name, &key, &placeholder_opt, &inject_to)?;
    }
    let config = load_config(ctx, &name)?;
    require_container(&config, &name)?;

    let value = read_value(&key)?;
    if value.is_empty() {
        eprintln!("error: empty secret value");
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    let env = agentcage_cli::secrets::SystemEnv;
    let writer = SecretWriter::new(
        ctx.runner.as_ref(),
        &env,
        &config,
        &name,
        ctx.paths.deployment_dir(&name),
    );
    writer.set(&key, &value)?;

    if !declare
        && !config.secret_injection.iter().any(|rule| rule.env == key)
        && !agentcage_cli::services::expected_secrets(&config).contains(&key)
    {
        eprintln!(
            "note: '{key}' has no secret_injection rule — the value is stored but \
             never injected (orphan). Re-run with --declare (optionally \
             --inject-to <domain>) to declare one."
        );
    }

    crate::cli::secret::live::apply_or_restart(ctx, &name, &key, &value);
    Ok(())
}

/// The value, from a terminal read with echo off or from stdin.
///
/// `sys.stdin.read().rstrip("\n")` for the piped case — *all* trailing
/// newlines, not one, so `printf 'v\n\n' | …` and `echo v | …` store
/// the same thing. Trailing `\r` is not stripped, because the Python
/// does not strip it either and a value that genuinely ends in one must
/// survive.
///
/// # Errors
///
/// [`EXIT_FAILURE`] if stdin cannot be read.
fn read_value(key: &str) -> Result<String, ExitCode> {
    if std::io::stdin().is_terminal() {
        return agentcage_cli::terminal::prompt_hidden(&format!("Value for {key}")).map_err(
            |error| {
                eprintln!("error: could not read a value for {key}: {error}");
                ExitCode::from(EXIT_FAILURE)
            },
        );
    }
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|error| {
            eprintln!("error: could not read a value for {key}: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    Ok(buffer.trim_end_matches('\n').to_owned())
}

/// `cli._declare_injection_rule` — append a `secret_injection` rule for
/// `key` to the **stored** `cage.yaml`.
///
/// An existing rule is left alone, with a note: editing one is
/// `cage edit`'s job, and silently rewriting a rule an operator tuned
/// (its `inject_to`, its `strict`) because they re-ran `secret set
/// --declare` would be a surprise with security consequences.
///
/// The placeholder defaults to a freshly minted entropic token. It is
/// not a secret — it is the decoy the workload sees — but its entropy
/// is load-bearing: a guessable one lets an outbound document that
/// happens to contain the literal string have a real credential
/// substituted into it.
fn declare_injection_rule(
    ctx: &Ctx,
    name: &str,
    key: &str,
    placeholder: &str,
    inject_to: &[String],
) -> Result<bool, ExitCode> {
    let mut raw = ctx
        .paths
        .load_raw_config(name, agentcage_state::AgentSchema::Check)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;

    let rules = rules_for_append(&mut raw).ok_or_else(|| {
        eprintln!(
            "error: cage '{name}' has a secret_injection section that is neither a \
             list of rules nor a mapping with a 'rules:' key — declare the rule by \
             hand with 'agentcage cage edit {name}'"
        );
        ExitCode::from(EXIT_FAILURE)
    })?;

    if rules.iter().any(|entry| {
        entry
            .as_mapping()
            .and_then(|rule| rule.get("env"))
            .and_then(Value::as_str)
            == Some(key)
    }) {
        eprintln!(
            "note: a secret_injection rule for '{key}' already exists; edit it via \
             'agentcage cage edit {name}'."
        );
        return Ok(false);
    }

    let token = if placeholder.is_empty() {
        agentcage_state::mint_placeholder(key)
    } else {
        placeholder.to_owned()
    };
    let mut entry = Mapping::new();
    entry.insert(
        Value::String("env".to_owned()),
        Value::String(key.to_owned()),
    );
    entry.insert(
        Value::String("placeholder".to_owned()),
        Value::String(token.clone()),
    );
    if !inject_to.is_empty() {
        entry.insert(
            Value::String("inject_to".to_owned()),
            Value::Sequence(
                inject_to
                    .iter()
                    .map(|domain| Value::String(domain.clone()))
                    .collect(),
            ),
        );
    }
    rules.push(Value::Mapping(entry));

    ctx.paths.save_raw_config(name, &raw).map_err(|error| {
        eprintln!("error: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;
    println!("Declared secret_injection rule for '{key}' (placeholder {token}).");
    if inject_to.is_empty() {
        eprintln!(
            "note: no --inject-to given — the real value will be injected for ALL \
             allowed domains. Add domains to scope it."
        );
    }
    Ok(true)
}

/// The rule list to push onto, creating the section when there is none.
///
/// `agentcage_core::config::injection_rules_mut` is the *reader*: it
/// hands back a slice, which is enough to rotate a placeholder and not
/// enough to add a rule. This is the writer's half, and it is the one
/// that has to decide what an unusable section means. `cli.py` answers
/// that by `append`ing to whatever it found — which raises
/// `AttributeError` on a scalar `secret_injection: nonsense`; here the
/// same document gets a refusal naming the fix.
fn rules_for_append(raw: &mut Value) -> Option<&mut Vec<Value>> {
    let Value::Mapping(document) = raw else {
        return None;
    };
    let key = Value::String("secret_injection".to_owned());
    // `if si is None: raw["secret_injection"] = si = []`.
    let section = document
        .entry(key)
        .or_insert_with(|| Value::Sequence(Vec::new()));
    if matches!(section, Value::Null) {
        *section = Value::Sequence(Vec::new());
    }
    match section {
        // `si.setdefault("rules", [])`.
        Value::Mapping(block) => {
            let rules = block
                .entry(Value::String("rules".to_owned()))
                .or_insert_with(|| Value::Sequence(Vec::new()));
            match rules {
                Value::Sequence(items) => Some(items),
                _ => None,
            }
        }
        Value::Sequence(items) => Some(items),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::rules_for_append;
    use agentcage_core::yaml;

    fn document(text: &str) -> yaml::Value {
        yaml::load(text).expect("valid YAML")
    }

    /// The three shapes `secret_injection:` is written in, plus the one
    /// that is not a shape at all.
    #[test]
    fn a_rule_can_be_appended_to_every_documented_shape() {
        // Absent entirely: the section is created.
        let mut absent = document("name: acme\n");
        assert_eq!(
            rules_for_append(&mut absent).map(|rules| rules.len()),
            Some(0)
        );
        assert!(absent.get("secret_injection").is_some());

        // `secret_injection:` with nothing under it parses as null.
        let mut null = document("secret_injection:\n");
        assert_eq!(
            rules_for_append(&mut null).map(|rules| rules.len()),
            Some(0)
        );

        // A bare list.
        let mut list = document("secret_injection:\n  - env: A\n");
        assert_eq!(
            rules_for_append(&mut list).map(|rules| rules.len()),
            Some(1)
        );

        // A mapping with `rules:`, and one without it.
        let mut mapping = document("secret_injection:\n  rules:\n    - env: A\n");
        assert_eq!(
            rules_for_append(&mut mapping).map(|rules| rules.len()),
            Some(1)
        );
        let mut bare_mapping = document("secret_injection:\n  strict: true\n");
        assert_eq!(
            rules_for_append(&mut bare_mapping).map(|rules| rules.len()),
            Some(0)
        );

        // A scalar is refused rather than `append`ed to. `cli.py`
        // raises `AttributeError` here; the refusal is this port's, and
        // it is the one behavioural difference in this file.
        let mut scalar = document("secret_injection: nonsense\n");
        assert!(rules_for_append(&mut scalar).is_none());
    }

    /// Appending is a real mutation of the document that gets saved.
    #[test]
    fn an_appended_rule_lands_in_the_document() {
        let mut raw = document("name: acme\nsecret_injection:\n  - env: A\n");
        let rules = rules_for_append(&mut raw).expect("a list");
        rules.push(document("env: B\nplaceholder: t\n"));
        let emitted = yaml::dump(&raw).expect("emittable");
        assert!(emitted.contains("env: B"), "{emitted}");
        assert!(emitted.contains("placeholder: t"), "{emitted}");
    }
}
