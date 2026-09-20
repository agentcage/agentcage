//! `agentcage secret <command>` — cage-scoped secrets.

use clap::{Arg, Command};

use crate::cli::args::{
    TEXT, aliases_section, cage_name, flag, group, leaf, multi_opt, positional,
};

/// `secret rotate-placeholders`'s docstring, verbatim from `cli.py`.
const ROTATE_LONG: &str = "\
Mint fresh entropic placeholders for a cage's injection rules.

Rotates every secret_injection rule's placeholder, or only the named
KEYS. Use this to retire a compromised placeholder or migrate a legacy
static/guessable one (e.g. ``{{GH_TOKEN}}``) to an entropic token. The
new tokens are persisted to the stored cage.yaml; a running cage is
restarted so the old placeholders stop injecting and the cage process
picks up the new ones.

Note: this fixes the live cage, not a cage.yaml you track elsewhere. If
your source config pins an explicit placeholder, the next ``cage update
-c`` reintroduces it — drop the ``placeholder:`` line from your source
so agentcage owns (and preserves) the generated token instead.";

/// The `secret` group.
pub(crate) fn command() -> Command {
    group("secret")
        .about("Manage cage-scoped secrets.")
        .after_help(aliases_section(&[("ls", "list")]))
        .subcommand(
            leaf("list")
                .alias("ls")
                .about("List secrets for a cage.")
                .arg(cage_name()),
        )
        .subcommand(
            leaf("rm")
                .about("Remove a secret for a cage.")
                .arg(cage_name())
                .arg(positional("key", "KEY")),
        )
        .subcommand(rotate_placeholders())
        .subcommand(set())
}

/// `secret set NAME KEY` — the value is never an argument.
///
/// Note what is *not* here: no `--value`. `cli.py` reads the value from
/// a prompt or from stdin, and a secret on the command line would land
/// in the shell history of every user of this tool.
fn set() -> Command {
    leaf("set")
        .about("Set a secret for a cage.")
        .arg(cage_name())
        .arg(positional("key", "KEY"))
        .arg(flag(
            "declare",
            "declare",
            "Declare a secret_injection rule for KEY if none exists (entropic placeholder, persisted to the stored cage.yaml) — makes a brand-new secret usable in one command.",
        ))
        .arg(
            Arg::new("placeholder_opt")
                .long("placeholder")
                .value_name(TEXT)
                .action(clap::ArgAction::Set)
                // click's default is the empty string, not None: the
                // implementation distinguishes "no --placeholder" from
                // "--placeholder ''" nowhere, and an Option<String> here
                // would invent a third state.
                .default_value("")
                .help("Explicit placeholder for the declared rule (implies --declare)."),
        )
        .arg(multi_opt(
            "inject_to",
            "inject-to",
            TEXT,
            "Domain(s) the declared rule injects to (implies --declare). Repeatable. Omitted = all domains.",
        ))
}

/// `secret rotate-placeholders NAME [KEYS]...`.
fn rotate_placeholders() -> Command {
    leaf("rotate-placeholders")
        .about("Mint fresh entropic placeholders for a cage's injection rules.")
        .long_about(ROTATE_LONG)
        .arg(cage_name())
        .arg(Arg::new("keys").num_args(0..).value_name("KEYS"))
}

// ── the bodies ───────────────────────────────────────

pub(crate) mod live;
pub(crate) mod rm;
pub(crate) mod rotate;
pub(crate) mod set;

use std::process::ExitCode;

use agentcage_core::config::Config;
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage};

/// Every `secret` subcommand starts the same way: the cage must exist,
/// and it must not be a pre-v0.22 one.
///
/// `secret set`'s "does not exist" message carries a hint the other
/// three do not — `cli.py` spells it out there and nowhere else,
/// because that is the command an operator reaches for first.
fn check_cage(ctx: &Ctx, name: &str, hint: bool) -> Result<(), ExitCode> {
    if !ctx.paths.deployment_exists(name) {
        if hint {
            eprintln!("error: cage '{name}' does not exist — create it first with 'cage create'");
        } else {
            eprintln!("error: cage '{name}' does not exist");
        }
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    ensure_v022_cage(&ctx.paths, name)
}

/// The stored config, with the load failure reported the way every
/// other body reports one.
///
/// Kept separate from [`check_cage`] because `secret set --declare`
/// rewrites the stored `cage.yaml` *between* the two: the config it
/// goes on to use has to be the one carrying the rule it just declared.
fn load_config(ctx: &Ctx, name: &str) -> Result<Config, ExitCode> {
    ctx.paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })
}

fn open_cage(ctx: &Ctx, name: &str, hint: bool) -> Result<Config, ExitCode> {
    check_cage(ctx, name, hint)?;
    load_config(ctx, name)
}

/// The one backend these bodies drive.
///
/// `vm` keeps its secrets inside the Lima guest and `apple-container`
/// in the macOS keychain; both are Track E, and both would be *wrong*
/// rather than merely unimplemented if this code drove host podman at
/// them — `secret list` would report every key missing, and `secret rm`
/// would report a secret that exists as absent. So they are refused by
/// name.
fn require_container(config: &Config, name: &str) -> Result<(), ExitCode> {
    if config.isolation == "container" {
        return Ok(());
    }
    eprintln!(
        "error: cage '{name}' uses the '{}' backend, whose secret store is not \
         ported yet (RUST-PORT-PLAN.md Track E)",
        config.isolation
    );
    Err(ExitCode::from(EXIT_FAILURE))
}

/// `secret list` — the NAME/TYPE/STATUS/PLACEHOLDER table.
pub(crate) fn list(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser");
    match run_list(ctx, name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn run_list(ctx: &Ctx, name: &str) -> Result<(), ExitCode> {
    let config = open_cage(ctx, name, false)?;
    require_container(&config, name)?;
    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
    let prefix = format!("{name}.");
    let present: Vec<String> = podman
        .secret_list(&prefix)
        .unwrap_or_default()
        .into_iter()
        .map(|full| full[prefix.len()..].to_owned())
        .collect();
    if render(&config, &present) {
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    Ok(())
}

/// How a listed secret is classified.
///
/// The four `secret list` prints plus `orphan`, which is not a
/// classification of a *declared* secret but of a stored one nothing
/// declares.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// A `secret_injection` rule.
    Injection,
    /// `agents.decider.api_key`'s `source:NAME`.
    Decider,
    /// `agents.watcher.api_key`'s `source:NAME`.
    Watcher,
    /// Expected, but by none of the above — a `podman_secrets` entry or
    /// a relay credential.
    Direct,
}

impl Kind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Injection => "injection",
            Self::Decider => "decider",
            Self::Watcher => "watcher",
            Self::Direct => "direct",
        }
    }
}

/// `cli._render_secret_list` — print the table, and answer whether any
/// declared secret is missing.
///
/// The *union* of declared and stored is rendered, so a value set for a
/// key with no rule behind it still shows (as `orphan`) rather than
/// being silently invisible; declared-but-absent shows `MISSING` and is
/// what makes the command exit 1.
///
/// The two agent API keys are classified under their owner rather than
/// falling through to `orphan`. That matters more than it looks: an
/// operator shown `orphan` next to the one credential the decider needs
/// is being invited to `secret rm` it. They are collected whether or
/// not the agent is `enable`d, which is `cli.py`'s behaviour and not
/// `services.expected_secrets`'s — a key configured for an agent that
/// is currently off is still that agent's key.
///
/// # Placeholders are printed; values never are
///
/// The last column is the rule's placeholder, which is a decoy token —
/// the *opposite* of a secret, and worth surfacing so a generated one
/// is discoverable without opening the stored `cage.yaml`. Nothing here
/// reads a stored value: the store is asked for *names* only
/// (`podman secret ls`), and `podman secret inspect --showsecret` is
/// never called.
fn render(config: &Config, present: &[String]) -> bool {
    let mut expected = agentcage_cli::services::expected_secrets(config);
    let injection: Vec<&str> = config
        .secret_injection
        .iter()
        .map(|rule| rule.env.as_str())
        .collect();

    let mut decider: Vec<String> = Vec::new();
    let mut watcher: Vec<String> = Vec::new();
    for (key, bucket) in [
        (&config.agents.decider.llm.api_key, &mut decider),
        (&config.agents.watcher.llm.api_key, &mut watcher),
    ] {
        let Some((_, arg)) = key.split_once(':') else {
            continue;
        };
        if arg.is_empty() {
            continue;
        }
        bucket.push(arg.to_owned());
        if !expected.iter().any(|k| k == arg) {
            expected.push(arg.to_owned());
        }
    }

    let placeholders: Vec<(&str, &str)> = config
        .secret_injection
        .iter()
        .map(|rule| (rule.env.as_str(), rule.placeholder.as_str()))
        .collect();

    // `sorted(k for k in present_keys if k not in expected_set)`.
    let mut orphans: Vec<&String> = present
        .iter()
        .filter(|key| !expected.iter().any(|e| e == *key))
        .collect();
    orphans.sort_unstable();
    orphans.dedup();

    println!("{:<30} {:<12} {:<8} PLACEHOLDER", "NAME", "TYPE", "STATUS");
    let mut any_missing = false;
    for key in &expected {
        let kind = if injection.contains(&key.as_str()) {
            Kind::Injection
        } else if decider.iter().any(|k| k == key) {
            Kind::Decider
        } else if watcher.iter().any(|k| k == key) {
            Kind::Watcher
        } else {
            Kind::Direct
        };
        let status = if present.iter().any(|k| k == key) {
            "ok"
        } else {
            any_missing = true;
            "MISSING"
        };
        // `.rstrip()` — a rule with no placeholder must not leave a run
        // of spaces at the end of the line.
        let placeholder = placeholders
            .iter()
            .find(|(env, _)| env == key)
            .map_or("", |(_, value)| *value);
        let line = format!("{key:<30} {:<12} {status:<8} {placeholder}", kind.as_str());
        println!("{}", line.trim_end());
    }
    for key in orphans {
        // Stored at rest but referenced by nothing: staged at start()
        // and never injected or redacted. Surfaced so it can be audited
        // or removed.
        println!("{key:<30} {:<12} ok", "orphan");
    }
    any_missing
}

#[cfg(test)]
mod tests {
    use super::render;
    use agentcage_core::config::Config;
    use agentcage_core::config::types::SecretInjectionRule;

    fn rule(env: &str, placeholder: &str) -> SecretInjectionRule {
        SecretInjectionRule {
            env: env.to_owned(),
            placeholder: placeholder.to_owned(),
            ..SecretInjectionRule::default()
        }
    }

    /// A declared-but-absent secret is what makes `secret list` exit 1.
    #[test]
    fn a_missing_declared_secret_is_reported() {
        let mut config = Config::default();
        config.secret_injection.push(rule("API_KEY", "{{API_KEY}}"));
        assert!(render(&config, &[]));
        assert!(!render(&config, &["API_KEY".to_owned()]));
    }

    /// An agent's API key is the agent's, not an orphan — even when the
    /// agent is switched off.
    #[test]
    fn a_disabled_agents_key_is_still_classified_as_its_own() {
        let mut config = Config::default();
        config.agents.watcher.enable = false;
        config.agents.watcher.llm.api_key = "env:WATCH_KEY".to_owned();
        // Present in the store, so nothing is missing; the point is
        // that it is *expected* at all, which is what keeps it off the
        // orphan list.
        assert!(!render(&config, &["WATCH_KEY".to_owned()]));
        assert!(render(&config, &[]));
    }
}
