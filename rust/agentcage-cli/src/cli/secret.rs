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
