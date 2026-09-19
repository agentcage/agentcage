//! `agentcage domain <command>` — the cage's DNS/L7 filter list.

use clap::Command;

use clap::Arg;

use crate::cli::args::{TEXT, aliases_section, cage_name, flag, group, leaf, value_opt};

/// `domain add`'s docstring, verbatim from `cli.py`.
const ADD_LONG: &str = "\
Add one or more domains to a cage's filter list.

Multiple domains may be passed; the cage is reloaded at most once.
With ``--expires-in`` the entry is time-limited (allowlist mode only):
it works until its TTL elapses, then the proxy blocks it at L7 and the
next reconcile (``cage grants <name> sync``, which also runs implicitly
from the CLI paths that read a cage) prunes it from the allowlist +
dnsmasq. Permanent by default.";

/// The `domain` group.
pub(crate) fn command() -> Command {
    group("domain")
        .about("Manage cage domain filters.")
        .after_help(aliases_section(&[("ls", "list")]))
        .subcommand(add())
        .subcommand(
            leaf("list")
                .alias("ls")
                .about("List domains for a cage.")
                .arg(cage_name()),
        )
        .subcommand(rm())
}

/// `domain add NAME DOMAIN_NAMES...` — the only variadic that is both
/// required and not a passthrough.
fn add() -> Command {
    leaf("add")
        .about("Add one or more domains to a cage's filter list.")
        .long_about(ADD_LONG)
        .arg(cage_name())
        .arg(
            Arg::new("domain_names")
                .required(true)
                .num_args(1..)
                .value_name("DOMAIN_NAMES"),
        )
        .arg(flag(
            "passthrough",
            "passthrough",
            "Also add to TLS passthrough list (no MITM interception).",
        ))
        .arg(value_opt(
            "expires_in",
            "expires-in",
            TEXT,
            "Time-limit the entry: e.g. 30m, 1h, 2d (or a bare number of seconds). After it expires the domain is blocked at the proxy and pruned from the allowlist. Useful for a one-off task like `npm install`. Only valid in allowlist mode.",
        ))
}

/// `domain rm NAME DOMAIN_NAME` — singular, unlike `add`.
fn rm() -> Command {
    leaf("rm")
        .about("Remove a domain from a cage's filter list.")
        .arg(cage_name())
        .arg(
            Arg::new("domain_name")
                .required(true)
                .value_name("DOMAIN_NAME"),
        )
        .arg(flag(
            "passthrough",
            "passthrough",
            "Remove only from passthrough list (keep in allow/block).",
        ))
}
