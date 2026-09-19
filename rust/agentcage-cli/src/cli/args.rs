//! The conventions every command in the tree is built from.
//!
//! `cli.py` gets its uniformity from click: a `@click.command()` comes
//! with `--help`, a group comes with a subcommand listing, and an
//! `@click.argument("name")` comes with an uppercase `NAME` metavar. The
//! clap defaults are *different* defaults, not absent ones — `-h` as
//! well as `--help`, a `help` subcommand on every group, `<name>` in
//! lower angle brackets — so reproducing click means overriding them,
//! and overriding them in 48 places by hand is how a surface drifts.
//!
//! Everything in this module exists so that no command module has to
//! remember any of it. Build leaves with [`leaf`], groups with [`group`],
//! and the click-shaped defaults come along.
//!
//! # The deliberate departures from clap's defaults
//!
//! * **No `-h`.** click declares `--help` alone. Adding a short form
//!   would be a kindness, but it would also be a flag the Python CLI
//!   rejects, and the point of this PR is that the two parse the same
//!   command lines.
//! * **`--help` is [`ArgAction::HelpLong`].** click prints a command's
//!   whole docstring for `--help` and only its first line in the parent's
//!   command listing. clap splits those two jobs across `about` and
//!   `long_about`, reached by `-h` and `--help` respectively — so the
//!   single `--help` click offers has to be the *long* one.
//! * **No `help` subcommand.** clap generates `agentcage cage help
//!   create`; click has no such thing.
//! * **Uppercase value names.** click derives `NAME`, `TEXT`, `INTEGER`,
//!   `PATH` from the parameter type. clap would print `<name>`.

use std::fmt::Write as _;

use clap::{Arg, ArgAction, Command};

/// Value name for a plain string parameter, as click's `STRING`/`TEXT`.
pub(crate) const TEXT: &str = "TEXT";
/// Value name for `click.INT`.
pub(crate) const INTEGER: &str = "INTEGER";
/// Value name for `click.Path`.
pub(crate) const PATH: &str = "PATH";

/// The `-s/--service` choice shared by `cage exec`, `cage shell` and `cage logs`.
pub(crate) const SERVICES: [&str; 2] = ["cage", "egress"];
/// The audit-record decision choice, shared by `cage audit` and `cage har`.
pub(crate) const DECISIONS: [&str; 3] = ["blocked", "flagged", "allowed"];
/// The traffic-direction choice, shared by `cage audit` and `cage har`.
pub(crate) const DIRECTIONS: [&str; 2] = ["inbound", "outbound"];
/// Inspector severities, as `config._LEVEL_ORDER` orders them.
pub(crate) const SEVERITIES: [&str; 5] = ["debug", "info", "warning", "error", "critical"];
/// Watcher finding severities — a different ladder from [`SEVERITIES`].
pub(crate) const FINDING_SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];
/// The isolation backends, shared by `init` and `run`.
pub(crate) const ISOLATIONS: [&str; 3] = ["container", "vm", "apple-container"];

/// click's `--help`: long form only, and worded exactly as click words it.
pub(crate) fn help_arg() -> Arg {
    Arg::new("help")
        .long("help")
        .action(ArgAction::HelpLong)
        .help("Show this message and exit.")
}

/// A command with no subcommands, carrying click's help conventions.
pub(crate) fn leaf(name: &'static str) -> Command {
    Command::new(name).disable_help_flag(true).arg(help_arg())
}

/// A command group, carrying click's help and no-arguments conventions.
///
/// `no_args_is_help` is click's default for a `Group`, and it is not the
/// gentle thing it sounds like: click raises `NoArgsIsHelpError`, which
/// prints the help to **stderr** and exits **2**. clap's
/// `arg_required_else_help` does precisely that, which is why it is here
/// rather than a hand-rolled check.
pub(crate) fn group(name: &'static str) -> Command {
    leaf(name)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .disable_help_subcommand(true)
        .subcommand_value_name("COMMAND")
        .subcommand_help_heading("Commands")
}

/// A required positional, with click's uppercase metavar.
pub(crate) fn positional(id: &'static str, value_name: &'static str) -> Arg {
    Arg::new(id).required(true).value_name(value_name)
}

/// An optional positional (`required=False` in click).
pub(crate) fn optional_positional(id: &'static str, value_name: &'static str) -> Arg {
    Arg::new(id).required(false).value_name(value_name)
}

/// A boolean flag (`is_flag=True`), defaulting to false as click's do.
pub(crate) fn flag(id: &'static str, long: &'static str, help: &'static str) -> Arg {
    Arg::new(id)
        .long(long)
        .action(ArgAction::SetTrue)
        .help(help)
}

/// A single-value option.
pub(crate) fn value_opt(
    id: &'static str,
    long: &'static str,
    value_name: &'static str,
    help: &'static str,
) -> Arg {
    Arg::new(id)
        .long(long)
        .value_name(value_name)
        .action(ArgAction::Set)
        .help(help)
}

/// A repeatable option (`multiple=True`).
///
/// click collects these into a tuple in the order given; clap's `Append`
/// does the same into a `Vec`, and both default to empty rather than to
/// a missing value — which matters, because several of these feed
/// filters where "not given" and "given nothing" mean the same thing.
pub(crate) fn multi_opt(
    id: &'static str,
    long: &'static str,
    value_name: &'static str,
    help: &'static str,
) -> Arg {
    Arg::new(id)
        .long(long)
        .value_name(value_name)
        .action(ArgAction::Append)
        .help(help)
}

/// The `NAME` positional that names a cage — the single most repeated
/// parameter in the tree (25 of the 44 arguments).
pub(crate) fn cage_name() -> Arg {
    positional("name", "NAME")
}

/// `-y/--yes`, worded as click words it (no full stop — click's own).
pub(crate) fn yes_flag() -> Arg {
    flag("yes", "yes", "Skip confirmation prompt").short('y')
}

/// Render click's `AliasGroup` / `_BannerGroup` "Aliases:" help section.
///
/// clap has `Command::visible_alias`, which inlines an alias into the
/// command listing as `list, ls`. click prints a separate trailing
/// section with an arrow. The aliases themselves are registered with
/// clap's *hidden* [`Command::alias`] so they resolve, and this renders
/// the section click prints. Pairs must already be sorted — click sorts
/// them, and the fixture records that order.
pub(crate) fn aliases_section(pairs: &[(&str, &str)]) -> String {
    let mut out = String::from("Aliases:\n");
    for (alias, target) in pairs {
        let _ = writeln!(out, "  {alias} \u{2192} {target}");
    }
    out.pop();
    out
}
