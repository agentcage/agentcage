//! `agentcage scaffold <command>` — user-authored cage templates.
//!
//! The only group in the tree that is a plain `click.Group` rather than
//! an `AliasGroup`: it publishes no aliases, and so prints no "Aliases:"
//! section. It also lives in its own Python module (`scaffold_cli.py`)
//! and is attached with `main.add_command(scaffold)`, which is why a
//! grep for `@main.group` in `cli.py` misses it.

use clap::Command;

use crate::cli::args::{TEXT, flag, group, leaf, positional, value_opt};

/// `scaffold create`'s docstring, verbatim (minus click's `\\x08`).
const CREATE_LONG: &str = "\
Create a new user scaffold.

Examples:
  agentcage scaffold create my-agent
  agentcage scaffold create my-claude --from claude-code";

/// The `scaffold` group.
pub(crate) fn command() -> Command {
    group("scaffold")
        .about("Create and manage custom scaffolds.")
        .subcommand(create())
        .subcommand(
            leaf("delete")
                .about("Delete a user scaffold.")
                .arg(positional("name", "NAME"))
                .arg(flag("yes", "yes", "Skip confirmation.").short('y')),
        )
        .subcommand(
            leaf("edit")
                .about("Open a user scaffold in $EDITOR.")
                .arg(positional("name", "NAME")),
        )
        .subcommand(
            leaf("export")
                .about("Export a scaffold to a directory.")
                .arg(positional("name", "NAME"))
                .arg(positional("dest", "DEST")),
        )
        .subcommand(leaf("list").about("List all available scaffolds."))
        .subcommand(
            leaf("show")
                .about("Show details of a scaffold.")
                .arg(positional("name", "NAME")),
        )
}

/// `scaffold create NAME`.
fn create() -> Command {
    leaf("create")
        .about("Create a new user scaffold.")
        .long_about(CREATE_LONG)
        .arg(positional("name", "NAME"))
        .arg(value_opt(
            "from_scaffold",
            "from",
            TEXT,
            "Fork an existing scaffold as starting point.",
        ))
        .arg(flag("force", "force", "Overwrite existing scaffold."))
}
