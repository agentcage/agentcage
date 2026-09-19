//! `agentcage cage <command>` — the group that carries 20 of the tree's
//! 41 commands, and the one the top-level aliases all point into.
//!
//! The three read-only, filter-heavy commands live in [`query`] and the
//! nested grants group in [`grants`]; `cage run` is [`crate::cli::run`],
//! registered here and again at the root. Everything else — the cage
//! lifecycle — is below.

pub(crate) mod grants;
pub(crate) mod query;

use clap::{Arg, Command};

use crate::cli::args::{
    PATH, SERVICES, TEXT, aliases_section, cage_name, flag, group, leaf, multi_opt,
    optional_positional, positional, value_opt, yes_flag,
};
use crate::cli::run;

/// `cage`'s aliases, as `cli.py:811` declares them, sorted the way click
/// sorts them for the help section.
pub(crate) const CAGE_ALIASES: [(&str, &str); 8] = [
    ("config", "edit"),
    ("delete", "destroy"),
    ("describe", "show"),
    ("inspect", "show"),
    ("ls", "list"),
    ("ps", "list"),
    ("reload", "restart"),
    ("rm", "destroy"),
];

/// `cage create`'s docstring, verbatim.
const CREATE_LONG: &str = "\
Build images, generate quadlets, install, and start a new cage.

The config may be given positionally (`agentcage create ./cage.yaml`)
or with -c (`agentcage create -c ./cage.yaml`).";

/// `cage update`'s docstring, verbatim.
const UPDATE_LONG: &str = "\
Rebuild and restart an existing cage.

NAME is optional when ``-c`` is given — the cage to update is taken
from the config's ``name:`` field. Mirrors ``cage create``, which
has never required a positional NAME for the same reason.";

/// `cage edit`'s docstring, verbatim.
const EDIT_LONG: &str = "\
Edit a cage's stored config in $EDITOR, with validation and safe save.

Unlike `$EDITOR ~/.config/agentcage/cages/NAME/cage.yaml`, this command:

  - Validates the edited YAML before saving (rejected edits are written
    to cage.yaml.rejected so you don't lose them).
  - Writes atomically (temp file + rename) so a crash mid-edit cannot
    corrupt your cage state.
  - Backs up the previous good config to cage.yaml.bak.
  - Shows a unified diff of what changed.
  - Auto-applies domain changes via dnsmasq SIGHUP (no cage restart).
  - Tells you exactly which next command will pick up other changes.";

/// `cage status`'s docstring, verbatim.
const STATUS_LONG: &str = "\
Show status — one cage's detail (with NAME) or all cages (without).

Mirrors `systemctl status`: `agentcage status` lists every cage;
`agentcage status <name>` shows that cage's detail (same as `cage show`).";

/// `cage exec`'s docstring, verbatim (minus click's `\\x08` marker).
const EXEC_LONG: &str = "\
Run a command inside a cage container.

Example:
  agentcage cage exec --as-root myapp -- openclaw devices list";

/// The whole `cage` group: 20 subcommands and 8 aliases.
pub(crate) fn command() -> Command {
    assemble(with_aliases)
}

/// The group *without* its aliases.
///
/// Two callers, and the second is the reason this exists. `_BannerGroup`
/// republishes nine of these subcommands at the top level (`agentcage
/// ls`, `agentcage rm`, ...), and those copies are taken from here
/// rather than from the aliased tree: a clone of the aliased `list`
/// would arrive at the root already answering to `ps`, colliding with
/// the root's own `ps` and tripping clap's duplicate-name assertion.
pub(crate) fn plain() -> Command {
    assemble(|sub| sub)
}

/// Build the group, passing each subcommand through `decorate` first.
///
/// The indirection is not decoration for its own sake: `mut_subcommand`
/// would have been the obvious way to bolt aliases onto an assembled
/// group, and it **moves the mutated subcommand to the end of the
/// listing**. click sorts its command listing, so that silently
/// reordered six of the twenty commands in `agentcage cage --help`.
fn assemble(decorate: impl Fn(Command) -> Command) -> Command {
    let mut cmd = group("cage")
        .about("Manage cages.")
        .after_help(aliases_section(&CAGE_ALIASES));
    for sub in subcommands() {
        cmd = cmd.subcommand(decorate(sub));
    }
    cmd
}

/// Register the aliases [`CAGE_ALIASES`] gives this subcommand.
///
/// Hidden aliases, not `visible_alias`: the latter would inline them
/// into the command listing as `list, ls`, and click prints them in a
/// trailing "Aliases:" section instead — which `after_help` reproduces.
fn with_aliases(sub: Command) -> Command {
    let name = sub.get_name().to_string();
    let mut sub = sub;
    for (alias, target) in CAGE_ALIASES {
        if target == name {
            sub = sub.alias(alias);
        }
    }
    sub
}

/// The 20 subcommands, alphabetically.
///
/// Not in `cli.py`'s declaration order: click sorts its command listing
/// and clap prints declaration order, so the sort has to happen here or
/// `agentcage cage --help` comes out in a different sequence from the
/// Python's.
fn subcommands() -> Vec<Command> {
    vec![
        query::audit(),
        backup(),
        create(),
        destroy(),
        edit(),
        exec(),
        grants::command(),
        query::har(),
        list(),
        query::logs(),
        prune(),
        restart(),
        restore(),
        run::command(),
        shell(),
        show(),
        start(),
        status(),
        stop(),
        update(),
        verify(),
    ]
}

/// `cage create` — the deploy path.
fn create() -> Command {
    leaf("create")
        .about("Build images, generate quadlets, install, and start a new cage.")
        .long_about(CREATE_LONG)
        // `config_pos` and `-c/--config` are two parameters for one
        // value on purpose: `cli.py:835` resolves them itself and
        // reports its own error when both are given, so they are NOT
        // declared as mutually exclusive here.
        .arg(optional_positional("config_pos", "CONFIG_POS").value_parser(existing_path()))
        .arg(
            value_opt(
                "config_path",
                "config",
                PATH,
                "Path to the cage config (cage.yaml). May also be given positionally.",
            )
            .short('c')
            .value_parser(existing_path()),
        )
        .arg(
            multi_opt(
                "secrets",
                "set-secret",
                TEXT,
                "Set a secret (KEY=VALUE or KEY to prompt). Repeatable.",
            )
            .short('s'),
        )
        .arg(flag(
            "no_cache",
            "no-cache",
            "Force a full image rebuild (ignore podman's layer cache).",
        ))
        .arg(flag(
            "pull",
            "pull",
            "Force re-pull of the base image from the registry.",
        ))
        .arg(flag(
            "show_timing",
            "time",
            "Echo per-phase wall times and print a summary on completion.",
        ))
}

/// `click.Path(exists=True)`: reject a missing path at parse time.
///
/// This is a *validation* contract, not a convenience. `cage create
/// ./typo.yaml` has to fail before anything is built, and the failure
/// has to come from the parser rather than from three frames into the
/// deploy. clap's `PathBufValueParser` does not check existence, so the
/// check is explicit.
fn existing_path() -> clap::builder::ValueParser {
    clap::builder::ValueParser::from(move |value: &str| -> Result<String, String> {
        if std::path::Path::new(value).exists() {
            Ok(value.to_string())
        } else {
            Err(format!("Path '{value}' does not exist."))
        }
    })
}

/// `cage update` — rebuild in place.
fn update() -> Command {
    leaf("update")
        .about("Rebuild and restart an existing cage.")
        .long_about(UPDATE_LONG)
        .arg(optional_positional("name", "NAME"))
        // No help string in `cli.py:1086`, and none invented here.
        .arg(
            Arg::new("config_path")
                .short('c')
                .long("config")
                .value_name(PATH)
                .value_parser(existing_path()),
        )
        .arg(flag(
            "no_cache",
            "no-cache",
            "Force a full image rebuild (ignore podman's layer cache). Use after pulling a fresh agentcage release that changed the Containerfile or any of its build context.",
        ))
        .arg(flag(
            "pull",
            "pull",
            "Force re-pull of the base image from the registry (--pull=always). Combine with --no-cache for a fully clean rebuild.",
        ))
        .arg(flag(
            "force",
            "force",
            "Rebuild and restart even when inputs are unchanged.",
        ))
}

/// `cage list` — the table.
fn list() -> Command {
    leaf("list").about("List all cages with status.")
}

/// `cage destroy` — the one command a silent no-op would be worst for.
fn destroy() -> Command {
    leaf("destroy")
        .about("Stop containers, remove quadlets, state, and scoped secrets.")
        .arg(cage_name())
        .arg(yes_flag())
        .arg(flag(
            "keep_secrets",
            "keep-secrets",
            "Keep scoped secrets (useful for recreating the cage)",
        ))
}

/// `cage prune` — bulk cleanup of exited ephemeral cages.
fn prune() -> Command {
    leaf("prune")
        .about("Remove all exited interactive and ephemeral cages.")
        .arg(yes_flag())
}

/// `cage verify` — the health probe.
fn verify() -> Command {
    leaf("verify")
        .about("Check that a cage is healthy.")
        .arg(cage_name())
}

/// `cage restart` — no rebuild.
fn restart() -> Command {
    leaf("restart")
        .about("Restart services without rebuilding images.")
        .arg(cage_name())
}

/// `cage edit` — `$EDITOR` with validation.
fn edit() -> Command {
    leaf("edit")
        .about("Edit a cage's stored config in $EDITOR, with validation and safe save.")
        .long_about(EDIT_LONG)
        .arg(cage_name())
}

/// `cage stop`.
fn stop() -> Command {
    leaf("stop")
        .about("Stop a running cage without destroying it.")
        .arg(cage_name())
}

/// `cage start`.
fn start() -> Command {
    leaf("start")
        .about("Start a stopped cage.")
        .arg(cage_name())
}

/// `cage show`.
fn show() -> Command {
    leaf("show")
        .about("Show cage configuration and status.")
        .arg(cage_name())
}

/// `cage status` — the only cage command whose `NAME` is optional.
fn status() -> Command {
    leaf("status")
        .about("Show status — one cage's detail (with NAME) or all cages (without).")
        .long_about(STATUS_LONG)
        .arg(optional_positional("name", "NAME"))
}

/// `cage exec` — the second of the two passthrough commands.
///
/// See [`crate::cli::run`] for why the trailing argument uses
/// `allow_hyphen_values` rather than `trailing_var_arg`. Unlike `run`'s,
/// this one is **required**: `agentcage cage exec myapp` with no command
/// is a usage error in click, not an implicit shell.
fn exec() -> Command {
    leaf("exec")
        .about("Run a command inside a cage container.")
        .long_about(EXEC_LONG)
        .arg(cage_name())
        .arg(
            value_opt(
                "service",
                "service",
                "[cage|egress]",
                "Container service to exec into.",
            )
            .short('s')
            .value_parser(SERVICES)
            .default_value("cage"),
        )
        .arg(flag(
            "as_root",
            "as-root",
            "Run the command as root (uid 0) instead of the workload's uid 1000 user (debug only).",
        ))
        .arg(
            Arg::new("command")
                .required(true)
                .num_args(1..)
                .value_name("COMMAND")
                .allow_hyphen_values(true),
        )
}

/// `cage shell`.
fn shell() -> Command {
    leaf("shell")
        .about("Open an interactive shell in a cage container.")
        .arg(cage_name())
        .arg(
            value_opt(
                "service",
                "service",
                "[cage|egress]",
                "Container service to shell into.",
            )
            .short('s')
            .value_parser(SERVICES)
            .default_value("cage"),
        )
        .arg(flag(
            "as_root",
            "as-root",
            "Open the shell as root (uid 0) instead of the workload's uid 1000 user (debug only).",
        ))
}

/// `cage backup`.
fn backup() -> Command {
    leaf("backup")
        .about("Create a backup tarball of a cage.")
        .arg(cage_name())
        .arg(
            value_opt(
                "output",
                "output",
                PATH,
                "Output path (default: ./{name}-backup-{timestamp}.tar.gz)",
            )
            .short('o'),
        )
        .arg(flag(
            "include_secrets",
            "include-secrets",
            "Include secret values in the backup (handle with care)",
        ))
}

/// `cage restore`.
fn restore() -> Command {
    leaf("restore")
        .about("Restore a cage from a backup tarball.")
        .arg(positional("tarball", "TARBALL").value_parser(existing_path()))
        .arg(value_opt(
            "new_name",
            "name",
            TEXT,
            "Restore with a different name (for cloning)",
        ))
        .arg(flag("force", "force", "Overwrite existing cage"))
        .arg(flag("no_start", "no-start", "Restore without starting"))
}
