//! The clap command tree — `cli.py`'s entire public surface, and
//! nothing behind it.
//!
//! # What this module is for
//!
//! PR D5 ports the *parse* half of `cli.py`: 48 command nodes, 80
//! declared options (4 of them hidden), 44 arguments, 31 aliases and
//! two passthrough commands. The bodies land in D6–D16, one e2e phase
//! at a time. Until then every
//! command that parses cleanly exits [`EXIT_NOT_IMPLEMENTED`] with a
//! message naming itself.
//!
//! That is a deliberate choice about what a skeleton should do. A tree
//! that accepted `cage destroy` and exited 0 would be worse than no
//! tree: it would look like it worked. B1's stub exited 2 on everything
//! it did not understand, and this keeps the discipline — the only
//! difference is that it can now *name* what it is refusing, which is
//! what makes the refusal useful.
//!
//! # Layout
//!
//! One module per command group, because `cli.py` is 5,632 lines in one
//! file and the plan calls that "already this codebase's worst seam".
//!
//! | Module | Node |
//! | :-- | :-- |
//! | [`cage`] | `cage` (20 commands) |
//! | [`cage::grants`] | `cage grants` |
//! | [`cage::query`] | `cage audit`, `cage har`, `cage logs` |
//! | [`run`] | `cage run`, and `run` at the root |
//! | [`domain`], [`secret`], [`watcher`], [`scaffold`] | their groups |
//! | [`init`] | `init`, `doctor` |
//! | [`args`] | the click-shaped defaults every command is built from |
//! | [`banner`] | `_BannerGroup`'s banner |
//! | [`completions`] | the one addition to the surface |
//!
//! # The two group classes this reproduces
//!
//! **`AliasGroup`** (`cli.py:551`) is a `click.Group` with an alias map
//! and a `format_help` override that prints an "Aliases:" section. Five
//! groups use it: `cage`, `cage grants`, `domain`, `secret` and
//! `watcher`. The aliases are registered with clap's hidden
//! `Command::alias` and the section is rebuilt by
//! [`args::aliases_section`] — not with `visible_alias`, which would
//! inline them into the command listing as `list, ls` and lose the
//! section.
//!
//! **`_BannerGroup`** is the root: it prints the banner above `--help`
//! and republishes 19 aliases for commands that live under `cage`. Those
//! are real top-level commands here, cloned from [`cage::plain`] and
//! hidden, exactly as click's `get_command` returns the target function
//! without listing it.

pub(crate) mod args;
pub(crate) mod banner;
pub(crate) mod cage;
pub(crate) mod completions;
#[cfg(test)]
mod conformance;
pub(crate) mod context;
pub(crate) mod domain;
pub(crate) mod init;
pub(crate) mod run;
pub(crate) mod scaffold;
pub(crate) mod secret;
pub(crate) mod watcher;

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgMatches, Command};

use crate::cli::args::aliases_section;

/// The program name, as it appears in `--version`, `--help` and errors.
pub(crate) const PROG: &str = "agentcage";

/// Exit status for a command that parsed but has no body yet.
///
/// Not 0 (that would be a lie), not 1 (that is "ran and failed"), and
/// not 2 (that is clap's and click's usage error, which this tree still
/// produces for genuinely bad input). 70 is sysexits.h's `EX_SOFTWARE`:
/// an internal error, which an unported command is.
pub(crate) const EXIT_NOT_IMPLEMENTED: u8 = 70;

/// `_BannerGroup._global_aliases`, flattened to (alias, canonical path).
///
/// Sorted by alias, as click sorts them for the help section and as the
/// generated fixture records them.
pub(crate) const TOP_LEVEL_ALIASES: [(&str, &str); 19] = [
    ("config", "cage edit"),
    ("delete", "cage destroy"),
    ("describe", "cage show"),
    ("edit", "cage edit"),
    ("exec", "cage exec"),
    ("inspect", "cage show"),
    ("logs", "cage logs"),
    ("ls", "cage list"),
    ("ps", "cage list"),
    ("reload", "cage restart"),
    ("restart", "cage restart"),
    ("rm", "cage destroy"),
    ("run", "cage run"),
    ("shell", "cage shell"),
    ("show", "cage show"),
    ("start", "cage start"),
    ("status", "cage status"),
    ("stop", "cage stop"),
    ("update", "cage update"),
];

/// The version line, byte-identical to what the Python CLI prints.
///
/// `cli.py` declares `@click.version_option(prog_name="agentcage")` and
/// click's default template is `%(prog)s, version %(version)s`. That
/// exact string is read by `install.sh` and by the e2e harness, so clap's
/// own `--version` is disabled and this is printed instead — clap would
/// say `agentcage 0.40.1`, which parses as a different thing.
pub(crate) fn version_line() -> String {
    format!("{PROG}, version {}", agentcage_core::VERSION)
}

/// Build the whole command tree.
///
/// `styled_banner` is `false` whenever the help is not going to a
/// terminal; `click.echo` strips styles from a non-tty stream and the
/// banner has to do the same, or every piped `agentcage --help` grows
/// escape bytes the Python does not emit.
pub(crate) fn command(styled_banner: bool) -> Command {
    let mut root = Command::new(PROG)
        .about("Defense-in-depth proxy sandbox for AI agents.")
        .before_help(banner::banner_text(agentcage_core::VERSION, styled_banner))
        .after_help(aliases_section(&TOP_LEVEL_ALIASES))
        // click's `Group` shows its help and exits 2 when given nothing.
        .arg_required_else_help(true)
        .disable_help_subcommand(true)
        .subcommand_value_name("COMMAND")
        .subcommand_help_heading("Commands")
        // Both flags are hand-rolled: click offers `--version` and
        // `--help` with no short forms, and clap offers `-V` and `-h`
        // as well. See `args::help_arg`.
        .disable_help_flag(true)
        .disable_version_flag(true)
        .arg(
            Arg::new("version")
                .long("version")
                .action(ArgAction::SetTrue)
                .help("Show the version and exit."),
        )
        .arg(args::help_arg())
        // Alphabetical, because click's `format_commands` sorts the
        // listing and clap prints declaration order. Sorting here is the
        // whole fix; `every_command_and_subcommand_is_present` asserts
        // the order, not just the set.
        .subcommand(cage::command())
        .subcommand(completions::command())
        .subcommand(init::doctor())
        .subcommand(domain::command())
        .subcommand(init::init())
        .subcommand(scaffold::command())
        .subcommand(secret::command())
        .subcommand(watcher::command());

    // The 19 `_BannerGroup` aliases, as hidden top-level commands. They
    // are clones rather than `Command::alias` entries because their
    // targets are not siblings: `ls` is a root command that runs
    // `cage list`, which clap has no way to express as an alias.
    let plain = cage::plain();
    for (alias, path) in TOP_LEVEL_ALIASES {
        let target_name = path.rsplit(' ').next().expect("non-empty path");
        let target = plain
            .find_subcommand(target_name)
            .unwrap_or_else(|| panic!("`cage {target_name}` is missing; alias `{alias}` is stale"))
            .clone();
        root = root.subcommand(target.name(alias).hide(true));
    }
    root
}

/// Parse `argv` (excluding `argv[0]`) and act on it.
pub(crate) fn dispatch(argv: &[String]) -> ExitCode {
    let styled = std::io::stdout().is_terminal();
    let mut full = vec![PROG.to_string()];
    full.extend_from_slice(argv);

    let matches = match command(styled).try_get_matches_from(full) {
        Ok(matches) => matches,
        Err(err) => {
            // clap already knows whether this is help (stdout, 0) or an
            // error (stderr, 2), and its codes agree with click's.
            let _ = err.print();
            return ExitCode::from(u8::try_from(err.exit_code()).unwrap_or(2));
        }
    };

    // `--version` is eager in click: it wins over whatever follows it.
    if matches.get_flag("version") {
        println!("{}", version_line());
        return ExitCode::SUCCESS;
    }

    let Some((name, sub)) = matches.subcommand() else {
        // Unreachable while `arg_required_else_help` is set and
        // `--version` is the only other way to get here, but a tree is a
        // thing people edit.
        let mut err = std::io::stderr();
        let _ = writeln!(err, "{}", command(false).render_help());
        return ExitCode::from(2);
    };

    if name == "completions" {
        let shell = sub
            .get_one::<String>("shell")
            .expect("required by the parser");
        let mut out = std::io::stdout();
        completions::generate(shell, command(false), &mut out);
        return ExitCode::SUCCESS;
    }

    // PR D15. `doctor` takes no arguments, reads no state and writes
    // nothing, so it is the one command whose body can land before the
    // e2e phase that would otherwise gate it.
    if name == "doctor" {
        return ExitCode::from(agentcage_cli::doctor::main());
    }

    let path = canonical_path(name, sub);
    if let Some(code) = dispatch_ported(&path, name, sub) {
        return code;
    }
    not_implemented(&path)
}

/// The command bodies this port has, keyed by canonical path.
///
/// `None` means "still a stub", which keeps [`not_implemented`] as the
/// single place that says so. The match is on the *canonical* path, so
/// `agentcage rm x` and `agentcage cage destroy x` reach the same body
/// without the aliases being listed twice.
fn dispatch_ported(path: &str, name: &str, sub: &ArgMatches) -> Option<ExitCode> {
    use crate::cli::cage::{audit, create, lifecycle, logs, update, verify};
    use crate::cli::context::Ctx;

    // The leaf's own matches: a top-level alias resolves to a command
    // with none below it, a `cage <cmd>` invocation has one.
    let leaf = sub.subcommand().map_or(sub, |(_, leaf)| leaf);
    let _ = name;

    // Nothing is constructed until a path matches, so a stubbed
    // command still costs no filesystem probe.
    let named = |id: &str| -> String { leaf.get_one::<String>(id).cloned().unwrap_or_default() };
    Some(match path {
        "cage create" => create::main(&Ctx::system(), leaf),
        "cage update" => update::main(&Ctx::system(), leaf),
        "cage list" => lifecycle::list(&Ctx::system()),
        "cage status" => lifecycle::status(&Ctx::system(), leaf),
        "cage show" => lifecycle::show(&Ctx::system(), &named("name")),
        "cage destroy" => lifecycle::destroy(&Ctx::system(), leaf),
        "cage verify" => verify::main(&Ctx::system(), &named("name")),
        "cage audit" => audit::main(&Ctx::system(), leaf),
        "cage logs" => logs::main(&Ctx::system(), leaf),
        // PR D13. `cage har` reads one file the egress addon wrote
        // and writes JSON; it touches no container and no unit.
        "cage har" => ExitCode::from(agentcage_cli::har::main(&cage::query::har_args(
            self::leaf(sub),
        ))),
        _ => return None,
    })
}

/// The deepest `ArgMatches` under `sub` — where a leaf command's own
/// options were parsed.
///
/// `canonical_path` walks the same chain to spell the command; this
/// returns what is at the end of it, so an invocation through one of the
/// hidden top-level aliases reaches the same matches as the canonical
/// spelling.
fn leaf(sub: &ArgMatches) -> &ArgMatches {
    let mut current = sub;
    while let Some((_, next)) = current.subcommand() {
        current = next;
    }
    current
}

/// The command a parse resolved to, spelled the way the user would type
/// it canonically — aliases expanded, so `agentcage rm x` reports
/// `cage destroy`.
pub(crate) fn canonical_path(name: &str, sub: &ArgMatches) -> String {
    let head = TOP_LEVEL_ALIASES
        .iter()
        .find(|(alias, _)| *alias == name)
        .map_or_else(|| name.to_string(), |(_, path)| (*path).to_string());

    let mut parts = vec![head];
    let mut current = sub;
    while let Some((child, next)) = current.subcommand() {
        parts.push(child.to_string());
        current = next;
    }
    parts.join(" ")
}

/// The stub every command currently ends at.
fn not_implemented(path: &str) -> ExitCode {
    eprintln!(
        "{PROG}: `{path}` is not implemented in the Rust port yet.\n\
         The command tree is complete (PR D5); the bodies land in D6-D16.\n\
         Run the Python `agentcage {path}` until PR F2 flips the default."
    );
    ExitCode::from(EXIT_NOT_IMPLEMENTED)
}

#[cfg(test)]
mod tests {
    use super::{TOP_LEVEL_ALIASES, command, version_line};

    /// clap's own debug assertions catch duplicate names, conflicting
    /// aliases and ill-formed argument relationships. They only run when
    /// something asks the tree to build itself completely.
    #[test]
    fn the_tree_is_internally_consistent() {
        command(false).debug_assert();
    }

    /// The one string this port genuinely has to get right.
    #[test]
    fn version_matches_the_click_format() {
        let line = version_line();
        assert_eq!(
            line,
            format!("agentcage, version {}", agentcage_core::VERSION)
        );
        assert!(line.starts_with("agentcage, version "));
    }

    /// Every top-level alias resolves, and resolves to a real command.
    #[test]
    fn top_level_aliases_are_reachable_and_hidden() {
        let root = command(false);
        for (alias, path) in TOP_LEVEL_ALIASES {
            let found = root
                .find_subcommand(alias)
                .unwrap_or_else(|| panic!("no top-level `{alias}`"));
            assert!(found.is_hide_set(), "`{alias}` should not be listed");
            let target = path.rsplit(' ').next().unwrap();
            let cage = root.find_subcommand("cage").expect("cage group");
            assert!(
                cage.find_subcommand(target).is_some(),
                "`{alias}` points at missing `{path}`"
            );
        }
    }

    /// `-h` and `-V` are clap's, not click's, and must not exist.
    #[test]
    fn no_short_help_or_version_flags() {
        let root = command(false);
        let shorts: Vec<char> = root
            .get_arguments()
            .filter_map(clap::Arg::get_short)
            .collect();
        assert!(!shorts.contains(&'h'), "{shorts:?}");
        assert!(!shorts.contains(&'V'), "{shorts:?}");
    }
}
