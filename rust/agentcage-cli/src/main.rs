//! The `agentcage` binary.
//!
//! # Why this crate exists
//!
//! Everything that talks to the world lives here: argument parsing, the
//! `CommandRunner` seam over `podman` / `systemctl` / `limactl` /
//! `container(1)`, the secret stores, terminal handling and every exit
//! code. [`agentcage_core`] is forbidden all of it, which is what makes
//! that crate testable by fixture diff. The split only pays off if this
//! side actually absorbs the mess, so when something here looks like it
//! could be pure, move it — do not weaken `agentcage-core`'s rules.
//!
//! It is also the only crate of the three that is a `[[bin]]`, so the
//! two libraries stay usable from tests, from benchmarks and from
//! whatever tooling wants them without dragging in a `main`.
//!
//! # What will live here
//!
//! Per RUST-PORT-PLAN.md Track D, which replaces `cli.py` — 5,632 lines
//! in one file, and the plan calls it "already this codebase's worst
//! seam". It is to be split one module per command group, not
//! transcribed.
//!
//! The clap command tree arrives in PR D5, and it is not a small job:
//! click gives agentcage an `AliasGroup` (`ls`→`list`, `rm`→`destroy`,
//! `ps`→`list`, `reload`→`restart`, `config`→`edit`), a `_BannerGroup`
//! help override, hidden back-compat options (`--lines`, `--json`,
//! `--no-follow`), `ignore_unknown_options` passthrough for `run` and
//! `exec`, and shell completions that click provides implicitly and clap
//! has to generate. D5's acceptance check is a golden diff of `--help`
//! against the click output for every subcommand.
//!
//! Then D6–D12 fill the tree in, each one gated on the e2e phase that
//! already covers it, and D13–D16 pick up `har`, `init`/`scaffold`/`run`,
//! `doctor` and the legacy-watcher cleanup.
//!
//! # What this stub does
//!
//! `--version` and `--help`, and nothing else. It answers `--version`
//! with the exact string the Python CLI prints, because that string is
//! parsed by `install.sh` and by the e2e harness. Every other argument
//! is an error that says the command tree is not built yet — the stub
//! does not accept a subcommand it cannot honour, because a binary that
//! silently no-ops `cage destroy` is worse than one that refuses.
//!
//! # Dependencies
//!
//! `agentcage-core` and `agentcage-assets`, and nothing external. The
//! argument handling below is thirty lines of `match` rather than
//! `clap`, so that the dependency arrives in D5 where the command tree
//! it exists to build actually shows up.

use std::process::ExitCode;

/// The program name, as it appears in `--version`, `--help` and errors.
///
/// The crate is `agentcage-cli`; the installed binary and everything a
/// user ever types is `agentcage`. Do not use `CARGO_PKG_NAME` here.
const PROG: &str = "agentcage";

/// What a run of the CLI produced: some text, and an exit status.
///
/// Splitting this out from [`main`] is what makes the stub testable
/// without spawning a process. The command tree in PR D5 should keep the
/// shape: decide first, print last.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    /// Text to write, with no trailing newline.
    text: String,
    /// `true` when `text` belongs on stderr rather than stdout.
    is_error: bool,
    /// The process exit code.
    code: u8,
}

impl Outcome {
    /// A successful run that prints to stdout.
    fn ok(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: false,
            code: 0,
        }
    }

    /// A failed run that prints to stderr.
    ///
    /// Exit code 2 is what click uses for a usage error, and the e2e
    /// harness distinguishes it from a command that ran and failed.
    fn usage_error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
            code: 2,
        }
    }
}

/// The version line, byte-identical to what the Python CLI prints.
///
/// `cli.py` declares `@click.version_option(version=..., prog_name="agentcage")`
/// and click's default template is `%(prog)s, version %(version)s`. That
/// exact string is what users, `install.sh` and the e2e harness read, so
/// it has to survive the port unchanged even though it is not a format
/// anything else would choose. The number comes from
/// [`agentcage_core::VERSION`].
fn version_line() -> String {
    format!("{PROG}, version {}", agentcage_core::VERSION)
}

/// Decide what a given argument list should produce.
///
/// `args` excludes `argv[0]`.
fn run(args: &[String]) -> Outcome {
    match args {
        [] => Outcome::ok(help_text()),
        [flag] if flag == "--version" || flag == "-V" => Outcome::ok(version_line()),
        [flag] if flag == "--help" || flag == "-h" => Outcome::ok(help_text()),
        _ => Outcome::usage_error(format!(
            "{PROG}: the Rust command tree is not built yet -- only --version and --help work.\n\
             Use the Python `agentcage` for everything else; see RUST-PORT-PLAN.md, Track D."
        )),
    }
}

/// The stub's `--help`.
///
/// Deliberately not a copy of the Python banner and command list. PR D4
/// ports the banner and D5 ports the command tree, each against a golden
/// diff of the click output; a hand-written imitation here would be a
/// second thing to keep in sync, and it would advertise commands this
/// binary does not have.
fn help_text() -> String {
    format!(
        "{}\n\
         \n\
         Defense-in-depth proxy sandbox for AI agents.\n\
         \n\
         This is the Rust port's skeleton binary. It carries the version and\n\
         nothing else; no cage, domain, secret, watcher, init, scaffold or\n\
         doctor command exists here yet. Run the Python `agentcage` for real\n\
         work until PR F2 flips the default.\n\
         \n\
         Usage: {PROG} [--version | --help]\n\
         \n\
         Options:\n\
         \x20 --version, -V  Show the version and exit.\n\
         \x20 --help,    -h  Show this message and exit.\n\
         \n\
         Plan: RUST-PORT-PLAN.md (branch `rust-port`).",
        version_line()
    )
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = run(&args);

    if outcome.is_error {
        eprintln!("{}", outcome.text);
    } else {
        println!("{}", outcome.text);
    }

    ExitCode::from(outcome.code)
}

#[cfg(test)]
mod tests {
    use super::{Outcome, help_text, run, version_line};

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_string()).collect()
    }

    /// The one string this stub genuinely has to get right.
    ///
    /// `tests/test_version.py::test_rust_workspace_version_matches_version_file`
    /// and `scripts/check-version.sh` between them hold the number equal
    /// to the root `VERSION` file; this holds the *shape* equal to
    /// click's `%(prog)s, version %(version)s`.
    #[test]
    fn version_matches_the_click_format() {
        let line = version_line();
        assert_eq!(
            line,
            format!("agentcage, version {}", agentcage_core::VERSION)
        );
        assert!(line.starts_with("agentcage, version "));
        assert!(!line.ends_with('\n'), "the newline is println!'s job");
    }

    #[test]
    fn version_flags_print_the_version() {
        for flag in ["--version", "-V"] {
            assert_eq!(run(&argv(&[flag])), Outcome::ok(version_line()), "{flag}");
        }
    }

    #[test]
    fn help_flags_and_no_arguments_print_help() {
        for args in [vec![], vec!["--help"], vec!["-h"]] {
            assert_eq!(run(&argv(&args)), Outcome::ok(help_text()), "{args:?}");
        }
    }

    /// The stub refuses what it cannot do, rather than no-opping it.
    ///
    /// A skeleton that exits 0 on `cage destroy` is a trap; this keeps
    /// the failure loud for as long as the command tree is missing.
    #[test]
    fn unimplemented_commands_fail_loudly() {
        for args in [vec!["cage", "list"], vec!["doctor"], vec!["--nope"]] {
            let outcome = run(&argv(&args));
            assert_eq!(outcome.code, 2, "{args:?}");
            assert!(outcome.is_error, "{args:?}");
            assert!(outcome.text.contains("not built yet"), "{args:?}");
        }
    }

    /// Help says what this binary is not, so nobody files a bug.
    #[test]
    fn help_admits_the_command_tree_is_missing() {
        let help = help_text();
        assert!(help.starts_with(&version_line()));
        assert!(help.contains("skeleton"));
        assert!(help.contains("--version"));
    }
}
