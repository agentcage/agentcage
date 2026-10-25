//! `agentcage update`: the command tree half of
//! [`agentcage_cli::self_update`].
//!
//! `update` used to be a hidden root alias for `cage update`, so
//! `agentcage update my-agent` rebuilt a cage. A positional that is not
//! a version is that habit, and it is answered with where the command
//! went rather than with "no such release".

use std::process::ExitCode;

use agentcage_cli::self_update::{self, Outcome, Request, Version};
use clap::{ArgMatches, Command};

use crate::cli::args::{flag, leaf, optional_positional};

pub(crate) fn command() -> Command {
    leaf("update")
        .about("Update agentcage to the latest release.")
        .long_about(
            "Update agentcage to the latest release.\n\n\
             Downloads the release for this platform from GitHub, checks its sha256, \
             checks that it runs, and replaces this binary with it. VERSION installs a \
             specific release instead, which may be older. Refuses a binary that \
             Homebrew or a system package manager installed, and says how to upgrade \
             it there.\n\n\
             Cages are not touched: run `agentcage cage update <name>` afterwards to \
             rebuild a cage's egress with the new release.",
        )
        .arg(optional_positional("version", "VERSION").help("The release to install, e.g. 0.53.1."))
        .arg(flag(
            "check",
            "check",
            "Only report whether an update is available.",
        ))
}

pub(crate) fn main(matches: &ArgMatches) -> ExitCode {
    let requested = matches.get_one::<String>("version");
    let version = match requested.map(|text| (text, Version::parse(text))) {
        None => None,
        Some((_, Some(version))) => Some(version),
        Some((text, None)) => {
            eprintln!(
                "error: '{text}' is not a release version (e.g. 0.53.1).\n\
                 `agentcage update` now updates agentcage itself. To rebuild a cage, run:\n  \
                 agentcage cage update {text}"
            );
            return ExitCode::from(2);
        }
    };
    let current = Version::parse(agentcage_core::VERSION).expect("the crate version is x.y.z");
    let exe = match self_update::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            eprintln!("error: could not find the running agentcage: {error}");
            return ExitCode::FAILURE;
        }
    };
    let repo = std::env::var("AGENTCAGE_REPO")
        .ok()
        .filter(|repo| !repo.is_empty())
        .unwrap_or_else(|| self_update::DEFAULT_REPO.to_owned());

    let runner = agentcage_exec::SystemRunner::new();
    let request = Request {
        repo: &repo,
        version,
        check: matches.get_flag("check"),
        exe: &exe,
        current,
    };
    match self_update::run(&runner, &request) {
        Ok(outcome) => {
            report(&outcome);
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn report(outcome: &Outcome) {
    match outcome {
        Outcome::UpToDate(version) => println!("agentcage {version} is up to date."),
        Outcome::Available { from, to } => {
            println!("agentcage {to} is available (installed: {from}). Run: agentcage update");
        }
        Outcome::AheadOfLatest { current, latest } => println!(
            "agentcage {current} is newer than the latest release ({latest}); nothing to do."
        ),
        Outcome::Updated { from, to } => {
            println!("Updated agentcage {from} -> {to}.");
            let cages = agentcage_state::Paths::from_env()
                .list_deployments()
                .unwrap_or_default();
            if !cages.is_empty() {
                println!(
                    "Cages keep running the egress they were built with. To rebuild each \
                     with this release:"
                );
                for cage in cages {
                    println!("  agentcage cage update {cage}");
                }
            }
        }
    }
}
