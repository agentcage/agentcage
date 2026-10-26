//! `agentcage version` — the version, for humans and for scripts.
//!
//! `--version` already exists and is what `install.sh` and the e2e
//! harness parse; it prints `agentcage, version <version>` and nothing
//! else, and that string is a contract. This command is the
//! machine-readable sibling the automation contract asks for:
//! `agentcage version --json` writes the same value inside the shared
//! envelope, so a script can ask one document for the tool's version
//! and read it with the same four lines it uses for `paths` or
//! `domain list`.
//!
//! Without `--json` it prints exactly what `--version` prints, so
//! `agentcage version` is a safe spelling to teach people.

use std::process::ExitCode;

use agentcage_core::har::json::Json;
use clap::{ArgMatches, Command};

use crate::cli::args::{flag, leaf};
use crate::cli::json_out;

/// The command, with its one flag.
pub(crate) fn command() -> Command {
    leaf("version")
        .about("Show the version and exit.")
        .arg(flag("as_json", "json", "Output as JSON."))
}

/// The body.
pub(crate) fn main(matches: &ArgMatches) -> ExitCode {
    if matches.get_flag("as_json") {
        json_out::print(
            "version",
            json_out::object(vec![
                ("name", Json::string(crate::cli::PROG)),
                ("version", Json::string(agentcage_core::VERSION)),
            ]),
            true,
            &[],
        );
    } else {
        println!("{}", crate::cli::version_line());
    }
    ExitCode::SUCCESS
}
