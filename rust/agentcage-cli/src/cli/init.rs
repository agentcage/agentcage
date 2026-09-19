//! `agentcage init [NAME]` and `agentcage doctor` — the two top-level
//! leaf commands.
//!
//! Small enough to share a module, and they have nothing in common
//! except that neither belongs to a group.

use clap::Command;

use crate::cli::args::{INTEGER, ISOLATIONS, TEXT, flag, leaf, optional_positional, value_opt};

/// `agentcage init` — write a starter `cage.yaml`.
pub(crate) fn init() -> Command {
    leaf("init")
        .about("Scaffold a new agentcage config file.")
        .arg(optional_positional("name", "NAME"))
        .arg(
            value_opt("output", "output", TEXT, "Output file path.")
                .short('o')
                .default_value("cage.yaml"),
        )
        .arg(value_opt("image", "image", TEXT, "Container image.").default_value("node:22-slim"))
        .arg(
            value_opt(
                "isolation",
                "isolation",
                "[container|vm|apple-container]",
                "Isolation backend (default: auto-detect from platform — container on Linux, apple-container on macOS 26+ ASi when Apple `container` is installed, vm otherwise).",
            )
            .value_parser(ISOLATIONS),
        )
        .arg(flag("force", "force", "Overwrite existing file."))
        .arg(value_opt(
            "scaffold",
            "scaffold",
            TEXT,
            "Use a scaffold template (e.g. openclaw).",
        ))
        .arg(flag(
            "list_scaffolds",
            "list-scaffolds",
            "List available scaffolds and exit.",
        ))
        .arg(
            value_opt(
                "port",
                "port",
                INTEGER,
                "Host port to publish (scaffold-specific).",
            )
            .value_parser(clap::value_parser!(i64)),
        )
}

/// `agentcage doctor` — no arguments at all, which is the whole point.
pub(crate) fn doctor() -> Command {
    leaf("doctor").about("Check system health and diagnose common issues.")
}
