//! `agentcage watcher <command>` — the in-egress traffic watcher.
//!
//! The one group whose alias does not point at `list`: `ls` resolves to
//! `findings`, because this group has no `list`. Worth noticing when
//! reading the alias table — four of the five `AliasGroup`s say
//! `{"ls": "list"}` and this one says `{"ls": "findings"}`.

use clap::Command;

use crate::cli::args::{
    FINDING_SEVERITIES, INTEGER, TEXT, aliases_section, cage_name, flag, group, leaf, multi_opt,
    value_opt,
};

/// The `watcher` group's docstring, verbatim from `cli.py:5498`.
const WATCHER_LONG: &str = "\
Read the traffic watcher's findings and scan status.

The watcher is an opt-in in-egress LLM agent that re-analyzes the
cage's recent traffic (audit + capture) after the fact and flags
suspicious patterns; it can revoke the runtime grants its analysis
damns (narrowing only) and recommends — never applies — baseline
edits. Enable it with the ``agents.watcher:`` block in cage.yaml. See
docs/explain/traffic-watcher.md.";

/// The `watcher` group.
pub(crate) fn command() -> Command {
    group("watcher")
        .about("Read the traffic watcher's findings and scan status.")
        .long_about(WATCHER_LONG)
        .after_help(aliases_section(&[("ls", "findings")]))
        .subcommand(findings())
        .subcommand(
            leaf("status")
                .about("Show the traffic watcher's configuration and last scan.")
                .arg(cage_name()),
        )
}

/// `watcher findings NAME`.
fn findings() -> Command {
    leaf("findings")
        .alias("ls")
        .about("Show the traffic watcher's recorded findings.")
        .arg(cage_name())
        .arg(
            multi_opt(
                "severities",
                "severity",
                "[info|low|medium|high|critical]",
                "Filter by severity (repeatable).",
            )
            .short('s')
            .value_parser(FINDING_SEVERITIES),
        )
        .arg(multi_opt(
            "hosts",
            "host",
            TEXT,
            "Filter by domain/host (substring match, repeatable).",
        ))
        .arg(
            value_opt(
                "max_entries",
                "max-entries",
                INTEGER,
                "Max findings to show (most recent; 0 = all).",
            )
            .short('n')
            .value_parser(clap::value_parser!(i64))
            .default_value("50"),
        )
        .arg(flag(
            "as_json",
            "json",
            "Output raw finding entries as JSON lines.",
        ))
}
