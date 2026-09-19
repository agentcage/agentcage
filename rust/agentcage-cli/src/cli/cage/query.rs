//! `cage audit`, `cage har` and `cage logs` — the three read-only
//! commands, split out of [`super`] because between them they carry 27
//! of the tree's 80 declared options and all four hidden ones.
//!
//! `audit` and `har` read the same two JSONL files the egress addon
//! writes and share five filter options verbatim; keeping them next to
//! each other is what makes a divergence between the two visible.

use clap::{Arg, ArgAction, Command};

use crate::cli::args::{
    DECISIONS, DIRECTIONS, INTEGER, PATH, SERVICES, SEVERITIES, TEXT, cage_name, flag, leaf,
    multi_opt, value_opt,
};

// ── shared filters ──────────────────────────────────────────────────
//
// `cage audit` and `cage har` declare these with identical spellings and
// identical help strings in `cli.py`. They are functions rather than a
// copied block so that the next person to reword one reworders both.

/// `-d/--decision`, repeatable, closed over [`DECISIONS`].
fn decision_filter() -> Arg {
    multi_opt(
        "decisions",
        "decision",
        "[blocked|flagged|allowed]",
        "Filter by decision (repeatable).",
    )
    .short('d')
    .value_parser(DECISIONS)
}

/// `--direction`, repeatable, closed over [`DIRECTIONS`].
fn direction_filter(help: &'static str) -> Arg {
    multi_opt("directions", "direction", "[inbound|outbound]", help).value_parser(DIRECTIONS)
}

/// `--method`, repeatable, free text (click does not close this set).
fn method_filter() -> Arg {
    multi_opt(
        "methods",
        "method",
        TEXT,
        "Filter by HTTP method (repeatable).",
    )
}

/// `--since`, a relative window or an ISO date, parsed downstream.
fn since_filter() -> Arg {
    value_opt(
        "since",
        "since",
        TEXT,
        "Time window: 1h, 30m, 7d, or ISO date.",
    )
}

// ── cage audit ──────────────────────────────────────────────────────

/// `agentcage cage audit NAME` — query the proxy's `audit.jsonl`.
///
/// Two of the hidden back-compat options live here. `--lines` is a
/// second spelling of `-n/--max-entries` and `--json-lines` a second
/// spelling of `--json`; both are separate parameters with their own
/// destinations rather than aliases, because `cli.py` has to tell
/// "the user passed the old flag" from "the user passed the new one"
/// to resolve the two against each other. Reproduce them as separate
/// options, not as `Arg::alias`, or that distinction is lost.
pub(crate) fn audit() -> Command {
    leaf("audit")
        .about("Query, filter, and summarize proxy audit logs.")
        .arg(cage_name())
        .arg(decision_filter())
        .arg(multi_opt(
            "hosts",
            "host",
            TEXT,
            "Filter by target host (substring match, repeatable).",
        ))
        .arg(multi_opt(
            "inspectors",
            "inspector",
            TEXT,
            "Filter by inspector name (repeatable).",
        ))
        .arg(
            value_opt(
                "severity",
                "severity",
                "[debug|info|warning|error|critical]",
                "Minimum inspector severity.",
            )
            .value_parser(SEVERITIES),
        )
        .arg(direction_filter(
            "Filter by traffic direction (repeatable).",
        ))
        .arg(method_filter())
        .arg(since_filter())
        .arg(
            value_opt(
                "max_entries",
                "max-entries",
                INTEGER,
                "Max entries to show (0 = unlimited).",
            )
            .short('n')
            .value_parser(clap::value_parser!(i64))
            .default_value("100"),
        )
        .arg(
            value_opt(
                "max_entries_compat",
                "lines",
                INTEGER,
                "Backward compat alias for --max-entries.",
            )
            .value_parser(clap::value_parser!(i64))
            .hide(true),
        )
        .arg(flag("follow", "follow", "Stream new entries in real time.").short('f'))
        .arg(flag("as_json", "json", "Output as JSON lines."))
        .arg(
            flag(
                "as_json_lines",
                "json-lines",
                "Backward compat alias for --json.",
            )
            .hide(true),
        )
        .arg(flag("summary", "summary", "Show aggregated statistics."))
        .arg(flag("no_color", "no-color", "Disable colored output."))
}

// ── cage har ────────────────────────────────────────────────────────

/// The `cage har` docstring, verbatim from `cli.py`.
///
/// The `\x08` click puts before the two-item glossary is a "do not
/// rewrap this paragraph" marker in click's formatter and has no clap
/// equivalent; it is dropped, and the indentation that makes the block
/// readable is kept. See `tests/fixtures/cli-surface/README.md`.
const HAR_LONG: &str = "\
Export captured HTTP traffic as HAR 1.2 JSON.

Reads the capture JSONL file for a cage and produces standard HAR JSON
loadable in Chrome DevTools (Network > Import HAR).

Two perspectives are available:

  inbound   What the bot saw inside the cage (placeholders, redacted
            secrets). Safe to share. This is the default.
  outbound  What went on the wire (real injected secrets, raw server
            responses). Treat as sensitive.";

/// `agentcage cage har NAME` — export capture records as HAR 1.2.
pub(crate) fn har() -> Command {
    leaf("har")
        .about("Export captured HTTP traffic as HAR 1.2 JSON.")
        .long_about(HAR_LONG)
        .arg(cage_name())
        .arg(
            value_opt(
                "view",
                "view",
                "[inbound|outbound]",
                "Perspective to export: inbound (cage sees, safe to share) or outbound (wire, contains secrets).",
            )
            .value_parser(DIRECTIONS)
            .default_value("inbound"),
        )
        .arg(decision_filter())
        .arg(multi_opt(
            "hosts",
            "host",
            TEXT,
            "Filter by host (substring match, repeatable).",
        ))
        .arg(method_filter())
        .arg(direction_filter(
            "Filter by traffic direction (repeatable).",
        ))
        .arg(since_filter())
        .arg(
            value_opt(
                "max_entries",
                "max-entries",
                INTEGER,
                "Max entries (0 = unlimited).",
            )
            .short('n')
            .value_parser(clap::value_parser!(i64))
            .default_value("0"),
        )
        .arg(
            value_opt(
                "output_file",
                "output",
                PATH,
                "Output file (default: stdout).",
            )
            .short('o'),
        )
        .arg(flag(
            "json_lines",
            "json-lines",
            "Output raw capture JSONL instead of HAR.",
        ))
        .arg(
            flag(
                "json_compat",
                "json",
                "Backward compat alias for --json-lines.",
            )
            .hide(true),
        )
}

// ── cage logs ───────────────────────────────────────────────────────

/// `agentcage cage logs NAME` — journal output for a cage's units.
///
/// `-n/--lines/--tail` is one option with three spellings, and `--tail`
/// is there because docker and podman spell it that way. In clap those
/// extra spellings are `Arg::alias`, not separate arguments — unlike
/// `audit`'s `--lines`, nothing downstream needs to know which one the
/// user typed.
pub(crate) fn logs() -> Command {
    leaf("logs")
        .about("Show journalctl logs for a cage.")
        .arg(cage_name())
        // No help text in `cli.py`, and that is not an oversight worth
        // fixing here: the fixture records `help: null`, and inventing
        // a sentence would be a surface change smuggled in under a port.
        .arg(
            Arg::new("services")
                .short('s')
                .long("service")
                .value_name("[cage|egress]")
                .action(ArgAction::Append)
                .value_parser(SERVICES),
        )
        .arg(
            value_opt(
                "lines",
                "lines",
                INTEGER,
                "Number of lines to show (alias: --tail, like docker/podman).",
            )
            .short('n')
            .alias("tail")
            .value_parser(clap::value_parser!(i64))
            .default_value("50"),
        )
        .arg(flag("follow", "follow", "Stream logs in real time.").short('f'))
        .arg(flag("no_follow", "no-follow", "Backward compat no-op.").hide(true))
        .arg(value_opt(
            "since",
            "since",
            TEXT,
            "Show entries since a time, journalctl syntax (e.g. '10 min ago', 'today', '2026-05-29 14:00'). Not supported on apple-container.",
        ))
        .arg(
            value_opt(
                "min_level",
                "severity",
                "[debug|info|warning|error|critical]",
                "Minimum severity level to show.",
            )
            .short('l')
            .value_parser(SEVERITIES),
        )
}
