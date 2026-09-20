//! `cage audit`, `cage har` and `cage logs` — the three read-only
//! commands, split out of [`super`] because between them they carry 27
//! of the tree's 80 declared options and all four hidden ones.
//!
//! `audit` and `har` read the same two JSONL files the egress addon
//! writes and share five filter options verbatim; keeping them next to
//! each other is what makes a divergence between the two visible.

use std::path::PathBuf;

use agentcage_cli::har::HarArgs;
use clap::{Arg, ArgAction, ArgMatches, Command};

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
            // The same divergence D13 fixed on `cage har`: click's
            // `default=100` is an unbounded `int`, so `-n -3` parses
            // there and simply does not limit anything (`cli.py` tests
            // `max_entries > 0`), while clap reads a leading `-` as
            // another flag and reports a usage error. Both `-n`s have
            // to say this or the two commands disagree about a command
            // line the Python accepts for either.
            .allow_negative_numbers(true)
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
            // click's `default=0` is an `int` parameter with no bound,
            // so `-n -3` is accepted there and simply does not limit
            // anything (`cli.py` tests `max_entries > 0`). clap treats a
            // leading `-` as another flag unless told otherwise, so
            // without this `agentcage cage har x -n -3` would be a usage
            // error against a command line the Python runs.
            .allow_negative_numbers(true)
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

/// Read a parsed `cage har` invocation into [`HarArgs`].
///
/// Deliberately next to [`har`]'s declaration rather than in the command
/// body: these ids are a contract between two files, and a typo in one
/// of them is a silently ignored option. Reading the list beside the one
/// that declares it is the only cheap way to check it.
pub(crate) fn har_args(matches: &ArgMatches) -> HarArgs {
    HarArgs {
        name: string(matches, "name"),
        view: string(matches, "view"),
        decisions: strings(matches, "decisions"),
        hosts: strings(matches, "hosts"),
        methods: strings(matches, "methods"),
        directions: strings(matches, "directions"),
        since: matches.get_one::<String>("since").cloned(),
        max_entries: matches
            .get_one::<i64>("max_entries")
            .copied()
            .unwrap_or_default(),
        output_file: matches.get_one::<String>("output_file").map(PathBuf::from),
        // `json_lines = json_lines or json_compat`, resolved here so the
        // body never learns there were two spellings.
        json_lines: matches.get_flag("json_lines") || matches.get_flag("json_compat"),
    }
}

/// A required-or-defaulted string, which the parser guarantees.
fn string(matches: &ArgMatches, id: &str) -> String {
    matches
        .get_one::<String>(id)
        .cloned()
        .unwrap_or_else(|| panic!("`{id}` is required or defaulted by the parser"))
}

/// A repeatable option, in the order it was given. click's `multiple=True`
/// and clap's `Append` both yield an empty collection when absent, which
/// is what every filter downstream reads as "no constraint".
fn strings(matches: &ArgMatches, id: &str) -> Vec<String> {
    matches
        .get_many::<String>(id)
        .map(|values| values.cloned().collect())
        .unwrap_or_default()
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
            // Unbounded in click exactly as `audit`'s and `har`'s are.
            // Nothing downstream rejects a negative here — the value is
            // stringified straight into journalctl's own `-n` — so
            // without this the Rust turns a command line the Python
            // forwards into a usage error before journalctl ever sees
            // it, and the operator gets clap's complaint instead of
            // journalctl's.
            .allow_negative_numbers(true)
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::har_args;
    use crate::cli::command;

    /// The leaf `ArgMatches` for any `cage <cmd>` command line, through
    /// the real tree — the tree these ids have to agree with.
    fn leaf_matches(argv: &[&str]) -> clap::ArgMatches {
        let matches = command(false)
            .try_get_matches_from(std::iter::once("agentcage").chain(argv.iter().copied()))
            .expect("the tree accepts this command line");
        let (_, cage) = matches.subcommand().expect("cage");
        let (_, leaf) = cage.subcommand().expect("a cage subcommand");
        leaf.clone()
    }

    /// Parse a `cage har` command line through the real tree.
    fn parse(argv: &[&str]) -> super::HarArgs {
        let matches = command(false)
            .try_get_matches_from(std::iter::once("agentcage").chain(argv.iter().copied()))
            .expect("the tree accepts this command line");
        let (_, cage) = matches.subcommand().expect("cage");
        let (name, har) = cage.subcommand().expect("har");
        assert_eq!(name, "har");
        har_args(har)
    }

    /// Every id in `har_args` has to be an id `har()` declared. A typo
    /// is not a compile error — it is an option that silently does
    /// nothing — so this reads one of each out of a full command line.
    #[test]
    fn every_option_reaches_its_field() {
        let args = parse(&[
            "cage",
            "har",
            "myapp",
            "--view",
            "outbound",
            "-d",
            "blocked",
            "-d",
            "flagged",
            "--host",
            "example.com",
            "--method",
            "post",
            "--direction",
            "inbound",
            "--since",
            "1h",
            "-n",
            "5",
            "-o",
            "/tmp/x.har",
            "--json-lines",
        ]);
        assert_eq!(args.name, "myapp");
        assert_eq!(args.view, "outbound");
        assert_eq!(args.decisions, ["blocked", "flagged"]);
        assert_eq!(args.hosts, ["example.com"]);
        assert_eq!(args.methods, ["post"]);
        assert_eq!(args.directions, ["inbound"]);
        assert_eq!(args.since.as_deref(), Some("1h"));
        assert_eq!(args.max_entries, 5);
        assert_eq!(args.output_file, Some(PathBuf::from("/tmp/x.har")));
        assert!(args.json_lines);
    }

    /// click's defaults, which `show_default` makes part of the surface.
    #[test]
    fn the_bare_invocation_carries_clicks_defaults() {
        let args = parse(&["cage", "har", "myapp"]);
        assert_eq!(args.view, "inbound");
        assert_eq!(args.max_entries, 0);
        assert!(args.decisions.is_empty());
        assert!(args.since.is_none());
        assert!(args.output_file.is_none());
        assert!(!args.json_lines);
    }

    /// The hidden back-compat spelling folds into the same field.
    #[test]
    fn the_json_alias_sets_json_lines() {
        assert!(parse(&["cage", "har", "myapp", "--json"]).json_lines);
        assert!(parse(&["cage", "har", "myapp", "--json-lines"]).json_lines);
    }

    /// `-n -3` is a command line the Python runs — and does not limit
    /// anything, because `cli.py` tests `max_entries > 0`. clap would
    /// read `-3` as a flag without `allow_negative_numbers`.
    #[test]
    fn a_negative_max_entries_parses_rather_than_erroring() {
        assert_eq!(parse(&["cage", "har", "myapp", "-n", "-3"]).max_entries, -3);
    }

    /// The same divergence, on the other two `-n`s. `cage audit` and
    /// `cage logs` declare the option with the same unbounded click
    /// `int` that `cage har` does, so the same command line has to
    /// reach the same place — D13 fixed one of the three and left the
    /// other two reporting a clap usage error against input the Python
    /// accepts.
    #[test]
    fn the_other_two_n_options_take_a_negative_too() {
        let audit = leaf_matches(&["cage", "audit", "myapp", "-n", "-3"]);
        assert_eq!(audit.get_one::<i64>("max_entries").copied(), Some(-3));
        let logs = leaf_matches(&["cage", "logs", "myapp", "-n", "-3"]);
        assert_eq!(logs.get_one::<i64>("lines").copied(), Some(-3));
    }

    /// `cage logs`'s own options, read back through the real tree —
    /// the ids are a contract with `cage/logs.rs` and a typo in one of
    /// them is a silently ignored flag, not a compile error.
    #[test]
    fn every_logs_option_reaches_its_id() {
        let m = leaf_matches(&[
            "cage",
            "logs",
            "basic",
            "-s",
            "egress",
            "--tail",
            "7",
            "-f",
            "--since",
            "10 min ago",
            "-l",
            "warning",
        ]);
        assert_eq!(m.get_one::<String>("name").unwrap(), "basic");
        assert_eq!(
            m.get_many::<String>("services")
                .unwrap()
                .cloned()
                .collect::<Vec<_>>(),
            ["egress"]
        );
        assert_eq!(m.get_one::<i64>("lines").copied(), Some(7));
        assert!(m.get_flag("follow"));
        assert_eq!(m.get_one::<String>("since").unwrap(), "10 min ago");
        assert_eq!(m.get_one::<String>("min_level").unwrap(), "warning");
        // The hidden no-op is declared, so the body can read and drop it.
        assert!(!m.get_flag("no_follow"));
    }

    /// click's `Choice(["cage", "egress"])`: the v0.21 service names
    /// are a parse error, not a cage that silently has no such unit.
    #[test]
    fn the_legacy_service_names_are_refused_at_parse_time() {
        assert!(
            command(false)
                .try_get_matches_from(["agentcage", "cage", "logs", "basic", "-s", "proxy"])
                .is_err()
        );
    }
}
