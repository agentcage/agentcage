//! The oracle: every node of the clap tree, checked against the click
//! tree it replaces.
//!
//! # What is asserted, and what is deliberately not
//!
//! `tests/fixtures/cli-surface/` is generated from the live click tree
//! by `scripts/gen-cli-surface.py` (run it with `--check` in CI). It
//! holds two things: `surface.json`, the structured declaration of every
//! command, and `parse-cases.json`, the outcome of parsing 58 real
//! command lines. This module asserts the Rust tree against both.
//!
//! clap and click do not, and should not, produce the same help screen.
//! Contorting clap into click's layout would mean re-implementing
//! click's formatter, which is a much larger surface to get wrong than
//! the one it would be protecting. So the split is:
//!
//! **Asserted, because it is a contract** — every command and
//! subcommand; every alias and what it resolves to; every option's long
//! name, short name and extra spellings; every option's help text, byte
//! for byte; every flag's hidden bit; every default value; every closed
//! choice set; every argument's arity and whether it is required; the
//! `--version` string; and the exit code and parsed values for 58
//! command lines including both passthrough commands.
//!
//! **Allowed to differ, enumerated here so a reviewer can read the list
//! rather than infer it from a fuzzy comparison** — see
//! [`ALLOWED_DIFFERENCES`]. Nothing outside that list is permitted to
//! differ; every item on it is a formatting or wording difference in
//! clap's own output that no user-visible contract depends on.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use clap::{Arg, ArgAction, Command};
use serde_json::Value;

use super::{TOP_LEVEL_ALIASES, command, version_line};

/// Everything the Rust CLI is allowed to print differently from click.
///
/// This list is the deliverable half of the golden diff. If a reviewer
/// reads nothing else in this file, they should read this: it is the
/// complete set of places where the port does not reproduce the Python,
/// and the reason each one is acceptable.
const ALLOWED_DIFFERENCES: &[(&str, &str)] = &[
    (
        "Usage line capitalisation and layout",
        "click prints `Usage: agentcage cage exec [OPTIONS] NAME COMMAND...`; clap prints \
         `Usage: agentcage cage exec [OPTIONS] <NAME> <COMMAND>...`. Same commands, same \
         arity, different brackets.",
    ),
    (
        "Help text wrapping",
        "click wraps at the terminal width with a 2-space indent under a hanging option \
         column; clap wraps at its own width with its own column. No text differs, only \
         where the line breaks fall.",
    ),
    (
        "Choice metavars",
        "click renders a `click.Choice` as `[inbound|outbound]`; clap renders it as \
         `<inbound|outbound>` unless a value name is given. The value names here are set to \
         click's spelling, so this shows up only in usage lines.",
    ),
    (
        "Default annotations",
        "click appends `[default: 100]` when `show_default=True` and says nothing \
         otherwise; clap appends `[default: 100]` whenever a default exists. Four options \
         (`--since`, `--severity` on logs, `--placeholder`, `-o/--output` on backup and har) \
         gain a `[default: ]` note they did not have. The defaults themselves are asserted \
         equal; only the annotation differs.",
    ),
    (
        "Section order and headings",
        "click prints Usage / description / Options / Commands / Aliases; clap prints the \
         description / Usage / Commands / Options, with the Aliases section appended by \
         `after_help`. Every section is present with the same contents.",
    ),
    (
        "`no_args_is_help` versus `MissingSubcommand`",
        "`agentcage cage grants myapp` with no subcommand prints click's help and exits 2; \
         clap prints `error: 'agentcage cage grants' requires a subcommand` and exits 2. \
         Same exit code, different words. `agentcage cage grants` with no arguments at all \
         prints help and exits 2 in both.",
    ),
    (
        "Error wording",
        "`No such command 'nope'.` versus `unrecognized subcommand 'nope'`, and \
         `Missing argument 'NAME'.` versus `the following required arguments were not \
         provided`. Every one of them still exits 2, which is what scripts read.",
    ),
    (
        "click's `\\x08` no-rewrap marker",
        "click embeds a backspace character on its own line to tell its formatter not to \
         re-wrap the paragraph that follows (used by `cage exec`, `cage run`, `cage har` \
         and `scaffold create`). clap has no equivalent and does not need one; the marker \
         lines are dropped and the text they protected is reproduced verbatim.",
    ),
    (
        "A hidden `completions` command",
        "click provides shell completion through the `_AGENTCAGE_COMPLETE` environment \
         protocol, with no command. clap has no stable equivalent, so the tree adds a \
         hidden `agentcage completions <SHELL>`. It is the only command in the Rust tree \
         with no counterpart in `cli.py`, and it is allowlisted by name below.",
    ),
];

/// The one command the Rust tree has that `cli.py` does not.
const ADDED_COMMANDS: &[&str] = &["completions"];

// ── fixture loading ─────────────────────────────────────────────────

/// `tests/fixtures/cli-surface/`, relative to this crate's manifest.
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/cli-surface")
        .canonicalize()
        .expect("the cli-surface fixture is committed; regenerate with scripts/gen-cli-surface.py")
}

fn load(name: &str) -> Value {
    let path = fixture_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ── normalisation ───────────────────────────────────────────────────

/// Strip the differences [`ALLOWED_DIFFERENCES`] permits from help text.
///
/// Two of them: click's `\x08` no-rewrap marker lines, and trailing
/// whitespace (click's `inspect.cleandoc` leaves a trailing newline that
/// a Rust string literal would not carry).
fn normalize_help(text: &str) -> String {
    text.lines()
        .filter(|line| line.trim() != "\u{8}")
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

/// The tree, with clap's own derived state filled in.
///
/// `Command::build` is what turns declarations into answers: before it
/// runs, `Arg::get_num_args` is `None` for every argument because clap
/// has not yet resolved an action into a value range. Every structural
/// assertion below reads derived state, so every one of them needs a
/// built tree.
fn built() -> Command {
    let mut root = command(false);
    root.build();
    root
}

/// The text `--help` shows for a node: clap's long about, or its about.
fn long_help_of(cmd: &Command) -> String {
    cmd.get_long_about()
        .or_else(|| cmd.get_about())
        .map(ToString::to_string)
        .unwrap_or_default()
}

// ── tree navigation ─────────────────────────────────────────────────

/// Resolve a fixture path like `["agentcage", "cage", "audit"]`.
fn find<'a>(root: &'a Command, path: &[String]) -> Option<&'a Command> {
    let mut cursor = root;
    for name in &path[1..] {
        cursor = cursor.find_subcommand(name)?;
    }
    Some(cursor)
}

/// The click parameters of a node, keyed by their Python destination —
/// which is the id every clap `Arg` in this tree is built with.
fn click_params(node: &Value) -> BTreeMap<String, &Value> {
    node["params"]
        .as_array()
        .expect("params is an array")
        .iter()
        .filter(|p| p["opts"][0] != "--help")
        .map(|p| (p["dest"].as_str().expect("dest").to_string(), p))
        .collect()
}

// ── assertions ──────────────────────────────────────────────────────

/// Every command and subcommand in `cli.py` exists here, and nothing
/// exists here that `cli.py` does not have.
#[test]
fn every_command_and_subcommand_is_present() {
    let surface = load("surface.json");
    let root = built();
    let nodes = surface["nodes"].as_array().expect("nodes");

    let mut checked = 0usize;
    for node in nodes {
        let path: Vec<String> = node["path"]
            .as_array()
            .expect("path")
            .iter()
            .map(|v| v.as_str().expect("path element").to_string())
            .collect();
        let cmd =
            find(&root, &path).unwrap_or_else(|| panic!("missing command: {}", path.join(" ")));
        checked += 1;

        // Ordered, not a set: click sorts its command listing, so the
        // sequence is as visible as the membership.
        let expected: Vec<String> = node["subcommands"]
            .as_array()
            .expect("subcommands")
            .iter()
            .map(|v| v.as_str().expect("subcommand").to_string())
            .collect();
        let actual: Vec<String> = cmd
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .filter(|n| !ADDED_COMMANDS.contains(&n.as_str()))
            // The 19 `_BannerGroup` aliases are real commands at the
            // root; click reaches them through `get_command`, so they
            // are not in `Group.commands` and must not be compared as
            // if they were. `top_level_aliases_resolve` covers them.
            .filter(|n| path.len() > 1 || !TOP_LEVEL_ALIASES.iter().any(|(alias, _)| alias == n))
            .collect();
        assert_eq!(
            actual,
            expected,
            "subcommands of `{}` differ",
            path.join(" ")
        );
    }

    assert_eq!(
        checked as u64,
        surface["counts"]["nodes"].as_u64().expect("count"),
        "the fixture and the walk disagree about how many nodes there are"
    );
}

/// Each node's `--help` text is the click docstring, byte for byte once
/// click's `\x08` markers are dropped — and each node's one-line summary
/// is the first line of it, which is what the parent listing shows.
#[test]
fn every_help_text_matches_the_python() {
    let surface = load("surface.json");
    let root = built();

    for node in surface["nodes"].as_array().expect("nodes") {
        let path: Vec<String> = node["path"]
            .as_array()
            .expect("path")
            .iter()
            .map(|v| v.as_str().expect("path element").to_string())
            .collect();
        let label = path.join(" ");
        let cmd = find(&root, &path).unwrap_or_else(|| panic!("missing: {label}"));

        let expected = normalize_help(node["help"].as_str().unwrap_or_default());
        assert_eq!(
            normalize_help(&long_help_of(cmd)),
            expected,
            "`{label}` --help"
        );

        let first_line = expected.lines().next().unwrap_or_default();
        assert_eq!(
            cmd.get_about().map(ToString::to_string).unwrap_or_default(),
            first_line,
            "`{label}` summary line (what the parent's Commands listing prints)"
        );
    }
}

/// Every option and argument: spelling, arity, default, hidden bit,
/// choices, and help text.
#[test]
fn every_flag_and_argument_matches_the_python() {
    let surface = load("surface.json");
    let root = built();

    for node in surface["nodes"].as_array().expect("nodes") {
        let path: Vec<String> = node["path"]
            .as_array()
            .expect("path")
            .iter()
            .map(|v| v.as_str().expect("path element").to_string())
            .collect();
        let label = path.join(" ");
        let cmd = find(&root, &path).unwrap_or_else(|| panic!("missing: {label}"));
        let expected = click_params(node);

        let actual: BTreeMap<String, &Arg> = cmd
            .get_arguments()
            .filter(|a| a.get_id() != "help")
            .map(|a| (a.get_id().to_string(), a))
            .collect();

        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "`{label}` has a different set of parameters"
        );

        let passthrough = node["ignore_unknown_options"].as_bool().unwrap_or(false);
        for (dest, click) in &expected {
            let arg = actual[dest];
            check_param(&label, dest, click, arg, passthrough);
        }
    }
}

/// One parameter, in detail.
///
/// Split across four helpers because the four questions are
/// independent: what it is called, what it says, how many values it
/// takes, and what it falls back to.
fn check_param(label: &str, dest: &str, click: &Value, arg: &Arg, passthrough: bool) {
    let where_ = format!("`{label}` parameter `{dest}`");

    check_spelling(&where_, click, arg);

    assert_eq!(
        arg.get_help().map(ToString::to_string),
        click["help"].as_str().map(ToString::to_string),
        "{where_} help text"
    );
    assert_eq!(
        arg.is_hide_set(),
        click["hidden"].as_bool().unwrap_or(false),
        "{where_} hidden bit"
    );

    check_arity(&where_, click, arg, passthrough);
    check_default_and_choices(&where_, click, arg);
}

/// Long name, extra long spellings, short name — or positional-ness.
fn check_spelling(where_: &str, click: &Value, arg: &Arg) {
    let opts: Vec<&str> = click["opts"]
        .as_array()
        .expect("opts")
        .iter()
        .map(|v| v.as_str().expect("opt"))
        .collect();

    if click["kind"] == "argument" {
        assert!(arg.is_positional(), "{where_} should be positional");
        return;
    }

    let longs: Vec<&str> = opts
        .iter()
        .filter(|o| o.starts_with("--"))
        .map(|o| &o[2..])
        .collect();
    let shorts: Vec<char> = opts
        .iter()
        .filter(|o| o.len() == 2 && o.starts_with('-'))
        .map(|o| o.chars().nth(1).expect("short flag letter"))
        .collect();

    assert_eq!(
        arg.get_long(),
        longs.first().copied(),
        "{where_} primary long spelling"
    );
    let aliases: BTreeSet<&str> = arg
        .get_all_aliases()
        .unwrap_or_default()
        .into_iter()
        .collect();
    for extra in &longs[1..] {
        assert!(aliases.contains(extra), "{where_} is missing `--{extra}`");
    }
    assert_eq!(
        arg.get_short(),
        shorts.first().copied(),
        "{where_} short spelling"
    );
}

/// How many values, whether required, and whether hyphens pass through.
fn check_arity(where_: &str, click: &Value, arg: &Arg, passthrough: bool) {
    let required = click["required"].as_bool().unwrap_or(false);
    assert_eq!(arg.is_required_set(), required, "{where_} required");

    let range = arg
        .get_num_args()
        .expect("clap computes a range for every arg once the tree is built");

    if click["nargs"].as_i64().expect("nargs") == -1 {
        assert_eq!(
            range.min_values(),
            usize::from(required),
            "{where_} variadic minimum"
        );
        assert!(range.max_values() > 1, "{where_} should take many values");
        // `ignore_unknown_options` is the whole reason `cage exec foo --
        // ls -la` works, and its absence is the reason `domain add foo
        // -x` is a usage error rather than a domain called `-x`. Both
        // directions are asserted: set on the two passthrough commands,
        // clear on the other two variadics.
        assert_eq!(
            arg.is_allow_hyphen_values_set(),
            passthrough,
            "{where_} passthrough: click's `ignore_unknown_options` is {passthrough}"
        );
    } else if click["is_flag"].as_bool().unwrap_or(false) {
        assert!(
            matches!(arg.get_action(), ArgAction::SetTrue),
            "{where_} should be a boolean flag"
        );
    } else if click["multiple"].as_bool().unwrap_or(false) {
        assert!(
            matches!(arg.get_action(), ArgAction::Append),
            "{where_} is `multiple=True` and must append"
        );
        assert_eq!(range.max_values(), 1, "{where_} takes one value per use");
    } else {
        assert_eq!(range.max_values(), 1, "{where_} takes exactly one value");
    }
}

/// The fallback value and the closed set, if either exists.
fn check_default_and_choices(where_: &str, click: &Value, arg: &Arg) {
    let is_flag = click["is_flag"].as_bool().unwrap_or(false);
    let actual_default: Vec<String> = arg
        .get_default_values()
        .iter()
        .map(|v| v.to_string_lossy().into_owned())
        .collect();
    match click_default(&click["default"], is_flag) {
        None => assert!(
            actual_default.is_empty() || is_flag,
            "{where_} should have no default, has {actual_default:?}"
        ),
        Some(value) => assert_eq!(actual_default, vec![value], "{where_} default"),
    }

    let expected_choices: Vec<String> = click["type"]["choices"]
        .as_array()
        .map(|c| {
            c.iter()
                .map(|v| v.as_str().expect("choice").to_string())
                .collect()
        })
        .unwrap_or_default();
    let actual_choices: Vec<String> = arg
        .get_possible_values()
        .iter()
        .map(|p| p.get_name().to_string())
        .collect();
    assert_eq!(actual_choices, expected_choices, "{where_} choices");
}

/// Translate a recorded click default into "what clap should report".
///
/// click has three ways of saying "nothing": a literal `None`, the
/// `UNSET` sentinel the fixture records as `{"unset": true}`, and the
/// empty tuple a `multiple=True` option starts at. None of the three is
/// a value a user can observe, so all three map to "clap has no
/// default". A boolean flag's `False` is the same story on clap's side,
/// where `SetTrue` implies it.
fn click_default(value: &Value, is_flag: bool) -> Option<String> {
    if is_flag {
        return None;
    }
    match value {
        Value::Null => None,
        Value::Object(map) if map.contains_key("unset") => None,
        Value::Array(items) if items.is_empty() => None,
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        other => panic!("unhandled click default: {other}"),
    }
}

/// Every alias in `cli.py` resolves here, to the same command.
#[test]
fn every_alias_resolves_to_the_same_command() {
    let surface = load("surface.json");
    let root = built();
    let aliases = surface["aliases"].as_array().expect("aliases");

    for entry in aliases {
        let parent: Vec<String> = entry["parent"]
            .as_array()
            .expect("parent")
            .iter()
            .map(|v| v.as_str().expect("path element").to_string())
            .collect();
        let alias = entry["alias"].as_str().expect("alias");
        let target: Vec<&str> = entry["target"]
            .as_array()
            .expect("target")
            .iter()
            .map(|v| v.as_str().expect("target element"))
            .collect();

        if parent.len() == 1 {
            // A `_BannerGroup` alias: a hidden top-level command whose
            // canonical path is recorded in `TOP_LEVEL_ALIASES`.
            let sub = root
                .find_subcommand(alias)
                .unwrap_or_else(|| panic!("no top-level `{alias}`"));
            assert!(sub.is_hide_set(), "`{alias}` must not be listed");
            let (_, canonical) = TOP_LEVEL_ALIASES
                .iter()
                .find(|(a, _)| *a == alias)
                .unwrap_or_else(|| panic!("`{alias}` missing from TOP_LEVEL_ALIASES"));
            assert_eq!(*canonical, target.join(" "), "`{alias}` target");
            // The clone really is the target command, not a lookalike.
            let real = find(
                &root,
                &["agentcage".into(), target[0].into(), target[1].into()],
            )
            .expect("alias target exists");
            assert_eq!(long_help_of(sub), long_help_of(real), "`{alias}` body");
        } else {
            // An `AliasGroup` alias: registered on the sibling command.
            let group = find(&root, &parent).expect("alias parent exists");
            assert_eq!(target.len(), 1, "in-group aliases name one sibling");
            let sub = group
                .find_subcommand(target[0])
                .unwrap_or_else(|| panic!("`{}` has no `{}`", parent.join(" "), target[0]));
            let registered: BTreeSet<&str> = sub.get_all_aliases().collect();
            assert!(
                registered.contains(alias),
                "`{}` should answer to `{alias}`",
                target[0]
            );
            assert!(
                !sub.get_visible_aliases().any(|a| a == alias),
                "`{alias}` must stay out of the command listing; click prints it in the \
                 Aliases section instead"
            );
        }
    }

    assert_eq!(
        aliases.len() as u64,
        surface["counts"]["aliases"].as_u64().expect("count")
    );
}

/// The "Aliases:" section `AliasGroup.format_help` and
/// `_BannerGroup.format_help` append is reproduced verbatim.
#[test]
fn the_aliases_help_section_is_reproduced() {
    let surface = load("surface.json");
    let root = built();

    for node in surface["nodes"].as_array().expect("nodes") {
        let aliases = node["aliases"].as_object().expect("aliases map");
        let path: Vec<String> = node["path"]
            .as_array()
            .expect("path")
            .iter()
            .map(|v| v.as_str().expect("path element").to_string())
            .collect();
        let cmd = find(&root, &path).expect("node exists");
        let after = cmd
            .get_after_help()
            .map(ToString::to_string)
            .unwrap_or_default();

        if aliases.is_empty() {
            assert!(
                after.is_empty(),
                "`{}` publishes no aliases but prints a section",
                path.join(" ")
            );
            continue;
        }
        let mut expected = String::from("Aliases:\n");
        for (alias, target) in aliases {
            let _ = writeln!(
                expected,
                "  {alias} \u{2192} {}",
                target.as_str().expect("target")
            );
        }
        assert_eq!(
            after,
            expected.trim_end(),
            "`{}` Aliases section",
            path.join(" ")
        );
    }
}

/// The counts, stated rather than implied.
#[test]
fn the_counts_match_the_fixture() {
    let surface = load("surface.json");
    let counts = &surface["counts"];
    let root = built();

    let mut nodes = 0u64;
    let mut options = 0u64;
    let mut hidden = 0u64;
    let mut arguments = 0u64;
    // Depth matters: `update`, `show`, `status` and six more are both a
    // top-level alias and a real `cage` subcommand. Filtering by name
    // alone would silently drop the real ones -- which is exactly the
    // bug this count exists to catch.
    let mut walk: Vec<(usize, &Command)> = vec![(0, &root)];
    while let Some((depth, cmd)) = walk.pop() {
        if ADDED_COMMANDS.contains(&cmd.get_name()) {
            continue;
        }
        // The cloned `_BannerGroup` aliases live only at depth 1; click
        // does not count them as nodes, because they are not in
        // `Group.commands`.
        if depth == 1 && TOP_LEVEL_ALIASES.iter().any(|(a, _)| *a == cmd.get_name()) {
            continue;
        }
        nodes += 1;
        for arg in cmd.get_arguments() {
            if arg.is_positional() {
                arguments += 1;
            } else {
                options += 1;
                if arg.is_hide_set() {
                    hidden += 1;
                }
            }
        }
        walk.extend(cmd.get_subcommands().map(|sub| (depth + 1, sub)));
    }

    assert_eq!(nodes, counts["nodes"].as_u64().expect("nodes"));
    assert_eq!(arguments, counts["arguments"].as_u64().expect("arguments"));
    // click's option count includes the `--help` it adds to every node
    // and the root's `--version`; so does this walk.
    assert_eq!(options, counts["options"].as_u64().expect("options"));
    assert_eq!(hidden, counts["hidden_options"].as_u64().expect("hidden"));
}

// ── behaviour ───────────────────────────────────────────────────────

/// Replay every recorded click parse against the clap tree.
///
/// This is where the passthrough is proven. `cage exec foo -- ls -la`
/// and `run codex -- codex --version` are in the fixture with the exact
/// token lists click produced, and so are the cases where a flag-shaped
/// argument appears *before* the `--` and must still be read as this
/// command's own flag.
#[test]
fn recorded_click_parses_reproduce() {
    let cases = load("parse-cases.json");
    let mut parsed = 0usize;
    let mut errors = 0usize;

    for case in cases["cases"].as_array().expect("cases") {
        let argv: Vec<String> = case["argv"]
            .as_array()
            .expect("argv")
            .iter()
            .map(|v| v.as_str().expect("token").to_string())
            .collect();
        let label = format!("agentcage {}", argv.join(" "));

        let mut full = vec!["agentcage".to_string()];
        full.extend(argv.iter().cloned());
        let outcome = command(false).try_get_matches_from(full);

        match case["outcome"].as_str().expect("outcome") {
            "parsed" => {
                parsed += 1;
                let matches = outcome.unwrap_or_else(|e| panic!("{label} should parse, got:\n{e}"));
                let frames = case["frames"].as_array().expect("frames");
                let leaf = &frames[frames.len() - 1];
                check_parsed_frame(&label, leaf, &matches);
            }
            "error" | "no_args_is_help" => {
                errors += 1;
                let err = outcome
                    .err()
                    .unwrap_or_else(|| panic!("{label} should have failed; click exited 2"));
                assert_eq!(
                    i64::from(err.exit_code()),
                    case["exit_code"].as_i64().expect("exit code"),
                    "{label} exit code (the message is allowed to differ: {})",
                    err.kind().as_str().unwrap_or("?")
                );
            }
            other => panic!("unhandled outcome `{other}` for {label}"),
        }
    }

    assert!(parsed >= 40, "only {parsed} successful parses replayed");
    assert!(errors >= 10, "only {errors} failures replayed");
}

/// Compare one recorded click frame's parameters against clap's.
fn check_parsed_frame(label: &str, frame: &Value, matches: &clap::ArgMatches) {
    // Descend to the same leaf clap reached.
    let mut cursor = matches;
    while let Some((_, next)) = cursor.subcommand() {
        cursor = next;
    }

    for (dest, expected) in frame["params"].as_object().expect("params") {
        let actual = read_param(cursor, dest, expected);
        assert_eq!(&actual, expected, "{label}: parameter `{dest}`");
    }
}

/// Read one parsed value back out of clap, in the shape click recorded.
///
/// The recorded value's *type* picks the accessor, which is itself an
/// assertion: click knows `--max-entries` is an integer, `--follow` a
/// boolean and `--set-secret` a list, so asking clap for the same type
/// fails loudly if the two trees disagree about what a parameter is.
fn read_param(matches: &clap::ArgMatches, dest: &str, expected: &Value) -> Value {
    match expected {
        Value::Bool(_) => matches
            .try_get_one::<bool>(dest)
            .ok()
            .flatten()
            .map_or(Value::Null, |b| Value::Bool(*b)),
        Value::Number(_) => matches
            .try_get_one::<i64>(dest)
            .ok()
            .flatten()
            .map_or(Value::Null, |n| Value::Number((*n).into())),
        Value::Array(_) => Value::Array(
            matches
                .try_get_many::<String>(dest)
                .ok()
                .flatten()
                .map(|values| values.map(|v| Value::String(v.clone())).collect())
                .unwrap_or_default(),
        ),
        Value::String(_) => matches
            .try_get_one::<String>(dest)
            .ok()
            .flatten()
            .map_or(Value::Null, |s| Value::String(s.clone())),
        // click recorded `None`: neither a string nor an integer
        // parameter was filled in. Ask for both, because a `null` from
        // the wrong accessor would pass for the wrong reason.
        Value::Null => {
            let as_text = matches.try_get_one::<String>(dest).ok().flatten();
            let as_number = matches.try_get_one::<i64>(dest).ok().flatten();
            match (as_text, as_number) {
                (None, None) => Value::Null,
                (Some(s), _) => Value::String(s.clone()),
                (_, Some(n)) => Value::Number((*n).into()),
            }
        }
        other @ Value::Object(_) => {
            panic!("unhandled recorded parameter shape: {other}")
        }
    }
}

/// The allowed-difference list is not allowed to be empty or silent.
#[test]
fn the_allowed_differences_are_documented() {
    assert!(
        ALLOWED_DIFFERENCES.len() >= 8,
        "if a difference was removed, delete its entry rather than the list"
    );
    for (title, why) in ALLOWED_DIFFERENCES {
        assert!(
            !title.is_empty() && why.len() > 40,
            "{title} needs a reason"
        );
    }
}

/// `--version` still prints click's `%(prog)s, version %(version)s`.
#[test]
fn the_version_string_is_pinned() {
    assert_eq!(
        version_line(),
        format!("agentcage, version {}", agentcage_core::VERSION)
    );
}
