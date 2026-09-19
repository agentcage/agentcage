//! `cage logs` — the journal, for one cage's units.
//!
//! `cli.py:2241`. There is no log *file* to read: §2.7's first trap is
//! that a `container` cage's output only ever exists in the journal, so
//! this command is a `journalctl` invocation and nothing else. The
//! `vm` and `apple-container` variants wrap the same read in `limactl
//! shell` and `container logs` respectively; both are Track E.
//!
//! Two shapes, chosen by `--severity`:
//!
//! * without it, `cli.py` `os.execvp`s journalctl and the CLI is gone —
//!   the operator gets journalctl's own pager, colours, Ctrl-C and exit
//!   status, none of which a wrapper reproduces faithfully;
//! * with it, journalctl is a child whose stdout is read a line at a
//!   time and classified, because journalctl's `-p` ladder is syslog
//!   priorities and these levels are inferred from the *text* the two
//!   containers write (see [`classify_line`]).

use std::process::ExitCode;

use agentcage_exec::Command;
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage};

/// `config._VALID_LEVELS`, in order — the index is the rank.
///
/// `agentcage_core::config::VALID_LOG_LEVELS` is the same tuple; it is
/// borrowed rather than re-spelled so that a level added to the config
/// schema cannot silently fail to be filterable here.
fn level_rank(level: &str) -> usize {
    agentcage_core::config::VALID_LOG_LEVELS
        .iter()
        .position(|candidate| *candidate == level)
        // `_LEVEL_ORDER.get(lvl, 1)` — an unrecognised level ranks as
        // `info`, not as 0, so garbage is not silently promoted into a
        // `--severity debug` view and dropped from every other one.
        .unwrap_or(1)
}

/// The body.
pub(crate) fn main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    // Both halves are already an `ExitCode`: the `Err` side is a
    // refusal this file printed, the `Ok` side is journalctl's own
    // status, and `cage logs` forwards that rather than flattening it.
    match run(ctx, matches) {
        Ok(code) | Err(code) => code,
    }
}

fn run(ctx: &Ctx, matches: &ArgMatches) -> Result<ExitCode, ExitCode> {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    let lines = matches.get_one::<i64>("lines").copied().unwrap_or(50);
    let follow = matches.get_flag("follow");
    // `--no-follow` is a hidden no-op in `cli.py`: it is read into a
    // parameter that the body never consults, because the default has
    // been "do not follow" since the flag was inverted. Reading it here
    // and discarding it is what keeps that true rather than accidental.
    let _no_follow = matches.get_flag("no_follow");
    let since = matches.get_one::<String>("since").cloned();
    let min_level = matches.get_one::<String>("min_level").cloned();

    if !ctx.paths.deployment_exists(&name) {
        eprintln!("error: cage '{name}' does not exist");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    ensure_v022_cage(&ctx.paths, &name)?;

    let Ok(config) = ctx
        .paths
        .load_deployment_config(&name, &agentcage_cli::hostenv::RealHost)
    else {
        eprintln!("error: cage '{name}' does not exist or has invalid config");
        return Err(ExitCode::from(EXIT_FAILURE));
    };

    // `selected = services or ("cage", "egress")` — an empty `-s` means
    // both, and the order is the order the units reach journalctl's argv.
    let selected: Vec<String> = matches
        .get_many::<String>("services")
        .map(|values| values.cloned().collect())
        .unwrap_or_default();
    let selected: Vec<String> = if selected.is_empty() {
        crate::cli::args::SERVICES
            .iter()
            .map(|service| (*service).to_owned())
            .collect()
    } else {
        selected
    };

    if config.isolation != "container" {
        eprintln!(
            "error: `cage logs` on the '{}' backend is not ported yet \
             (RUST-PORT-PLAN.md Track E); run the Python \
             `agentcage cage logs {name}` for now",
            config.isolation
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    logs_container(
        ctx,
        &name,
        &selected,
        lines,
        follow,
        since.as_deref(),
        min_level.as_deref(),
    )
}

/// `_logs_container` — one `-u` per host-level unit, then journalctl.
fn logs_container(
    ctx: &Ctx,
    name: &str,
    services: &[String],
    lines: i64,
    follow: bool,
    since: Option<&str>,
    min_level: Option<&str>,
) -> Result<ExitCode, ExitCode> {
    // Under a file log driver the container's output never reaches the
    // journal at all, so journalctl comes back near-empty and exits 0 —
    // which reads as "the cage is quiet" rather than "you are reading
    // the wrong place". Say so before printing the misleading stream.
    let backend = ctx.backend();
    let file_backed: Vec<&String> = services
        .iter()
        .filter(|service| backend.logs_to_file(&format!("{name}-{service}")))
        .collect();
    if let Some(first) = file_backed.first() {
        let units = file_backed
            .iter()
            .map(|service| format!("{name}-{service}"))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "warning: {units} log to a file driver, not the journal — \
             output below will be incomplete. Read it with: \
             podman logs {name}-{first}"
        );
    }

    let argv = journalctl_argv(name, services, lines, follow, since);

    let Some(min_level) = min_level else {
        return Ok(exec_journalctl(&argv));
    };
    filtered_stream(ctx, &argv, name, services, min_level)
}

/// The exact argv `cli.py` hands to `os.execvp`.
///
/// Pulled out of [`logs_container`] because it is the one thing about
/// this command the Python pins by value — `tests/test_cage_cli.py`
/// asserts all five of its shapes, element by element, against a mocked
/// `execvp` — and a list that is asserted by value is worth being able
/// to assert by value here too.
///
/// `-n` is spelled with its argument as a separate element, not as
/// `-n50`. journalctl accepts both, but `-n` is an option whose
/// argument is *optional*, so `-n` followed by a `--since` would mean
/// "default count" rather than a parse error — the separate element is
/// what keeps the count attached to the flag.
///
/// Note what is absent: `-o cat`. `cage audit` asks for it because it
/// is parsing the payload; `cage logs` wants journalctl's default
/// format, timestamps and unit prefixes included — the prefix is also
/// what [`service_of`] classifies against.
fn journalctl_argv(
    name: &str,
    services: &[String],
    lines: i64,
    follow: bool,
    since: Option<&str>,
) -> Vec<String> {
    let mut argv = vec!["journalctl".to_owned(), "--user".to_owned()];
    for service in services {
        argv.push("-u".to_owned());
        argv.push(format!("{name}-{service}"));
    }
    argv.push("-n".to_owned());
    argv.push(lines.to_string());
    if let Some(since) = since {
        argv.push("--since".to_owned());
        argv.push(since.to_owned());
    }
    if follow {
        argv.push("-f".to_owned());
    }
    argv
}

/// The `os.execvp` half: hand the terminal to journalctl and be gone.
///
/// [`agentcage_cli::terminal::run_interactive`] is a true `execvp` when
/// stdin is not a terminal, which is every scripted and piped caller
/// including the e2e suite. With a terminal it runs journalctl as a
/// child so the CLI survives to put the termios back — a `journalctl -f`
/// that the operator quits with `q` leaves the pager's mode behind
/// otherwise, and the Python's `execvp` simply had nothing left to fix
/// it with.
fn exec_journalctl(argv: &[String]) -> ExitCode {
    match agentcage_cli::terminal::run_interactive(argv) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(EXIT_FAILURE)),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// The `--severity` half: read journalctl's stdout and drop what ranks
/// below `min_level`.
fn filtered_stream(
    ctx: &Ctx,
    argv: &[String],
    name: &str,
    services: &[String],
    min_level: &str,
) -> Result<ExitCode, ExitCode> {
    let (program, rest) = argv.split_first().expect("journalctl is argv[0]");
    let command = Command::new(program.clone()).args(rest.iter().cloned());
    let mut stream = ctx.runner.stream(&command).map_err(|error| {
        eprintln!("error: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;

    let min_rank = level_rank(min_level);
    while let Some(line) = stream.next_line() {
        let service = service_of(name, services, &line);
        if level_rank(classify_line(service, &line)) >= min_rank {
            println!("{line}");
        }
    }
    // `finally: proc.terminate()`. SIGTERM, not SIGKILL: with `-f` this
    // is a live journalctl, and on the vm backend the same shape wraps
    // an ssh client whose remote end would outlive a kill.
    let _ = stream.terminate();
    Ok(ExitCode::SUCCESS)
}

/// Which of the selected services a journal line came from.
///
/// journalctl's default output carries the unit name in the syslog
/// identifier, so a substring test is enough — and it is what `cli.py`
/// does. The first match in the *selected* order wins, and a line that
/// names none of them (a journalctl notice, a boot separator) is
/// classified as `cage`, which is the more conservative of the two
/// ladders: it has no `debug` tier, so nothing is dropped from a
/// `--severity info` view by guessing wrong.
fn service_of<'a>(name: &str, services: &'a [String], line: &str) -> &'a str {
    services
        .iter()
        .find(|service| line.contains(&format!("{name}-{service}")))
        .map_or("cage", String::as_str)
}

/// `_classify_line` — a severity for a line that carries no priority.
///
/// The `egress` container is mitmproxy and dnsmasq in one, so its
/// classifier is the union of the two pre-v0.22 heuristics: the
/// inspector's decision JSON first, then dnsmasq's vocabulary. Falling
/// through to `info` is the legacy `dns` branch's default, kept.
///
/// Order matters twice. A blocked decision is a `warning` even though
/// the line also contains "error"-ish words, because the decision test
/// runs first; and dnsmasq's `refused`/`servfail` outrank its
/// `query[`/`reply` tier for the same reason.
#[must_use]
fn classify_line(service: &str, line: &str) -> &'static str {
    if service == "egress" {
        for decision in ["blocked", "flagged"] {
            if line.contains(&format!("\"decision\":\"{decision}\""))
                || line.contains(&format!("\"decision\": \"{decision}\""))
            {
                return "warning";
            }
        }
        if line.contains("\"decision\":\"allowed\"") || line.contains("\"decision\": \"allowed\"") {
            return "info";
        }
        let low = line.to_lowercase();
        if low.contains("error") || low.contains("traceback") {
            return "error";
        }
        if low.contains("refused") || low.contains("servfail") {
            return "error";
        }
        for pattern in ["query[", "reply", "cached", "forwarded"] {
            if low.contains(pattern) {
                return "debug";
            }
        }
        return "info";
    }

    let low = line.to_lowercase();
    for pattern in ["error", "traceback", "fatal", "exit code"] {
        if low.contains(pattern) {
            return "error";
        }
    }
    if low.contains("warn") {
        return "warning";
    }
    "info"
}

#[cfg(test)]
mod tests {
    use super::{classify_line, journalctl_argv, level_rank, service_of};

    fn both() -> Vec<String> {
        vec!["cage".to_owned(), "egress".to_owned()]
    }

    /// `TestCageLogs`, transferred by value. Every one of these is a
    /// `mock_execvp.assert_called_once_with` in `test_cage_cli.py`.
    #[test]
    fn the_argv_matches_the_python_by_value() {
        assert_eq!(
            journalctl_argv("basic", &both(), 50, false, None),
            [
                "journalctl",
                "--user",
                "-u",
                "basic-cage",
                "-u",
                "basic-egress",
                "-n",
                "50"
            ]
        );
        // `-f` goes last, after `--since` would have.
        assert_eq!(
            journalctl_argv("basic", &both(), 50, true, None)
                .last()
                .unwrap(),
            "-f"
        );
        assert_eq!(
            journalctl_argv("basic", &both(), 7, false, None)[7],
            "7",
            "`--tail 7` is the same `-n`"
        );
        assert_eq!(
            journalctl_argv("basic", &both(), 50, false, Some("10 min ago")),
            [
                "journalctl",
                "--user",
                "-u",
                "basic-cage",
                "-u",
                "basic-egress",
                "-n",
                "50",
                "--since",
                "10 min ago"
            ]
        );
        // `-s egress` narrows to one unit rather than filtering after.
        assert_eq!(
            journalctl_argv("basic", &["egress".to_owned()], 50, false, None),
            ["journalctl", "--user", "-u", "basic-egress", "-n", "50"]
        );
    }

    /// The ladder the `--severity` comparison runs on.
    #[test]
    fn levels_rank_in_the_python_order() {
        assert!(level_rank("debug") < level_rank("info"));
        assert!(level_rank("info") < level_rank("warning"));
        assert!(level_rank("warning") < level_rank("error"));
        assert!(level_rank("error") < level_rank("critical"));
        // `_LEVEL_ORDER.get(lvl, 1)`.
        assert_eq!(level_rank("nonsense"), level_rank("info"));
    }

    /// The egress ladder: decisions first, then dnsmasq's vocabulary.
    #[test]
    fn the_egress_classifier_is_the_union_of_two_heuristics() {
        assert_eq!(
            classify_line("egress", r#"{"decision":"blocked","host":"evil.com"}"#),
            "warning"
        );
        assert_eq!(
            classify_line("egress", r#"{"decision": "flagged", "host": "x"}"#),
            "warning"
        );
        assert_eq!(
            classify_line("egress", r#"{"decision":"allowed","host":"ok.com"}"#),
            "info"
        );
        assert_eq!(classify_line("egress", "dnsmasq: query[A] ok.com"), "debug");
        assert_eq!(classify_line("egress", "config error: bad zone"), "error");
        assert_eq!(classify_line("egress", "nameserver REFUSED"), "error");
        assert_eq!(classify_line("egress", "started"), "info");
    }

    /// A blocked decision stays a warning even though "blocked" lines
    /// routinely also carry the word "error" further along — the
    /// decision test runs before the substring sweep, and inverting
    /// that would reclassify every blocked request.
    #[test]
    fn a_decision_outranks_the_substring_sweep() {
        assert_eq!(
            classify_line(
                "egress",
                r#"{"decision":"blocked","reason":"error: not allowed"}"#
            ),
            "warning"
        );
    }

    /// The cage ladder has no `debug` tier, which is why an
    /// unattributable line is classified against it.
    #[test]
    fn the_cage_classifier_has_three_tiers() {
        assert_eq!(
            classify_line("cage", "Traceback (most recent call last)"),
            "error"
        );
        assert_eq!(classify_line("cage", "exit code 3"), "error");
        assert_eq!(classify_line("cage", "WARNING: deprecated"), "warning");
        assert_eq!(classify_line("cage", "listening on :3000"), "info");
    }

    #[test]
    fn a_line_is_attributed_to_the_first_selected_unit_it_names() {
        let services = ["cage".to_owned(), "egress".to_owned()];
        assert_eq!(
            service_of("basic", &services, "May 29 basic-egress[12]: hi"),
            "egress"
        );
        assert_eq!(
            service_of("basic", &services, "May 29 basic-cage[12]: hi"),
            "cage"
        );
        // Journalctl's own notices name no unit; they fall to `cage`.
        assert_eq!(service_of("basic", &services, "-- Boot 0e1f... --"), "cage");
    }
}
