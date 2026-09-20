//! End-to-end checks on the built `agentcage` binary.
//!
//! [`crate::cli::conformance`](../src/cli/conformance.rs) proves the
//! *tree* matches click's. This file proves the parts that only exist
//! once the tree is a process: which stream each thing is written to,
//! what exit code comes back, and that the completion scripts a shell
//! would source are real scripts.
//!
//! Everything here shells out to the binary rather than calling into the
//! crate, because "prints the version to stdout and exits 0" is a claim
//! about a process, and `install.sh` and the e2e harness make it by
//! running one.

use std::path::PathBuf;
use std::process::{Command, Output};

/// Run the built binary with `args`.
fn agentcage(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentcage"))
        .args(args)
        .output()
        .expect("the binary is built by `cargo test`")
}

/// The same, with every state root pointed at a throwaway home.
///
/// Required for any command with a body (PR D6 onwards): `cage list`
/// run against the developer's real `HOME` reports the cages they
/// actually have, and the quadlet directory and the apple-container
/// root follow `~` rather than `XDG_CONFIG_HOME`, so redirecting the
/// XDG variables alone would leave two roots pointing at their machine.
fn agentcage_sandboxed(dir: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentcage"))
        .args(args)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join(".config"))
        .env("XDG_DATA_HOME", dir.join(".local/share"))
        .env("XDG_RUNTIME_DIR", dir.join("run"))
        .output()
        .expect("the binary is built by `cargo test`")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("no signal")
}

/// sysexits' `EX_SOFTWARE`, which every unported command exits with.
const NOT_IMPLEMENTED: i32 = 70;

// ── the version string ──────────────────────────────────────────────

/// `install.sh` and the e2e harness parse this line. It is click's
/// `%(prog)s, version %(version)s`, and clap's default (`agentcage
/// 0.40.1`) is not it.
#[test]
fn version_is_the_click_format_on_stdout() {
    let out = agentcage(&["--version"]);
    assert_eq!(code(&out), 0);
    assert_eq!(
        stdout(&out).trim_end(),
        format!("agentcage, version {}", agentcage_core::VERSION)
    );
    assert!(stderr(&out).is_empty());
}

/// click declares no `-V`, so neither does this.
#[test]
fn there_is_no_short_version_flag() {
    let out = agentcage(&["-V"]);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
}

// ── help and the banner ─────────────────────────────────────────────

/// `--help` goes to stdout with the banner above it, and exits 0.
#[test]
fn help_prints_the_banner_and_the_alias_section() {
    let out = agentcage(&["--help"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.starts_with('\u{256d}'),
        "banner is missing: {text:.60}"
    );
    assert!(text.contains(&format!("agentcage v{}", agentcage_core::VERSION)));
    assert!(text.contains("Defense-in-depth proxy sandbox for AI agents."));
    assert!(text.contains("Aliases:"));
    assert!(text.contains("ls \u{2192} cage list"));
    assert!(text.contains("run \u{2192} cage run"));
}

/// A pipe is not a terminal, so the banner carries no escape bytes —
/// `click.echo` strips them the same way.
#[test]
fn piped_help_has_no_ansi() {
    assert!(!stdout(&agentcage(&["--help"])).contains('\u{1b}'));
}

/// click's `no_args_is_help`: the help, on **stderr**, exit 2. Not a
/// detail — a script that runs `agentcage` bare must see a failure.
#[test]
fn no_arguments_prints_help_to_stderr_and_exits_two() {
    let out = agentcage(&[]);
    assert_eq!(code(&out), 2);
    assert!(stdout(&out).is_empty());
    assert!(stderr(&out).contains("Defense-in-depth"));
}

/// Same for a group with no subcommand.
#[test]
fn a_bare_group_prints_help_to_stderr_and_exits_two() {
    for group in ["cage", "domain", "secret", "watcher", "scaffold"] {
        let out = agentcage(&[group]);
        assert_eq!(code(&out), 2, "{group}: {}", stderr(&out));
        assert!(stdout(&out).is_empty(), "{group}");
    }
}

// ── the stub ────────────────────────────────────────────────────────

/// A command that parses cleanly says so, and still fails.
///
/// The failure is the point. A skeleton that exited 0 on `cage destroy`
/// would look like it had destroyed something.
#[test]
fn a_parsed_command_fails_loudly_and_names_itself() {
    for (args, expected) in [
        (vec!["cage", "edit", "myapp"], "cage edit"),
        (vec!["cage", "grants", "myapp", "sync"], "cage grants sync"),
        (vec!["domain", "list", "myapp"], "domain list"),
    ] {
        let out = agentcage(&args);
        assert_eq!(code(&out), NOT_IMPLEMENTED, "{args:?}");
        assert!(stdout(&out).is_empty(), "{args:?}");
        let text = stderr(&out);
        assert!(text.contains(&format!("`{expected}`")), "{args:?}: {text}");
        assert!(text.contains("not implemented"), "{args:?}: {text}");
    }
}

/// `doctor` is no longer a stub (PR D15).
///
/// Run against the real machine, so nothing here asserts *what* it found
/// -- that is `tests/golden_doctor.rs`'s job, over 37 faked hosts. What
/// this adds is the half a fixture cannot reach: that the binary wires
/// the command up, prints to stdout, and exits on the error count rather
/// than on `EX_SOFTWARE`.
#[test]
fn doctor_runs_for_real() {
    let out = agentcage(&["doctor"]);
    assert!(
        code(&out) == 0 || code(&out) == 1,
        "doctor exited {} -- 0 and 1 are the only outcomes `cli.py:632` \
         produces: {}",
        code(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    for want in [
        "agentcage doctor",
        "Prerequisites",
        "System",
        "Secrets",
        "Network",
        "Summary:",
    ] {
        assert!(
            text.contains(want),
            "doctor output is missing {want:?}:\n{text}"
        );
    }
    assert!(
        stderr(&out).is_empty(),
        "doctor wrote to stderr: {}",
        stderr(&out)
    );
    // The check the port deletes: RUST-PORT-PLAN.md §2.4 makes "no host
    // Python" an invariant, so `doctor` must not go looking for one.
    assert!(
        !text.contains("Python"),
        "doctor still reports a host Python version:\n{text}"
    );
}

/// An alias reports the command it resolves to, not the alias.
#[test]
fn aliases_report_their_canonical_command() {
    for (alias, canonical) in [
        (["config", "myapp"], "cage edit"),
        (["edit", "myapp"], "cage edit"),
        (["start", "myapp"], "cage start"),
        // `stop`, `shell` and `exec` used to be here. They have bodies
        // as of PR D12, so they answer "does not exist" rather than
        // naming themselves as unported — which
        // `aliases_of_ported_commands_reach_the_body` asserts instead.
    ] {
        let args: Vec<&str> = alias.iter().copied().filter(|a| *a != "--").collect();
        let out = agentcage(&args);
        assert_eq!(code(&out), NOT_IMPLEMENTED, "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains(&format!("`{canonical}`")),
            "{args:?} should resolve to {canonical}: {}",
            stderr(&out)
        );
    }
}

/// Anything unrecognised is still a usage error, as B1's stub had it.
#[test]
fn unrecognised_input_exits_two() {
    for args in [
        vec!["nosuchcommand"],
        vec!["cage", "nosuchcommand"],
        vec!["doctor", "--nope"],
        vec!["cage", "show"],
        vec!["cage", "audit", "myapp", "-d", "nope"],
    ] {
        let out = agentcage(&args);
        assert_eq!(code(&out), 2, "{args:?}: {}", stderr(&out));
    }
}

// ── passthrough ─────────────────────────────────────────────────────

// `passthrough_accepts_flag_shaped_arguments` lived here. It proved that
// a flag-shaped argument after `--` reaches the workload rather than the
// parser, by asserting the *stub's* exit code — the only observable a
// command without a body has.
//
// Both halves now have bodies: `cage exec` in PR D12, `run` in PR D14.
// Running either row would deploy a cage from a parser test. The
// assertion did not weaken, it moved somewhere stronger:
// `cli::conformance::recorded_click_parses_reproduce` replays the
// recorded click parses for both commands — including
// `run claude-code --verbose -- --not-a-flag` — and compares every
// parsed parameter rather than inferring one from an exit status.
    ] {
        let out = agentcage(&args);
        assert_eq!(
            code(&out),
            NOT_IMPLEMENTED,
            "{args:?} should have parsed: {}",
            stderr(&out)
        );
        assert!(stderr(&out).contains("`cage run`"), "{args:?}");
    }
}

/// The same claim for `cage exec`, now that it has a body.
///
/// Every spelling has to get past the parser and reach the body, which
/// refuses an unknown cage with exit 1 — never clap's exit 2, which is
/// what a `-la` parsed as this command's own option would produce.
#[test]
fn passthrough_exec_reaches_its_body() {
    let dir = agentcage_state::TestDir::new("binary-exec-passthrough");
    for args in [
        vec!["cage", "exec", "myapp", "--", "ls", "-la"],
        vec![
            "cage",
            "exec",
            "--as-root",
            "myapp",
            "--",
            "openclaw",
            "devices",
            "list",
        ],
        // Without `--` too: click's `ignore_unknown_options` does not
        // require the separator, and neither does this.
        vec!["cage", "exec", "myapp", "ls", "-la"],
        vec!["exec", "myapp", "--", "ls", "-la"],
        vec![
            "cage",
            "exec",
            "-s",
            "egress",
            "myapp",
            "--",
            "sh",
            "-c",
            "echo $HOME",
        ],
    ] {
        let out = agentcage_sandboxed(dir.path(), &args);
        assert_eq!(
            code(&out),
            1,
            "{args:?} should have parsed and been refused: {}",
            stderr(&out)
        );
        assert!(
            stderr(&out).contains("cage 'myapp' does not exist"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
}

/// `cage shell` and `cage stop` reached through their root aliases.
///
/// The alias clones are separate `Command` values, so "the canonical
/// spelling has a body" does not imply the alias does.
#[test]
fn aliases_of_ported_commands_reach_the_body() {
    let dir = agentcage_state::TestDir::new("binary-ported-aliases");
    for args in [vec!["shell", "myapp"], vec!["stop", "myapp"]] {
        let out = agentcage_sandboxed(dir.path(), &args);
        assert_eq!(code(&out), 1, "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("cage 'myapp' does not exist"),
            "{args:?}: {}",
            stderr(&out)
        );
    }

    for args in [
        vec!["cage", "exec", "myapp", "--", "ls", "-la"],
        vec![
            "cage",
            "exec",
            "--as-root",
            "myapp",
            "--",
            "openclaw",
            "devices",
            "list",
        ],
        // Without `--` too: click's `ignore_unknown_options` does not
        // require the separator, and neither does this.
        vec!["cage", "exec", "myapp", "ls", "-la"],
        vec!["exec", "myapp", "--", "ls", "-la"],
    ] {
        let out = agentcage(&args);
        assert_ne!(code(&out), 2, "{args:?} failed to parse: {}", stderr(&out));
        assert!(
            stderr(&out).contains("cage 'myapp' does not exist"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
}

// ── completions ─────────────────────────────────────────────────────

/// All three shells produce a script, and each script mentions the
/// program and at least one real subcommand.
#[test]
fn completion_scripts_generate_for_three_shells() {
    for shell in ["bash", "zsh", "fish"] {
        let out = agentcage(&["completions", shell]);
        assert_eq!(code(&out), 0, "{shell}: {}", stderr(&out));
        let script = stdout(&out);
        assert!(script.len() > 500, "{shell} script is suspiciously short");
        assert!(script.contains("agentcage"), "{shell}");
        assert!(script.contains("destroy"), "{shell} lists no subcommands");
    }
    // A shell nobody asked for is a usage error, not an empty script.
    assert_eq!(code(&agentcage(&["completions", "elvish"])), 2);
}

/// `completions` is the one command with no counterpart in `cli.py`, so
/// it must not appear in the help.
#[test]
fn the_completions_command_is_hidden() {
    assert!(!stdout(&agentcage(&["--help"])).contains("completions"));
}

/// The generated scripts parse in the shells that are installed.
///
/// Only bash is assumed present (this runs on CI images and on the
/// maintainer's Arch box); zsh and fish are checked when available and
/// skipped with a note when not, because a missing shell is not a
/// failure of this crate.
#[test]
fn generated_scripts_load_without_error() {
    let dir = std::env::temp_dir().join(format!("agentcage-completions-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");

    let mut checked = 0;
    for (shell, program, flags) in [
        ("bash", "bash", vec!["-n"]),
        ("zsh", "zsh", vec!["-n"]),
        ("fish", "fish", vec!["--no-execute"]),
    ] {
        let script = stdout(&agentcage(&["completions", shell]));
        let path: PathBuf = dir.join(format!("agentcage.{shell}"));
        std::fs::write(&path, &script).expect("write script");

        let mut cmd = Command::new(program);
        cmd.args(&flags).arg(&path);
        match cmd.output() {
            Ok(out) if out.status.success() => checked += 1,
            Ok(out) => panic!(
                "{shell} rejected its own completion script:\n{}",
                String::from_utf8_lossy(&out.stderr)
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("note: {program} is not installed; skipped its syntax check");
            }
            Err(err) => panic!("{program}: {err}"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        checked > 0,
        "no shell was available to check a completion script; bash at minimum is expected"
    );
}

// ── the bodies PR D6 landed ─────────────────────────────────────────

/// The eight commands with bodies are no longer stubs.
///
/// Read-only or refusing, all of them, and all run against a throwaway
/// home so nothing on the developer's machine is read or touched. What
/// this asserts is only that the dispatch reaches a body: the *output*
/// is the e2e suite's business, which is where this PR's real
/// acceptance check lives (phase 1, under `AGENTCAGE=<this binary>`).
#[test]
fn the_ported_commands_are_wired_up() {
    let dir = agentcage_state::TestDir::new("binary-ported");
    for (args, wanted) in [
        (vec!["cage", "list"], "No cages found."),
        (vec!["cage", "status"], "No cages found."),
        (vec!["ls"], "No cages found."),
        (vec!["ps"], "No cages found."),
    ] {
        let out = agentcage_sandboxed(dir.path(), &args);
        assert_eq!(code(&out), 0, "{args:?}: {}", stderr(&out));
        assert!(stdout(&out).contains(wanted), "{args:?}: {}", stdout(&out));
    }
}

/// `run` refuses an unknown scaffold before it touches anything.
///
/// The one end-to-end assertion this suite can make about `run`: it
/// reaches its own body (so the passthrough parsed), it resolves the
/// scaffold search path, and it stops — no state directory, no podman,
/// no deploy. The trailing `--verbose -- --not-a-flag` is there to prove
/// the flag-shaped passthrough survives the trip through a real
/// invocation.
#[test]
fn run_refuses_an_unknown_scaffold_without_deploying() {
    let dir = agentcage_state::TestDir::new("binary-run-unknown");
    for args in [
        vec!["run", "no-such-scaffold", "--verbose", "--", "--not-a-flag"],
        vec!["cage", "run", "no-such-scaffold"],
    ] {
        let out = agentcage_sandboxed(dir.path(), &args);
        assert_eq!(code(&out), 1, "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("Unknown scaffold 'no-such-scaffold'"),
            "{args:?}: {}",
            stderr(&out)
        );
        // It lists what there is, which is how the operator recovers.
        assert!(
            stderr(&out).contains("openclaw"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
    assert!(
        !dir.path().join(".config/agentcage/cages").exists(),
        "run created state for a cage it refused"
    );
}

/// `init` writes a config, and `init --scaffold <name>` writes the
/// scaffold's — with the build context beside it, because that is what
/// `cage create -c` will build from.
#[test]
fn init_writes_a_config_and_stages_the_scaffold_context() {
    let dir = agentcage_state::TestDir::new("binary-init");
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let config = work.join("cage.yaml");

    let out = agentcage_sandboxed(
        dir.path(),
        &[
            "init",
            "e2e-demo",
            "--output",
            &config.display().to_string(),
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(text.contains("name: e2e-demo"), "{text}");
    assert!(stdout(&out).contains("Next steps:"), "{}", stdout(&out));

    // Without `--force`, a second run refuses rather than clobbering.
    let out = agentcage_sandboxed(
        dir.path(),
        &[
            "init",
            "e2e-demo",
            "--output",
            &config.display().to_string(),
        ],
    );
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("already exists"), "{}", stderr(&out));

    // An unknown scaffold is named, and lists the alternatives.
    let out = agentcage_sandboxed(dir.path(), &["init", "x", "--scaffold", "nope"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("unknown scaffold 'nope'"),
        "{}",
        stderr(&out)
    );

    // A name that could be a path is refused.
    let out = agentcage_sandboxed(dir.path(), &["init", "../escape"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("lowercase"), "{}", stderr(&out));

    // `--list-scaffolds` needs no NAME.
    let out = agentcage_sandboxed(dir.path(), &["init", "--list-scaffolds"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("openclaw"), "{}", stdout(&out));
}

/// The `scaffold` group, end to end against a sandboxed `XDG_CONFIG_HOME`.
#[test]
fn the_scaffold_group_creates_shows_lists_and_deletes() {
    let dir = agentcage_state::TestDir::new("binary-scaffold");

    let out = agentcage_sandboxed(dir.path(), &["scaffold", "list"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("NAME"), "{}", stdout(&out));
    assert!(stdout(&out).contains("built-in"), "{}", stdout(&out));

    let out = agentcage_sandboxed(dir.path(), &["scaffold", "show", "openclaw"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("Scaffold: openclaw"),
        "{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("Build steps:"), "{}", stdout(&out));

    // A built-in cannot be edited or deleted in place.
    for args in [
        vec!["scaffold", "edit", "openclaw"],
        vec!["scaffold", "delete", "openclaw", "-y"],
    ] {
        let out = agentcage_sandboxed(dir.path(), &args);
        assert_eq!(code(&out), 1, "{args:?}: {}", stderr(&out));
        assert!(stderr(&out).contains("built-in"), "{args:?}");
    }

    // Forking one produces a user scaffold that then shadows it.
    let out = agentcage_sandboxed(
        dir.path(),
        &["scaffold", "create", "my-claw", "--from", "openclaw"],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let forked = dir.path().join(".config/agentcage/scaffolds/my-claw");
    assert!(forked.join("cage.yaml.j2").is_file());
    assert!(forked.join("Containerfile").is_file());

    let out = agentcage_sandboxed(dir.path(), &["scaffold", "show", "my-claw"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("Source:   user"), "{}", stdout(&out));

    // The starter template substitutes the name.
    let out = agentcage_sandboxed(dir.path(), &["scaffold", "create", "from-starter"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let starter = dir.path().join(".config/agentcage/scaffolds/from-starter");
    let rendered = std::fs::read_to_string(starter.join("cage.yaml.j2")).unwrap();
    assert!(!rendered.contains("{{SCAFFOLD_NAME}}"), "{rendered}");

    // Export, then delete.
    let out = agentcage_sandboxed(
        dir.path(),
        &[
            "scaffold",
            "export",
            "my-claw",
            &dir.path().join("out").display().to_string(),
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(dir.path().join("out/my-claw/cage.yaml.j2").is_file());

    let out = agentcage_sandboxed(dir.path(), &["scaffold", "delete", "my-claw", "-y"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(!forked.exists());
}

/// A command that names a cage which does not exist refuses with the
/// Python's message and exit 1 — not with the stub's 70.
#[test]
fn an_unknown_cage_is_refused_rather_than_stubbed() {
    let dir = agentcage_state::TestDir::new("binary-unknown");
    for args in [
        vec!["cage", "show", "nope"],
        vec!["describe", "nope"],
        vec!["cage", "update", "nope"],
        vec!["cage", "audit", "nope"],
        vec!["cage", "logs", "nope"],
    ] {
        let out = agentcage_sandboxed(dir.path(), &args);
        assert_eq!(code(&out), 1, "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("does not exist"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
}

/// `cage destroy` on a cage with no state and no quadlets removes
/// nothing and says so, without ever reaching podman.
#[test]
fn destroying_an_absent_cage_is_a_reported_no_op() {
    let dir = agentcage_state::TestDir::new("binary-destroy");
    let out = agentcage_sandboxed(dir.path(), &["rm", "nope", "-y"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("no stored config and no backend resources"),
        "{}",
        stdout(&out)
    );
}

/// `cage create` with neither a positional config nor `-c` is the
/// Python's own error, not clap's usage message.
#[test]
fn create_without_a_config_names_both_ways_to_give_one() {
    let dir = agentcage_state::TestDir::new("binary-create");
    let out = agentcage_sandboxed(dir.path(), &["cage", "create"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("missing config") && stderr(&out).contains("-c/--config"),
        "{}",
        stderr(&out)
    );
}

/// `cage update` with neither a NAME nor `-c` cannot identify a cage.
#[test]
fn update_without_a_target_says_why() {
    let dir = agentcage_state::TestDir::new("binary-update");
    let out = agentcage_sandboxed(dir.path(), &["cage", "update"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("either NAME or -c/--config is required"),
        "{}",
        stderr(&out)
    );
}

/// Write just enough state under `home` for the two read-only commands
/// to get past their existence and version gates: a `cage.yaml` the
/// loader accepts and a `metadata.json` claiming v0.22.
fn stage_cage(home: &std::path::Path, name: &str, isolation: &str) {
    let paths = agentcage_state::Paths::under(home);
    std::fs::create_dir_all(paths.deployment_dir(name)).expect("the deployment dir is writable");
    std::fs::write(
        paths.deployment_dir(name).join("cage.yaml"),
        format!("name: {name}\nisolation: {isolation}\ncontainer:\n  image: \"alpine\"\n"),
    )
    .expect("the config is writable");
    paths
        .save_metadata(
            name,
            &agentcage_core::har::json::Json::Object(vec![(
                "agentcage_version".to_owned(),
                agentcage_core::har::json::Json::string("0.40.1"),
            )]),
        )
        .expect("the metadata is writable");
}

/// `cage logs` and `cage audit` both read their source through a
/// backend, and only the container one is ported. A `vm` cage answered
/// out of the *host* journal would print nothing and exit 0 — a wrong
/// answer that looks exactly like a quiet cage — so both refuse
/// instead, the way `cage verify` reports its unported probes.
///
/// §2.7's first trap is why this cannot be papered over with a file
/// reader: `audit.jsonl` exists host-side only for apple-container.
#[test]
fn the_unported_backends_are_refused_rather_than_read_wrongly() {
    let dir = agentcage_state::TestDir::new("binary-tracke");
    for isolation in ["vm", "apple-container"] {
        let name = format!("cage-{isolation}");
        stage_cage(dir.path(), &name, isolation);
        for command in ["logs", "audit"] {
            let out = agentcage_sandboxed(dir.path(), &["cage", command, &name]);
            assert_eq!(code(&out), 1, "{command} {isolation}: {}", stderr(&out));
            assert!(
                stderr(&out).contains("not ported yet") && stderr(&out).contains(isolation),
                "{command} {isolation}: {}",
                stderr(&out)
            );
        }
    }
}

/// A container cage reaches journalctl and `cage logs` forwards *its*
/// status rather than inventing one. This is the shape `assert_cmd_ok`
/// checks in e2e phase 2.
///
/// Gated on a journal this user can actually read, because that is the
/// thing being forwarded: a build container with no journal files
/// answers 1 to every query, and the test would then be asserting the
/// host's systemd rather than this command. The probe is the same query
/// the command will make, so whatever it answers is the expectation.
#[test]
fn logs_forwards_journalctls_own_status() {
    let Ok(probe) = Command::new("journalctl")
        .args(["--user", "-u", "agentcage-no-such-unit", "-n", "1"])
        .output()
    else {
        return;
    };
    if !probe.status.success() {
        return;
    }
    let dir = agentcage_state::TestDir::new("binary-logs-ok");
    stage_cage(dir.path(), "quiet", "container");
    let out = agentcage_sandboxed(dir.path(), &["cage", "logs", "quiet", "-n", "5"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}
