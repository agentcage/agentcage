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

/// [`agentcage_sandboxed`] with extra environment.
///
/// `cage edit` needs `$EDITOR`, and the sandbox has to stay otherwise
/// identical — a second copy of the env block would drift from the
/// first.
fn agentcage_sandboxed_env(dir: &std::path::Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentcage"));
    command
        .args(args)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join(".config"))
        .env("XDG_DATA_HOME", dir.join(".local/share"))
        .env("XDG_RUNTIME_DIR", dir.join("run"));
    for (key, value) in env {
        command.env(key, value);
    }
    command
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
    // A host interpreter is not a dependency, so `doctor` must not go
    // looking for one (earlier releases reported a version line).
    assert!(
        !text.contains("Python"),
        "doctor still reports a host Python version:\n{text}"
    );
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
// `passthrough_accepts_flag_shaped_arguments` lived here. It proved a
// flag-shaped argument after `--` reaches the workload rather than the
// parser, by asserting the *stub's* exit code — the only observable a
// command without a body has.
//
// Both halves now have bodies: `cage exec` in PR D12, `run` in PR D14,
// so running either row would deploy a cage from a parser test. The
// claim did not weaken, it moved somewhere stronger:
// `cli::conformance::recorded_click_parses_reproduce` replays the
// recorded click parses for both — including
// `run claude-code --verbose -- --not-a-flag` — and compares every
// parsed parameter rather than inferring one from an exit status.

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

/// `cage shell`, `cage stop` and `cage start` reached through their
/// root aliases.
///
/// The alias clones are separate `Command` values, so "the canonical
/// spelling has a body" does not imply the alias does.
#[test]
fn aliases_of_ported_commands_reach_the_body() {
    let dir = agentcage_state::TestDir::new("binary-ported-aliases");
    for args in [
        vec!["shell", "myapp"],
        vec!["stop", "myapp"],
        vec!["start", "myapp"],
        // `config` and `edit` moved here from
        // `aliases_report_their_canonical_command` when `cage edit`
        // gained a body.
        vec!["config", "myapp"],
        vec!["edit", "myapp"],
    ] {
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

/// A command that names a cage which does not exist refuses with the
/// pinned message and exit 1 — not with the stub's 70.
#[test]
fn an_unknown_cage_is_refused_rather_than_stubbed() {
    let dir = agentcage_state::TestDir::new("binary-unknown");
    for args in [
        vec!["cage", "show", "nope"],
        vec!["describe", "nope"],
        vec!["cage", "update", "nope"],
        vec!["cage", "audit", "nope"],
        vec!["cage", "logs", "nope"],
        // PR D10. `domain list` reconciles first and the reconcile is
        // deliberately quiet about a missing cage, so the refusal here
        // is the one the listing itself makes.
        vec!["domain", "list", "nope"],
        vec!["domain", "add", "nope", "example.com"],
        vec!["domain", "rm", "nope", "example.com"],
        vec!["cage", "grants", "nope", "list"],
        vec!["cage", "grants", "nope", "sync"],
        vec!["cage", "grants", "nope", "promote", "example.com"],
        vec!["cage", "grants", "nope", "revoke", "example.com"],
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
    assert!(
        !stdout(&out).contains("Kept:"),
        "a cage with no data directory reported keeping one: {}",
        stdout(&out)
    );
}

/// The `Kept:` block reports what is on disk, not whether this run
/// removed anything, so a cage that is already gone still names the
/// data directory its destroy left behind (#423).
///
/// Suppressing it on the "not found" branch would hide exactly the
/// leftover a later `cage create` of the same name inherits.
#[test]
fn destroy_reports_kept_data_for_an_absent_cage() {
    let dir = agentcage_state::TestDir::new("binary-destroy-kept-absent");
    let paths = agentcage_state::Paths::under(dir.path());
    let name = "pr423-gone";
    paths.append_policy_audit(
        name,
        "2026-10-24T00:00:00Z",
        &agentcage_core::har::json::Json::Object(Vec::new()),
    );

    let out = agentcage_sandboxed(dir.path(), &["cage", "destroy", name, "-y"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("Nothing to remove"),
        "the absent cage was not reported: {text}"
    );
    assert!(
        text.contains(&format!(
            "Kept:\n  data:{}\n  left in place: policy-audit.jsonl\n",
            paths.cage_data_dir(name).display()
        )),
        "the leftover data directory was not named: {text}"
    );
}

/// `cage destroy` keeps the per-cage data directory, and says where it
/// is (#423).
///
/// The visible change is the `Kept:` block: `Removed:` still reports
/// exactly what it always did, the inventory names the entries that
/// are actually in the data directory (and not the staged
/// `inspectors/`, which goes with the deployment), and the data it
/// says survives is still on disk afterward.
#[test]
fn destroy_names_the_data_directory_it_keeps() {
    let dir = agentcage_state::TestDir::new("binary-destroy-kept");
    let paths = agentcage_state::Paths::under(dir.path());
    let name = "pr423-kept-data";
    stage_cage(dir.path(), name, "container");
    std::fs::create_dir_all(paths.grants_dir(name)).expect("the data dir is writable");
    std::fs::write(paths.grants_file(name), "- domain: example.com\n").expect("writable");
    std::fs::create_dir_all(paths.capture_dir(name)).expect("the capture dir is writable");
    std::fs::write(paths.capture_file(name), "{}\n").expect("the capture log is writable");
    std::fs::write(paths.policy_audit_file(name), "{\"decision\":\"allow\"}\n")
        .expect("the audit log is writable");
    let timings = paths.cage_data_dir(name).join("timings");
    std::fs::create_dir_all(&timings).expect("the timings dir is writable");
    std::fs::write(timings.join("20261024T000000-1.jsonl"), "{}\n").expect("writable");
    let inspectors = paths.inspectors_dir(name);
    std::fs::create_dir_all(&inspectors).expect("the inspectors dir is writable");
    std::fs::write(inspectors.join("plugin.wasm"), "not really").expect("writable");

    let out = agentcage_sandboxed(dir.path(), &["cage", "destroy", name, "-y"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let data = paths.cage_data_dir(name);
    assert_eq!(
        stdout(&out),
        format!(
            "Stopping services...\n\
             Removing resources...\n\
             \n\
             Removed:\n  state:{name}\n\
             Kept:\n  data:{}\n  \
             left in place: capture/, grants/, policy-audit.jsonl, timings/\n",
            data.display()
        ),
        "stderr: {}",
        stderr(&out)
    );
    assert!(data.is_dir(), "the data directory was removed");
    assert!(
        paths.policy_audit_file(name).is_file(),
        "the policy audit log was removed"
    );
    assert!(
        paths.capture_file(name).is_file(),
        "the capture log was removed"
    );
    assert!(
        !inspectors.exists(),
        "the staged inspectors were kept with the data"
    );
}

/// The `Kept:` block must not name `capture/` on `apple-container`.
///
/// That backend writes `capture.jsonl` under
/// `~/.config/agentcage/apple-container/<name>/logs/`, which
/// `destroy_resources` `remove_dir_all`s with the rest of the apple
/// state tree (#423). The old fixed sentence said "capture/ … survive"
/// while the command had just deleted the log — the exact inversion of
/// what the issue asked for. The deploy still creates an empty host
/// `capture/` for every backend, so staging it here is what a real
/// apple cage has on disk before the destroy.
#[test]
fn destroy_does_not_claim_apple_capture_survives() {
    let dir = agentcage_state::TestDir::new("binary-destroy-apple-kept");
    let paths = agentcage_state::Paths::under(dir.path());
    let name = "pr423-apple-kept";
    stage_cage(dir.path(), name, "apple-container");
    std::fs::create_dir_all(paths.grants_dir(name)).expect("the data dir is writable");
    std::fs::write(paths.grants_file(name), "- domain: example.com\n").expect("writable");
    std::fs::write(paths.policy_audit_file(name), "{\"decision\":\"allow\"}\n")
        .expect("the audit log is writable");
    // What `ensure_capture_dir` leaves for `capture.enable_har`, on a
    // backend whose log actually goes to the apple state tree.
    std::fs::create_dir_all(paths.capture_dir(name)).expect("the capture dir is writable");
    let apple_capture = paths.apple_capture_file(name);
    std::fs::create_dir_all(apple_capture.parent().expect("has a parent"))
        .expect("the apple logs dir is writable");
    std::fs::write(&apple_capture, "{}\n").expect("the apple capture log is writable");

    let out = agentcage_sandboxed(dir.path(), &["cage", "destroy", name, "-y"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    let kept = text.split_once("Kept:").map_or_else(
        || panic!("no Kept: block in {text}"),
        |(_, rest)| format!("Kept:{rest}"),
    );
    assert_eq!(
        kept,
        format!(
            "Kept:\n  data:{}\n  left in place: grants/, policy-audit.jsonl\n",
            paths.cage_data_dir(name).display()
        ),
        "stderr: {}",
        stderr(&out)
    );
    assert!(
        !text.contains("capture/"),
        "the block named the capture log destroy had just deleted: {text}"
    );
    assert!(
        !apple_capture.exists(),
        "destroy kept the apple capture log it reported removing"
    );
    assert!(
        paths.policy_audit_file(name).is_file(),
        "the policy audit log was removed"
    );
}

/// `cage create` with neither a positional config nor `-c` is the
/// CLI's own error, not clap's usage message.
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

/// `--no-pull` skips the registry and `--pull` forces it: together they
/// are a usage error, refused before anything is looked up.
#[test]
fn update_refuses_no_pull_with_pull() {
    let dir = agentcage_state::TestDir::new("binary-update-pull");
    let out = agentcage_sandboxed(dir.path(), &["cage", "update", "x", "--pull", "--no-pull"]);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("cannot be used with")
            && stderr(&out).contains("'--no-pull'")
            && stderr(&out).contains("'--pull'"),
        "{}",
        stderr(&out)
    );
}

/// Write just enough state under `home` for the two read-only commands
/// to get past their existence and version gates: a `cage.yaml` the
/// loader accepts and a `metadata.json` claiming v0.22.
fn stage_cage(home: &std::path::Path, name: &str, isolation: &str) {
    stage_cage_with_config(
        home,
        name,
        &format!("name: {name}\nisolation: {isolation}\ncontainer:\n  image: \"alpine\"\n"),
    );
}

/// [`stage_cage`] with the config's bytes chosen by the caller.
///
/// `cage edit` refuses a cage without metadata (the version check in
/// `preflight`), so this writes the same `0.40.1` stamp. The file itself
/// is written byte-for-byte: the edit tests are about which bytes
/// survive the command, and a helper that rendered the document first
/// would hide the very thing they assert.
fn stage_cage_with_config(home: &std::path::Path, name: &str, config: &str) {
    let paths = agentcage_state::Paths::under(home);
    std::fs::create_dir_all(paths.deployment_dir(name)).expect("the deployment dir is writable");
    std::fs::write(paths.stored_config_path(name), config).expect("the config is writable");
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

/// `cage prune`'s three filters, each shown by the cage it walks past.
///
/// None of these reaches the teardown, which is the point: a prune
/// that removes a `service` cage, or a v0.21 cage it cannot probe, is
/// indistinguishable from data loss. The candidate list is the whole
/// command.
#[test]
fn prune_walks_past_everything_it_must_not_remove() {
    let dir = agentcage_state::TestDir::new("binary-prune");

    // Nothing at all.
    let out = agentcage_sandboxed(dir.path(), &["cage", "prune"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("Nothing to prune."),
        "{}",
        stdout(&out)
    );

    // A stopped `service` cage: down on purpose, not exited.
    stage_cage(dir.path(), "svc", "container");
    let out = agentcage_sandboxed(dir.path(), &["cage", "prune"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("Nothing to prune."),
        "prune targeted a service cage: {}",
        stdout(&out)
    );

    // An `interactive` v0.21 cage: the third exemption from the
    // legacy gate. `list` annotates it, `destroy` proceeds on it, and
    // `prune` must walk past — probing the v0.22 shape would answer
    // "not running" for a cage that is running under the old names.
    let paths = agentcage_state::Paths::under(dir.path());
    std::fs::create_dir_all(paths.deployment_dir("old")).expect("writable");
    std::fs::write(
        paths.deployment_dir("old").join("cage.yaml"),
        "name: old
isolation: container
lifecycle: interactive
container:
  image: \"alpine\"\n",
    )
    .expect("writable");
    paths
        .save_metadata(
            "old",
            &agentcage_core::har::json::Json::Object(vec![(
                "agentcage_version".to_owned(),
                agentcage_core::har::json::Json::string("0.21.5"),
            )]),
        )
        .expect("writable");
    let out = agentcage_sandboxed(dir.path(), &["cage", "prune"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("Nothing to prune."),
        "prune targeted a v0.21 cage: {}",
        stdout(&out)
    );
    assert!(
        !stderr(&out).contains("legacy 3-service"),
        "prune consulted the gate instead of skipping: {}",
        stderr(&out)
    );
}

/// `cage prune` takes `destroy`'s teardown and keeps the same data
/// directory, so it says so too (#423): one `Kept:` block per removed
/// cage, under that cage's `Removing` line.
#[test]
fn prune_names_the_data_directory_it_keeps() {
    let dir = agentcage_state::TestDir::new("binary-prune-kept");
    let paths = agentcage_state::Paths::under(dir.path());
    let name = "pr423-pruned";
    stage_cage(dir.path(), name, "container");
    std::fs::write(
        paths.deployment_dir(name).join("cage.yaml"),
        format!(
            "name: {name}\nisolation: container\nlifecycle: interactive\ncontainer:\n  image: \"alpine\"\n"
        ),
    )
    .expect("the config is writable");
    std::fs::create_dir_all(paths.cage_data_dir(name)).expect("the data dir is writable");
    std::fs::write(paths.policy_audit_file(name), "{\"decision\":\"allow\"}\n")
        .expect("the audit log is writable");

    let out = agentcage_sandboxed(dir.path(), &["cage", "prune", "-y"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains(&format!(
            "Removing {name}...\nKept:\n  data:{}\n  left in place: policy-audit.jsonl\nPruned 1 cage(s).\n",
            paths.cage_data_dir(name).display()
        )),
        "prune did not name the data directory it kept: {text}"
    );
    assert!(
        paths.policy_audit_file(name).is_file(),
        "prune removed the policy audit log"
    );
}

/// Every command in the tree has a body.
///
/// Two tests used to live here: one asserting an unported command
/// failed loudly and named itself, and one asserting an *alias* of such
/// a command named its canonical form. Both carried a comment saying
/// they should be deleted rather than emptied once their last row
/// gained a body, and `watcher findings` / `watcher status` were that
/// last row. `not_implemented` is now unreachable from the dispatch
/// table — it survives only as the guard for an isolation spelling that
/// reaches `AnyBackend::new`'s fall-through, which `backends.rs` tests
/// directly.
///
/// What replaces them is this: the tree and the dispatch table agree.
/// A command added to one and not the other is the regression those
/// tripwires existed to catch, and it is now catchable without a stub
/// to point at.
#[test]
fn every_leaf_command_has_a_body() {
    let dir = agentcage_state::TestDir::new("binary-no-stubs");
    // Walking clap's tree from the outside needs the help output; the
    // dispatch table is not introspectable from a test. So this asserts
    // the observable property instead: no command answers with the
    // not-implemented stub.
    for args in [
        vec!["watcher", "findings", "myapp"],
        vec!["watcher", "status", "myapp"],
        vec!["watcher", "ls", "myapp"],
        vec!["cage", "edit", "myapp"],
    ] {
        let out = agentcage_sandboxed(dir.path(), &args);
        let text = format!("{}{}", stdout(&out), stderr(&out));
        assert!(
            !text.contains("not implemented"),
            "{args:?} is still a stub: {text}"
        );
        // Each reaches a body, and the body refuses an absent cage.
        assert_eq!(code(&out), 1, "{args:?}: {text}");
        assert!(
            text.contains("cage 'myapp' does not exist"),
            "{args:?}: {text}"
        );
    }
}

/// An `apple-container` cage's logs and audit are read through its own
/// backend, not out of the host.
///
/// Both used to refuse (Track E), and the refusal was the right answer
/// while the reader was missing: a cage answered out of the *host*
/// journal prints nothing and exits 0, which looks exactly like a quiet
/// cage. E5 ported both readers, so what has to be asserted now is that
/// neither refuses and neither reaches podman.
///
/// `cage logs` ends in Apple's own complaint about a container that
/// does not exist — which is the point, it reached `container`. `cage
/// audit` is a `tail` over a host file that is not there, and an empty
/// stream is an empty table on every backend, so all that can be said
/// of it is that it stopped refusing.
#[test]
fn an_apple_cage_is_read_through_its_own_backend() {
    if Command::new("container").arg("--version").output().is_err() {
        return;
    }
    let dir = agentcage_state::TestDir::new("binary-apple-read");
    stage_cage(dir.path(), "cage-apple", "apple-container");
    for command in ["logs", "audit"] {
        let out = agentcage_sandboxed(dir.path(), &["cage", command, "cage-apple"]);
        let complaint = format!("{}{}", stdout(&out), stderr(&out));
        assert!(
            !complaint.contains("not ported yet"),
            "{command} apple-container still refuses: {complaint}"
        );
        assert!(
            !complaint.contains("podman"),
            "{command} apple-container reached podman: {complaint}"
        );
    }
}

/// An `apple-container` cage is backed up and restored through the
/// apple *shape*, by the shipped binary, with no runtime installed and
/// no subprocess run.
///
/// Unlike the two readers above this needs nothing on the host, which
/// is why it is not skipped: `cage backup` on this backend reads files
/// and writes a tarball, and `cage restore --no-start` stops before the
/// first image build. So the whole decision — which members travel,
/// which manifest keys are written, and which of the two capture
/// layouts the logs come back into — is checkable as a process.
///
/// What it pins that `src/cli/cage/backup.rs`'s unit tests cannot: that
/// the `audit/` member and the apple logs dir survive a real argv, a
/// real `HOME`, and the `~`-rooted apple state root that ignores
/// `XDG_CONFIG_HOME` entirely.
#[test]
fn an_apple_cage_is_backed_up_and_restored_in_its_own_shape() {
    let dir = agentcage_state::TestDir::new("binary-apple-backup");
    stage_cage(dir.path(), "cage-apple", "apple-container");

    let paths = agentcage_state::Paths::under(dir.path());
    let logs = paths.apple_logs_dir("cage-apple");
    std::fs::create_dir_all(&logs).expect("the apple logs dir is writable");
    std::fs::write(logs.join("capture.jsonl"), "{\"id\": 1}\n").expect("capture is writable");
    std::fs::write(logs.join("audit.jsonl"), "{\"event\": \"allow\"}\n")
        .expect("audit is writable");

    // ── Backup ──
    let tarball = dir.join("apple.tar.gz");
    let out = agentcage_sandboxed(
        dir.path(),
        &[
            "cage",
            "backup",
            "cage-apple",
            "-o",
            &tarball.display().to_string(),
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let names = agentcage_cli::archive::member_names(&tarball).expect("a readable tarball");
    for member in [
        "agentcage-backup/audit/audit.jsonl",
        "agentcage-backup/capture/capture.jsonl",
        "agentcage-backup/config/cage.yaml",
        "agentcage-backup/manifest.json",
    ] {
        assert!(names.iter().any(|name| name == member), "{names:?}");
    }
    // No `volumes/` and no `secrets/`: neither exists on this backend.
    assert!(
        !names
            .iter()
            .any(|name| name.contains("volumes") || name.contains("secrets")),
        "{names:?}"
    );
    assert!(stdout(&out).contains("Volumes: 0 (not supported on apple-container)"));

    // ── `--include-secrets` is a refusal, not a quiet omission ──
    let out = agentcage_sandboxed(
        dir.path(),
        &[
            "cage",
            "backup",
            "cage-apple",
            "--include-secrets",
            "-o",
            &dir.join("never.tar.gz").display().to_string(),
        ],
    );
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("--include-secrets is not supported on apple-container"),
        "{}",
        stderr(&out)
    );
    assert!(!dir.join("never.tar.gz").exists());

    // ── Restore, as a clone ──
    let out = agentcage_sandboxed(
        dir.path(),
        &[
            "cage",
            "restore",
            &tarball.display().to_string(),
            "--name",
            "cage-clone",
            "--no-start",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let complaint = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        !complaint.contains("not ported yet"),
        "apple-container restore still refuses: {complaint}"
    );
    // The logs came back into the apple layout, not the container one.
    let restored = paths.apple_logs_dir("cage-clone");
    assert_eq!(
        std::fs::read_to_string(restored.join("capture.jsonl")).expect("capture restored"),
        "{\"id\": 1}\n"
    );
    assert_eq!(
        std::fs::read_to_string(restored.join("audit.jsonl")).expect("audit restored"),
        "{\"event\": \"allow\"}\n"
    );
    assert!(!paths.capture_file("cage-clone").exists());
}

/// A `vm` cage's logs and audit go to its guest, not to the host.
///
/// There is no guest here, so `cage logs` ends in `limactl`'s own
/// "instance does not exist" — which is the point: it reached `limactl`
/// rather than printing an empty host journal. `cage audit` parses a
/// stream and a reader that produced none is an empty table and exit 0
/// on every backend, so all that can be asserted of it is that it no
/// longer refuses.
///
/// Skipped where `limactl` is not installed, which is every CI runner
/// the rest of this file runs on.
#[test]
fn a_vm_cage_is_read_through_its_guest() {
    if Command::new("limactl").arg("--version").output().is_err() {
        return;
    }
    let dir = agentcage_state::TestDir::new("binary-vm-read");
    stage_cage(dir.path(), "cage-vm", "vm");
    for command in ["logs", "audit"] {
        let out = agentcage_sandboxed(dir.path(), &["cage", command, "cage-vm"]);
        let complaint = format!("{}{}", stdout(&out), stderr(&out));
        assert!(
            !complaint.contains("not ported yet"),
            "{command} vm still refuses: {complaint}"
        );
    }
    let out = agentcage_sandboxed(dir.path(), &["cage", "logs", "cage-vm"]);
    let complaint = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        complaint.contains("agentcage-cage-vm"),
        "logs vm did not reach limactl: {complaint}"
    );
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

/// `cage show` counts an apple cage's secrets through its *own* store,
/// not through host podman.
///
/// This is the shape of bug this backend keeps producing: podman does
/// not error when asked about a cage it has never heard of, it answers
/// *nothing found*. So `cage show` reported `Secrets: 0/1 (1 missing)`
/// on a cage whose secret was present and whose `secret list` said
/// `ok` — two commands disagreeing about the same cage, with the wrong
/// one being the reassuring-looking summary. Observed against a real
/// cage before the fix, where an earlier release answered `1/1`.
///
/// `backend: plaintext` keeps this to a file in the cage's own state
/// directory, so the test never reaches the macOS keychain — and so it
/// runs on Linux CI too, where the bug would otherwise be invisible
/// because `default_isolation` there is `container`.
#[test]
fn an_apple_cage_counts_its_secrets_through_its_own_store() {
    let dir = agentcage_state::TestDir::new("binary-apple-secret-count");
    let home = dir.path();
    let paths = agentcage_state::Paths::under(home);
    let name = "counted";

    std::fs::create_dir_all(paths.deployment_dir(name)).expect("deployment dir");
    std::fs::write(
        paths.deployment_dir(name).join("cage.yaml"),
        format!(
            "name: {name}\n\
             isolation: apple-container\n\
             container:\n  image: \"alpine\"\n\
             secrets:\n  backend: plaintext\n  allow_plaintext: true\n\
             secret_injection:\n  \
               - env: COUNTED_KEY\n    placeholder: \"{{{{COUNTED_KEY}}}}\"\n"
        ),
    )
    .expect("config");
    paths
        .save_metadata(
            name,
            &agentcage_core::har::json::Json::Object(vec![(
                "agentcage_version".to_owned(),
                agentcage_core::har::json::Json::string(agentcage_core::VERSION),
            )]),
        )
        .expect("metadata");

    // With no value stored, the summary must say so.
    let out = agentcage_sandboxed(home, &["cage", "show", name]);
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("Secrets:    0/1 (1 missing)"),
        "an unset secret should read as missing: {text}"
    );

    // The plaintext store's file *is* the store on this backend.
    std::fs::write(
        paths.deployment_dir(name).join("pending_secrets.json"),
        "[[\"COUNTED_KEY\", \"a-value\"]]",
    )
    .expect("store");

    let out = agentcage_sandboxed(home, &["cage", "show", name]);
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("Secrets:    1/1"),
        "a stored secret must be counted through the cage's own store: {text}"
    );
    assert!(
        !text.contains("missing"),
        "nothing is missing once the store has it: {text}"
    );
}

/// `cage edit`'s refusals, driven through the shipped binary with a
/// scripted `$EDITOR`.
///
/// The command's whole reason to exist is that a bad edit cannot leave
/// the cage unloadable, so what is asserted is the *refusals*: each one
/// exits 1, writes the operator's text to `cage.yaml.rejected` so it is
/// not lost, and leaves `cage.yaml` byte-identical. None of these paths
/// reaches a backend, which is what lets them run on a runner with no
/// podman and no Apple CLI.
#[test]
fn cage_edit_refuses_a_bad_edit_without_touching_the_config() {
    let dir = agentcage_state::TestDir::new("binary-cage-edit");
    let home = dir.path();
    let paths = agentcage_state::Paths::under(home);
    let name = "edited";
    stage_cage(home, name, "container");

    let config_path = paths.stored_config_path(name);
    let rejected = paths.deployment_dir(name).join("cage.yaml.rejected");
    let original = std::fs::read_to_string(&config_path).expect("stored config");

    // A scripted editor per case: the argument is the temp file click
    // hands it, so each script edits that rather than the real config.
    let script = |body: &str| -> std::path::PathBuf {
        let path = home.join(format!("ed-{}.sh", body.len()));
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        path
    };

    let cases: [(&str, &str); 3] = [
        // Unparseable YAML.
        ("printf 'a: [b: c\\n' >> \"$1\"", "is not valid YAML"),
        // A top-level list rather than a mapping.
        (
            "printf -- '- a\\n- b\\n' > \"$1\"",
            "must be a YAML mapping",
        ),
        // A rename, which needs state moves this command does not do.
        (
            "sed -e 's/^name: .*/name: other/' \"$1\" > \"$1.t\" && mv \"$1.t\" \"$1\"",
            "renaming a cage via 'cage edit' is not supported",
        ),
    ];

    for (body, expected) in cases {
        let _ = std::fs::remove_file(&rejected);
        let editor = script(body);
        let out = agentcage_sandboxed_env(
            home,
            &["cage", "edit", name],
            &[("EDITOR", editor.to_str().expect("utf-8 path"))],
        );
        let text = format!("{}{}", stdout(&out), stderr(&out));
        assert_eq!(code(&out), 1, "{body}: {text}");
        assert!(text.contains(expected), "{body}: {text}");
        assert!(
            text.contains("is unchanged"),
            "{body}: the refusal must say the original survived: {text}"
        );
        assert!(rejected.is_file(), "{body}: the edit was not kept");
        assert_eq!(
            std::fs::read_to_string(&config_path).expect("stored config"),
            original,
            "{body}: the stored config was modified by a refused edit"
        );
    }

    // An editor that saves nothing is "no changes", exit 0, and no
    // rejected file — `require_save` in click's terms.
    let _ = std::fs::remove_file(&rejected);
    let editor = script("exit 0");
    let out = agentcage_sandboxed_env(
        home,
        &["cage", "edit", name],
        &[("EDITOR", editor.to_str().expect("utf-8 path"))],
    );
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert_eq!(code(&out), 0, "{text}");
    assert!(text.contains("No changes to cage"), "{text}");
    assert!(!rejected.exists(), "a no-op edit left a rejected file");
    assert_eq!(
        std::fs::read_to_string(&config_path).expect("stored config"),
        original
    );
}

/// The old/new line counts in a `@@ -a,b +c,d @@` header, so the helper
/// below can tell where a hunk ends without guessing from the prefix.
fn diff_hunk_counts(header: &str) -> (usize, usize) {
    let mut parts = header.split_whitespace();
    let _at_at = parts.next();
    let old = parts.next().unwrap_or("-0,0");
    let new = parts.next().unwrap_or("+0,0");
    let count = |range: &str| {
        // `-a,b` or `-a` (a one-line range omits the `,b`).
        let body = range.trim_start_matches(['-', '+']);
        let mut fields = body.split(',');
        let _start = fields.next();
        fields
            .next()
            .and_then(|count| count.parse().ok())
            .unwrap_or(1)
    };
    (count(old), count(new))
}

/// Check the unified diff `cage edit` printed against the bytes it
/// actually saved: every `+` line is in the file, every `-` line is not,
/// and every context line still is.
///
/// The diff is a preview, so a discrepancy means the operator was shown
/// a change that is not what landed on disk — the bug in #523 was
/// exactly that, with the preview showing a re-render the operator never
/// asked for.
fn assert_diff_matches_written(stdout: &str, written: &str) {
    let mut in_diff = false;
    let (mut old_left, mut new_left) = (0usize, 0usize);
    for line in stdout.lines() {
        if !in_diff {
            in_diff = line.starts_with("--- ");
            continue;
        }
        if line.starts_with("+++ ") {
            continue;
        }
        if line.starts_with("@@") {
            (old_left, new_left) = diff_hunk_counts(line);
            continue;
        }
        if old_left == 0 && new_left == 0 {
            // The hunk is fully consumed; anything after it is the
            // command's next-steps output.
            break;
        }
        if let Some(added) = line.strip_prefix('+') {
            assert!(
                written.lines().any(|line| line == added),
                "printed as added but not written: {added:?}\n{stdout}"
            );
            new_left = new_left.saturating_sub(1);
        } else if let Some(removed) = line.strip_prefix('-') {
            assert!(
                !written.lines().any(|line| line == removed),
                "printed as removed but still written: {removed:?}\n{stdout}"
            );
            old_left = old_left.saturating_sub(1);
        } else if let Some(context) = line.strip_prefix(' ') {
            assert!(
                written.lines().any(|line| line == context),
                "printed as context but not written: {context:?}\n{stdout}"
            );
            old_left = old_left.saturating_sub(1);
            new_left = new_left.saturating_sub(1);
        } else {
            break;
        }
    }
    assert!(in_diff, "no diff was printed:\n{stdout}");
}

/// The regression from #523: a one-value edit used to re-render the whole
/// document through the YAML emitter, so every comment, quoted scalar and
/// flow-style list in the operator's `cage.yaml` was replaced by the
/// emitter's formatting.
///
/// The bytes written are asserted whole, not line by line: "keeps the
/// comments" means the saved file is the operator's file with the one
/// value changed, and anything looser would let a reformat through.
#[test]
fn cage_edit_keeps_the_operators_comments_and_formatting() {
    let dir = agentcage_state::TestDir::new("binary-cage-edit-comments");
    let home = dir.path();
    let paths = agentcage_state::Paths::under(home);
    let name = "demo";
    let original = r#"# Cage for the demo agent -- keep this comment.
name: demo

isolation: container

container:
  image: "alpine"  # pinned on purpose
  command: ["sleep", "infinity"]
  volumes:
    # Mount the project directory.
    - "~/project:/workspace:rw"
"#;
    stage_cage_with_config(home, name, original);

    let editor = home.join("change-image.sh");
    std::fs::write(
        &editor,
        "#!/bin/sh\nsed -e 's/\"alpine\"/\"ubuntu\"/' \"$1\" > \"$1.t\" && mv \"$1.t\" \"$1\"\n",
    )
    .expect("script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&editor, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let editor = editor.to_str().expect("utf-8 path");
    let out = agentcage_sandboxed_env(
        home,
        &["cage", "edit", name],
        &[("VISUAL", editor), ("EDITOR", editor)],
    );
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert_eq!(code(&out), 0, "{text}");

    let written =
        std::fs::read_to_string(paths.stored_config_path(name)).expect("the stored config");
    assert_eq!(
        written,
        original.replace("\"alpine\"", "\"ubuntu\""),
        "the edit reformatted something besides the value it changed"
    );

    // The diff is computed against the bytes on disk, not a re-render:
    // the swapped line is the only change and the comment lines are
    // context, never removals.
    let printed = stdout(&out);
    assert!(
        printed.contains("-  image: \"alpine\"  # pinned on purpose\n"),
        "{printed}"
    );
    assert!(
        printed.contains("+  image: \"ubuntu\"  # pinned on purpose\n"),
        "{printed}"
    );
    assert!(
        printed.contains(" # Mount the project directory.\n"),
        "the volumes comment was not shown as unchanged context: {printed}"
    );
    assert!(
        !printed.contains("-# Mount the project directory."),
        "a comment the edit did not touch was printed as removed: {printed}"
    );
    assert_diff_matches_written(&printed, &written);
}

/// The other half of the contract: when the CLI itself has to change the
/// document — here, minting a placeholder for a rule that omits one —
/// there is no operator text for the value tree to preserve, so the
/// re-rendered document is the one saved and the one the diff describes.
#[test]
fn cage_edit_saves_the_rendered_document_when_it_fills_a_placeholder() {
    let dir = agentcage_state::TestDir::new("binary-cage-edit-fill");
    let home = dir.path();
    let paths = agentcage_state::Paths::under(home);
    let name = "fill";
    let original = r#"# A comment the fill cannot keep.
name: fill

isolation: container

container:
  image: "alpine"

domains:
  allow:
    - example.com

secret_injection:
  # No placeholder yet, so the CLI has to add one.
  - env: DEMO_KEY
    inject_to:
      - example.com
"#;
    stage_cage_with_config(home, name, original);

    let editor = home.join("change-image.sh");
    std::fs::write(
        &editor,
        "#!/bin/sh\nsed -e 's/\"alpine\"/\"ubuntu\"/' \"$1\" > \"$1.t\" && mv \"$1.t\" \"$1\"\n",
    )
    .expect("script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&editor, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let editor = editor.to_str().expect("utf-8 path");
    let out = agentcage_sandboxed_env(
        home,
        &["cage", "edit", name],
        &[("VISUAL", editor), ("EDITOR", editor)],
    );
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert_eq!(code(&out), 0, "{text}");

    let written =
        std::fs::read_to_string(paths.stored_config_path(name)).expect("the stored config");
    // The minted token is the only nondeterministic part.
    assert!(
        written.contains("placeholder: agentcage:secret:DEMO_KEY:"),
        "the filled placeholder was not saved: {written}"
    );
    // Re-rendered, as the fallback requires: the emitter drops comments
    // and the operator's quotes, and the intended value change is there.
    assert!(
        !written.lines().any(|line| line.contains('#')),
        "a fill must save the re-rendered document, not the commented text: {written}"
    );
    assert!(
        written.contains("image: ubuntu") && !written.contains("\"ubuntu\""),
        "the saved document was not re-rendered: {written}"
    );

    let printed = stdout(&out);
    assert!(
        printed.contains("-# A comment the fill cannot keep.\n"),
        "the diff did not describe the re-rendered document: {printed}"
    );
    assert!(
        printed.contains("+  placeholder: agentcage:secret:DEMO_KEY:"),
        "the diff does not show the minted placeholder: {printed}"
    );
    assert_diff_matches_written(&printed, &written);
}

// ── the automation contract (issue #569, phase 0) ───────────────────
//
// `-h`, `--no-color`/`NO_COLOR`, `--quiet`/`CI`, the JSON envelope and
// `agentcage paths` are for scripts. The script-shaped assertions here
// are deliberately made against the *process*: a pty for the colour
// tests (a pipe would strip the escapes for a reason that has nothing to
// do with the new flags), and one parsed JSON document for each envelope.

/// Put the child's stdout/stderr on a pty and read everything it wrote.
///
/// Only a terminal makes `output::echo` keep its escapes, so proving
/// `--no-color` changes anything needs one. stdin is `/dev/null`; the
/// child is `--help` or a command that fails fast, and both exits close
/// the slave side.
fn agentcage_in_a_pty(home: &std::path::Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let pty = nix::pty::openpty(None, None).expect("a pty");
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentcage"));
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_RUNTIME_DIR", home.join("run"))
        // The test controls these; an inherited value would decide the
        // assertion for it. A terminal alone is not enough for clap's
        // colour writer: `TERM=dumb` (GitHub's runner) strips the help,
        // so use a colour-capable terminal name for the pty.
        .env_remove("NO_COLOR")
        .env_remove("CI")
        .env("TERM", "xterm-256color")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(
            pty.slave.try_clone().expect("clone the pty"),
        ))
        .stderr(std::process::Stdio::from(pty.slave));
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("the binary starts");
    // The parent's own copies of the slave side keep the pty open; the
    // child closing its stdio is what must produce EOF here.
    drop(command);
    let mut output = Vec::new();
    {
        use std::io::Read as _;
        let mut master = std::fs::File::from(pty.master);
        let mut buffer = [0_u8; 4096];
        loop {
            match master.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buffer[..n]),
                // A signal interrupted the read; try again.
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                // EIO once the last slave descriptor closes, on Linux.
                Err(_) => break,
            }
        }
    }
    let _ = child.wait();
    String::from_utf8_lossy(&output).into_owned()
}

/// One parsed JSON document on stdout, and nothing on stderr.
fn json_document(out: &Output) -> serde_json::Value {
    assert_eq!(code(out), 0, "stderr: {}", stderr(out));
    assert!(stderr(out).is_empty(), "{}", stderr(out));
    serde_json::from_str(&stdout(out)).unwrap_or_else(|error| {
        panic!("stdout is not one JSON document ({error}): {}", stdout(out))
    })
}

/// The five envelope keys, in this order, in the raw bytes.
fn assert_envelope(doc: &serde_json::Value, command: &str) {
    assert_eq!(doc["schema_version"], 1);
    assert_eq!(doc["command"], command);
    assert_eq!(doc["ok"], true);
    assert_eq!(doc["warnings"], serde_json::json!([]));
}

fn assert_key_order(text: &str, keys: &[&str]) {
    let mut last = 0;
    for key in keys {
        let needle = format!("\"{key}\"");
        let at = text[last..]
            .find(&needle)
            .unwrap_or_else(|| panic!("{key} missing from {text}"))
            + last;
        assert!(at >= last, "{keys:?} are out of order in {text}");
        last = at + needle.len();
    }
}

/// `-h` is the same help as `--help`, at the root and under any command.
#[test]
fn short_and_long_help_are_the_same_help() {
    assert_eq!(stdout(&agentcage(&["-h"])), stdout(&agentcage(&["--help"])));
    for args in [
        vec!["cage", "har"],
        vec!["cage", "create"],
        vec!["domain", "list"],
        vec!["secret", "set"],
        vec!["paths"],
        vec!["version"],
    ] {
        let mut short_args = args.clone();
        short_args.push("-h");
        let mut long_args = args.clone();
        long_args.push("--help");
        let short = agentcage(&short_args);
        let long = agentcage(&long_args);
        assert_eq!(code(&short), 0, "{args:?}: {}", stderr(&short));
        assert_eq!(
            stdout(&short),
            stdout(&long),
            "{args:?}: -h and --help differ"
        );
        assert!(stdout(&short).contains("Usage:"), "{args:?}");
    }
    // Every group as well.
    for group in ["cage", "domain", "secret", "watcher", "scaffold"] {
        let out = agentcage(&[group, "-h"]);
        assert_eq!(code(&out), 0, "{group}: {}", stderr(&out));
        assert!(stdout(&out).contains("Usage:"), "{group}");
    }
}

/// On a terminal the escapes are there, and `--no-color` / `NO_COLOR`
/// take them away — including clap's own styled usage output.
#[test]
fn no_color_switches_off_ansi_on_a_terminal() {
    let dir = agentcage_state::TestDir::new("binary-no-color");
    let home = dir.path();

    let styled = agentcage_in_a_pty(home, &["--help"], &[]);
    assert!(
        styled.contains("\u{1b}["),
        "a tty should keep the banner's escapes: {styled:.80}"
    );

    for (args, env) in [
        (vec!["--no-color", "--help"], vec![]),
        (vec!["--help"], vec![("NO_COLOR", "1")]),
        // "any value", including the empty one.
        (vec!["--help"], vec![("NO_COLOR", "")]),
        // After the command, before the help: every global position.
        (vec!["cage", "list", "--no-color", "--help"], vec![]),
    ] {
        let plain = agentcage_in_a_pty(home, &args, &env);
        assert!(
            !plain.contains("\u{1b}["),
            "{args:?} {env:?} still carried an escape: {plain:.80}"
        );
    }

    // A parse error is clap's output, and the flag has to reach it too.
    let plain = agentcage_in_a_pty(home, &["nosuchcommand", "--no-color"], &[]);
    assert!(!plain.contains("\u{1b}["), "{plain:.80}");
}

/// `--quiet` and `CI` drop the progress banner; the command's own error
/// still lands on stderr.
#[test]
fn quiet_and_ci_silence_progress_but_never_the_error() {
    let dir = agentcage_state::TestDir::new("binary-quiet");
    let home = dir.path();
    let config = home.join("not-a-cage.yaml");
    std::fs::write(&config, "not a cage\n").expect("a config file");
    let config = config.display().to_string();

    let loud = agentcage_in_a_pty(home, &["cage", "create", &config], &[]);
    assert!(
        loud.contains(&format!("agentcage v{}", agentcage_core::VERSION)),
        "the banner is the progress output this test removes: {loud:.80}"
    );
    assert!(loud.contains("error:"), "{loud:.80}");

    for (args, env) in [
        (vec!["--quiet", "cage", "create", &config], vec![]),
        (vec!["cage", "create", "--quiet", &config], vec![]),
        (vec!["cage", "create", &config], vec![("CI", "1")]),
    ] {
        let quiet = agentcage_in_a_pty(home, &args, &env);
        assert!(
            !quiet.contains(&format!("agentcage v{}", agentcage_core::VERSION)),
            "{args:?} {env:?} still printed the banner: {quiet:.80}"
        );
        assert!(
            quiet.contains("error:"),
            "{args:?} {env:?} swallowed the error: {quiet:.80}"
        );
    }
}

/// `--quiet` must not touch a command's explicit output.
#[test]
fn quiet_keeps_explicit_command_output() {
    let dir = agentcage_state::TestDir::new("binary-quiet-output");
    let quiet = agentcage_sandboxed(dir.path(), &["--quiet", "paths"]);
    let loud = agentcage_sandboxed(dir.path(), &["paths"]);
    assert_eq!(code(&quiet), 0, "{}", stderr(&quiet));
    assert_eq!(stdout(&quiet), stdout(&loud));
    assert!(stdout(&quiet).contains("ROOT"), "{}", stdout(&quiet));

    // An error still reaches stderr under --quiet, with exit 1.
    let out = agentcage_sandboxed(dir.path(), &["domain", "list", "nope", "--quiet"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("does not exist"), "{}", stderr(&out));
}

/// `agentcage version --json`, and the plain spelling it replaces.
#[test]
fn version_json_is_the_shared_envelope() {
    let out = agentcage(&["version", "--json"]);
    let text = stdout(&out);
    let doc = json_document(&out);
    assert_envelope(&doc, "version");
    assert_eq!(doc["data"]["name"], "agentcage");
    assert_eq!(doc["data"]["version"], agentcage_core::VERSION);
    assert_key_order(
        &text,
        &["schema_version", "command", "ok", "data", "warnings"],
    );

    let plain = agentcage(&["version"]);
    assert_eq!(code(&plain), 0);
    assert_eq!(
        stdout(&plain).trim_end(),
        format!("agentcage, version {}", agentcage_core::VERSION)
    );
}

/// `agentcage paths` prints the roots `Paths` resolved, in both shapes.
#[test]
fn paths_prints_the_resolved_roots() {
    let dir = agentcage_state::TestDir::new("binary-paths");
    let home = dir.path();

    let human = agentcage_sandboxed(home, &["paths"]);
    assert_eq!(code(&human), 0, "{}", stderr(&human));
    let text = stdout(&human);
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].starts_with("ROOT"), "{text}");
    for label in [
        "home",
        "config",
        "data",
        "cache",
        "runtime",
        "apple-container",
        "quadlets",
        "user-units",
    ] {
        assert!(
            lines.iter().any(|line| line.starts_with(label)),
            "{label} is missing from:\n{text}"
        );
    }
    assert!(
        text.contains(&home.join(".config/agentcage").display().to_string()),
        "the config root is not the sandbox's: {text}"
    );

    let out = agentcage_sandboxed(home, &["paths", "--json"]);
    let doc = json_document(&out);
    assert_envelope(&doc, "paths");
    assert_eq!(
        doc["data"]["config"],
        home.join(".config/agentcage").display().to_string()
    );
    assert_eq!(
        doc["data"]["data"],
        home.join(".local/share/agentcage").display().to_string()
    );
    assert_eq!(
        doc["data"]["runtime"],
        home.join("run").display().to_string()
    );
    assert_eq!(
        doc["data"]["cache"],
        home.join(".local/share/agentcage/assets")
            .display()
            .to_string()
    );
    // Nothing was created by asking.
    assert!(!home.join(".config/agentcage").exists());
}

/// A cage on disk with a domain list, for the two `list --json` cases.
fn stage_domain_cage(home: &std::path::Path, name: &str) {
    stage_cage_with_config(
        home,
        name,
        &format!(
            "name: {name}\n\
             isolation: container\n\
             container:\n  image: \"alpine\"\n\
             domains:\n  allow:\n    - example.com\n    - api.example.com\n\
             \x20 passthrough:\n    - passthrough.example.com\n\
             \x20 expires:\n    api.example.com: 2030-01-01T00:00:00Z\n"
        ),
    );
}

/// `domain list --json` (and its `ls` alias) is the shared envelope, and
/// carries the same list the table prints.
#[test]
fn domain_list_json_is_the_shared_envelope() {
    let dir = agentcage_state::TestDir::new("binary-domain-json");
    let home = dir.path();
    stage_domain_cage(home, "acme");

    let out = agentcage_sandboxed(home, &["domain", "list", "acme", "--json"]);
    let text = stdout(&out);
    let doc = json_document(&out);
    assert_envelope(&doc, "domain list");
    assert_eq!(doc["data"]["cage"], "acme");
    assert_eq!(doc["data"]["mode"], "allowlist");
    let domains: Vec<&str> = doc["data"]["domains"]
        .as_array()
        .expect("domains")
        .iter()
        .map(|entry| entry["domain"].as_str().expect("domain"))
        .collect();
    assert_eq!(domains, ["api.example.com", "example.com"]);
    let api = &doc["data"]["domains"][0];
    assert_eq!(api["expires_at"], "2030-01-01T00:00:00Z");
    assert_eq!(
        doc["data"]["passthrough"],
        serde_json::json!(["passthrough.example.com"])
    );
    assert_eq!(
        doc["data"]["passthrough_only"],
        serde_json::json!(["passthrough.example.com"])
    );
    assert_key_order(
        &text,
        &["schema_version", "command", "ok", "data", "warnings"],
    );

    // The alias resolves to the same document.
    let alias = agentcage_sandboxed(home, &["domain", "ls", "acme", "--json"]);
    assert_eq!(stdout(&alias), text, "the ls alias changed the document");
    assert_eq!(code(&alias), 0, "{}", stderr(&alias));
}

/// `secret list --json` names secrets and never emits their values.
#[test]
fn secret_list_json_never_carries_a_value() {
    let dir = agentcage_state::TestDir::new("binary-secret-json");
    let home = dir.path();
    let name = "acme";
    let paths = agentcage_state::Paths::under(home);
    stage_cage_with_config(
        home,
        name,
        &format!(
            "name: {name}\n\
             isolation: apple-container\n\
             container:\n  image: \"alpine\"\n\
             secrets:\n  backend: plaintext\n  allow_plaintext: true\n\
             secret_injection:\n  \
               - env: API_KEY\n    placeholder: \"{{{{API_KEY}}}}\"\n"
        ),
    );
    let value = "sk-live-this-must-not-be-printed";
    std::fs::write(
        paths.deployment_dir(name).join("pending_secrets.json"),
        format!("[[\"API_KEY\", {value:?}]]"),
    )
    .expect("the plaintext store");

    let out = agentcage_sandboxed(home, &["secret", "list", name, "--json"]);
    let doc = json_document(&out);
    assert_envelope(&doc, "secret list");
    assert_eq!(doc["data"]["cage"], name);
    assert_eq!(doc["data"]["secrets"][0]["name"], "API_KEY");
    assert_eq!(doc["data"]["secrets"][0]["type"], "injection");
    assert_eq!(doc["data"]["secrets"][0]["present"], true);
    assert_eq!(doc["data"]["secrets"][0]["placeholder"], "{{API_KEY}}");
    assert!(
        !stdout(&out).contains(value),
        "the secret value reached stdout: {}",
        stdout(&out)
    );

    let alias = agentcage_sandboxed(home, &["secret", "ls", name, "--json"]);
    assert_eq!(stdout(&alias), stdout(&out));
    assert_eq!(code(&alias), 0, "{}", stderr(&alias));
}

/// A declared-but-absent secret still exits 1 in JSON mode — the
/// envelope documents what was found, and the exit code reports it.
#[test]
fn secret_list_json_keeps_the_missing_exit_code() {
    let dir = agentcage_state::TestDir::new("binary-secret-json-missing");
    let home = dir.path();
    stage_cage_with_config(
        home,
        "acme",
        "name: acme\nisolation: apple-container\ncontainer:\n  image: \"alpine\"\n\
         secrets:\n  backend: plaintext\n  allow_plaintext: true\n\
         secret_injection:\n  - env: API_KEY\n    placeholder: \"{{API_KEY}}\"\n",
    );
    let out = agentcage_sandboxed(home, &["secret", "list", "acme", "--json"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    let doc: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("one document");
    assert_envelope(&doc, "secret list");
    assert_eq!(doc["data"]["secrets"][0]["present"], false);
}

/// `completions print --shell` is the positional spelling, byte for byte.
#[test]
fn completions_print_matches_the_positional_spelling() {
    for shell in ["bash", "zsh", "fish"] {
        let positional = agentcage(&["completions", shell]);
        let flagged = agentcage(&["completions", "print", "--shell", shell]);
        assert_eq!(code(&positional), 0, "{shell}: {}", stderr(&positional));
        assert_eq!(code(&flagged), 0, "{shell}: {}", stderr(&flagged));
        assert_eq!(stdout(&flagged), stdout(&positional), "{shell}");
        assert!(stdout(&flagged).contains("agentcage"), "{shell}");
    }
    assert_eq!(code(&agentcage(&["completions", "print"])), 2);
    assert_eq!(
        code(&agentcage(&["completions", "print", "--shell", "elvish"])),
        2
    );
    // There is no `install`: dotfiles are the user's.
    assert_eq!(code(&agentcage(&["completions", "install", "bash"])), 2);
}
