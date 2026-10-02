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
    // The check the port deletes: RUST-PORT-PLAN.md §2.4 makes "no host
    // Python" an invariant, so `doctor` must not go looking for one.
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
/// cage before the fix, where the Python answered `1/1`.
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
