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
        (vec!["cage", "destroy", "myapp", "-y"], "cage destroy"),
        (vec!["doctor"], "doctor"),
        (vec!["cage", "grants", "myapp", "sync"], "cage grants sync"),
        (
            vec!["secret", "rotate-placeholders", "myapp"],
            "secret rotate-placeholders",
        ),
    ] {
        let out = agentcage(&args);
        assert_eq!(code(&out), NOT_IMPLEMENTED, "{args:?}");
        assert!(stdout(&out).is_empty(), "{args:?}");
        let text = stderr(&out);
        assert!(text.contains(&format!("`{expected}`")), "{args:?}: {text}");
        assert!(text.contains("not implemented"), "{args:?}: {text}");
    }
}

/// An alias reports the command it resolves to, not the alias.
#[test]
fn aliases_report_their_canonical_command() {
    for (alias, canonical) in [
        (["rm", "myapp"], "cage destroy"),
        (["ls", "--"], "cage list"),
        (["ps", "--"], "cage list"),
        (["reload", "myapp"], "cage restart"),
        (["config", "myapp"], "cage edit"),
        (["describe", "myapp"], "cage show"),
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

/// The two `ignore_unknown_options` commands, end to end.
///
/// A flag-shaped argument after `--` must reach the workload rather than
/// being parsed. The binary cannot yet *run* a workload, so what is
/// asserted is the observable consequence: the command parsed (exit 70,
/// naming itself) instead of failing on the flag (exit 2).
#[test]
fn passthrough_accepts_flag_shaped_arguments() {
    for (args, expected) in [
        (
            vec!["cage", "exec", "myapp", "--", "ls", "-la"],
            "cage exec",
        ),
        (
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
            "cage exec",
        ),
        // Without `--` too: click's `ignore_unknown_options` does not
        // require the separator, and neither does this.
        (vec!["cage", "exec", "myapp", "ls", "-la"], "cage exec"),
        (vec!["exec", "myapp", "--", "ls", "-la"], "cage exec"),
        (vec!["run", "codex", "--", "codex", "--version"], "cage run"),
        (
            vec!["cage", "run", "claude-code", "--", "claude", "-p", "hi"],
            "cage run",
        ),
        // A known flag before the separator is still this command's own.
        (
            vec!["run", "claude-code", "--verbose", "--", "--not-a-flag"],
            "cage run",
        ),
    ] {
        let out = agentcage(&args);
        assert_eq!(
            code(&out),
            NOT_IMPLEMENTED,
            "{args:?} should have parsed: {}",
            stderr(&out)
        );
        assert!(stderr(&out).contains(&format!("`{expected}`")), "{args:?}");
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
