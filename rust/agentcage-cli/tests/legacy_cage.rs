//! The v0.21 legacy-cage detector, at the command entry point.
//!
//! `tests/test_v021_legacy_cage.py`, ported. The plan filed that file
//! under D16 with the `legacy_watcher` work, which is a name collision:
//! it never imports `legacy_watcher`. It imports the CLI and drives
//! `CliRunner` over the whole command tree, which makes it a *command
//! tree* test and PR D7's.
//!
//! # What it pins
//!
//! v0.22 collapsed the per-cage shape from three services (cage /
//! proxy / dns) into two (cage / egress). A v0.21 cage's containers
//! carry the old names, its quadlets reference deleted templates, and
//! its resolver IPs are off by one — the old `ip_dns` slot is now
//! `ip_egress`. Every v0.22 command addresses the new shape, so rather
//! than failing with a podman error six frames down, each one checks
//! the version recorded in `metadata.json` and exits **2** with the
//! migration procedure.
//!
//! Two commands are **exempt**, and the exemptions are the interesting
//! half:
//!
//! * **`cage destroy`** is the documented way out. Gating it would
//!   leave an operator with a cage they are told to destroy and a
//!   `destroy` that refuses to.
//! * **`cage list`** annotates instead. Running the v0.22 probe
//!   against a legacy cage answers "not running" for containers that
//!   are running under other names, so a gate here would be replaced
//!   by a *wrong answer*, which is worse.
//!
//! A third exemption exists that the Python file does not cover, and
//! it is the same reasoning one step further: `cage prune` walks past
//! legacy cages silently, because it acts on "not running" — see
//! `cli/cage/lifecycle.rs`.
//!
//! # Why this shells out
//!
//! The Python patches `agentcage.cli.state` and asserts on
//! `CliRunner`'s captured output. There is no equivalent seam here —
//! `Ctx::system()` is built inside the dispatch — so the state is
//! staged on disk under a throwaway `HOME` and the binary is run for
//! real. That is a stronger test of the same claim: it proves the gate
//! fires through the *shipped* entry point, aliases and all.

use std::path::Path;
use std::process::{Command, Output};

use agentcage_core::har::json::Json;

/// sysexits' `EX_SOFTWARE`, which every command without a body exits
/// with.
const NOT_IMPLEMENTED: i32 = 70;

/// The detector's own status. Not 1: a script that treated "no such
/// cage" and "this cage predates the layout" alike would retry a
/// migration forever.
const LEGACY: i32 = 2;

fn agentcage(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentcage"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_RUNTIME_DIR", home.join("run"))
        // `cage edit` would otherwise open one.
        .env("EDITOR", "/bin/true")
        .output()
        .expect("the binary is built by `cargo test`")
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("no signal")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A cage on disk whose `metadata.json` stamps `version`.
///
/// The `cage.yaml` is real and loadable, because two of the guarded
/// commands (`cage verify`, `cage prune`) read the config *before* the
/// gate; staging a cage that fails to load would have them exit 1 for
/// the wrong reason and the test would pass for no reason.
fn stage(home: &Path, name: &str, version: Option<&str>) {
    let paths = agentcage_state::Paths::under(home);
    std::fs::create_dir_all(paths.deployment_dir(name)).expect("the deployment dir is writable");
    std::fs::write(
        paths.deployment_dir(name).join("cage.yaml"),
        format!("name: {name}\nisolation: container\ncontainer:\n  image: \"alpine\"\n"),
    )
    .expect("the config is writable");
    let fields = version.map_or_else(Vec::new, |version| {
        vec![("agentcage_version".to_owned(), Json::string(version))]
    });
    paths
        .save_metadata(name, &Json::Object(fields))
        .expect("the metadata is writable");
}

/// The migration procedure, as an operator reads it.
fn says_migrate(out: &Output, version: &str) {
    let text = stderr(out);
    assert!(
        text.contains(&format!("was created with agentcage v{version}")),
        "no version in the refusal: {text}"
    );
    assert!(
        text.contains("legacy 3-service layout (cage / proxy / dns)"),
        "no diagnosis in the refusal: {text}"
    );
    assert!(
        text.contains("agentcage cage destroy"),
        "the refusal does not name the way out: {text}"
    );
}

// ── guarded ─────────────────────────────────────────────────────────

/// Every ported command that addresses a cage refuses a v0.21 one.
///
/// One `HOME` for all of them: the gate is a read, so nothing here
/// changes what the next case sees.
#[test]
fn the_guarded_commands_refuse_a_v021_cage() {
    let dir = agentcage_state::TestDir::new("legacy-guarded");
    stage(dir.path(), "test", Some("0.21.5"));

    for args in [
        vec!["cage", "restart", "test"],
        vec!["cage", "stop", "test"],
        vec!["cage", "start", "test"],
        vec!["cage", "show", "test"],
        vec!["cage", "logs", "test"],
        vec!["cage", "verify", "test"],
        vec!["cage", "exec", "test", "--", "ls"],
        vec!["cage", "shell", "test"],
        vec!["cage", "audit", "test"],
        vec!["cage", "har", "test"],
        vec!["cage", "update", "test"],
        vec!["secret", "list", "test"],
        vec!["secret", "rm", "test", "KEY"],
    ] {
        let out = agentcage(dir.path(), &args);
        assert_eq!(code(&out), LEGACY, "{args:?}: {}", stderr(&out));
        says_migrate(&out, "0.21.5");
    }
}

/// The same refusal through the hidden root aliases, which are separate
/// `Command` clones and so could in principle miss the gate.
#[test]
fn the_root_aliases_refuse_it_too() {
    let dir = agentcage_state::TestDir::new("legacy-aliases");
    stage(dir.path(), "test", Some("0.21.5"));

    for args in [
        vec!["start", "test"],
        vec!["stop", "test"],
        vec!["restart", "test"],
        vec!["reload", "test"],
        vec!["show", "test"],
        vec!["describe", "test"],
        vec!["inspect", "test"],
        vec!["status", "test"],
        vec!["logs", "test"],
        vec!["update", "test"],
        vec!["shell", "test"],
        vec!["exec", "test", "--", "ls"],
    ] {
        let out = agentcage(dir.path(), &args);
        assert_eq!(code(&out), LEGACY, "{args:?}: {}", stderr(&out));
    }
}

/// The commands the Python file guards that this port has not reached.
///
/// They are asserted to be *stubs*, not to be guarded, which is the
/// point: when `cage edit`, `cage backup` or the `domain` group lands,
/// this test fails and whoever landed it has to move the row up into
/// [`the_guarded_commands_refuse_a_v021_cage`]. A guarded command that
/// quietly arrives ungated is exactly what that would otherwise look
/// like.
#[test]
fn the_unported_guarded_commands_are_still_stubs() {
    let dir = agentcage_state::TestDir::new("legacy-unported");
    stage(dir.path(), "test", Some("0.21.5"));

    for args in [
        vec!["cage", "backup", "test"],
        vec!["cage", "edit", "test"],
        vec!["domain", "list", "test"],
        vec!["domain", "add", "test", "example.com"],
        vec!["domain", "rm", "test", "example.com"],
    ] {
        let out = agentcage(dir.path(), &args);
        assert_eq!(
            code(&out),
            NOT_IMPLEMENTED,
            "{args:?} has a body now — add it to the guarded list: {}",
            stderr(&out)
        );
    }
}

// ── exempt ──────────────────────────────────────────────────────────

/// `cage destroy` is the escape hatch. It must not consult the gate,
/// and it must actually remove the cage.
#[test]
fn destroy_is_exempt_and_removes_the_legacy_cage() {
    let dir = agentcage_state::TestDir::new("legacy-destroy");
    // Not "test": destroy is the one case here that reaches the real
    // host podman, and an idempotent `rm` of `<name>-net` is only
    // harmless while `<name>` is a name nothing else uses.
    stage(dir.path(), "d7-legacy-victim", Some("0.21.5"));

    let out = agentcage(dir.path(), &["cage", "destroy", "d7-legacy-victim", "-y"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("state:d7-legacy-victim"),
        "destroy did not remove the state: {}",
        stdout(&out)
    );
    assert!(
        !stderr(&out).contains("legacy 3-service"),
        "destroy consulted the gate: {}",
        stderr(&out)
    );
    assert!(
        !agentcage_state::Paths::under(dir.path()).deployment_exists("d7-legacy-victim"),
        "the cage is still on disk"
    );
}

/// `rm` and `delete`, destroy's root aliases, are exempt on the same
/// terms — they are what an operator reaching for the escape hatch
/// actually types.
#[test]
fn destroys_aliases_are_exempt_too() {
    for alias in ["rm", "delete"] {
        let dir = agentcage_state::TestDir::new(&format!("legacy-destroy-{alias}"));
        let name = format!("d7-legacy-{alias}");
        stage(dir.path(), &name, Some("0.21.5"));
        let out = agentcage(dir.path(), &[alias, &name, "-y"]);
        assert_eq!(code(&out), 0, "{alias}: {}", stderr(&out));
        assert!(
            !stderr(&out).contains("legacy 3-service"),
            "{alias} consulted the gate: {}",
            stderr(&out)
        );
    }
}

/// `cage list` annotates instead of refusing, and prints no live
/// status for the legacy row — the whole reason it is exempt.
#[test]
fn list_is_exempt_and_annotates_instead() {
    let dir = agentcage_state::TestDir::new("legacy-list");
    stage(dir.path(), "old", Some("0.21.5"));

    let out = agentcage(dir.path(), &["cage", "list"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("old"), "{text}");
    assert!(text.contains("legacy v0.21"), "{text}");
    // The probe was not run: a status would mean the v0.22 shape was
    // queried, and the answer for a live legacy cage is "stopped".
    assert!(
        !text.contains("running (") && !text.contains("stopped ("),
        "cage list probed the new shape for a legacy cage: {text}"
    );
}

/// A v0.22 cage in the same table takes the normal status path. The
/// Python's regression guard, and the reason the annotation cannot be
/// unconditional.
#[test]
fn a_current_cage_in_the_table_is_unaffected() {
    let dir = agentcage_state::TestDir::new("legacy-list-mixed");
    stage(dir.path(), "new", Some("0.22.0"));

    let out = agentcage(dir.path(), &["cage", "list"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("new"), "{text}");
    assert!(!text.contains("legacy v0.21"), "{text}");
    // No cage is running under a throwaway HOME, so the probe ran and
    // answered.
    assert!(text.contains("stopped (0/2)"), "{text}");
}

// ── the version parse, at the entry point ───────────────────────────

/// The detector fails **closed**. A stamp it cannot read is not a
/// future version, an opt-out or a blank slate — it is a cage this
/// build does not know how to address.
#[test]
fn an_unreadable_version_is_treated_as_legacy() {
    for (label, version) in [
        ("missing", None),
        ("garbage", Some("not-a-version")),
        ("empty", Some("")),
        ("one component", Some("1")),
    ] {
        let dir = agentcage_state::TestDir::new(&format!("legacy-ver-{}", label.replace(' ', "-")));
        stage(dir.path(), "test", version);
        let out = agentcage(dir.path(), &["cage", "stop", "test"]);
        assert_eq!(code(&out), LEGACY, "{label}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("legacy 3-service"),
            "{label}: {}",
            stderr(&out)
        );
    }
}

/// `< (0, 22)`, so 0.22.0 itself is current — and everything after it.
///
/// Asserted as "not the gate" rather than "exit 0": `cage stop` goes on
/// to talk to systemd, and what systemd says about a cage that was
/// never deployed is not this test's business.
#[test]
fn v022_and_everything_after_it_passes() {
    for version in ["0.22.0", "0.22.1", "0.99.0", "1.0.0"] {
        let dir = agentcage_state::TestDir::new(&format!("legacy-ok-{version}"));
        stage(dir.path(), "test", Some(version));
        let out = agentcage(dir.path(), &["cage", "stop", "test"]);
        assert_ne!(code(&out), LEGACY, "{version}: {}", stderr(&out));
        assert!(
            !stderr(&out).contains("legacy 3-service"),
            "{version}: {}",
            stderr(&out)
        );
    }
}

/// A `metadata.json` that exists and will not parse is the one case
/// that is *not* the migration message.
///
/// The Python raises `JSONDecodeError` out of the command and prints a
/// traceback. Neither the traceback nor "migrate away from the v0.21
/// layout" is true of a cage whose metadata simply got corrupted, so
/// this reports the file and exits 1 — `preflight::EXIT_NO_SUCH_CAGE`.
#[test]
fn a_corrupt_metadata_file_is_reported_rather_than_diagnosed() {
    let dir = agentcage_state::TestDir::new("legacy-corrupt");
    stage(dir.path(), "test", Some("0.40.1"));
    let paths = agentcage_state::Paths::under(dir.path());
    std::fs::write(
        paths.deployment_dir("test").join("metadata.json"),
        "{not json",
    )
    .expect("the metadata is writable");

    let out = agentcage(dir.path(), &["cage", "stop", "test"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("cannot read state for cage 'test'"),
        "{}",
        stderr(&out)
    );
    assert!(
        !stderr(&out).contains("legacy 3-service"),
        "{}",
        stderr(&out)
    );
}
