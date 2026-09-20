//! `cage har` against the Python's own recordings.
//!
//! `tests/fixtures/cage-har/cases.json` is 26 runs of the real
//! `agentcage cage har` over a throwaway copy of PR A7's frozen 0.40.1
//! state, recorded by `scripts/gen-cage-har-fixture.py`: argv, the setup
//! each one needed, the exit status, stdout, stderr, and the file any
//! `-o` wrote. This replays every one of them through
//! [`agentcage_cli::har::run`] and compares all four outputs byte for
//! byte.
//!
//! # Why the comparison is bytes and not shape
//!
//! Two of the four are JSON and it would be easy to parse both sides and
//! compare values. That would throw away the thing being tested.
//! `cli.py:3101` is `json.dumps(har, indent=2)` — Python **insertion
//! order**, `ensure_ascii=True`, two-space indent — and the golden
//! corpus stores the *other* serialization of the same value
//! (`sort_keys=True, ensure_ascii=False`). A value comparison passes
//! under either, so it would not notice this command shipping the wrong
//! one. C6's unit tests pin `dumps`; these pin what reaches a file.
//!
//! # What this cannot check
//!
//! The plan's acceptance for PR D13 is "corpus diff plus a manual
//! `DevTools` load", and the second half is not reachable from a test
//! runner — there is no browser here and importing a HAR into Chrome
//! `DevTools`' Network panel is a human action. What is checked instead is
//! stronger than a smoke test and weaker than a load: every byte this
//! command writes is a byte the Python wrote, for five capture files
//! across two state roots. If `DevTools` accepted the Python's export, it
//! accepts this one, because they are the same file. Whether `DevTools`
//! accepts the Python's export at all is a question about `har.py`,
//! which this port does not change.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use agentcage_cli::har::{self, HarArgs};
use agentcage_exec::FakeRunner;
use agentcage_state::paths::Paths;
use agentcage_state::testdir::TestDir;
use serde_json::Value;

use common::{repo_root, state_fixture_root};

/// One recorded run.
struct Case {
    name: String,
    argv: Vec<String>,
    setup: Vec<Value>,
    exit_code: u8,
    stdout: String,
    stderr: String,
    output_path: Option<String>,
    output_text: Option<String>,
}

fn fixture() -> (String, Vec<Case>) {
    let path = repo_root().join("tests/fixtures/cage-har/cases.json");
    let text = fs::read_to_string(&path).expect("the cage-har fixture is committed");
    let root: Value = serde_json::from_str(&text).expect("valid JSON");

    let version = root["version"].as_str().expect("version").to_owned();
    let cases = root["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| Case {
            name: case["name"].as_str().expect("name").to_owned(),
            argv: case["argv"]
                .as_array()
                .expect("argv")
                .iter()
                .map(|a| a.as_str().expect("argv item").to_owned())
                .collect(),
            setup: case["setup"].as_array().cloned().unwrap_or_default(),
            exit_code: u8::try_from(case["exit_code"].as_i64().expect("exit_code"))
                .expect("an exit status fits in a byte"),
            stdout: case["stdout"].as_str().expect("stdout").to_owned(),
            stderr: case["stderr"].as_str().expect("stderr").to_owned(),
            output_path: case["output_path"].as_str().map(str::to_owned),
            output_text: case["output_text"].as_str().map(str::to_owned),
        })
        .collect();
    (version, cases)
}

/// A7's snapshot copied into a home, with both XDG trees under it.
///
/// Under it rather than beside it, because the apple-container root is
/// `~/.config/agentcage/apple-container` with no XDG lookup anywhere
/// near it. A sandbox built out of `XDG_CONFIG_HOME` alone would leave
/// `cage har mac-agent` reading the developer's real home, and the case
/// that proves the two roots differ would prove nothing.
fn build_home(dir: &TestDir) -> PathBuf {
    let home = dir.join("home");
    let root = state_fixture_root();
    copy_tree(&root.join("xdg-config"), &home.join(".config"));
    copy_tree(&root.join("xdg-data"), &home.join(".local/share"));
    home
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create");
    for entry in fs::read_dir(from).expect("read fixture dir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

/// The generator's `write` / `append` / `remove` / `copy` vocabulary.
fn apply_setup(home: &Path, setup: &[Value]) {
    for op in setup {
        let target = home.join(op["path"].as_str().expect("op path"));
        match op["op"].as_str().expect("op") {
            "remove" => fs::remove_file(&target).expect("remove"),
            "write" => {
                fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
                fs::write(&target, op["text"].as_str().expect("text")).expect("write");
            }
            "append" => {
                let mut text = fs::read_to_string(&target).expect("read");
                text.push_str(op["text"].as_str().expect("text"));
                fs::write(&target, text).expect("write");
            }
            "copy" => {
                fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
                let source = repo_root().join(op["from"].as_str().expect("from"));
                fs::copy(&source, &target).expect("copy");
            }
            other => panic!("unknown setup op {other}"),
        }
    }
}

/// Turn the recorded argv back into the struct the parser would build.
///
/// Not a second argument parser: the clap tree's own conformance is
/// `src/cli/conformance.rs`'s job, and `cli::cage::query::har_args` is
/// what maps matches onto these fields. This only has to read the
/// spellings the fixture actually uses, and it panics on anything else
/// so a new case cannot be silently misread as its defaults.
fn parse(argv: &[String], home: &Path) -> HarArgs {
    assert_eq!(
        &argv[..2],
        &["cage".to_owned(), "har".to_owned()],
        "every case is a `cage har`"
    );
    let mut parsed = HarArgs {
        name: String::new(),
        view: "inbound".to_owned(),
        decisions: Vec::new(),
        hosts: Vec::new(),
        methods: Vec::new(),
        directions: Vec::new(),
        since: None,
        max_entries: 0,
        output_file: None,
        json_lines: false,
    };
    let expand = |value: &str| value.replace("{HOME}", &home.to_string_lossy());

    let mut rest = argv[2..].iter();
    let mut name = None;
    while let Some(token) = rest.next() {
        let mut value = || expand(rest.next().expect("the flag takes a value"));
        match token.as_str() {
            "--view" => parsed.view = value(),
            "-d" | "--decision" => parsed.decisions.push(value()),
            "--host" => parsed.hosts.push(value()),
            "--method" => parsed.methods.push(value()),
            "--direction" => parsed.directions.push(value()),
            "--since" => parsed.since = Some(value()),
            "-n" | "--max-entries" => parsed.max_entries = value().parse().expect("an integer"),
            "-o" | "--output" => parsed.output_file = Some(PathBuf::from(value())),
            // `json_lines = json_lines or json_compat`, which
            // `har_args` resolves for the real parser.
            "--json-lines" | "--json" => parsed.json_lines = true,
            other => {
                assert!(!other.starts_with('-'), "unhandled flag {other}");
                assert!(name.replace(other.to_owned()).is_none(), "two names");
            }
        }
    }
    parsed.name = name.expect("every case names a cage");
    parsed
}

/// Undo the generator's two substitutions.
fn expand(recorded: &str, home: &Path, version: &str) -> String {
    recorded
        .replace("{HOME}", &home.to_string_lossy())
        .replace("{VERSION}", version)
}

/// Every recorded run, replayed.
#[test]
fn every_recorded_run_is_reproduced_byte_for_byte() {
    let (version, cases) = fixture();
    assert_eq!(
        version,
        agentcage_core::VERSION,
        "the fixture was recorded against a different agentcage; rerun \
         scripts/gen-cage-har-fixture.py"
    );
    assert!(cases.len() >= 20, "the fixture lost cases: {}", cases.len());

    for case in &cases {
        let dir = TestDir::new(&format!("cage-har-{}", case.name));
        let home = build_home(&dir);
        apply_setup(&home, &case.setup);

        let paths = Paths::under(&home);
        // `cage har` shells out for exactly one thing — resolving a
        // Mac's default isolation backend — and no case reaches it, so
        // a runner that would panic on an unstubbed call is the right
        // one to hand it.
        let runner = FakeRunner::new();
        let args = parse(&case.argv, &home);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = har::run(&paths, &runner, &args, &mut stdout, &mut stderr);

        let label = &case.name;
        assert_eq!(
            String::from_utf8(stdout).expect("utf-8"),
            expand(&case.stdout, &home, &version),
            "{label}: stdout"
        );
        assert_eq!(
            String::from_utf8(stderr).expect("utf-8"),
            expand(&case.stderr, &home, &version),
            "{label}: stderr"
        );
        assert_eq!(code, case.exit_code, "{label}: exit status");

        if let (Some(path), Some(text)) = (&case.output_path, &case.output_text) {
            let written = fs::read_to_string(home.join(path))
                .unwrap_or_else(|e| panic!("{label}: the -o file was not written: {e}"));
            assert_eq!(written, expand(text, &home, &version), "{label}: -o file");
        }
    }
}

/// The two cages disagree about which root holds their capture, and the
/// fixture has to keep covering both.
///
/// A regeneration that dropped the apple-container cases would still
/// pass the replay above — there would simply be nothing left asserting
/// that `~/.config/agentcage/apple-container/<name>/logs/` is ever
/// consulted. This is the guard against that, and it is spelled as an
/// assertion about coverage rather than about behaviour.
#[test]
fn both_state_roots_are_covered() {
    let (_, cases) = fixture();
    let names: BTreeSet<&str> = cases.iter().map(|case| case.name.as_str()).collect();
    for required in [
        // the data root, and the apple root
        "inbound-default",
        "apple-container-root",
        // the path each one names when the file is absent
        "capture-disabled",
        "apple-container-root-missing",
        // the reader's two hard cases
        "rotated-generation-first",
        "truncated-tail-dropped",
        // the two exit statuses that are not 1
        "legacy-v021-cage",
        "no-metadata-reads-as-legacy",
    ] {
        assert!(names.contains(required), "the fixture lost `{required}`");
    }
}

/// The error for an absent capture names the root the *backend* uses.
///
/// This is the one decision `cage har` makes that nothing else in the
/// output reveals, so it is asserted directly as well as through the
/// recording: a port that read the data root for every cage would
/// produce byte-identical output for `acme-agent` and differ only here.
#[test]
fn the_apple_backend_reads_the_apple_root() {
    let (_, cases) = fixture();
    let case = cases
        .iter()
        .find(|case| case.name == "apple-container-root-missing")
        .expect("the case is in the fixture");
    assert!(
        case.stderr
            .contains("{HOME}/.config/agentcage/apple-container/mac-agent/logs/capture.jsonl"),
        "{}",
        case.stderr
    );
    let ordinary = cases
        .iter()
        .find(|case| case.name == "capture-disabled")
        .expect("the case is in the fixture");
    assert!(
        ordinary
            .stderr
            .contains("{HOME}/.local/share/agentcage/plain-cage/capture/capture.jsonl"),
        "{}",
        ordinary.stderr
    );
}

/// Reading a capture must not create anything.
///
/// `state.capture_dir` calls `mkdir(parents=True, exist_ok=True)` before
/// returning, so the Python leaves an empty
/// `$XDG_DATA_HOME/agentcage/<name>/capture/` behind even when it goes
/// on to report that there is no capture file. That is a side effect of
/// asking where a file is, and it is not reproduced — this asserts the
/// absence rather than leaving it to a comment.
#[test]
fn a_missing_capture_creates_no_directory() {
    let dir = TestDir::new("cage-har-no-mkdir");
    let home = build_home(&dir);
    let paths = Paths::under(&home);
    let runner = FakeRunner::new();

    let args = HarArgs {
        name: "plain-cage".to_owned(),
        view: "inbound".to_owned(),
        decisions: Vec::new(),
        hosts: Vec::new(),
        methods: Vec::new(),
        directions: Vec::new(),
        since: None,
        max_entries: 0,
        output_file: None,
        json_lines: false,
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        har::run(&paths, &runner, &args, &mut stdout, &mut stderr),
        1
    );
    assert!(
        !paths.capture_dir("plain-cage").exists(),
        "reporting a missing capture created {}",
        paths.capture_dir("plain-cage").display()
    );
}

/// An unreadable capture file is a message, not a traceback.
///
/// The Python has no `try` around `open(_src)`: a `PermissionError` there
/// escapes `cage_har` and click prints a stack trace naming this
/// repository's files. That cannot be recorded as a contract, so it is
/// asserted here instead — the exit status is the same 1 the Python's
/// crash produces, and what changes is that the line is readable.
#[test]
#[cfg_attr(
    target_os = "linux",
    allow(unused_mut, reason = "the guard below may skip")
)]
fn an_unreadable_capture_file_reports_cleanly() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TestDir::new("cage-har-unreadable");
    let home = build_home(&dir);
    let paths = Paths::under(&home);
    let capture = paths.capture_file("acme-agent");
    fs::set_permissions(&capture, fs::Permissions::from_mode(0o000)).expect("chmod");

    // root ignores the mode bits, so this can only be checked as a
    // non-root user. CI runs as one; a container shell may not.
    if fs::read_to_string(&capture).is_ok() {
        return;
    }

    let args = HarArgs {
        name: "acme-agent".to_owned(),
        view: "inbound".to_owned(),
        decisions: Vec::new(),
        hosts: Vec::new(),
        methods: Vec::new(),
        directions: Vec::new(),
        since: None,
        max_entries: 0,
        output_file: None,
        json_lines: false,
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = har::run(&paths, &FakeRunner::new(), &args, &mut stdout, &mut stderr);
    let stderr = String::from_utf8(stderr).expect("utf-8");

    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.starts_with("error: cannot read "), "{stderr}");
    assert!(stderr.contains("capture.jsonl"), "{stderr}");
    assert!(stdout.is_empty(), "nothing partial reached stdout");

    // Leave the copy removable.
    fs::set_permissions(&capture, fs::Permissions::from_mode(0o644)).expect("chmod");
}

/// An `-o` path that cannot be written is a message too, for the same
/// reason: the Python's `open(output_file, "w")` is unguarded.
#[test]
fn an_unwritable_output_path_reports_cleanly() {
    let dir = TestDir::new("cage-har-unwritable");
    let home = build_home(&dir);
    let paths = Paths::under(&home);

    let args = HarArgs {
        name: "acme-agent".to_owned(),
        view: "inbound".to_owned(),
        decisions: Vec::new(),
        hosts: Vec::new(),
        methods: Vec::new(),
        directions: Vec::new(),
        since: None,
        max_entries: 0,
        output_file: Some(home.join("no/such/directory/export.har")),
        json_lines: false,
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = har::run(&paths, &FakeRunner::new(), &args, &mut stdout, &mut stderr);
    let stderr = String::from_utf8(stderr).expect("utf-8");

    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.starts_with("error: cannot write "), "{stderr}");
    assert!(stdout.is_empty(), "the export did not fall back to stdout");
}
