//! `tests/fixtures/apple-container/argv.json`, replayed.
//!
//! The fixture is 38 calls into the real
//! `AppleContainerBackend.exec_argv` / `logs_argv` / `audit_argv`,
//! recorded by `scripts/gen-apple-argv-fixture.py` with
//! `platform.system()` patched to `"Darwin"`, `container_binary()`
//! pinned and `current_placeholders` declared per case. This replays
//! every one against [`agentcage_core::apple`] and compares the argv
//! element by element, including the two refusal messages.
//!
//! # Why it lives in this crate and not in `agentcage-core`
//!
//! Because of `audit_argv`. The argv builder itself is pure and sits in
//! `agentcage-core`, but the *path* it tails is
//! [`Paths::apple_audit_file`] — and the interesting property of that
//! path is that the apple state root expands `~` directly, ignoring
//! `XDG_CONFIG_HOME`. The generator sets `XDG_CONFIG_HOME` somewhere
//! else entirely and records the result under `{{HOME}}/.config`
//! anyway; this test derives the path through `Paths` rather than
//! pasting the recorded string back in, so the two halves are checked
//! against each other. `agentcage-core` cannot see `agentcage-state`,
//! so the test that needs both goes in the crate that depends on both.
//!
//! That path is the only host-side `audit.jsonl` in agentcage: on
//! `container` and `vm` cages the addon writes to stderr and the host
//! reads the journal (PR D8). Nothing else in the port exercises a
//! file-reading audit source.

use std::path::Path;

use agentcage_core::apple::{AppleArgvError, audit_argv, exec_argv, logs_argv};
use agentcage_state::Paths;
use serde_json::Value;

/// The home the generator pinned, as its scrubber wrote it.
const SCRUBBED_HOME: &str = "{{HOME}}";

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/apple-container/argv.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    serde_json::from_str(&text).expect("fixture JSON")
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("an array of strings")
        .iter()
        .map(|item| item.as_str().expect("a string").to_owned())
        .collect()
}

/// What the case expects: an argv, or a refusal message.
fn expectation(case: &Value) -> Result<Vec<String>, String> {
    match (case.get("argv"), case.get("error")) {
        (Some(argv), None) => Ok(strings(argv)),
        (None, Some(error)) => Err(error.as_str().expect("a message").to_owned()),
        _ => panic!("a case records exactly one of argv / error"),
    }
}

/// The Python renders a `BackendUnsupported` as
/// `"<ExceptionType>: <message>"`; the Rust error's `Display` is the
/// message alone, because it is not an exception and `agentcage-core`
/// prints nothing.
fn as_python(error: &AppleArgvError) -> String {
    format!("BackendUnsupported: {error}")
}

fn binary(case: &Value) -> Option<&str> {
    case["binary"].as_str()
}

fn cases<'a>(fixture: &'a Value, group: &str) -> &'a Vec<Value> {
    fixture[group].as_array().expect("a case array")
}

fn id(case: &Value) -> &str {
    case["id"].as_str().expect("an id")
}

#[test]
fn every_recorded_exec_argv_is_reproduced() {
    let fixture = fixture();
    let recorded = cases(&fixture, "exec_argv");
    for case in recorded {
        let placeholders: Vec<(String, String)> = case["placeholders"]
            .as_array()
            .expect("a placeholder array")
            .iter()
            .map(|pair| {
                let pair = strings(pair);
                (pair[0].clone(), pair[1].clone())
            })
            .collect();
        let produced = exec_argv(
            binary(case),
            case["name"].as_str().expect("a name"),
            case["service"].as_str().expect("a service"),
            &strings(&case["command"]),
            case["interactive"].as_bool().expect("interactive"),
            case["as_root"].as_bool().expect("as_root"),
            &placeholders,
        )
        .map_err(|error| as_python(&error));
        assert_eq!(
            produced,
            expectation(case),
            "exec_argv case {}: {}",
            id(case),
            case["why"].as_str().unwrap_or_default()
        );
    }
    assert_eq!(recorded.len(), 21, "the exec_argv matrix moved");
}

#[test]
fn every_recorded_logs_argv_is_reproduced() {
    let fixture = fixture();
    let recorded = cases(&fixture, "logs_argv");
    for case in recorded {
        // `lines` and `min_level` are recorded but have no parameter:
        // Apple's `container logs` accepts neither, and the Python
        // takes them only for protocol parity. Asserting that the
        // recorded argv ignores them is the whole point of those cases.
        let produced = logs_argv(
            binary(case),
            case["name"].as_str().expect("a name"),
            &strings(&case["services"]),
            case["follow"].as_bool().expect("follow"),
        )
        .map_err(|error| as_python(&error));
        assert_eq!(
            produced,
            expectation(case),
            "logs_argv case {}: {}",
            id(case),
            case["why"].as_str().unwrap_or_default()
        );
    }
    assert_eq!(recorded.len(), 12, "the logs_argv matrix moved");
}

#[test]
fn every_recorded_audit_argv_is_reproduced() {
    let fixture = fixture();
    let recorded = cases(&fixture, "audit_argv");
    // `Paths::under` puts every root under one directory, home
    // included, which is exactly the shape the generator's sandbox had.
    // Passing the scrubbed token as the home makes the derived path
    // come out in the same scrubbed space as the recording.
    let paths = Paths::under(Path::new(SCRUBBED_HOME));
    for case in recorded {
        let name = case["name"].as_str().expect("a name");
        let derived = paths.apple_audit_file(name);
        let derived = derived.to_str().expect("a UTF-8 path");
        assert_eq!(
            derived,
            case["audit_path"].as_str().expect("a recorded path"),
            "audit path for {name} — the apple state root ignores XDG_CONFIG_HOME"
        );
        let produced = audit_argv(derived, case["follow"].as_bool().expect("follow"));
        assert_eq!(
            Ok(produced),
            expectation(case),
            "audit_argv case {}: {}",
            id(case),
            case["why"].as_str().unwrap_or_default()
        );
    }
    assert_eq!(recorded.len(), 5, "the audit_argv matrix moved");
}

/// The property PR D12 proved for the container backend, restated for
/// this one: `cage exec demo -- ls -la` and `cage exec demo ls -la`
/// parse to the same `command`, so they must produce the same argv —
/// and neither carries a separator of agentcage's own.
#[test]
fn the_two_spellings_of_cage_exec_agree() {
    let fixture = fixture();
    let recorded = cases(&fixture, "exec_argv");
    let find = |wanted: &str| {
        expectation(
            recorded
                .iter()
                .find(|case| id(case) == wanted)
                .unwrap_or_else(|| panic!("case {wanted}")),
        )
        .expect("an argv")
    };
    let with = find("command-separator-form");
    let without = find("command-no-separator-form");
    assert_eq!(with, without);
    assert!(
        !with.iter().any(|part| part == "--"),
        "a bare separator reached the argv: {with:?}"
    );
    // A `--` the operator meant as an argument still does.
    let inner = find("command-inner-separator");
    assert!(inner.iter().any(|part| part == "--"), "{inner:?}");
}
