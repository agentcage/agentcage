//! The A4 cross-language contract fixtures, against the Rust side.
//!
//! `tests/fixtures/contracts/` is the oracle for every piece of logic
//! agentcage implements on *both* sides of its trust boundary
//! (RUST-PORT-PLAN.md §2.2). Before the port the contract was
//! `host == proxy`; after it, `host == fixture` **and**
//! `proxy == fixture`, because the first form cannot be written across
//! a language boundary and also passes when both sides drift together.
//!
//! pytest (`tests/test_contract_fixtures.py`) holds the Python to these
//! files. This binary holds the Rust to them. Neither implementation is
//! the oracle: if the two ever disagree, the fixture says which one
//! moved.
//!
//! Three of the six fixtures land in PR C3's scope:
//!
//! | File | Rust side |
//! | :-- | :-- |
//! | `validate_relay_entry.json` | [`agentcage_core::relays`] — 114 cases |
//! | `shared_constants.json` | the constants both sides duplicate |
//! | `scaffold_inspectors.json` | the host half of the inspector handshake |
//!
//! The other three (`valid_domain`, `encoded_private_ip`,
//! `is_never_grant`) are PR C2's.
//!
//! Every expectation is read off disk rather than transcribed, so this
//! file and the fixture cannot drift: a case added by
//! `scripts/gen-contract-fixtures.py` is asserted here the moment it
//! lands.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use agentcage_core::config::{BUILTIN_INSPECTOR_NAMES, MAX_CAPTURE_FILE_BYTES};
use agentcage_core::relays::{KNOWN_RELAY_TYPES, WRITE_MODES, validate_relay_entry};
use agentcage_core::yaml::Value;

use common::repo_root;

/// `tests/fixtures/contracts/<name>.json`, parsed.
fn contract(name: &str) -> serde_json::Value {
    let path: PathBuf = repo_root()
        .join("tests/fixtures/contracts")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    serde_json::from_str(&text).expect("contract fixture is JSON")
}

/// A fixture `entry` as the value tree the validator takes.
///
/// The fixture is JSON and the validator reads YAML, which is not the
/// mismatch it looks like: `yaml.safe_load` and `json.loads` produce
/// the same seven Python types, and the fixture README pins the
/// JSON→Python mapping the error messages depend on (`null` is
/// `NoneType`, a fractional number is `float`, and so on). `serde_json`
/// deserializing straight into `serde_norway::Value` reproduces that
/// mapping — an integer stays an integer and `993.7` stays a float, so
/// `int()` truncation and the `(got float)` wording both land where
/// the fixture says.
fn as_yaml(entry: &serde_json::Value) -> Value {
    serde_json::from_value(entry.clone()).expect("JSON value into the YAML value tree")
}

/// Every `validate_relay_entry` case, byte for byte.
///
/// This is PR C3's headline acceptance check. 114 cases reach every
/// `raise ValueError` branch in `_validate.py`; six `order-*` cases
/// pin *which* of two problems an entry with both is told about, which
/// is the part a second implementation gets wrong silently.
#[test]
fn every_validate_relay_entry_case_matches() {
    let fixture = contract("validate_relay_entry");
    let cases = fixture["cases"].as_array().expect("cases");
    let mut wrong: Vec<String> = Vec::new();
    let mut messages: BTreeSet<String> = BTreeSet::new();
    let mut ordering = 0;

    for case in cases {
        let id = case["id"].as_str().expect("id");
        let entry = as_yaml(&case["entry"]);
        let expected_ok = case["ok"].as_bool().expect("ok");
        let expected_error = case["error"].as_str();
        let expected_calls: Vec<&str> = case["source_validator_calls"]
            .as_array()
            .expect("source_validator_calls")
            .iter()
            .map(|call| call.as_str().expect("a call is a string"))
            .collect();

        if id.starts_with("order-") {
            ordering += 1;
        }
        if let Some(error) = expected_error {
            messages.insert(error.to_owned());
        }

        // The host passes `secret_resolver.validate_source` here. The
        // fixture's hook never raises -- the generator asserts that a
        // hook which accepts everything changes neither `ok` nor
        // `error` -- so what is under test is *which arguments it
        // receives, in order*. A validator that forgot `password_source`
        // would still pass every ok/error assertion.
        let mut seen: Vec<String> = Vec::new();
        let mut record = |source: &str| {
            seen.push(source.to_owned());
            Ok(())
        };

        match validate_relay_entry(&entry, Some(&mut record)) {
            Ok(()) if expected_ok => {}
            Ok(()) => wrong.push(format!(
                "  {id}: accepted it; python raised\n      python: {}",
                expected_error.unwrap_or("<missing>")
            )),
            Err(error) if expected_ok => {
                wrong.push(format!("  {id}: refused it -- {}", error.message()));
            }
            Err(error) => {
                let produced = error.message();
                if Some(produced) != expected_error {
                    wrong.push(format!(
                        "  {id}\n      python: {}\n      rust:   {produced}",
                        expected_error.unwrap_or("<missing>")
                    ));
                }
            }
        }

        if seen != expected_calls {
            wrong.push(format!(
                "  {id}: source_validator saw {seen:?}, fixture records {expected_calls:?}"
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} validate_relay_entry cases disagree with the fixture. The fixture is \
         the oracle: a disagreement means either this port or `_validate.py` moved, and \
         the diff says which:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n")
    );
    assert_eq!(
        cases.len(),
        114,
        "the fixture grew or shrank; if that is intended, update this number and read \
         the new cases"
    );
    assert_eq!(
        messages.len(),
        52,
        "the number of DISTINCT error messages changed -- a branch was added, removed \
         or reworded"
    );
    assert_eq!(
        ordering, 6,
        "the check-order cases are the contract's sharpest half"
    );
    println!(
        "{} validate_relay_entry cases matched, {} distinct messages, {ordering} order cases",
        cases.len(),
        messages.len()
    );
}

/// The constants both sides of the boundary duplicate.
///
/// Three of the five are C3's: the `CaptureWriter` size-cap default,
/// the built-in inspector names, and the two relay sets. The other two
/// belong to C2's half of the roster and are checked here anyway when
/// this crate already carries them — a constant is cheap to assert and
/// the fixture is the only thing holding the addon's literals and
/// these in step.
#[test]
fn the_duplicated_constants_match() {
    let fixture = contract("shared_constants");
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for case in fixture["cases"].as_array().expect("cases") {
        let id = case["id"].as_str().expect("id");
        let value = &case["value"];
        seen.insert(id.to_owned());
        match id {
            // `capture.CaptureWriter` falls back to a literal of its
            // own when `max_file_size` is unset, so an operator who
            // never writes the key still gets a bound -- and it has to
            // be the same bound the host documents and validates
            // against. PR A6 found this one; §2.2's original list
            // missed it.
            "max_capture_file_bytes" => {
                assert_eq!(value.as_i64(), Some(MAX_CAPTURE_FILE_BYTES), "{id}");
            }
            // `config._BUILTIN_INSPECTOR_NAMES` mirrors
            // `addon._BUILTIN_INSPECTORS`. A name on one side and not
            // the other is a config that validates and then silently
            // does nothing.
            "builtin_inspector_names" => {
                let mut ours: Vec<&str> = BUILTIN_INSPECTOR_NAMES.to_vec();
                ours.sort_unstable();
                assert_eq!(strings(value), ours, "{id}");
            }
            "known_relay_types" => assert_eq!(strings(value), KNOWN_RELAY_TYPES.to_vec(), "{id}"),
            "relay_write_modes" => assert_eq!(strings(value), WRITE_MODES.to_vec(), "{id}"),
            "auto_never_grant" => {
                assert_eq!(
                    strings(value),
                    agentcage_core::config::AUTO_NEVER_GRANT.to_vec(),
                    "{id}"
                );
            }
            other => panic!(
                "shared_constants grew a case this test does not know about: {other}. \
                 Adding a constant to the fixture without asserting it here is how a \
                 duplicated value drifts."
            ),
        }
    }

    assert_eq!(seen.len(), 5, "shared_constants case count changed");
}

/// The host half of the `render_config` → addon handshake.
///
/// `scaffold_inspectors.json` is the one contract split down the
/// middle: the artifact crossing the boundary is a *file*, so the host
/// proves it renders the recorded config and the proxy proves that
/// config loads the recorded inspector chain, in order. pytest keeps
/// the second half.
///
/// The first half is `init.render_config`, which is a later PR. What
/// C3 owns is the consequence: every name those nine scaffolds render
/// must be one this crate calls built-in, or `validate_config` would
/// warn on a config agentcage itself wrote. That is the assertion here
/// — it fails the day a scaffold gains an inspector the validator does
/// not know, which is exactly the drift the fixture exists to catch.
#[test]
fn every_scaffold_renders_inspectors_the_validator_knows() {
    let fixture = contract("scaffold_inspectors");
    let cases = fixture["cases"].as_array().expect("cases");
    let mut unknown: Vec<String> = Vec::new();

    for case in cases {
        let scaffold = case["scaffold"].as_str().unwrap_or("<default>");
        let Some(entries) = case["inspector_config"]["inspectors"].as_array() else {
            // The blank default renders no `inspectors:` key at all.
            continue;
        };
        for (index, entry) in entries.iter().enumerate() {
            let name = entry["name"].as_str().unwrap_or_default();
            if !name.is_empty() && !BUILTIN_INSPECTOR_NAMES.contains(&name) {
                unknown.push(format!("  {scaffold}: inspectors[{index}] {name:?}"));
            }
            assert!(
                entry.get("path").is_none(),
                "{scaffold}: a built-in scaffold rendered a custom `path:` inspector, \
                 which the apple-container backend cannot stage"
            );
        }
    }

    assert!(
        unknown.is_empty(),
        "a scaffold renders an inspector name BUILTIN_INSPECTOR_NAMES does not carry, so \
         `agentcage init` produces a config `validate_config` warns about:\n{}",
        unknown.join("\n")
    );
    assert_eq!(cases.len(), 9, "the scaffold roster changed");
    println!("{} scaffolds render only known inspectors", cases.len());
}

/// A JSON array of strings.
fn strings(value: &serde_json::Value) -> Vec<&str> {
    value
        .as_array()
        .expect("an array")
        .iter()
        .map(|item| item.as_str().expect("a string"))
        .collect()
}
