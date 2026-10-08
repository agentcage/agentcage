//! The two domain contracts, against PR A4's language-neutral fixtures.
//!
//! `valid_domain` and `encoded_private_ip` exist on both sides of
//! agentcage's trust boundary (RUST-PORT-PLAN.md §2.2), and until this
//! port they were held equal by a pytest that imported both copies. That
//! mechanism does not survive the language split, so
//! `tests/fixtures/contracts/` records the answers instead:
//!
//! > Before: `host == proxy`. After: `host == fixture` **and**
//! > `proxy == fixture`.
//!
//! Two things follow, and both shape this file:
//!
//! 1. **Neither implementation is the oracle.** If a change makes this
//!    file fail, the question is whether the *contract* changed — not
//!    which side to bend. Regenerating the fixture on autopilot defeats
//!    the point of having it.
//! 2. **The cases are read off disk, never restated here.** A copy in
//!    Rust source would be a third implementation of the corpus, free to
//!    drift from the file `tests/test_contract_fixtures.py` asserts the
//!    Python side against. Every case, every id and every `why` comes
//!    from the JSON.

mod common;

use std::path::PathBuf;

use agentcage_core::config::{LabelPolicy, encoded_private_ip, valid_domain};
use serde::Deserialize;

use common::repo_root;

/// `tests/fixtures/contracts/<name>.json`.
fn contract(name: &str) -> PathBuf {
    repo_root()
        .join("tests/fixtures/contracts")
        .join(format!("{name}.json"))
}

fn read<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = contract(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "reading {}: {error}. Generate it with \
             `uv run python scripts/gen-contract-fixtures.py`",
            path.display()
        )
    });
    serde_json::from_str(&text).expect("contract JSON")
}

#[derive(Debug, Deserialize)]
struct Fixture<C> {
    contract: String,
    cases: Vec<C>,
}

#[derive(Debug, Deserialize)]
struct DomainCase {
    /// The anchor a diff is read against.
    id: String,
    /// Why this input is in the corpus.
    why: String,
    input: String,
    /// Strict mode — the shape *both* sides implement.
    expected: bool,
    /// Host-only: `valid_domain(d, allow_single_label=True)`. The proxy
    /// has no counterpart and must not be checked against it.
    expected_allow_single_label: bool,
}

#[derive(Debug, Deserialize)]
struct EncodedCase {
    id: String,
    why: String,
    input: String,
    /// The decoded dotted quad, or `null`.
    expected: Option<String>,
}

/// Every `valid_domain` case, in both modes.
#[test]
fn valid_domain_matches_the_contract_fixture() {
    let fixture: Fixture<DomainCase> = read("valid_domain");
    assert_eq!(fixture.contract, "valid_domain");

    let mut wrong: Vec<String> = Vec::new();
    for case in &fixture.cases {
        for (policy, expected, column) in [
            (LabelPolicy::StrictDotted, case.expected, "expected"),
            (
                LabelPolicy::AllowSingleLabel,
                case.expected_allow_single_label,
                "expected_allow_single_label",
            ),
        ] {
            let produced = valid_domain(&case.input, policy);
            if produced != expected {
                wrong.push(format!(
                    "  {} [{column}] input={:?}\n      python: {expected}\n      rust:   \
                     {produced}\n      why:    {}",
                    case.id, case.input, case.why
                ));
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} valid_domain cases disagree with the contract fixture. Neither \
         implementation is the oracle -- decide whether the CONTRACT changed before \
         touching either side:\n{}",
        wrong.len(),
        fixture.cases.len(),
        wrong.join("\n")
    );
    assert_eq!(
        fixture.cases.len(),
        96,
        "the fixture grew or shrank; if that is intended, update this number"
    );
}

/// Every `encoded_private_ip` case.
#[test]
fn encoded_private_ip_matches_the_contract_fixture() {
    let fixture: Fixture<EncodedCase> = read("encoded_private_ip");
    assert_eq!(fixture.contract, "encoded_private_ip");

    let mut wrong: Vec<String> = Vec::new();
    for case in &fixture.cases {
        let produced = encoded_private_ip(&case.input);
        if produced.as_deref() != case.expected.as_deref() {
            wrong.push(format!(
                "  {} input={:?}\n      python: {:?}\n      rust:   {produced:?}\n      why:    {}",
                case.id, case.input, case.expected, case.why
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} encoded_private_ip cases disagree with the contract fixture. This is \
         the structural half of the SSRF guard -- a disagreement here is a hole, not a \
         style difference:\n{}",
        wrong.len(),
        fixture.cases.len(),
        wrong.join("\n")
    );
    assert_eq!(
        fixture.cases.len(),
        77,
        "the fixture grew or shrank; if that is intended, update this number"
    );
}

/// The `is_private()` substitution must fail, not merely be discouraged.
///
/// PR A4's report names this as the finding a Rust port has to honour:
/// `is_global` and `is_private` are different predicates, and
/// `100.64.0.0/10` is the proof — carrier-grade NAT is `is_global ==
/// False` and `is_private == False` at the same time, so a port reaching
/// for a crate's `is_private()` would let it straight through the guard.
///
/// This asserts the fixture still *carries* the cases that would catch
/// it. `encoded_private_ip_matches_the_contract_fixture` above is what
/// actually runs them; this fails if a future regeneration ever drops
/// them, which would quietly re-open the substitution.
#[test]
fn the_fixture_still_carries_the_cases_that_catch_a_crate_is_private() {
    let fixture: Fixture<EncodedCase> = read("encoded_private_ip");
    for (id, input, expected) in [
        ("cgnat-low", "100-64-0-0.nip.io", Some("100.64.0.0")),
        (
            "cgnat-high",
            "100-127-255-255.nip.io",
            Some("100.127.255.255"),
        ),
        ("cgnat-below", "100-63-255-255.nip.io", None),
        ("cgnat-above", "100-128-0-0.nip.io", None),
    ] {
        let case = fixture
            .cases
            .iter()
            .find(|case| case.id == id)
            .unwrap_or_else(|| panic!("the fixture no longer carries the {id} case"));
        assert_eq!(case.input, input);
        assert_eq!(case.expected.as_deref(), expected);
        // And the implementation still answers it that way, stated here
        // too so this test fails on its own terms rather than only
        // through its neighbour.
        assert_eq!(encoded_private_ip(&case.input).as_deref(), expected);
    }
}
