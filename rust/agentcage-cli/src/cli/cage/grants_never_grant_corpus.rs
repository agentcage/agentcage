//! `tests/fixtures/contracts/is_never_grant.json`, against the host's copy.
//!
//! The never-grant floor exists on both sides of the trust boundary: the
//! egress refuses such a grant, and this copy stops `grants reconcile`
//! promoting one into the operator's baseline from an overlay that was
//! hand-edited or written by an older egress. The fixture's cases carry
//! the effective set explicitly, so they exercise exactly the predicate
//! the reconcile calls. A child module of `grants`, because the predicate
//! is private to it.

use std::collections::BTreeSet;
use std::path::PathBuf;

use super::is_never_grant;

fn cases() -> Vec<serde_json::Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate is nested at rust/<crate>")
        .join("tests/fixtures/contracts/is_never_grant.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&text).expect("contract JSON");
    let cases = doc["cases"].as_array().expect("cases").clone();
    assert!(
        !cases.is_empty(),
        "an empty contract fixture asserts nothing"
    );
    cases
}

fn never(case: &serde_json::Value) -> BTreeSet<String> {
    case["never_grant"]
        .as_array()
        .expect("never_grant")
        .iter()
        .map(|d| d.as_str().expect("a domain").to_owned())
        .collect()
}

#[test]
fn the_host_never_grant_predicate_matches_the_fixture() {
    let failures: Vec<String> = cases()
        .iter()
        .filter_map(|case| {
            let input = case["input"].as_str().expect("input");
            let want = case["expected"].as_bool().expect("expected");
            let got = is_never_grant(input, &never(case));
            (got != want).then(|| {
                format!(
                    "{}: is_never_grant({input:?}) = {got}, fixture says {want} ({})",
                    case["id"], case["why"]
                )
            })
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The corpus bites: label-boundary matching swapped for a plain string
/// suffix (the mistake the `near-*` cases exist for) is caught.
#[test]
fn a_string_suffix_predicate_is_caught() {
    let caught = cases().iter().any(|case| {
        let input = case["input"].as_str().expect("input").to_lowercase();
        let suffix_match = never(case).iter().any(|n| input.ends_with(n.as_str()));
        suffix_match != case["expected"].as_bool().expect("expected")
            && agentcage_core::config::encoded_private_ip(&input).is_none()
    });
    assert!(caught, "no case tells label matching from suffix matching");
}
