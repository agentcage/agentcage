//! The shape every file in `tests/fixtures/contracts/` must keep.
//!
//! The per-contract tests assert behaviour; this pins what makes the files
//! usable as an oracle at all: each names its contract and both
//! implementations, has cases, gives every case a unique `id` (the anchor
//! a diff is read against) and a `why`, and stays ASCII-escaped JSON so
//! the cases carrying zero-width and non-breaking characters survive an
//! editor, a terminal or a diff viewer intact.

mod common;

use common::repo_root;

fn contract_files() -> Vec<std::path::PathBuf> {
    let dir = repo_root().join("tests/fixtures/contracts");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no contract fixtures found");
    files
}

#[test]
fn every_contract_fixture_is_well_formed() {
    for path in contract_files() {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("a UTF-8 name");
        let raw = std::fs::read(&path).expect("readable");
        assert!(
            raw.is_ascii(),
            "{name}: fixtures must be ASCII-escaped JSON"
        );
        assert!(raw.ends_with(b"\n"), "{name}: missing trailing newline");

        let doc: serde_json::Value = serde_json::from_slice(&raw).expect("valid JSON");
        assert_eq!(
            doc["contract"].as_str(),
            Some(name),
            "{name}: contract name"
        );
        assert!(
            doc["summary"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty()),
            "{name}: summary"
        );
        let mut sides: Vec<&String> = doc["implementations"]
            .as_object()
            .unwrap_or_else(|| panic!("{name}: implementations"))
            .keys()
            .collect();
        sides.sort();
        assert_eq!(sides, ["host", "proxy"], "{name}: implementations");

        let cases = doc["cases"].as_array().expect("cases");
        assert!(
            !cases.is_empty(),
            "{name}: an empty contract fixture asserts nothing"
        );
        let mut ids = std::collections::BTreeSet::new();
        for case in cases {
            let id = case["id"]
                .as_str()
                .unwrap_or_else(|| panic!("{name}: a case without id"));
            assert!(ids.insert(id), "{name}: duplicate case id {id}");
            assert!(
                case["why"].as_str().is_some_and(|w| !w.trim().is_empty()),
                "{name}/{id} has no rationale"
            );
        }
    }
}
