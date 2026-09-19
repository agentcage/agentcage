//! Shared plumbing for the three YAML test binaries.
//!
//! Integration tests are separate crates, so this is `mod common;` in
//! each of them rather than a library. Not every binary uses every
//! helper; `dead_code` is allowed for that reason alone.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// One row of `tests/fixtures/yaml_1_1_scalars.json`.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct Case {
    /// Stable anchor a diff is read against.
    pub(crate) id: String,
    /// The exact scalar text.
    pub(crate) scalar: String,
    /// What this case is for.
    pub(crate) why: String,
    /// The YAML tag PyYAML resolves `scalar` to when it is written
    /// plain, with the `tag:yaml.org,2002:` prefix stripped. Anything
    /// but `str` means the emitter has to quote it.
    pub(crate) plain_tag: String,
}

/// One document from the reading half of the corpus.
///
/// Carries no recorded expectation on purpose: the crossing test loads
/// each one with `yaml.safe_load` and with `yaml::load` and requires
/// the two to agree, so nothing here is a human's guess.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ReadCase {
    /// Stable anchor a diff is read against.
    pub(crate) id: String,
    /// The document text.
    pub(crate) yaml: String,
    /// What this case is for.
    pub(crate) why: String,
}

/// The committed ambiguity corpus.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct Fixture {
    /// Every emit-side case, in file order.
    pub(crate) cases: Vec<Case>,
    /// Every read-side document, in file order.
    pub(crate) read_side_cases: Vec<ReadCase>,
}

/// Repo root, from this crate's manifest directory.
pub(crate) fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// Read and parse `tests/fixtures/yaml_1_1_scalars.json`.
pub(crate) fn fixture() -> Fixture {
    let path = fixture_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    serde_json::from_str(&text).expect("fixture JSON")
}

/// Where the corpus lives.
pub(crate) fn fixture_path() -> PathBuf {
    repo_root().join("tests/fixtures/yaml_1_1_scalars.json")
}

/// Every `*.yaml` / `*.yml` under the config fixture trees.
///
/// The two directories RUST-PORT-PLAN.md Track B names:
/// `tests/configs/**` (the pytest corpus) and `tests/e2e/configs/**`
/// (the end-to-end corpus).
pub(crate) fn committed_configs() -> Vec<PathBuf> {
    let root = repo_root();
    let mut found = Vec::new();
    for directory in ["tests/configs", "tests/e2e/configs"] {
        collect(&root.join(directory), &mut found);
    }
    found.sort();
    assert!(
        !found.is_empty(),
        "no configs found; the fixture directories moved"
    );
    found
}

/// Recursive `*.yaml` walk.
fn collect(directory: &Path, found: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("reading {}: {error}", directory.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect(&path, found);
        } else if matches!(
            path.extension().and_then(std::ffi::OsStr::to_str),
            Some("yaml" | "yml")
        ) {
            found.push(path);
        }
    }
}
