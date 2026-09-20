//! Reproduce every fingerprint the Python has committed to this repo.
//!
//! Two independent sources, because the thing being checked is the one
//! value in the port that has to survive a change of language on a
//! user's machine without anybody noticing:
//!
//! * **The golden corpus** (`tests/fixtures/golden/`, PR A3) — 125 cages
//!   worth of `fingerprint.json`, each with a `fingerprint-inputs.json`
//!   recipe naming the files that were hashed. Breadth: every isolation
//!   mode, every shape of `cage.yaml` the corpus covers.
//!
//! * **The state-compat fixtures** (`tests/fixtures/state-compat/`, PR
//!   A7) — one `fingerprint.json` written by agentcage 0.40.1 for a
//!   *deployed* cage, from a different generator with different inputs.
//!   Depth: this is the exact shape a real user's disk carries at
//!   cutover, and the one `cage update` has to call a no-op on first
//!   run (RUST-PORT-PLAN.md §2.7, F2's acceptance check).
//!
//! Both comparisons are byte-for-byte against the committed file, not
//! digest-against-digest: that also pins the document `cage update`
//! writes back out.
//!
//! # Why the recipes hash scrubbed text
//!
//! Rendered units and a stored `cage.yaml` both embed absolute host
//! paths, so hashing what either generator's sandbox actually wrote
//! would produce a digest belonging to whoever ran it. Both generators
//! scrub first and hash the scrubbed text, which is exactly the digest
//! an operator whose home really was `{{HOME}}` (or
//! `/home/agentcage-fixture`) would get. The committed bytes are
//! therefore the real inputs, and this test can rebuild the hash from
//! the directory alone. Everything else in the chain — `stable_json`,
//! the component layout, the sha256-of-sha256s — is exercised
//! unchanged.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use agentcage_core::fingerprint::{CageYaml, Components, Fingerprint, Inputs, compute_fingerprint};
use agentcage_core::har::json::{self, DumpOptions, Json};

/// How many `valid/` cases the corpus carries. Asserted rather than
/// inferred, so a case that silently stops being visited fails here
/// instead of quietly shrinking the coverage.
const GOLDEN_CASES: usize = 128;

/// Cases whose `resolved-config.json` is *not* the object the recorded
/// fingerprint was computed over.
///
/// `scripts/gen-golden-corpus.py` writes `resolved-config.json` from the
/// config as first loaded, then calls `state.fill_placeholders`, reloads
/// the config, and feeds *that* to `compute_fingerprint`. For a cage
/// with a generated `agentcage:secret:NAME:<hex>` placeholder the two
/// differ, so the committed file cannot rebuild that one component.
/// This is a gap in the corpus recipe, not a disagreement about the
/// fingerprint: the other four components and the layout are still
/// checked for these cases, and the input the recipe *does* name —
/// `stored-cage.yaml`, which is post-fill — reproduces exactly.
const PLACEHOLDER_FILLED: &[&str] = &[
    "misc-kitchen-sink",
    "secrets-placeholder-generated",
    "seed-e2e-secrets",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `_json_text` from both generators: `json.dumps(value, indent=2,
/// sort_keys=True, ensure_ascii=False)` plus a trailing newline.
fn corpus_text(value: &Json) -> String {
    json::dumps(
        value,
        DumpOptions {
            indent: Some(2),
            sort_keys: true,
            ensure_ascii: false,
            ..DumpOptions::default()
        },
    ) + "\n"
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

fn read_json(path: &Path) -> Json {
    json::parse(&read(path)).unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()))
}

/// A `{string: string}` object from a recipe, as a map.
fn string_map(value: Option<&Json>) -> BTreeMap<String, String> {
    match value {
        Some(Json::Object(pairs)) => pairs
            .iter()
            .map(|(key, item)| {
                (
                    key.clone(),
                    item.as_str()
                        .expect("recipe values are strings")
                        .to_string(),
                )
            })
            .collect(),
        other => panic!("expected an object in the recipe, found {other:?}"),
    }
}

/// Every file in a directory, by filename, or an empty map when the
/// directory is absent — which is `units or {}` in the Python.
fn files_in(directory: &Path) -> BTreeMap<String, String> {
    let Ok(entries) = fs::read_dir(directory) else {
        return BTreeMap::new();
    };
    let mut units = BTreeMap::new();
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        let name = path
            .file_name()
            .expect("a named file")
            .to_str()
            .expect("a UTF-8 filename")
            .to_string();
        // Every file here is a unit, including an apple-container
        // cage's `<cage>.json`: `cli.py::_update_fingerprint` feeds
        // `backend.generate_units` to `compute_fingerprint` whatever
        // the backend is. Before PR E3 the corpus wrote a
        // `NOT-APPLICABLE.txt` marker here instead and this function
        // special-cased it into an empty map — which recorded, for
        // those five cases, a fingerprint no real deploy could produce.
        units.insert(name, read(&path));
    }
    units
}

/// Build the fingerprint for one `valid/<case>` from its recipe.
fn corpus_fingerprint(case: &Path) -> Fingerprint {
    let recipe = read_json(&case.join("fingerprint-inputs.json"));
    let resolved_config = read_json(&case.join("resolved-config.json"));
    let units = files_in(&case.join("quadlets"));
    let image_digests = string_map(recipe.get("image_digests"));
    let scaffold_version = recipe
        .get("scaffold_version")
        .and_then(Json::as_str)
        .expect("the recipe names a scaffold version");
    let cage_yaml = read(&case.join("stored-cage.yaml"));

    compute_fingerprint(Inputs {
        cage_yaml: CageYaml::Text(&cage_yaml),
        resolved_config: &resolved_config,
        units: &units,
        image_digests: &image_digests,
        scaffold_version,
    })
    .unwrap_or_else(|error| panic!("{}: {error}", case.display()))
}

/// Every component but `resolved_config`, for the cases whose recipe
/// cannot rebuild that one.
fn without_resolved_config(components: &Components) -> [&str; 4] {
    [
        &components.cage_yaml,
        &components.units,
        &components.image_digests,
        &components.scaffold_version,
    ]
}

fn expected_components(document: &Json) -> Components {
    let components = document.get("components").expect("components");
    let field = |name: &str| {
        components
            .get(name)
            .and_then(Json::as_str)
            .unwrap_or_else(|| panic!("component {name}"))
            .to_string()
    };
    Components {
        cage_yaml: field("cage_yaml"),
        resolved_config: field("resolved_config"),
        units: field("units"),
        image_digests: field("image_digests"),
        scaffold_version: field("scaffold_version"),
    }
}

#[test]
fn every_golden_corpus_fingerprint_is_reproduced() {
    let root = repo_root().join("tests/fixtures/golden/valid");
    let mut cases: Vec<PathBuf> = fs::read_dir(&root)
        .expect("the golden corpus is committed beside the Rust workspace")
        .map(|entry| entry.expect("readable corpus entry").path())
        .collect();
    cases.sort();

    let mut exact = 0_usize;
    let mut partial = 0_usize;
    for case in &cases {
        let name = case.file_name().and_then(std::ffi::OsStr::to_str).unwrap();
        let expected_path = case.join("fingerprint.json");
        let expected_text = read(&expected_path);
        let produced = corpus_fingerprint(case);

        if PLACEHOLDER_FILLED.contains(&name) {
            let expected = expected_components(&read_json(&expected_path));
            assert_eq!(
                without_resolved_config(&produced.components),
                without_resolved_config(&expected),
                "{name}: components other than resolved_config differ",
            );
            partial += 1;
            continue;
        }

        assert_eq!(
            corpus_text(&produced.to_json()),
            expected_text,
            "{name}: fingerprint.json differs from the golden corpus",
        );
        exact += 1;
    }

    assert_eq!(
        exact + partial,
        GOLDEN_CASES,
        "the corpus changed size; update GOLDEN_CASES deliberately",
    );
    assert_eq!(
        partial,
        PLACEHOLDER_FILLED.len(),
        "unexpected partial cases"
    );
    assert_eq!(exact, 125, "expected 125 byte-exact corpus fingerprints");
}

/// The deployed-cage fingerprint, from a different generator.
///
/// `scripts/gen-state-fixtures.py` feeds `compute_fingerprint` the
/// scrubbed `cage.yaml`, the scrubbed `proxy-config.yaml` as the
/// resolved config, the scrubbed units, two hard-coded image digests and
/// a hard-coded scaffold version. All five are committed, so this
/// rebuilds the hash from the fixture tree alone.
///
/// Note the `resolved_config` input here is a *parsed YAML document*,
/// not the JSON dump of a config object the golden corpus uses — two
/// different shapes reaching the same serializer.
#[test]
fn the_deployed_cage_fingerprint_is_reproduced() {
    let root = repo_root().join("tests/fixtures/state-compat/0.40.1");
    let cage = root.join("xdg-config/agentcage/cages/acme-agent");

    let cage_yaml = read(&cage.join("cage.yaml"));
    let proxy_config = read(&cage.join("proxy-config.yaml"));
    let resolved_config = json_from_yaml_text(&proxy_config);
    let units = files_in(&root.join("xdg-config/containers/systemd"));
    assert_eq!(units.len(), 5, "the fixture ships five quadlets");

    let image_digests: BTreeMap<String, String> = [("cage", "11"), ("egress", "22")]
        .into_iter()
        .map(|(name, byte)| (name.to_string(), format!("sha256:{}", byte.repeat(32))))
        .collect();

    let produced = compute_fingerprint(Inputs {
        cage_yaml: CageYaml::Text(&cage_yaml),
        resolved_config: &resolved_config,
        units: &units,
        image_digests: &image_digests,
        scaffold_version: &"deadbeef".repeat(8),
    })
    .expect("computes");

    assert_eq!(
        corpus_text(&produced.to_json()),
        read(&cage.join("fingerprint.json")),
        "the fingerprint a Python-deployed cage carries is not reproduced; \
         at cutover every `cage update` would rebuild",
    );
}

/// `yaml.safe_load(text) or {}`, as a JSON value.
///
/// The fingerprint crate keeps this private — it is an implementation
/// detail of `normalize_cage_yaml` — so the test does the same
/// conversion by going through `normalize_cage_yaml`'s text path and
/// parsing the canonical JSON back. Round-tripping through the exact
/// serializer under test is fine here: what this needs is the *value*,
/// and any error in the serializer would fail the assertion above, not
/// hide in it.
fn json_from_yaml_text(text: &str) -> Json {
    let canonical = agentcage_core::fingerprint::normalize_cage_yaml(CageYaml::Text(text))
        .expect("the fixture's proxy-config.yaml parses");
    json::parse(&canonical).expect("stable_json emits JSON")
}
