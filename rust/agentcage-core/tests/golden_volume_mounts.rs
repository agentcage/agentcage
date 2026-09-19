//! Reproduce the golden corpus's `volume-mounts.json` byte-for-byte.
//!
//! `tests/fixtures/golden/` (PR A3) records, for every case in the config
//! matrix, everything `src/agentcage/volume_mounts.py` derives from that
//! config's mounts — plus a standalone spec table in `shared/` that covers
//! the shapes no `cage.yaml` in the matrix happens to use. The fixture is the
//! specification: this test rebuilds each document from the same inputs and
//! compares the bytes, so a divergence shows up as a diff rather than as a
//! judgement call. See `tests/fixtures/golden/README.md`.
//!
//! The comparison is byte-exact, not by parsed value. The corpus README puts
//! JSON on the byte-exact side of its line, and it costs nothing here:
//! `CPython`'s `json.dumps(..., indent=2, sort_keys=True, ensure_ascii=False)`
//! and `serde_json::to_string_pretty` agree on two-space indentation, on
//! `": "` between key and value, on sorted keys (`serde_json`'s `Map` is a
//! `BTreeMap`, which for the ASCII keys here is the same order `CPython`'s
//! `sort_keys` produces) and on leaving non-ASCII unescaped.

use std::fs;
use std::path::{Path, PathBuf};

use agentcage_core::volume_mounts::{
    MountTarget, enclosing_mount, is_non_persistent_volume, mask_copyup_entries,
    mask_mountpoint_dirs, split_volume_spec, tmpfs_spec_options, tmpfs_spec_target,
    tmpfs_wants_copyup, validate_non_persistent_volume, volume_options,
};
use serde_json::{Value, json};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/golden")
        .canonicalize()
        .expect("golden corpus is committed next to the Rust workspace")
}

/// Serialize exactly as the corpus harness's `_json_text` does.
fn json_text(value: &Value) -> String {
    let mut out = serde_json::to_string_pretty(value).expect("report is plain JSON");
    out.push('\n');
    out
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|v| v.as_str().expect("spec is a string").to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn mount_pairs(value: &Value) -> Vec<MountTarget> {
    value
        .as_array()
        .expect("mount_targets is an array")
        .iter()
        .map(|pair| {
            let pair = pair
                .as_array()
                .expect("mount target is a [target, source] pair");
            MountTarget::new(
                pair[0].as_str().expect("target is a string"),
                pair[1].as_str().expect("source is a string"),
            )
        })
        .collect()
}

fn mount_targets_json(mounts: &[MountTarget]) -> Value {
    Value::Array(mounts.iter().map(|m| json!([m.target, m.source])).collect())
}

/// One row of the harness's per-spec volume table.
fn volume_row(spec: &str, with_validation: bool) -> Value {
    let (source, target, raw_options) = split_volume_spec(spec);
    let mut row = json!({
        "spec": spec,
        "source": source,
        "target": target,
        "raw_options": raw_options,
        "options": volume_options(spec),
        "non_persistent": is_non_persistent_volume(spec),
    });
    if with_validation {
        let error = match validate_non_persistent_volume(spec) {
            Ok(()) => Value::Null,
            Err(err) => Value::String(err.to_string()),
        };
        row["validation_error"] = error;
    }
    row
}

/// One row of the harness's per-spec tmpfs table.
///
/// Note that `enclosing_mount` is fed the *raw* target here, trailing slash
/// and all — that is what the harness does, and the corpus has a
/// `/workspace/.claude/` case that only passes if the slash survives.
fn tmpfs_row(spec: &str, mounts: &[MountTarget]) -> Value {
    let target = tmpfs_spec_target(spec);
    let enclosing = enclosing_mount(target, mounts)
        .map_or_else(|| json!(["", ""]), |m| json!([m.target, m.source]));
    json!({
        "spec": spec,
        "target": target,
        "options": tmpfs_spec_options(spec),
        "wants_copyup": tmpfs_wants_copyup(spec),
        "enclosing_mount": enclosing,
    })
}

/// Serialize `mask_mountpoint_dirs` as ordered `[source, [dirs]]` pairs.
///
/// The harness used to iterate the returned Python `dict` directly, which
/// yields only its keys, so the corpus recorded the bind sources and dropped
/// the host paths under each one. Those paths are the half #320's
/// `ExecStopPost` rmdir chain consumes, and their order is load-bearing —
/// deepest first, so `<project>/.git/hooks` is retired before
/// `<project>/.git`. The harness now records the pairs, so this compares the
/// values rather than trusting the module's own unit tests for them.
///
/// Pairs rather than a JSON object: an object would not promise to preserve
/// that ordering.
fn mask_dirs_json(tmpfs: &[String], mounts: &[MountTarget]) -> Value {
    Value::Array(
        mask_mountpoint_dirs(tmpfs, mounts)
            .into_iter()
            .map(|entry| {
                Value::Array(vec![
                    Value::String(entry.host_source),
                    Value::Array(entry.dirs.into_iter().map(Value::String).collect()),
                ])
            })
            .collect(),
    )
}

fn mask_copyup_json(tmpfs: &[String], mounts: &[MountTarget]) -> Value {
    Value::Array(
        mask_copyup_entries(tmpfs, mounts)
            .into_iter()
            .map(|e| json!([e.container_target, e.host_source, e.host_root]))
            .collect(),
    )
}

/// `shared/volume-mounts.json`: the standalone spec table.
///
/// Its inputs are hard-coded in `scripts/gen-golden-corpus.py` rather than
/// derived from a config, and the fixture carries every one of them — each
/// row's `spec`, plus the `mount_targets` table, which for this artifact is a
/// pure input. So the test reads its inputs back out of the fixture and
/// recomputes everything else.
#[test]
fn shared_volume_spec_table_matches() {
    let path = corpus_root().join("shared/volume-mounts.json");
    let expected = fs::read_to_string(&path).expect("shared table is committed");
    let parsed: Value = serde_json::from_str(&expected).expect("fixture is JSON");

    let mounts = mount_pairs(&parsed["mount_targets"]);
    let volume_specs: Vec<String> = parsed["volume_specs"]
        .as_array()
        .expect("volume_specs is an array")
        .iter()
        .map(|row| row["spec"].as_str().expect("spec is a string").to_string())
        .collect();
    let tmpfs_specs: Vec<String> = parsed["tmpfs_specs"]
        .as_array()
        .expect("tmpfs_specs is an array")
        .iter()
        .map(|row| row["spec"].as_str().expect("spec is a string").to_string())
        .collect();

    let actual = json_text(&json!({
        "volume_specs": volume_specs
            .iter()
            .map(|s| volume_row(s, true))
            .collect::<Vec<_>>(),
        "tmpfs_specs": tmpfs_specs
            .iter()
            .map(|s| tmpfs_row(s, &mounts))
            .collect::<Vec<_>>(),
        "mount_targets": mount_targets_json(&mounts),
        "mask_mountpoint_dirs": mask_dirs_json(&tmpfs_specs, &mounts),
        "mask_copyup_entries": mask_copyup_json(&tmpfs_specs, &mounts),
    }));

    assert_eq!(actual, expected, "{} differs", path.display());
}

/// Every `valid/<case>/volume-mounts.json` in the corpus.
///
/// Inputs come from the case's own `resolved-config.json` —
/// `container.volumes`, `container.tmpfs` and `container.named_volumes` — so
/// this exercises the parse from the same starting point the Python harness
/// used. One input cannot be taken from there: see [`named_volume_targets`].
#[test]
fn every_case_volume_report_matches() {
    let root = corpus_root();
    let mut cases: Vec<PathBuf> = fs::read_dir(root.join("valid"))
        .expect("corpus has a valid/ directory")
        .map(|entry| entry.expect("readable corpus entry").path())
        .filter(|path| path.join("volume-mounts.json").is_file())
        .collect();
    cases.sort();
    assert!(
        cases.len() > 100,
        "expected the whole config matrix, found {} cases — is the corpus \
         checked out?",
        cases.len()
    );

    let mut checked = 0usize;
    for case in &cases {
        let expected = fs::read_to_string(case.join("volume-mounts.json"))
            .expect("case has a volume-mounts.json");
        let config: Value = serde_json::from_str(
            &fs::read_to_string(case.join("resolved-config.json"))
                .expect("a valid case has a resolved-config.json"),
        )
        .expect("resolved config is JSON");
        let container = &config["container"];

        let volumes = strings(container.get("volumes"));
        let tmpfs = strings(container.get("tmpfs"));

        // The harness's `mount_targets`: one entry per `container.volumes`
        // bind, with the host source blanked for `np` (its writes land in an
        // overlay upperdir, never on the host), then one per named volume,
        // which never reaches the host either.
        let mut mounts: Vec<MountTarget> = volumes
            .iter()
            .map(|spec| {
                let (source, target, _) = split_volume_spec(spec);
                let source = if is_non_persistent_volume(spec) {
                    ""
                } else {
                    source
                };
                MountTarget::new(target, source)
            })
            .collect();
        mounts.extend(named_volume_targets(container, &expected, volumes.len()));

        let actual = json_text(&json!({
            "mount_targets": mount_targets_json(&mounts),
            "volumes": volumes
                .iter()
                .map(|s| volume_row(s, false))
                .collect::<Vec<_>>(),
            "tmpfs": tmpfs
                .iter()
                .map(|s| tmpfs_row(s, &mounts))
                .collect::<Vec<_>>(),
            "mask_mountpoint_dirs": mask_dirs_json(&tmpfs, &mounts),
            "mask_copyup_entries": mask_copyup_json(&tmpfs, &mounts),
        }));

        assert_eq!(
            actual,
            expected,
            "{}/volume-mounts.json differs",
            case.file_name().expect("case directory").to_string_lossy()
        );
        checked += 1;
    }

    // A loop that silently checked nothing would pass; say what it did.
    assert_eq!(checked, cases.len());
    println!("reproduced {checked} per-case volume reports");
}

/// The named-volume tail of `mount_targets`, which the corpus cannot hand
/// back as an input.
///
/// `container.named_volumes` is a mapping, and the harness walks its
/// `.values()` in YAML order — but `resolved-config.json` was written with
/// `sort_keys=True`, so reading it back gives the *keys* sorted instead.
/// `valid/volumes-named` declares `state` before `cache` and is the one case
/// where the two orders differ.
///
/// Recovering the real order needs a YAML parser (PR B2), which is not in
/// this PR. So the order comes from the fixture's own `mount_targets` tail,
/// and the assertion below is what keeps that from being a free pass: the
/// tail must be exactly the container paths `container.named_volumes` names,
/// as a multiset, each with an empty host source. Only the *ordering* of that
/// tail is taken on trust, and ordering here is not `volume_mounts.py`'s
/// behaviour — it is the mapping order C1 will be responsible for preserving.
fn named_volume_targets(
    container: &Value,
    expected: &str,
    volume_count: usize,
) -> Vec<MountTarget> {
    let named = container.get("named_volumes").and_then(Value::as_object);
    let Some(named) = named.filter(|m| !m.is_empty()) else {
        return Vec::new();
    };

    let mut declared: Vec<String> = named
        .values()
        .map(|mount| {
            let mount = mount.as_str().expect("named volume mount is a string");
            mount
                .split_once(':')
                .map_or(mount, |(target, _)| target)
                .to_string()
        })
        .collect();

    let fixture: Value = serde_json::from_str(expected).expect("fixture is JSON");
    let tail: Vec<MountTarget> = mount_pairs(&fixture["mount_targets"])
        .into_iter()
        .skip(volume_count)
        .collect();

    let mut seen: Vec<String> = tail.iter().map(|m| m.target.clone()).collect();
    declared.sort();
    seen.sort();
    assert_eq!(
        declared, seen,
        "the named-volume tail of mount_targets does not match named_volumes"
    );
    assert!(
        tail.iter().all(|m| m.source.is_empty()),
        "a named volume must never carry a host source"
    );
    tail
}
