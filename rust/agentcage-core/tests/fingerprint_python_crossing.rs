//! `stable_json` and `compute_fingerprint`, checked against CPython.
//!
//! # Why a crossing test and not a table of expectations
//!
//! The golden corpus proves this port reproduces 126 fingerprints that
//! already exist. It cannot prove the port reproduces the *next* one,
//! because every input in it is a well-behaved cage configuration:
//! ASCII keys, string values, no floats. The failure modes that worry
//! this module are all outside that set —
//!
//! * **Floats.** Python's `repr` is not Rust's `Display`: `1e16`, `1e-05`
//!   and `-0.0` all render differently, and one differing byte is a
//!   different sha256.
//! * **Unicode.** `ensure_ascii=False` means raw UTF-8 reaches the hash,
//!   so escaping and key ordering both have to match exactly for
//!   non-ASCII.
//! * **Large integers.** Python's `int` is unbounded.
//!
//! — so those cases have to come from a real interpreter rather than
//! from a hand-written table, which would just be this author's belief
//! about `repr` written down twice.
//!
//! # Why it is `#[ignore]`d
//!
//! Same reason as `yaml_pyyaml_crossing.rs`: `cargo test` has to work on
//! a machine with no Python, since the point of the port is that Python
//! stops being a runtime dependency. CI runs it as its own step:
//!
//! ```text
//! cargo test -p agentcage-core --test fingerprint_python_crossing -- --ignored
//! ```
//!
//! Set `AGENTCAGE_PYTHON` to pick the interpreter; the default is
//! `python3`. It needs `src/` on `PYTHONPATH` (this test adds it) and
//! PyYAML, which `fingerprint.py` imports. It **fails** rather than
//! skips when either is missing: a conformance test that silently passes
//! because it could not run is worse than no test.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use agentcage_core::fingerprint::{CageYaml, Inputs, compute_fingerprint, stable_json};
use agentcage_core::har::json::{self, DumpOptions, Json};

/// The Python side.
///
/// Reads a JSON job on `argv[1]`, writes a JSON verdict on stdout. It
/// calls the shipped `fingerprint` module rather than re-deriving what
/// it does, so this cannot drift from the thing being ported.
const CROSSING_SCRIPT: &str = r#"
import json, sys

from agentcage.fingerprint import compute_fingerprint, stable_json

job = json.load(open(sys.argv[1]))
out = {"python_version": sys.version.split()[0]}

# `json.loads` gives the same objects PyYAML would for these shapes, and
# starting from a document text means the Rust and Python sides begin
# from one source of truth rather than from two literal tables.
out["stable_json"] = {
    case["id"]: stable_json(json.loads(case["document"]))
    for case in job["stable_json"]
}

out["fingerprints"] = {
    case["id"]: compute_fingerprint(
        case["cage_yaml"],
        resolved_config=json.loads(case["resolved_config"]),
        units=case["units"],
        image_digests=case["image_digests"],
        scaffold_version=case["scaffold_version"],
    )
    for case in job["fingerprints"]
}

json.dump(out, sys.stdout, ensure_ascii=False)
"#;

/// A value whose serialization is worth crossing the language boundary
/// for, as the JSON text both sides start from.
///
/// Every one of these is a shape no corpus case has. The ids are what a
/// failure names.
fn stable_json_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        // ── floats: `repr` layout, not just digits ────────────
        ("float-whole", r#"{"v": 1.0}"#),
        ("float-third", r#"{"v": 0.3333333333333333}"#),
        ("float-negative-zero", r#"{"v": -0.0}"#),
        ("float-exponent-upper", r#"{"v": 1e16}"#),
        ("float-below-exponent", r#"{"v": 1e15}"#),
        ("float-exponent-lower", r#"{"v": 1e-5}"#),
        ("float-just-above-lower", r#"{"v": 1e-4}"#),
        ("float-subnormal", r#"{"v": 5e-324}"#),
        ("float-max", r#"{"v": 1.7976931348623157e308}"#),
        ("float-nan", r#"{"v": NaN}"#),
        ("float-infinities", r#"{"v": [Infinity, -Infinity]}"#),
        // ── integers: Python's are unbounded ──────────────────
        (
            "int-i64-edges",
            r#"{"v": [-9223372036854775808, 9223372036854775807]}"#,
        ),
        ("int-past-i64", r#"{"v": 18446744073709551615}"#),
        // ── unicode under ensure_ascii=False ──────────────────
        ("unicode-values", r#"{"v": "h\u00e9llo \u65e5\u672c"}"#),
        ("unicode-astral", r#"{"v": "\ud83d\ude00"}"#),
        ("unicode-combining", r#"{"v": ["e\u0301", "\u00e9"]}"#),
        ("unicode-line-separator", r#"{"v": "a\u2028b"}"#),
        (
            "unicode-del-and-controls",
            r#"{"v": "a\u007fb\u0000c\u001fd"}"#,
        ),
        // ── key ordering: byte order vs code-point order ──────
        (
            "keys-mixed-scripts",
            r#"{"z": 1, "\u00e9": 2, "\uffff": 3, "\ud800\udc00": 4, "A": 5, "_": 6}"#,
        ),
        ("keys-prefix", r#"{"ab": 1, "a": 2, "a ": 3, "a!": 4}"#),
        ("keys-empty", r#"{"": 1, " ": 2}"#),
        // ── structure ─────────────────────────────────────────
        ("empty-containers", r#"{"a": {}, "b": [], "c": [[]]}"#),
        (
            "nested-sorting",
            r#"{"b": {"d": 1, "c": [{"f": 1, "e": 2}]}, "a": null}"#,
        ),
        ("escapes", r#"{"q\"\\": "tab\tnl\ncr\rbs\bff\f"}"#),
        ("booleans", r#"{"t": true, "f": false, "n": null}"#),
    ]
}

/// One end-to-end fingerprint, in the five inputs `compute_fingerprint`
/// takes. `resolved_config` is a JSON document text for the same reason
/// the cases above are.
struct FingerprintCase {
    id: &'static str,
    cage_yaml: &'static str,
    resolved_config: &'static str,
    units: Vec<(&'static str, &'static str)>,
    image_digests: Vec<(&'static str, &'static str)>,
    scaffold_version: &'static str,
}

fn fingerprint_cases() -> Vec<FingerprintCase> {
    vec![
        FingerprintCase {
            id: "empty-everything",
            cage_yaml: "",
            resolved_config: "{}",
            units: Vec::new(),
            image_digests: Vec::new(),
            scaffold_version: "",
        },
        FingerprintCase {
            id: "ordinary-cage",
            cage_yaml: "name: demo\nimage: docker.io/library/node:22-slim\ndomains:\n  - api.example.com\n  - '*.github.com'\n",
            resolved_config: r#"{"name": "demo", "capture": {"enabled": false, "max_body_bytes": 65536}}"#,
            units: vec![
                ("demo-cage.container", "[Container]\nImage=x\n"),
                ("demo-net.network", "[Network]\n"),
            ],
            image_digests: vec![("docker.io/library/node:22-slim", "sha256:00")],
            scaffold_version: "claude-code@1.2.3",
        },
        FingerprintCase {
            id: "yaml-1-1-booleans",
            cage_yaml: "relays:\n  - upstream:\n      tls: no\n      verify: 'no'\n      keepalive: on\n",
            resolved_config: r#"{"tls": false}"#,
            units: Vec::new(),
            image_digests: Vec::new(),
            scaffold_version: "",
        },
        FingerprintCase {
            id: "unicode-throughout",
            // A non-ASCII key, a non-ASCII value, and a unit whose
            // *name* is non-ASCII -- units are hashed as a mapping, so
            // the name is sorted and escaped like any other key.
            cage_yaml: "名前: デモ\nnotes: \"héllo 😀\"\n",
            resolved_config: r#"{"é": "😀", "z": 1}"#,
            units: vec![("ünit.container", "[Container]\n# héllo\n")],
            image_digests: vec![("ghcr.io/例/img", "sha256:11")],
            scaffold_version: "版-1",
        },
        FingerprintCase {
            id: "numbers-in-the-config",
            cage_yaml: "port: 8080\nratio: 0.5\nbig: 12345678901234567890\n",
            resolved_config: r#"{"a": 1.0, "b": 1e16, "c": -0.0, "d": 1e-5}"#,
            units: Vec::new(),
            image_digests: Vec::new(),
            scaffold_version: "",
        },
        FingerprintCase {
            id: "falsy-cage-yaml",
            // `yaml.safe_load(text) or {}`: this has to hash the same as
            // the empty document.
            cage_yaml: "# nothing but a comment\n",
            resolved_config: "{}",
            units: Vec::new(),
            image_digests: Vec::new(),
            scaffold_version: "",
        },
    ]
}

// ── Plumbing ─────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn compact(value: &Json) -> String {
    json::dumps(
        value,
        DumpOptions {
            sort_keys: true,
            ensure_ascii: false,
            ..DumpOptions::default()
        },
    )
}

fn object(pairs: Vec<(&str, Json)>) -> Json {
    Json::Object(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

fn string_object(pairs: &[(&str, &str)]) -> Json {
    Json::Object(
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), Json::string(*value)))
            .collect(),
    )
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

/// Run the Python side and parse its verdict.
fn ask_python(job: &Json) -> Json {
    let root = repo_root();
    let directory =
        std::env::temp_dir().join(format!("agentcage-fp-crossing-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a scratch directory");
    let job_path = directory.join("job.json");
    let script_path = directory.join("crossing.py");
    // The job file is written `ensure_ascii=False` and read back the
    // same way, so the non-ASCII cases cross as UTF-8 rather than as
    // escapes -- which is the thing under test.
    std::fs::write(&job_path, compact(job)).expect("write the job");
    std::fs::write(&script_path, CROSSING_SCRIPT).expect("write the script");

    let interpreter = std::env::var("AGENTCAGE_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let output = Command::new(&interpreter)
        .arg(&script_path)
        .arg(&job_path)
        .env("PYTHONPATH", root.join("src"))
        .env("PYTHONIOENCODING", "utf-8")
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "could not run {interpreter}: {error}. This test needs an \
                 interpreter with PyYAML; set AGENTCAGE_PYTHON to pick one."
            )
        });
    assert!(
        output.status.success(),
        "the Python side failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&directory);
    json::parse(&String::from_utf8(output.stdout).expect("UTF-8 from Python"))
        .expect("the Python side emits JSON")
}

/// Build the job, ask Python, and compare every answer.
#[test]
#[ignore = "needs a Python interpreter with PyYAML; CI runs it explicitly"]
fn python_agrees_byte_for_byte() {
    let serializer_cases: Vec<Json> = stable_json_cases()
        .iter()
        .map(|(id, document)| {
            object(vec![
                ("id", Json::string(*id)),
                ("document", Json::string(*document)),
            ])
        })
        .collect();

    let cases = fingerprint_cases();
    let fingerprint_jobs: Vec<Json> = cases
        .iter()
        .map(|case| {
            object(vec![
                ("id", Json::string(case.id)),
                ("cage_yaml", Json::string(case.cage_yaml)),
                ("resolved_config", Json::string(case.resolved_config)),
                ("units", string_object(&case.units)),
                ("image_digests", string_object(&case.image_digests)),
                ("scaffold_version", Json::string(case.scaffold_version)),
            ])
        })
        .collect();

    let verdict = ask_python(&object(vec![
        ("stable_json", Json::Array(serializer_cases)),
        ("fingerprints", Json::Array(fingerprint_jobs)),
    ]));

    // ── the serializer ───────────────────────────────────────
    let python_serialized = verdict.get("stable_json").expect("stable_json verdict");
    for (id, document) in stable_json_cases() {
        let value = json::parse(document).unwrap_or_else(|e| panic!("{id}: {e}"));
        let expected = python_serialized
            .get(id)
            .and_then(Json::as_str)
            .unwrap_or_else(|| panic!("{id}: Python returned nothing"));
        assert_eq!(
            stable_json(&value),
            expected,
            "{id}: stable_json disagrees with CPython"
        );
    }

    // ── the whole fingerprint ────────────────────────────────
    let python_fingerprints = verdict.get("fingerprints").expect("fingerprints verdict");
    for case in &cases {
        let resolved_config =
            json::parse(case.resolved_config).unwrap_or_else(|e| panic!("{}: {e}", case.id));
        let produced = compute_fingerprint(Inputs {
            cage_yaml: CageYaml::Text(case.cage_yaml),
            resolved_config: &resolved_config,
            units: &map(&case.units),
            image_digests: &map(&case.image_digests),
            scaffold_version: case.scaffold_version,
        })
        .unwrap_or_else(|error| panic!("{}: {error}", case.id));

        let expected = python_fingerprints
            .get(case.id)
            .unwrap_or_else(|| panic!("{}: Python returned nothing", case.id));
        // Compared as serialized documents so a mismatch prints both
        // sides in full rather than as two opaque `Json` debug dumps.
        assert_eq!(
            compact(&produced.to_json()),
            compact(expected),
            "{}: the fingerprint disagrees with CPython",
            case.id
        );
    }
}
