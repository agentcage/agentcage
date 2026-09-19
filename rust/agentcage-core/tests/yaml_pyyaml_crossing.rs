//! The test that actually proves it: Rust emits, **PyYAML reads**.
//!
//! # Why this test is the only one that counts
//!
//! The corruption this PR exists to stop happens in one direction.
//! PyYAML quotes `'no'` on output, so Python→Rust and Python→Python are
//! both safe, and a Rust→Rust round trip is safe whether or not the bug
//! is present — `no` goes out unquoted, comes back as the string `"no"`,
//! and the test is green while every `proxy-config.yaml` the host writes
//! is quietly wrong. The fixture has to cross the language boundary in
//! the Rust→Python direction, which means running `yaml.safe_load`.
//!
//! # Why it is `#[ignore]`d
//!
//! `cargo test` has to work on a machine with no Python. The whole point
//! of the port (RUST-PORT-PLAN.md, scope decision) is that Python stops
//! being an agentcage runtime dependency, so requiring an interpreter to
//! run the unit suite would be an odd thing to introduce. It is run
//! explicitly instead — by a developer, and by CI, which has both:
//!
//! ```text
//! cargo test -p agentcage-core --test yaml_pyyaml_crossing -- --ignored
//! ```
//!
//! `.github/workflows/rust.yml` has that as its own step, so "runnable"
//! does not mean "never run".
//!
//! Set `AGENTCAGE_PYTHON` to pick the interpreter; the default is
//! `python3`. The test fails, rather than skipping, when the interpreter
//! or PyYAML is missing: a conformance test that silently passes because
//! it could not run is worse than no test.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use agentcage_core::yaml::{self, Mapping, Value};

use common::{committed_configs, fixture};

/// The Python side of the crossing.
///
/// Reads a JSON job on `argv[1]` and writes a JSON verdict on stdout.
/// Kept in one place so both tests use the same `safe_load` call rather
/// than two subtly different ones.
const CROSSING_SCRIPT: &str = r#"
import datetime, json, sys, yaml

job = json.load(open(sys.argv[1]))
out = {"pyyaml_version": yaml.__version__}
resolver = yaml.resolver.Resolver()


def plain_tag(scalar):
    """The tag PyYAML gives this text when it appears as a PLAIN scalar."""
    tag = resolver.resolve(yaml.ScalarNode, scalar, (True, False))
    prefix = "tag:yaml.org,2002:"
    return tag[len(prefix):] if tag.startswith(prefix) else tag


def describe(value):
    return {"type": type(value).__name__, "repr": repr(value)}


if job["kind"] == "scalars":
    document = yaml.safe_load(job["emitted"])
    values = document["values"]
    keys = document["keys"]
    cases = {}
    for case in job["cases"]:
        got = values[case["id"]]
        cases[case["id"]] = {
            "value": describe(got),
            "value_is_the_string_it_went_in_as": isinstance(got, str)
            and got == case["scalar"],
            "key_is_the_string_it_went_in_as": any(
                isinstance(k, str) and k == case["scalar"] for k in keys
            ),
            "plain_tag": plain_tag(case["scalar"]),
        }
    out["cases"] = cases

elif job["kind"] == "naive_scalars":
    # One document per case: `=` and `<<` make safe_load raise, and a
    # raise has to be recorded as corruption rather than take the batch
    # down with it.
    cases = {}
    for case in job["cases"]:
        try:
            got = yaml.safe_load(case["emitted"])["v"]
        except Exception as error:
            cases[case["id"]] = {
                "value": {"type": "RAISED", "repr": type(error).__name__},
                "value_is_the_string_it_went_in_as": False,
                "key_is_the_string_it_went_in_as": False,
                "plain_tag": plain_tag(case["scalar"]),
            }
            continue
        cases[case["id"]] = {
            "value": describe(got),
            "value_is_the_string_it_went_in_as": isinstance(got, str)
            and got == case["scalar"],
            "key_is_the_string_it_went_in_as": True,
            "plain_tag": plain_tag(case["scalar"]),
        }
    out["cases"] = cases

elif job["kind"] == "documents":
    # The reading half. `describe` is a canonical, order-preserving
    # rendering of whatever safe_load produced, so the Rust side can
    # build the same string from its own Value and compare. Python
    # dicts keep insertion order, so key order is compared too.
    def describe(value):
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "bool:true" if value else "bool:false"
        if isinstance(value, int):
            return "int:" + repr(value)
        if isinstance(value, float):
            return "float:" + repr(value)
        if isinstance(value, str):
            return "str:" + value
        if isinstance(value, list):
            return "seq[" + ",".join(describe(v) for v in value) + "]"
        if isinstance(value, dict):
            return "map{" + ",".join(
                describe(k) + "=>" + describe(v) for k, v in value.items()
            ) + "}"
        return "other:" + type(value).__name__

    cases = {}
    for case in job["cases"]:
        loaded = yaml.safe_load(case["yaml"])
        cases[case["id"]] = {
            "described": describe(loaded),
            # The coercion relays/_validate.py:76 applies to the value
            # it pulls out. Reported for the mapping key the case names,
            # when there is one.
            "bool_of_tls": bool(loaded["tls"])
            if isinstance(loaded, dict) and "tls" in loaded
            else None,
        }
    out["cases"] = cases

elif job["kind"] == "configs":
    files = {}
    for entry in job["files"]:
        original = yaml.safe_load(open(entry["path"]).read())
        emitted = yaml.safe_load(entry["emitted"])
        files[entry["path"]] = {
            "equal": original == emitted,
            "original_keys": list(original) if isinstance(original, dict) else None,
            "emitted_keys": list(emitted) if isinstance(emitted, dict) else None,
        }
    out["files"] = files

else:
    raise SystemExit("unknown job kind " + repr(job["kind"]))

json.dump(out, sys.stdout)
"#;

/// A scratch directory for this test process.
fn scratch() -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "agentcage-yaml-crossing-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    ));
    std::fs::create_dir_all(&directory).expect("scratch dir");
    directory
}

/// Run the crossing script over `job` and parse its verdict.
fn run_python(job: &serde_json::Value) -> serde_json::Value {
    let directory = scratch();
    let script = directory.join("crossing.py");
    let job_path = directory.join("job.json");
    std::fs::write(&script, CROSSING_SCRIPT).expect("write script");
    std::fs::write(&job_path, serde_json::to_vec(job).expect("job JSON")).expect("write job");

    let interpreter = std::env::var("AGENTCAGE_PYTHON").unwrap_or_else(|_| "python3".to_owned());
    let output = Command::new(&interpreter)
        .arg(&script)
        .arg(&job_path)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "could not run {interpreter:?}: {error}. This test needs a Python with \
                 PyYAML; set AGENTCAGE_PYTHON to point at one."
            )
        });

    assert!(
        output.status.success(),
        "{interpreter} failed ({}):\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = std::fs::remove_dir_all(&directory);
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "unparseable verdict: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Every scalar in the corpus, emitted by Rust, read by PyYAML.
///
/// Asserted three ways per case:
///
/// 1. the value comes back as a `str` holding exactly what went in;
/// 2. so does the same text used as a mapping **key** — `proxy-config`
///    carries header names and domains in key position too;
/// 3. the live PyYAML resolver agrees with the `plain_tag` recorded in
///    the fixture, so the corpus cannot rot against a PyYAML upgrade
///    without this failing.
#[test]
#[ignore = "needs a Python with PyYAML; run with --ignored (CI does)"]
fn every_hazardous_scalar_crosses_into_pyyaml_as_a_string() {
    let fixture = fixture();

    let mut values = Mapping::new();
    let mut keys = Mapping::new();
    for case in &fixture.cases {
        values.insert(
            Value::String(case.id.clone()),
            Value::String(case.scalar.clone()),
        );
        keys.insert(
            Value::String(case.scalar.clone()),
            Value::String(case.id.clone()),
        );
    }
    let mut document = Mapping::new();
    document.insert(Value::String("values".to_owned()), Value::Mapping(values));
    document.insert(Value::String("keys".to_owned()), Value::Mapping(keys));

    let emitted = yaml::dump(&Value::Mapping(document)).expect("dump");

    let job = serde_json::json!({
        "kind": "scalars",
        "emitted": emitted,
        "cases": fixture.cases.iter().map(|case| serde_json::json!({
            "id": case.id,
            "scalar": case.scalar,
        })).collect::<Vec<_>>(),
    });
    let verdict = run_python(&job);
    let cases = verdict["cases"].as_object().expect("cases");

    let mut corrupted = Vec::new();
    let mut drifted = Vec::new();
    for case in &fixture.cases {
        let got = &cases[&case.id];
        if got["value_is_the_string_it_went_in_as"] != serde_json::Value::Bool(true) {
            corrupted.push(format!(
                "  {:<28} {:?} -> {} {}",
                case.id, case.scalar, got["value"]["type"], got["value"]["repr"]
            ));
        }
        if got["key_is_the_string_it_went_in_as"] != serde_json::Value::Bool(true) {
            corrupted.push(format!(
                "  {:<28} {:?} did not survive in key position",
                case.id, case.scalar
            ));
        }
        if got["plain_tag"] != serde_json::Value::String(case.plain_tag.clone()) {
            drifted.push(format!(
                "  {:<28} fixture says `{}`, this PyYAML says {}",
                case.id, case.plain_tag, got["plain_tag"]
            ));
        }
    }

    assert!(
        drifted.is_empty(),
        "the fixture disagrees with the PyYAML on this machine ({}):\n{}",
        verdict["pyyaml_version"],
        drifted.join("\n")
    );
    assert!(
        corrupted.is_empty(),
        "{} of {} scalars changed type crossing into PyYAML {}:\n{}\n--- emitted ---\n{emitted}",
        corrupted.len(),
        fixture.cases.len(),
        verdict["pyyaml_version"],
        corrupted.join("\n")
    );

    println!(
        "{} scalars crossed into PyYAML {} unchanged",
        fixture.cases.len(),
        verdict["pyyaml_version"]
    );
}

/// The control arm: the same corpus emitted *without* the extra quoting.
///
/// A conformance corpus that passes against a broken implementation
/// reads like coverage and is worse than nothing
/// (`tests/fixtures/contracts/README.md`, "Proving the fixtures bite").
/// So this emits every hazard the way the bare crate would — which is
/// what this PR's whole argument says is unsafe — and requires PyYAML's
/// answer to line up exactly with what the crate chose to quote:
///
/// - the crate left it **plain** → PyYAML must corrupt it, or the case
///   is not a hazard and proves nothing;
/// - the crate **quoted** it → PyYAML must read it back intact. These
///   are the YAML 1.2 specials (`true`, `null`, `0755`, `.inf`), and
///   they are in the corpus to mark the boundary of what the crate
///   handles on its own.
///
/// If the first list ever comes back empty, the hazard has gone away
/// and `yaml::emit`'s extra quoting can be deleted.
#[test]
#[ignore = "needs a Python with PyYAML; run with --ignored (CI does)"]
fn the_unquoted_emission_really_is_corrupted() {
    let fixture = fixture();
    let hazards: Vec<_> = fixture
        .cases
        .iter()
        .filter(|case| case.plain_tag != "str")
        .collect();

    // `serde_norway::to_string` straight, with none of this module's
    // quoting: the "before" picture, one document per case so that the
    // two scalars `safe_load` refuses outright do not take the rest of
    // the batch down with them.
    let mut left_plain = Vec::new();
    let cases: Vec<serde_json::Value> = hazards
        .iter()
        .map(|case| {
            let mut mapping = Mapping::new();
            mapping.insert(
                Value::String("v".to_owned()),
                Value::String(case.scalar.clone()),
            );
            let naive = serde_norway::to_string(&Value::Mapping(mapping)).expect("naive dump");
            let scalar = naive
                .strip_prefix("v: ")
                .unwrap_or(&naive)
                .trim_end_matches('\n');
            if !(scalar.starts_with('\'') || scalar.starts_with('"') || scalar.starts_with('|')) {
                left_plain.push(case.id.as_str());
            }
            serde_json::json!({
                "id": case.id,
                "scalar": case.scalar,
                "emitted": naive,
            })
        })
        .collect();

    let verdict = run_python(&serde_json::json!({
        "kind": "naive_scalars",
        "cases": cases,
    }));
    let reports = verdict["cases"].as_object().expect("cases");

    let mut wrong = Vec::new();
    for case in &hazards {
        let survived =
            reports[&case.id]["value_is_the_string_it_went_in_as"] == serde_json::Value::Bool(true);
        let was_plain = left_plain.contains(&case.id.as_str());
        if was_plain && survived {
            wrong.push(format!(
                "  {:<28} {:?} is in the corpus as a `{}` hazard, but the bare \
                 crate emits it plain and PyYAML still reads a string",
                case.id, case.scalar, case.plain_tag
            ));
        }
        if !was_plain && !survived {
            wrong.push(format!(
                "  {:<28} {:?} was quoted by the crate and PyYAML still gave {} {}",
                case.id,
                case.scalar,
                reports[&case.id]["value"]["type"],
                reports[&case.id]["value"]["repr"]
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "control arm disagrees:\n{}",
        wrong.join("\n")
    );
    assert!(
        left_plain.len() >= 14,
        "only {} hazards leak through the bare crate; the measurement in \
         RUST-PORT-PLAN.md section 2.8 found 14",
        left_plain.len()
    );
    println!(
        "control arm: {} of {} corpus hazards leak through the bare crate and \
         are corrupted by PyYAML {}; the other {} it quotes on its own",
        left_plain.len(),
        hazards.len(),
        verdict["pyyaml_version"],
        hazards.len() - left_plain.len()
    );
    let mut leaking: Vec<&str> = left_plain.clone();
    leaking.sort_unstable();
    println!("  leaking: {}", leaking.join(", "));
}

/// Every committed config, emitted by Rust, compared **by PyYAML**.
///
/// The Rust→Rust round trip in `yaml_config_roundtrip.rs` proves key
/// order and structure survive this crate. This proves the far side
/// agrees: `yaml.safe_load` of the file the host would write equals
/// `yaml.safe_load` of the file as committed, key order included. That
/// is the property `state.save_proxy_config` → `addon.Agentcage.load`
/// actually depends on.
#[test]
#[ignore = "needs a Python with PyYAML; run with --ignored (CI does)"]
fn every_committed_config_crosses_into_pyyaml_unchanged() {
    let configs = committed_configs();
    let files: Vec<serde_json::Value> = configs
        .iter()
        .map(|path| {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            let value = yaml::load(&source)
                .unwrap_or_else(|error| panic!("loading {}: {error}", path.display()));
            let emitted = yaml::dump(&value)
                .unwrap_or_else(|error| panic!("dumping {}: {error}", path.display()));
            serde_json::json!({ "path": path.to_string_lossy(), "emitted": emitted })
        })
        .collect();

    let verdict = run_python(&serde_json::json!({ "kind": "configs", "files": files }));
    let reports = verdict["files"].as_object().expect("files");

    let mut broken = Vec::new();
    for path in &configs {
        let report = &reports[path.to_string_lossy().as_ref()];
        if report["equal"] != serde_json::Value::Bool(true) {
            broken.push(format!("  {}: values differ", display(path)));
        }
        if report["original_keys"] != report["emitted_keys"] {
            broken.push(format!(
                "  {}: top-level key order changed, {} -> {}",
                display(path),
                report["original_keys"],
                report["emitted_keys"]
            ));
        }
    }

    assert!(
        broken.is_empty(),
        "{} of {} configs do not survive the crossing into PyYAML {}:\n{}",
        broken.len(),
        configs.len(),
        verdict["pyyaml_version"],
        broken.join("\n")
    );
    println!(
        "{} committed configs crossed into PyYAML {} unchanged",
        configs.len(),
        verdict["pyyaml_version"]
    );
}

/// The reading half: what `yaml::load` produces must be what
/// `yaml.safe_load` produces.
///
/// This is the test that decides whether a user's `cage.yaml` keeps
/// meaning what it meant. The four corners it has to get right:
///
/// ```text
/// tls: no        PyYAML False   ->  bool(False) = False  ->  TLS off
/// tls: 'no'      PyYAML 'no'    ->  bool('no')  = True   ->  TLS on
/// tls: false     PyYAML False   ->  False                ->  TLS off
/// tls: "false"   PyYAML 'false' ->  bool('false') = True ->  TLS on
/// ```
///
/// Rows two and four are Python bugs — `bool()` of a non-empty string is
/// always `True` — but they fail *safe*, on a relay that carries
/// credentials upstream. Resolving the quoted spellings to `false` would
/// turn them into a silent TLS downgrade introduced by the port, so the
/// quote is honoured and `python_bool` reproduces the coercion.
///
/// Both halves are computed live: PyYAML's answer comes from the
/// interpreter, agentcage's from `yaml::load`, and neither is compared
/// against a table typed by hand.
#[test]
#[ignore = "needs a Python with PyYAML; run with --ignored (CI does)"]
fn the_read_side_agrees_with_pyyaml() {
    let fixture = fixture();
    assert!(
        fixture.read_side_cases.len() >= 25,
        "read-side corpus shrank to {}",
        fixture.read_side_cases.len()
    );

    let job = serde_json::json!({
        "kind": "documents",
        "cases": fixture.read_side_cases.iter().map(|case| serde_json::json!({
            "id": case.id,
            "yaml": case.yaml,
        })).collect::<Vec<_>>(),
    });
    let verdict = run_python(&job);
    let reports = verdict["cases"].as_object().expect("cases");

    let mut wrong = Vec::new();
    for case in &fixture.read_side_cases {
        let loaded = match yaml::load_named(&case.id, &case.yaml) {
            Ok(value) => value,
            Err(error) => {
                wrong.push(format!("  {:<22} agentcage refused it: {error}", case.id));
                continue;
            }
        };

        let report = &reports[&case.id];
        let ours = describe(&loaded);
        let theirs = report["described"].as_str().expect("described");
        if ours != theirs {
            wrong.push(format!(
                "  {:<22} {:?}\n      PyYAML:    {theirs}\n      agentcage: {ours}\n      ({})",
                case.id, case.yaml, case.why
            ));
        }

        // And the coercion config.py actually applies to the value.
        if let Some(expected) = report["bool_of_tls"].as_bool() {
            let ours = yaml::python_bool(&loaded["tls"]);
            if ours != expected {
                wrong.push(format!(
                    "  {:<22} {:?} -- bool(tls) is {expected} in Python and {ours} here. \
                     This is the TLS flip; see the test docs.",
                    case.id, case.yaml
                ));
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} documents mean something different to agentcage than to PyYAML {}:\n{}",
        wrong.len(),
        fixture.read_side_cases.len(),
        verdict["pyyaml_version"],
        wrong.join("\n")
    );
    println!(
        "{} documents read identically by agentcage and PyYAML {}",
        fixture.read_side_cases.len(),
        verdict["pyyaml_version"]
    );
}

/// The Rust half of the canonical rendering the Python side builds.
///
/// Deliberately mirrors `describe` in `CROSSING_SCRIPT` line for line,
/// including the ordered rendering of mappings, so that a key-order
/// change shows up as a difference rather than being compared away.
fn describe(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(flag) => format!("bool:{flag}"),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                format!("int:{integer}")
            } else if let Some(unsigned) = number.as_u64() {
                format!("int:{unsigned}")
            } else {
                format!("float:{}", number.as_f64().expect("a number"))
            }
        }
        Value::String(text) => format!("str:{text}"),
        Value::Sequence(items) => {
            let rendered: Vec<String> = items.iter().map(describe).collect();
            format!("seq[{}]", rendered.join(","))
        }
        Value::Mapping(mapping) => {
            let rendered: Vec<String> = mapping
                .iter()
                .map(|(key, value)| format!("{}=>{}", describe(key), describe(value)))
                .collect();
            format!("map{{{}}}", rendered.join(","))
        }
        Value::Tagged(tagged) => format!("other:{}", tagged.tag),
    }
}

/// Path relative to the repo root, for readable failures.
fn display(path: &Path) -> String {
    path.strip_prefix(common::repo_root())
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}
