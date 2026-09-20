//! The port vs. `tests/fixtures/doctor/environments.json`, byte for byte.
//!
//! # What is being proved
//!
//! `agentcage doctor` answers questions about the machine, so its output
//! on the CI runner says nothing useful about the code: the runner has
//! podman, has systemd, has no Lima and is not a Mac, and that is one
//! host out of the dozens an operator runs this on.
//!
//! So the fixture is a *matrix of hosts*. Each case declares what every
//! probe answers, and `scripts/gen-doctor-fixture.py` recorded what the
//! real `agentcage.doctor.run_doctor` printed when every probe was made
//! to answer that way. This file rebuilds the same host out of a
//! [`FakeRunner`] and a fake [`DoctorHost`] and requires the same bytes
//! back, in both colour modes.
//!
//! `CommandRunner::which` being on the trait is what makes the
//! missing-binary half of that reachable at all — PR D1 put it there for
//! exactly this, and `doctor` is the command that needed it most.
//!
//! # Two things the fixture records and this file does not reproduce
//!
//! `_safe_check` catches any exception a check raises and reports
//! `"<label> crashed: <exc>"`. Two cases drive that — a `disk_usage`
//! that raises something other than `OSError`, and `podman network ls`
//! printing non-JSON. The ported checks are total functions with no
//! exception path, so there is nothing to catch. Those cases carry
//! `"ported": false` and a reason, and [`the_unported_set_is_exactly_the_two_crash_cases`]
//! pins the set so a third one cannot be added by marking it unported.

use std::collections::{BTreeMap, BTreeSet};

use agentcage_cli::doctor::{self, CheckResult, DnsOutcome, DoctorHost, Level};
use agentcage_exec::{FakeRunner, Reply};
use serde_json::Value;

/// Every environment in the fixture, ported and unported.
const TOTAL_CASES: usize = 39;

/// The cases whose Python behaviour comes from `_safe_check`.
const UNPORTED: [&str; 2] = ["linux-check-crashes", "linux-subnet-json-garbage"];

fn fixture() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/doctor/environments.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn cases(doc: &Value) -> &Vec<Value> {
    doc["cases"].as_array().expect("cases")
}

fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

// ── the faked host ───────────────────────────────────────────

/// A [`DoctorHost`] built from one fixture case's `env` block.
#[derive(Debug)]
struct FakeHost {
    macos: bool,
    os_release: Option<String>,
    existing_paths: BTreeSet<String>,
    disk: Value,
    dns: Value,
    ports: BTreeMap<u16, bool>,
    env_vars: BTreeMap<String, String>,
    euid: i64,
    apple_issues: Vec<String>,
}

impl FakeHost {
    fn from_json(env: &Value) -> Self {
        Self {
            macos: env["macos"].as_bool().expect("macos"),
            os_release: env["os_release"].as_str().map(str::to_owned),
            existing_paths: env["existing_paths"]
                .as_array()
                .expect("existing_paths")
                .iter()
                .map(|v| v.as_str().expect("a path").to_owned())
                .collect(),
            disk: env["disk"].clone(),
            dns: env["dns"].clone(),
            ports: env["ports"]
                .as_object()
                .expect("ports")
                .iter()
                .map(|(k, v)| {
                    (
                        k.parse().expect("a port number"),
                        v.as_bool().expect("bool"),
                    )
                })
                .collect(),
            env_vars: env["env_vars"]
                .as_object()
                .expect("env_vars")
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().expect("a string").to_owned()))
                .collect(),
            euid: env["euid"].as_i64().expect("euid"),
            apple_issues: env["apple_issues"]
                .as_array()
                .expect("apple_issues")
                .iter()
                .map(|v| v.as_str().expect("an issue").to_owned())
                .collect(),
        }
    }
}

impl DoctorHost for FakeHost {
    fn is_macos(&self) -> bool {
        self.macos
    }

    fn os_release(&self) -> Option<String> {
        self.os_release.clone()
    }

    fn path_exists(&self, path: &str) -> Result<bool, String> {
        // The generator's sentinel for "the `exists()` call itself
        // raised", which is `check_cgroup_v2`'s `except OSError`.
        if self.existing_paths.contains("cgroup-crash") {
            return Err("permission denied".to_owned());
        }
        Ok(self.existing_paths.contains(path))
    }

    fn disk_free_bytes(&self) -> Result<u64, String> {
        match str_at(&self.disk, "kind") {
            "free" => Ok(self.disk["bytes"].as_u64().expect("bytes")),
            "error" => Err(str_at(&self.disk, "message").to_owned()),
            other => panic!("{other}: only an unported case declares this disk kind"),
        }
    }

    fn resolve_dns(&self) -> DnsOutcome {
        match str_at(&self.dns, "kind") {
            "ok" => DnsOutcome::Resolved,
            "gaierror" => DnsOutcome::NameError,
            "timeout" => DnsOutcome::TimedOut,
            "oserror" => DnsOutcome::Failed(str_at(&self.dns, "message").to_owned()),
            other => panic!("unknown dns kind: {other}"),
        }
    }

    fn port_is_free(&self, port: u16) -> bool {
        *self
            .ports
            .get(&port)
            .unwrap_or_else(|| panic!("the fixture declares no answer for port {port}"))
    }

    fn env_var(&self, name: &str) -> Option<String> {
        self.env_vars.get(name).cloned()
    }

    fn non_root(&self) -> bool {
        self.euid != 0
    }

    fn apple_container_issues(&self) -> Vec<String> {
        self.apple_issues.clone()
    }
}

// ── the faked subprocess layer ───────────────────────────────

/// Build a [`FakeRunner`] from a case's `env` block and the fixture's
/// shared `command_keys` table.
///
/// Every key in that table gets a rule, whether or not the case named
/// it: an unnamed probe is one the Python's fake answered with
/// `FileNotFoundError`, and leaving it unstubbed would turn a
/// deliberately-absent binary into a panic. A probe that is in *neither*
/// still panics, which is the point — a new subprocess in `doctor` must
/// be declared on both sides.
fn runner_for(doc: &Value, env: &Value) -> FakeRunner {
    let fake = FakeRunner::new();
    fake.assume_missing();

    for (program, path) in env["which"].as_object().expect("which") {
        match path.as_str() {
            Some(p) => {
                fake.stub_which(program, p);
            }
            None => {
                fake.stub_missing(program);
            }
        }
    }

    let declared = env["commands"].as_object().expect("commands");
    // Longest prefix first: `FakeRunner::on` takes the first matching
    // rule, so a shorter prefix registered earlier would shadow a longer
    // one. None of today's keys overlap; sorting means that stays true
    // when one does.
    let mut keys: Vec<(&String, Vec<String>)> = doc["command_keys"]
        .as_object()
        .expect("command_keys")
        .iter()
        .map(|(key, argv)| {
            let prefix = argv
                .as_array()
                .expect("an argv")
                .iter()
                .map(|a| a.as_str().expect("an argument").to_owned())
                .collect();
            (key, prefix)
        })
        .collect();
    keys.sort_by_key(|(_, prefix)| std::cmp::Reverse(prefix.len()));

    for (key, prefix) in keys {
        let reply = declared.get(key).map_or(Reply::NotFound, reply_for);
        fake.on(prefix, reply);
    }
    fake
}

fn reply_for(spec: &Value) -> Reply {
    match str_at(spec, "kind") {
        "ok" => Reply::ok(str_at(spec, "stdout")),
        "rc" => {
            let code = i32::try_from(spec["code"].as_i64().expect("code")).expect("an exit code");
            // The Python's fake puts its bytes on stdout whatever the
            // exit status, and two checks read stdout on a non-zero exit.
            Reply::Ran(agentcage_exec::Output {
                status: agentcage_exec::ExitStatus::exited(code),
                stdout: spec["stdout"].as_str().unwrap_or_default().into(),
                stderr: Vec::new(),
            })
        }
        "missing" => Reply::NotFound,
        "timeout" => Reply::TimedOut,
        other => panic!("unknown command kind: {other}"),
    }
}

// ── the assertions ───────────────────────────────────────────

fn result_json(r: &CheckResult) -> Value {
    serde_json::json!({
        "level": r.level.as_str(),
        "message": r.message,
        "hint": r.hint,
    })
}

fn ported_cases(doc: &Value) -> Vec<&Value> {
    cases(doc)
        .iter()
        .filter(|c| c["ported"].as_bool().expect("ported"))
        .collect()
}

/// The whole point: the bytes, for every host the fixture declares.
#[test]
fn every_environment_reproduces_the_python_output() {
    let doc = fixture();
    let mut checked = 0;
    for case in ported_cases(&doc) {
        let id = str_at(case, "id");
        let env = &case["env"];
        let host = FakeHost::from_json(env);
        let runner = runner_for(&doc, env);

        let report = doctor::run(&runner, &host);

        let color = doctor::render(&report, true);
        let plain = doctor::render(&report, false);
        assert_eq!(
            color,
            str_at(&case["expected"], "color"),
            "{id}: styled output differs from the Python's ({})",
            str_at(case, "why")
        );
        assert_eq!(
            plain,
            str_at(&case["expected"], "plain"),
            "{id}: piped output differs from the Python's ({})",
            str_at(case, "why")
        );
        checked += 1;
    }
    assert_eq!(checked, TOTAL_CASES - UNPORTED.len());
}

/// The structured half, which is what a caller other than the printer
/// would read — and which localizes a failure to one check.
#[test]
fn every_environment_reproduces_the_python_results() {
    let doc = fixture();
    for case in ported_cases(&doc) {
        let id = str_at(case, "id");
        let host = FakeHost::from_json(&case["env"]);
        let runner = runner_for(&doc, &case["env"]);

        let report = doctor::run(&runner, &host);
        let produced: Vec<Value> = report.results().map(result_json).collect();
        let expected = case["expected_results"].as_array().expect("results");
        assert_eq!(&produced, expected, "{id}: check results differ");
    }
}

/// `cli.py:632`: one error anywhere makes the whole run exit 1.
#[test]
fn the_exit_code_is_one_if_and_only_if_something_errored() {
    let doc = fixture();
    for case in ported_cases(&doc) {
        let id = str_at(case, "id");
        let host = FakeHost::from_json(&case["env"]);
        let runner = runner_for(&doc, &case["env"]);
        let report = doctor::run(&runner, &host);
        let expected =
            u8::try_from(case["exit_code"].as_u64().expect("exit_code")).expect("0 or 1");
        assert_eq!(report.exit_code(), expected, "{id}: wrong exit code");
        assert_eq!(
            report.exit_code() == 1,
            report.results().any(|r| r.level == Level::Error),
            "{id}: the exit code and the results disagree"
        );
    }
}

/// PR D4's invariant, restated for this command: colour only ever *adds*
/// escapes, so the piped form is the styled form stripped. The generator
/// asserts the same thing on the Python side before recording.
#[test]
fn colour_only_adds_escapes() {
    let doc = fixture();
    for case in ported_cases(&doc) {
        let id = str_at(case, "id");
        let host = FakeHost::from_json(&case["env"]);
        let runner = runner_for(&doc, &case["env"]);
        let report = doctor::run(&runner, &host);
        assert_eq!(
            agentcage_cli::output::strip_ansi(&doctor::render(&report, true)),
            doctor::render(&report, false),
            "{id}: the two modes differ by more than the escapes"
        );
    }
}

/// The deletion, stated as a test.
///
/// The port drops `check_python_version` (RUST-PORT-PLAN.md §2.4: the
/// host no longer needs Python). The fixture records what the Python
/// printed *and* what it printed minus that one line; this asserts the
/// difference is exactly one line, that it is the Python-version line,
/// and that the port emits nothing resembling it.
#[test]
fn the_python_version_check_is_gone_and_nothing_else_went_with_it() {
    let doc = fixture();
    let pinned = str_at(&doc, "pinned_python_version");
    for case in cases(&doc) {
        let id = str_at(case, "id");
        let dropped = case["dropped"].as_array().expect("dropped");
        assert_eq!(dropped.len(), 1, "{id}: expected exactly one dropped line");
        let line = dropped[0].as_str().expect("a line");
        assert!(
            line.contains(&format!("Python {pinned}")),
            "{id}: the dropped line is not the Python-version line: {line:?}"
        );

        let full = str_at(&case["python"], "plain");
        let expected = str_at(&case["expected"], "plain");
        assert_eq!(
            full.lines().count(),
            expected.lines().count() + 1,
            "{id}: dropping the Python check removed more than one line"
        );
    }

    for case in ported_cases(&doc) {
        let host = FakeHost::from_json(&case["env"]);
        let runner = runner_for(&doc, &case["env"]);
        let report = doctor::run(&runner, &host);
        assert!(
            !report.results().any(|r| r.message.starts_with("Python ")),
            "{}: the port still reports a host Python version",
            str_at(case, "id")
        );
    }
}

/// The unported set is closed.
///
/// Both members are `_safe_check` catching an exception, which the port
/// has no counterpart for (see the module docs). Pinning the set by name
/// means a future case cannot be excused from the golden comparison by
/// flipping a flag.
#[test]
fn the_unported_set_is_exactly_the_two_crash_cases() {
    let doc = fixture();
    assert_eq!(cases(&doc).len(), TOTAL_CASES, "the fixture changed size");

    let unported: Vec<&str> = cases(&doc)
        .iter()
        .filter(|c| !c["ported"].as_bool().expect("ported"))
        .map(|c| str_at(c, "id"))
        .collect();
    assert_eq!(unported, UNPORTED);

    for case in cases(&doc) {
        if !case["ported"].as_bool().expect("ported") {
            let why = str_at(case, "not_ported_because");
            assert!(
                why.contains("_safe_check"),
                "{}: an unported case must say which exception path it is",
                str_at(case, "id")
            );
            assert!(
                str_at(&case["python"], "plain").contains("crashed:"),
                "{}: an unported case must actually be a crash",
                str_at(case, "id")
            );
        }
    }
}

/// The ports the doctor probes are the fixture's, in the fixture's
/// order — a check that costs nothing and would catch a port that
/// silently added or reordered one.
#[test]
fn the_probed_ports_agree_with_the_fixture() {
    let doc = fixture();
    let expected: Vec<u16> = doc["common_ports"]
        .as_array()
        .expect("common_ports")
        .iter()
        .map(|p| u16::try_from(p.as_u64().expect("a port")).expect("a port"))
        .collect();
    assert_eq!(doctor::COMMON_PORTS.to_vec(), expected);
}

/// The fake answers `which` for everything, so a real lookup never
/// escapes into the test process — and the doctor does ask, on both
/// platforms.
#[test]
fn the_doctor_asks_which_rather_than_probing_the_real_path() {
    let doc = fixture();
    for id in ["linux-healthy", "macos-healthy"] {
        let case = cases(&doc)
            .iter()
            .find(|c| str_at(c, "id") == id)
            .expect("case");
        let host = FakeHost::from_json(&case["env"]);
        let runner = runner_for(&doc, &case["env"]);
        let _ = doctor::run(&runner, &host);
        assert!(
            !runner.which_lookups().is_empty(),
            "{id}: no `which` lookup, so the missing-binary branches are \
             being decided somewhere the fake cannot reach"
        );
    }
}
