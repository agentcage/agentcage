//! The vm fixtures, against [`VmBackend::generate_units`].
//!
//! `tests/fixtures/vm/` records what the Python's
//! `backends/vm.py::VmBackend.generate_units` returned for ten cages:
//! the Lima YAML, every quadlet, the dict order, the stderr, and — for
//! the one case that raises — the `ValueError` a user would see. This
//! reproduces all of it byte for byte, which is PR E1's acceptance
//! check (RUST-PORT-PLAN.md Track E).
//!
//! # Why this test builds a filesystem, and an environment
//!
//! Same reason `golden_quadlets.rs` does: the renderer probes the host.
//! It expands `~` and `$VAR` in volume sources, calls `realpath`, skips
//! a source that does not exist, refuses one under `~/.ssh`, and copies
//! a single-file source for the guest to see. The generator answered
//! those from a hermetic tree under a temp directory, so this rebuilds
//! the same tree.
//!
//! The environment is the difference. `golden_quadlets.rs` answers
//! `QuadletHost` from a struct and never touches the process
//! environment; [`VmBackend`] is a *command* object that builds its own
//! [`RealQuadletHost`], so the sandbox has to reach it the way the real
//! one does. It goes through [`hostenv::publish_env`], the overlay the
//! `run` flow already uses to publish `PROJECT_DIR` without an unsafe
//! `setenv`. That overlay is process-wide, which is why this is its own
//! test binary: nothing else in it reads `HOME`.
//!
//! [`RealQuadletHost`]: agentcage_cli::hostenv::RealQuadletHost

use std::fs;
use std::path::{Path, PathBuf};

use agentcage_cli::hostenv;
use agentcage_cli::vm::VmBackend;
use agentcage_core::config::{FixedHost, load};
use agentcage_exec::FakeRunner;
use agentcage_state::Paths;

/// What the generator pins `importlib.metadata.version("agentcage")` to.
const FROZEN_VERSION: &str = "0.0.0-golden";

/// What it pins `config._host_dns_servers()` to.
const FROZEN_DNS_SERVERS: [&str; 2] = ["192.0.2.53", "192.0.2.54"];

/// What it pins `pwd.getpwuid(os.getuid()).pw_name` to.
const FROZEN_LIMA_USER: &str = "cageuser";

/// The repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn fixtures() -> PathBuf {
    repo_root().join("tests/fixtures/vm")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

/// One case, as `manifest.json` describes it.
#[derive(Debug)]
struct Case {
    name: String,
    kind: String,
    platform: Vec<String>,
    config_timeout_start_sec: Option<i64>,
    unit_timeout_start_sec: Option<i64>,
}

fn manifest() -> Vec<Case> {
    let document: serde_json::Value =
        serde_json::from_str(&read(&fixtures().join("manifest.json"))).expect("manifest JSON");
    document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| Case {
            name: case["case"].as_str().expect("case").to_owned(),
            kind: case["kind"].as_str().expect("kind").to_owned(),
            platform: case["platform"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            config_timeout_start_sec: case["config_timeout_start_sec"].as_i64(),
            unit_timeout_start_sec: case["unit_timeout_start_sec"].as_i64(),
        })
        .collect()
}

// ─── the hermetic tree ───────────────────────────────────────

/// The generator's sandbox, rebuilt.
///
/// `gen-vm-fixture.py` builds it by calling `gen-golden-corpus.py`'s
/// `_build_sandbox`, so this is the same directory list — a volume
/// source that does not exist is *skipped with a warning* rather than
/// failing, which means a missing directory here would not fail
/// loudly, it would quietly change the units.
struct Sandbox {
    root: PathBuf,
    home: PathBuf,
}

impl Sandbox {
    fn build(label: &str) -> Self {
        // Labelled per test: the two tests in this binary run on
        // different threads, and a shared root would have one's `Drop`
        // delete the other's tree mid-render.
        let root =
            std::env::temp_dir().join(format!("agentcage-vm-units-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("work dir");
        // Resolved once: on macOS `/tmp` is a symlink, and every path
        // that reaches a unit has been through `realpath`.
        let root = fs::canonicalize(&root).expect("canonical work dir");
        let home = root.join("home");
        for relative in [
            ".config/agentcage",
            ".local/share/agentcage",
            "agent",
            "project",
            "workspace",
            "data",
            "e2e-work/test-agent",
            "certs",
        ] {
            fs::create_dir_all(home.join(relative)).expect("sandbox dir");
        }
        fs::write(home.join("dotfile.conf"), "# fake dotfile\n").expect("dotfile");
        fs::create_dir_all(root.join("run")).expect("runtime dir");
        fs::create_dir_all(root.join("patches")).expect("patches dir");
        Self { root, home }
    }

    /// Publish the sandbox to every host probe in this process.
    ///
    /// The overlay wins over the real environment, so this is the
    /// hermetic tree even on a developer's machine with `HOME` set.
    fn publish(&self) {
        for (name, value) in [
            ("HOME", self.home.display().to_string()),
            (
                "XDG_CONFIG_HOME",
                self.home.join(".config").display().to_string(),
            ),
            (
                "XDG_DATA_HOME",
                self.home.join(".local/share").display().to_string(),
            ),
            (
                "XDG_RUNTIME_DIR",
                self.root.join("run").display().to_string(),
            ),
            ("TZ", "UTC".to_owned()),
            ("GOLDEN_SET_VAR", "set-value".to_owned()),
        ] {
            hostenv::publish_env(name, &value);
        }
    }

    fn paths(&self) -> Paths {
        Paths::from_roots(
            &self.home,
            self.home.join(".config"),
            self.home.join(".local/share"),
            self.root.join("run"),
        )
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The generator's `Scrubber`, for the rules these fixtures reach.
///
/// Longest prefix first, so `$HOME/.config` is not half-rewritten by
/// the `$HOME` rule.
///
/// Unlike `golden_quadlets.rs`'s, this one does **not** decode base64
/// blobs. It does not need to: no unit in this fixture embeds a
/// base64-encoded host path — that encoding is reached by tmpfs masks
/// and `np` overlay bookkeeping whose paths are `%t`-relative here. A
/// future case that did embed one would fail this test loudly rather
/// than pass by accident, and the decoder next door is what it would
/// borrow.
struct Scrubber {
    rules: Vec<(String, &'static str)>,
}

impl Scrubber {
    fn new(sandbox: &Sandbox) -> Self {
        let work = sandbox.root.display().to_string();
        let home = sandbox.home.display().to_string();
        let mut rules: Vec<(String, &'static str)> = vec![
            (format!("{home}/.local/share"), "{{XDG_DATA_HOME}}"),
            (format!("{home}/.config"), "{{XDG_CONFIG_HOME}}"),
            (home, "{{HOME}}"),
            (format!("{work}/run"), "{{XDG_RUNTIME_DIR}}"),
            (work, "{{WORK}}"),
            (repo_root().display().to_string(), "{{REPO}}"),
        ];
        rules.sort_by_key(|(raw, _)| std::cmp::Reverse(raw.len()));
        Self { rules }
    }

    fn text(&self, value: &str) -> String {
        let mut out = value.to_owned();
        for (raw, token) in &self.rules {
            if !raw.is_empty() && out.contains(raw.as_str()) {
                out = out.replace(raw.as_str(), token);
            }
        }
        out
    }
}

/// The host probe for the platform the generator pinned for a case.
fn host_probe(platform: &[String]) -> FixedHost {
    FixedHost {
        isolation: match platform.first().map(String::as_str) {
            Some("Darwin") => "vm".to_owned(),
            _ => "container".to_owned(),
        },
        dns_servers: Ok(FROZEN_DNS_SERVERS
            .iter()
            .map(|server| (*server).to_owned())
            .collect()),
    }
}

/// The first line that differs, with a little context.
fn first_difference(expected: &str, produced: &str) -> String {
    for (index, (want, got)) in expected.lines().zip(produced.lines()).enumerate() {
        if want != got {
            return format!(
                "  line {}\n  expected: {want:?}\n  produced: {got:?}",
                index + 1
            );
        }
    }
    format!(
        "  line counts differ: expected {}, produced {}",
        expected.lines().count(),
        produced.lines().count()
    )
}

// ─── the tests ───────────────────────────────────────────────

/// The acceptance check: every file `generate_units` returned.
/// Serialises the two tests in this binary.
///
/// `Sandbox::publish` writes `HOME` and the XDG roots into
/// `hostenv`'s process-global overlay, and `Sandbox`'s `Drop` deletes
/// its tree. `cargo test` runs both tests on one thread pool in one
/// process, so without this the second `publish` redirects the first
/// test mid-render, and the second sandbox's `Drop` then removes the
/// tree the first is still reading — which surfaces as
/// "host path does not exist" warnings against the *other* test's
/// sandbox path, a confusing way to learn about a race.
///
/// Labelling the roots per test (above) stops them sharing a
/// directory; it cannot stop them sharing the overlay.
static ONE_SANDBOX_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`ONE_SANDBOX_AT_A_TIME`], stepping over a poisoned lock.
///
/// The data behind it is `()`; letting one test's panic turn the other
/// red would hide the failure that actually matters.
fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    ONE_SANDBOX_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
// One case-walk over every fixture. Splitting it would mean threading the
// mismatch accumulator and the two counters through helpers for no gain in
// readability; the body is a single loop with its assertions inline.
#[allow(clippy::too_many_lines)]
fn every_case_reproduces_its_units() {
    let _serialised = exclusive();
    let sandbox = Sandbox::build("units");
    sandbox.publish();
    let scrubber = Scrubber::new(&sandbox);
    let paths = sandbox.paths();
    let root = fixtures();

    let mut wrong: Vec<String> = Vec::new();
    let mut checked_cases = 0;
    let mut checked_files = 0;

    for case in manifest() {
        let directory = root.join(&case.name);
        // A guest that does not exist: `limactl list --json` fails, so
        // `store_secrets` stays `None`. Exactly the stub the generator
        // patched `LimaInstance` with.
        let runner = FakeRunner::new();
        runner.assume_installed();
        runner.on(["limactl"], agentcage_exec::Reply::status(1));
        let backend = VmBackend::with_facts(
            &paths,
            &runner,
            FROZEN_VERSION,
            case.platform.first().map_or("Linux", String::as_str),
            FROZEN_LIMA_USER,
        );

        let stored_path = directory.join("stored-cage.yaml");
        let input = read(&directory.join("input/cage.yaml"));
        let source = if stored_path.is_file() {
            read(&stored_path)
        } else {
            // The refusing case never gets a stored config written.
            input
        };
        let config = match load("cage.yaml", &source, &host_probe(&case.platform)) {
            Ok(config) => config,
            Err(error) => {
                wrong.push(format!("{}: config does not load: {error}", case.name));
                continue;
            }
        };

        let deploy = config.name.clone();
        let config_host_path = paths.stored_config_path(&deploy).display().to_string();
        let patches = sandbox.root.join("patches").display().to_string();
        let produced =
            backend.generate_units(&config, &config_host_path, &patches, &deploy, None, None);

        if case.kind == "invalid" {
            let expected = read(&directory.join("error.txt"));
            let actual = match produced {
                Ok(_) => {
                    wrong.push(format!("{}: expected a refusal, got units", case.name));
                    continue;
                }
                Err(agentcage_cli::backend::BackendError::Config(error)) => {
                    format!("{}\n", error.as_python_traceback_line())
                }
                Err(other) => {
                    wrong.push(format!("{}: wrong error type: {other}", case.name));
                    continue;
                }
            };
            checked_cases += 1;
            if scrubber.text(&actual) != expected {
                wrong.push(format!(
                    "{}/error.txt:\n  expected: {expected:?}\n  produced: {actual:?}",
                    case.name
                ));
            }
            continue;
        }

        let produced = match produced {
            Ok(produced) => produced,
            Err(error) => {
                wrong.push(format!("{}: render failed: {error}", case.name));
                continue;
            }
        };
        checked_cases += 1;

        // Dict order, which `install_units` writes in and which puts
        // `lima.yaml` first.
        let expected_order: Vec<String> =
            serde_json::from_str(&read(&directory.join("unit-order.json"))).expect("order JSON");
        let produced_order: Vec<String> = produced.files.keys().cloned().collect();
        if produced_order != expected_order {
            wrong.push(format!(
                "{}: unit order differs\n  expected: {expected_order:?}\n  produced: {produced_order:?}",
                case.name
            ));
            continue;
        }

        for (filename, content) in &produced.files {
            let expected = read(&directory.join("units").join(filename));
            let actual = scrubber.text(content);
            checked_files += 1;
            if actual != expected {
                wrong.push(format!(
                    "{}/units/{filename}:\n{}",
                    case.name,
                    first_difference(&expected, &actual)
                ));
            }
        }

        // The warnings are the Python's stderr, and they are what an
        // operator sees when a volume is skipped — byte-exact too.
        let expected_warnings = read(&directory.join("render-warnings.txt"));
        let mut actual_warnings = String::new();
        for warning in &produced.warnings {
            actual_warnings.push_str(&scrubber.text(warning));
            actual_warnings.push('\n');
        }
        if actual_warnings != expected_warnings {
            wrong.push(format!(
                "{}/render-warnings.txt:\n  expected: {expected_warnings:?}\n  produced: {actual_warnings:?}",
                case.name
            ));
        }

        // The floor, read back off the rendered unit rather than off
        // the config, because the unit is what systemd sees. The
        // config's own value is checked too: the floor is applied to a
        // deepcopy, so a `cage update` re-render has to see the
        // original.
        assert_eq!(
            case.config_timeout_start_sec,
            Some(config.container.timeout_start_sec),
            "{}: generate_units mutated the caller's config",
            case.name
        );
        if let Some(expected) = case.unit_timeout_start_sec {
            let cage_unit = produced
                .files
                .iter()
                .find(|(name, _)| name.ends_with("-cage.container"))
                .map(|(_, body)| body.clone())
                .unwrap_or_default();
            let line = format!("TimeoutStartSec={expected}");
            assert!(
                cage_unit.lines().any(|l| l == line),
                "{}: {line} not in the cage unit",
                case.name
            );
        }
    }

    assert!(
        wrong.is_empty(),
        "{} mismatch(es):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert!(checked_cases >= 10, "only {checked_cases} cases checked");
    assert!(checked_files >= 50, "only {checked_files} files checked");
}

/// The floor is applied to a copy, not to the caller's config.
///
/// `cage update` fingerprints the parsed config and re-renders from it;
/// a floor that mutated it in place would make the second render differ
/// from the first and report a change that is not one. The Python takes
/// a `copy.deepcopy` for this reason and `test_vm_backend.py` pins the
/// resulting `TimeoutStartSec`, but not the absence of the mutation.
#[test]
fn the_floor_does_not_reach_the_callers_config() {
    let _serialised = exclusive();
    let sandbox = Sandbox::build("floor");
    sandbox.publish();
    let paths = sandbox.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    runner.on(["limactl"], agentcage_exec::Reply::status(1));
    let backend = VmBackend::with_facts(&paths, &runner, FROZEN_VERSION, "Linux", FROZEN_LIMA_USER);

    let source = read(&fixtures().join("timeout-floored/stored-cage.yaml"));
    let config = load("cage.yaml", &source, &host_probe(&["Linux".to_owned()])).expect("loads");
    assert_eq!(config.container.timeout_start_sec, 60);

    let patches = sandbox.root.join("patches").display().to_string();
    let first = backend
        .generate_units(
            &config,
            "/tmp/cage.yaml",
            &patches,
            &config.name,
            None,
            None,
        )
        .expect("renders");
    assert_eq!(
        config.container.timeout_start_sec, 60,
        "generate_units mutated the caller's config"
    );
    let second = backend
        .generate_units(
            &config,
            "/tmp/cage.yaml",
            &patches,
            &config.name,
            None,
            None,
        )
        .expect("renders");
    assert_eq!(
        first.files, second.files,
        "repeated generation is not deterministic"
    );
}
