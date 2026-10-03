//! The golden corpus, against the apple-container generation half.
//!
//! Every `isolation: apple-container` case in `tests/fixtures/golden/`
//! records two artifacts this crate produces:
//!
//! * `quadlets/<cage>.json` — `AppleContainerBackend.generate_units`.
//!   It lives in the `quadlets/` directory despite not being a quadlet
//!   because that is the directory `fingerprint-inputs.json` names as
//!   "the units", and the fingerprint hashes it exactly as it hashes a
//!   `.container` file on the container backend.
//! * `launchd/io.agentcage.<cage>.plist` — what
//!   `_install_launchd_plist` writes. The harness calls the **real**
//!   installer with `_gui_domain_reachable` pinned to `False`, so the
//!   recorded bytes come from the Python's own f-string rather than
//!   from a copy of it in the generator.
//!
//! Before PR E3 both directories were a single `NOT-APPLICABLE.txt`
//! (PR C8 recorded the gap and assigned it to Track E). This test is
//! the other half of closing it.
//!
//! # Why this one does not build a filesystem
//!
//! `golden_quadlets.rs` rebuilds the harness's sandbox and renders
//! against real absolute paths, because `quadlets.py` runs
//! `shlex.quote` over host paths and `shlex.quote("{{HOME}}/x")` quotes
//! where `shlex.quote("/tmp/…/home/x")` does not — so the scrub has to
//! happen *after* the render.
//!
//! Nothing in the apple generation half does that. The unit JSON
//! interpolates `container.env` values through `os.path.expandvars` and
//! nothing else; the plist interpolates two paths verbatim. No
//! quoting, no `realpath`, no length- or content-sensitive step. So
//! this test renders directly in *scrubbed space* — it hands the
//! renderer `{{HOME}}/agent` as `GOLDEN_AGENT_DIR` and compares the
//! result to the corpus byte for byte, with no scrubber in the middle.
//! Fewer moving parts, and the ones that remain are the ones under
//! test.
//!
//! # What is injected rather than computed
//!
//! The `volumes` field is `_user_volume_argv`, which expands `~` and
//! `$VAR`, calls `realpath`, refuses a source outside the home
//! directory and warns on each skip. It belongs to PR E2 and it is not
//! in `agentcage-core` at all — `generate_units` takes the resolved
//! list as a parameter for that reason. So this test reads the recorded
//! `volumes` array back out of the corpus and feeds it in. That one
//! field is therefore not checked here; every other byte of the
//! document is, and E2 owns the function that produces it. When E2
//! lands, this is the call site to point at the real thing.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use agentcage_core::apple::{generate_units, plist_text};
use agentcage_core::config::{Config, FixedHost, load};
use agentcage_core::quadlets::QuadletHost;

use common::repo_root;

/// What the harness pins `apple_container.cli.container_binary()` to.
///
/// `shutil.which` over `PATH` plus `/usr/local/bin/container` and
/// `/opt/homebrew/bin/container`, which answers `None` on every machine
/// that is not a Mac with the `.pkg` installed — so without the pin
/// there would be no plist to record at all.
const FROZEN_CONTAINER_BINARY: &str = "/usr/local/bin/container";

/// What it pins `config._host_dns_servers()` to.
const FROZEN_DNS_SERVERS: [&str; 2] = ["192.0.2.53", "192.0.2.54"];

fn corpus() -> PathBuf {
    repo_root().join("tests/fixtures/golden")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

/// The `isolation: apple-container` cases, by name, in manifest order.
fn apple_cases() -> Vec<String> {
    let text = read(&corpus().join("manifest.json"));
    let document: serde_json::Value = serde_json::from_str(&text).expect("manifest JSON");
    document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter(|case| {
            case["kind"] == "valid" && case["isolation"].as_str() == Some("apple-container")
        })
        .map(|case| case["case"].as_str().expect("case").to_owned())
        .collect()
}

/// `config.default_isolation()` on the platform the harness pinned for
/// these cases: Darwin / arm64, which is the only combination that
/// validates `isolation: apple-container` at all.
fn darwin_probe() -> FixedHost {
    FixedHost {
        isolation: "apple-container".to_owned(),
        dns_servers: Ok(FROZEN_DNS_SERVERS
            .iter()
            .map(|server| (*server).to_owned())
            .collect()),
    }
}

/// The harness's sandbox environment, already scrubbed.
///
/// Only `env_var` is ever reached: `generate_units` uses the host for
/// `os.path.expandvars` over `container.env` values and for nothing
/// else. The filesystem methods panic rather than returning a plausible
/// answer, so a future caller that starts probing the disk fails loudly
/// here instead of silently agreeing with a corpus generated against a
/// real tree.
struct ScrubbedHost;

impl QuadletHost for ScrubbedHost {
    fn env_var(&self, name: &str) -> Option<String> {
        match name {
            "HOME" => Some("{{HOME}}".to_owned()),
            "XDG_CONFIG_HOME" => Some("{{XDG_CONFIG_HOME}}".to_owned()),
            "XDG_DATA_HOME" => Some("{{XDG_DATA_HOME}}".to_owned()),
            "XDG_RUNTIME_DIR" => Some("{{XDG_RUNTIME_DIR}}".to_owned()),
            "GOLDEN_AGENT_DIR" => Some("{{HOME}}/agent".to_owned()),
            "GOLDEN_SET_VAR" => Some("set-value".to_owned()),
            "TZ" => Some("UTC".to_owned()),
            // GOLDEN_UNSET_VAR is deliberately absent, as in the
            // harness: it is what makes an unresolved `$VAR` reachable.
            _ => None,
        }
    }

    fn realpath(&self, _path: &str) -> String {
        unreachable!("the apple generation half never calls realpath")
    }

    fn exists(&self, _path: &str) -> bool {
        unreachable!("the apple generation half never probes the filesystem")
    }

    fn is_dir(&self, _path: &str) -> bool {
        unreachable!("the apple generation half never probes the filesystem")
    }

    fn stage_vm_file_volume(&self, _source: &str, _deploy_name: &str) -> Result<String, String> {
        unreachable!("vm-only")
    }

    fn detect_default_creds_scope(&self) -> Option<String> {
        unreachable!("the apple generation half never resolves a creds scope")
    }
}

/// `Paths::apple_state_dir`, in scrubbed space.
///
/// `~/.config/agentcage/apple-container/<cage>` —
/// `backends/apple_container.py:206`, an `expanduser` with no XDG
/// lookup anywhere near it. The corpus cannot tell that apart from an
/// XDG-derived root: the harness's sandbox sets `XDG_CONFIG_HOME` to
/// `$HOME/.config` and the scrubber prefers the longer rule, so the
/// recorded plist says `{{XDG_CONFIG_HOME}}`. The distinction is real —
/// an `XDG_CONFIG_HOME` sandbox does **not** redirect this root — and
/// it is pinned where it can be, in `agentcage-state`'s `Paths` tests.
fn apple_state_dir(name: &str) -> String {
    format!("{{{{XDG_CONFIG_HOME}}}}/agentcage/apple-container/{name}")
}

/// `_user_volume_argv`'s answer, read back out of the recorded unit.
///
/// See the module docs: PR E2 owns that function.
fn recorded_volumes(unit: &str) -> Vec<String> {
    let document: serde_json::Value = serde_json::from_str(unit).expect("recorded unit is JSON");
    document["volumes"]
        .as_array()
        .expect("the unit records a volumes array")
        .iter()
        .map(|entry| entry.as_str().expect("a volume string").to_owned())
        .collect()
}

fn load_case(name: &str) -> (Config, PathBuf) {
    let directory = corpus().join("valid").join(name);
    let stored = read(&directory.join("stored-cage.yaml"));
    let config = load("cage.yaml", &stored, &darwin_probe())
        .unwrap_or_else(|error| panic!("{name}: stored config does not load: {error}"));
    (config, directory)
}

/// The acceptance check for `generate_units`: every recorded unit,
/// byte for byte.
#[test]
fn every_apple_case_reproduces_its_unit_json() {
    let cases = apple_cases();
    let mut wrong: Vec<String> = Vec::new();

    for name in &cases {
        let (config, directory) = load_case(name);
        let recorded = read(&directory.join("quadlets").join(format!("{name}.json")));
        let volumes = recorded_volumes(&recorded);

        let produced = generate_units(&config, name, &volumes, &ScrubbedHost);
        let expected: BTreeMap<String, String> =
            [(format!("{name}.json"), recorded)].into_iter().collect();
        if produced != expected {
            let produced_text = produced
                .get(&format!("{name}.json"))
                .map_or("<missing>", String::as_str);
            let expected_text = expected[&format!("{name}.json")].as_str();
            wrong.push(format!(
                "{name}:\n--- corpus\n{expected_text}\n--- produced\n{produced_text}"
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} apple-container cases diverge:\n\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n\n")
    );
    assert_eq!(
        cases.len(),
        8,
        "the corpus's apple-container case count moved"
    );
}

/// The acceptance check for the plist.
#[test]
fn every_apple_case_reproduces_its_launchd_plist() {
    let cases = apple_cases();
    for name in &cases {
        let directory = corpus().join("valid").join(name);
        let recorded = read(
            &directory
                .join("launchd")
                .join(format!("io.agentcage.{name}.plist")),
        );
        let produced = plist_text(name, FROZEN_CONTAINER_BINARY, &apple_state_dir(name));
        assert_eq!(produced, recorded, "{name}: plist differs");
    }
    assert!(!cases.is_empty(), "no apple-container cases in the corpus");
}

/// The gap PR C8 reported, asserted closed.
///
/// `tests/fixtures/golden/README.md` used to list "apple-container
/// units are not captured" under Known gaps, and each such case carried
/// a `quadlets/NOT-APPLICABLE.txt` where the units would be. If either
/// ever comes back, this fails rather than the two tests above quietly
/// checking nothing.
#[test]
fn no_apple_case_still_carries_the_not_applicable_marker() {
    for name in apple_cases() {
        let directory = corpus().join("valid").join(&name);
        assert!(
            !directory.join("quadlets/NOT-APPLICABLE.txt").exists(),
            "{name} still carries the NOT-APPLICABLE marker"
        );
        assert!(
            directory
                .join("quadlets")
                .join(format!("{name}.json"))
                .is_file(),
            "{name} has no recorded unit"
        );
        assert!(
            directory
                .join("launchd")
                .join(format!("io.agentcage.{name}.plist"))
                .is_file(),
            "{name} has no recorded launchd plist"
        );
    }
}
