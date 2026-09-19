//! The golden corpus, against the three derived files the deploy path
//! writes.
//!
//! `tests/fixtures/golden/valid/<case>/` records what the Python
//! produced for each config, and PR C8's `golden_quadlets.rs` already
//! reproduces the unit files and `dns-allowlist.conf` from
//! `agentcage-core`'s side. What it cannot reach is the *writers*:
//! `save_proxy_config` and `save_placeholders_env` are I/O, so they live
//! here, and until now nothing checked their output against the corpus —
//! D2's tests check them against the A7 state fixtures, which cover
//! three cages rather than 125 configs.
//!
//! That gap matters for this PR (Track D, D6) because `cage create`
//! writes all three before the egress ever starts, and two of them are
//! read by code on the *other* side of the trust boundary:
//! `proxy-config.yaml` by the mitmproxy addon and `placeholders.env` by
//! the cage quadlet's `EnvironmentFile=`. A drift here is not a failed
//! command, it is a cage that comes up with the wrong policy.

use std::fs;
use std::path::{Path, PathBuf};

use agentcage_core::config::{ConfigError, FixedHost};
use agentcage_core::har::json::{Json, parse};
use agentcage_state::{Paths, TestDir};

/// What the harness pins `importlib.metadata.version("agentcage")` to.
///
/// `save_proxy_config` stamps it into the document, so the corpus would
/// churn on every release without it.
const FROZEN_VERSION: &str = "0.0.0-golden";

/// What it pins `config._host_dns_servers()` to.
const FROZEN_DNS_SERVERS: [&str; 2] = ["192.0.2.53", "192.0.2.54"];

/// The one case this test cannot run, and why.
///
/// `relay-imap-ca-file` declares `ca_file: ${HOME}/certs/fake-ca.pem`,
/// and `resolve_relay_ca_files` expands `$HOME` from the **process**
/// environment — deliberately, because that is what the Python does and
/// an operator's `~` is the only meaning that path can have. The corpus
/// harness ran with `HOME` pointed at a sandbox holding that file; a
/// test cannot reproduce that without either setting `HOME` (unsound:
/// `std::env::set_var` races every other test in the binary, and this
/// workspace forbids the `unsafe` it now requires) or writing into the
/// developer's real home.
///
/// The path it exercises is not unchecked: `state_compat.rs` covers the
/// PEM inlining against the A7 fixtures, where the file is inside the
/// fixture tree.
const UNREACHABLE_CASES: [&str; 1] = ["relay-imap-ca-file"];

fn repo_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `<repo>/rust/agentcage-state`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate is two levels below the repo root")
        .to_path_buf()
}

fn corpus() -> PathBuf {
    repo_root().join("tests/fixtures/golden")
}

/// One case's name and the platform the harness pinned for it.
struct Case {
    name: String,
    isolation: String,
}

fn manifest() -> Vec<Case> {
    let text = fs::read_to_string(corpus().join("manifest.json")).expect("manifest.json");
    let document = parse(&text).expect("manifest JSON");
    let Some(Json::Array(cases)) = document.get("cases") else {
        panic!("manifest.json has no `cases` array");
    };
    cases
        .iter()
        .filter(|case| case.get("kind").and_then(Json::as_str) == Some("valid"))
        .map(|case| {
            let platform: Vec<&str> = match case.get("platform") {
                Some(Json::Array(items)) => items.iter().filter_map(Json::as_str).collect(),
                _ => Vec::new(),
            };
            Case {
                name: case
                    .get("case")
                    .and_then(Json::as_str)
                    .expect("case name")
                    .to_owned(),
                // `config.default_isolation()` on the platform the
                // harness pinned, which is what an unpinned config
                // resolves to.
                isolation: match (platform.first(), platform.get(1)) {
                    (Some(&"Darwin"), Some(&"arm64")) => "apple-container",
                    (Some(&"Darwin"), _) => "vm",
                    _ => "container",
                }
                .to_owned(),
            }
        })
        .collect()
}

fn host(isolation: &str) -> FixedHost {
    FixedHost {
        isolation: isolation.to_owned(),
        dns_servers: Ok(FROZEN_DNS_SERVERS
            .iter()
            .map(|server| (*server).to_owned())
            .collect()),
    }
}

/// Compare two YAML documents by value, key order included.
///
/// `serde_norway`'s `Mapping` is an `IndexMap`, so `==` already answers
/// "same keys, same values" — but not "same order", which
/// `proxy-config.yaml` does carry: it is built by walking the stored
/// document, so a reordering would mean the filter changed.
fn assert_documents_equal(case: &str, expected: &str, actual: &str) {
    let expected_value = agentcage_core::yaml::load(expected).expect("corpus YAML parses");
    let actual_value = agentcage_core::yaml::load(actual).expect("written YAML parses");
    assert_eq!(
        actual_value, expected_value,
        "{case}/proxy-config.yaml differs from the corpus by value\n\
         corpus:\n{expected}\nwritten:\n{actual}"
    );
    assert_eq!(
        key_order(&actual_value),
        key_order(&expected_value),
        "{case}/proxy-config.yaml differs from the corpus in key order"
    );
}

/// Every mapping key in the document, depth-first, in emission order.
fn key_order(value: &agentcage_core::yaml::Value) -> Vec<String> {
    let mut out = Vec::new();
    walk_keys(value, &mut out);
    out
}

fn walk_keys(value: &agentcage_core::yaml::Value, out: &mut Vec<String>) {
    match value {
        agentcage_core::yaml::Value::Mapping(mapping) => {
            for (key, child) in mapping {
                out.push(
                    key.as_str()
                        .map_or_else(|| format!("{key:?}"), str::to_owned),
                );
                walk_keys(child, out);
            }
        }
        agentcage_core::yaml::Value::Sequence(items) => {
            for item in items {
                walk_keys(item, out);
            }
        }
        _ => {}
    }
}

/// The cage name a stored config carries, which is also its state-dir
/// name.
fn cage_name(stored: &str) -> String {
    agentcage_core::yaml::load(stored)
        .ok()
        .and_then(|document| {
            document
                .get("name")
                .and_then(agentcage_core::yaml::Value::as_str)
                .map(str::to_owned)
        })
        .expect("every valid case names its cage")
}

/// Plant a case's `stored-cage.yaml` as a deployment and return its
/// name.
fn plant(paths: &Paths, directory: &Path) -> String {
    let stored = fs::read_to_string(directory.join("stored-cage.yaml"))
        .unwrap_or_else(|error| panic!("reading {}: {error}", directory.display()));
    let name = cage_name(&stored);
    let dir = paths.deployment_dir(&name);
    fs::create_dir_all(&dir).expect("deployment dir");
    fs::write(paths.stored_config_path(&name), &stored).expect("stored config");
    name
}

/// Every valid case's three derived files.
#[test]
fn the_derived_files_match_the_python() {
    let dir = TestDir::new("golden-derived");
    let cases = manifest();
    assert!(
        cases.len() > 100,
        "the corpus shrank: {} cases",
        cases.len()
    );

    let mut checked = 0_usize;
    let mut skipped: Vec<String> = Vec::new();
    for case in &cases {
        if UNREACHABLE_CASES.contains(&case.name.as_str()) {
            skipped.push(case.name.clone());
            continue;
        }
        let directory = corpus().join("valid").join(&case.name);
        // Each case gets its own roots: two cases can share a cage name.
        let sandbox = dir.path().join(&case.name);
        fs::create_dir_all(&sandbox).expect("case sandbox");
        let paths = Paths::under(&sandbox);
        let name = plant(&paths, &directory);

        // `save_proxy_config` writes `placeholders.env` in lockstep, so
        // one call produces two of the three artifacts — which is
        // itself the contract: a proxy config without the matching
        // placeholders is a cage whose injected values never match.
        paths
            .save_proxy_config(&name, FROZEN_VERSION)
            .unwrap_or_else(|error| panic!("{}: save_proxy_config: {error}", case.name));
        paths
            .save_dns_allowlist(&name, &host(&case.isolation))
            .unwrap_or_else(|error| panic!("{}: save_dns_allowlist: {error}", case.name));

        // `placeholders.env` and `dns-allowlist.conf` are compared
        // byte for byte: their consumers are podman's `EnvironmentFile=`
        // parser and dnsmasq, both byte-sensitive. `proxy-config.yaml`
        // is compared by *parsed value*, key order included — the
        // corpus README's own split (§2.8). PyYAML's emitter is not
        // reproducible from Rust (it wraps at 80 columns and has its own
        // quoting heuristics), and the egress parses this file rather
        // than diffing it.
        for artifact in ["placeholders.env", "dns-allowlist.conf"] {
            let expected = fs::read_to_string(directory.join(artifact))
                .unwrap_or_else(|error| panic!("{}/{artifact}: {error}", case.name));
            let actual = fs::read_to_string(match artifact {
                "placeholders.env" => paths.placeholders_env_path(&name),
                _ => paths.dns_allowlist_path(&name),
            })
            .unwrap_or_else(|error| panic!("{}/{artifact} was not written: {error}", case.name));
            assert_eq!(
                actual, expected,
                "{}/{artifact} differs from the corpus",
                case.name
            );
            checked += 1;
        }
        assert_documents_equal(
            &case.name,
            &fs::read_to_string(directory.join("proxy-config.yaml")).expect("corpus proxy config"),
            &fs::read_to_string(paths.proxy_config_path(&name)).expect("written proxy config"),
        );
        checked += 1;
    }

    assert_eq!(
        skipped, UNREACHABLE_CASES,
        "the exemption list is stale: it must name exactly the cases that were skipped"
    );
    assert_eq!(checked, (cases.len() - UNREACHABLE_CASES.len()) * 3);
}

/// `save_proxy_config` twice over is the same bytes.
///
/// Not a tautology: it is written **in place** rather than renamed
/// (§2.7 — the quadlets bind-mount it, and a rename swaps the inode out
/// from under the mount), so a writer that appended, or that left a
/// longer previous document's tail behind, would pass the test above on
/// a fresh directory and corrupt a real cage on the second deploy.
#[test]
fn rewriting_in_place_does_not_leave_a_tail() {
    let dir = TestDir::new("golden-derived-rewrite");
    let paths = Paths::under(dir.path());

    // A long config first, then a short one under the same name.
    let long = corpus().join("valid/agents-both");
    let short = corpus().join("valid/ports-defaults");
    assert!(
        short.is_dir(),
        "the small case this test shrinks to is gone"
    );

    let name = plant(&paths, &long);
    paths.save_proxy_config(&name, FROZEN_VERSION).unwrap();
    let long_text = fs::read_to_string(paths.proxy_config_path(&name)).unwrap();

    let short_stored = fs::read_to_string(short.join("stored-cage.yaml")).unwrap();
    // Same deployment directory, a different document.
    fs::write(
        paths.stored_config_path(&name),
        short_stored.replace(
            &format!("name: {}", cage_name(&short_stored)),
            &format!("name: {name}"),
        ),
    )
    .unwrap();
    paths.save_proxy_config(&name, FROZEN_VERSION).unwrap();
    let short_text = fs::read_to_string(paths.proxy_config_path(&name)).unwrap();

    assert!(short_text.len() < long_text.len(), "{short_text}");
    assert!(
        !short_text.contains("decider"),
        "the previous document's tail survived:\n{short_text}"
    );
}

/// The corpus is not silently empty.
#[test]
fn every_valid_case_has_all_three_artifacts() {
    let mut missing: Vec<String> = Vec::new();
    for case in manifest() {
        let directory = corpus().join("valid").join(&case.name);
        for artifact in [
            "proxy-config.yaml",
            "placeholders.env",
            "dns-allowlist.conf",
        ] {
            if !directory.join(artifact).is_file() {
                missing.push(format!("{}/{artifact}", case.name));
            }
        }
    }
    assert!(missing.is_empty(), "{missing:#?}");
}

/// A `FixedHost` whose DNS detection failed is what a loopback-only host
/// looks like, and `save_dns_allowlist` has to surface it rather than
/// writing an allowlist that forwards nowhere.
#[test]
fn a_host_with_no_usable_resolvers_is_an_error_not_an_empty_file() {
    let dir = TestDir::new("golden-derived-nodns");
    let paths = Paths::under(dir.path());
    // A case that does *not* pin `dns_servers:`, so the host probe is
    // the only source — which is the condition being tested.
    let name = plant(&paths, &corpus().join("valid/dns-servers-autodetected"));

    let broken = FixedHost {
        isolation: "container".to_owned(),
        dns_servers: Err(ConfigError::runtime("Could not detect usable DNS servers")),
    };
    let error = paths
        .save_dns_allowlist(&name, &broken)
        .expect_err("a host with only loopback resolvers cannot deploy");
    assert!(error.to_string().contains("usable DNS servers"), "{error}");
    assert!(
        !paths.dns_allowlist_path(&name).exists(),
        "a failed detection must not leave a half-written allowlist"
    );
}
