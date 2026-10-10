//! The logging defaults contract, against `tests/fixtures/contracts/logging_defaults.json`.
//!
//! Whether allowed requests are logged is resolved twice: here, from
//! `cage.yaml`, and in the egress, from the `proxy-config.yaml` the host
//! writes. The fixture splits at that file, like the scaffold contract:
//! this half proves what the host resolves for each case and what it
//! writes for the egress to read; the proxy half (`TestLoggingDefaults`
//! in `tests/test_contract_fixtures.py`) proves the egress reads the
//! recorded file to the same answer.
//!
//! It lives in `agentcage-state` rather than beside the other contract
//! tests because the writer (`save_proxy_config`) does: a key the host
//! resolves but strips from `proxy-config.yaml` is exactly the drift this
//! catches, and the parse alone cannot see it.

use std::fs;
use std::path::{Path, PathBuf};

use agentcage_core::config::{FixedHost, load};
use agentcage_core::yaml::{self, Mapping, Value};
use agentcage_state::{Paths, TestDir};

/// The keys of `proxy-config.yaml` this contract is about.
const LOGGING_KEYS: [&str; 2] = ["logging", "log_allowed"];

fn repo_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `<repo>/rust/agentcage-state`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate is two levels below the repo root")
        .to_path_buf()
}

/// A JSON value as YAML: JSON is a subset of YAML 1.2, so it is fed to
/// the same loader the host reads `cage.yaml` and `proxy-config.yaml` with.
fn as_yaml(value: &serde_json::Value) -> Value {
    yaml::load(&serde_json::to_string(value).expect("serializes")).expect("JSON is YAML")
}

#[test]
fn the_host_resolves_and_forwards_allowed_requests_as_recorded() {
    let path = repo_root().join("tests/fixtures/contracts/logging_defaults.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    let document: serde_json::Value = serde_json::from_str(&text).expect("contract JSON");
    let cases = document["cases"].as_array().expect("cases");
    assert!(
        !cases.is_empty(),
        "an empty contract fixture asserts nothing"
    );

    let dir = TestDir::new("contract-logging-defaults");
    for case in cases {
        let id = case["id"].as_str().expect("id");
        let mut cage = serde_json::json!({
            "name": "test",
            "isolation": "container",
            "dns_servers": ["1.1.1.1"],
            "container": {"image": "node:22-slim"},
            "domains": {"allow": ["example.com"]},
        });
        for (key, value) in case["cage"].as_object().expect("cage") {
            cage[key] = value.clone();
        }
        let cage_yaml = serde_json::to_string(&cage).expect("config serializes");

        // The host's own answer: what it validates and documents.
        let config = load("cage.yaml", &cage_yaml, &FixedHost::linux(&["1.1.1.1"]))
            .unwrap_or_else(|error| panic!("{id}: the host refuses the sample: {error:?}"));
        assert_eq!(
            serde_json::Value::Bool(config.logging.allowed_requests),
            case["allowed_requests"],
            "{id}: the host resolves allowed_requests differently — {}",
            case["why"].as_str().unwrap_or_default()
        );

        // What it hands the egress.
        let paths = Paths::under(dir.path().join(id));
        fs::create_dir_all(paths.deployment_dir("test")).expect("deployment dir");
        fs::write(paths.stored_config_path("test"), &cage_yaml).expect("stored config");
        paths
            .save_proxy_config("test", "0.0.0-contract")
            .unwrap_or_else(|error| panic!("{id}: save_proxy_config: {error}"));
        let written = yaml::load(
            &fs::read_to_string(paths.proxy_config_path("test")).expect("proxy-config.yaml"),
        )
        .expect("proxy-config.yaml parses");
        let mut forwarded = Mapping::new();
        if let Value::Mapping(written) = &written {
            for (key, value) in written {
                if key.as_str().is_some_and(|key| LOGGING_KEYS.contains(&key)) {
                    forwarded.insert(key.clone(), value.clone());
                }
            }
        }
        assert_eq!(
            Value::Mapping(forwarded),
            as_yaml(&case["proxy_config"]),
            "{id}: proxy-config.yaml carries different logging keys than the \
             egress half of the contract reads — {}",
            case["why"].as_str().unwrap_or_default()
        );
    }
}
