//! The egress half of the host/egress contracts in `tests/fixtures/contracts/`.
//!
//! Each contract there is asserted on both sides of the trust boundary:
//! the host half lives in `agentcage-core` / `agentcage-cli`, and this
//! file holds the egress halves that no egress unit test already covers.
//! The others are asserted where the behaviour lives: `agents_defaults`
//! in `watcher::config` and `watcher::corpus`, `logging_defaults` in
//! `audit::records`, and `valid_domain` / `encoded_private_ip` /
//! `validate_relay_entry`, which the egress takes from `agentcage-core`
//! unchanged, in that crate.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentcage_egress::config::{Config, Mapping, Value};
use agentcage_egress::inspect::chain::{BUILTIN_NAMES, NoPlugins, build_chain};
use agentcage_egress::inspect::domain::DomainInspector;
use agentcage_egress::policy::decider_enabled;
use agentcage_egress::watcher::WatcherConfig;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate is nested at rust/<crate>")
        .to_path_buf()
}

/// A contract file, read with the YAML loader the egress reads its config
/// with (JSON is YAML), so a case's config is exactly the tree the egress
/// would see on disk.
fn contract(name: &str) -> Value {
    let path = repo_root()
        .join("tests/fixtures/contracts")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    agentcage_core::yaml::load(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn cases(doc: &Value) -> &[Value] {
    let cases = doc["cases"].as_sequence().expect("cases");
    assert!(
        !cases.is_empty(),
        "an empty contract fixture asserts nothing"
    );
    cases
}

fn config(value: &Value) -> Config {
    Config::from_value(value.clone()).expect("the case config is a mapping")
}

fn names(value: &Value) -> Vec<&str> {
    value
        .as_sequence()
        .expect("a list")
        .iter()
        .map(|n| n.as_str().expect("a name"))
        .collect()
}

/// `scaffold_inspectors.json`: from each scaffold's rendered config, the
/// egress builds exactly the recorded inspector chain, in order. The host
/// half (the renderer emits that config) is in `agentcage-core`.
#[test]
fn the_egress_loads_the_recorded_inspector_chain() {
    let doc = contract("scaffold_inspectors");
    for case in cases(&doc) {
        let id = case["id"].as_str().expect("id");
        let cfg = config(&case["inspector_config"]);
        let chain = build_chain(&cfg, &Arc::new(DomainInspector::new()), &NoPlugins)
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(
            chain.chain().names(),
            names(&case["loaded_inspectors"]),
            "{id}: {}",
            case["why"].as_str().unwrap_or_default()
        );
    }
}

/// `shared_constants.json`: the values the egress defines itself. The
/// never-grant floor and the relay type/mode sets are `agentcage-core`
/// constants the egress imports, asserted there.
#[test]
fn the_egress_constants_match_the_fixture() {
    let doc = contract("shared_constants");
    let value = |id: &str| {
        &cases(&doc)
            .iter()
            .find(|c| c["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("no {id} case"))["value"]
    };
    assert_eq!(
        value("max_capture_file_bytes").as_i64(),
        Some(agentcage_egress::capture::DEFAULT_MAX_FILE_SIZE)
    );
    let mut builtins = BUILTIN_NAMES.to_vec();
    builtins.sort_unstable();
    assert_eq!(names(value("builtin_inspector_names")), builtins);
}

/// `agents_config.json`: the egress builds both agents from the canonical
/// `agents` block the host accepts, and neither from an empty one.
#[test]
fn the_egress_builds_both_agents_from_the_canonical_block() {
    let doc = contract("agents_config");
    for case in cases(&doc) {
        let id = case["id"].as_str().expect("id");
        let raw = &case["config"];
        let block = &raw["agents"]["watcher"];
        let cfg = config(raw);

        assert!(decider_enabled(&cfg), "{id}: the decider is enabled");
        let watcher = WatcherConfig::parse(&cfg, &mut |_| {});
        assert!(watcher.enable, "{id}: the watcher is enabled");
        assert_eq!(Some(watcher.provider.as_str()), block["provider"].as_str());
        assert_eq!(Some(watcher.model.as_str()), block["model"].as_str());
        assert_eq!(Some(watcher.base_url.as_str()), block["base_url"].as_str());

        let mut emptied = raw.clone();
        emptied["agents"] = Value::Mapping(Mapping::new());
        let cfg = config(&emptied);
        assert!(!decider_enabled(&cfg), "{id}: no decider without a block");
        assert!(!WatcherConfig::parse(&cfg, &mut |_| {}).enable, "{id}");
    }
}
