//! The `agents` block contract, against `tests/fixtures/contracts/agents_config.json`.
//!
//! The host parses and validates a cage's `agents` block, then copies it
//! into `proxy-config.yaml` unchanged; the egress addon builds its decider
//! and watcher from the same keys. The proxy half asserts the addon
//! accepts the fixture's sample (`tests/test_agents_config_proxy.py`);
//! this is the host half, so a key renamed or reshaped on either side
//! fails on the side that moved.

mod common;

use agentcage_core::config::{FixedHost, FixedValidationHost, load, validate};

use common::repo_root;

#[test]
fn the_canonical_agents_block_loads_validates_and_resolves() {
    let path = repo_root().join("tests/fixtures/contracts/agents_config.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    let document: serde_json::Value = serde_json::from_str(&text).expect("contract JSON");
    let cases = document["cases"].as_array().expect("cases");
    assert!(
        !cases.is_empty(),
        "an empty contract fixture asserts nothing"
    );

    for case in cases {
        let id = case["id"].as_str().expect("id");
        // JSON is a subset of YAML 1.2, so the sample is fed to the
        // parser exactly as written.
        let yaml = serde_json::to_string(&case["config"]).expect("config serializes");
        let config = load("cage.yaml", &yaml, &FixedHost::linux(&["1.1.1.1"]))
            .unwrap_or_else(|error| panic!("{id}: the host refuses the sample: {error:?}"));

        let mut host = FixedValidationHost::linux();
        host.environment
            .extend(["TESTKEY".to_owned(), "WATCHKEY".to_owned()]);
        validate(&config, &host)
            .unwrap_or_else(|error| panic!("{id}: the sample fails validation: {error:?}"));

        let expect = &case["expect"];
        let decider = &config.agents.decider;
        let watcher = &config.agents.watcher;
        assert_eq!(
            decider.host,
            expect["decider_host"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            decider.rate_limit_rps,
            expect["decider_rate_limit_rps"].as_f64().unwrap(),
            "{id}"
        );
        assert_eq!(
            decider.llm.max_tokens,
            expect["decider_max_tokens"].as_i64().unwrap(),
            "{id}"
        );
        assert_eq!(
            watcher.context,
            expect["watcher_context"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            watcher.auto_revoke,
            expect["watcher_auto_revoke"].as_bool().unwrap(),
            "{id}"
        );
    }
}
