//! The `agents` defaults contract, against `tests/fixtures/contracts/agents_defaults.json`.
//!
//! The host copies the operator's `agents` block into `proxy-config.yaml`
//! as written, so a key left out is resolved on both sides: here, where
//! validation and the spend warning use it, and in the egress, which runs
//! with it. The proxy half (`TestAgentsDefaults` in
//! `tests/test_contract_fixtures.py`) pins the egress fallbacks to the
//! same fixture; this is the host half.

mod common;

use agentcage_core::config::{Config, FixedHost, FixedValidationHost, load, validate};
use serde_json::{Value, json};

use common::repo_root;

/// The host's resolved value for one fixture case id.
fn resolved(config: &Config, id: &str) -> Value {
    let decider = &config.agents.decider;
    let watcher = &config.agents.watcher;
    match id {
        "decider.host" => json!(decider.host),
        "decider.timeout_seconds" => json!(decider.llm.timeout_seconds),
        "decider.max_tokens" => json!(decider.llm.max_tokens),
        "decider.rate_limit.requests_per_second" => json!(decider.rate_limit_rps),
        "decider.rate_limit.burst" => json!(decider.rate_limit_burst),
        "watcher.interval_seconds" => json!(watcher.interval_seconds),
        "watcher.window_seconds" => json!(watcher.window_seconds),
        "watcher.max_flows" => json!(watcher.max_flows),
        "watcher.auto_revoke" => json!(watcher.auto_revoke),
        "watcher.dedup_samples" => json!(watcher.dedup_samples),
        "watcher.max_digest_tokens" => json!(watcher.max_digest_tokens),
        "watcher.timeout_seconds" => json!(watcher.llm.timeout_seconds),
        "watcher.max_tokens" => json!(watcher.llm.max_tokens),
        other => panic!("{other}: no host field mapped for this case; add one"),
    }
}

#[test]
fn an_omitted_agents_key_resolves_to_the_recorded_default() {
    let path = repo_root().join("tests/fixtures/contracts/agents_defaults.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    let document: Value = serde_json::from_str(&text).expect("contract JSON");
    let cases = document["cases"].as_array().expect("cases");
    assert!(
        !cases.is_empty(),
        "an empty contract fixture asserts nothing"
    );

    let mut cage = json!({
        "name": "test",
        "isolation": "container",
        "dns_servers": ["1.1.1.1"],
        "container": {"image": "node:22-slim"},
        "domains": {"allow": ["example.com"]},
    });
    cage["agents"] = document["config"]["agents"].clone();
    // JSON is a subset of YAML 1.2, so the sample is fed to the parser
    // exactly as written.
    let yaml = serde_json::to_string(&cage).expect("config serializes");
    let config = load("cage.yaml", &yaml, &FixedHost::linux(&["1.1.1.1"]))
        .unwrap_or_else(|error| panic!("the host refuses the sample: {error:?}"));
    assert!(config.agents.decider.enable && config.agents.watcher.enable);

    let mut host = FixedValidationHost::linux();
    host.environment
        .extend(["TESTKEY".to_owned(), "WATCHKEY".to_owned()]);
    validate(&config, &host)
        .unwrap_or_else(|error| panic!("the sample fails validation: {error:?}"));

    for case in cases {
        let id = case["id"].as_str().expect("id");
        assert_eq!(resolved(&config, id), case["value"], "{id}");
    }
}
