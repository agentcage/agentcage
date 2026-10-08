//! The golden corpus, against PR C3's half of `validate_config`.
//!
//! `tests/fixtures/golden/` records, for every generated `cage.yaml`,
//! what `config.py` produced from it: `error.txt` when
//! `load_config`/`validate_config` raised, `warnings.txt` when they
//! did not. Both are captured verbatim, because both are UX — a user
//! reads them (README, "Byte-exact vs. semantic comparison").
//!
//! `tests/golden_config.rs` holds the parser to the corpus. This
//! binary holds [`validate_agents`] and [`inspector_warnings`] to it:
//! the `agents.decider`, `agents.watcher` and inspector-chain rules
//! that PR C3 owns.
//!
//! # Why this is not one test with C2's
//!
//! `validate_config` is one Python function whose checks interleave —
//! identity, image, ports, domains, then the agent blocks — and the
//! ordered driver that reassembles it belongs to neither C2 nor C3
//! (see [`agentcage_core::config`]). So each half is exercised on its
//! own here, which is sound because every corpus case carries exactly
//! **one** fault: a case whose recorded message is an agents message
//! passed every earlier check in Python, so running the agents rules
//! alone reaches the same verdict.
//!
//! The cases where that is *not* true are the point of
//! [`SHADOWED_BY_C2`]: a config whose agents block is also wrong, but
//! which Python rejects earlier for a different reason. Those are
//! listed rather than ignored, so the day the driver lands the list
//! either empties or names a real ordering bug.

mod common;

use std::path::PathBuf;

use agentcage_core::config::{
    Config, ConfigError, FixedHost, inspector_warnings, load, validate_agents,
};

use common::repo_root;

/// The harness pins `config._host_dns_servers()` to these.
const FROZEN_DNS_SERVERS: [&str; 2] = ["192.0.2.53", "192.0.2.54"];

fn corpus() -> PathBuf {
    repo_root().join("tests/fixtures/golden")
}

fn read(path: &PathBuf) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

/// Every case in `manifest.json`, as `(case, kind, host)`.
fn manifest() -> Vec<(String, String, FixedHost)> {
    let text = read(&corpus().join("manifest.json"));
    let document: serde_json::Value = serde_json::from_str(&text).expect("manifest JSON");
    document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| {
            let platform: Vec<&str> = case["platform"]
                .as_array()
                .map(|items| items.iter().filter_map(|item| item.as_str()).collect())
                .unwrap_or_default();
            let isolation = match (platform.first(), platform.get(1)) {
                (Some(&"Darwin"), Some(&"arm64")) => "apple-container",
                (Some(&"Darwin"), _) => "vm",
                _ => "container",
            };
            (
                case["case"].as_str().expect("case").to_owned(),
                case["kind"].as_str().expect("kind").to_owned(),
                FixedHost {
                    isolation: isolation.to_owned(),
                    dns_servers: Ok(FROZEN_DNS_SERVERS
                        .iter()
                        .map(|server| (*server).to_owned())
                        .collect()),
                },
            )
        })
        .collect()
}

/// Load a case's `cage.yaml`, or `None` when it has none.
///
/// A handful of `invalid/` cases carry an `invocation.txt` instead:
/// they pin error paths no file on disk can reach.
fn parse(case: &str, kind: &str, host: &FixedHost) -> Option<Result<Config, ConfigError>> {
    let input = corpus().join(kind).join(case).join("input/cage.yaml");
    input
        .exists()
        .then(|| load("cage.yaml", &read(&input), host))
}

/// Which `invalid/` cases C3's validators reproduce verbatim.
#[test]
fn every_agents_invalid_case_matches_verbatim() {
    let root = corpus().join("invalid");
    let mut matched: Vec<String> = Vec::new();
    let mut deferred = 0;
    let mut differed: Vec<String> = Vec::new();

    for (case, kind, host) in manifest() {
        if kind != "invalid" {
            continue;
        }
        let Some(loaded) = parse(&case, &kind, &host) else {
            // `invocation.txt` cases pin error paths no file on disk
            // can reach.
            continue;
        };
        let expected = read(&root.join(&case).join("error.txt"));
        // A case the parser already rejects belongs to C1, C2 or C3's
        // relay half; `golden_config.rs` owns those.
        let Ok(config) = loaded else {
            deferred += 1;
            continue;
        };
        match validate_agents(&config) {
            Ok(_) => deferred += 1,
            Err(error) => {
                let produced = format!("{}\n", error.as_python_traceback_line());
                if produced == expected {
                    matched.push(case);
                } else if SHADOWED_BY_C2.contains(&case.as_str()) {
                    deferred += 1;
                } else {
                    differed.push(format!(
                        "  {case}\n      python: {}\n      rust:   {}",
                        expected.trim_end(),
                        produced.trim_end()
                    ));
                }
            }
        }
    }

    assert!(
        differed.is_empty(),
        "{} invalid cases produced a DIFFERENT message than config.py. Either the port is \
         wrong, or an earlier C2 check shadows this one in Python and the case belongs in \
         SHADOWED_BY_C2 with a reason:\n{}",
        differed.len(),
        differed.join("\n")
    );

    let matched: Vec<&str> = matched.iter().map(String::as_str).collect();
    assert_eq!(
        matched,
        C3_OWNED.to_vec(),
        "the set of invalid cases C3's agent rules reproduce changed"
    );
    println!(
        "{} agents invalid cases reproduced verbatim, {deferred} outside these rules",
        matched.len()
    );
}

/// No valid case is refused, and the warnings C3 owns match verbatim.
///
/// The second half is the one with teeth. Two corpus cases record the
/// watcher's spend warnings and one records the apple-container
/// inspector warnings; the number formatting in them (`166M`,
/// `100,000 tokens`, `1440 scans`) is Python's `format`, which is
/// where a port quietly goes wrong.
#[test]
fn every_valid_case_validates_with_the_warnings_it_recorded() {
    let mut wrong: Vec<String> = Vec::new();
    let mut checked = 0;
    let mut with_warnings = 0;

    for (case, kind, host) in manifest() {
        if kind != "valid" {
            continue;
        }
        let Some(Ok(config)) = parse(&case, &kind, &host) else {
            // `golden_config.rs` asserts every valid case parses; a
            // failure there is its business, not this test's.
            continue;
        };
        let recorded = read(&corpus().join("valid").join(&case).join("warnings.txt"));
        let expected: Vec<&str> = recorded
            .lines()
            .filter(|line| is_c3_warning(line))
            .collect();

        match validate_agents(&config) {
            Ok(agent_warnings) => {
                checked += 1;
                let mut produced = agent_warnings;
                produced.extend(inspector_warnings(&config));
                // `config.py` appends the inspector warnings ahead of
                // the watcher's, so compare as sets-in-order-of-kind
                // rather than assuming one interleaving: what is under
                // test is the TEXT, and the driver PR owns the order
                // in which the two halves are concatenated.
                let mut produced: Vec<&str> = produced.iter().map(String::as_str).collect();
                let mut expected = expected.clone();
                produced.sort_unstable();
                expected.sort_unstable();
                if produced != expected {
                    wrong.push(format!(
                        "  {case}\n      python: {expected:#?}\n      rust:   {produced:#?}"
                    ));
                } else if !expected.is_empty() {
                    with_warnings += 1;
                }
            }
            Err(error) => wrong.push(format!("  {case}: refused a valid config -- {error}")),
        }
    }

    assert!(
        wrong.is_empty(),
        "{} valid cases disagree with the corpus:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert!(checked >= 128, "the corpus shrank");
    assert_eq!(
        with_warnings, 3,
        "three corpus cases carry a C3-owned warning; if that changed, read the diff"
    );
    println!("{checked} valid cases validated, {with_warnings} with C3 warnings");
}

/// The warning lines PR C3 produces.
///
/// A prefix match, not a guess: each one is the literal opening of a
/// `warnings.append` in `config.py`'s agent and inspector blocks.
fn is_c3_warning(line: &str) -> bool {
    line.starts_with("inspectors[")
        || line.starts_with("agents.watcher may send up to")
        || line.starts_with("agents.watcher.max_digest_tokens is 0")
}

/// The `invalid/` cases C3's agent rules reproduce, in manifest order.
const C3_OWNED: &[&str] = &[
    "err-decider-api-key-cmd",
    "err-decider-api-key-missing",
    "err-decider-api-key-podman",
    "err-decider-base-url-http",
    "err-decider-context-too-long",
    "err-decider-host-in-allow",
    "err-decider-host-single-label",
    "err-decider-max-tokens-too-small",
    "err-decider-model-missing",
    "err-decider-provider-invalid",
    "err-decider-provider-wrong-case",
    "err-decider-rate-limit-negative",
    "err-decider-requires-allowlist",
    "err-decider-timeout-not-positive",
    "err-watcher-api-key-cmd",
    "err-watcher-api-key-missing",
    "err-watcher-api-key-podman",
    "err-watcher-base-url-http",
    "err-watcher-blocklist-mode",
    "err-watcher-context-too-long",
    "err-watcher-digest-tokens-too-high",
    "err-watcher-digest-tokens-too-low",
    "err-watcher-interval-too-fast",
    "err-watcher-max-flows-too-high",
    "err-watcher-max-flows-too-low",
    "err-watcher-max-tokens-too-small",
    "err-watcher-model-missing",
    "err-watcher-provider-invalid",
    "err-watcher-timeout-not-positive",
    "err-watcher-window-too-long",
    "err-watcher-window-zero",
];

/// Cases whose agents block is also wrong, but which `config.py`
/// rejects earlier for a reason PR C2 owns.
///
/// Empty today, and that is a finding rather than an omission: every
/// corpus case carries exactly one fault, so no case reaches an agents
/// rule after a C2 rule would have fired. The list stays because the
/// day a case does, the alternative is this test failing with a
/// message that reads like a port bug.
const SHADOWED_BY_C2: &[&str] = &[];
