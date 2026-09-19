//! The golden corpus, against the Rust validator.
//!
//! `tests/golden_config.rs` covers PR C1 — parsing, and the structural
//! refusals `load_config` makes on its way through a document. This is
//! the other half: `load` followed by [`validate`], which is what
//! `agentcage cage create` actually runs, compared against the corpus's
//! `error.txt` and `warnings.txt`.
//!
//! # The three buckets
//!
//! [`the_invalid_cases_match_verbatim`] sorts every `invalid/` case into
//! *matched*, *deferred* and *differed*, and the third one is the point.
//! A case this pipeline refuses with **different wording** than
//! `config.py` is a failure, because that is a message a user reads. A
//! case it *accepts* is merely not implemented yet, and is recorded as
//! deferred with a named owner.
//!
//! Both lists are asserted exactly, so C3 landing changes the lists and
//! nothing else, and losing a case is a regression rather than a silent
//! reclassification.

mod common;

use std::path::{Path, PathBuf};

use agentcage_core::config::{
    Config, ConfigError, FixedHost, FixedValidationHost, LabelPolicy, encoded_private_ip, load,
    valid_domain, validate,
};

use common::repo_root;

/// The harness pins `config._host_dns_servers()` to these.
const FROZEN_DNS_SERVERS: [&str; 2] = ["192.0.2.53", "192.0.2.54"];

/// The environment `scripts/gen-golden-corpus.py` pins before importing
/// `agentcage`.
///
/// `GOLDEN_UNSET_VAR` is deliberately *absent* — it is what makes the
/// "env var reference is unset" warning reachable. Every other name a
/// corpus config references is here; one that is not would mean the
/// corpus had captured a warning that depends on the developer's own
/// environment, which `_assert_no_leaks` exists to prevent.
const FROZEN_ENVIRONMENT: [&str; 6] = [
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "GOLDEN_AGENT_DIR",
    "GOLDEN_SET_VAR",
];

fn corpus() -> PathBuf {
    repo_root().join("tests/fixtures/golden")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

/// One case's pinned platform and the hosts derived from it.
struct CaseHosts {
    probe: FixedHost,
    validation: FixedValidationHost,
}

fn hosts_for(platform: &[String]) -> CaseHosts {
    let system = platform.first().map_or("Linux", String::as_str);
    let machine = platform.get(1).map_or("x86_64", String::as_str);
    let isolation = match (system, machine) {
        ("Darwin", "arm64") => "apple-container",
        ("Darwin", _) => "vm",
        _ => "container",
    };
    CaseHosts {
        probe: FixedHost {
            isolation: isolation.to_owned(),
            dns_servers: Ok(FROZEN_DNS_SERVERS
                .iter()
                .map(|server| (*server).to_owned())
                .collect()),
        },
        validation: FixedValidationHost {
            system: system.to_owned(),
            machine: machine.to_owned(),
            environment: FROZEN_ENVIRONMENT
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
        },
    }
}

/// Every case in `manifest.json`, as `(case, kind, hosts)`.
fn manifest() -> Vec<(String, String, CaseHosts)> {
    let path = corpus().join("manifest.json");
    let document: serde_json::Value = serde_json::from_str(&read(&path)).expect("manifest JSON");
    document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| {
            let platform: Vec<String> = case["platform"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            (
                case["case"].as_str().expect("case").to_owned(),
                case["kind"].as_str().expect("kind").to_owned(),
                hosts_for(&platform),
            )
        })
        .collect()
}

/// `load` then `validate`, the way `cage create` runs them.
fn pipeline(
    source: &str,
    text: &str,
    hosts: &CaseHosts,
) -> Result<(Config, Vec<String>), ConfigError> {
    let config = load(source, text, &hosts.probe)?;
    let warnings = validate(&config, &hosts.validation)?;
    Ok((config, warnings))
}

/// Every `invalid/` case, sorted into matched, deferred and differed.
#[test]
fn the_invalid_cases_match_verbatim() {
    let root = corpus().join("invalid");
    let mut matched: Vec<String> = Vec::new();
    let mut deferred: Vec<String> = Vec::new();
    let mut differed: Vec<String> = Vec::new();

    for (case, kind, hosts) in manifest() {
        if kind != "invalid" {
            continue;
        }
        let input_path = root.join(&case).join("input/cage.yaml");
        if !input_path.exists() {
            // `invocation.txt` cases pin error paths no file on disk can
            // reach: a missing config file, the host-DNS-detection
            // failures.
            continue;
        }
        let expected = read(&root.join(&case).join("error.txt"));
        match pipeline("cage.yaml", &read(&input_path), &hosts) {
            Ok(_) => deferred.push(case),
            Err(error) => {
                let produced = format!("{}\n", error.as_python_traceback_line());
                if produced == expected {
                    matched.push(case);
                } else if KNOWN_DIVERGENT.contains(&case.as_str()) {
                    deferred.push(case);
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
        "{} invalid cases produced a DIFFERENT message than config.py. Either the port \
         is wrong, or the divergence is deliberate and belongs in KNOWN_DIVERGENT with a \
         reason:\n{}",
        differed.len(),
        differed.join("\n")
    );

    let matched: Vec<&str> = matched.iter().map(String::as_str).collect();
    assert_eq!(
        matched, REPRODUCED,
        "the set of invalid cases the pipeline reproduces changed. Adding one is usually \
         right (C3 landing); losing one is a regression."
    );
    let deferred: Vec<&str> = deferred.iter().map(String::as_str).collect();
    assert_eq!(
        deferred, DEFERRED,
        "the set of invalid cases still deferred changed. Every entry needs an owner."
    );
    println!(
        "{} invalid cases reproduced verbatim, {} deferred",
        matched.len(),
        deferred.len()
    );
}

/// Every `valid/` case's warnings, byte for byte and in order.
///
/// Warnings are as much UX as errors — `cage create` prints them — and
/// several of them are the only notice an operator gets that a config
/// knob is decorative on their backend. Order matters because they are
/// printed in it.
#[test]
fn the_valid_cases_reproduce_their_warnings() {
    let root = corpus().join("valid");
    let mut wrong: Vec<String> = Vec::new();
    let mut deferred: Vec<String> = Vec::new();
    let mut checked = 0;

    for (case, kind, hosts) in manifest() {
        if kind != "valid" {
            continue;
        }
        let directory = root.join(&case);
        let expected: Vec<String> = read(&directory.join("warnings.txt"))
            .lines()
            .map(str::to_owned)
            .collect();
        let (_, produced) = pipeline(
            "cage.yaml",
            &read(&directory.join("input/cage.yaml")),
            &hosts,
        )
        .unwrap_or_else(|error| panic!("{case}: a valid case was refused -- {error}"));

        if produced == expected {
            checked += 1;
        } else if WARNINGS_DEFERRED.contains(&case.as_str()) {
            deferred.push(case);
        } else {
            wrong.push(format!(
                "  {case}\n      python: {expected:#?}\n      rust:   {produced:#?}"
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "{} valid cases produced different warnings than config.py:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    let deferred: Vec<&str> = deferred.iter().map(String::as_str).collect();
    assert_eq!(
        deferred, WARNINGS_DEFERRED,
        "the set of cases whose warnings need C3 changed"
    );
    println!(
        "{checked} valid cases reproduced warnings.txt, {} deferred",
        deferred.len()
    );
}

/// `shared/domain-validation.json`, the corpus's own domain table.
///
/// Overlaps `tests/contract_domain.rs`, on purpose: that file checks the
/// cross-language contract fixture, this one checks the corpus artifact,
/// and the two were captured by different harnesses. A port that passed
/// one and failed the other would mean the two oracles had drifted, which
/// is worth finding out about.
#[test]
fn the_shared_domain_table_matches() {
    let path = corpus().join("shared/domain-validation.json");
    let rows: Vec<serde_json::Value> = serde_json::from_str(&read(&path)).expect("domain JSON");
    assert!(!rows.is_empty(), "the shared domain table is empty");

    let mut wrong: Vec<String> = Vec::new();
    for row in &rows {
        let domain = row["domain"].as_str().expect("domain");
        let expectations = [
            (
                "valid_domain",
                serde_json::Value::Bool(valid_domain(domain, LabelPolicy::StrictDotted)),
            ),
            (
                "valid_domain_single_label",
                serde_json::Value::Bool(valid_domain(domain, LabelPolicy::AllowSingleLabel)),
            ),
            (
                "encoded_private_ip",
                encoded_private_ip(domain).map_or(serde_json::Value::Null, |address| {
                    serde_json::Value::String(address)
                }),
            ),
        ];
        for (key, produced) in expectations {
            if row[key] != produced {
                wrong.push(format!(
                    "  {domain:?} [{key}]\n      python: {}\n      rust:   {produced}",
                    row[key]
                ));
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "{} disagreements with shared/domain-validation.json:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    println!("{} shared domain rows matched", rows.len());
}

/// Everything the port refuses with `config.py`'s exact words, in
/// manifest order.
///
/// PR C1's 34 structural refusals, plus the 42 value checks PR C2 adds.
/// The list is asserted rather than counted so that a case moving between
/// buckets shows up as a named diff.
const REPRODUCED: &[&str] = &[
    "err-agents-auto-revoke-not-bool",
    "err-agents-decider-context-not-string",
    "err-agents-decider-kind",
    "err-agents-decider-wrapper-agent",
    "err-agents-dedup-samples-not-bool",
    "err-agents-domains-auto",
    "err-agents-domains-not-mapping",
    "err-agents-enable-not-bool",
    "err-agents-llm-max-tokens-not-number",
    "err-agents-llm-timeout-bool",
    "err-agents-not-mapping",
    "err-agents-role-not-mapping",
    "err-agents-top-level-watcher",
    "err-agents-unknown-role",
    "err-agents-watcher-context-not-string",
    "err-agents-watcher-number-not-number",
    "err-agents-watcher-wrapper-decider",
    "err-container-port-not-a-number",
    "err-container-port-out-of-range",
    "err-container-port-spec-shape",
    "err-decider-timeout-not-finite",
    "err-domain-syntax-block",
    "err-domain-syntax-expires-key",
    "err-domain-syntax-ip-literal",
    "err-domain-syntax-newline",
    "err-domain-syntax-passthrough",
    "err-domain-syntax-short-tld",
    "err-domain-syntax-uppercase",
    "err-domains-allow-and-block",
    "err-image-invalid-ref",
    "err-image-missing",
    "err-isolation-apple-on-intel-mac",
    "err-isolation-apple-on-linux",
    "err-isolation-container-on-macos",
    "err-isolation-unknown",
    "err-lifecycle-unknown",
    "err-logging-level-invalid",
    "err-logging-service-level-invalid",
    "err-name-invalid-chars",
    "err-name-missing",
    "err-name-too-long",
    "err-nested-containers-on-vm",
    "err-port-collides-with-publish",
    "err-port-collides-with-relay",
    "err-port-entry-bool",
    "err-port-entry-duplicate",
    "err-port-entry-not-int",
    "err-port-entry-out-of-range",
    "err-port-reserved-8080",
    "err-port-reserved-8443",
    "err-ports-icmp-allow-not-bool",
    "err-ports-icmp-not-mapping",
    "err-ports-not-mapping",
    "err-ports-tcp-allow-not-list",
    "err-ports-tcp-not-mapping",
    "err-ports-tcp-passthrough-not-list",
    "err-ports-udp-allow-not-list",
    "err-ports-udp-not-mapping",
    "err-relay-auth-not-mapping",
    "err-relay-entry-not-mapping",
    "err-relay-folder-allowlist-not-list",
    "err-relay-missing-fields",
    "err-relay-servername-not-string",
    "err-relay-upstream-not-mapping",
    "err-secret-env-name-invalid",
    "err-secret-source-scheme-unknown",
    "err-secret-transform-unknown",
    "err-secrets-backend-invalid",
    "err-secrets-scope-invalid",
    "err-vm-mem-too-low",
    "err-vm-vcpus-too-low",
    "err-volume-np-with-z",
    "misc-empty-config",
    "seed-unit-test",
    "seed-unit-test-curl",
];

/// The cases this pipeline still accepts, each with its owner.
///
/// | Cases | Owner | Why |
/// | :-- | :-- | :-- |
/// | `err-agents-*-api-key-no-scheme`, `err-decider-*`, `err-watcher-*` | C3 | the decider and watcher validation blocks |
/// | `err-relay-*` past the required-key check | C3 | `relays/_validate.validate_relay_entry` |
/// | `err-volume-outside-home` | C8 | raised by `quadlets.py`, not by `validate_config` — a rendering check, not a config one |
/// | `err-yaml-syntax`, `err-yaml-tab` | — | in [`KNOWN_DIVERGENT`]: the line and column match, the scanner's own wording cannot |
const DEFERRED: &[&str] = &[
    "err-agents-decider-api-key-no-scheme",
    "err-agents-watcher-api-key-no-scheme",
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
    "err-relay-auth-source-scheme",
    "err-relay-ca-file-and-pem",
    "err-relay-ca-file-missing",
    "err-relay-ca-file-not-pem",
    "err-relay-ca-file-not-string",
    "err-relay-ca-pem-not-pem",
    "err-relay-ca-pem-not-string",
    "err-relay-tls-false-with-ca",
    "err-relay-unknown-type",
    "err-relay-upstream-bad-port",
    "err-relay-write-mode-contradicts-readonly",
    "err-relay-write-mode-invalid",
    "err-volume-outside-home",
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
    "err-yaml-syntax",
    "err-yaml-tab",
];

/// Cases where the port errors, deliberately, with wording of its own.
///
/// Inherited from `tests/golden_config.rs`: PyYAML's scanner text is its
/// own and `serde_norway` reports the same fault in its own words. The
/// surrounding sentence, and the line and column a user acts on, are
/// reproduced.
const KNOWN_DIVERGENT: &[&str] = &["err-yaml-syntax", "err-yaml-tab"];

/// Valid cases whose `warnings.txt` needs a check this PR does not make.
///
/// All three are C3's, and each is missing exactly the lines C3 adds —
/// the rest of every list is already produced:
///
/// - the two `agents-watcher-*` cases want the watcher's spend
///   warnings, which belong with the rest of the watcher block;
/// - `backend-apple-container-inspectors` wants the per-entry
///   inspector-chain warnings, the `── C3 ──` marker at the end of
///   `config::validate::apple_container_warnings`.
const WARNINGS_DEFERRED: &[&str] = &[
    "agents-watcher-expensive",
    "agents-watcher-unbounded-digest",
    "backend-apple-container-inspectors",
];

// ── error precedence ─────────────────────────────────────

/// Which of two faults gets reported, compared against `config.py`.
///
/// The corpus is one fault per case, so it says nothing about this. It
/// matters anyway: an operator fixes errors one at a time, and a
/// validator that reports the *second* problem sends them to the wrong
/// line.
///
/// Every `python` string below was produced by running the same document
/// through `config.load_config` + `config.validate_config` on CPython
/// 3.13.0, not written from reading the source.
///
/// # The one divergence
///
/// PR C1 typed `ports.{tcp,udp}.{allow,passthrough}` as `Vec<i64>` so
/// that `entries must be integers (got: '443')` could be reproduced
/// verbatim at all. That moves the check from `validate_config` into the
/// parser, and the parser runs first — so a **string or boolean port
/// entry now preempts every check `validate_config` makes**, `name`
/// included.
///
/// Its position relative to the rest of `load_config` is unchanged:
/// `validate_agents_raw`, the `secrets:` section and `protocol_relays`
/// still win, because the parser reaches them before the `ports:`
/// section. So the divergence is exactly one boundary wide, and the
/// `preempts-*` cases below map it.
// A table, not logic: the length is the corpus of pairs, and splitting
// it would put the cases somewhere other than the explanation of them.
#[allow(clippy::too_many_lines)]
#[test]
fn error_precedence_matches_python() {
    struct Precedence {
        id: &'static str,
        yaml: &'static str,
        /// What `config.py` reports, verbatim.
        python: &'static str,
        /// What this port reports, when that differs.
        rust: Option<&'static str>,
    }

    let cases = [
        // ── Agreements. Both faults are in `validate_config`, or the
        // first one is a `load_config` check that already ran first in
        // Python too.
        Precedence {
            id: "name-before-port-range",
            yaml: "name: BAD_NAME\ncontainer:\n  image: alpine\nports:\n  tcp:\n    allow: [70000]\n",
            python: "ValueError: 'name' must be 1-63 lowercase alphanumeric characters or \
                     hyphens, starting with a letter or digit (got: 'BAD_NAME')",
            rust: None,
        },
        Precedence {
            id: "secrets-scope-before-name",
            yaml: "name: BAD_NAME\ncontainer:\n  image: alpine\nsecrets:\n  scope: global\n",
            python: "ValueError: invalid secrets.scope: 'global'. Valid: auto, user, system",
            rust: None,
        },
        Precedence {
            id: "relay-required-keys-before-name",
            yaml: "name: BAD_NAME\ncontainer:\n  image: alpine\nprotocol_relays:\n- name: mail\n  \
                   type: imap\n  listen: ''\n",
            python: "ValueError: protocol_relays entry requires name/type/listen \
                     (got name='mail', type='imap', listen='')",
            rust: None,
        },
        Precedence {
            id: "env-name-before-name",
            yaml: "name: BAD_NAME\ncontainer:\n  image: alpine\nsecret_injection:\n- env: \
                   'not-valid'\n  source: 'env:X'\n",
            python: "ValueError: invalid env name: 'not-valid'. Must match [A-Za-z_][A-Za-z0-9_]*",
            rust: None,
        },
        Precedence {
            id: "source-scheme-before-transform",
            yaml: "name: cage\ncontainer:\n  image: alpine\nsecret_injection:\n- env: TOK\n  \
                   source: 'vault:X'\n  transform: nope\n",
            python: "ValueError: unknown secret source scheme: 'vault'. \
                     Valid schemes: cmd, env, podman, systemd-creds",
            rust: None,
        },
        Precedence {
            id: "volume-np-before-image-reference",
            yaml: "name: cage\ncontainer:\n  image: '!!bad!!'\n  volumes: ['/h:/c:np,z']\n",
            python: "ValueError: volume '/h:/c:np,z': the np option cannot be combined with z; \
                     only rw,np is supported",
            rust: None,
        },
        Precedence {
            id: "image-before-domain-syntax",
            yaml: "name: cage\ncontainer:\n  image: '!!bad!!'\ndomains:\n  mode: allowlist\n  \
                   allow: ['BAD.example.com']\n",
            python: "ValueError: invalid container image reference: '!!bad!!'",
            rust: None,
        },
        Precedence {
            id: "lifecycle-before-logging-level",
            yaml: "name: cage\nlifecycle: daemon\ncontainer:\n  image: alpine\nlogging:\n  \
                   level: verbose\n",
            python: "ValueError: lifecycle must be one of ('service', 'interactive', \
                     'ephemeral') (got: 'daemon')",
            rust: None,
        },
        Precedence {
            id: "container-port-spec-before-tcp-range",
            yaml: "name: cage\ncontainer:\n  image: alpine\n  ports: ['3000']\nports:\n  tcp:\n    \
                   allow: [70000]\n",
            python: "ValueError: invalid port spec '3000': expected HOST_PORT:CONTAINER_PORT or \
                     BIND:HOST_PORT:CONTAINER_PORT",
            rust: None,
        },
        Precedence {
            id: "domains-exclusivity-before-domain-syntax",
            yaml: "name: cage\ndomains:\n  allow: ['BAD.example.com']\n  block: ['also.bad']\n\
                   container:\n  image: alpine\n",
            python: "ValueError: domains: cannot specify both 'allow' and 'block' lists",
            rust: None,
        },
        Precedence {
            id: "duplicate-port-before-out-of-range",
            yaml: "name: cage\ncontainer:\n  image: alpine\nports:\n  tcp:\n    \
                   allow: [443, 443, 70000]\n",
            python: "ValueError: ports.tcp.allow entry 443 appears more than once",
            rust: None,
        },
        Precedence {
            id: "reserved-port-before-relay-collision",
            yaml: "name: cage\ncontainer:\n  image: alpine\nports:\n  tcp:\n    \
                   allow: [8080, 1143]\nprotocol_relays:\n- name: mail\n  type: imap\n  \
                   listen: '0.0.0.0:1143'\n  upstream: {host: imap.example.com, port: 993}\n  \
                   auth: {type: plain, user_source: 'env:U', password_source: 'env:P'}\n",
            python: "ValueError: ports.tcp.allow entry 8080 is reserved by mitmdump (8080 = \
                     HTTP-proxy listener, 8443 = transparent listener); redirecting it would \
                     loop or break the L7 proxy path. Move it to ports.tcp.passthrough if the \
                     cage needs to reach an upstream service on this port without inspection",
            rust: None,
        },
        // Still behind `validate_agents_raw` and the `secrets:` section,
        // which the parser reaches before `ports:`.
        Precedence {
            id: "agents-schema-still-preempts-port-type",
            yaml: "name: cage\ncontainer:\n  image: alpine\nports:\n  tcp:\n    allow: ['443']\n\
                   agents:\n  auditor: {}\n",
            python: "ValueError: unknown agents: auditor",
            rust: None,
        },
        Precedence {
            id: "secrets-scope-still-preempts-port-type",
            yaml: "name: cage\ncontainer:\n  image: alpine\nports:\n  tcp:\n    allow: ['443']\n\
                   secrets:\n  scope: global\n",
            python: "ValueError: invalid secrets.scope: 'global'. Valid: auto, user, system",
            rust: None,
        },
        Precedence {
            id: "relay-required-keys-still-preempt-port-type",
            yaml: "name: cage\ncontainer:\n  image: alpine\nports:\n  tcp:\n    allow: ['443']\n\
                   protocol_relays:\n- name: mail\n  type: imap\n  listen: ''\n",
            python: "ValueError: protocol_relays entry requires name/type/listen \
                     (got name='mail', type='imap', listen='')",
            rust: None,
        },
        // ── The divergence, mapped. A non-integer port entry preempts
        // every `validate_config` check, and nothing else moves.
        Precedence {
            id: "preempts-name",
            yaml: "name: BAD_NAME\ncontainer:\n  image: alpine\nports:\n  tcp:\n    \
                   allow: ['443']\n",
            python: "ValueError: 'name' must be 1-63 lowercase alphanumeric characters or \
                     hyphens, starting with a letter or digit (got: 'BAD_NAME')",
            rust: Some("ValueError: ports.tcp.allow entries must be integers (got: '443')"),
        },
        Precedence {
            id: "preempts-name-via-a-boolean-entry",
            yaml: "name: BAD_NAME\ncontainer:\n  image: alpine\nports:\n  udp:\n    allow: [true]\n",
            python: "ValueError: 'name' must be 1-63 lowercase alphanumeric characters or \
                     hyphens, starting with a letter or digit (got: 'BAD_NAME')",
            rust: Some("ValueError: ports.udp.allow entries must be integers (got: True)"),
        },
        Precedence {
            id: "preempts-name-via-passthrough",
            yaml: "name: BAD_NAME\ncontainer:\n  image: alpine\nports:\n  tcp:\n    \
                   passthrough: ['443']\n",
            python: "ValueError: 'name' must be 1-63 lowercase alphanumeric characters or \
                     hyphens, starting with a letter or digit (got: 'BAD_NAME')",
            rust: Some("ValueError: ports.tcp.passthrough entries must be integers (got: '443')"),
        },
        Precedence {
            id: "preempts-missing-image",
            yaml: "name: cage\ncontainer: {}\nports:\n  tcp:\n    allow: ['443']\n",
            python: "ValueError: container.image is required in config",
            rust: Some("ValueError: ports.tcp.allow entries must be integers (got: '443')"),
        },
        Precedence {
            id: "preempts-isolation",
            yaml: "name: cage\nisolation: jail\ncontainer:\n  image: alpine\nports:\n  tcp:\n    \
                   allow: ['443']\n",
            python: "ValueError: isolation must be 'container', 'vm', or 'apple-container' \
                     (got: 'jail')",
            rust: Some("ValueError: ports.tcp.allow entries must be integers (got: '443')"),
        },
    ];

    let hosts = hosts_for(&[]);
    let mut wrong: Vec<String> = Vec::new();
    for case in &cases {
        let expected = case.rust.unwrap_or(case.python);
        let produced = match pipeline("cage.yaml", case.yaml, &hosts) {
            Err(error) => error.as_python_traceback_line(),
            Ok(_) => "accepted the config".to_owned(),
        };
        if produced != expected {
            wrong.push(format!(
                "  {}\n      want: {expected}\n      got:  {produced}",
                case.id
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} precedence cases moved:\n{}",
        wrong.len(),
        wrong.join("\n")
    );

    let divergent = cases.iter().filter(|case| case.rust.is_some()).count();
    assert_eq!(
        divergent, 5,
        "the number of KNOWN precedence divergences changed. Every one of them is a \
         message an operator reads first, so a new one needs a reason in this test."
    );
}
