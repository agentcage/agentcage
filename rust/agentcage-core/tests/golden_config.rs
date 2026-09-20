//! The golden corpus, against the Rust config parser.
//!
//! `tests/fixtures/golden/` holds 125 valid `cage.yaml` cases, each with
//! the `resolved-config.json` that `config.py`'s `load_config` produced
//! from it. Reproducing all 125 byte for byte is PR C1's acceptance
//! check, and it is what turns "did I port 2,473 lines of parsing
//! correctly?" into a diff (RUST-PORT-PLAN.md §4, Layer 1).
//!
//! `tests/fixtures/scaffold-configs/` is the same comparison over the
//! eight built-in scaffolds' rendered `cage.yaml`. The corpus is a
//! matrix written *for* the corpus; the scaffolds are what
//! `agentcage init --scaffold claude-code` actually hands a new user,
//! and they exercise shapes the matrix does not. `scripts/
//! gen-scaffold-configs.py` generates them, with `--check` to prove they
//! are current.
//!
//! The `invalid/` half is mostly **not** this PR's. C1 parses and
//! rejects structural problems; the value checks belong to C2 and C3.
//! [`the_structural_invalid_cases_match_verbatim`] pins exactly which
//! messages C1 already reproduces, and — more usefully — asserts that
//! no case produces a *different* error than Python's. A case C1 accepts
//! is recorded as deferred, not as a pass.

mod common;

use std::path::{Path, PathBuf};

use agentcage_core::config::{Config, ConfigError, FixedHost, HostProbe, load, to_json};
use agentcage_core::yaml::{self, Value};

use common::repo_root;

/// The harness pins `config._host_dns_servers()` to these, so a case
/// that omits `dns_servers:` records them.
const FROZEN_DNS_SERVERS: [&str; 2] = ["192.0.2.53", "192.0.2.54"];

/// `tests/fixtures/golden/`.
fn corpus() -> PathBuf {
    repo_root().join("tests/fixtures/golden")
}

/// One case's platform, as `manifest.json` records it, turned into the
/// isolation backend `config.default_isolation()` would pick there.
///
/// Every apple-container case names its backend explicitly, so this
/// only ever supplies `"container"` today. It is derived from the
/// manifest anyway, so that a future Darwin case which *omits*
/// `isolation:` is read the way the harness read it rather than
/// silently landing on the Linux answer.
fn host_for(platform: &[String]) -> FixedHost {
    let isolation = match (
        platform.first().map(String::as_str),
        platform.get(1).map(String::as_str),
    ) {
        (Some("Darwin"), Some("arm64")) => "apple-container",
        (Some("Darwin"), _) => "vm",
        _ => "container",
    };
    FixedHost {
        isolation: isolation.to_owned(),
        dns_servers: Ok(FROZEN_DNS_SERVERS
            .iter()
            .map(|server| (*server).to_owned())
            .collect()),
    }
}

/// Every case in `manifest.json`, as `(case, kind, host)`.
fn manifest() -> Vec<(String, String, FixedHost)> {
    let path = corpus().join("manifest.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    let document: serde_json::Value = serde_json::from_str(&text).expect("manifest JSON");
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
                host_for(&platform),
            )
        })
        .collect()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

/// The acceptance check: all 125 valid cases, byte for byte.
#[test]
fn every_valid_case_reproduces_resolved_config() {
    let root = corpus();
    let mut wrong: Vec<String> = Vec::new();
    let mut checked = 0;

    for (case, kind, host) in manifest() {
        if kind != "valid" {
            continue;
        }
        let directory = root.join("valid").join(&case);
        let input = read(&directory.join("input/cage.yaml"));
        let expected = read(&directory.join("resolved-config.json"));

        match load("cage.yaml", &input, &host) {
            Ok(config) => {
                let produced = to_json(&config);
                if produced == expected {
                    checked += 1;
                } else {
                    wrong.push(format!(
                        "  {case}\n{}",
                        first_difference(&expected, &produced)
                    ));
                }
            }
            Err(error) => wrong.push(format!("  {case}: refused it -- {error}")),
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} valid cases did not reproduce resolved-config.json:\n{}",
        wrong.len(),
        checked + wrong.len(),
        wrong.join("\n")
    );
    assert_eq!(
        checked, 128,
        "the corpus grew or shrank; if that is intended, update this number"
    );
    println!("{checked} valid corpus configs reproduced resolved-config.json");
}

/// The persisted form of each config parses too.
///
/// `stored-cage.yaml` is what `state.save_deployment` wrote: the same
/// document re-emitted by PyYAML with generated placeholders filled in.
/// It is the file every later `cage` invocation reads, so the parser
/// has to accept PyYAML's own output as readily as the user's.
#[test]
fn every_stored_config_parses() {
    let root = corpus();
    let mut refused: Vec<String> = Vec::new();
    let mut checked = 0;

    for (case, kind, host) in manifest() {
        if kind != "valid" {
            continue;
        }
        let path = root.join("valid").join(&case).join("stored-cage.yaml");
        if !path.exists() {
            continue;
        }
        match load("stored-cage.yaml", &read(&path), &host) {
            Ok(_) => checked += 1,
            Err(error) => refused.push(format!("  {case}: {error}")),
        }
    }

    assert!(
        refused.is_empty(),
        "{} stored configs were refused:\n{}",
        refused.len(),
        refused.join("\n")
    );
    assert!(checked >= 128, "expected one stored config per valid case");
    println!("{checked} stored configs parsed");
}

/// Every built-in scaffold's rendered `cage.yaml`, byte for byte.
#[test]
fn every_scaffold_config_reproduces_resolved_config() {
    let root = repo_root().join("tests/fixtures/scaffold-configs");
    let names = read(&root.join("MANIFEST.txt"));
    let names: Vec<&str> = names.lines().filter(|line| !line.is_empty()).collect();
    assert!(!names.is_empty(), "no scaffold fixtures");

    // Every scaffold with a `cage.yaml.j2` must be in the fixture, so
    // adding one to `src/agentcage/scaffolds/` fails here rather than
    // going unparsed.
    let scaffolds = repo_root().join("src/agentcage/scaffolds");
    let mut expected: Vec<String> = std::fs::read_dir(&scaffolds)
        .expect("scaffolds directory")
        .filter_map(|entry| {
            let path = entry.expect("dir entry").path();
            path.join("cage.yaml.j2").exists().then(|| {
                path.file_name()
                    .expect("name")
                    .to_string_lossy()
                    .into_owned()
            })
        })
        .collect();
    expected.sort();
    assert_eq!(
        names, expected,
        "tests/fixtures/scaffold-configs is stale; \
         run `uv run python scripts/gen-scaffold-configs.py`"
    );

    let host = FixedHost {
        isolation: "container".to_owned(),
        dns_servers: Ok(FROZEN_DNS_SERVERS
            .iter()
            .map(|server| (*server).to_owned())
            .collect()),
    };
    let mut wrong: Vec<String> = Vec::new();
    for name in &names {
        let directory = root.join(name);
        let input = read(&directory.join("cage.yaml"));
        let expected = read(&directory.join("resolved-config.json"));
        match load("cage.yaml", &input, &host) {
            Ok(config) => {
                let produced = to_json(&config);
                if produced != expected {
                    wrong.push(format!(
                        "  {name}\n{}",
                        first_difference(&expected, &produced)
                    ));
                }
            }
            Err(error) => wrong.push(format!("  {name}: refused it -- {error}")),
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} scaffold configs did not reproduce resolved-config.json:\n{}",
        wrong.len(),
        names.len(),
        wrong.join("\n")
    );
    println!(
        "{} scaffold configs reproduced resolved-config.json",
        names.len()
    );
}

/// Every config the repo ships parses, whatever else is asserted about
/// it.
///
/// `tests/configs/**` and `tests/e2e/configs/**` are the pytest and
/// end-to-end corpora. They have no recorded `resolved-config.json`, so
/// this is the weaker check — but it is the one that covers the files a
/// contributor edits by hand.
#[test]
fn every_committed_config_parses() {
    let host = FixedHost::linux(&FROZEN_DNS_SERVERS);
    let mut refused: Vec<String> = Vec::new();
    let mut checked = 0;

    for path in common::committed_configs() {
        let text = read(&path);
        // Not every file under those trees is a cage.yaml -- some are
        // Lima templates or proxy configs. A document that is not a
        // mapping yields the default `Config`, which is fine; what is
        // being asserted is that nothing *errors*.
        match load(&path.to_string_lossy(), &text, &host) {
            Ok(_) => checked += 1,
            Err(error) => refused.push(format!("  {}: {error}", display(&path))),
        }
    }

    assert!(
        refused.is_empty(),
        "{} committed configs were refused:\n{}",
        refused.len(),
        refused.join("\n")
    );
    println!("{checked} committed configs parsed");
}

/// No config anywhere leans on a YAML 1.1 scalar the reader does not
/// resolve.
///
/// `crate::yaml` resolves 1.1 **booleans** and nothing else, so a plain
/// `0755` reaches the parser as the string `"0755"` where PyYAML gave
/// `config.py` the integer 493. The parser refuses such a value rather
/// than guessing, and this asserts the case is theoretical: if it ever
/// stops being, this test names the file, and the reader's coverage
/// becomes a real bug rather than a documented gap.
#[test]
fn no_committed_config_uses_an_unresolved_yaml_1_1_scalar() {
    let mut found: Vec<String> = Vec::new();

    let mut paths: Vec<PathBuf> = common::committed_configs();
    for (case, kind, _) in manifest() {
        let directory = corpus().join(if kind == "valid" { "valid" } else { "invalid" });
        for file in ["input/cage.yaml", "stored-cage.yaml"] {
            let path = directory.join(&case).join(file);
            if path.exists() {
                paths.push(path);
            }
        }
    }
    let scaffolds = repo_root().join("tests/fixtures/scaffold-configs");
    for name in read(&scaffolds.join("MANIFEST.txt")).lines() {
        if !name.is_empty() {
            paths.push(scaffolds.join(name).join("cage.yaml"));
        }
    }

    for path in paths {
        // A malformed case (there are two) has nothing to scan.
        let Ok(value) = yaml::load(&read(&path)) else {
            continue;
        };
        let mut hits = Vec::new();
        scan(&value, &mut Vec::new(), &mut hits);
        for (location, scalar) in hits {
            // A quoted scalar is a string to PyYAML too, so it is not a
            // disagreement. Telling quoted from plain properly needs
            // the style pass, which is private to `yaml`; a textual
            // look for the quoted spelling is enough for a tripwire and
            // costs nothing. `domains.expires` is why this matters --
            // its values are ISO-8601 timestamps, the corpus writes
            // them quoted, and an unquoted one WOULD diverge.
            let source = read(&path);
            if source.contains(&format!("'{scalar}'")) || source.contains(&format!("\"{scalar}\""))
            {
                continue;
            }
            found.push(format!("  {} at {location}: {scalar:?}", display(&path)));
        }
    }

    assert!(
        found.is_empty(),
        "these scalars mean different things to PyYAML and to \
         agentcage_core::yaml, so the reader's boolean-only 1.1 resolution is no longer \
         a theoretical gap:\n{}",
        found.join("\n")
    );
}

/// Which `invalid/` cases the parser already reproduces verbatim.
///
/// The point of this test is not the list — it is the third bucket. A
/// case that *errors* with different wording than `config.py` is a
/// failure, because that is a message a user would read. A case that
/// is accepted is fine: it is a value check, and C2 or C3 will add it.
/// So the two lists below grow as those PRs land, one per PR, and
/// nothing else here has to be touched.
#[test]
fn the_structural_invalid_cases_match_verbatim() {
    let root = corpus().join("invalid");
    let mut matched: Vec<String> = Vec::new();
    let mut deferred: Vec<String> = Vec::new();
    let mut differed: Vec<String> = Vec::new();

    for (case, kind, host) in manifest() {
        if kind != "invalid" {
            continue;
        }
        let input_path = root.join(&case).join("input/cage.yaml");
        if !input_path.exists() {
            // `invocation.txt` cases pin error paths no file on disk
            // can reach -- a missing config file, the host-DNS
            // detection failures.
            continue;
        }
        let expected = read(&root.join(&case).join("error.txt"));
        match load("cage.yaml", &read(&input_path), &host) {
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

    let mut expected: Vec<&str> = C1_OWNED.iter().chain(C3_OWNED).copied().collect();
    expected.sort_unstable();
    let matched: Vec<&str> = matched.iter().map(String::as_str).collect();
    assert_eq!(
        matched, expected,
        "the set of invalid cases the parser reproduces changed. Adding one is usually \
         right (C2/C3 landing); losing one is a regression."
    );
    println!(
        "{} invalid cases reproduced verbatim ({} by C1, {} by C3), {} deferred to C2",
        matched.len(),
        C1_OWNED.len(),
        C3_OWNED.len(),
        deferred.len()
    );
}

/// The `invalid/` cases [`load`] alone reproduces verbatim, in manifest
/// order.
///
/// Most are *structural* complaints `load_config` makes before any
/// validator runs: a section that is not a mapping, a removed schema
/// key, a list where an integer belongs. The five `err-secret*` entries
/// are the exception, and not one: `load_config` makes those value
/// checks inline, so they belong to PR C2 by ownership and to this list
/// by call site. `config::parse`'s module docs carry the inventory of
/// which value checks live there and who owns each.
///
/// The rest of `invalid/` needs [`validate`](agentcage_core::config::validate)
/// too, and `tests/golden_validate.rs` is where the whole pipeline is
/// checked against the corpus.
const C1_OWNED: &[&str] = &[
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
    "err-decider-timeout-not-finite",
    "err-port-entry-bool",
    "err-port-entry-not-int",
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
];

/// The `invalid/` cases PR C3 added to the *parse* path.
///
/// `config.py` calls `relays/_validate.validate_relay_entry` from
/// inside `load_config` and runs the `source:NAME` shape check on each
/// agent API key as soon as the roster entry is built, so these are
/// `load` errors rather than `validate_config` errors — which is why
/// they belong in this test and not in `golden_validate_agents.rs`.
///
/// Every relay message here comes from [`agentcage_core::relays`], the
/// module the egress proxy's `_validate.py` is now a second copy of;
/// `tests/contract_relay_entry.rs` holds it to the A4 fixture, and
/// this list is the corpus half of the same claim.
const C3_OWNED: &[&str] = &[
    "err-agents-decider-api-key-no-scheme",
    "err-agents-watcher-api-key-no-scheme",
    "err-relay-ca-file-and-pem",
    "err-relay-ca-file-not-string",
    "err-relay-ca-pem-not-pem",
    "err-relay-ca-pem-not-string",
    "err-relay-tls-false-with-ca",
    "err-relay-unknown-type",
    "err-relay-upstream-bad-port",
    "err-relay-write-mode-contradicts-readonly",
    "err-relay-write-mode-invalid",
];

/// Cases where C1 errors, deliberately, with wording of its own.
///
/// Each needs a reason, and "the Python message is nicer" is not one —
/// if the wording can be matched it should be.
const KNOWN_DIVERGENT: &[&str] = &[
    // PyYAML's scanner text ("expected ',' or ']', but got '<stream
    // end>'") is its own; `serde_norway` reports the same fault in its
    // own words. The surrounding sentence -- "<path> is not valid YAML
    // at line N, column M: " -- is reproduced, and the line and column
    // are what a user acts on.
    "err-yaml-syntax",
    "err-yaml-tab",
];

// ── helpers ─────────────────────────────────────────────

/// The first differing line of two documents, with context.
fn first_difference(expected: &str, produced: &str) -> String {
    for (index, (want, got)) in expected.lines().zip(produced.lines()).enumerate() {
        if want != got {
            return format!(
                "      line {}\n      python: {want}\n      rust:   {got}",
                index + 1
            );
        }
    }
    format!(
        "      same prefix; python has {} lines, rust has {}",
        expected.lines().count(),
        produced.lines().count()
    )
}

/// Collect scalars whose meaning differs between the two readers.
///
/// Only strings can be hits: anything the reader turned into a number
/// or a boolean already agrees. A *quoted* `'0755'` would be flagged
/// too — it is a string to both readers — which is a false positive
/// this test accepts, because nothing in the repo writes one and a
/// louder net is the right trade here.
fn scan(value: &Value, path: &mut Vec<String>, hits: &mut Vec<(String, String)>) {
    match value {
        Value::String(text) => {
            if pyyaml_would_read_a_number(text) {
                hits.push((path.join("."), text.clone()));
            }
        }
        Value::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(format!("[{index}]"));
                scan(item, path, hits);
                path.pop();
            }
        }
        Value::Mapping(mapping) => {
            for (key, entry) in mapping {
                path.push(key.as_str().unwrap_or("?").to_owned());
                scan(entry, path, hits);
                path.pop();
            }
        }
        _ => {}
    }
}

/// PyYAML's 1.1-**only** numeric and timestamp shapes.
///
/// Deliberately not `yaml::is_yaml_1_1_ambiguous`: that predicate is
/// the *emitter's*, and says yes to an ordinary `8` and to every
/// boolean spelling as well. Neither is a disagreement — `8` is a
/// number to both readers, and the booleans are the one family
/// `yaml::load` does resolve. What is wanted here is the families
/// `serde_norway` leaves as strings and PyYAML does not, transcribed
/// from PyYAML's own implicit resolver:
///
/// ```text
/// int    [-+]?0b[0-1_]+ | [-+]?0[0-7_]+ | [-+]?0x[0-9a-fA-F_]+
///        [-+]?(0|[1-9][0-9_]*)            (only when it has a `_`)
///        [-+]?[1-9][0-9_]*(:[0-5]?[0-9])+
/// float  the same sexagesimal, with a fraction; and `_` in a decimal
/// stamp  YYYY-MM-DD, with or without a time after it
/// ```
///
/// A *quoted* `'0755'` is flagged too — it is a string to both readers,
/// so it is a false positive. The test accepts that: nothing in the
/// repo writes one, and a louder net is the right trade for a check
/// whose job is to notice the day this gap stops being theoretical.
fn pyyaml_would_read_a_number(text: &str) -> bool {
    let body = text.strip_prefix(['-', '+']).unwrap_or(text);
    if body.is_empty() {
        return false;
    }
    is_radix_literal(body)
        || is_sexagesimal(body)
        || is_underscored_decimal(body)
        || is_timestamp(body)
}

/// `0b1010`, `0755`, `0x1f` — a base PyYAML knows and YAML 1.2 does
/// not spell the same way.
fn is_radix_literal(body: &str) -> bool {
    let digits = |rest: &str, allowed: fn(char) -> bool| {
        !rest.is_empty() && rest.chars().all(|c| allowed(c) || c == '_')
    };
    if let Some(rest) = body.strip_prefix("0b") {
        return digits(rest, |c| c == '0' || c == '1');
    }
    if let Some(rest) = body.strip_prefix("0x") {
        return digits(rest, |c| c.is_ascii_hexdigit());
    }
    match body.strip_prefix('0') {
        Some(rest) => digits(rest, |c| ('0'..='7').contains(&c)),
        None => false,
    }
}

/// `1:30`, `12:00:00`, `1:30.5` — base 60, which YAML dropped in 1.2.
fn is_sexagesimal(body: &str) -> bool {
    // A fractional tail is the float branch; strip it and check the
    // integer shape underneath.
    let (body, fraction_ok) = match body.split_once('.') {
        Some((head, tail)) => (head, tail.chars().all(|c| c.is_ascii_digit() || c == '_')),
        None => (body, true),
    };
    if !fraction_ok {
        return false;
    }
    let mut groups = body.split(':');
    let Some(first) = groups.next() else {
        return false;
    };
    if !first.starts_with(|c: char| ('1'..='9').contains(&c))
        || !first.chars().all(|c| c.is_ascii_digit() || c == '_')
    {
        return false;
    }
    let mut any = false;
    for group in groups {
        any = true;
        let ok = matches!(group.len(), 1 | 2)
            && group.chars().all(|c| c.is_ascii_digit())
            && group.as_bytes()[0] <= b'5';
        if !ok {
            return false;
        }
    }
    any
}

/// `1_000`, `1_000.5` — digit grouping PyYAML strips and YAML 1.2 does
/// not.
fn is_underscored_decimal(body: &str) -> bool {
    body.contains('_')
        && body.starts_with(|c: char| c.is_ascii_digit())
        && body
            .chars()
            .all(|c| c.is_ascii_digit() || c == '_' || c == '.')
}

/// `2024-01-02`, with or without a time — a `datetime` to PyYAML.
fn is_timestamp(body: &str) -> bool {
    let date = body.split(['T', 't', ' ']).next().unwrap_or(body);
    let parts: Vec<&str> = date.split('-').collect();
    parts.len() == 3
        && parts[0].len() == 4
        && matches!(parts[1].len(), 1 | 2)
        && matches!(parts[2].len(), 1 | 2)
        && parts
            .iter()
            .all(|part| part.chars().all(|c| c.is_ascii_digit()))
}

/// Path relative to the repo root, for readable failures.
fn display(path: &Path) -> String {
    path.strip_prefix(repo_root())
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// Keeps the unused-import lint honest about the trait and the types
/// the assertions above name only through inference.
#[allow(dead_code)]
fn _type_check(host: &dyn HostProbe) -> Result<Config, ConfigError> {
    load("<x>", "", host)
}
