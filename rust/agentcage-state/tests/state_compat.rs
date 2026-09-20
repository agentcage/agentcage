//! Read what the Python wrote — every file in PR A7's state fixture.
//!
//! # The point
//!
//! At cutover every existing user has cages the *Python* CLI deployed,
//! and the Rust binary must read that state in place, on first run,
//! with no migration step (RUST-PORT-PLAN.md §2.7). None of it carries
//! a schema version. There is nothing to branch on, so these readers
//! have to accept exactly what the Python writers produced —
//! and `tests/fixtures/state-compat/0.40.1/` is the definition of
//! "exactly".
//!
//! It is not hand-written JSON. `scripts/gen-state-fixtures.py` drives
//! the real code paths — `state.save_deployment`,
//! `state.fill_placeholders`, `state.save_proxy_config`,
//! `state.save_grants`, `secret_store.*`, `quadlets.generate_quadlets`
//! and the actual `cage backup` click command — inside a throwaway XDG
//! sandbox with the clock, the entropy, the uid and the subnet octet
//! all frozen, then scrubs every path down to `/home/agentcage-fixture`.
//!
//! `tests/test_state_compat.py` asserts concrete values against it on
//! the Python side. This file is its counterpart, and deliberately
//! asserts the same *values*, not merely that nothing raised: these
//! assertions are the specification, and a test that only proves the
//! parser did not crash proves nothing about the format.
//!
//! # Every file, and how that is checked rather than claimed
//!
//! [`covered`] runs every reader in the crate over the fixture and
//! returns the set of files it actually opened.
//! [`every_file_in_the_fixture_is_read`] compares that set against
//! `MANIFEST.json`, so a file added to a future generation fails this
//! suite until a reader reaches it. The one exception is stated in
//! that test and is not silent.
//!
//! # Why the fixture is copied first
//!
//! Several readers `mkdir` on the way in, and a `cargo test` run must
//! not mutate a committed fixture. The copy also relocates the two
//! XDG trees under a single sandbox `HOME`, which is what the
//! generator itself had: the apple-container root and the quadlet
//! directory follow `~` and ignore `XDG_CONFIG_HOME`, so a sandbox
//! that moved only the XDG variables would send those two at the
//! developer's real home directory.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use agentcage_core::audit::{AuditEntry, compute_summary, extract_audit_json};
use agentcage_core::config::FixedHost;
use agentcage_core::har::capture_to_har;
use agentcage_core::har::json::{Json, parse as parse_json};
use agentcage_core::yaml::{self, Value};
use agentcage_state::{AgentSchema, Paths, TestDir};

/// The three cages the generator emits, as `MANIFEST.json` names them.
const RICH: &str = "acme-agent";
const MINIMAL: &str = "plain-cage";
const APPLE: &str = "mac-agent";

/// The stand-in home every real path in the fixture was scrubbed to.
const SCRUB_HOME: &str = "/home/agentcage-fixture";

/// The generation under test.
///
/// A new agentcage version adds a directory here rather than replacing
/// one — keeping several generations is the point, since the Rust
/// reader has to cope with state written by any version a user might
/// be upgrading from. When a second one lands, this becomes a loop.
const GENERATION: &str = "0.40.1";

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/state-compat")
        .join(GENERATION)
}

/// A writable copy of the fixture, with both XDG trees under one home.
struct Fixture {
    dir: TestDir,
    paths: Paths,
}

impl Fixture {
    fn open() -> Self {
        let dir = TestDir::new("state-compat");
        let home = dir.join("home");
        let root = fixture_root();
        copy_tree(&root.join("xdg-config"), &home.join(".config"));
        copy_tree(&root.join("xdg-data"), &home.join(".local/share"));
        // The relay CA the stored `cage.yaml` names as
        // `upstream.ca_file: ~/fixture-ca.pem`. The Python suite plants
        // the same file under its fake home rather than stubbing the
        // resolver out, so a rewrite of `proxy-config.yaml` resolves it
        // for real.
        fs::write(
            home.join("fixture-ca.pem"),
            "-----BEGIN CERTIFICATE-----\n\
             TEST-NOT-A-REAL-CERTIFICATE-0001\n\
             -----END CERTIFICATE-----\n",
        )
        .unwrap();
        let paths = Paths::under(&home);
        Self { dir, paths }
    }

    fn paths(&self) -> &Paths {
        &self.paths
    }

    /// The manifest-relative spelling of a path inside the copy.
    ///
    /// The coverage ledger's other half: every reader hands back an
    /// absolute path under the sandbox, and the manifest names the
    /// same files as `xdg-config/...` / `xdg-data/...`.
    fn relative(&self, path: &Path) -> String {
        let home = self.dir.join("home");
        if let Ok(rest) = path.strip_prefix(home.join(".config")) {
            return format!("xdg-config/{}", rest.display());
        }
        if let Ok(rest) = path.strip_prefix(home.join(".local/share")) {
            return format!("xdg-data/{}", rest.display());
        }
        panic!("{} is outside the fixture copy", path.display());
    }
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn host() -> FixedHost {
    // The generator pinned `platform.system()` to Linux and
    // `_host_dns_servers()` to a fixed pair, so the corpus is identical
    // on a developer's Mac. Same here.
    FixedHost::linux(&["1.1.1.1", "9.9.9.9"])
}

fn manifest() -> Json {
    parse_json(&fs::read_to_string(fixture_root().join("MANIFEST.json")).unwrap()).unwrap()
}

/// `value[key]`, for the JSON documents in the fixture.
fn j<'a>(value: &'a Json, key: &str) -> &'a Json {
    value
        .get(key)
        .unwrap_or_else(|| panic!("no key {key:?} in {value:?}"))
}

fn jstr(value: &Json, key: &str) -> String {
    j(value, key)
        .as_str()
        .unwrap_or_else(|| panic!("{key:?} is not a string"))
        .to_owned()
}

fn jarray<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    match j(value, key) {
        Json::Array(items) => items,
        other => panic!("{key:?} is not an array: {other:?}"),
    }
}

fn jint(value: &Json, key: &str) -> i64 {
    match j(value, key) {
        Json::Int(n) => *n,
        other => panic!("{key:?} is not an int: {other:?}"),
    }
}

fn jkeys(value: &Json) -> Vec<&str> {
    match value {
        Json::Object(fields) => fields.iter().map(|(key, _)| key.as_str()).collect(),
        other => panic!("not an object: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────
// The fixture itself
// ─────────────────────────────────────────────────────────

#[test]
fn the_generation_is_stamped_with_its_version() {
    let manifest = manifest();
    assert_eq!(jstr(&manifest, "agentcage_version"), GENERATION);
    assert_eq!(
        jstr(&manifest, "generator"),
        "scripts/gen-state-fixtures.py"
    );
    let cages = j(&manifest, "cages");
    assert_eq!(jstr(cages, "rich"), RICH);
    assert_eq!(jstr(cages, "minimal"), MINIMAL);
    assert_eq!(jstr(cages, "apple"), APPLE);
    // The frozen values every assertion below leans on.
    let frozen = j(&manifest, "frozen");
    assert_eq!(jstr(frozen, "home"), SCRUB_HOME);
    assert_eq!(jstr(frozen, "now"), "2026-03-14T15:09:26+00:00");
    assert_eq!(jint(frozen, "network_octet"), 137);
    assert_eq!(jint(frozen, "uid"), 1000);
}

#[test]
fn the_manifest_lists_every_file_present() {
    let root = fixture_root();
    let mut on_disk: Vec<String> = Vec::new();
    walk(&root, &mut |path| {
        let relative = path.strip_prefix(&root).unwrap().display().to_string();
        if relative != "MANIFEST.json" {
            on_disk.push(relative);
        }
    });
    on_disk.sort();
    let listed: Vec<String> = jarray(&manifest(), "files")
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(listed, on_disk);
    assert_eq!(
        on_disk.len(),
        39,
        "the fixture is 39 files plus MANIFEST.json"
    );
}

fn walk(dir: &Path, visit: &mut impl FnMut(&Path)) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            walk(&entry.path(), visit);
        } else {
            visit(&entry.path());
        }
    }
}

/// Every file a reader in this crate opened, manifest-relative.
///
/// Exercised for its side effect: if a reader panics or returns an
/// error, this fails before any ledger comparison happens.
fn covered(fixture: &Fixture) -> BTreeSet<String> {
    let paths = fixture.paths();
    let mut seen = BTreeSet::new();
    let mut note = |path: PathBuf| {
        seen.insert(fixture.relative(&path));
    };

    for cage in [RICH, MINIMAL, APPLE] {
        paths.load_raw_config(cage, AgentSchema::Check).unwrap();
        paths.load_deployment_config(cage, &host()).unwrap();
        note(paths.stored_config_path(cage));

        paths.load_metadata(cage).unwrap();
        note(paths.metadata_path(cage));

        if paths.load_fingerprint(cage).is_some() {
            note(paths.fingerprint_path(cage));
        }
        if paths.proxy_config_path(cage).is_file() {
            yaml::load(&fs::read_to_string(paths.proxy_config_path(cage)).unwrap()).unwrap();
            note(paths.proxy_config_path(cage));
        }
        if paths.placeholders_env_path(cage).is_file() {
            note(paths.placeholders_env_path(cage));
        }
        if paths.dns_allowlist_path(cage).is_file() {
            note(paths.dns_allowlist_path(cage));
        }
        for key in paths.list_cred_keys(cage).unwrap() {
            note(paths.cred_path(cage, &key));
        }
        if !paths.load_secret_key_index(cage).unwrap().is_empty() {
            note(paths.secret_keys_path(cage));
        }
        if !paths.load_pending_secrets(cage).unwrap().is_empty() {
            note(paths.pending_secrets_path(cage));
        }
        if !paths.load_grants(cage).is_empty() {
            note(paths.grants_file(cage));
        }
        if paths.policy_audit_file(cage).is_file() {
            note(paths.policy_audit_file(cage));
        }
        if paths.capture_file(cage).is_file() {
            note(paths.capture_file(cage));
        }
        for patch in [
            paths.cage_resolv_patch(cage),
            paths.egress_resolv_patch(cage),
        ] {
            if patch.is_file() {
                note(patch);
            }
        }
        for apple in [
            paths.apple_audit_file(cage),
            paths.apple_capture_file(cage),
            paths.apple_dnsmasq_log(cage),
            paths.apple_ready_marker(cage),
        ] {
            if apple.is_file() {
                note(apple);
            }
        }
    }

    // The quadlets, which belong to no single reader: `Units` decides
    // which directory each one lives in.
    for entry in fs::read_dir(paths.quadlet_dir()).unwrap() {
        note(entry.unwrap().path());
    }

    seen
}

#[test]
fn every_file_in_the_fixture_is_read() {
    let fixture = Fixture::open();
    let read = covered(&fixture);

    let mut expected: BTreeSet<String> = jarray(&manifest(), "files")
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();

    // Two entries are not read by a `Paths` method, and both are
    // accounted for rather than quietly dropped:
    //
    //  * `README.md` documents the fixture; there is nothing to parse.
    //  * `backup/<name>-backup.tar.gz` is a gzipped tar, and the
    //    reader for it is `cage restore` — PR D11, whose acceptance
    //    check is restoring this exact tarball. It is still read here,
    //    structurally, by `the_backup_tarball_is_a_python_made_archive`.
    assert!(expected.remove("README.md"));
    assert!(expected.remove(&format!("backup/{RICH}-backup.tar.gz")));

    let missed: Vec<&String> = expected.difference(&read).collect();
    assert!(missed.is_empty(), "no reader opened: {missed:?}");
    let extra: Vec<&String> = read.difference(&expected).collect();
    assert!(
        extra.is_empty(),
        "read something not in the manifest: {extra:?}"
    );
    assert_eq!(read.len(), 37);
}

// ─────────────────────────────────────────────────────────
// load_raw_config
// ─────────────────────────────────────────────────────────

fn raw(fixture: &Fixture, cage: &str) -> Value {
    fixture
        .paths()
        .load_raw_config(cage, AgentSchema::Check)
        .unwrap()
}

fn at<'v>(value: &'v Value, key: &str) -> &'v Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("no key {key:?} in {value:?}"))
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_sequence()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect()
}

#[test]
fn load_raw_config_rich() {
    let fixture = Fixture::open();
    let raw = raw(&fixture, RICH);

    assert_eq!(at(&raw, "name").as_str(), Some(RICH));
    assert_eq!(at(&raw, "isolation").as_str(), Some("container"));
    assert_eq!(at(&raw, "lifecycle").as_str(), Some("service"));
    assert_eq!(at(&raw, "scaffold").as_str(), Some("claude-code"));

    let container = at(&raw, "container");
    assert_eq!(
        at(container, "image").as_str(),
        Some("docker.io/library/node:22-slim")
    );
    assert_eq!(strings(at(container, "command")), ["node", "/app/agent.js"]);
    assert_eq!(
        at(at(container, "named_volumes"), "acme-agent-npm").as_str(),
        Some("/home/node/.npm:rw")
    );

    assert_eq!(strings(at(&raw, "dns_servers")), ["1.1.1.1", "9.9.9.9"]);

    let domains = at(&raw, "domains");
    assert_eq!(at(domains, "mode").as_str(), Some("allowlist"));
    assert_eq!(
        strings(at(domains, "allow")),
        [
            "api.anthropic.com",
            "github.com",
            "*.githubusercontent.com",
            "registry.npmjs.org",
            "openrouter.ai",
        ]
    );
    assert_eq!(strings(at(domains, "block")), ["telemetry.example.com"]);
    assert_eq!(
        strings(at(domains, "passthrough")),
        ["pinned-api.example.com"]
    );
    assert_eq!(
        at(at(domains, "expires"), "temp-download.example.com").as_str(),
        Some("2026-09-08T18:00:00Z"),
        "an ISO timestamp must stay a string, not become a PyYAML date"
    );

    let tcp_allow: Vec<i64> = at(at(at(&raw, "ports"), "tcp"), "allow")
        .as_sequence()
        .unwrap()
        .iter()
        .map(|v| v.as_i64().unwrap())
        .collect();
    assert_eq!(tcp_allow, [80, 443, 993]);
    assert_eq!(
        at(at(at(&raw, "ports"), "icmp"), "allow").as_bool(),
        Some(false)
    );

    assert_eq!(at(&raw, "max_request_body").as_i64(), Some(10_485_760));
    assert_eq!(
        strings(at(at(&raw, "exec_aliases"), "claude")),
        ["claude", "--print"]
    );
}

#[test]
fn load_raw_config_key_order_is_preserved() {
    // `save_raw_config` dumps with `sort_keys=False`. cage.yaml key
    // order is user-visible after `cage edit`, so a reader that
    // normalised it would make the first Rust-written rewrite of a
    // Python cage.yaml a gratuitous whole-file diff.
    let fixture = Fixture::open();
    let raw = raw(&fixture, RICH);
    let keys: Vec<&str> = raw
        .as_mapping()
        .unwrap()
        .keys()
        .map(|k| k.as_str().unwrap())
        .collect();
    assert_eq!(
        keys[..6],
        [
            "name",
            "isolation",
            "lifecycle",
            "scaffold",
            "container",
            "dns_servers"
        ]
    );
}

#[test]
fn load_raw_config_secret_injection_shapes() {
    // Three rules, three different secret sources, one minted
    // placeholder.
    let fixture = Fixture::open();
    let raw = raw(&fixture, RICH);
    let rules = at(&raw, "secret_injection").as_sequence().unwrap();

    let envs: Vec<&str> = rules
        .iter()
        .map(|r| at(r, "env").as_str().unwrap())
        .collect();
    assert_eq!(envs, ["ANTHROPIC_API_KEY", "GITHUB_TOKEN", "IMAP_PASSWORD"]);

    assert_eq!(
        at(&rules[0], "source").as_str(),
        Some("systemd-creds:ANTHROPIC_API_KEY")
    );
    assert_eq!(strings(at(&rules[0], "inject_headers")), ["x-api-key"]);
    assert_eq!(at(&rules[0], "inject_body").as_bool(), Some(false));
    assert_eq!(
        at(&rules[1], "source").as_str(),
        Some("env:FIXTURE_GITHUB_TOKEN")
    );
    assert_eq!(
        strings(at(&rules[1], "inject_to")),
        ["github.com", "*.githubusercontent.com"]
    );

    // This rule omitted `placeholder:` in the operator's file;
    // `fill_placeholders` minted one and rewrote cage.yaml.
    let minted = at(&rules[2], "placeholder").as_str().unwrap();
    assert!(minted.starts_with("agentcage:secret:IMAP_PASSWORD:"));
    let entropy = minted.rsplit(':').next().unwrap();
    assert_eq!(entropy.len(), 32);
    assert!(entropy.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(rules[2].get("source").is_none());
}

#[test]
fn load_raw_config_protocol_relay() {
    let fixture = Fixture::open();
    let raw = raw(&fixture, RICH);
    let relay = &at(&raw, "protocol_relays").as_sequence().unwrap()[0];

    assert_eq!(at(relay, "name").as_str(), Some("mail"));
    assert_eq!(at(relay, "type").as_str(), Some("imap"));
    assert_eq!(at(relay, "listen").as_str(), Some("0.0.0.0:1143"));

    let upstream = at(relay, "upstream");
    assert_eq!(at(upstream, "host").as_str(), Some("imap.example.com"));
    assert_eq!(at(upstream, "port").as_i64(), Some(993));
    assert_eq!(at(upstream, "tls").as_bool(), Some(true));
    assert_eq!(
        at(upstream, "tls_servername").as_str(),
        Some("imap.example.com")
    );
    // Still the host path in the *stored* config; only the derived
    // proxy-config.yaml carries the inlined PEM.
    assert_eq!(at(upstream, "ca_file").as_str(), Some("~/fixture-ca.pem"));

    assert_eq!(
        at(at(relay, "policy"), "write_mode").as_str(),
        Some("organise")
    );
    assert_eq!(
        strings(at(at(relay, "policy"), "folder_allowlist")),
        ["INBOX", "Archive"]
    );
    assert_eq!(
        at(at(relay, "auth"), "password_source").as_str(),
        Some("systemd-creds:IMAP_PASSWORD")
    );
}

#[test]
fn load_raw_config_agents() {
    let fixture = Fixture::open();
    let raw = raw(&fixture, RICH);
    let agents = at(&raw, "agents");

    let decider = at(agents, "decider");
    assert_eq!(at(decider, "enable").as_bool(), Some(true));
    assert_eq!(at(decider, "provider").as_str(), Some("openrouter"));
    assert_eq!(at(decider, "model").as_str(), Some("z-ai/glm-5.3"));
    assert_eq!(
        at(decider, "api_key").as_str(),
        Some("systemd-creds:OPENROUTER_API_KEY")
    );

    let watcher = at(agents, "watcher");
    assert_eq!(at(watcher, "auto_revoke").as_bool(), Some(true));
    assert_eq!(at(watcher, "max_digest_tokens").as_i64(), Some(8000));
}

#[test]
fn load_raw_config_minimal() {
    // A cage whose config sets almost nothing still round-trips, and
    // the *absence* of everything else is part of the fixture.
    let fixture = Fixture::open();
    let raw = raw(&fixture, MINIMAL);
    let mapping = raw.as_mapping().unwrap();
    assert_eq!(
        mapping
            .keys()
            .map(|k| k.as_str().unwrap())
            .collect::<Vec<_>>(),
        ["name", "container", "dns_servers"]
    );
    assert_eq!(at(&raw, "name").as_str(), Some(MINIMAL));
    assert_eq!(
        at(at(&raw, "container"), "image").as_str(),
        Some("localhost/plain:latest")
    );
    assert_eq!(strings(at(&raw, "dns_servers")), ["1.1.1.1"]);
}

#[test]
fn list_deployments_finds_all_three() {
    let fixture = Fixture::open();
    assert_eq!(
        fixture.paths().list_deployments().unwrap(),
        [RICH, APPLE, MINIMAL]
    );
    for cage in [RICH, MINIMAL, APPLE] {
        assert!(fixture.paths().deployment_exists(cage));
    }
}

#[test]
fn load_deployment_config_parses_to_a_full_config() {
    // The full validating parser, not just the raw YAML reader.
    let fixture = Fixture::open();
    let cfg = fixture
        .paths()
        .load_deployment_config(RICH, &host())
        .unwrap();

    assert_eq!(cfg.name, RICH);
    assert_eq!(cfg.isolation, "container");
    assert_eq!(cfg.scaffold, "claude-code");
    assert_eq!(cfg.dns_servers, ["1.1.1.1", "9.9.9.9"]);
    assert_eq!(cfg.domains.mode, "allowlist");
    assert_eq!(cfg.domains.block, ["telemetry.example.com"]);
    assert_eq!(cfg.ports.tcp.allow, [80, 443, 993]);
    assert_eq!(cfg.secrets.backend, "systemd-creds");
    assert_eq!(cfg.secrets.scope, "user");
    assert!(!cfg.secrets.allow_plaintext);
    assert_eq!(
        cfg.secret_injection
            .iter()
            .map(|r| r.env.as_str())
            .collect::<Vec<_>>(),
        ["ANTHROPIC_API_KEY", "GITHUB_TOKEN", "IMAP_PASSWORD"]
    );
    assert!(cfg.capture.enable_har);
    assert_eq!(cfg.capture.exclude_domains, ["registry.npmjs.org"]);
    assert!(cfg.agents.decider.enable);
    assert_eq!(cfg.agents.watcher.max_flows, 100);

    let relay = &cfg.protocol_relays[0];
    assert_eq!(relay.name, "mail");
    assert_eq!(relay.r#type, "imap");
    assert_eq!(relay.listen, "0.0.0.0:1143");
    assert_eq!(relay.upstream.host, "imap.example.com");
    assert_eq!(relay.upstream.port, 993);
    assert!(relay.upstream.tls);
    assert_eq!(relay.policy.write_mode, "organise");
}

#[test]
fn the_apple_cage_keeps_its_isolation_through_a_linux_parse() {
    // `apple-container` isolation would be *rejected* by
    // `validate_config` on Linux; the parser does not run it, and
    // `cage list` on a Mac-shaped cage must still read.
    let fixture = Fixture::open();
    let cfg = fixture
        .paths()
        .load_deployment_config(APPLE, &host())
        .unwrap();
    assert_eq!(cfg.isolation, "apple-container");
    assert_eq!(cfg.secrets.backend, "keychain");
}

// ─────────────────────────────────────────────────────────
// metadata.json
// ─────────────────────────────────────────────────────────

#[test]
fn load_metadata_rich() {
    // A bare `json.dumps(dict)` — no version field to branch on.
    let fixture = Fixture::open();
    let meta = fixture.paths().load_metadata(RICH).unwrap();
    assert_eq!(jstr(&meta, "agentcage_version"), GENERATION);
    assert_eq!(jstr(&meta, "scaffold"), "claude-code");
    assert_eq!(jint(&meta, "network_octet"), 137);
    // Insertion order, not sorted: `network_octet` comes last.
    assert_eq!(
        jkeys(&meta),
        ["agentcage_version", "scaffold", "network_octet"]
    );
    assert_eq!(meta.get("state_version"), None);
}

#[test]
fn load_metadata_minimal_has_no_scaffold() {
    let fixture = Fixture::open();
    let meta = fixture.paths().load_metadata(MINIMAL).unwrap();
    assert_eq!(jstr(&meta, "agentcage_version"), GENERATION);
    assert_eq!(meta.get("scaffold"), None);
    assert_eq!(jint(&meta, "network_octet"), 137);

    // The apple cage has neither: no subnet, no scaffold.
    let apple = fixture.paths().load_metadata(APPLE).unwrap();
    assert_eq!(jkeys(&apple), ["agentcage_version"]);
}

#[test]
fn load_metadata_missing_returns_empty() {
    let fixture = Fixture::open();
    assert_eq!(
        jkeys(&fixture.paths().load_metadata("no-such-cage").unwrap()),
        Vec::<&str>::new()
    );
}

#[test]
fn metadata_json_is_compact_single_line_and_survives_a_rewrite() {
    let fixture = Fixture::open();
    let path = fixture.paths().metadata_path(RICH);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.starts_with(r#"{"agentcage_version":"#));
    assert!(!text.contains('\n'), "no indent, no trailing newline");

    // Read-modify-write is what `cli.py` does, and it must not
    // re-order the file: a `BTreeMap` would hoist `network_octet`
    // above `scaffold`.
    let meta = fixture.paths().load_metadata(RICH).unwrap();
    fixture.paths().save_metadata(RICH, &meta).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), text);
}

// ─────────────────────────────────────────────────────────
// fingerprint.json
// ─────────────────────────────────────────────────────────

#[test]
fn load_fingerprint() {
    let fixture = Fixture::open();
    let fp = fixture.paths().load_fingerprint(RICH).unwrap();

    assert_eq!(jint(&fp, "version"), 1);
    assert_eq!(
        jint(&fp, "version"),
        agentcage_core::fingerprint::FINGERPRINT_VERSION
    );
    let components = j(&fp, "components");
    // `sort_keys=True` wrote them in this order.
    assert_eq!(
        jkeys(components),
        [
            "cage_yaml",
            "image_digests",
            "resolved_config",
            "scaffold_version",
            "units"
        ]
    );
    for name in jkeys(components) {
        assert_eq!(jstr(components, name).len(), 64, "{name} is not a sha256");
    }
    assert_eq!(
        jstr(&fp, "fingerprint"),
        "f1f70ea67d597f124616fa0b0a328d18ea1d26ca61eafc1e5e548ae3b161e24d"
    );
    assert_eq!(
        jstr(components, "cage_yaml"),
        "e7f77ad79b39cc797ea4f7b2bb22db247cf0df2b86e8867e9ae5cfd887abca43"
    );
}

#[test]
fn a_stored_python_fingerprint_is_read_back_as_a_match() {
    // The cutover test in miniature: `cage update` compares the stored
    // document against a freshly computed one and must be able to
    // conclude "no change" from a *Python*-written file.
    let fixture = Fixture::open();
    let stored = fixture.paths().load_fingerprint(RICH).unwrap();
    let components = j(&stored, "components");
    let rebuilt = agentcage_core::fingerprint::Fingerprint {
        version: jint(&stored, "version"),
        components: agentcage_core::fingerprint::Components {
            cage_yaml: jstr(components, "cage_yaml"),
            resolved_config: jstr(components, "resolved_config"),
            units: jstr(components, "units"),
            image_digests: jstr(components, "image_digests"),
            scaffold_version: jstr(components, "scaffold_version"),
        },
        fingerprint: jstr(&stored, "fingerprint"),
    };
    assert!(agentcage_core::fingerprint::fingerprint_matches(
        &stored, &rebuilt
    ));
}

#[test]
fn fingerprint_json_is_indented_and_sorted() {
    let fixture = Fixture::open();
    let text = fs::read_to_string(fixture.paths().fingerprint_path(RICH)).unwrap();
    assert!(text.ends_with("}\n"));
    assert!(text.lines().nth(1).unwrap().starts_with("  \"components\""));

    // And the Rust writer reproduces those bytes exactly.
    let fp = fixture.paths().load_fingerprint(RICH).unwrap();
    fixture.paths().save_fingerprint(RICH, &fp).unwrap();
    assert_eq!(
        fs::read_to_string(fixture.paths().fingerprint_path(RICH)).unwrap(),
        text
    );
}

#[test]
fn a_never_deployed_cage_has_no_fingerprint() {
    let fixture = Fixture::open();
    assert_eq!(fixture.paths().load_fingerprint(MINIMAL), None);
    assert_eq!(fixture.paths().load_fingerprint(APPLE), None);
}

// ─────────────────────────────────────────────────────────
// the grants overlay
// ─────────────────────────────────────────────────────────

#[test]
fn load_grants() {
    // The overlay is `grants/grants.yaml` — a YAML *list*, not JSON.
    let fixture = Fixture::open();
    assert_eq!(
        fixture.paths().grants_file(RICH).file_name().unwrap(),
        "grants.yaml"
    );

    let grants = fixture.paths().load_grants(RICH);
    assert_eq!(grants.len(), 2);

    let first = &grants[0];
    assert_eq!(
        first.get("domain").unwrap().as_str(),
        Some("files.pythonhosted.org")
    );
    assert_eq!(
        first.get("granted_at").unwrap().as_str(),
        Some("2026-03-14T15:00:00+00:00")
    );
    assert_eq!(
        first.get("expires_at").unwrap().as_str(),
        Some("2026-03-14T16:00:00+00:00")
    );
    assert_eq!(
        first.get("reason").unwrap().as_str(),
        Some("pip install requested by the decider")
    );
    assert_eq!(first.get("source").unwrap().as_str(), Some("policy-hook"));

    let second = &grants[1];
    assert_eq!(
        second.get("domain").unwrap().as_str(),
        Some("objects.githubusercontent.com")
    );
    assert_eq!(second.get("source").unwrap().as_str(), Some("operator"));
    // An empty `expires_at` means "no expiry", not "expired" — and it
    // is an empty *string*, which is why the emitter has to quote it.
    assert_eq!(second.get("expires_at").unwrap().as_str(), Some(""));
}

#[test]
fn the_grants_overlay_survives_a_rust_rewrite() {
    let fixture = Fixture::open();
    let before = fixture.paths().load_grants(RICH);
    fixture.paths().save_grants(RICH, &before).unwrap();
    assert_eq!(fixture.paths().load_grants(RICH), before);
    // Still quoted, so PyYAML does not read it back as `None`.
    let text = fs::read_to_string(fixture.paths().grants_file(RICH)).unwrap();
    assert!(text.contains("expires_at: ''"), "{text}");
}

#[test]
fn load_grants_absent_is_empty() {
    let fixture = Fixture::open();
    assert!(fixture.paths().load_grants(MINIMAL).is_empty());
    assert!(fixture.paths().load_grants(APPLE).is_empty());
}

#[test]
fn the_policy_audit_trail_is_one_object_per_line() {
    let fixture = Fixture::open();
    let path = fixture.paths().policy_audit_file(RICH);
    let text = fs::read_to_string(&path).unwrap();
    let entries: Vec<Json> = text.lines().map(|line| parse_json(line).unwrap()).collect();

    assert_eq!(entries.len(), 2);
    assert_eq!(jstr(&entries[0], "kind"), "policy_grant_applied");
    assert_eq!(jstr(&entries[1], "kind"), "policy_grant_removed");
    assert_eq!(jstr(&entries[0], "domain"), "files.pythonhosted.org");
    assert_eq!(jstr(&entries[0], "ts"), "2026-03-14T15:09:26+00:00");
    assert_eq!(jkeys(&entries[0])[0], "ts", "ts is prepended, not appended");
    // `ts` is prepended, not appended.
    assert!(text.starts_with(r#"{"ts": "#));

    // It must NOT live inside grants/ — that directory is bind-mounted
    // read-write into the egress container.
    assert_eq!(path.parent(), fixture.paths().grants_dir(RICH).parent());
}

// ─────────────────────────────────────────────────────────
// the secret stores' files (the format; the stores are D3's)
// ─────────────────────────────────────────────────────────

#[test]
fn the_secret_key_index_is_a_sorted_array_of_names() {
    let fixture = Fixture::open();
    assert_eq!(
        fixture.paths().load_secret_key_index(RICH).unwrap(),
        ["ANTHROPIC_API_KEY", "GITHUB_TOKEN"]
    );
    assert_eq!(
        fixture.paths().load_secret_key_index(APPLE).unwrap(),
        ["ANTHROPIC_API_KEY", "OPENROUTER_API_KEY"]
    );
    assert!(
        fixture
            .paths()
            .load_secret_key_index(MINIMAL)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn pending_secrets_is_a_list_of_pairs() {
    // Not an object. Both writers agree on this —
    // `ApplePlaintextStore._save` and the VM hand-off in `cli.py` — and
    // a reader that assumed a map would fail on every cage that ever
    // used either path.
    let fixture = Fixture::open();
    assert_eq!(
        fixture.paths().load_pending_secrets(RICH).unwrap(),
        [(
            "GITHUB_TOKEN".to_owned(),
            "TEST-NOT-A-REAL-SECRET-0003".to_owned()
        )]
    );
    assert_eq!(
        fixture.paths().load_pending_secrets(APPLE).unwrap(),
        [(
            "GITHUB_TOKEN".to_owned(),
            "TEST-NOT-A-REAL-SECRET-0003".to_owned()
        )]
    );
    assert!(
        fixture
            .paths()
            .load_pending_secrets(MINIMAL)
            .unwrap()
            .is_empty()
    );

    // The bytes on disk really are a nested array.
    let text = fs::read_to_string(fixture.paths().pending_secrets_path(RICH)).unwrap();
    assert!(text.starts_with("[["), "{text}");
}

#[test]
fn cred_blobs_are_found_by_name_and_never_parsed() {
    // systemd-creds encryption is host-bound, so the blob is opaque
    // everywhere except the machine that made it. The Rust port has
    // the same obligation the Python has: find the file, hand it to
    // `systemd-creds decrypt`, never parse it.
    let fixture = Fixture::open();
    assert_eq!(
        fixture.paths().list_cred_keys(RICH).unwrap(),
        ["ANTHROPIC_API_KEY", "IMAP_PASSWORD", "OPENROUTER_API_KEY"]
    );
    assert!(fixture.paths().list_cred_keys(MINIMAL).unwrap().is_empty());

    let blob = fs::read(fixture.paths().cred_path(RICH, "ANTHROPIC_API_KEY")).unwrap();
    assert!(blob.len() > 64);
    // base64 armour, as `systemd-creds encrypt … -` emits it.
    assert!(
        blob.iter()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=\n\t ".contains(b))
    );
}

// ─────────────────────────────────────────────────────────
// the derived artifacts
// ─────────────────────────────────────────────────────────

fn proxy_config(fixture: &Fixture, cage: &str) -> Value {
    yaml::load(&fs::read_to_string(fixture.paths().proxy_config_path(cage)).unwrap()).unwrap()
}

#[test]
fn the_proxy_config_holds_only_the_whitelisted_keys() {
    let fixture = Fixture::open();
    let cfg = proxy_config(&fixture, RICH);
    for key in cfg.as_mapping().unwrap().keys() {
        let key = key.as_str().unwrap();
        assert!(
            agentcage_state::PROXY_KEYS.contains(&key) || key == "agentcage_version",
            "{key} is not a proxy key"
        );
    }
    for leaked in ["container", "dns_servers", "name", "isolation", "ports"] {
        assert!(cfg.get(leaked).is_none(), "{leaked} reached the proxy");
    }
    assert_eq!(
        strings(at(at(&cfg, "domains"), "allow"))[0],
        "api.anthropic.com"
    );
    assert_eq!(at(at(&cfg, "capture"), "enable_har").as_bool(), Some(true));
    assert_eq!(
        at(at(at(&cfg, "agents"), "decider"), "model").as_str(),
        Some("z-ai/glm-5.3")
    );
}

#[test]
fn the_proxy_config_inlines_the_relay_ca() {
    let fixture = Fixture::open();
    let cfg = proxy_config(&fixture, RICH);
    let relay = &at(&cfg, "protocol_relays").as_sequence().unwrap()[0];
    let upstream = at(relay, "upstream");

    assert!(
        upstream.get("ca_file").is_none(),
        "the host path must not reach the proxy"
    );
    let pem = at(upstream, "ca_pem").as_str().unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(pem.contains("TEST-NOT-A-REAL-CERTIFICATE-0001"));
    // The version stamp the Policy API reports when AGENTCAGE_VERSION
    // is unset in the egress environment.
    assert_eq!(at(&cfg, "agentcage_version").as_str(), Some(GENERATION));
}

#[test]
fn the_proxy_config_of_a_defaulted_cage_is_just_the_version() {
    let fixture = Fixture::open();
    let cfg = proxy_config(&fixture, MINIMAL);
    let mapping = cfg.as_mapping().unwrap();
    assert_eq!(mapping.len(), 1);
    assert_eq!(at(&cfg, "agentcage_version").as_str(), Some(GENERATION));
}

#[test]
fn rewriting_the_proxy_config_reproduces_the_python_by_value() {
    // §2.8: the port is allowed to differ from PyYAML's *formatting*
    // (it already drops comments today), so the corpus compares YAML
    // by parsed value. The content has to be identical.
    let fixture = Fixture::open();
    for cage in [RICH, MINIMAL, APPLE] {
        let before = proxy_config(&fixture, cage);
        fixture.paths().save_proxy_config(cage, GENERATION).unwrap();
        let after = proxy_config(&fixture, cage);
        assert!(
            yaml::eq_with_key_order(&before, &after),
            "{cage}: proxy-config.yaml changed\nbefore: {before:?}\nafter:  {after:?}"
        );
    }
}

#[test]
fn the_placeholders_env_is_one_line_per_injected_secret() {
    let fixture = Fixture::open();
    let text = fs::read_to_string(fixture.paths().placeholders_env_path(RICH)).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(text.ends_with('\n'));

    let envs: Vec<&str> = lines.iter().map(|l| l.split_once('=').unwrap().0).collect();
    assert_eq!(envs, ["ANTHROPIC_API_KEY", "GITHUB_TOKEN", "IMAP_PASSWORD"]);
    for line in &lines {
        let (env, placeholder) = line.split_once('=').unwrap();
        assert!(placeholder.starts_with(&format!("agentcage:secret:{env}:")));
    }
    assert!(lines[0].ends_with(":aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

    // And the Rust writer reproduces it byte for byte.
    fixture.paths().save_placeholders_env(RICH).unwrap();
    assert_eq!(
        fs::read_to_string(fixture.paths().placeholders_env_path(RICH)).unwrap(),
        text
    );
}

#[test]
fn the_placeholders_env_is_empty_when_nothing_is_injected() {
    let fixture = Fixture::open();
    assert_eq!(
        fs::read_to_string(fixture.paths().placeholders_env_path(MINIMAL)).unwrap(),
        ""
    );
    fixture.paths().save_placeholders_env(MINIMAL).unwrap();
    assert_eq!(
        fs::read_to_string(fixture.paths().placeholders_env_path(MINIMAL)).unwrap(),
        ""
    );
}

#[test]
fn the_dns_allowlist_is_domains_times_upstreams() {
    let fixture = Fixture::open();
    let text = fs::read_to_string(fixture.paths().dns_allowlist_path(RICH)).unwrap();
    let lines: Vec<&str> = text.lines().collect();

    assert_eq!(
        lines[..4],
        [
            "server=/api.anthropic.com/1.1.1.1",
            "server=/api.anthropic.com/9.9.9.9",
            "server=/github.com/1.1.1.1",
            "server=/github.com/9.9.9.9",
        ]
    );
    // The relay upstream is allowlisted too; blocked domains are not.
    assert!(lines.contains(&"server=/imap.example.com/1.1.1.1"));
    assert!(!lines.iter().any(|l| l.contains("telemetry.example.com")));
    assert_eq!(lines.len(), 14);

    // Byte for byte from the Rust writer, including the passthrough
    // and relay-derived entries the allowlist picks up.
    fixture.paths().save_dns_allowlist(RICH, &host()).unwrap();
    assert_eq!(
        fs::read_to_string(fixture.paths().dns_allowlist_path(RICH)).unwrap(),
        text
    );
}

#[test]
fn the_defaulted_cages_allowlist_is_an_empty_file() {
    let fixture = Fixture::open();
    assert_eq!(
        fs::read_to_string(fixture.paths().dns_allowlist_path(MINIMAL)).unwrap(),
        ""
    );
    fixture
        .paths()
        .save_dns_allowlist(MINIMAL, &host())
        .unwrap();
    assert_eq!(
        fs::read_to_string(fixture.paths().dns_allowlist_path(MINIMAL)).unwrap(),
        ""
    );
    // The apple cage is in allowlist mode with one domain and one
    // resolver: exactly one line.
    assert_eq!(
        fs::read_to_string(fixture.paths().dns_allowlist_path(APPLE)).unwrap(),
        "server=/api.anthropic.com/1.1.1.1\n"
    );
}

// ─────────────────────────────────────────────────────────
// the quadlets systemd is still running
// ─────────────────────────────────────────────────────────

#[test]
fn the_installed_quadlets_are_where_the_unit_router_expects_them() {
    let fixture = Fixture::open();
    let fake = agentcage_exec::FakeRunner::new();
    fake.assume_installed()
        .push(agentcage_exec::Reply::status(0));
    let units = agentcage_state::Units::with_elevation(
        fixture.paths(),
        &fake,
        agentcage_exec::Elevation::none(),
    );

    let mut names: Vec<String> = fs::read_dir(fixture.paths().quadlet_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "acme-agent-cage.container",
            "acme-agent-certs.volume",
            "acme-agent-egress.container",
            "acme-agent-net.network",
            "acme-agent-public-certs.volume",
        ]
    );
    for name in &names {
        assert_eq!(
            units.unit_dir_for(name),
            fixture.paths().quadlet_dir(),
            "{name} was routed away from the quadlet directory"
        );
    }
    // The fixture's cage has no nested-podman volume.
    assert!(!units.has_podman_storage_volume(RICH));

    let cage = fs::read_to_string(
        fixture
            .paths()
            .quadlet_dir()
            .join("acme-agent-cage.container"),
    )
    .unwrap();
    assert!(cage.contains("ContainerName=acme-agent-cage"));
    assert!(cage.contains("Image=docker.io/library/node:22-slim"));
    // The pinned subnet: metadata.json's network_octet is 137.
    assert!(cage.contains("Network=acme-agent-net.network:ip=10.89.137.2"));
    assert!(cage.contains(&format!(r#"Environment="AGENTCAGE_VERSION={GENERATION}""#)));
    // The paths in the units are the *scrubbed* ones, so they are the
    // shape `Paths` derives, just rooted at the fixture's fake home.
    assert!(cage.contains(&format!(
        "EnvironmentFile={SCRUB_HOME}/.config/agentcage/cages/acme-agent\
         /cage-env/placeholders.env"
    )));

    let egress = fs::read_to_string(
        fixture
            .paths()
            .quadlet_dir()
            .join("acme-agent-egress.container"),
    )
    .unwrap();
    assert!(egress.contains(&format!("Image=localhost/agentcage-egress:{GENERATION}")));
    assert!(egress.contains(r#"systemd-creds --user decrypt --name "ANTHROPIC_API_KEY""#));
    // Runtime secrets stage under %t, never a literal uid.
    assert!(egress.contains("%t/agentcage/acme-agent/secrets"));
    assert!(!egress.contains("/run/user/1000/agentcage"));

    // Nothing above spawned a process; the router is a file check.
    assert_eq!(fake.call_count(), 0);
}

#[test]
fn the_patches_dir_is_shared_and_holds_both_resolv_files() {
    let fixture = Fixture::open();
    let mut names: Vec<String> = fs::read_dir(fixture.paths().patches_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["resolv-acme-agent.conf", "resolv-egress-acme-agent.conf"]
    );

    assert_eq!(
        fs::read_to_string(fixture.paths().cage_resolv_patch(RICH)).unwrap(),
        "nameserver 10.89.137.10\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.paths().egress_resolv_patch(RICH)).unwrap(),
        "nameserver 1.1.1.1\nnameserver 9.9.9.9\n"
    );
    // Shared, not per-cage: both files sit in one directory that is not
    // under either cage's data dir.
    assert_eq!(
        fixture.paths().patches_dir(),
        fixture.paths().data_root().join("patches")
    );
    assert!(
        !fixture
            .paths()
            .patches_dir()
            .starts_with(fixture.paths().cage_data_dir(RICH))
    );
}

// ─────────────────────────────────────────────────────────
// the logs the egress wrote
// ─────────────────────────────────────────────────────────

#[test]
fn the_capture_jsonl_round_trips_through_the_har_builder() {
    let fixture = Fixture::open();
    let text = fs::read_to_string(fixture.paths().capture_file(RICH)).unwrap();
    let entries: Vec<Json> = text.lines().map(|line| parse_json(line).unwrap()).collect();
    assert_eq!(entries.len(), 2);

    let first = &entries[0];
    assert_eq!(jstr(first, "flow_id"), "fixture-flow-0001");
    assert_eq!(jstr(first, "decision"), "allowed");
    assert_eq!(jstr(first, "host"), "api.anthropic.com");
    assert_eq!(jstr(first, "direction"), "outbound");

    // Headers are [name, value] pairs, and both perspectives are
    // recorded: inbound keeps the placeholder, outbound has the wire
    // value.
    let header = |entry: &Json, view: &str, name: &str| -> String {
        let Json::Array(headers) = j(j(entry, view), "request").get("headers").unwrap() else {
            panic!("headers is not an array")
        };
        headers
            .iter()
            .find_map(|pair| match pair {
                Json::Array(pair) if pair[0].as_str() == Some(name) => pair[1].as_str(),
                _ => None,
            })
            .unwrap()
            .to_owned()
    };
    assert!(
        header(first, "inbound", "x-api-key").starts_with("agentcage:secret:ANTHROPIC_API_KEY:")
    );
    assert_eq!(
        header(first, "outbound", "x-api-key"),
        "TEST-NOT-A-REAL-SECRET-0001"
    );

    assert_eq!(jstr(&entries[1], "decision"), "blocked");
    assert_eq!(
        jstr(&jarray(&entries[1], "inspectors")[0], "name"),
        "domain"
    );
    assert_eq!(
        j(j(&entries[1], "outbound"), "response"),
        &Json::Object(Vec::new())
    );

    let har = capture_to_har(&entries, "inbound");
    let log = j(&har, "log");
    assert_eq!(jstr(log, "version"), "1.2");
    let har_entries = jarray(log, "entries");
    assert_eq!(har_entries.len(), 2);
    assert_eq!(
        jstr(j(&har_entries[0], "request"), "url"),
        "https://api.anthropic.com/v1/messages"
    );
    assert_eq!(jint(j(&har_entries[0], "response"), "status"), 200);

    let outbound = capture_to_har(&entries, "outbound");
    let out_entries = jarray(j(&outbound, "log"), "entries");
    let value = jarray(j(&out_entries[0], "request"), "headers")
        .iter()
        .find(|h| h.get("name").and_then(Json::as_str) == Some("x-api-key"))
        .map(|h| jstr(h, "value"))
        .unwrap();
    assert_eq!(value, "TEST-NOT-A-REAL-SECRET-0001");
}

#[test]
fn the_apple_container_root_is_a_third_state_root() {
    // `~/.config/agentcage/apple-container/<name>/logs/` — NOT under
    // the deployments dir and NOT under $XDG_DATA_HOME. And on the
    // container and vm backends there is no host-side `audit.jsonl` at
    // all: the addon writes to stderr and the host reads journalctl.
    let fixture = Fixture::open();
    let paths = fixture.paths();

    let logs = paths.apple_logs_dir(APPLE);
    let mut names: Vec<String> = fs::read_dir(&logs)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["audit.jsonl", "capture.jsonl", "dnsmasq.log", "ready"]
    );

    // It is neither of the other two roots.
    assert!(!logs.starts_with(paths.deployments_dir()));
    assert!(!logs.starts_with(paths.data_root()));
    assert!(logs.starts_with(paths.apple_root()));

    // No audit.jsonl beside the container backend's capture dir.
    assert!(!paths.cage_data_dir(RICH).join("audit.jsonl").exists());
    assert!(!paths.deployment_dir(RICH).join("audit.jsonl").exists());

    let text = fs::read_to_string(paths.apple_audit_file(APPLE)).unwrap();
    let entries: Vec<AuditEntry> = text
        .lines()
        .map(|line| AuditEntry::from_value(&extract_audit_json(line).unwrap()))
        .collect();

    assert_eq!(
        entries
            .iter()
            .map(|e| e.decision.as_str())
            .collect::<Vec<_>>(),
        ["allowed", "blocked", "flagged"]
    );
    assert_eq!(
        entries.iter().map(|e| e.host.as_str()).collect::<Vec<_>>(),
        ["api.anthropic.com", "telemetry.example.com", "github.com"]
    );
    assert_eq!(entries[0].ts, "2026-03-14T15:09:26+00:00");
    assert_eq!(entries[0].secrets_injected, ["ANTHROPIC_API_KEY"]);
    assert_eq!(entries[0].port, 443);
    assert_eq!(entries[1].reason, "domain not in allowlist");
    // `AuditEntry::inspectors` keeps raw `serde_json` values, so that
    // fields a custom inspector wrote and this version does not know
    // about survive a round trip.
    assert_eq!(
        entries[1].inspectors[0]
            .get("severity")
            .and_then(serde_json::Value::as_str),
        Some("high")
    );
    assert_eq!(entries[2].secrets_redacted, ["GITHUB_TOKEN"]);
    assert_eq!(entries[2].source, "relay");

    let summary = compute_summary(&entries);
    assert_eq!(summary.total, 3);
    assert_eq!(summary.decisions.get("allowed"), 1);
    assert_eq!(summary.decisions.get("blocked"), 1);
    assert_eq!(summary.decisions.get("flagged"), 1);

    // The apple cage's capture file is the one under the apple root,
    // not the container backend's under the data root.
    let capture = fs::read_to_string(paths.apple_capture_file(APPLE)).unwrap();
    let flows: Vec<Json> = capture.lines().map(|l| parse_json(l).unwrap()).collect();
    assert_eq!(flows.len(), 2);
    assert_eq!(jstr(&flows[0], "flow_id"), "fixture-flow-0001");
    assert_eq!(jstr(&flows[0], "host"), "api.anthropic.com");
    assert_eq!(jstr(&flows[1], "decision"), "blocked");
    // And it is NOT the container backend's capture file, which the
    // apple cage does not have at all.
    assert!(!paths.capture_file(APPLE).exists());
    assert_ne!(paths.apple_capture_file(APPLE), paths.capture_file(APPLE));

    // The readiness marker is an empty file; its existence is the
    // signal.
    assert_eq!(
        fs::read_to_string(paths.apple_ready_marker(APPLE)).unwrap(),
        ""
    );
    assert!(
        fs::read_to_string(paths.apple_dnsmasq_log(APPLE))
            .unwrap()
            .contains("using nameserver 1.1.1.1#53 for domain api.anthropic.com")
    );
}

// ─────────────────────────────────────────────────────────
// the backup tarball
// ─────────────────────────────────────────────────────────

#[test]
fn the_backup_tarball_is_a_python_made_archive() {
    // The Rust *reader* for this is `cage restore`, PR D11, whose
    // acceptance check is restoring this exact tarball — and a tar and
    // gzip decoder is that PR's dependency to add, not this one's. So
    // what is pinned here is the contract D11 has to meet: the member
    // list and the manifest a Python `cage backup --include-secrets`
    // produced. Read through the system `tar`, which is present
    // wherever this suite runs.
    let tarball = fixture_root().join(format!("backup/{RICH}-backup.tar.gz"));
    assert!(tarball.is_file());

    let listing = std::process::Command::new("tar")
        .args(["-tzf", &tarball.to_string_lossy()])
        .output()
        .expect("the system tar");
    assert!(listing.status.success());
    let mut names: Vec<&str> = std::str::from_utf8(&listing.stdout)
        .unwrap()
        .lines()
        .map(|line| line.trim_end_matches('/'))
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "agentcage-backup/capture",
            "agentcage-backup/capture/capture.jsonl",
            "agentcage-backup/config",
            "agentcage-backup/config/cage.yaml",
            "agentcage-backup/config/metadata.json",
            "agentcage-backup/config/proxy-config.yaml",
            "agentcage-backup/manifest.json",
            "agentcage-backup/secrets",
            "agentcage-backup/secrets/ANTHROPIC_API_KEY",
            "agentcage-backup/secrets/GITHUB_TOKEN",
            "agentcage-backup/secrets/IMAP_PASSWORD",
            "agentcage-backup/volumes",
        ]
    );

    let member = |name: &str| -> String {
        let out = std::process::Command::new("tar")
            .args(["-xzOf", &tarball.to_string_lossy(), name])
            .output()
            .expect("the system tar");
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };

    let manifest = parse_json(&member("agentcage-backup/manifest.json")).unwrap();
    assert_eq!(jint(&manifest, "format_version"), 1);
    assert_eq!(jstr(&manifest, "agentcage_version"), GENERATION);
    assert_eq!(jstr(&manifest, "cage_name"), RICH);
    assert_eq!(jstr(&manifest, "isolation"), "container");
    assert_eq!(jstr(&manifest, "timestamp"), "2026-03-14T15:09:26+00:00");
    assert_eq!(j(&manifest, "has_secrets"), &Json::Bool(true));
    assert_eq!(j(&manifest, "has_capture"), &Json::Bool(true));
    assert_eq!(j(&manifest, "secrets_included"), &Json::Bool(true));
    assert!(jarray(&manifest, "named_volumes").is_empty());
    // The three injection rules plus the agents' shared api_key,
    // sorted — NOT just what happened to be in the store.
    assert_eq!(
        jarray(&manifest, "secret_keys")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "ANTHROPIC_API_KEY",
            "GITHUB_TOKEN",
            "IMAP_PASSWORD",
            "OPENROUTER_API_KEY"
        ]
    );

    // A backed-up secret is the bare value, with no wrapper and no
    // trailing newline.
    assert_eq!(
        member("agentcage-backup/secrets/ANTHROPIC_API_KEY"),
        "TEST-NOT-A-REAL-SECRET-0001"
    );

    // And the archived cage.yaml is the same document the state tree
    // holds, so a restore lands on the readers above.
    let fixture = Fixture::open();
    let archived = yaml::load(&member("agentcage-backup/config/cage.yaml")).unwrap();
    assert!(yaml::eq_with_key_order(&archived, &raw(&fixture, RICH)));
}

// ─────────────────────────────────────────────────────────
// the fixture's own guarantees
// ─────────────────────────────────────────────────────────

#[test]
fn the_fixture_carries_no_real_secrets_and_no_local_paths() {
    // A regression guard on the fixture, not on any reader: if this
    // ever fails, something in the generator stopped scrubbing.
    let root = fixture_root();
    walk(&root, &mut |path| {
        if path.extension().is_some_and(|e| e == "gz") {
            // gzip would hide a leak from a raw scan; the Python suite
            // decompresses. Here the tarball's text members are read
            // in the test above, where the same values are asserted.
            return;
        }
        let text = String::from_utf8_lossy(&fs::read(path).unwrap()).into_owned();
        for needle in ["/Users/", "/tmp/agentcage-state-fixture-"] {
            assert!(!text.contains(needle), "{} leaks {needle}", path.display());
        }
        for (index, _) in text.match_indices("/home/") {
            let tail = &text[index + "/home/".len()..];
            let user: String = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
                .collect();
            // `node` and `acproxy` are homes *inside* the workload and
            // egress containers, not host paths.
            assert!(
                ["agentcage-fixture", "node", "acproxy"].contains(&user.as_str()),
                "{} leaks home dir {user:?}",
                path.display()
            );
        }
    });
}
