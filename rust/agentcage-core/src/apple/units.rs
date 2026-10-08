//! `AppleContainerBackend.generate_units` — the per-cage metadata blob.
//!
//! The container and vm backends hand systemd a set of quadlet files.
//! Apple's `container` CLI has no such thing, so this backend persists
//! everything `start()` will need as one JSON document and rebuilds the
//! `container run` argv from it at start time. Two consequences:
//!
//! * **`start()` never sees a `Config`.** Anything the argv depends on
//!   has to be resolved here, at create/update time, and written down.
//!   That is why the port policy, the expanded volume list and the
//!   secret placeholder map are all in this document rather than being
//!   recomputed later — see the Python's comments, which say so at
//!   length and name the bug each one fixed.
//! * **The bytes are load-bearing.** `cli.py::_update_fingerprint`
//!   feeds `backend.generate_units`'s return value to
//!   `compute_fingerprint` on *every* backend, so this text is hashed
//!   into the digest `cage update` compares against the last deploy's
//!   `fingerprint.json`. A reordered key or a dropped space is a
//!   spurious "configuration changed".
//!
//! # `sort_keys=True`
//!
//! `json.dumps(…, indent=2, sort_keys=True)`, with `ensure_ascii` left
//! at its default of `True`. The insertion order below is the Python's,
//! for readability only; the emitter sorts.
//!
//! # Why `volumes` is a parameter
//!
//! `_user_volume_argv` is the one input here that touches the host: it
//! expands `~` and `$VAR`, calls `realpath`, refuses a source outside
//! the home directory and *warns on stderr* for each one it skips. It
//! belongs to PR E2, and it does not belong in a crate whose first rule
//! is that it performs no I/O. So the resolved list arrives as an
//! argument and this function stays pure.

use std::collections::BTreeMap;

use crate::config::types::Config;
use crate::har::json::{DumpOptions, Json, dumps};
use crate::quadlets::{QuadletHost, effective_port_policy, expandvars};

/// `generate_units` — `{"<deploy_name>.json": <document>}`.
///
/// `volumes` is `_user_volume_argv(config.container.volumes)`, resolved
/// by the caller (see the module docs). `host` answers the `$VAR`
/// lookups `container.env` values go through, and nothing else.
///
/// The Python's signature also takes `config_host_path`,
/// `patches_host_dir`, `used_octets` and `network_octet`; all four are
/// `# noqa: ARG002` there — accepted to satisfy the `Backend` protocol
/// and ignored — so they are not parameters here.
#[must_use]
pub fn generate_units(
    config: &Config,
    deploy_name: &str,
    volumes: &[String],
    host: &dyn QuadletHost,
) -> BTreeMap<String, String> {
    let mut units = BTreeMap::new();
    units.insert(
        format!("{deploy_name}.json"),
        unit_json(config, deploy_name, volumes, host),
    );
    units
}

/// The document [`generate_units`] wraps, for a caller that wants the
/// text without the one-entry map around it.
#[must_use]
pub fn unit_json(
    config: &Config,
    deploy_name: &str,
    volumes: &[String],
    host: &dyn QuadletHost,
) -> String {
    let options = DumpOptions {
        indent: Some(2),
        sort_keys: true,
        // `json.dumps` defaults to `ensure_ascii=True`, and this call
        // does not override it — unlike the golden corpus harness's own
        // writer, which passes `ensure_ascii=False`. A cage.yaml with a
        // non-ASCII `container.env` value lands here as `\uXXXX`.
        ensure_ascii: true,
        separators: None,
    };
    dumps(&unit_value(config, deploy_name, volumes, host), options)
}

/// The [`Json`] tree behind [`unit_json`].
///
/// One `match`-free block per key, in the Python's own order. It is
/// long because the document is: `#[allow]`ing the line count keeps
/// the two readable side by side, which is the point.
#[allow(clippy::too_many_lines)]
fn unit_value(
    config: &Config,
    deploy_name: &str,
    volumes: &[String],
    host: &dyn QuadletHost,
) -> Json {
    let secrets = SecretEnvs::collect(config);
    let policy = effective_port_policy(config);

    Json::Object(vec![
        ("name".to_owned(), Json::string(deploy_name)),
        (
            "user_image".to_owned(),
            Json::string(&config.container.image),
        ),
        ("cpus".to_owned(), Json::string(cpus(config))),
        ("memory".to_owned(), Json::string(memory(config))),
        ("lifecycle".to_owned(), Json::string(&config.lifecycle)),
        (
            "secret_envs".to_owned(),
            Json::Array(
                config
                    .secret_injection
                    .iter()
                    .map(|rule| Json::string(&rule.env))
                    .collect(),
            ),
        ),
        (
            "secret_env_placeholders".to_owned(),
            Json::Object(
                secrets
                    .placeholders
                    .iter()
                    .map(|(env, placeholder)| (env.clone(), Json::string(placeholder)))
                    .collect(),
            ),
        ),
        (
            "relay_secret_envs".to_owned(),
            Json::Array(secrets.relay_envs.iter().map(Json::string).collect()),
        ),
        (
            "decider_api_key_source".to_owned(),
            Json::string(&secrets.decider_api_key_source),
        ),
        (
            "watcher_api_key_source".to_owned(),
            Json::string(&secrets.watcher_api_key_source),
        ),
        (
            "dns_servers".to_owned(),
            Json::Array(config.dns_servers.iter().map(Json::string).collect()),
        ),
        (
            "secrets_backend".to_owned(),
            Json::string(&config.secrets.backend),
        ),
        (
            "secrets_allow_plaintext".to_owned(),
            Json::Bool(config.secrets.allow_plaintext),
        ),
        (
            "autostart".to_owned(),
            Json::Bool(config.apple_container_autostart),
        ),
        (
            "decider_enabled".to_owned(),
            Json::Bool(config.agents.decider.enable),
        ),
        (
            "has_expiring_domains".to_owned(),
            Json::Bool(!config.domains.expires.is_empty()),
        ),
        (
            "watcher_enabled".to_owned(),
            Json::Bool(config.agents.watcher.enable),
        ),
        (
            "volumes".to_owned(),
            Json::Array(volumes.iter().map(Json::string).collect()),
        ),
        (
            "tmpfs".to_owned(),
            Json::Array(config.container.tmpfs.iter().map(Json::string).collect()),
        ),
        (
            "env".to_owned(),
            Json::Object(
                config
                    .container
                    .env
                    .iter()
                    .map(|(key, value)| (key.clone(), Json::string(expandvars(value, host))))
                    .collect(),
            ),
        ),
        (
            "inspected_tcp_ports".to_owned(),
            Json::Array(
                policy
                    .inspected_tcp
                    .iter()
                    .copied()
                    .map(Json::Int)
                    .collect(),
            ),
        ),
        (
            "passthrough_tcp_ports".to_owned(),
            Json::Array(
                policy
                    .passthrough_tcp
                    .iter()
                    .copied()
                    .map(Json::Int)
                    .collect(),
            ),
        ),
        (
            "allow_udp_ports".to_owned(),
            Json::Array(policy.allow_udp.iter().copied().map(Json::Int).collect()),
        ),
        ("allow_icmp".to_owned(), Json::Bool(config.ports.icmp.allow)),
    ])
}

/// `container.cpus` wins over `vm.vcpus`.
///
/// `vm.vcpus` exists for the Lima backend's outer VM and used to be the
/// only thing this backend read, which silently dropped a per-cage
/// `container.cpus` on Mac. Empty on both sides means no `--cpus` flag
/// and Apple's own default.
fn cpus(config: &Config) -> String {
    if config.container.cpus.is_empty() {
        // `if getattr(config.vm, "vcpus", 0)` — Python truthiness, so
        // zero falls through and anything else (including a negative,
        // which validation rejects earlier) does not.
        if config.vm.vcpus == 0 {
            String::new()
        } else {
            config.vm.vcpus.to_string()
        }
    } else {
        config.container.cpus.clone()
    }
}

/// `container.memory` wins over `vm.mem_mb`, which is rendered with the
/// lowercase `m` suffix `_normalize_memory` later uppercases.
fn memory(config: &Config) -> String {
    if config.container.memory.is_empty() {
        if config.vm.mem_mb == 0 {
            String::new()
        } else {
            format!("{}m", config.vm.mem_mb)
        }
    } else {
        config.container.memory.clone()
    }
}

/// The four secret-shaped fields, which are computed together because
/// three of them append to the same list.
struct SecretEnvs {
    /// `{rule.env: rule.placeholder}`, skipping rules whose placeholder
    /// has not been generated yet — an empty placeholder must not become
    /// `-e ENV=` on the cage. A `BTreeMap` because the emitter sorts the
    /// keys anyway and a repeated `env` takes the last value either way.
    placeholders: BTreeMap<String, String>,
    /// Env names that must reach the *egress*, never the cage workload:
    /// protocol-relay credentials first, then the decider's `api_key`,
    /// then the watcher's. Order-preserving and deduplicated, because
    /// the Python builds it with `if var not in relay_secret_envs`.
    relay_envs: Vec<String>,
    /// The decider `api_key`'s full source (`env:NAME` /
    /// `systemd-creds:NAME`), so `_stage_secrets` can stage it
    /// scheme-appropriately and name it accurately in a warning.
    decider_api_key_source: String,
    /// The watcher's, same shape.
    watcher_api_key_source: String,
}

impl SecretEnvs {
    fn collect(config: &Config) -> Self {
        let mut placeholders = BTreeMap::new();
        for rule in &config.secret_injection {
            if !rule.placeholder.is_empty() {
                placeholders.insert(rule.env.clone(), rule.placeholder.clone());
            }
        }

        let mut relay_envs: Vec<String> = Vec::new();
        for relay in &config.protocol_relays {
            for source in [&relay.auth.user_source, &relay.auth.password_source] {
                if let Some(var) = source_var(source) {
                    push_unique(&mut relay_envs, var);
                }
            }
        }

        let decider_api_key_source = api_key_source(
            config.agents.decider.enable,
            &config.agents.decider.llm.api_key,
            &mut relay_envs,
        );
        let watcher_api_key_source = api_key_source(
            config.agents.watcher.enable,
            &config.agents.watcher.llm.api_key,
            &mut relay_envs,
        );

        Self {
            placeholders,
            relay_envs,
            decider_api_key_source,
            watcher_api_key_source,
        }
    }
}

/// `scheme, _, var = source.partition(":")`, then `if scheme and var`.
///
/// `str.partition` returns `(source, "", "")` when the separator is
/// absent, so a bare `NAME` yields an empty `var` and is skipped; a
/// leading `:` yields an empty scheme and is skipped; and `a:b:c` keeps
/// `b:c` as the variable, because `partition` splits once.
fn source_var(source: &str) -> Option<&str> {
    let (scheme, var) = source.split_once(':')?;
    if scheme.is_empty() || var.is_empty() {
        return None;
    }
    Some(var)
}

/// `if var not in relay_secret_envs: relay_secret_envs.append(var)`.
fn push_unique(envs: &mut Vec<String>, var: &str) {
    if !envs.iter().any(|seen| seen == var) {
        envs.push(var.to_owned());
    }
}

/// An agent's `api_key`, staged like a relay credential.
///
/// Returns the full source string when the agent is on and its key
/// names one, and appends the variable to the egress-only list. A
/// disabled agent contributes nothing, and neither does an enabled one
/// whose `api_key` is empty or schemeless — `cmd:` is rejected at
/// config time, so only `env:` and `systemd-creds:` reach here.
fn api_key_source(enabled: bool, api_key: &str, relay_envs: &mut Vec<String>) -> String {
    if !enabled {
        return String::new();
    }
    match source_var(api_key) {
        Some(var) => {
            push_unique(relay_envs, var);
            api_key.to_owned()
        }
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{generate_units, source_var};
    use crate::config::{FixedHost, load};
    use crate::quadlets::QuadletHost;

    /// A host with nothing in its environment, which is all the two
    /// tests below need: neither config expands a `$VAR`.
    struct Bare;

    impl QuadletHost for Bare {
        fn env_var(&self, _name: &str) -> Option<String> {
            None
        }
        fn realpath(&self, path: &str) -> String {
            path.to_owned()
        }
        fn exists(&self, _path: &str) -> bool {
            false
        }
        fn is_dir(&self, _path: &str) -> bool {
            false
        }
        fn stage_vm_file_volume(&self, _source: &str, _deploy: &str) -> Result<String, String> {
            unreachable!("vm-only")
        }
        fn detect_default_creds_scope(&self) -> Option<String> {
            None
        }
    }

    fn darwin() -> FixedHost {
        FixedHost {
            isolation: "apple-container".to_owned(),
            dns_servers: Ok(vec!["192.0.2.53".to_owned()]),
        }
    }

    fn unit(yaml: &str) -> String {
        let config = load("cage.yaml", yaml, &darwin()).expect("config");
        let mut units = generate_units(&config, "demo", &[], &Bare);
        units
            .remove("demo.json")
            .expect("one unit, named for the cage")
    }

    /// A rule whose placeholder has not been generated yet is left out
    /// of `secret_env_placeholders` entirely — an empty placeholder
    /// must not become `-e ENV=` on the cage.
    ///
    /// Unreachable from a golden-corpus case, because the harness runs
    /// `state.fill_placeholders` before `generate_units`. It is
    /// reachable in a real `cage create`, between declaring a secret
    /// and the CLI filling it in.
    #[test]
    fn an_unfilled_placeholder_is_skipped_but_the_env_name_is_kept() {
        let text = unit(concat!(
            "name: demo\n",
            "isolation: apple-container\n",
            "container:\n  image: node:22-slim\n",
            "domains:\n  allow:\n    - api.example.com\n",
            "secret_injection:\n",
            "  rules:\n",
            "    - env: FILLED\n",
            "      placeholder: decoy-1\n",
            "      secret: a\n",
            "      inject_to: [api.example.com]\n",
            "    - env: UNFILLED\n",
            "      secret: b\n",
            "      inject_to: [api.example.com]\n",
        ));
        assert!(text.contains("\"FILLED\": \"decoy-1\""), "{text}");
        assert!(!text.contains("\"UNFILLED\":"), "{text}");
        // `secret_envs` is the backward-compatible list of names and
        // keeps both, because 0.21.0-and-earlier cages read it.
        assert!(text.contains("\"UNFILLED\""), "{text}");
    }

    /// `str.partition(":")`, which splits once and yields two empty
    /// strings when the separator is absent.
    #[test]
    fn a_credential_source_is_split_once_on_the_first_colon() {
        assert_eq!(source_var("env:NAME"), Some("NAME"));
        assert_eq!(source_var("systemd-creds:NAME"), Some("NAME"));
        // Splits once: the rest, colons and all, is the variable.
        assert_eq!(source_var("env:NAME:EXTRA"), Some("NAME:EXTRA"));
        // `if scheme and var` rejects all three of these.
        assert_eq!(source_var("NAME"), None);
        assert_eq!(source_var(":NAME"), None);
        assert_eq!(source_var("env:"), None);
        assert_eq!(source_var(""), None);
    }
}
