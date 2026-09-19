//! `resolved-config.json` — a [`Config`] the way the golden corpus
//! records one.
//!
//! The corpus harness writes each case's parsed config with
//!
//! ```python
//! json.dumps(dataclasses_to_jsonable(cfg), indent=2, sort_keys=True,
//!            ensure_ascii=False) + "\n"
//! ```
//!
//! and `tests/fixtures/golden/README.md` puts JSON on the **byte-exact**
//! side of its comparison rule — only YAML artifacts are compared by
//! parsed value. So this is not a convenience serializer: reproducing
//! those bytes for all 125 valid cases is PR C1's acceptance check.
//!
//! # Why not `serde_json`
//!
//! Three reasons, and the first is enough on its own.
//!
//! * **Floats.** `agents.decider.timeout_seconds` is `15.0` in the
//!   corpus, not `15`. Python's `repr` keeps the decimal point on an
//!   integral float, and `serde_json` only agrees when the value went
//!   in as an `f64` — which survives a struct but not a round trip
//!   through a generic `Value`. `crate::har::json` already owns a
//!   measured `repr` clone for exactly this reason.
//! * **Non-finite floats.** `json.dumps(float('inf'))` is `Infinity`,
//!   and `serde_json::to_value` refuses the number outright. A config
//!   carrying `timeout_seconds: .inf` is rejected by validation, not by
//!   parsing, so it has to be *printable* first.
//! * **Feature unification.** `serde_json`'s object ordering is a
//!   crate-wide feature flag, and `crate::har` already documents why
//!   this workspace must not turn it on.
//!
//! # Shape
//!
//! `_dataclass_to_jsonable` walks the dataclass tree by
//! `dataclasses.fields`, so the JSON has one key per field, nested
//! exactly as the types nest — with one wrinkle. `DeciderAgentConfig`
//! and `WatcherAgentConfig` *inherit* their LLM client fields in
//! Python, so those appear flat alongside `enable` and `host`;
//! `crate::config::types` makes the shared fields a nested
//! [`LlmAgentConfig`] instead, and this module flattens them back out.
//! Key order is irrelevant either way, because `sort_keys=True`.

use crate::har::json::{DumpOptions, Json, dumps};
use crate::yaml::Value;

use super::types::{
    AgentsConfig, BuildConfig, CaptureConfig, Config, ContainerConfig, DeciderAgentConfig,
    DomainConfig, LlmAgentConfig, LoggingConfig, OrderedMap, PortsConfig, ProtocolRelay, RelayAuth,
    RelayPolicy, RelayRecipientAllowlist, RelayUpstream, SecretInjectionRule, SecretsConfig,
    VmConfig, WatcherAgentConfig,
};

/// Render a [`Config`] as the corpus's `resolved-config.json`.
///
/// Includes the trailing newline the harness appends.
#[must_use]
pub fn to_json(config: &Config) -> String {
    let options = DumpOptions {
        indent: Some(2),
        sort_keys: true,
        // `ensure_ascii=False`: a `help:` string with an em dash stays
        // an em dash rather than becoming `—`.
        ensure_ascii: false,
    };
    format!("{}\n", dumps(&to_value(config), options))
}

/// The [`Json`] tree behind [`to_json`].
#[must_use]
pub fn to_value(config: &Config) -> Json {
    object([
        ("name", Json::string(&config.name)),
        ("isolation", Json::string(&config.isolation)),
        ("lifecycle", Json::string(&config.lifecycle)),
        ("container", container(&config.container)),
        ("secrets", secrets(&config.secrets)),
        (
            "secret_injection",
            Json::Array(config.secret_injection.iter().map(rule).collect()),
        ),
        (
            "inspectors",
            Json::Array(
                config
                    .inspectors
                    .iter()
                    .map(|entry| from_yaml(&Value::Mapping(entry.clone())))
                    .collect(),
            ),
        ),
        (
            "protocol_relays",
            Json::Array(config.protocol_relays.iter().map(relay).collect()),
        ),
        ("dns_servers", strings(&config.dns_servers)),
        ("domains", domains(&config.domains)),
        ("agents", agents(&config.agents)),
        ("logging", logging(&config.logging)),
        ("capture", capture(&config.capture)),
        ("ports", ports(&config.ports)),
        ("vm", vm(&config.vm)),
        ("help", Json::string(&config.help)),
        (
            "exec_aliases",
            Json::Object(
                config
                    .exec_aliases
                    .iter()
                    .map(|(name, argv)| (name.clone(), strings(argv)))
                    .collect(),
            ),
        ),
        ("scaffold", Json::string(&config.scaffold)),
        (
            "apple_container_autostart",
            Json::Bool(config.apple_container_autostart),
        ),
    ])
}

fn container(container: &ContainerConfig) -> Json {
    object([
        ("image", Json::string(&container.image)),
        ("command", strings(&container.command)),
        ("volumes", strings(&container.volumes)),
        ("named_volumes", string_map(&container.named_volumes)),
        ("tmpfs", strings(&container.tmpfs)),
        ("ports", strings(&container.ports)),
        ("podman_secrets", strings(&container.podman_secrets)),
        ("env", string_map(&container.env)),
        ("user", Json::string(&container.user)),
        ("memory", Json::string(&container.memory)),
        ("cpus", Json::string(&container.cpus)),
        ("read_only", Json::Bool(container.read_only)),
        ("drop_capabilities", strings(&container.drop_capabilities)),
        ("add_capabilities", strings(&container.add_capabilities)),
        ("no_new_privileges", Json::Bool(container.no_new_privileges)),
        ("nested_containers", Json::Bool(container.nested_containers)),
        (
            "security_label_disable",
            Json::Bool(container.security_label_disable),
        ),
        ("userns", Json::string(&container.userns)),
        ("build", build(&container.build)),
        ("restart", Json::string(&container.restart)),
        ("restart_sec", Json::Int(container.restart_sec)),
        ("timeout_start_sec", Json::Int(container.timeout_start_sec)),
        ("timeout_stop_sec", Json::Int(container.timeout_stop_sec)),
    ])
}

fn build(build: &BuildConfig) -> Json {
    object([
        ("containerfile", Json::string(&build.containerfile)),
        ("args", string_map(&build.args)),
    ])
}

fn secrets(secrets: &SecretsConfig) -> Json {
    object([
        ("backend", Json::string(&secrets.backend)),
        ("scope", Json::string(&secrets.scope)),
        ("allow_plaintext", Json::Bool(secrets.allow_plaintext)),
    ])
}

fn rule(rule: &SecretInjectionRule) -> Json {
    object([
        ("env", Json::string(&rule.env)),
        ("placeholder", Json::string(&rule.placeholder)),
        ("inject_to", strings(&rule.inject_to)),
        ("source", Json::string(&rule.source)),
        ("transform", Json::string(&rule.transform)),
        (
            "transform_config",
            from_yaml(&Value::Mapping(rule.transform_config.clone())),
        ),
        ("inject_body", Json::Bool(rule.inject_body)),
        ("inject_headers", strings(&rule.inject_headers)),
    ])
}

fn relay(relay: &ProtocolRelay) -> Json {
    object([
        ("name", Json::string(&relay.name)),
        ("type", Json::string(&relay.r#type)),
        ("listen", Json::string(&relay.listen)),
        ("upstream", upstream(&relay.upstream)),
        ("auth", auth(&relay.auth)),
        ("policy", policy(&relay.policy)),
    ])
}

fn upstream(upstream: &RelayUpstream) -> Json {
    object([
        ("host", Json::string(&upstream.host)),
        ("port", Json::Int(upstream.port)),
        ("tls", Json::Bool(upstream.tls)),
        ("ca_file", Json::string(&upstream.ca_file)),
        ("ca_pem", Json::string(&upstream.ca_pem)),
        ("tls_servername", Json::string(&upstream.tls_servername)),
    ])
}

fn auth(auth: &RelayAuth) -> Json {
    object([
        ("type", Json::string(&auth.r#type)),
        ("user_source", Json::string(&auth.user_source)),
        ("password_source", Json::string(&auth.password_source)),
    ])
}

fn policy(policy: &RelayPolicy) -> Json {
    object([
        ("conn_rate_limit", Json::string(&policy.conn_rate_limit)),
        (
            "idle_timeout_seconds",
            Json::Int(policy.idle_timeout_seconds),
        ),
        ("readonly", Json::Bool(policy.readonly)),
        ("write_mode", Json::string(&policy.write_mode)),
        ("folder_allowlist", strings(&policy.folder_allowlist)),
        ("folder_denylist", strings(&policy.folder_denylist)),
        ("sender_allowlist", strings(&policy.sender_allowlist)),
        (
            "recipient_allowlist",
            recipient_allowlist(&policy.recipient_allowlist),
        ),
        ("max_message_bytes", Json::Int(policy.max_message_bytes)),
        ("max_recipients", Json::Int(policy.max_recipients)),
        ("send_rate_limit", Json::string(&policy.send_rate_limit)),
        (
            "bypass_inspectors_for_allowlisted",
            strings(&policy.bypass_inspectors_for_allowlisted),
        ),
    ])
}

fn recipient_allowlist(allowlist: &RelayRecipientAllowlist) -> Json {
    object([
        ("addresses", strings(&allowlist.addresses)),
        ("domains", strings(&allowlist.domains)),
    ])
}

fn domains(domains: &DomainConfig) -> Json {
    object([
        ("mode", Json::string(&domains.mode)),
        ("allow", strings(&domains.allow)),
        ("block", strings(&domains.block)),
        ("passthrough", strings(&domains.passthrough)),
        ("expires", string_map(&domains.expires)),
    ])
}

fn agents(agents: &AgentsConfig) -> Json {
    object([
        ("decider", decider(&agents.decider)),
        ("watcher", watcher(&agents.watcher)),
    ])
}

/// The LLM client fields, flattened as Python's inheritance leaves
/// them.
fn with_llm(llm: &LlmAgentConfig, own: Vec<(String, Json)>) -> Json {
    let mut fields = vec![
        ("provider".to_owned(), Json::string(&llm.provider)),
        ("model".to_owned(), Json::string(&llm.model)),
        ("api_key".to_owned(), Json::string(&llm.api_key)),
        (
            "timeout_seconds".to_owned(),
            Json::Float(llm.timeout_seconds),
        ),
        ("max_tokens".to_owned(), Json::Int(llm.max_tokens)),
        ("base_url".to_owned(), Json::string(&llm.base_url)),
    ];
    fields.extend(own);
    Json::Object(fields)
}

fn decider(decider: &DeciderAgentConfig) -> Json {
    with_llm(
        &decider.llm,
        vec![
            ("enable".to_owned(), Json::Bool(decider.enable)),
            ("host".to_owned(), Json::string(&decider.host)),
            ("context".to_owned(), Json::string(&decider.context)),
            (
                "rate_limit_rps".to_owned(),
                Json::Float(decider.rate_limit_rps),
            ),
            (
                "rate_limit_burst".to_owned(),
                Json::Int(decider.rate_limit_burst),
            ),
        ],
    )
}

fn watcher(watcher: &WatcherAgentConfig) -> Json {
    with_llm(
        &watcher.llm,
        vec![
            ("enable".to_owned(), Json::Bool(watcher.enable)),
            (
                "interval_seconds".to_owned(),
                Json::Float(watcher.interval_seconds),
            ),
            (
                "window_seconds".to_owned(),
                Json::Float(watcher.window_seconds),
            ),
            ("max_flows".to_owned(), Json::Int(watcher.max_flows)),
            ("auto_revoke".to_owned(), Json::Bool(watcher.auto_revoke)),
            (
                "dedup_samples".to_owned(),
                Json::Bool(watcher.dedup_samples),
            ),
            (
                "max_digest_tokens".to_owned(),
                Json::Int(watcher.max_digest_tokens),
            ),
            ("context".to_owned(), Json::string(&watcher.context)),
        ],
    )
}

fn logging(logging: &LoggingConfig) -> Json {
    object([
        ("dns_queries", Json::Bool(logging.dns_queries)),
        ("proxy_connections", Json::Bool(logging.proxy_connections)),
        ("allowed_requests", Json::Bool(logging.allowed_requests)),
        ("level", Json::string(&logging.level)),
        ("dns", Json::string(&logging.dns)),
        ("proxy", Json::string(&logging.proxy)),
        ("cage", Json::string(&logging.cage)),
    ])
}

fn capture(capture: &CaptureConfig) -> Json {
    object([
        ("enable_har", Json::Bool(capture.enable_har)),
        ("max_body_size", Json::Int(capture.max_body_size)),
        ("max_file_size", Json::Int(capture.max_file_size)),
        ("min_action", Json::string(&capture.min_action)),
        ("domains", strings(&capture.domains)),
        ("exclude_domains", strings(&capture.exclude_domains)),
    ])
}

fn ports(ports: &PortsConfig) -> Json {
    object([
        (
            "tcp",
            object([
                ("allow", ints(&ports.tcp.allow)),
                ("passthrough", ints(&ports.tcp.passthrough)),
            ]),
        ),
        ("udp", object([("allow", ints(&ports.udp.allow))])),
        ("icmp", object([("allow", Json::Bool(ports.icmp.allow))])),
    ])
}

fn vm(vm: &VmConfig) -> Json {
    object([
        ("vcpus", Json::Int(vm.vcpus)),
        ("mem_mb", Json::Int(vm.mem_mb)),
    ])
}

// ── small constructors ──────────────────────────────────

fn object<const N: usize>(fields: [(&str, Json); N]) -> Json {
    Json::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn strings(items: &[String]) -> Json {
    Json::Array(items.iter().map(Json::string).collect())
}

fn ints(items: &[i64]) -> Json {
    Json::Array(items.iter().copied().map(Json::Int).collect())
}

fn string_map(map: &OrderedMap<String>) -> Json {
    Json::Object(
        map.iter()
            .map(|(key, value)| (key.clone(), Json::string(value)))
            .collect(),
    )
}

/// A raw YAML value, as `json.dumps` would render the Python object
/// `yaml.safe_load` built from it.
///
/// Reached by `inspectors` and by `secret_injection[].transform_config`,
/// the two fields `config.py` deliberately keeps as raw dicts so the
/// proxy addon stays the single source of truth for their contents.
///
/// A non-string mapping key is rendered the way `json.dumps` renders
/// one: an `int` by its digits, a `bool` as `true`/`false` — **not**
/// Python's `str(True)`, which is `"True"` — and `None` as `null`.
/// `sort_keys=True` then orders by the rendered key, as it does here.
fn from_yaml(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(flag) => Json::Bool(*flag),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                Json::Int(integer)
            } else if let Some(unsigned) = number.as_u64() {
                i64::try_from(unsigned)
                    .map_or_else(|_| Json::BigInt(unsigned.to_string()), Json::Int)
            } else {
                Json::Float(number.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(text) => Json::string(text),
        Value::Sequence(items) => Json::Array(items.iter().map(from_yaml).collect()),
        Value::Mapping(mapping) => Json::Object(
            mapping
                .iter()
                .map(|(key, entry)| (json_key(key), from_yaml(entry)))
                .collect(),
        ),
        // `yaml.safe_load` raises on an unknown tag, so no Python
        // `Config` can hold one. Rendering the tag keeps this total.
        Value::Tagged(tagged) => Json::string(format!("{}", tagged.tag)),
    }
}

/// A mapping key, as `json.dumps` spells it.
fn json_key(key: &Value) -> String {
    match key {
        Value::Null => "null".to_owned(),
        Value::Bool(true) => "true".to_owned(),
        Value::Bool(false) => "false".to_owned(),
        Value::String(text) => text.clone(),
        other => crate::python::str_of(other),
    }
}

#[cfg(test)]
mod tests {
    use super::to_json;
    use crate::config::{Config, FixedHost, load};

    /// Integral floats keep their decimal point, which is the whole
    /// reason this module does not use `serde_json`.
    #[test]
    fn floats_render_like_python_repr() {
        let json = to_json(&Config::default());
        assert!(json.contains("\"timeout_seconds\": 15.0"), "{json}");
        assert!(json.contains("\"interval_seconds\": 900.0"), "{json}");
        assert!(json.contains("\"rate_limit_rps\": 1.0"), "{json}");
        assert!(json.contains("\"max_tokens\": 8192"), "{json}");
    }

    #[test]
    fn keys_are_sorted_and_the_document_ends_in_a_newline() {
        let json = to_json(&Config::default());
        assert!(json.starts_with("{\n  \"agents\": {\n"), "{json}");
        assert!(json.ends_with("}\n"));
        let agents = json.find("\"agents\"").expect("agents");
        let container = json.find("\"container\"").expect("container");
        assert!(agents < container, "sort_keys=True");
    }

    /// The LLM fields are flat, as Python's inheritance leaves them.
    #[test]
    fn the_llm_client_fields_are_flattened() {
        let json = to_json(&Config::default());
        let decider = json.find("\"decider\"").expect("decider");
        let provider = json[decider..].find("\"provider\"").expect("provider");
        let watcher = json[decider..].find("\"watcher\"").expect("watcher");
        assert!(provider < watcher, "provider must sit inside decider");
    }

    #[test]
    fn a_raw_inspector_config_survives() {
        let config = load(
            "<test>",
            "name: c\ninspectors:\n- name: entropy\n  config:\n    threshold: 4.5\n    on: true\n",
            &FixedHost::linux(&["192.0.2.53"]),
        )
        .expect("parse");
        let json = to_json(&config);
        assert!(json.contains("\"threshold\": 4.5"), "{json}");
        // A plain `on:` key is the boolean `True` in YAML 1.1, and
        // `json.dumps` renders a `True` key as the text "true".
        assert!(json.contains("\"true\": true"), "{json}");
    }
}
