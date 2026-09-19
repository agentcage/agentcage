//! `load_config` — a `cage.yaml` document into a [`Config`].
//!
//! Read alongside `src/agentcage/config.py`; the order of the sections
//! below is `load_config`'s order, because error precedence is
//! observable. A config with two faults reports the first one
//! `load_config` reaches, and the golden corpus records which.
//!
//! # Value checks this module does *not* make
//!
//! `load_config` raises on a handful of *values* inline, rather than
//! leaving them to `validate_config`. Those are still value checks, so
//! they belong to PR C2 (domains, ports, secrets, placeholders) and PR
//! C3 (relays, agents, capture, inspectors) with the rest. The full
//! list, so neither PR has to find them by reading:
//!
//! | `config.py` | Message | Owner |
//! | :-- | :-- | :-- |
//! | `secrets.scope` not in `_VALID_SECRET_SCOPES` | `invalid secrets.scope: …` | C2 |
//! | `secrets.backend` not in `KNOWN_BACKENDS` | `invalid secrets.backend: …` | C2 |
//! | `secret_resolver.validate_env_name` | `invalid env name: …` | C2 |
//! | `secret_resolver.validate_source` ×5 | `unknown secret source scheme: …` | C2 |
//! | `config.validate_transform` | `unknown secret_injection transform: …` | C2 |
//! | `relays/_validate.validate_relay_entry`, past its required-key check | 15 messages | C3 |
//! | `agents.{decider,watcher}.api_key` scheme shape | `must use the 'source:NAME' scheme …` | C3 |
//!
//! Two of those have a structural *part* that this module does make,
//! because parsing cannot continue without it:
//! `validate_relay_entry`'s "requires name/type/listen" (`load_config`
//! then indexes `entry["name"]`, which would be a `KeyError`), and the
//! `api_key` split into scheme and name (which decides whether the
//! name is stripped from the cage's environment).
//!
//! # Dead error strings
//!
//! Five `raise` sites in `load_config` are unreachable, because
//! `validate_agents_raw` rejects the same input first with
//! *different*, suffix-free wording — `agents.decider.enable`,
//! `agents.watcher.enable`, `auto_revoke` and `dedup_samples`, each of
//! which would otherwise append `— got <type>`. The corpus's
//! `RAISE-COVERAGE.md` §2 lists them. They are not ported: reproducing
//! them would be reproducing dead code, and if those messages are the
//! ones users should see, the fix is to relax the earlier guard in
//! `config.py`, not to write both here.
//!
//! # Deliberate divergences
//!
//! Each is noted again at its site. All of them turn a value Python
//! carries silently forward into an error, and none changes a config
//! that works today:
//!
//! 1. **A scalar where a list or mapping belongs is an error.** Python
//!    calls `list(x)` / `dict(x)`, and `list("node")` is
//!    `['n','o','d','e']` — a `command:` written as a bare string
//!    becomes four one-character arguments. No config can be relying on
//!    that.
//! 2. **A sequence or mapping where a string belongs is an error.**
//!    Python's `str([1, 2])` is the text `"[1, 2]"`, which then lands
//!    in a systemd unit.
//! 3. **A non-numeric value in a numeric field is an error.** Python
//!    leaves `restart_sec` uncoerced, so a string reaches the quadlet
//!    template and systemd refuses the unit at start time. The error
//!    moves from deploy to parse.
//! 4. **A YAML-1.1-ambiguous string in a numeric field is an error.**
//!    See "Numbers that are not numbers yet" below.
//! 5. **A malformed top-level section is a `ValueError`, not an
//!    `AttributeError`.** `container: nope` makes `config.py` fail with
//!    `'str' object has no attribute 'get'` and a traceback; here it is
//!    a sentence.
//!
//! # Numbers that are not numbers yet
//!
//! `crate::yaml`'s reader resolves YAML 1.1 **booleans** and nothing
//! else, which is a narrower promise than PyYAML's. An unquoted `0755`
//! is `493` to PyYAML and the string `"0755"` here; `1:30`, `1_000` and
//! `2024-01-02` are likewise numbers or dates there and strings here.
//!
//! So a numeric field that receives a string cannot simply be parsed:
//! `"0755"` parses as 755, and 755 is not 493. So [`py_int`] and
//! [`py_float`] refuse a string in a radix the two readers spell
//! differently — see [`reject_ambiguous`], which is narrow on purpose:
//! `1:30` and `2024-01-02` fail to parse anyway, and `1_000` is 1000 to
//! both. Only the radix prefixes parse *successfully* into a number
//! that disagrees.
//!
//! The string-valued fields are a separate question, and the answer
//! there is "nothing to do, with one caveat". `str()` of a
//! `datetime.date` is `"2030-01-01"`, which is what the text said, so a
//! plain date in a string field means the same thing on both sides. A
//! `datetime` with a *time* does not: Python renders it
//! `"2030-01-01 00:00:00+00:00"` where the text said
//! `2030-01-01T00:00:00Z`. The one field shaped like that is
//! `domains.expires`, whose values are ISO-8601 timestamps — every
//! config in the repo writes them quoted, and quoted is a string to
//! both readers. `tests/golden_config.rs` asserts that no committed
//! config writes an unquoted one, so the day that changes the assertion
//! says so.

use std::borrow::Cow;
use std::collections::BTreeSet;

use crate::python::{repr, str_of};
use crate::yaml::{self, Mapping, Value};

use super::types::{
    AgentsConfig, BuildConfig, CaptureConfig, Config, ContainerConfig, DeciderAgentConfig,
    DomainConfig, IcmpPortsConfig, LlmAgentConfig, LoggingConfig, MAX_CAPTURE_BODY_BYTES,
    MAX_CAPTURE_FILE_BYTES, OrderedMap, PortsConfig, ProtocolRelay, RelayAuth, RelayPolicy,
    RelayRecipientAllowlist, RelayUpstream, SecretInjectionRule, SecretsConfig, UdpPortsConfig,
    VmConfig, WatcherAgentConfig,
};
use super::{ConfigError, HostProbe};

type Parsed<T> = Result<T, ConfigError>;

/// Parse `text` as a `cage.yaml`.
///
/// `source` is the path the text came from — it appears in the YAML
/// syntax-error message and nowhere else, mirroring `load_config`'s
/// `path` argument. This crate does no I/O (see the crate docs), so
/// reading the file and reporting an `OSError` belong to the caller;
/// `config.py`'s wording for that one is
/// `could not read {path}: {os_error}`.
///
/// # Errors
///
/// [`ConfigError::Value`] for malformed YAML and for every structural
/// problem in the document; [`ConfigError::Runtime`] when the config
/// omits `dns_servers:` and the host has none to lend.
// One long function on purpose. `load_config` is 630 lines of ordered
// reads, and the order is observable: a config with two faults reports
// whichever one comes first, and the golden corpus records which.
// Splitting it into a dozen helpers would hide that ordering behind
// call sites and make the two files impossible to read side by side,
// which is how this port is reviewed.
#[allow(clippy::too_many_lines)]
pub fn load(source: &str, text: &str, host: &dyn HostProbe) -> Parsed<Config> {
    // `yaml.YAMLError` -> "<path> is not valid YAML at line N, column
    // M: <problem>". `config.py` builds that from PyYAML's
    // `problem_mark`, so that a malformed file reads like a compiler
    // error instead of a traceback. The location comes from
    // `serde_norway`; the wording of the problem itself is its own and
    // cannot match PyYAML's scanner text, which is the one part of
    // this message the port does not reproduce.
    let document = yaml::load_named(source, text).map_err(|error| {
        let where_ = match error.location() {
            Some(location) => format!(" at line {}, column {}", location.line(), location.column()),
            None => String::new(),
        };
        ConfigError::value(format!("{source} is not valid YAML{where_}: {error}"))
    })?;

    // `if not raw or not isinstance(raw, dict): return Config()`. An
    // empty file and a file holding a bare list both yield the
    // all-defaults config, which then fails validation on the missing
    // name — that is how `misc-empty-config` reaches "'name' is
    // required in config" rather than a type error.
    let Value::Mapping(raw) = &document else {
        return Ok(Config::default());
    };
    if raw.is_empty() {
        return Ok(Config::default());
    }

    validate_agents_raw(raw)?;

    // `raw.get("isolation") or default_isolation()` — an absent, null
    // or empty value all take the host probe.
    let isolation = match raw.get("isolation") {
        Some(value) if yaml::python_bool(value) => scalar_string(value, "isolation")?,
        _ => host.default_isolation(),
    };
    let mut config = Config {
        name: raw_string(raw.get("name"), "", "name")?,
        // Silently migrate "firecracker" isolation to "vm".
        isolation: if isolation == "firecracker" {
            "vm".to_owned()
        } else {
            isolation
        },
        lifecycle: raw_string(raw.get("lifecycle"), "service", "lifecycle")?,
        scaffold: raw_string(raw.get("scaffold"), "", "scaffold")?,
        ..Config::default()
    };

    // ── VM ──────────────────────────────────────────────
    //
    // Prefer the explicit `vm:` key, fall back to `firecracker:` for
    // the same migration.
    let vm_raw = match raw.get("vm") {
        Some(value) if yaml::python_bool(value) => mapping_of(value, "vm")?,
        _ => match raw.get("firecracker") {
            Some(value) if yaml::python_bool(value) => mapping_of(value, "firecracker")?,
            _ => Cow::Owned(Mapping::new()),
        },
    };
    config.vm = VmConfig {
        vcpus: int_field(vm_raw.get("vcpus"), VmConfig::default().vcpus, "vm.vcpus")?,
        mem_mb: int_field(
            vm_raw.get("mem_mb"),
            VmConfig::default().mem_mb,
            "vm.mem_mb",
        )?,
    };

    // ── Container ───────────────────────────────────────
    let container_raw = section(raw.get("container"), "container")?;
    let c = container_raw.as_ref();
    let mut container = ContainerConfig {
        image: raw_string(c.get("image"), "", "container.image")?,
        command: string_list(c.get("command"), "container.command")?,
        volumes: string_list(c.get("volumes"), "container.volumes")?,
        named_volumes: string_map(c.get("named_volumes"), "container.named_volumes")?,
        tmpfs: string_list(c.get("tmpfs"), "container.tmpfs")?,
        ports: string_list(c.get("ports"), "container.ports")?,
        podman_secrets: string_list(c.get("podman_secrets"), "container.podman_secrets")?,
        env: string_map(c.get("env"), "container.env")?,
        // Default "1000:1000"; an explicit `user: ""` or `user: null`
        // means "use the image's own user", which is why the null case
        // becomes the empty string rather than the default.
        user: raw_string(c.get("user"), "1000:1000", "container.user")?,
        memory: string_or_empty(c.get("memory"), "container.memory")?,
        cpus: string_or_empty(c.get("cpus"), "container.cpus")?,
        // `config.py` stores these three uncoerced and the quadlet
        // template tests them with `{% if %}`, so Python's truthiness
        // is the behaviour to reproduce, not an `isinstance` check.
        read_only: bool_field(c.get("read_only"), true),
        no_new_privileges: bool_field(c.get("no_new_privileges"), true),
        nested_containers: bool_field(c.get("nested_containers"), false),
        security_label_disable: bool_field(c.get("security_label_disable"), true),
        userns: string_or_empty(c.get("userns"), "container.userns")?,
        add_capabilities: string_list(c.get("add_capabilities"), "container.add_capabilities")?,
        ..ContainerConfig::default()
    };

    // drop_capabilities: default "ALL", and a bare scalar is accepted
    // as a one-element list. A falsy value (`[]`, `""`, `null`, false)
    // drops nothing at all, which is how `container-drop-caps-empty`
    // asks for the container's default capability set.
    container.drop_capabilities = match c.get("drop_capabilities") {
        None => vec!["ALL".to_owned()],
        Some(value) if !yaml::python_bool(value) => Vec::new(),
        Some(Value::Sequence(items)) => items
            .iter()
            .map(|item| scalar_string(item, "container.drop_capabilities"))
            .collect::<Parsed<Vec<String>>>()?,
        Some(value) => vec![scalar_string(value, "container.drop_capabilities")?],
    };

    container.restart = or_string(c.get("restart"), "on-failure", "container.restart")?;
    // `restart_sec` and the two timeouts differ in how they treat an
    // explicit null, and the difference is not decorative:
    // `restart_sec: null` is the default 10, while `timeout_stop_sec:
    // null` is 0. `config.py` writes the first with `is not None` and
    // the second with `or`, and `container-timeouts-zero` pins both.
    container.restart_sec = match c.get("restart_sec") {
        None | Some(Value::Null) => 10,
        Some(value) => int_value(value, "container.restart_sec")?,
    };
    // The 120 here is not `ContainerConfig`'s 600. See types.rs.
    container.timeout_start_sec = or_int(
        c.get("timeout_start_sec"),
        120,
        "container.timeout_start_sec",
    )?;
    container.timeout_stop_sec =
        or_int(c.get("timeout_stop_sec"), 30, "container.timeout_stop_sec")?;

    let build_raw = section(c.get("build"), "container.build")?;
    container.build = BuildConfig {
        containerfile: raw_string(
            build_raw.get("containerfile"),
            "",
            "container.build.containerfile",
        )?,
        args: string_map(build_raw.get("args"), "container.build.args")?,
    };

    // ── Secrets ─────────────────────────────────────────
    //
    // The two enum checks (`scope`, `backend`) are value checks and
    // belong to C2; the strings are parsed here. `str()` is applied
    // with no `or`, so an explicit null becomes the text "None" and
    // C2's message reads `invalid secrets.scope: 'None'` — matching
    // `config.py`.
    let secrets_raw = section(raw.get("secrets"), "secrets")?;
    config.secrets = SecretsConfig {
        backend: str_field(secrets_raw.get("backend"), "auto"),
        scope: str_field(secrets_raw.get("scope"), "auto"),
        allow_plaintext: bool_field(secrets_raw.get("allow_plaintext"), false),
    };

    // ── Secret injection ────────────────────────────────
    //
    // Accepts a list, or `{"rules": [...]}`.
    let injection_raw = raw.get("secret_injection");
    let rules: Cow<'_, [Value]> = match injection_raw {
        Some(value) if yaml::python_bool(value) => match value {
            Value::Mapping(mapping) => {
                Cow::Owned(value_list(mapping.get("rules"), "secret_injection.rules")?)
            }
            Value::Sequence(items) => Cow::Borrowed(items.as_slice()),
            other => {
                return Err(ConfigError::value(format!(
                    "secret_injection must be a list of rules or a mapping with a 'rules' \
                     key (got {})",
                    type_name(other)
                )));
            }
        },
        _ => Cow::Owned(Vec::new()),
    };

    let mut injected_names: BTreeSet<String> = BTreeSet::new();
    for entry in rules.iter() {
        let entry = mapping_of(entry, "secret_injection rule")?;
        // A rule with no `env` is skipped outright, placeholder and
        // all. `config.py` guards the whole body with `if env_name:`.
        let Some(env_value) = entry.get("env") else {
            continue;
        };
        if !yaml::python_bool(env_value) {
            continue;
        }
        let env = scalar_string(env_value, "secret_injection[].env")?;
        // validate_env_name / validate_source / validate_transform are
        // C2's; see the module docs.
        let source = raw_string(entry.get("source"), "", "secret_injection[].source")?;
        let transform = or_string(entry.get("transform"), "", "secret_injection[].transform")?;
        let transform_config = section(
            entry.get("transform_config"),
            "secret_injection[].transform_config",
        )?
        .into_owned();
        injected_names.insert(env.clone());
        config.secret_injection.push(SecretInjectionRule {
            env,
            // Empty means "not yet generated" — see the field docs.
            placeholder: or_string(
                entry.get("placeholder"),
                "",
                "secret_injection[].placeholder",
            )?,
            inject_to: string_list(entry.get("inject_to"), "secret_injection[].inject_to")?,
            source,
            transform,
            transform_config,
            inject_body: bool_field(entry.get("inject_body"), false),
            inject_headers: value_list(
                entry.get("inject_headers"),
                "secret_injection[].inject_headers",
            )?
            .iter()
            .map(|header| str_of(header).trim().to_owned())
            .collect(),
        });
    }

    // Remove injected secrets from podman_secrets and env — they are
    // handled separately via placeholder substitution in the proxy.
    // Leaving them in env would expose the real value inside the cage
    // (`os.path.expandvars` expands `${VAR}` references during quadlet
    // generation).
    strip_secrets(&mut container, &injected_names);

    // ── Inspectors ──────────────────────────────────────
    //
    // Preserved as raw mappings so the proxy addon's dispatch logic
    // stays the single source of truth for valid keys. A non-list
    // value leaves the field empty rather than raising — that is
    // `config.py`'s `if isinstance(insp_raw, list)`, and it is
    // reproduced rather than tightened because C3 owns what an
    // inspector entry may contain.
    if let Some(Value::Sequence(items)) = raw.get("inspectors") {
        config.inspectors = items
            .iter()
            .filter_map(|entry| match entry {
                Value::Mapping(mapping) => Some(mapping.clone()),
                _ => None,
            })
            .collect();
    }

    // ── Protocol relays ─────────────────────────────────
    let relays_raw = value_list(raw.get("protocol_relays"), "protocol_relays")?;
    let mut relay_secret_names: BTreeSet<String> = BTreeSet::new();
    for entry in &relays_raw {
        let entry = mapping_of(entry, "protocol_relays entry")?;
        // The required-key half of `validate_relay_entry`. The rest of
        // that validator is C3's; this part is here because
        // `load_config` indexes `entry["name"]` straight after it.
        let name = raw_string(entry.get("name"), "", "protocol_relays[].name")?;
        let relay_type = raw_string(entry.get("type"), "", "protocol_relays[].type")?;
        let listen = raw_string(entry.get("listen"), "", "protocol_relays[].listen")?;
        if name.is_empty() || relay_type.is_empty() || listen.is_empty() {
            return Err(ConfigError::value(format!(
                "protocol_relays entry requires name/type/listen (got name={}, type={}, \
                 listen={})",
                repr(entry.get("name").unwrap_or(&Value::String(String::new()))),
                repr(entry.get("type").unwrap_or(&Value::String(String::new()))),
                repr(entry.get("listen").unwrap_or(&Value::String(String::new()))),
            )));
        }

        // From here on the relay's own name goes in every path, the
        // way `validate_relay_entry` writes them —
        // `protocol_relays[mail].upstream` — because a config with
        // three relays needs to say which one.
        let at = format!("protocol_relays[{name}]");
        // `validate_relay_entry`'s wording for these two carries no
        // `(got X)` suffix; matched exactly so the message does not
        // change when C3 takes the rest of that validator over.
        let upstream_raw = match entry.get("upstream") {
            Some(value) if yaml::python_bool(value) => match value {
                Value::Mapping(mapping) => Cow::Borrowed(mapping),
                _ => {
                    return Err(ConfigError::value(format!(
                        "{at}.upstream must be a mapping"
                    )));
                }
            },
            _ => Cow::Owned(Mapping::new()),
        };
        let upstream = RelayUpstream {
            host: str_field(upstream_raw.get("host"), ""),
            port: or_int(upstream_raw.get("port"), 0, &format!("{at}.upstream.port"))?,
            tls: bool_field(upstream_raw.get("tls"), true),
            ca_file: string_or_empty(
                upstream_raw.get("ca_file"),
                &format!("{at}.upstream.ca_file"),
            )?,
            ca_pem: string_or_empty(upstream_raw.get("ca_pem"), &format!("{at}.upstream.ca_pem"))?,
            tls_servername: string_or_empty(
                upstream_raw.get("tls_servername"),
                &format!("{at}.upstream.tls_servername"),
            )?,
        };

        let auth_raw = match entry.get("auth") {
            Some(value) if yaml::python_bool(value) => match value {
                Value::Mapping(mapping) => Cow::Borrowed(mapping),
                _ => return Err(ConfigError::value(format!("{at}.auth must be a mapping"))),
            },
            _ => Cow::Owned(Mapping::new()),
        };
        let auth = RelayAuth {
            r#type: string_or_empty(auth_raw.get("type"), &format!("{at}.auth.type"))?,
            user_source: string_or_empty(
                auth_raw.get("user_source"),
                &format!("{at}.auth.user_source"),
            )?,
            password_source: string_or_empty(
                auth_raw.get("password_source"),
                &format!("{at}.auth.password_source"),
            )?,
        };
        // Collect env names (the part after "scheme:") so they are
        // stripped from the cage's env/podman_secrets the same way
        // secret_injection's are — these credentials must only land in
        // the proxy.
        for source in [&auth.user_source, &auth.password_source] {
            if let Some((scheme, argument)) = source.split_once(':')
                && !scheme.is_empty()
                && !argument.is_empty()
            {
                relay_secret_names.insert(argument.to_owned());
            }
        }

        let policy_raw = section(entry.get("policy"), &format!("{at}.policy"))?;
        // Convenience shorthand: a flat list is treated as `addresses`.
        let recipient_allowlist = match policy_raw.get("recipient_allowlist") {
            Some(Value::Sequence(items)) => RelayRecipientAllowlist {
                addresses: items
                    .iter()
                    .map(|item| scalar_string(item, &format!("{at}.policy.recipient_allowlist")))
                    .collect::<Parsed<Vec<String>>>()?,
                domains: Vec::new(),
            },
            other => {
                let mapping = section(other, &format!("{at}.policy.recipient_allowlist"))?;
                RelayRecipientAllowlist {
                    addresses: string_list(
                        mapping.get("addresses"),
                        &format!("{at}.policy.recipient_allowlist"),
                    )?,
                    domains: string_list(
                        mapping.get("domains"),
                        &format!("{at}.policy.recipient_allowlist"),
                    )?,
                }
            }
        };
        // An explicit `[]` keeps strict behaviour for trusted
        // recipients, so the key's presence is what selects the
        // default, not its truthiness.
        let bypass = if policy_raw.contains_key("bypass_inspectors_for_allowlisted") {
            string_list(
                policy_raw.get("bypass_inspectors_for_allowlisted"),
                &format!("{at}.policy.bypass_inspectors_for_allowlisted"),
            )?
        } else {
            RelayPolicy::default().bypass_inspectors_for_allowlisted
        };
        let policy = RelayPolicy {
            conn_rate_limit: or_string(
                policy_raw.get("conn_rate_limit"),
                "30/min",
                &format!("{at}.policy.conn_rate_limit"),
            )?,
            idle_timeout_seconds: int_field(
                policy_raw.get("idle_timeout_seconds"),
                0,
                &format!("{at}.policy.idle_timeout_seconds"),
            )?,
            readonly: bool_field(policy_raw.get("readonly"), false),
            write_mode: string_or_empty(
                policy_raw.get("write_mode"),
                &format!("{at}.policy.write_mode"),
            )?,
            folder_allowlist: string_list(
                policy_raw.get("folder_allowlist"),
                &format!("{at}.policy.folder_allowlist"),
            )?,
            folder_denylist: string_list(
                policy_raw.get("folder_denylist"),
                &format!("{at}.policy.folder_denylist"),
            )?,
            sender_allowlist: string_list(
                policy_raw.get("sender_allowlist"),
                &format!("{at}.policy.sender_allowlist"),
            )?,
            recipient_allowlist,
            max_message_bytes: int_field(
                policy_raw.get("max_message_bytes"),
                5_242_880,
                &format!("{at}.policy.max_message_bytes"),
            )?,
            max_recipients: int_field(
                policy_raw.get("max_recipients"),
                10,
                &format!("{at}.policy.max_recipients"),
            )?,
            send_rate_limit: or_string(
                policy_raw.get("send_rate_limit"),
                "20/hour",
                &format!("{at}.policy.send_rate_limit"),
            )?,
            bypass_inspectors_for_allowlisted: bypass,
        };

        config.protocol_relays.push(ProtocolRelay {
            name,
            r#type: relay_type,
            listen,
            upstream,
            auth,
            policy,
        });
    }
    strip_secrets(&mut container, &relay_secret_names);

    // ── In-egress LLM agents ────────────────────────────
    //
    // Both api_keys are collected into the SAME egress-only secret set
    // (stripped from the cage env/podman_secrets below, staged into
    // the proxy's tmpfs secret files by the quadlet renderer): these
    // agents run in the egress, so their LLM keys follow the exact
    // relay credential chain and never reach the cage, even as a
    // placeholder.
    //
    // Parse strictness (both blocks): a malformed block REJECTS the
    // config (it would ride proxy-config.yaml verbatim and
    // crash/degrade the in-egress consumer), explicit values are
    // preserved as-is so validation's bounds can reject them (a bare
    // `or` fallback would silently coerce an explicit 0 into the
    // default), and booleans must be REAL booleans (`bool("false")` is
    // True — silently enabling an agent against the operator's written
    // intent).
    let mut policy_secret_names: BTreeSet<String> = BTreeSet::new();
    let agents_raw = section(raw.get("agents"), "agents")?;

    let decider_raw = agent_mapping(agents_raw.get("decider"), "agents.decider")?;
    let decider = if truthy(decider_raw.get("enable")) {
        let rate_limit_raw =
            agent_mapping(decider_raw.get("rate_limit"), "agents.decider.rate_limit")?;
        Some(DeciderAgentConfig {
            llm: llm_client(
                &decider_raw,
                15.0,
                "agents.decider",
                &mut policy_secret_names,
            )?,
            enable: true,
            host: or_string(
                decider_raw.get("host"),
                "agentcage.local",
                "agents.decider.host",
            )?,
            context: agent_context(decider_raw.get("context"), "agents.decider.context")?,
            // Preserve an explicit 0 (rate limiting disabled — the
            // operator's deliberate choice; the proxy parses 0 the same
            // way). Only absent/null/empty falls back to the default.
            rate_limit_rps: present_float(
                rate_limit_raw.get("requests_per_second"),
                1.0,
                "agents.decider.rate_limit.requests_per_second",
            )?,
            rate_limit_burst: present_int(
                rate_limit_raw.get("burst"),
                5,
                "agents.decider.rate_limit.burst",
            )?,
        })
    } else {
        None
    };

    let watcher_raw = agent_mapping(agents_raw.get("watcher"), "agents.watcher")?;
    let watcher = if truthy(watcher_raw.get("enable")) {
        Some(WatcherAgentConfig {
            context: agent_context(watcher_raw.get("context"), "agents.watcher.context")?,
            auto_revoke: real_bool(
                watcher_raw.get("auto_revoke"),
                true,
                "agents.watcher.auto_revoke",
            )?,
            dedup_samples: real_bool(
                watcher_raw.get("dedup_samples"),
                true,
                "agents.watcher.dedup_samples",
            )?,
            interval_seconds: watcher_number(&watcher_raw, "interval_seconds", 900.0)?,
            window_seconds: watcher_number(&watcher_raw, "window_seconds", 3600.0)?,
            #[allow(clippy::cast_possible_truncation)]
            max_flows: watcher_number(&watcher_raw, "max_flows", 200.0)? as i64,
            #[allow(clippy::cast_possible_truncation)]
            max_digest_tokens: watcher_number(&watcher_raw, "max_digest_tokens", 8000.0)? as i64,
            llm: llm_client(
                &watcher_raw,
                30.0,
                "agents.watcher",
                &mut policy_secret_names,
            )?,
            enable: true,
        })
    } else {
        None
    };

    config.agents = AgentsConfig {
        decider: decider.unwrap_or_default(),
        watcher: watcher.unwrap_or_default(),
    };
    strip_secrets(&mut container, &policy_secret_names);

    config.container = container;

    // ── DNS ─────────────────────────────────────────────
    //
    // Default to the host's resolvers. The probe can fail, and only
    // reaching it can make it fail, which is why it is not evaluated
    // for a config that names its own.
    config.dns_servers = match raw.get("dns_servers") {
        Some(value) if yaml::python_bool(value) => string_list(Some(value), "dns_servers")?,
        _ => host.dns_servers()?,
    };

    // ── Domains ─────────────────────────────────────────
    let domains_raw = section(raw.get("domains"), "domains")?;
    // The mode is derived from which keys are present, not from their
    // contents: an empty `allow: []` is still allowlist mode, and the
    // `domains: cannot specify both 'allow' and 'block' lists` check
    // that catches the ambiguous case is a value check, so it is C2's.
    let (mode, allow, block) = if domains_raw.contains_key("allow") {
        // New format: explicit allow/block lists.
        (
            "allowlist".to_owned(),
            string_list(domains_raw.get("allow"), "domains.allow")?,
            if domains_raw.contains_key("block") {
                string_list(domains_raw.get("block"), "domains.block")?
            } else {
                Vec::new()
            },
        )
    } else if domains_raw.contains_key("block") {
        (
            "blocklist".to_owned(),
            Vec::new(),
            string_list(domains_raw.get("block"), "domains.block")?,
        )
    } else if domains_raw.contains_key("mode") {
        // Backward compat: mode + list. An unrecognised mode keeps its
        // entries nowhere, exactly as `config.py` does — validation
        // then reports the mode.
        let mode = raw_string(domains_raw.get("mode"), "", "domains.mode")?;
        let entries = string_list(domains_raw.get("list"), "domains.list")?;
        match mode.as_str() {
            "allowlist" => (mode, entries, Vec::new()),
            "blocklist" => (mode, Vec::new(), entries),
            _ => (mode, Vec::new(), Vec::new()),
        }
    } else {
        (String::new(), Vec::new(), Vec::new())
    };
    let mut domains = DomainConfig {
        mode,
        allow,
        block,
        passthrough: string_list(domains_raw.get("passthrough"), "domains.passthrough")?,
        ..DomainConfig::default()
    };

    // Per-domain expiry (allowlist mode). Accepts either a flat
    // mapping `{domain: expires_at}` or a list of `{domain,
    // expires_at}` objects for readability. Domains not in allow are
    // ignored; an expires value for a blocklisted domain is
    // meaningless (blocklist denies by membership, not time). All
    // values are kept as ISO-8601 strings and validated loosely (the
    // inspector and the grants reconcile parse them at check time and
    // treat an unparseable value as "no expiry").
    let mut expires: OrderedMap<String> = OrderedMap::new();
    match domains_raw.get("expires") {
        Some(Value::Mapping(mapping)) => {
            for (key, value) in mapping {
                if yaml::python_bool(key) && yaml::python_bool(value) {
                    expires.insert(normalize_domain(&str_of(key)), str_of(value));
                }
            }
        }
        Some(Value::Sequence(items)) => {
            for item in items {
                let Value::Mapping(entry) = item else {
                    continue;
                };
                let (Some(domain), Some(at)) = (entry.get("domain"), entry.get("expires_at"))
                else {
                    continue;
                };
                if yaml::python_bool(domain) && yaml::python_bool(at) {
                    expires.insert(normalize_domain(&str_of(domain)), str_of(at));
                }
            }
        }
        // Anything else — absent, null, or a scalar — is `or {}`.
        _ => {}
    }
    domains.expires = expires;
    config.domains = domains;

    // ── Logging ─────────────────────────────────────────
    let logging_raw = section(raw.get("logging"), "logging")?;
    config.logging = LoggingConfig {
        dns_queries: bool_field(logging_raw.get("dns_queries"), false),
        proxy_connections: bool_field(logging_raw.get("proxy_connections"), false),
        // The legacy top-level `log_allowed:` is the fallback, and only
        // when `logging.allowed_requests` is absent entirely.
        allowed_requests: if logging_raw.contains_key("allowed_requests") {
            bool_field(logging_raw.get("allowed_requests"), false)
        } else {
            bool_field(raw.get("log_allowed"), false)
        },
        level: or_string(logging_raw.get("level"), "info", "logging.level")?,
        dns: string_or_empty(logging_raw.get("dns"), "logging.dns")?,
        proxy: string_or_empty(logging_raw.get("proxy"), "logging.proxy")?,
        cage: string_or_empty(logging_raw.get("cage"), "logging.cage")?,
    };

    // ── Capture ─────────────────────────────────────────
    let capture_raw = section(raw.get("capture"), "capture")?;
    config.capture = CaptureConfig {
        enable_har: bool_field(capture_raw.get("enable_har"), false),
        max_body_size: int_field(
            capture_raw.get("max_body_size"),
            MAX_CAPTURE_BODY_BYTES,
            "capture.max_body_size",
        )?,
        max_file_size: int_field(
            capture_raw.get("max_file_size"),
            MAX_CAPTURE_FILE_BYTES,
            "capture.max_file_size",
        )?,
        min_action: or_string(capture_raw.get("min_action"), "all", "capture.min_action")?,
        domains: string_list(capture_raw.get("domains"), "capture.domains")?,
        exclude_domains: string_list(
            capture_raw.get("exclude_domains"),
            "capture.exclude_domains",
        )?,
    };

    // ── Ports ───────────────────────────────────────────
    //
    // Nested by protocol. Per-entry range and duplicate checks are
    // C2's, so that all bad entries are reported together. The
    // structural shape (mappings at each level) is checked here so a
    // malformed config like `ports: "yes"` or `ports.tcp: [80, 443]`
    // (operator forgot the `allow:` key) raises a clean error rather
    // than crashing with AttributeError/TypeError or silently
    // swallowing the operator's intent.
    config.ports = parse_ports(raw)?;

    // apple-container only: opt-in launchd autostart at user login.
    config.apple_container_autostart = bool_field(raw.get("apple_container_autostart"), false);

    config.help = string_or_empty(raw.get("help"), "help")?;

    // Exec aliases. A value that is not a list is dropped without
    // complaint — `config.py`'s `if isinstance(v, list)`.
    let aliases_raw = section(raw.get("exec_aliases"), "exec_aliases")?;
    for (key, value) in aliases_raw.as_ref() {
        if let Value::Sequence(items) = value {
            let argv = items
                .iter()
                .map(|item| scalar_string(item, "exec_aliases"))
                .collect::<Parsed<Vec<String>>>()?;
            config.exec_aliases.insert(str_of(key), argv);
        }
    }

    Ok(config)
}

// ── agents schema validation ────────────────────────────

/// `validate_agents_raw` — check the sole supported agent schema
/// without rewriting the input.
///
/// Removed keys are rejected by *presence*, even when empty or
/// disabled. Silently ignoring old settings could turn off monitoring
/// or change egress policy.
fn validate_agents_raw(raw: &Mapping) -> Parsed<()> {
    let domains = agent_mapping(raw.get("domains"), "domains")?;
    if domains.contains_key("auto") {
        return Err(ConfigError::value(
            "domains.auto is no longer supported; use agents.decider with flat LLM fields",
        ));
    }
    if raw.contains_key("watcher") {
        return Err(ConfigError::value(
            "top-level watcher is no longer supported; use agents.watcher with flat LLM fields",
        ));
    }
    let agents = agent_mapping(raw.get("agents"), "agents")?;
    let mut unknown: Vec<String> = agents
        .keys()
        .map(str_of)
        .filter(|key| key != "decider" && key != "watcher")
        .collect();
    if !unknown.is_empty() {
        unknown.sort();
        unknown.dedup();
        return Err(ConfigError::value(format!(
            "unknown agents: {}",
            unknown.join(", ")
        )));
    }
    for role in ["decider", "watcher"] {
        let path = format!("agents.{role}");
        let block = agent_mapping(agents.get(role), &path)?;
        if block.contains_key("kind") {
            return Err(ConfigError::value(format!(
                "{path}.kind is no longer supported; omit kind"
            )));
        }
        for wrapper in ["agent", "decider"] {
            if block.contains_key(wrapper) {
                return Err(ConfigError::value(format!(
                    "{path}: LLM fields must be flat, not under '{wrapper}'"
                )));
            }
        }
        for flag in ["enable", "auto_revoke", "dedup_samples"] {
            if let Some(value) = block.get(flag)
                && !matches!(value, Value::Bool(_))
            {
                // `bool("false")` is True, so a hand-edited `enable:
                // "false"` would silently turn an agent — and with the
                // decider, the caged agent's ability to grant egress —
                // ON against the operator's written intent.
                return Err(ConfigError::value(format!(
                    "{path}.{flag} must be a boolean (true/false)"
                )));
            }
        }
    }
    Ok(())
}

/// The flat LLM client fields, shared by every roster entry.
///
/// One grammar, one credential shape. NOT lowercased: validation
/// rejects any casing but the exact provider key.
fn llm_client(
    block: &Mapping,
    default_timeout: f64,
    label: &str,
    secret_names: &mut BTreeSet<String>,
) -> Parsed<LlmAgentConfig> {
    for key in ["timeout_seconds", "max_tokens"] {
        if matches!(block.get(key), Some(Value::Bool(_))) {
            return Err(ConfigError::value(format!(
                "{label}: invalid LLM client value ({key} must be a number, not a boolean)"
            )));
        }
    }
    let wrap =
        |error: String| ConfigError::value(format!("{label}: invalid LLM client value ({error})"));

    let client = LlmAgentConfig {
        provider: or_string(block.get("provider"), "", label)?,
        model: or_string(block.get("model"), "", label)?,
        api_key: or_string(block.get("api_key"), "", label)?,
        timeout_seconds: match present(block.get("timeout_seconds")) {
            Some(value) => py_float(value).map_err(wrap)?,
            None => default_timeout,
        },
        max_tokens: match present(block.get("max_tokens")) {
            Some(value) => py_int(value).map_err(wrap)?,
            None => 8192,
        },
        base_url: or_string(block.get("base_url"), "", label)?,
    };

    // The `source:NAME` split. The *shape* check that rejects a bare
    // name is C3's; what happens here is the part parsing needs — an
    // `env:` key names a host variable that must be stripped from the
    // cage's environment, because an egress-only credential must never
    // reach the cage even as a placeholder.
    if let Some((scheme, argument)) = client.api_key.split_once(':')
        && scheme == "env"
        && !argument.is_empty()
    {
        secret_names.insert(argument.to_owned());
    }
    Ok(client)
}

/// `agents.*.context` — optional free-text describing the cage's
/// purpose.
///
/// Null is "", a string is itself, and anything else is rejected here
/// rather than `str()`-coerced: a mapping would otherwise ride the
/// agent's system prompt as a misleading repr like
/// `{'enable': True}`. The 4096-char cap is a value check, so it is
/// C3's.
fn agent_context(value: Option<&Value>, path: &str) -> Parsed<String> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(other) => Err(ConfigError::value(format!(
            "{path} must be a string (got {})",
            type_name(other)
        ))),
    }
}

/// One of the watcher's numeric knobs.
///
/// Preserves the explicit-0 / absent distinction: only an ABSENT or
/// empty value falls back to the default, so an explicit value
/// (including 0) reaches validation's bounds untouched.
fn watcher_number(block: &Mapping, key: &str, default: f64) -> Parsed<f64> {
    match present(block.get(key)) {
        None => Ok(default),
        Some(value) => py_float(value).map_err(|_| {
            ConfigError::value(format!(
                "agents.watcher.{key} must be a number (got {})",
                repr(value)
            ))
        }),
    }
}

// ── ports ───────────────────────────────────────────────

/// The `ports:` block, with its four structural guards.
fn parse_ports(raw: &Mapping) -> Parsed<PortsConfig> {
    let ports_raw = match raw.get("ports") {
        Some(value) if yaml::python_bool(value) => match value {
            Value::Mapping(mapping) => Cow::Borrowed(mapping),
            other => {
                return Err(ConfigError::value(format!(
                    "ports must be a mapping with 'tcp', 'udp', and/or 'icmp' keys (got: {})",
                    repr(other)
                )));
            }
        },
        _ => Cow::Owned(Mapping::new()),
    };

    let mut ports = PortsConfig::default();

    let tcp_raw = protocol_section(ports_raw.get("tcp"), || {
        "ports.tcp must be a mapping with 'allow' and/or 'passthrough' keys (got: {}). If you \
         meant to list TCP ports, use 'ports.tcp.allow: [...]'"
    })?;
    if tcp_raw.contains_key("allow") {
        ports.tcp.allow = port_list(tcp_raw.get("allow"), "ports.tcp.allow")?;
    }
    if tcp_raw.contains_key("passthrough") {
        ports.tcp.passthrough = port_list(tcp_raw.get("passthrough"), "ports.tcp.passthrough")?;
    }

    let udp_raw = protocol_section(ports_raw.get("udp"), || {
        "ports.udp must be a mapping with an 'allow' key (got: {}). If you meant to list UDP \
         ports, use 'ports.udp.allow: [...]'"
    })?;
    if udp_raw.contains_key("allow") {
        ports.udp = UdpPortsConfig {
            allow: port_list(udp_raw.get("allow"), "ports.udp.allow")?,
        };
    }

    let icmp_raw = protocol_section(ports_raw.get("icmp"), || {
        "ports.icmp must be a mapping with an 'allow' boolean (got: {}). To allow outbound \
         ping, use 'ports.icmp.allow: true'"
    })?;
    if let Some(value) = icmp_raw.get("allow") {
        // A real boolean, not truthiness: `allow: "no"` must not turn
        // ICMP on.
        let Value::Bool(flag) = value else {
            return Err(ConfigError::value(format!(
                "ports.icmp.allow must be a boolean (got: {})",
                repr(value)
            )));
        };
        ports.icmp = IcmpPortsConfig { allow: *flag };
    }

    Ok(ports)
}

/// One `ports.<protocol>` mapping, with its own "you forgot the key"
/// hint.
fn protocol_section(
    value: Option<&Value>,
    template: impl Fn() -> &'static str,
) -> Parsed<Cow<'_, Mapping>> {
    match value {
        Some(value) if yaml::python_bool(value) => match value {
            Value::Mapping(mapping) => Ok(Cow::Borrowed(mapping)),
            other => Err(ConfigError::value(template().replacen(
                "{}",
                &repr(other),
                1,
            ))),
        },
        _ => Ok(Cow::Owned(Mapping::new())),
    }
}

/// `ports.*.allow` / `ports.tcp.passthrough` — a list of integers.
///
/// `config.py` keeps the entries raw and lets `validate_config` reject
/// a non-integer with `ports.tcp.allow entries must be integers (got:
/// …)`. That message is reproduced here rather than in C2 because the
/// field is typed `Vec<i64>`: a raw list would push the type problem
/// into every consumer. The only observable difference is precedence —
/// a config with both a bad port and a bad name reports the port
/// first, where `config.py` reports the name.
fn port_list(value: Option<&Value>, path: &str) -> Parsed<Vec<i64>> {
    let items = match value {
        Some(value) if yaml::python_bool(value) => match value {
            Value::Sequence(items) => items,
            other => {
                return Err(ConfigError::value(format!(
                    "{path} must be a list of integers (got: {})",
                    repr(other)
                )));
            }
        },
        _ => return Ok(Vec::new()),
    };
    items
        .iter()
        .map(|item| match item {
            // A YAML bool is an int in Python (`True == 1`), so the
            // check `config.py` makes is `isinstance(e, int) and not
            // isinstance(e, bool)` — a bare `isinstance` would let
            // `- true` through as port 1.
            Value::Number(number) if number.is_i64() || number.is_u64() => number
                .as_i64()
                .or_else(|| number.as_u64().and_then(|n| i64::try_from(n).ok()))
                .ok_or_else(|| {
                    ConfigError::value(format!(
                        "{path} entries must be integers (got: {})",
                        repr(item)
                    ))
                }),
            other => Err(ConfigError::value(format!(
                "{path} entries must be integers (got: {})",
                repr(other)
            ))),
        })
        .collect()
}

// ── small helpers over the raw document ─────────────────

/// Python's type name, for the `(got X)` half of a message.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(number) => {
            if number.is_f64() {
                "float"
            } else {
                "int"
            }
        }
        Value::String(_) => "str",
        Value::Sequence(_) => "list",
        Value::Mapping(_) => "dict",
        Value::Tagged(_) => "object",
    }
}

/// `x.get(key)` filtered through Python's `not in (None, "")`.
fn present(value: Option<&Value>) -> Option<&Value> {
    match value {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if text.is_empty() => None,
        Some(value) => Some(value),
    }
}

/// `bool(x)` on an optional key; an absent key is `False`.
fn truthy(value: Option<&Value>) -> bool {
    value.is_some_and(yaml::python_bool)
}

/// `raw.get(key) or {}` — a section that a falsy value empties.
fn section<'a>(value: Option<&'a Value>, path: &str) -> Parsed<Cow<'a, Mapping>> {
    match value {
        Some(value) if yaml::python_bool(value) => mapping_of(value, path),
        _ => Ok(Cow::Owned(Mapping::new())),
    }
}

/// `_agent_mapping` — null is an empty block; other non-mappings are
/// operator errors.
///
/// Note the difference from [`section`]: `[]` is falsy, so `section`
/// would quietly empty it, while this rejects it. `config.py` uses
/// this stricter form for `domains`, `agents` and the two roster
/// entries, where silently ignoring a removed setting could change
/// egress policy.
fn agent_mapping<'a>(value: Option<&'a Value>, path: &str) -> Parsed<Cow<'a, Mapping>> {
    match value {
        None | Some(Value::Null) => Ok(Cow::Owned(Mapping::new())),
        Some(Value::Mapping(mapping)) => Ok(Cow::Borrowed(mapping)),
        Some(other) => Err(ConfigError::value(format!(
            "{path} must be a mapping (got {})",
            type_name(other)
        ))),
    }
}

/// A value that has to be a mapping.
fn mapping_of<'a>(value: &'a Value, path: &str) -> Parsed<Cow<'a, Mapping>> {
    match value {
        Value::Mapping(mapping) => Ok(Cow::Borrowed(mapping)),
        other => Err(ConfigError::value(format!(
            "{path} must be a mapping (got {})",
            type_name(other)
        ))),
    }
}

/// `list(x or [])`, keeping the items raw.
fn value_list(value: Option<&Value>, path: &str) -> Parsed<Vec<Value>> {
    match value {
        Some(value) if yaml::python_bool(value) => match value {
            Value::Sequence(items) => Ok(items.clone()),
            other => Err(ConfigError::value(format!(
                "{path} must be a list (got {})",
                type_name(other)
            ))),
        },
        _ => Ok(Vec::new()),
    }
}

/// `list(x or [])` over scalars.
fn string_list(value: Option<&Value>, path: &str) -> Parsed<Vec<String>> {
    value_list(value, path)?
        .iter()
        .map(|item| scalar_string(item, path))
        .collect()
}

/// `dict(x or {})` over scalar values.
fn string_map(value: Option<&Value>, path: &str) -> Parsed<OrderedMap<String>> {
    let mapping = section(value, path)?;
    mapping
        .iter()
        .map(|(key, entry)| Ok((str_of(key), scalar_string(entry, path)?)))
        .collect()
}

/// A scalar, as the string Python's `str()` would make of it.
///
/// Divergence 2: a sequence or mapping is an error rather than its own
/// repr.
fn scalar_string(value: &Value, path: &str) -> Parsed<String> {
    match value {
        Value::Null => Ok(String::new()),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(str_of(value)),
        other => Err(ConfigError::value(format!(
            "{path} must be a string (got {})",
            type_name(other)
        ))),
    }
}

/// `x.get(key, default)` with no coercion — an absent key takes the
/// default, an explicit null becomes the empty string.
///
/// Null maps to `""` rather than to Python's `None` because every
/// consumer of these fields tests them for emptiness (`if not
/// config.name`) or feeds them to a regex, and `None` would be a
/// `TypeError` there. The empty string keeps the falsiness and drops
/// the crash.
fn raw_string(value: Option<&Value>, default: &str, path: &str) -> Parsed<String> {
    match value {
        None => Ok(default.to_owned()),
        Some(value) => scalar_string(value, path),
    }
}

/// `str(x.get(key, default))` — an explicit null becomes the text
/// `"None"`, which is what `config.py` then reports back to the user.
fn str_field(value: Option<&Value>, default: &str) -> String {
    match value {
        None => default.to_owned(),
        Some(value) => str_of(value),
    }
}

/// `str(x.get(key) or default)` — any falsy value takes the default.
fn or_string(value: Option<&Value>, default: &str, path: &str) -> Parsed<String> {
    match value {
        Some(value) if yaml::python_bool(value) => scalar_string(value, path),
        _ => Ok(default.to_owned()),
    }
}

/// `str(x.get(key, "") or "")`.
fn string_or_empty(value: Option<&Value>, path: &str) -> Parsed<String> {
    or_string(value, "", path)
}

/// `bool(x.get(key, default))` — Python truthiness, not an
/// `isinstance` check.
fn bool_field(value: Option<&Value>, default: bool) -> bool {
    match value {
        None => default,
        Some(value) => yaml::python_bool(value),
    }
}

/// A field that must be a **real** boolean.
///
/// `config.py:1343` and `:1350`: `bool("false")` is `True`, so a
/// hand-edited string would silently invert the operator's intent.
/// Only the watcher's `auto_revoke` and `dedup_samples` reach this
/// through a live path — `validate_agents_raw` has already rejected a
/// non-boolean with different wording, so this is the belt to that
/// braces and its message is the reachable one.
fn real_bool(value: Option<&Value>, default: bool, path: &str) -> Parsed<bool> {
    match value {
        None => Ok(default),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(ConfigError::value(format!(
            "{path} must be a boolean (true/false)"
        ))),
    }
}

/// `int(x.get(key, default))`.
fn int_field(value: Option<&Value>, default: i64, path: &str) -> Parsed<i64> {
    match value {
        None => Ok(default),
        Some(value) => int_value(value, path),
    }
}

/// `int(x)`, with the path in the message.
fn int_value(value: &Value, path: &str) -> Parsed<i64> {
    py_int(value).map_err(|error| ConfigError::value(format!("{path}: {error}")))
}

/// `x.get(key, default) or 0` over an integer — a falsy value is 0,
/// not the default.
fn or_int(value: Option<&Value>, default: i64, path: &str) -> Parsed<i64> {
    match value {
        None => Ok(default),
        Some(value) if !yaml::python_bool(value) => Ok(0),
        Some(value) => int_value(value, path),
    }
}

/// `float(x if x not in (None, "") else default)`.
fn present_float(value: Option<&Value>, default: f64, path: &str) -> Parsed<f64> {
    match present(value) {
        None => Ok(default),
        Some(value) => {
            py_float(value).map_err(|error| ConfigError::value(format!("{path}: {error}")))
        }
    }
}

/// `int(x if x not in (None, "") else default)`.
fn present_int(value: Option<&Value>, default: i64, path: &str) -> Parsed<i64> {
    match present(value) {
        None => Ok(default),
        Some(value) => {
            py_int(value).map_err(|error| ConfigError::value(format!("{path}: {error}")))
        }
    }
}

/// `domain.lower().rstrip(".")`.
fn normalize_domain(domain: &str) -> String {
    domain.to_lowercase().trim_end_matches('.').to_owned()
}

/// Drop every name in `names` from the cage's podman secrets and
/// environment.
///
/// Called three times — for `secret_injection`, for relay credentials
/// and for the agents' API keys — because all three are secrets the
/// cage must never see, even as a placeholder.
fn strip_secrets(container: &mut ContainerConfig, names: &BTreeSet<String>) {
    if names.is_empty() {
        return;
    }
    container
        .podman_secrets
        .retain(|secret| !names.contains(secret));
    container.env.retain(|key, _| !names.contains(key));
}

// ── Python's int() and float() ──────────────────────────

/// `int(value)`, returning CPython's own exception text on failure.
///
/// The text matters: `_llm_client` wraps it as
/// `agents.decider: invalid LLM client value (<text>)`, and the corpus
/// records that string.
fn py_int(value: &Value) -> Result<i64, String> {
    match value {
        Value::Bool(flag) => Ok(i64::from(*flag)),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                Ok(integer)
            } else if let Some(unsigned) = number.as_u64() {
                i64::try_from(unsigned).map_err(|_| "Python int too large to convert".to_owned())
            } else {
                let float = number.as_f64().unwrap_or(f64::NAN);
                if float.is_nan() {
                    Err("cannot convert float NaN to integer".to_owned())
                } else if float.is_infinite() {
                    Err("cannot convert float infinity to integer".to_owned())
                } else {
                    #[allow(clippy::cast_possible_truncation)]
                    Ok(float.trunc() as i64)
                }
            }
        }
        Value::String(text) => {
            reject_ambiguous(text)?;
            parse_python_int(text)
                .ok_or_else(|| format!("invalid literal for int() with base 10: '{text}'"))
        }
        other => Err(format!(
            "int() argument must be a string, a bytes-like object or a real number, not '{}'",
            type_name(other)
        )),
    }
}

/// `float(value)`, returning CPython's own exception text on failure.
fn py_float(value: &Value) -> Result<f64, String> {
    match value {
        Value::Bool(flag) => Ok(if *flag { 1.0 } else { 0.0 }),
        Value::Number(number) => Ok(number.as_f64().unwrap_or(f64::NAN)),
        Value::String(text) => {
            reject_ambiguous(text)?;
            text.trim()
                .replace('_', "")
                .parse::<f64>()
                .map_err(|_| format!("could not convert string to float: '{text}'"))
        }
        other => Err(format!(
            "float() argument must be a string or a real number, not '{}'",
            type_name(other)
        )),
    }
}

/// Refuse a string that Python would turn into a *different* number.
///
/// `crate::yaml`'s reader resolves YAML 1.1 booleans and nothing else,
/// so a plain `0755` arrives here as the text `"0755"` where
/// `config.py` received the integer 493 — PyYAML reads a leading zero
/// as octal. `int("0755")` is 755, so parsing it would be a silent
/// wrong answer by a factor of 1.5.
///
/// The guard is narrow on purpose. Most of the 1.1-only patterns are
/// already loud: `1:30` and `2024-01-02` fail to parse at all, so they
/// produce `invalid literal for int() with base 10`. And `1_000` is
/// 1000 to both readers, so it needs no guard. Only the radix
/// prefixes — octal, hex and binary — parse *successfully* into a
/// number that disagrees with PyYAML's, and those are the ones
/// rejected here. The shapes come from PyYAML's own `int` resolver
/// regex; the sexagesimal branch is included for its message rather
/// than its necessity.
fn reject_ambiguous(text: &str) -> Result<(), String> {
    let body = text.trim().trim_start_matches(['-', '+']);
    let radix = match body.as_bytes() {
        [b'0', b'b' | b'B', rest @ ..] if !rest.is_empty() => Some("binary"),
        [b'0', b'x' | b'X', rest @ ..] if !rest.is_empty() => Some("hexadecimal"),
        [b'0', rest @ ..]
            if !rest.is_empty() && rest.iter().all(|b| b.is_ascii_digit() || *b == b'_') =>
        {
            Some("octal")
        }
        _ if body.contains(':') && body.starts_with(|c: char| c.is_ascii_digit()) => {
            Some("sexagesimal")
        }
        _ => None,
    };
    match radix {
        Some(radix) => Err(format!(
            "'{text}' is a YAML 1.1 {radix} literal, which the egress proxy's PyYAML \
             reads as a different number than a plain decimal parse would. agentcage \
             will not guess which one you meant; write it as a plain decimal number"
        )),
        None => Ok(()),
    }
}

/// CPython's `int(str)`: optional sign, decimal digits, underscores
/// between digits, surrounding whitespace allowed.
fn parse_python_int(text: &str) -> Option<i64> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let digits = trimmed.replace('_', "");
    // `replace` would also accept `1__0` and `_1`, which CPython
    // rejects. Guard those explicitly rather than hand-rolling a
    // scanner: a leading, trailing or doubled underscore is the whole
    // difference.
    if trimmed.contains("__")
        || trimmed.starts_with('_')
        || trimmed.ends_with('_')
        || trimmed.contains("-_")
        || trimmed.contains("+_")
    {
        return None;
    }
    digits.parse::<i64>().ok()
}

#[cfg(test)]
mod tests {
    use super::{Config, load};
    use crate::config::{ConfigError, FixedHost};

    fn host() -> FixedHost {
        FixedHost::linux(&["192.0.2.53"])
    }

    fn parse(text: &str) -> Config {
        load("<test>", text, &host()).expect("parse")
    }

    fn error(text: &str) -> ConfigError {
        load("<test>", text, &host()).expect_err("should fail")
    }

    #[test]
    fn an_empty_document_is_the_default_config() {
        assert_eq!(parse(""), Config::default());
        assert_eq!(parse("{}\n"), Config::default());
        // A document that is not a mapping is the same -- it fails
        // later, on the missing name.
        assert_eq!(parse("- one\n- two\n"), Config::default());
    }

    #[test]
    fn the_host_probe_supplies_isolation_and_dns() {
        let config = parse("name: c\n");
        assert_eq!(config.isolation, "container");
        assert_eq!(config.dns_servers, ["192.0.2.53"]);
    }

    #[test]
    fn the_dns_probe_is_not_reached_when_the_config_names_its_own() {
        let broken = FixedHost {
            isolation: "container".to_owned(),
            dns_servers: Err(ConfigError::runtime("no usable DNS servers")),
        };
        let config = load("<test>", "name: c\ndns_servers: [1.1.1.1]\n", &broken)
            .expect("must not consult the probe");
        assert_eq!(config.dns_servers, ["1.1.1.1"]);
        // And it *is* reached when the key is absent.
        let error = load("<test>", "name: c\n", &broken).expect_err("probe fails");
        assert_eq!(error.python_type(), "RuntimeError");
    }

    #[test]
    fn firecracker_migrates_to_vm() {
        assert_eq!(parse("name: c\nisolation: firecracker\n").isolation, "vm");
        let config = parse("name: c\nisolation: vm\nfirecracker:\n  vcpus: 8\n");
        assert_eq!(config.vm.vcpus, 8);
        // An explicit `vm:` wins over the legacy key.
        let config = parse("name: c\nvm:\n  vcpus: 2\nfirecracker:\n  vcpus: 8\n");
        assert_eq!(config.vm.vcpus, 2);
    }

    /// The null/absent asymmetry `container-timeouts-zero` pins.
    #[test]
    fn restart_sec_and_the_timeouts_treat_null_differently() {
        let config = parse("name: c\ncontainer:\n  restart_sec: null\n  timeout_stop_sec: null\n");
        assert_eq!(config.container.restart_sec, 10);
        assert_eq!(config.container.timeout_stop_sec, 0);

        let config = parse("name: c\ncontainer:\n  timeout_start_sec: 0\n");
        assert_eq!(config.container.timeout_start_sec, 0);

        // Absent takes 120, not `ContainerConfig::default()`'s 600.
        assert_eq!(parse("name: c\n").container.timeout_start_sec, 120);
    }

    #[test]
    fn drop_capabilities_take_a_scalar_a_list_or_nothing() {
        assert_eq!(parse("name: c\n").container.drop_capabilities, ["ALL"]);
        assert_eq!(
            parse("name: c\ncontainer:\n  drop_capabilities: NET_RAW\n")
                .container
                .drop_capabilities,
            ["NET_RAW"]
        );
        assert!(
            parse("name: c\ncontainer:\n  drop_capabilities: []\n")
                .container
                .drop_capabilities
                .is_empty()
        );
    }

    #[test]
    fn an_empty_user_means_the_image_default() {
        assert_eq!(parse("name: c\n").container.user, "1000:1000");
        assert_eq!(
            parse("name: c\ncontainer:\n  user: ''\n").container.user,
            ""
        );
        assert_eq!(
            parse("name: c\ncontainer:\n  user: null\n").container.user,
            ""
        );
    }

    #[test]
    fn domains_pick_their_mode_from_the_keys_present() {
        assert_eq!(
            parse("name: c\ndomains:\n  allow: [a.example.com]\n")
                .domains
                .mode,
            "allowlist"
        );
        assert_eq!(
            parse("name: c\ndomains:\n  block: [a.example.com]\n")
                .domains
                .mode,
            "blocklist"
        );
        let legacy = parse("name: c\ndomains:\n  mode: allowlist\n  list: [a.example.com]\n");
        assert_eq!(legacy.domains.list(), ["a.example.com"]);
        // An empty `allow:` is still allowlist mode -- the key's
        // presence is what decides, not its contents.
        let empty = parse("name: c\ndomains:\n  allow: []\n");
        assert_eq!(empty.domains.mode, "allowlist");
        assert!(empty.domains.allow.is_empty());
    }

    #[test]
    fn expires_takes_a_mapping_or_a_list() {
        let mapped = parse(
            "name: c\ndomains:\n  allow: [a.example.com]\n  expires:\n    A.Example.Com.: '2030-01-01T00:00:00Z'\n",
        );
        assert_eq!(
            mapped
                .domains
                .expires
                .get("a.example.com")
                .map(String::as_str),
            Some("2030-01-01T00:00:00Z")
        );
        let listed = parse(
            "name: c\ndomains:\n  allow: [a.example.com]\n  expires:\n  - domain: a.example.com\n    expires_at: '2030-01-01T00:00:00Z'\n",
        );
        assert_eq!(listed.domains.expires.len(), 1);
    }

    #[test]
    fn a_disabled_agent_block_keeps_every_default() {
        let config = parse(
            "name: c\nagents:\n  decider:\n    enable: false\n    provider: anthropic\n    model: m\n",
        );
        // The operator's provider and model are discarded, exactly as
        // `config.py` discards them: the block is only read when
        // `enable` is true.
        assert_eq!(config.agents.decider.llm.provider, "");
        assert!(!config.agents.decider.enable);
    }

    /// Comparing floats for equality is exactly the assertion here:
    /// the value must be the 0 the operator wrote, not a default that
    /// happens to be close to it.
    #[allow(clippy::float_cmp)]
    #[test]
    fn an_enabled_decider_keeps_an_explicit_zero_rate_limit() {
        let config = parse(
            "name: c\nagents:\n  decider:\n    enable: true\n    provider: anthropic\n    model: m\n    api_key: env:K\n    rate_limit:\n      requests_per_second: 0\n      burst: 0\n",
        );
        assert_eq!(config.agents.decider.rate_limit_rps, 0.0);
        assert_eq!(config.agents.decider.rate_limit_burst, 0);
        assert_eq!(config.agents.decider.llm.timeout_seconds, 15.0);
    }

    #[test]
    fn an_agents_api_key_is_stripped_from_the_cage_environment() {
        let config = parse(
            "name: c\ncontainer:\n  env:\n    K: v\n    OTHER: keep\n  podman_secrets: [K]\nagents:\n  watcher:\n    enable: true\n    provider: openai\n    model: m\n    api_key: env:K\n",
        );
        assert!(!config.container.env.contains_key("K"));
        assert!(config.container.env.contains_key("OTHER"));
        assert!(config.container.podman_secrets.is_empty());
    }

    #[test]
    fn a_removed_schema_is_rejected_by_presence() {
        assert_eq!(
            error("name: c\ndomains:\n  auto:\n    enable: false\n").message(),
            "domains.auto is no longer supported; use agents.decider with flat LLM fields"
        );
        assert_eq!(
            error("name: c\nwatcher: {}\n").message(),
            "top-level watcher is no longer supported; use agents.watcher with flat LLM fields"
        );
        assert_eq!(
            error("name: c\nagents:\n  auditor: {}\n").message(),
            "unknown agents: auditor"
        );
        assert_eq!(
            error("name: c\nagents:\n  decider:\n    kind: llm\n").message(),
            "agents.decider.kind is no longer supported; omit kind"
        );
        assert_eq!(
            error("name: c\nagents:\n  decider:\n    agent: {}\n").message(),
            "agents.decider: LLM fields must be flat, not under 'agent'"
        );
        assert_eq!(
            error("name: c\nagents:\n  decider:\n    enable: 'yes'\n").message(),
            "agents.decider.enable must be a boolean (true/false)"
        );
    }

    #[test]
    fn the_ports_block_is_structurally_checked() {
        assert_eq!(
            error("name: c\nports: [80, 443]\n").message(),
            "ports must be a mapping with 'tcp', 'udp', and/or 'icmp' keys (got: [80, 443])"
        );
        assert_eq!(
            error("name: c\nports:\n  tcp: [80, 443]\n").message(),
            "ports.tcp must be a mapping with 'allow' and/or 'passthrough' keys (got: [80, 443]). \
             If you meant to list TCP ports, use 'ports.tcp.allow: [...]'"
        );
        assert_eq!(
            error("name: c\nports:\n  udp: [443]\n").message(),
            "ports.udp must be a mapping with an 'allow' key (got: [443]). If you meant to list \
             UDP ports, use 'ports.udp.allow: [...]'"
        );
        assert_eq!(
            error("name: c\nports:\n  icmp: true\n").message(),
            "ports.icmp must be a mapping with an 'allow' boolean (got: True). To allow outbound \
             ping, use 'ports.icmp.allow: true'"
        );
        assert_eq!(
            error("name: c\nports:\n  tcp:\n    allow: '80,443'\n").message(),
            "ports.tcp.allow must be a list of integers (got: '80,443')"
        );
        assert_eq!(
            error("name: c\nports:\n  icmp:\n    allow: yes-please\n").message(),
            "ports.icmp.allow must be a boolean (got: 'yes-please')"
        );
        assert_eq!(
            error("name: c\nports:\n  tcp:\n    allow: ['443']\n").message(),
            "ports.tcp.allow entries must be integers (got: '443')"
        );
        // `True == 1` in Python, so an `isinstance(e, int)` alone would
        // let this through as port 1.
        assert_eq!(
            error("name: c\nports:\n  udp:\n    allow: [true]\n").message(),
            "ports.udp.allow entries must be integers (got: True)"
        );
    }

    #[test]
    fn a_relay_without_its_required_keys_is_rejected() {
        assert_eq!(
            error("name: c\nprotocol_relays:\n- name: mail\n  type: imap\n  listen: ''\n")
                .message(),
            "protocol_relays entry requires name/type/listen (got name='mail', type='imap', \
             listen='')"
        );
        assert_eq!(
            error("name: c\nprotocol_relays:\n- nope\n").message(),
            "protocol_relays entry must be a mapping (got str)"
        );
    }

    #[test]
    fn a_relay_credential_is_stripped_from_the_cage_environment() {
        let config = parse(
            "name: c\ncontainer:\n  env:\n    MAIL_PW: v\nprotocol_relays:\n- name: mail\n  type: imap\n  listen: 0.0.0.0:1143\n  upstream:\n    host: imap.example.com\n    port: 993\n  auth:\n    type: imap-login\n    user_source: env:MAIL_USER\n    password_source: env:MAIL_PW\n",
        );
        assert!(config.container.env.is_empty());
        assert_eq!(config.protocol_relays[0].policy.conn_rate_limit, "30/min");
        assert_eq!(
            config.protocol_relays[0]
                .policy
                .bypass_inspectors_for_allowlisted,
            ["secrets", "entropy", "content-type"]
        );
    }

    #[test]
    fn an_explicit_empty_bypass_list_is_kept() {
        let config = parse(
            "name: c\nprotocol_relays:\n- name: mail\n  type: smtp\n  listen: 0.0.0.0:1025\n  upstream:\n    host: smtp.example.com\n    port: 465\n  policy:\n    bypass_inspectors_for_allowlisted: []\n",
        );
        assert!(
            config.protocol_relays[0]
                .policy
                .bypass_inspectors_for_allowlisted
                .is_empty()
        );
    }

    #[test]
    fn a_recipient_allowlist_may_be_a_bare_list() {
        let config = parse(
            "name: c\nprotocol_relays:\n- name: mail\n  type: smtp\n  listen: 0.0.0.0:1025\n  upstream:\n    host: smtp.example.com\n    port: 465\n  policy:\n    recipient_allowlist: [a@example.com]\n",
        );
        assert_eq!(
            config.protocol_relays[0]
                .policy
                .recipient_allowlist
                .addresses,
            ["a@example.com"]
        );
    }

    #[test]
    fn a_rule_without_an_env_name_is_skipped() {
        let config = parse(
            "name: c\nsecret_injection:\n- placeholder: x\n- env: TOKEN\n  source: env:TOKEN\n",
        );
        assert_eq!(config.secret_injection.len(), 1);
        assert_eq!(config.secret_injection[0].env, "TOKEN");
    }

    #[test]
    fn secret_injection_takes_a_list_or_a_rules_mapping() {
        let flat = parse("name: c\nsecret_injection:\n- env: A\n  source: env:A\n");
        let wrapped =
            parse("name: c\nsecret_injection:\n  rules:\n  - env: A\n    source: env:A\n");
        assert_eq!(flat.secret_injection, wrapped.secret_injection);
    }

    #[test]
    fn inspectors_keep_their_raw_shape_and_a_non_list_is_ignored() {
        let config = parse(
            "name: c\ninspectors:\n- name: domain\n- name: secrets\n  config:\n    action: block\n",
        );
        assert_eq!(config.inspectors.len(), 2);
        assert_eq!(
            config.inspectors[1]["config"]["action"].as_str(),
            Some("block")
        );
        assert!(parse("name: c\ninspectors: nope\n").inspectors.is_empty());
    }

    #[test]
    fn the_legacy_log_allowed_key_is_the_fallback() {
        assert!(
            parse("name: c\nlog_allowed: true\n")
                .logging
                .allowed_requests
        );
        // An explicit `logging.allowed_requests` wins, even when false.
        assert!(
            !parse("name: c\nlog_allowed: true\nlogging:\n  allowed_requests: false\n")
                .logging
                .allowed_requests
        );
    }

    /// A plain `no` is a real boolean by the time it gets here, and a
    /// quoted `'no'` is not -- the whole point of B2's reader.
    #[test]
    fn a_quoted_no_still_means_tls_on() {
        let off = parse(
            "name: c\nprotocol_relays:\n- name: m\n  type: imap\n  listen: 0.0.0.0:1143\n  upstream:\n    host: h\n    port: 993\n    tls: no\n",
        );
        assert!(!off.protocol_relays[0].upstream.tls);
        let on = parse(
            "name: c\nprotocol_relays:\n- name: m\n  type: imap\n  listen: 0.0.0.0:1143\n  upstream:\n    host: h\n    port: 993\n    tls: 'no'\n",
        );
        assert!(on.protocol_relays[0].upstream.tls);
    }

    /// The reader hands over `"0755"` where PyYAML hands over 493.
    /// Parsing it as 755 would be a silent wrong answer.
    #[test]
    fn a_yaml_1_1_ambiguous_scalar_in_a_numeric_field_is_refused() {
        let message = error("name: c\nvm:\n  mem_mb: 0755\n").message().to_owned();
        assert!(message.contains("YAML 1.1"), "unexpected: {message}");
        assert!(
            error("name: c\nvm:\n  vcpus: 1:30\n")
                .message()
                .contains("YAML 1.1")
        );
        // A plain decimal string is still accepted, as `int()` would.
        assert_eq!(parse("name: c\nvm:\n  vcpus: '8'\n").vm.vcpus, 8);
    }

    #[test]
    fn a_merge_key_reaches_the_parser_merged() {
        let config = parse(
            "defaults: &d\n  image: docker.io/library/node:22-slim\n  user: '0:0'\nname: c\ncontainer:\n  <<: *d\n  user: '1:1'\n",
        );
        assert_eq!(config.container.image, "docker.io/library/node:22-slim");
        assert_eq!(config.container.user, "1:1");
    }

    #[test]
    fn a_scalar_where_a_list_belongs_is_refused() {
        // `list("node")` is four one-character arguments in Python.
        assert_eq!(
            error("name: c\ncontainer:\n  command: node\n").message(),
            "container.command must be a list (got str)"
        );
        assert_eq!(
            error("name: c\ncontainer:\n  env: nope\n").message(),
            "container.env must be a mapping (got str)"
        );
    }

    #[test]
    fn malformed_yaml_names_the_file_and_the_place() {
        let message = error("name: [unclosed\n").message().to_owned();
        assert!(
            message.starts_with("<test> is not valid YAML at line "),
            "{message}"
        );
    }
}
