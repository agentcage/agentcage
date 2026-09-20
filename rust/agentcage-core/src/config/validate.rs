//! `validate_config` — the value checks, and the warnings.
//!
//! Read alongside `src/agentcage/config.py:1597`. As in [`super::parse`],
//! the order of this file is the Python function's order, because **error
//! precedence is observable**: a config with two faults reports whichever
//! check runs first, and that is what an operator fixing errors one at a
//! time experiences. The golden corpus records the answer for 127 invalid
//! configs.
//!
//! # Scope
//!
//! This is PR C2. `validate_config` is one 620-line function, so the file
//! exists in full here, with C3's checks left as marked holes rather than
//! as a second copy of the skeleton:
//!
//! | | Owner |
//! | :-- | :-- |
//! | name, image, volumes, isolation, lifecycle, logging, vm | C2 |
//! | `container.ports` specs, `ports.{tcp,udp,icmp}`, the three collision checks | C2 |
//! | domains: `allow`/`block` exclusivity, per-entry syntax | C2 |
//! | secrets: scope, backend, env names, source schemes, transforms | C2 (in [`super::parse`], where `load_config` makes them) |
//! | placeholders: the canonical-form warning | C2 |
//! | `agents.decider` / `agents.watcher` | C3 |
//! | the apple-container inspector-chain warnings | C3 |
//!
//! Both C3 rows were left as `── C3 ──` comments at the exact point
//! `config.py` makes the check, so that filling them in would be an
//! insertion rather than a merge. **Both are filled.** The first
//! delegates to [`super::agents::validate_agents`], which C3 wrote but
//! never called from here; the second is inline at the end of
//! `apple_container_warnings`. Until they were, this function validated
//! every config *except* its agents — and `tests/golden_validate.rs`
//! measured the cost at thirty-one invalid corpus cases the port
//! accepted and `config.py` refused.
//!
//! # One Python behaviour reproduced rather than fixed
//!
//! It is noted again at its site. It is not fixed here, but it looks
//! like a bug rather than a choice:
//!
//! 1. **`_check_port_entry` runs after seven other checks.** It is the
//!    one type check in `validate_config` rather than in `load_config`,
//!    which is why this port reports it earlier than Python does — see
//!    "Error precedence" below.
//!
//! # Error precedence and the `Vec<i64>` ports
//!
//! PR C1 typed `ports.tcp.allow` and friends as `Vec<i64>` rather than as
//! raw values, so that `ports.tcp.allow entries must be integers (got:
//! '443')` could be reproduced byte-for-byte at all. The cost is that the
//! check moves from `validate_config` to `load_config`, and `load_config`
//! runs first.
//!
//! For a config with *one* fault that makes no difference, which is why
//! every corpus case still matches. It shows up only when a config has
//! **two**, and then the divergence is total in one direction: a string
//! or boolean port entry now preempts **every** check in this file,
//! `name` included. `name: BAD` with `ports.tcp.allow: ['443']` reports
//! the name in Python and the port here.
//!
//! Its position relative to the rest of `load_config` is unchanged —
//! `validate_agents_raw`, the `secrets:` section and `protocol_relays`
//! still win, because the parser reaches them before the `ports:`
//! section — so the boundary that moved is exactly one wide.
//!
//! `tests/golden_validate.rs`'s `error_precedence_matches_python` maps
//! it: twenty pairs, every expectation taken from running the same
//! document through `config.py` on CPython 3.13.0, five of which are the
//! divergence and fifteen of which are not.

use std::collections::BTreeSet;

use crate::python::{repr, repr_str};
use crate::volume_mounts::{
    self, MountTarget, TMPFS_COPYUP_OPTIONS, is_non_persistent_volume, mask_copyup_entries,
    split_volume_spec, tmpfs_wants_copyup, validate_non_persistent_volume,
};

use super::ConfigError;
use super::domain::{LabelPolicy, valid_domain};
use super::placeholder::is_canonical;
use super::types::{
    BUILTIN_INSPECTOR_NAMES, Config, MITMDUMP_RESERVED_PORTS, PLACEHOLDER_PREFIX, VALID_LIFECYCLES,
    VALID_LOG_LEVELS,
};
use crate::yaml::{Value, python_bool};

type Validated<T> = Result<T, ConfigError>;

/// What `validate_config` reads from the world around it.
///
/// `config.py` calls `platform.system()`, `platform.machine()` and
/// `os.environ` directly. This crate does no I/O (see the crate docs), so
/// they arrive as a trait — a separate one from [`super::HostProbe`], which
/// [`super::load`] takes, because the two are asked at different times
/// and a caller may well answer them from different places.
pub trait ValidationHost {
    /// `platform.system()` — `"Linux"`, `"Darwin"`, …
    fn system(&self) -> &str;

    /// `platform.machine()` — `"x86_64"`, `"arm64"`, …
    fn machine(&self) -> &str;

    /// `name in os.environ`.
    ///
    /// Only ever asked about a name a `${...}` reference in
    /// `container.env` mentioned, and only to decide whether to warn.
    fn env_var_is_set(&self, name: &str) -> bool;
}

/// A [`ValidationHost`] with every answer decided up front.
///
/// What tests and the golden corpus use — the harness pins
/// `platform.system()` / `platform.machine()` so the corpus is identical
/// on a developer's Mac.
#[derive(Clone, Debug)]
pub struct FixedValidationHost {
    /// What [`ValidationHost::system`] returns.
    pub system: String,
    /// What [`ValidationHost::machine`] returns.
    pub machine: String,
    /// The environment variables that count as set.
    pub environment: BTreeSet<String>,
}

impl FixedValidationHost {
    /// The Linux/x86\_64 answer, with an empty environment.
    #[must_use]
    pub fn linux() -> Self {
        Self {
            system: "Linux".to_owned(),
            machine: "x86_64".to_owned(),
            environment: BTreeSet::new(),
        }
    }

    /// The Apple Silicon answer, with an empty environment.
    #[must_use]
    pub fn macos_arm64() -> Self {
        Self {
            system: "Darwin".to_owned(),
            machine: "arm64".to_owned(),
            environment: BTreeSet::new(),
        }
    }
}

impl ValidationHost for FixedValidationHost {
    fn system(&self) -> &str {
        &self.system
    }

    fn machine(&self) -> &str {
        &self.machine
    }

    fn env_var_is_set(&self, name: &str) -> bool {
        self.environment.contains(name)
    }
}

/// Validate a config and return its warnings.
///
/// # Errors
///
/// [`ConfigError::Value`] for the first fatal problem found, in
/// `config.py`'s order. Warnings are returned, never raised: every one of
/// them describes a config that deploys and runs, and several fire on
/// stock scaffolds.
// One long function, for the reason `load_config`'s port is one long
// function: the order is the contract, and splitting it into helpers
// would hide the ordering behind call sites.
#[allow(clippy::too_many_lines)]
pub fn validate(config: &Config, host: &dyn ValidationHost) -> Validated<Vec<String>> {
    // ── Identity ────────────────────────────────────────
    if config.name.is_empty() {
        return Err(ConfigError::value("'name' is required in config"));
    }
    if !matches_name(&config.name) {
        return Err(ConfigError::value(format!(
            "'name' must be 1-63 lowercase alphanumeric characters or hyphens, \
             starting with a letter or digit (got: {})",
            repr_str(&config.name)
        )));
    }
    if config.container.image.is_empty() {
        return Err(ConfigError::value("container.image is required in config"));
    }
    // Before the image-reference check, matching `config.py`. The
    // ordering is not obviously deliberate, but it is observable.
    for volume in &config.container.volumes {
        validate_non_persistent_volume(volume).map_err(ConfigError::value)?;
    }
    if !matches_image_reference(&config.container.image) {
        return Err(ConfigError::value(format!(
            "invalid container image reference: {}",
            repr_str(&config.container.image)
        )));
    }

    // ── Backend ─────────────────────────────────────────
    if !matches!(
        config.isolation.as_str(),
        "container" | "vm" | "apple-container"
    ) {
        return Err(ConfigError::value(format!(
            "isolation must be 'container', 'vm', or 'apple-container' (got: {})",
            repr_str(&config.isolation)
        )));
    }
    if !VALID_LIFECYCLES.contains(&config.lifecycle.as_str()) {
        return Err(ConfigError::value(format!(
            "lifecycle must be one of {} (got: {})",
            python_tuple(&VALID_LIFECYCLES),
            repr_str(&config.lifecycle)
        )));
    }
    if config.isolation == "container" && host.system() == "Darwin" {
        return Err(ConfigError::value(
            "container isolation is not available on macOS; \
             use vm or apple-container instead",
        ));
    }
    if config.isolation == "apple-container" {
        if host.system() != "Darwin" {
            return Err(ConfigError::value(format!(
                "apple-container isolation requires macOS; current platform is {}",
                host.system()
            )));
        }
        if host.machine() != "arm64" {
            return Err(ConfigError::value(format!(
                "apple-container isolation requires Apple Silicon (arm64); current arch is {}",
                host.machine()
            )));
        }
    }
    if config.isolation == "vm" {
        if config.vm.vcpus < 1 {
            return Err(ConfigError::value("vm.vcpus must be >= 1"));
        }
        if config.vm.mem_mb < 128 {
            return Err(ConfigError::value("vm.mem_mb must be >= 128"));
        }
    }

    // ── Logging levels ──────────────────────────────────
    if !VALID_LOG_LEVELS.contains(&config.logging.level.as_str()) {
        return Err(ConfigError::value(format!(
            "logging.level must be one of {} (got: {})",
            python_tuple(&VALID_LOG_LEVELS),
            repr_str(&config.logging.level)
        )));
    }
    for (service, value) in [
        ("dns", &config.logging.dns),
        ("proxy", &config.logging.proxy),
        ("cage", &config.logging.cage),
    ] {
        if !value.is_empty() && !VALID_LOG_LEVELS.contains(&value.as_str()) {
            return Err(ConfigError::value(format!(
                "logging.{service} must be one of {} or empty (got: {})",
                python_tuple(&VALID_LOG_LEVELS),
                repr_str(value)
            )));
        }
    }

    // ── container.ports specs ───────────────────────────
    //
    // `HOST:CONTAINER` or `BIND:HOST:CONTAINER`. The bind address is not
    // checked — only the port numbers are, and both of them.
    for spec in &config.container.ports {
        let parts: Vec<&str> = spec.split(':').collect();
        let numbers: Vec<&str> = match parts.len() {
            3 => vec![parts[1], parts[2]],
            2 => parts.clone(),
            _ => {
                return Err(ConfigError::value(format!(
                    "invalid port spec {}: expected HOST_PORT:CONTAINER_PORT or \
                     BIND:HOST_PORT:CONTAINER_PORT",
                    repr_str(spec)
                )));
            }
        };
        for number in numbers {
            let Some(port) = python_int(number) else {
                return Err(ConfigError::value(format!(
                    "invalid port number {} in port spec {}",
                    repr_str(number),
                    repr_str(spec)
                )));
            };
            if !(1..=65535).contains(&port) {
                return Err(ConfigError::value(format!(
                    "port {port} out of range (1-65535) in port spec {}",
                    repr_str(spec)
                )));
            }
        }
    }

    // ── ports.tcp / ports.udp ───────────────────────────
    //
    // Per-list range and duplicate validation is independent. The
    // reserved-port and collision checks below apply only to the
    // *inspected* TCP set (tcp.allow - tcp.passthrough): those ports
    // become nat:PREROUTING REDIRECT rules, which collide with
    // mitmdump's own listeners and with in-process listeners (relays,
    // reverse-mode mitmdump for inbound forwards). Passthrough ports
    // never get a REDIRECT, so they do not conflict. UDP entries never
    // get one either — mitmdump cannot audit UDP — so the reserved-port
    // checks do not apply to them.
    //
    // The `entries must be integers` half of `_check_port_entry` is not
    // here: PR C1's `Vec<i64>` makes it a parse error. See the module
    // docs on error precedence.
    let tcp_allow = validate_port_list(&config.ports.tcp.allow, "ports.tcp.allow")?;
    let tcp_passthrough =
        validate_port_list(&config.ports.tcp.passthrough, "ports.tcp.passthrough")?;
    let udp_allow = validate_port_list(&config.ports.udp.allow, "ports.udp.allow")?;

    let inspected: BTreeSet<i64> = tcp_allow.difference(&tcp_passthrough).copied().collect();

    // `sorted(inspected_tcp_ports)` in Python, because CPython set order
    // is not deterministic and an operator with two violations would
    // otherwise see a different "first violation" on each run. A
    // `BTreeSet` is sorted already; the note is why the sort exists.
    for port in &inspected {
        if MITMDUMP_RESERVED_PORTS.contains(port) {
            return Err(ConfigError::value(format!(
                "ports.tcp.allow entry {port} is reserved by mitmdump \
                 (8080 = HTTP-proxy listener, 8443 = transparent listener); \
                 redirecting it would loop or break the L7 proxy path. \
                 Move it to ports.tcp.passthrough if the cage needs to \
                 reach an upstream service on this port without inspection"
            )));
        }
    }

    // Against protocol_relays listen ports.
    for relay in &config.protocol_relays {
        // `relay.listen.rpartition(":")` — the part after the last
        // colon, or nothing at all when there is no colon.
        let Some((_, port_text)) = relay.listen.rsplit_once(':') else {
            continue;
        };
        if port_text.is_empty() {
            continue;
        }
        let Some(port) = python_int(port_text) else {
            continue;
        };
        if inspected.contains(&port) {
            return Err(ConfigError::value(format!(
                "ports.tcp.allow entry {port} collides with \
                 protocol_relays[{}].listen={}; \
                 the REDIRECT would intercept connections meant for the \
                 relay. Move it to ports.tcp.passthrough if the cage also \
                 talks to an external service on this port",
                repr_str(&relay.name),
                repr_str(&relay.listen)
            )));
        }
    }

    // Against container.ports inbound forwards — the proxy runs
    // reverse-mode mitmdump listeners on those ports, and PREROUTING
    // REDIRECT fires before INPUT.
    for spec in &config.container.ports {
        let parts: Vec<&str> = spec.split(':').collect();
        let container_port = match parts.len() {
            3 => parts[2],
            2 => parts[1],
            _ => continue,
        };
        let Some(port) = python_int(container_port) else {
            continue;
        };
        if inspected.contains(&port) {
            return Err(ConfigError::value(format!(
                "ports.tcp.allow entry {port} collides with \
                 container.ports inbound forward {}; the \
                 REDIRECT would intercept connections meant for the \
                 cage's reverse-mode listener",
                repr_str(spec)
            )));
        }
    }

    // ── Domains ─────────────────────────────────────────
    if !config.domains.allow.is_empty() && !config.domains.block.is_empty() {
        return Err(ConfigError::value(
            "domains: cannot specify both 'allow' and 'block' lists",
        ));
    }

    // Per-entry syntax for allow/block/passthrough AND the
    // `domains.expires` KEYS. All of these flow verbatim into the same
    // dnsmasq `server=/` rendering chain: allow/block directly via
    // `state.save_dns_allowlist`, passthrough via quadlets'
    // `_effective_dns_allowlist` and the addon's `_apply_passthrough`
    // (both `re.escape` the entry into a mitmproxy `--ignore-hosts`
    // regex AND merge it into the DNS allowlist so the bypassed host
    // still resolves), and `expires` keys are domains too (`load_config`
    // has already lowercased them and stripped a trailing dot). A string
    // containing a newline or a slash in any of these would inject extra
    // directives or break the regex.
    //
    // The validator is lowercase-only on purpose: the DNS pipeline
    // lowercases, but the config value itself is rendered unmodified, so
    // being strict here keeps the trust boundary at parse time rather
    // than at render time.
    //
    // `passthrough` entries are plain dotted hostnames — the consumers
    // add the subdomain-wildcard prefix themselves — so no leading-dot
    // or bare-TLD wildcard form is accepted; a `.example.com` entry
    // would be escaped verbatim and silently fail to match anything.
    //
    // `AllowSingleLabel` on every static list: these entries are
    // operator-owned, the same trust as editing `cage.yaml` itself, and
    // a bare LAN/tailnet hostname is a legitimate entry that 0.34.0's
    // strict-dotted validator broke. The runtime-grant validators stay
    // strict; see `domain::LabelPolicy`.
    let offenders: Vec<&String> = config
        .domains
        .allow
        .iter()
        .chain(&config.domains.block)
        .chain(&config.domains.passthrough)
        .chain(config.domains.expires.keys())
        .filter(|entry| !valid_domain(entry, LabelPolicy::AllowSingleLabel))
        .collect();
    if !offenders.is_empty() {
        let rendered: Vec<String> = offenders
            .iter()
            .map(|entry| repr_str(entry.as_str()))
            .collect();
        return Err(ConfigError::value(format!(
            "invalid domain syntax: {} — expected a plain lowercase hostname \
             (e.g. 'api.example.com', or a bare LAN name like 'fcos-vm-home-01')",
            rendered.join(", ")
        )));
    }

    let mut warnings: Vec<String> = Vec::new();

    // Surface the fail-closed default-deny posture, so an operator who
    // omitted (or emptied) the domains policy is not surprised that
    // egress is fully blocked. An omitted `domains:` used to fall open
    // and allow every host at L7; the DomainInspector default-denies
    // now, and this is the loud heads-up that goes with it.
    if !matches!(config.domains.mode.as_str(), "allowlist" | "blocklist") {
        warnings.push(
            "no domains policy configured: all outbound hosts are blocked at \
             the proxy (default-deny). Add a domains.allow list (or \
             domains.block for blocklist mode) to permit egress."
                .to_owned(),
        );
    } else if config.domains.mode == "allowlist" && config.domains.allow.is_empty() {
        warnings.push(
            "domains.allow is empty: all outbound hosts are blocked at the \
             proxy (default-deny)."
                .to_owned(),
        );
    }

    if config.isolation == "apple-container" {
        apple_container_warnings(config, &mut warnings);
    }

    // Mirrors the domains.passthrough auto-merge warning below.
    for port in &config.ports.tcp.passthrough {
        if !tcp_allow.contains(port) {
            warnings.push(format!(
                "ports.tcp.passthrough entry {port} is not in \
                 ports.tcp.allow and will be added automatically to \
                 the effective allow list"
            ));
        }
    }

    // Transparent TCP capture fully disabled: with no inspected ports,
    // no REDIRECT rules are installed and only L7-aware traffic (apps
    // that honour HTTP_PROXY) is audited.
    if inspected.is_empty() {
        warnings.push(
            "ports has no inspected TCP entries (tcp.allow - \
             tcp.passthrough is empty): transparent capture disabled, \
             only L7 HTTP_PROXY-aware traffic will be audited"
                .to_owned(),
        );
    }

    // Default-deny with nothing allowed through: filter:FORWARD policy
    // is DROP, inspected TCP gets REDIRECTed, tcp.passthrough gets an
    // explicit TCP ACCEPT, udp.allow a UDP ACCEPT, ICMP echo-request
    // always ACCEPT. With all three lists empty the cage cannot initiate
    // any new TCP/UDP connection at all.
    if tcp_allow.is_empty() && tcp_passthrough.is_empty() && udp_allow.is_empty() {
        warnings.push(
            "ports.tcp.allow, ports.tcp.passthrough, and ports.udp.allow \
             are all empty: the cage will have zero outbound TCP/UDP \
             connectivity (the proxy's filter:FORWARD policy is DROP \
             and no ports are allowed through)"
                .to_owned(),
        );
    }

    // Placeholders outside the canonical `agentcage:secret:<ENV>:<hex>`
    // shape. A placeholder is matched as a literal string in outbound
    // content, so a guessable value like `{{GH_TOKEN}}` — or any string
    // an outbound payload might legitimately contain — is an
    // accidental-substitution hazard. The canonical prefix is also
    // self-identifying. Existing cages keep working: this is a warning,
    // and `agentcage secret rotate-placeholders` mints a conforming
    // token.
    for rule in &config.secret_injection {
        if !rule.placeholder.is_empty() && !is_canonical(&rule.placeholder) {
            warnings.push(format!(
                "secret_injection[{}]: placeholder \
                 '{}' is not in the '{PLACEHOLDER_PREFIX}*' \
                 form — omit `placeholder:` to auto-generate an entropic \
                 token, or run `agentcage secret rotate-placeholders` to \
                 mint one",
                repr_str(&rule.env),
                rule.placeholder
            ));
        }
    }

    if !config.domains.passthrough.is_empty() {
        warnings.push(
            "domains.passthrough bypasses TLS interception for listed domains \
             (proxy inspectors will not see this traffic)"
                .to_owned(),
        );
        if config.domains.mode == "allowlist" {
            let allowed: BTreeSet<&str> = config.domains.allow.iter().map(String::as_str).collect();
            for domain in &config.domains.passthrough {
                if !allowed.contains(domain.as_str()) {
                    warnings.push(format!(
                        "passthrough domain '{domain}' is not in the allow list \
                         and will be added automatically for DNS resolution"
                    ));
                }
            }
        }
    }

    if config.container.nested_containers {
        if config.isolation == "vm" {
            return Err(ConfigError::value(
                "nested_containers is not supported with vm isolation",
            ));
        }
        warnings.push(
            "nested_containers grants elevated capabilities, \
             disables NoNewPrivileges, and disables seccomp"
                .to_owned(),
        );
    }

    // Unset `${VAR}` references in container.env. Scanned by hand rather
    // than by regex because `config.py` does: it walks for `${`, takes
    // everything up to the next `}`, and resumes *after* that `}`, so a
    // malformed `${` with no closing brace ends the scan rather than
    // being skipped over.
    for (key, value) in &config.container.env {
        let mut start = 0;
        while let Some(open) = value[start..].find("${") {
            let open = start + open;
            let Some(close) = value[open..].find('}') else {
                break;
            };
            let close = open + close;
            let name = &value[open + 2..close];
            if !name.is_empty() && !host.env_var_is_set(name) {
                warnings.push(format!(
                    "env var reference ${{{name}}} is unset (key: {key})"
                ));
            }
            start = close + 1;
        }
    }

    // ── C3: the agents blocks ───────────────────────────
    //
    // `config.py`'s "Policy API validation", "agents.decider validation"
    // and "agents.watcher validation" run last, in that order, and
    // [`super::agents::validate_agents`] reproduces all three:
    //
    //   * `agents.{decider,watcher}.timeout_seconds must be finite and > 0`
    //     for each enabled role, both roles checked before either one's
    //     own block runs;
    //   * the decider block — control host shape, control host not in
    //     domains.allow/block/passthrough, allowlist mode, provider,
    //     model, max_tokens, api_key (required / scheme / not `cmd:`),
    //     https-only base_url, rate limits, context length, and the
    //     never-grant invariant;
    //   * the watcher block — not blocklist mode, the same LLM client
    //     checks field for field, then interval / window / max_flows /
    //     max_digest_tokens, the two spend warnings, and context length.
    //
    // C3 wrote that function and left this as a seam. The seam stayed
    // empty, so until it was filled the CLI validated every config
    // *except* its agents: a bad control host, an `api_key` in a scheme
    // the egress cannot resolve, or a `max_tokens` under the measured
    // 1024 floor all passed here and were caught only by the Python.
    // The last of those is the one that hurt — 0.38.0 added that floor
    // precisely because a starved decider denies every request while
    // looking healthy.
    warnings.extend(super::agents::validate_agents(config)?);

    Ok(warnings)
}

// ── ports ────────────────────────────────────────────────

/// `_validate_port_list` — range-check and dedupe one port list.
///
/// The type half of `_check_port_entry` is missing on purpose: the list
/// is `Vec<i64>`, so a non-integer entry never reaches here. See the
/// module docs.
fn validate_port_list(entries: &[i64], field: &str) -> Validated<BTreeSet<i64>> {
    let mut seen: BTreeSet<i64> = BTreeSet::new();
    for entry in entries {
        if !(1..=65535).contains(entry) {
            return Err(ConfigError::value(format!(
                "{field} entry {entry} out of range (1-65535)"
            )));
        }
        if !seen.insert(*entry) {
            return Err(ConfigError::value(format!(
                "{field} entry {entry} appears more than once"
            )));
        }
    }
    Ok(seen)
}

// ── apple-container parity warnings ──────────────────────

/// The knobs the apple-container backend does not respect, as warnings.
///
/// Plain `validate_config` warnings so the user sees them on `cage
/// create` / `update` / `show`. They do not block the operation, because
/// several built-in scaffolds set these fields unconditionally for the
/// container backend. The long-term fix is either to make the supervisor
/// honour them or to make the scaffold templates omit them on this
/// backend; until then, this tells the operator which of their entries
/// are decorative here. Tracked as issue #120.
///
/// Two absences are deliberate and documented in `config.py`:
/// `container.volumes` and `container.tmpfs` are both wired through
/// `container run` argv now, and `container.add_capabilities` is inert on
/// every backend (the cage workload runs as uid 1000 with an empty cap
/// set) while every stock package-manager scaffold sets it — so warning
/// about it was pure noise on the common path.
// As long as `validate` itself, and for the same reason: `config.py`
// builds this list in one place and in one order, and the order is what
// the corpus records.
#[allow(clippy::too_many_lines)]
fn apple_container_warnings(config: &Config, warnings: &mut Vec<String>) {
    let container = &config.container;
    let drops: [(&str, bool, &str); 8] = [
        (
            "container.named_volumes",
            !container.named_volumes.is_empty(),
            "podman named volumes (no equivalent on apple-container)",
        ),
        (
            "container.podman_secrets",
            !container.podman_secrets.is_empty(),
            "Podman secret refs (no host Podman secret store on apple-container; \
             use cage.yaml `secret_injection:` or env: instead)",
        ),
        (
            "container.nested_containers",
            container.nested_containers,
            "nested container runtime (no podman-in-podman shim available in \
             the Apple microVM)",
        ),
        (
            // Inbound published ports. On the container and vm backends
            // these become egress `PublishPort=` entries plus
            // reverse-mode mitmdump listeners. Apple's runtime has no
            // host-port-publishing equivalent — it uses VMNET_SHARED_MODE
            // NAT and reaches containers by their vmnet-assigned IP — so
            // the entry is silently dropped.
            "container.ports",
            !container.ports.is_empty(),
            "inbound published ports — Apple's runtime has no host \
             port-publishing (no `--publish`); reach the cage by its \
             vmnet IP instead",
        ),
        (
            // The scaffold default `keep-id` exists for rootless
            // podman's uid mapping. Here the supervisor's drop to uid
            // 1000 already achieves the "workload isn't root" goal, so
            // keep-id is a no-op rather than a missing feature; anything
            // else is operator intent that does not apply.
            "container.userns",
            !container.userns.is_empty() && container.userns != "keep-id",
            "user namespace remap (the supervisor drops to a fixed uid 1000 — \
             no remap layer)",
        ),
        (
            "container.drop_capabilities",
            container.drop_capabilities != ["ALL"],
            "custom drop list — the supervisor unconditionally drops ALL caps; \
             your selective drop list has no effect",
        ),
        (
            // Only when the operator EXPLICITLY wants a read-only
            // rootfs. The `false` default matches the backend's actual
            // behaviour — that is parity, not conflict. Before 0.22.7
            // this predicate was `is False` and fired on every default
            // cage, making it the noisiest warning agentcage had.
            "container.read_only",
            container.read_only,
            "read-only rootfs — apple-container's rootfs is always RW, \
             so `read_only: true` cannot be enforced",
        ),
        (
            "container.security_label_disable",
            !container.security_label_disable,
            "SELinux label control — apple-container's microVM has no SELinux",
        ),
    ];
    for (field, non_default, summary) in drops {
        if non_default {
            warnings.push(format!(
                "{field}: silently has no effect on apple-container \
                 ({summary}). See issue #120 for the parity plan."
            ));
        }
    }

    // `container.tmpfs` IS applied here since #318: `start()` emits one
    // `container run --tmpfs <path>` per entry, and Apple sorts the
    // container's mounts by destination depth before the in-guest OCI
    // runtime applies them, so `/workspace/.git/hooks` lands on top of
    // the `/workspace` bind. The #170 cage→host git-hook pivot mask and
    // the #173 cage→cage `.claude/settings.json` injection mask take
    // effect.
    //
    // What is still not honoured is the OPTION list, and separately the
    // copy-up of a mask whose source is not a host directory.
    let mount_targets: Vec<MountTarget> = container
        .volumes
        .iter()
        .map(|volume| {
            let (source, target, _options) = split_volume_spec(volume);
            MountTarget::new(
                target,
                if is_non_persistent_volume(volume) {
                    ""
                } else {
                    source
                },
            )
        })
        .chain(container.named_volumes.values().map(|mount| {
            MountTarget::new(
                mount.split_once(':').map_or(mount.as_str(), |(at, _)| at),
                "",
            )
        }))
        .collect();

    // `tmpcopyup`/`notmpcopyup` are honoured, by emulation rather than
    // by the runtime (#328): the backend mounts the covered host
    // directory read-only alongside a copy-up mask and cage-init replays
    // it into the tmpfs as the cage user. What the emulation cannot
    // reach is a copy-up whose source is not a host directory — a mask
    // over a named volume, over an `np` bind, or a tmpfs over a plain
    // image directory. Those come up empty here while podman copies the
    // covered content up.
    let copyup = mask_copyup_entries(&container.tmpfs, &mount_targets);
    let unseedable: Vec<&str> = container
        .tmpfs
        .iter()
        .filter(|entry| tmpfs_wants_copyup(entry))
        .filter(|entry| {
            let target = tmpfs_target(entry);
            let key = volume_mounts::normpath(match target.trim_end_matches('/') {
                "" => "/",
                trimmed => trimmed,
            });
            !copyup
                .iter()
                .any(|mask| mask.container_target == key && !mask.host_source.is_empty())
        })
        .map(|entry| tmpfs_target(entry))
        .collect();
    if !unseedable.is_empty() {
        warnings.push(format!(
            "container.tmpfs: `tmpcopyup` on {} cannot be emulated on \
             apple-container — Apple's `--tmpfs` has no option channel, \
             so agentcage seeds the tmpfs itself, and only from the host \
             directory a mask covers. These entries sit over a named \
             volume, an `np` bind or a plain image directory, so they \
             come up EMPTY here while podman copies the covered content \
             up. See #328.",
            unseedable.join(", ")
        ));
    }

    // Apple's `--tmpfs` takes a bare path (container 1.0.0 treats the
    // whole argument as the destination), so `rw,noexec,nosuid,nodev,
    // size=64M` is dropped and the mount lands with kernel-default tmpfs
    // semantics: writable, exec/suid/dev permitted, and sized only by
    // the cage VM's memory. The copy-up options are excluded because
    // they ARE honoured, by the emulation above.
    let dropped: Vec<&str> = container
        .tmpfs
        .iter()
        .filter(|entry| {
            tmpfs_options(entry)
                .iter()
                .any(|option| !TMPFS_COPYUP_OPTIONS.contains(option))
        })
        .map(|entry| tmpfs_target(entry))
        .collect();
    if !dropped.is_empty() {
        // The masks' pivot defence comes from the overlay itself, not
        // from `noexec` — a planted hook would execute on the HOST,
        // outside the cage's mount namespace, where an in-cage `noexec`
        // is irrelevant. But an operator who wrote `size=64M` deserves
        // to know it is not enforced, and an unbounded tmpfs is a
        // memory-exhaustion vector against the cage VM.
        let masks: Vec<&str> = dropped
            .iter()
            .copied()
            .filter(|target| {
                matches!(
                    target.trim_end_matches('/'),
                    "/workspace/.git/hooks" | "/workspace/.claude"
                )
            })
            .collect();
        let note = if masks.is_empty() {
            String::new()
        } else {
            format!(
                " The mask entries ({}) do still block their cage→host / \
                 cage→cage pivot: that protection comes from the tmpfs \
                 overlaying the bind, not from `noexec`.",
                masks.join(", ")
            )
        };
        warnings.push(format!(
            "container.tmpfs: the mounts ARE applied on apple-container, \
             but their OPTIONS are not — Apple's `container run --tmpfs` \
             takes a bare path, so {} get kernel-default tmpfs semantics: \
             noexec/nosuid/nodev are NOT enforced and any `size=` cap is \
             ignored (an unbounded tmpfs can exhaust the cage VM's \
             memory; bound it with container.memory).{note} See #120.",
            dropped.join(", ")
        ));
    }

    // `secret_injection.transform` runs end-to-end on apple-container —
    // the in-cage addon loads the same `data/proxy/transforms` registry
    // the container backend uses, and `KNOWN_TRANSFORMS` is the schema's
    // view of what it can dispatch. Anything outside that set is already
    // rejected at parse time by `validate_transform`, so reaching this
    // loop with an unknown transform is impossible. It is kept as a hard
    // assert, so a future divergence between the schema and the in-cage
    // registry surfaces as a config-time warning instead of a silent
    // runtime drop.
    for rule in &config.secret_injection {
        if !rule.transform.is_empty()
            && !super::types::KNOWN_TRANSFORMS.contains(&rule.transform.as_str())
        {
            warnings.push(format!(
                "secret_injection[{}].transform ={}: not in KNOWN_TRANSFORMS — the \
                 apple-container addon will skip the rule at startup. See issue #120.",
                repr_str(&rule.env),
                repr_str(&rule.transform)
            ));
        }
    }

    // ── C3: the inspector chain ─────────────────────────
    //
    // Last in this block, one warning per `config.inspectors` entry.
    // Built-in inspectors run end to end on apple-container and are
    // accepted in silence. The two that are not:
    //
    //   * an entry with `path:` — a custom Python file — is not staged
    //     into the wrapper image, so the in-cage addon skips it;
    //   * an unrecognised built-in name, so a typo does not no-op
    //     silently.
    //
    // `name` is `entry.get("name", "")`, so a missing key is the empty
    // string and `{name!r}` renders it `''`. A non-string name is not
    // in the built-in set either, and [`python::repr`] renders it the
    // way Python's `!r` would — `5`, not `'5'`.
    //
    // `config.inspectors` is already filtered to mappings at parse
    // time, so the index here is the post-filter one, exactly as in
    // `config.py`: both enumerate the same already-filtered list.
    let empty = Value::String(String::new());
    for (index, entry) in config.inspectors.iter().enumerate() {
        let name = entry.get("name").unwrap_or(&empty);
        if entry.get("path").is_some_and(python_bool) {
            warnings.push(format!(
                "inspectors[{index}] {}: custom Python file inspectors (path: ...) are \
                 not yet staged into the apple-container wrapper image — the in-cage \
                 addon will skip this entry. Use a built-in inspector or stay on the \
                 container backend.",
                repr(name)
            ));
        } else if python_bool(name) && !is_builtin_inspector(name) {
            warnings.push(format!(
                "inspectors[{index}] {}: not a known built-in inspector — the in-cage \
                 addon will skip this entry. Valid names: {}.",
                repr(name),
                sorted_builtin_inspector_names().join(", ")
            ));
        }
    }
}

/// `name in _BUILTIN_INSPECTOR_NAMES`.
///
/// A non-string is never in a `frozenset` of strings, so it falls to
/// the warning — which is what `config.py` does.
fn is_builtin_inspector(name: &Value) -> bool {
    name.as_str()
        .is_some_and(|text| BUILTIN_INSPECTOR_NAMES.contains(&text))
}

/// `', '.join(sorted(_BUILTIN_INSPECTOR_NAMES))`.
///
/// The constant is declared in registry order; the message is sorted.
fn sorted_builtin_inspector_names() -> Vec<&'static str> {
    let mut names = BUILTIN_INSPECTOR_NAMES.to_vec();
    names.sort_unstable();
    names
}

/// A `container.tmpfs` entry's target — `entry.partition(":")[0]`.
///
/// Deliberately *not* [`volume_mounts::tmpfs_spec_target`]: this is the
/// raw text before the first colon, which is what the warnings print,
/// trailing slash and all.
fn tmpfs_target(entry: &str) -> &str {
    entry.split_once(':').map_or(entry, |(target, _)| target)
}

/// A `container.tmpfs` entry's non-empty options.
fn tmpfs_options(entry: &str) -> Vec<&str> {
    entry.split_once(':').map_or_else(Vec::new, |(_, options)| {
        options.split(',').filter(|o| !o.is_empty()).collect()
    })
}

// ── Python-shaped helpers ────────────────────────────────

/// `repr()` of a Python tuple of strings.
///
/// `lifecycle` and `logging.level` interpolate their valid-value tuple
/// with `{}`, which for a tuple is its `repr` — `('service',
/// 'interactive', 'ephemeral')`, trailing comma and all if it ever holds
/// one element.
fn python_tuple(values: &[&str]) -> String {
    let rendered: Vec<String> = values.iter().map(|value| repr_str(value)).collect();
    if rendered.len() == 1 {
        format!("({},)", rendered[0])
    } else {
        format!("({})", rendered.join(", "))
    }
}

/// `re.match(r'^[a-z0-9][a-z0-9-]{0,62}\Z', name)`.
///
/// # The anchor
///
/// This pattern anchored on `$` until the anchor sweep. Python's `$` matches at
/// the end of the string **or immediately before one trailing newline**,
/// so `"my-cage\n"` used to pass — and the name goes on to become a
/// systemd unit name, a podman object name and a directory under the
/// state dir. `valid_domain` had always anchored on `\Z` for exactly
/// that reason; `name` and `container.image` did not get the same
/// treatment until the anchor sweep. Both sides now reject it.
fn matches_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// `re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._/:-]*(@sha256:[a-f0-9]{64})?\Z', image)`.
///
/// Anchored on `\Z` since the anchor sweep, for the reason
/// [`matches_name`] gives.
///
/// No backtracking is needed: `@` is not in the body charset, so the
/// optional digest can only begin at the first `@`, and the split point
/// is unambiguous.
fn matches_image_reference(image: &str) -> bool {
    let (reference, digest) = match image.split_once('@') {
        Some((reference, digest)) => (reference, Some(digest)),
        None => (image, None),
    };

    let bytes = reference.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    let body_ok = bytes[1..].iter().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b':' | b'-')
    });
    if !body_ok {
        return false;
    }

    match digest {
        None => true,
        Some(digest) => {
            let Some(hex) = digest.strip_prefix("sha256:") else {
                return false;
            };
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }
    }
}

/// `int(text)`, for the strings inside a `container.ports` spec.
///
/// Python's `int` is more forgiving than `str::parse`, and the
/// difference is reachable here because these strings come out of a
/// user-written `"127.0.0.1: 8080 :3000"`. It accepts surrounding
/// whitespace, an optional sign, and single underscores between digits
/// (PEP 515). It does **not** accept an empty string, a bare sign, a
/// leading or trailing underscore, or two in a row.
///
/// Whitespace is Python's, not Rust's — see `domain::is_python_space`
/// for why those differ.
fn python_int(text: &str) -> Option<i64> {
    let trimmed = text.trim_matches(super::domain::is_python_space);
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if digits.is_empty() {
        return None;
    }

    let mut value: i64 = 0;
    let mut previous_was_underscore = true; // a leading `_` is invalid
    for byte in digits.bytes() {
        if byte == b'_' {
            if previous_was_underscore {
                return None;
            }
            previous_was_underscore = true;
            continue;
        }
        if !byte.is_ascii_digit() {
            return None;
        }
        previous_was_underscore = false;
        value = value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))?;
    }
    // A trailing underscore is invalid too.
    if previous_was_underscore {
        return None;
    }
    Some(if negative { -value } else { value })
}

#[cfg(test)]
mod tests {
    use super::{
        FixedValidationHost, matches_image_reference, matches_name, python_int, python_tuple,
        validate,
    };
    use crate::config::types::Config;

    fn named(name: &str) -> Config {
        Config {
            name: name.to_owned(),
            container: crate::config::types::ContainerConfig {
                image: "docker.io/library/alpine:3".to_owned(),
                ..Default::default()
            },
            ..Config::default()
        }
    }

    #[test]
    fn a_config_with_no_name_is_the_first_complaint() {
        let error = validate(&Config::default(), &FixedValidationHost::linux())
            .expect_err("expected a refusal");
        assert_eq!(error.message(), "'name' is required in config");
    }

    #[test]
    fn the_tuple_messages_read_like_pythons() {
        assert_eq!(python_tuple(&["a", "b"]), "('a', 'b')");
        assert_eq!(python_tuple(&["a"]), "('a',)");
    }

    /// The `\Z` anchor — see [`matches_name`]. A trailing newline used
    /// to pass both patterns and no longer does, on either side.
    #[test]
    fn a_trailing_newline_fails_name_and_image_exactly_as_it_does_in_python() {
        assert!(matches_name("my-cage"));
        assert!(!matches_name("my-cage\n"));
        assert!(!matches_name("my-cage\n\n"));
        assert!(!matches_name("my_cage"));
        assert!(matches_image_reference("alpine:3"));
        assert!(!matches_image_reference("alpine:3\n"));
        assert!(!matches_image_reference("!!not a ref!!"));
    }

    #[test]
    fn an_image_digest_must_be_a_lowercase_sha256() {
        let digest = "a".repeat(64);
        assert!(matches_image_reference(&format!("alpine@sha256:{digest}")));
        assert!(!matches_image_reference(&format!("alpine@sha512:{digest}")));
        assert!(!matches_image_reference(&format!(
            "alpine@sha256:{}",
            "A".repeat(64)
        )));
        assert!(!matches_image_reference("alpine@sha256:abc"));
    }

    #[test]
    fn python_int_is_more_forgiving_than_parse() {
        assert_eq!(python_int(" 80 "), Some(80));
        assert_eq!(python_int("+80"), Some(80));
        assert_eq!(python_int("1_000"), Some(1000));
        assert_eq!(python_int("http"), None);
        assert_eq!(python_int("_80"), None);
        assert_eq!(python_int("80_"), None);
        assert_eq!(python_int("8__0"), None);
        assert_eq!(python_int(""), None);
    }

    #[test]
    fn a_duplicate_port_is_named_once_the_ranges_are_clean() {
        let mut config = named("cage");
        config.ports.tcp.allow = vec![443, 443];
        let error = validate(&config, &FixedValidationHost::linux()).expect_err("dup");
        assert_eq!(
            error.message(),
            "ports.tcp.allow entry 443 appears more than once"
        );
    }

    #[test]
    fn an_offending_domain_from_any_list_is_named() {
        let mut config = named("cage");
        config.domains.mode = "allowlist".to_owned();
        config.domains.passthrough = vec![".example.com".to_owned()];
        let error = validate(&config, &FixedValidationHost::linux()).expect_err("domain");
        assert_eq!(
            error.message(),
            "invalid domain syntax: '.example.com' — expected a plain lowercase hostname \
             (e.g. 'api.example.com', or a bare LAN name like 'fcos-vm-home-01')"
        );
    }
}
