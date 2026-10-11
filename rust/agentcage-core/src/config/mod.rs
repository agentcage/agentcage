//! `cage.yaml`, as a Rust type: parsing, structural checks and
//! validation.
//!
//! # Layout
//!
//! | | Module |
//! | :-- | :-- |
//! | the type tree | [`types`] |
//! | `load` — reading a document into that tree | [`parse`] |
//! | structural rejection (a list where a mapping belongs) | [`parse`] |
//! | `resolved-config.json` | [`json`] |
//! | domains, ports, secrets, placeholders | [`domain`], [`secret`], [`placeholder`], [`mod@validate`] |
//! | agent rules | [`agents`] |
//! | inspector warnings | [`inspectors`] |
//! | one `protocol_relays` entry | [`crate::relays`] |
//!
//! Validation is two self-contained halves: the relay, agent, capture
//! and inspector half, and the domain, port, secret and placeholder
//! half. Each runs its checks in a fixed order internally, and the
//! order is observable — the first failing check is the one reported.
//!
//! "Capture" has no validator of its own — `capture.max_body_size` and
//! `capture.max_file_size` are bounded by their defaults rather than by
//! a check. What that area does own is a cross-boundary constant:
//! [`types::MAX_CAPTURE_FILE_BYTES`] must equal the literal the
//! egress's capture writer falls back to, which `shared_constants.json`
//! pins and `tests/contract_relay_entry.rs` asserts.
//!
//! The line between parsing and validation is **structure versus
//! value**. "`ports` must be a mapping" is structural and lives in
//! [`parse`]; "port 70000 is out of range" is a value judgement and
//! does not. The few value checks [`parse`] performs inline anyway are
//! listed in its docs.
//!
//! # What "faithful" means here
//!
//! The acceptance test is mechanical: [`json::to_json`] over every
//! config in `tests/fixtures/golden/valid/` must reproduce that case's
//! recorded `resolved-config.json` byte for byte, all 125 of them, and
//! every case under `tests/fixtures/golden/invalid/` must fail with its
//! recorded message. `tests/golden_config.rs` is the test.
//!
//! Faithful does **not** mean permissive. The lenient reads earlier
//! releases did — defaults for missing keys, falling back on falsy
//! values, coercing scalars to strings or integers — accepted a handful
//! of combinations that produced values no user meant: `"node"` read
//! as a list is four one-character strings, and a wrongly-typed
//! `restart_sec` becomes a `RestartSec=` line systemd then refuses.
//! Where such a value used to be carried forward, this module returns
//! an error instead. Each one is noted at the site, and they are
//! collected in [`parse`]'s docs under "Deliberate divergences".
//!
//! # No I/O
//!
//! `agentcage-core` does not touch the outside world (see the crate
//! docs), but loading a config does, twice: it reads the file, and it
//! probes the host for a default isolation backend and for the
//! resolvers in `/etc/resolv.conf`. So [`load`] takes the file's text
//! from its caller and takes the two probes as a [`HostProbe`]. The
//! probe is a trait rather than two arguments because the resolver
//! probe is only called when `dns_servers:` is absent and can *fail*
//! when it is — a config that sets its own resolvers must load on a
//! host that has none.

pub mod agents;
pub mod domain;
pub mod egress;
pub mod inspectors;
pub mod json;
pub mod parse;
pub mod placeholder;
pub mod secret;
pub mod types;
pub mod validate;

pub use agents::{
    AGENT_MAX_TOKENS_FLOOR, VALID_AGENT_KEY_SCHEMES, VALID_AGENT_PROVIDERS, require_api_key_shape,
    validate_agent_api_key, validate_agent_max_tokens, validate_agents,
};
pub use domain::{LabelPolicy, encoded_private_ip, is_global_ip, valid_domain};
pub use egress::EgressConfig;
pub use inspectors::{
    CUSTOM_INSPECTORS_GUIDE, PluginRef, inspector_warnings, plugin_file_name, plugin_refs,
    validate_plugins,
};
pub use json::to_json;
pub use parse::{load, validate_agents_document, validate_agents_raw};
pub use placeholder::{
    fill_raw_placeholders, injection_rules, injection_rules_mut, is_canonical, placeholder_for,
};
pub use secret::{KNOWN_BACKENDS, KNOWN_SOURCE_SCHEMES};
pub use types::{
    AUTO_MAX_GRANTS, AUTO_NEVER_GRANT, AUTO_REQUIRE_ALLOWLIST_MODE, AUTO_TTL_SECONDS, AgentsConfig,
    BUILTIN_INSPECTOR_NAMES, BuildConfig, CAPTURE_MIN_ACTION_ALIASES, CaptureConfig, Config,
    ContainerConfig, DEFAULT_TCP_ALLOW_PORTS, DeciderAgentConfig, DomainConfig,
    EGRESS_RESERVED_PORTS, IcmpPortsConfig, KNOWN_TRANSFORMS, LlmAgentConfig, LoggingConfig,
    MAX_CAPTURE_BODY_BYTES, MAX_CAPTURE_FILE_BYTES, OrderedMap, PLACEHOLDER_PREFIX, PortsConfig,
    ProtocolRelay, RelayAuth, RelayPolicy, RelayRecipientAllowlist, RelayUpstream,
    SecretInjectionRule, SecretsConfig, TcpPortsConfig, UdpPortsConfig, VALID_CAPTURE_MIN_ACTIONS,
    VALID_LIFECYCLES, VALID_LOG_LEVELS, VALID_SECRET_SCOPES, VmConfig, WatcherAgentConfig,
};
pub use validate::{FixedValidationHost, ValidationHost, validate};

use std::fmt;

/// Why a config failed to load.
///
/// Two classes, and the golden corpus records both, as
/// `"<Class>: <message>"` in `error.txt` — the class names are the ones
/// earlier releases printed. The CLI turns a `Value` error into a clean
/// one-line message and lets a `Runtime` error through as the more
/// unusual failure it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// `ValueError` — almost everything.
    Value(String),
    /// `RuntimeError` — raised by the host resolver probe alone, when the host has no usable upstream resolver to inherit.
    Runtime(String),
}

impl ConfigError {
    /// A `ValueError`, from anything that can be displayed.
    pub(crate) fn value(message: impl fmt::Display) -> Self {
        Self::Value(message.to_string())
    }

    /// A `RuntimeError`.
    pub fn runtime(message: impl fmt::Display) -> Self {
        Self::Runtime(message.to_string())
    }

    /// The class name, for the corpus's `error.txt`.
    #[must_use]
    pub fn error_class(&self) -> &'static str {
        match self {
            Self::Value(_) => "ValueError",
            Self::Runtime(_) => "RuntimeError",
        }
    }

    /// The message without the type prefix.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Value(message) | Self::Runtime(message) => message,
        }
    }

    /// `"<Class>: <message>"` — the corpus's recorded form.
    #[must_use]
    pub fn as_error_line(&self) -> String {
        format!("{}: {}", self.error_class(), self.message())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ConfigError {}

/// The two host probes loading a config makes.
///
/// Both are I/O, and both are lazy — `default_isolation()` runs only
/// when `isolation:` is absent, `dns_servers()` only when
/// `dns_servers:` is. Keeping them lazy is not a micro-
/// optimisation: a laptop with a broken `/etc/resolv.conf` must still
/// be able to load a config that names its own resolvers, and eager
/// evaluation would take that away.
pub trait HostProbe {
    /// The best isolation backend for this host.
    ///
    /// Linux → `container`. macOS 26+ on Apple Silicon with the
    /// `container` CLI installed → `apple-container`. Any other macOS →
    /// `vm`.
    fn default_isolation(&self) -> String;

    /// The host's usable upstream resolvers.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Runtime`] when every nameserver the host offers
    /// is a loopback address, which a container cannot reach.
    fn dns_servers(&self) -> Result<Vec<String>, ConfigError>;
}

/// A [`HostProbe`] with both answers decided up front.
///
/// What tests use, and what the golden corpus needs: the harness pins
/// `_host_dns_servers()` to a fixed pair and `platform.system()` to
/// Linux so the corpus is identical on a developer's Mac.
#[derive(Clone, Debug)]
pub struct FixedHost {
    /// What [`HostProbe::default_isolation`] returns.
    pub isolation: String,
    /// What [`HostProbe::dns_servers`] returns — `Err` models a host
    /// with nothing but loopback resolvers.
    pub dns_servers: Result<Vec<String>, ConfigError>,
}

impl FixedHost {
    /// The Linux answer, with the resolvers the caller names.
    #[must_use]
    pub fn linux(dns_servers: &[&str]) -> Self {
        Self {
            isolation: "container".to_owned(),
            dns_servers: Ok(dns_servers
                .iter()
                .map(|&server| server.to_owned())
                .collect()),
        }
    }
}

impl HostProbe for FixedHost {
    fn default_isolation(&self) -> String {
        self.isolation.clone()
    }

    fn dns_servers(&self) -> Result<Vec<String>, ConfigError> {
        self.dns_servers.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigError;

    #[test]
    fn the_error_renders_like_the_corpus_records_it() {
        let error = ConfigError::value("'name' is required in config");
        assert_eq!(
            error.as_error_line(),
            "ValueError: 'name' is required in config"
        );
        assert_eq!(
            ConfigError::runtime("no DNS").as_error_line(),
            "RuntimeError: no DNS"
        );
        // Display is the message alone, so a caller that wants to print
        // it without the class name can.
        assert_eq!(error.to_string(), "'name' is required in config");
    }
}
