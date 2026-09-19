//! `cage.yaml`, as a Rust type — the port of `config.py`'s parser.
//!
//! # Scope
//!
//! This is PR C1 of RUST-PORT-PLAN.md's Track C, and it is deliberately
//! only half of `config.py`:
//!
//! | | Here | Elsewhere |
//! | :-- | :-- | :-- |
//! | the type tree | [`types`] | |
//! | `load_config` — reading a document into that tree | [`parse`] | |
//! | structural rejection (a list where a mapping belongs) | [`parse`] | |
//! | `resolved-config.json` | [`json`] | |
//! | domains, ports, secrets, placeholders | | PR C2 |
//! | `validate_config`'s agent rules | [`agents`] | |
//! | `validate_config`'s inspector warnings | [`inspectors`] | |
//! | one `protocol_relays` entry | [`crate::relays`] | |
//!
//! PR C3 added the last three rows. It owns the relay, agent, capture
//! and inspector half of `validate_config`; PR C2 owns the domain,
//! port, secret and placeholder half. The single ordered driver that
//! calls both is in neither: the two PRs land in parallel, and a
//! function whose body is half one branch and half the other is a
//! merge conflict with an observable ordering inside it. Each half is
//! a self-contained step, in `config.py`'s order internally.
//!
//! "Capture" has no validator of its own — `config.py` bounds
//! `capture.max_body_size` and `capture.max_file_size` by their
//! defaults rather than by a check. What C3 owed that area was the
//! cross-boundary constant: [`types::MAX_CAPTURE_FILE_BYTES`] must
//! equal the literal `capture.CaptureWriter` falls back to, which
//! `shared_constants.json` pins and
//! `tests/contract_relay_entry.rs` asserts.
//!
//! The line between the halves is **structure versus value**. "`ports`
//! must be a mapping" is structural and lives here; "port 70000 is out
//! of range" is a value judgement and does not. `config.py` does not
//! draw that line in one place — `load_config` raises on some values
//! itself, and delegates others to `validate_config`,
//! `secret_resolver` and `relays/_validate` — so the split is by the
//! *kind* of complaint, not by which Python function makes it. Every
//! value check `load_config` performs inline and this module does not
//! is listed in [`parse`]'s docs, so C2 and C3 have a checklist rather
//! than a diff to go hunting through.
//!
//! # What "faithful" means here
//!
//! The acceptance test is mechanical: [`json::to_json`] over every
//! config in `tests/fixtures/golden/valid/` must reproduce that case's
//! `resolved-config.json` byte for byte, all 125 of them. That is what
//! turns "did I port 2,473 lines correctly?" into a diff
//! (RUST-PORT-PLAN.md §4, Layer 1). `tests/golden_config.rs` is the
//! test.
//!
//! Faithful does **not** mean transliterated. `config.py` reads its
//! fields with Python's `dict.get`, `or`-fallbacks and `str()`/`int()`
//! coercions, and a handful of those combinations produce values no
//! user meant — `list("node")` is four one-character strings, and a
//! wrongly-typed `restart_sec` becomes a `RestartSec=` line systemd
//! then refuses. Where Python would carry such a value forward, this
//! module returns an error instead. Each one is noted at the site, and
//! they are collected in [`parse`]'s docs under "Deliberate
//! divergences".
//!
//! # No I/O
//!
//! `agentcage-core` does not touch the outside world (see the crate
//! docs), but `load_config` does, twice: it reads the file, and it
//! probes the host for a default isolation backend and for the
//! resolvers in `/etc/resolv.conf`. So [`load`] takes the file's text
//! from its caller and takes the two probes as a [`HostProbe`]. The
//! probe is a trait rather than two arguments because
//! `_host_dns_servers()` is only called when `dns_servers:` is absent
//! and can *fail* when it is — a config that sets its own resolvers
//! must load on a host that has none.

pub mod agents;
pub mod inspectors;
pub mod json;
pub mod parse;
pub mod types;

pub use agents::{
    AGENT_MAX_TOKENS_FLOOR, VALID_AGENT_KEY_SCHEMES, VALID_AGENT_PROVIDERS, require_api_key_shape,
    validate_agent_api_key, validate_agent_max_tokens, validate_agents,
};
pub use inspectors::inspector_warnings;
pub use json::to_json;
pub use parse::load;
pub use types::{
    AUTO_MAX_GRANTS, AUTO_NEVER_GRANT, AUTO_REQUIRE_ALLOWLIST_MODE, AUTO_TTL_SECONDS, AgentsConfig,
    BUILTIN_INSPECTOR_NAMES, BuildConfig, CaptureConfig, Config, ContainerConfig,
    DEFAULT_TCP_ALLOW_PORTS, DeciderAgentConfig, DomainConfig, IcmpPortsConfig, KNOWN_TRANSFORMS,
    LlmAgentConfig, LoggingConfig, MAX_CAPTURE_BODY_BYTES, MAX_CAPTURE_FILE_BYTES,
    MITMDUMP_RESERVED_PORTS, OrderedMap, PLACEHOLDER_PREFIX, PortsConfig, ProtocolRelay, RelayAuth,
    RelayPolicy, RelayRecipientAllowlist, RelayUpstream, SecretInjectionRule, SecretsConfig,
    TcpPortsConfig, UdpPortsConfig, VALID_LIFECYCLES, VALID_LOG_LEVELS, VALID_SECRET_SCOPES,
    VmConfig, WatcherAgentConfig,
};

use std::fmt;

/// What `load_config` raises.
///
/// `config.py` raises two exception types and the golden corpus records
/// both, as `"<ExceptionType>: <message>"` in `error.txt`. The type is
/// part of the recorded string, so it is part of the port: the CLI
/// turns a `ValueError` into a clean one-line message and lets a
/// `RuntimeError` through as the more unusual failure it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// Python's `ValueError` — almost everything.
    Value(String),
    /// Python's `RuntimeError` — raised by `_host_dns_servers()` alone,
    /// when the host has no usable upstream resolver to inherit.
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

    /// The Python exception class name, for the corpus's `error.txt`.
    #[must_use]
    pub fn python_type(&self) -> &'static str {
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

    /// `"<ExceptionType>: <message>"` — the corpus's recorded form.
    #[must_use]
    pub fn as_python_traceback_line(&self) -> String {
        format!("{}: {}", self.python_type(), self.message())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ConfigError {}

/// The two host probes `load_config` makes.
///
/// Both are I/O, and both are lazy in Python — `default_isolation()`
/// runs only when `isolation:` is absent, `_host_dns_servers()` only
/// when `dns_servers:` is. Keeping them lazy is not a micro-
/// optimisation: a laptop with a broken `/etc/resolv.conf` must still
/// be able to load a config that names its own resolvers, and eager
/// evaluation would take that away.
pub trait HostProbe {
    /// `config.default_isolation()` — the best isolation backend for
    /// this host.
    ///
    /// Linux → `container`. macOS 26+ on Apple Silicon with the
    /// `container` CLI installed → `apple-container`. Any other macOS →
    /// `vm`.
    fn default_isolation(&self) -> String;

    /// `config._host_dns_servers()` — the host's usable upstream
    /// resolvers.
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
            error.as_python_traceback_line(),
            "ValueError: 'name' is required in config"
        );
        assert_eq!(
            ConfigError::runtime("no DNS").as_python_traceback_line(),
            "RuntimeError: no DNS"
        );
        // Display is the message alone, so a caller that wants to print
        // it without the Python class name can.
        assert_eq!(error.to_string(), "'name' is required in config");
    }
}
