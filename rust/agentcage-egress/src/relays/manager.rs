//! Starting the relays from the config, and keeping them in step with it.
//!
//! [`RelayManager::sync`] runs at boot and on every config reload. Entries
//! are diffed against the running relays by `name`:
//!
//! * identical entry, same credentials: the running relay is kept, not
//!   restarted, so its sessions (a long IMAP IDLE) survive; it takes the
//!   reload's `log_allowed` and relay inspector chain;
//! * changed entry, or credentials that now resolve to different values
//!   (`agentcage secret set` re-stages the file and bumps the config
//!   mtime; a relay reads its credentials only when it is built): the old
//!   relay is stopped and a new one built from the new entry. If the new
//!   entry fails validation or construction the old relay is still
//!   stopped, so the running set is always what a fresh boot with this
//!   config would produce, minus the restarts the diff avoids;
//! * removed entry: stopped, its sessions told goodbye;
//! * new entry: validated, built and started as at boot, with the same
//!   `relay_config_invalid` / `relay_init_failed` / `relay_start_failed`
//!   audit records.
//!
//! A later entry reusing a name is `relay_config_invalid` and the first
//! one wins: diffing by name needs unique names. Every stop completes
//! before any start, so a changed relay that keeps its listen port has
//! released it before the replacement binds.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use indexmap::IndexMap;
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;

use super::imap::ImapRelay;
use super::smtp::SmtpRelay;
use super::{RelaySettings, relay_log, s};
use crate::audit::AuditSink;
use crate::config::{Config, Value};
use crate::json::Json;

const LOGGER: &str = "agentcage";

/// A running relay of either protocol.
#[derive(Debug)]
pub enum Relay {
    /// An IMAP relay.
    Imap(ImapRelay),
    /// An SMTP relay.
    Smtp(SmtpRelay),
}

impl Relay {
    /// Build the relay an entry describes (`type: imap|smtp`).
    ///
    /// # Errors
    ///
    /// An unknown type, or the relay's own construction error.
    pub fn build(
        entry: &Value,
        audit: Arc<dyn AuditSink>,
        settings: &RelaySettings,
    ) -> Result<Self, String> {
        let rtype = match entry {
            Value::Mapping(m) => m
                .get("type")
                .map(agentcage_core::python::str_of)
                .unwrap_or_default(),
            _ => String::new(),
        };
        match rtype.as_str() {
            "imap" => ImapRelay::new(entry, audit, settings).map(Self::Imap),
            "smtp" => SmtpRelay::new(entry, audit, settings).map(Self::Smtp),
            other => Err(format!(
                "unknown relay type '{other}'. Registered: imap, smtp"
            )),
        }
    }

    /// The relay's name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Imap(r) => r.name(),
            Self::Smtp(r) => r.name(),
        }
    }

    /// Bind and serve.
    ///
    /// # Errors
    ///
    /// The listen address is invalid or cannot be bound.
    pub async fn start(&self) -> Result<(), String> {
        match self {
            Self::Imap(r) => r.start().await,
            Self::Smtp(r) => r.start().await,
        }
    }

    /// Close the listener and drain the sessions.
    pub async fn stop(&self) {
        match self {
            Self::Imap(r) => r.stop().await,
            Self::Smtp(r) => r.stop().await,
        }
    }

    /// Take a reload's settings without restarting.
    pub fn update_settings(&self, settings: &RelaySettings) {
        match self {
            Self::Imap(r) => r.update_settings(settings),
            Self::Smtp(r) => r.update_settings(settings),
        }
    }

    /// The bound address, once started.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Imap(r) => r.local_addr().await,
            Self::Smtp(r) => r.local_addr().await,
        }
    }
}

/// SHA-256 over the values an entry's `auth.*_source` resolve to now.
///
/// Lets a reload notice a rotated credential without keeping another
/// plaintext copy of it. A source that does not resolve, or uses a
/// refused scheme, contributes `""` (the relay itself refuses it).
#[must_use]
pub fn credentials_digest(entry: &Value) -> String {
    let auth = match entry {
        Value::Mapping(m) => match m.get("auth") {
            Some(Value::Mapping(a)) => Some(a),
            _ => None,
        },
        _ => None,
    };
    let values: Vec<String> = ["user_source", "password_source"]
        .iter()
        .map(|key| {
            let source = super::str_or(auth.and_then(|a| a.get(*key)), "");
            super::resolve_credential(&source).unwrap_or_default()
        })
        .collect();
    let digest = Sha256::digest(values.join("\0").as_bytes());
    digest.iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

/// A YAML value as the JSON an audit record carries.
fn to_json(value: &Value) -> Json {
    match value {
        Value::Null | Value::Tagged(_) => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Number(n) => n
            .as_i64()
            .map(Json::Int)
            .or_else(|| n.as_f64().map(Json::Float))
            .unwrap_or(Json::Null),
        Value::String(text) => Json::Str(text.clone()),
        Value::Sequence(items) => Json::Array(items.iter().map(to_json).collect()),
        Value::Mapping(m) => Json::Object(
            m.iter()
                .map(|(k, v)| (agentcage_core::python::str_of(k), to_json(v)))
                .collect(),
        ),
    }
}

/// The key a relay name is tracked under, or Python's complaint about an
/// unhashable one. A string and a number that print alike stay apart.
fn name_key(name: &Value) -> Result<String, String> {
    match name {
        Value::Sequence(_) | Value::Mapping(_) => Err(format!(
            "unhashable type: '{}'",
            agentcage_core::python::type_name(name)
        )),
        Value::String(text) => Ok(format!("s:{text}")),
        other => Ok(format!("r:{}", agentcage_core::python::repr(other))),
    }
}

#[derive(Debug)]
struct Running {
    entry: Value,
    credentials: String,
    relay: Arc<Relay>,
}

/// The running relays, kept in step with the config.
#[derive(Debug)]
pub struct RelayManager {
    audit: Arc<dyn AuditSink>,
    running: IndexMap<String, Running>,
}

impl RelayManager {
    /// No relays yet; the first [`Self::sync`] starts them.
    #[must_use]
    pub fn new(audit: Arc<dyn AuditSink>) -> Self {
        Self {
            audit,
            running: IndexMap::new(),
        }
    }

    /// The running relay named `name`.
    #[must_use]
    pub fn relay(&self, name: &str) -> Option<Arc<Relay>> {
        self.running
            .get(&format!("s:{name}"))
            .map(|r| Arc::clone(&r.relay))
    }

    /// The running relays, in config order.
    #[must_use]
    pub fn relays(&self) -> Vec<Arc<Relay>> {
        self.running
            .values()
            .map(|r| Arc::clone(&r.relay))
            .collect()
    }

    fn emit(&self, kind: &str, name: &Json, error: &str) {
        let entry = match name {
            Json::Str(name) => crate::audit::relay_failure(kind, name, error),
            // A name that is not a string is recorded as written.
            other => crate::json::object([
                ("kind", s(kind)),
                ("relay", other.clone()),
                ("error", s(error)),
            ]),
        };
        self.audit.emit(entry);
    }

    /// Make the running relays match `cfg`'s `protocol_relays`.
    ///
    /// `settings` is the reload's `log_allowed` and relay inspector chain
    /// (the chain's `relay_inspectors()`); a kept relay takes them too, since
    /// an inspector the reload added or dropped would otherwise never
    /// reach it.
    #[allow(clippy::too_many_lines)] // one pass over the entries, in the order the audit records come out
    pub async fn sync(&mut self, cfg: &Config, settings: &RelaySettings) {
        let entries: Vec<Value> = match cfg.get("protocol_relays") {
            Some(Value::Sequence(items)) => items.clone(),
            Some(Value::Mapping(m)) => m.keys().cloned().collect(),
            Some(Value::String(text)) => {
                text.chars().map(|c| Value::String(c.to_string())).collect()
            }
            _ => Vec::new(),
        };
        let mut current = std::mem::take(&mut self.running);
        let mut wanted: IndexMap<String, Running> = IndexMap::new();
        let mut starts: Vec<(String, Json, Arc<Relay>)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for entry in entries {
            let name_value = match &entry {
                Value::Mapping(m) => m
                    .get("name")
                    .cloned()
                    .unwrap_or_else(|| Value::String("?".into())),
                _ => Value::String("?".into()),
            };
            let name = to_json(&name_value);
            let checked = super::validate::validate_relay_entry(&entry).and_then(|()| {
                let key = name_key(&name_value)?;
                if seen.contains(&key) {
                    return Err(format!(
                        "duplicate relay name {}",
                        agentcage_core::python::repr(&name_value)
                    ));
                }
                Ok(key)
            });
            let key = match checked {
                Ok(key) => key,
                Err(e) => {
                    relay_log!(
                        warning,
                        LOGGER,
                        "relay {} invalid config: {e}",
                        agentcage_core::python::str_of(&name_value)
                    );
                    self.emit("relay_config_invalid", &name, &e);
                    continue;
                }
            };
            seen.insert(key.clone());
            // Digested before the relay reads them: a value re-staged in
            // between costs one extra restart on the next reload, never a
            // relay kept on old credentials.
            let credentials = credentials_digest(&entry);
            if let Some(running) = current.get(&key)
                && running.entry == entry
                && running.credentials == credentials
            {
                running.relay.update_settings(settings);
                if let Some(kept) = current.shift_remove(&key) {
                    wanted.insert(key, kept);
                }
                continue;
            }
            let relay = match Relay::build(&entry, Arc::clone(&self.audit), settings) {
                Ok(relay) => Arc::new(relay),
                Err(e) => {
                    relay_log!(
                        warning,
                        LOGGER,
                        "relay {} init failed: {e}",
                        agentcage_core::python::str_of(&name_value)
                    );
                    self.emit("relay_init_failed", &name, &e);
                    continue;
                }
            };
            relay_log!(info, LOGGER, "scheduled relay {}", relay.name());
            starts.push((key.clone(), name, Arc::clone(&relay)));
            wanted.insert(
                key,
                Running {
                    entry,
                    credentials,
                    relay,
                },
            );
        }

        // Whatever is left in `current` was removed or replaced.
        let mut stops = JoinSet::new();
        for (_, old) in current.drain(..) {
            relay_log!(info, LOGGER, "stopping relay {}", old.relay.name());
            stops.spawn(async move { old.relay.stop().await });
        }
        while stops.join_next().await.is_some() {}
        self.running = wanted;

        let mut started = JoinSet::new();
        for (i, (_, _, relay)) in starts.iter().enumerate() {
            let relay = Arc::clone(relay);
            started.spawn(async move { (i, relay.start().await) });
        }
        let mut results = Vec::new();
        while let Some(joined) = started.join_next().await {
            if let Ok(result) = joined {
                results.push(result);
            }
        }
        results.sort_by_key(|(i, _)| *i);
        for (i, result) in results {
            if let Err(e) = result {
                let (key, name, relay) = &starts[i];
                self.start_failed(key, name, relay, &e);
            }
        }
    }

    /// Audit a relay that could not start, and forget it, so the next
    /// reload treats the entry as new and tries again instead of calling
    /// it unchanged. Only that exact relay is dropped.
    fn start_failed(&mut self, key: &str, name: &Json, relay: &Arc<Relay>, error: &str) {
        relay_log!(
            error,
            LOGGER,
            "relay {} start failed: {error}",
            relay.name()
        );
        self.emit("relay_start_failed", name, error);
        if self
            .running
            .get(key)
            .is_some_and(|r| Arc::ptr_eq(&r.relay, relay))
        {
            self.running.shift_remove(key);
        }
    }

    /// Stop every relay (egress shutdown).
    pub async fn shutdown(&mut self) {
        let mut stops = JoinSet::new();
        for (_, running) in self.running.drain(..) {
            stops.spawn(async move { running.relay.stop().await });
        }
        while stops.join_next().await.is_some() {}
    }
}

#[cfg(test)]
#[path = "manager_tests.rs"]
mod tests;
