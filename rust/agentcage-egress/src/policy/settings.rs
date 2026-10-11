//! The `agents.decider` block, read the way the replaced implementation
//! read it on every (re)load.
//!
//! The block arrives from the raw proxy config, which unvalidated host
//! write paths can produce, so every field is coerced exactly as the
//! Python coerced it (`str(x or "")`, `float(x or 15.0)`, …) and a value
//! that made the Python raise is a [`ConfigError`]: the whole block is
//! refused and, on a reload, the running settings are kept.

use agentcage_core::python::str_of as py_str;

use super::pyfmt::{int_literal, strip, truncate_chars};
use crate::config::{Config, Mapping, Value, truthy};

/// The default control host.
pub const DEFAULT_CONTROL_HOST: &str = "agentcage.local";

/// The longest operator context carried into the prompt, in characters.
pub const MAX_CONTEXT_CHARS: usize = 4096;

/// A decider block the Python would have raised on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "agents.decider: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Whether the config enables the decider: the addon's gate, `agents` /
/// `decider` read as `x or {}` and `enable` by truthiness. A block that
/// is not a mapping is not enabled.
#[must_use]
pub fn decider_enabled(config: &Config) -> bool {
    let decider = config
        .get("agents")
        .filter(|v| truthy(v))
        .and_then(|agents| match agents {
            Value::Mapping(m) => m.get("decider"),
            _ => None,
        });
    match decider {
        Some(Value::Mapping(m)) => m.get("enable").is_some_and(truthy),
        _ => false,
    }
}

/// The parsed block. The API key is resolved separately (it is a secret
/// and is re-read on every reload); [`Settings::api_key_name`] names it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Settings {
    pub(crate) enable: bool,
    pub(crate) host: String,
    pub(crate) context: String,
    pub(crate) passthrough: Vec<String>,
    pub(crate) timeout_seconds: f64,
    pub(crate) max_tokens: u32,
    pub(crate) provider: String,
    pub(crate) model: String,
    pub(crate) base_url: String,
    pub(crate) api_key_name: String,
    pub(crate) rate_rps: f64,
    pub(crate) rate_burst: f64,
    pub(crate) agentcage_version: String,
}

/// `value or {}` where the Python went on to call `.get` on it: falsy is
/// empty, a mapping is itself, anything else raised `AttributeError`.
fn mapping_or_empty<'a>(
    value: Option<&'a Value>,
    what: &str,
) -> Result<Option<&'a Mapping>, ConfigError> {
    match value {
        None => Ok(None),
        Some(v) if !truthy(v) => Ok(None),
        Some(Value::Mapping(m)) => Ok(Some(m)),
        Some(_) => Err(ConfigError(format!("{what} is not a mapping"))),
    }
}

fn get<'a>(m: Option<&'a Mapping>, key: &str) -> Option<&'a Value> {
    m.and_then(|m| m.get(key))
}

/// `str(value or "")`.
fn str_or_empty(value: Option<&Value>) -> String {
    match value {
        Some(v) if truthy(v) => py_str(v),
        _ => String::new(),
    }
}

/// `float(value)`.
fn to_float(value: &Value, what: &str) -> Result<f64, ConfigError> {
    let bad = || ConfigError(format!("{what} is not a number: {}", py_str(value)));
    match value {
        Value::Number(n) => n.as_f64().ok_or_else(bad),
        Value::Bool(b) => Ok(f64::from(u8::from(*b))),
        Value::String(s) => strip(s).replace('_', "").parse().map_err(|_| bad()),
        _ => Err(bad()),
    }
}

/// `int(value)`, as an `i64`.
fn to_int(value: &Value, what: &str) -> Result<i64, ConfigError> {
    let bad = || ConfigError(format!("{what} is not an integer: {}", py_str(value)));
    match value {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i)
            } else if n.as_u64().is_some() {
                Ok(i64::MAX)
            } else {
                let f = n.as_f64().ok_or_else(bad)?;
                if f.is_finite() {
                    #[allow(clippy::cast_possible_truncation)]
                    Ok(f.trunc() as i64)
                } else {
                    Err(bad())
                }
            }
        }
        Value::Bool(b) => Ok(i64::from(*b)),
        Value::String(s) => int_literal(s).ok_or_else(bad),
        _ => Err(bad()),
    }
}

/// `list(value or [])` for `domains.passthrough`, keeping the strings.
fn passthrough(config: &Config) -> Result<Vec<String>, ConfigError> {
    let domains = mapping_or_empty(config.get("domains"), "domains")?;
    Ok(match get(domains, "passthrough") {
        Some(v) if !truthy(v) => Vec::new(),
        None => Vec::new(),
        Some(Value::Sequence(items)) => items
            .iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        // `list("abc")` is its characters, `list({...})` its keys.
        Some(Value::String(s)) => s.chars().map(String::from).collect(),
        Some(Value::Mapping(m)) => m
            .keys()
            .filter_map(|k| match k {
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        Some(_) => {
            return Err(ConfigError(
                "domains.passthrough is not iterable".to_owned(),
            ));
        }
    })
}

impl Settings {
    /// Parse the block out of the whole proxy config. Everything that can
    /// fail runs before anything is returned, so a caller never holds half
    /// a new config.
    pub(crate) fn parse(config: &Config) -> Result<Self, ConfigError> {
        let agents = mapping_or_empty(config.get("agents"), "agents")?;
        let cfg = mapping_or_empty(get(agents, "decider"), "agents.decider")?;
        let passthrough = passthrough(config)?;

        let host = match get(cfg, "host") {
            Some(v) if truthy(v) => py_str(v),
            _ => DEFAULT_CONTROL_HOST.to_owned(),
        }
        .to_lowercase()
        .trim_end_matches('.')
        .to_owned();

        let context = match get(cfg, "context") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(s)) => {
                let stripped = strip(s);
                let length = stripped.chars().count();
                if length > MAX_CONTEXT_CHARS {
                    eprintln!(
                        "agentcage: agents.decider.context truncated to {MAX_CONTEXT_CHARS} chars \
                         (was {length}) — validate_config normally rejects this; the proxy \
                         config was written by an unvalidated path"
                    );
                    truncate_chars(stripped, MAX_CONTEXT_CHARS)
                } else {
                    stripped.to_owned()
                }
            }
            // Never coerce a mapping or a number into a misleading repr
            // riding the system prompt; ignore it instead.
            Some(other) => {
                eprintln!(
                    "agentcage: agents.decider.context is not a string in the proxy config \
                     (got {}) — ignoring it",
                    agentcage_core::python::type_name(other)
                );
                String::new()
            }
        };

        let timeout_seconds = match get(cfg, "timeout_seconds") {
            Some(v) if truthy(v) => to_float(v, "timeout_seconds")?,
            _ => 15.0,
        };
        let max_tokens = match get(cfg, "max_tokens") {
            Some(v) if truthy(v) => to_int(v, "max_tokens")?,
            _ => 8192,
        };
        // The wire field is unsigned; a value the Python would have sent
        // only for the provider to reject it is refused here instead.
        let max_tokens = u32::try_from(max_tokens)
            .map_err(|_| ConfigError(format!("max_tokens out of range: {max_tokens}")))?;

        // An explicit 0 disables limiting; absent, null or "" falls back
        // to the 1 rps / burst 5 default rather than to 0.
        let rl = mapping_or_empty(get(cfg, "rate_limit"), "agents.decider.rate_limit")?;
        let unset = |v: Option<&Value>| match v {
            None | Some(Value::Null) => true,
            Some(Value::String(s)) => s.is_empty(),
            _ => false,
        };
        let rps_v = get(rl, "requests_per_second");
        let rate_rps = if unset(rps_v) {
            1.0
        } else {
            to_float(
                rps_v.unwrap_or(&Value::Null),
                "rate_limit.requests_per_second",
            )?
        };
        let burst_v = get(rl, "burst");
        let rate_burst = if unset(burst_v) {
            5
        } else {
            to_int(burst_v.unwrap_or(&Value::Null), "rate_limit.burst")?
        };

        let api_key = str_or_empty(get(cfg, "api_key"));
        // `auth_source.partition(":")[2]`: a bare name without a scheme
        // names nothing.
        let api_key_name = api_key
            .split_once(':')
            .map(|(_, name)| name.to_owned())
            .unwrap_or_default();

        Ok(Self {
            enable: get(cfg, "enable").is_some_and(truthy),
            host,
            context,
            passthrough,
            timeout_seconds,
            max_tokens,
            provider: str_or_empty(get(cfg, "provider")).to_lowercase(),
            model: str_or_empty(get(cfg, "model")),
            base_url: str_or_empty(get(cfg, "base_url"))
                .trim_end_matches('/')
                .to_owned(),
            api_key_name,
            rate_rps,
            #[allow(clippy::cast_precision_loss)]
            rate_burst: rate_burst as f64,
            agentcage_version: str_or_empty(config.get("agentcage_version")),
        })
    }
}
