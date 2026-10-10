//! The egress config: `/etc/agentcage/config.yaml`.
//!
//! The host writes a proxy-config document (a dozen top-level keys plus
//! `agentcage_version`) and bind-mounts it read-only; a live change
//! rewrites it in place, and its mtime is the reload trigger. The full
//! `cage.yaml` is accepted too, with unknown keys ignored.
//!
//! The tree is kept as the YAML value the host's PyYAML-compatible loader
//! produces, and each module reads its own section with the Python
//! semantics it replaces (`cfg.get("x") or {}`, `bool(...)`). That keeps
//! lenient parsing — a wrong-typed value treated the way the Python
//! treated it — local to the module that owns the key, instead of one
//! schema struct guessing for everyone.

use std::path::Path;

pub use agentcage_core::yaml::{Mapping, Value};

/// A loaded config document.
#[derive(Clone, Debug, Default)]
pub struct Config {
    raw: Value,
}

/// Why a config could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The file could not be read.
    Io(std::io::Error),
    /// The YAML is malformed.
    Yaml(agentcage_core::yaml::Error),
    /// The document is not a mapping (or empty-as-null, which loads as an
    /// empty config).
    NotAMapping,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read config: {e}"),
            Self::Yaml(e) => write!(f, "malformed config: {e}"),
            Self::NotAMapping => f.write_str("config is not a mapping"),
        }
    }
}

impl std::error::Error for LoadError {}

impl Config {
    /// Read and parse `path`.
    ///
    /// # Errors
    ///
    /// The file is unreadable, malformed, or not a mapping.
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        let text = std::fs::read_to_string(path).map_err(LoadError::Io)?;
        Self::parse(&path.display().to_string(), &text)
    }

    /// Parse `text`; `source` names it in errors.
    ///
    /// # Errors
    ///
    /// The text is malformed or not a mapping. An empty document is an
    /// empty config, as `yaml.safe_load(f) or {}` makes it.
    pub fn parse(source: &str, text: &str) -> Result<Self, LoadError> {
        let raw = agentcage_core::yaml::load_named(source, text).map_err(LoadError::Yaml)?;
        Self::from_value(raw)
    }

    /// Wrap an already-loaded tree.
    ///
    /// # Errors
    ///
    /// `raw` is neither a mapping nor null.
    pub fn from_value(raw: Value) -> Result<Self, LoadError> {
        match raw {
            Value::Null => Ok(Self {
                raw: Value::Mapping(Mapping::new()),
            }),
            Value::Mapping(_) => Ok(Self { raw }),
            _ => Err(LoadError::NotAMapping),
        }
    }

    /// The whole tree.
    #[must_use]
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// `cfg.get(key)`: a top-level value, `None` when absent.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        get(&self.raw, key)
    }

    /// `cfg.get(key) or {}`: a top-level section as a mapping. Absent,
    /// null, falsy or not-a-mapping all read as empty.
    #[must_use]
    pub fn section(&self, key: &str) -> &Mapping {
        section(&self.raw, key)
    }
}

static EMPTY: std::sync::LazyLock<Mapping> = std::sync::LazyLock::new(Mapping::new);

/// `value.get(key)` on a mapping; `None` for a non-mapping or a missing
/// key.
#[must_use]
pub fn get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Mapping(m) => m.get(key),
        _ => None,
    }
}

/// `value.get(key) or {}` as a mapping.
#[must_use]
pub fn section<'a>(value: &'a Value, key: &str) -> &'a Mapping {
    match get(value, key) {
        Some(Value::Mapping(m)) => m,
        _ => &EMPTY,
    }
}

/// `mapping.get(key)` on a [`Mapping`].
#[must_use]
pub fn mget<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(key)
}

/// Python `bool(value)`.
#[must_use]
pub fn truthy(value: &Value) -> bool {
    agentcage_core::yaml::python_bool(value)
}

/// A string value, or `None` for anything else (no coercion).
#[must_use]
pub fn as_str(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::String(s)) => Some(s),
        _ => None,
    }
}

/// `[str(x) for x in value or []]` restricted to string items: a list of
/// strings, skipping non-string items; anything but a list is empty.
#[must_use]
pub fn str_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Sequence(items)) => items
            .iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// An integer value; floats are truncated as `int(x)` would, strings
/// that parse as integers are accepted as `int("12")` would.
#[must_use]
pub fn as_i64(value: Option<&Value>) -> Option<i64> {
    match value? {
        Value::Number(n) => n.as_i64().or_else(|| {
            #[allow(clippy::cast_possible_truncation)]
            n.as_f64().map(|f| f.trunc() as i64)
        }),
        Value::Bool(b) => Some(i64::from(*b)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// A float value, coercing integers and numeric strings as `float(x)`.
#[must_use]
pub fn as_f64(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_null_documents_are_empty_configs() {
        let c = Config::parse("t", "").unwrap();
        assert!(c.section("domains").is_empty());
        let c = Config::parse("t", "~\n").unwrap();
        assert!(c.get("domains").is_none());
    }

    #[test]
    fn sections_read_like_dict_get_or_empty() {
        let c = Config::parse("t", "domains:\n  mode: allowlist\ncapture: null\nx: 3\n").unwrap();
        assert_eq!(
            as_str(mget(c.section("domains"), "mode")),
            Some("allowlist")
        );
        assert!(c.section("capture").is_empty());
        assert!(c.section("x").is_empty());
        assert_eq!(as_i64(c.get("x")), Some(3));
    }

    #[test]
    fn a_list_document_is_refused() {
        assert!(matches!(
            Config::parse("t", "- a\n"),
            Err(LoadError::NotAMapping)
        ));
    }
}
