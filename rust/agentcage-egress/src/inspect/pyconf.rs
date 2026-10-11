//! Reading an inspector's config section with the replaced
//! implementation's semantics.
//!
//! Each built-in took a plain dict and read it with `config.get(key,
//! default)`, using the value as whatever Python type it came in as. The
//! helpers here reproduce that where the result is well defined (an `int`
//! or a `float` threshold, truthiness for flags) and refuse the config
//! where Python would have raised later, on every request, or iterated a
//! string's characters as if they were list items. Refusing at configure
//! time keeps a bad reload fail-closed (D1): the last good chain stays.

use agentcage_core::python::{str_of, type_name};

use crate::config::{Mapping, Value, truthy};
use crate::json::Json;

static EMPTY: std::sync::LazyLock<Mapping> = std::sync::LazyLock::new(Mapping::new);

/// The section as a mapping. A null section (an `inspectors:` entry with
/// `config: null`, a top-level `secrets: null`) reads as empty; the
/// replaced implementation raised on it, and an empty config is each
/// inspector's defaults.
pub(crate) fn section<'a>(value: &'a Value, inspector: &str) -> Result<&'a Mapping, String> {
    match value {
        Value::Null => Ok(&EMPTY),
        Value::Mapping(m) => Ok(m),
        other => Err(format!(
            "{inspector} inspector config must be a mapping (got {})",
            type_name(other)
        )),
    }
}

/// A number from the config, kept with its Python spelling: reasons
/// interpolate it (`threshold 7.0` for a float, `threshold 7` for an int).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Num {
    /// The value, for comparisons.
    pub value: f64,
    /// `str(value)` in Python.
    pub text: String,
    /// The value as `json.dumps` would write it (inspector metadata).
    pub json: Json,
}

impl Num {
    pub(crate) fn int(i: i64) -> Self {
        #[allow(clippy::cast_precision_loss)] // config byte counts and thresholds, far below 2^53
        Self {
            value: i as f64,
            text: i.to_string(),
            json: Json::Int(i),
        }
    }

    pub(crate) fn float(f: f64) -> Self {
        Self {
            value: f,
            text: py_float_str(f),
            json: Json::Float(f),
        }
    }

    /// Whether Python would call it truthy (`if not limit`).
    pub(crate) fn is_zero(&self) -> bool {
        self.value == 0.0
    }

    fn from_value(value: &Value) -> Option<Self> {
        match value {
            // `bool` is an `int` subclass in Python: compares as 0/1,
            // prints as `True`/`False`.
            Value::Bool(b) => Some(Self {
                value: f64::from(u8::from(*b)),
                text: str_of(value),
                json: Json::Bool(*b),
            }),
            Value::Number(n) => Some(match n.as_i64() {
                Some(i) => Self::int(i),
                None => match n.as_u64() {
                    #[allow(clippy::cast_precision_loss)]
                    // only for > i64::MAX, which no limit reaches
                    Some(u) => Self {
                        value: u as f64,
                        text: u.to_string(),
                        json: Json::BigInt(u.to_string()),
                    },
                    None => Self::float(n.as_f64().unwrap_or(f64::NAN)),
                },
            }),
            _ => None,
        }
    }
}

/// `str(f)` for a Python float: `repr`, with Python's spellings for the
/// non-finite values (`json.dumps` spells those differently).
pub(crate) fn py_float_str(f: f64) -> String {
    if f.is_nan() {
        "nan".to_owned()
    } else if f.is_infinite() {
        if f > 0.0 { "inf" } else { "-inf" }.to_owned()
    } else {
        crate::json::format_float(f)
    }
}

/// `config.get(key, default)` for a number.
pub(crate) fn num(map: &Mapping, key: &str, default: Num, inspector: &str) -> Result<Num, String> {
    match map.get(key) {
        None => Ok(default),
        Some(v) => Num::from_value(v)
            .ok_or_else(|| format!("{inspector}.{key} must be a number (got {})", type_name(v))),
    }
}

/// `int(v)`: integers, floats truncated, bools, and strings that parse
/// as an integer.
pub(crate) fn int_like(value: &Value) -> Option<i64> {
    match value {
        Value::String(s) => s.trim().parse().ok(),
        Value::Number(_) | Value::Bool(_) => crate::config::as_i64(Some(value)),
        _ => None,
    }
}

/// `config.get(key, default)` for a string.
pub(crate) fn string(
    map: &Mapping,
    key: &str,
    default: &str,
    inspector: &str,
) -> Result<String, String> {
    match map.get(key) {
        None => Ok(default.to_owned()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(v) => Err(format!(
            "{inspector}.{key} must be a string (got {})",
            type_name(v)
        )),
    }
}

/// `bool(config.get(key, default))`.
pub(crate) fn flag(map: &Mapping, key: &str, default: bool) -> bool {
    map.get(key).map_or(default, truthy)
}

/// A list of strings.
pub(crate) fn str_items(value: &Value, what: &str) -> Result<Vec<String>, String> {
    let Value::Sequence(items) = value else {
        return Err(format!(
            "{what} must be a list of strings (got {})",
            type_name(value)
        ));
    };
    items
        .iter()
        .map(|v| match v {
            Value::String(s) => Ok(s.clone()),
            other => Err(format!(
                "{what} entries must be strings (got {})",
                type_name(other)
            )),
        })
        .collect()
}

/// `config.get(key, default)` for a list of strings.
pub(crate) fn str_list(
    map: &Mapping,
    key: &str,
    default: &[&str],
    inspector: &str,
) -> Result<Vec<String>, String> {
    match map.get(key) {
        None => Ok(default.iter().map(|s| (*s).to_owned()).collect()),
        Some(v) => str_items(v, &format!("{inspector}.{key}")),
    }
}

/// A `{host: [prefix, ...]}` map, `{h.lower(): prefixes}`. Later keys
/// that lowercase to an earlier one replace it, keeping its position.
pub(crate) fn host_lists(
    map: &Mapping,
    key: &str,
    inspector: &str,
) -> Result<Vec<(String, Vec<String>)>, String> {
    let raw = match map.get(key) {
        None => return Ok(Vec::new()),
        Some(Value::Mapping(m)) => m,
        Some(v) => {
            return Err(format!(
                "{inspector}.{key} must be a mapping (got {})",
                type_name(v)
            ));
        }
    };
    let mut out: indexmap::IndexMap<String, Vec<String>> = indexmap::IndexMap::new();
    for (h, v) in raw {
        let Value::String(h) = h else {
            return Err(format!("{inspector}.{key} keys must be host names"));
        };
        out.insert(
            h.to_lowercase(),
            str_items(v, &format!("{inspector}.{key}.{h}"))?,
        );
    }
    Ok(out.into_iter().collect())
}

/// `host == h or host.endswith("." + h)`.
pub(crate) fn host_matches(host: &str, h: &str) -> bool {
    host == h || host.strip_suffix(h).is_some_and(|rest| rest.ends_with('.'))
}

/// Python's `str.isspace()` for one character, which is also what `\s`
/// matches in a `str` pattern. Unicode `White_Space` plus the four
/// C0 information separators (U+001C–U+001F) Python counts too.
pub(crate) fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `s.strip()`.
pub(crate) fn py_strip(s: &str) -> &str {
    s.trim_matches(py_isspace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_keep_their_python_spelling() {
        let m = agentcage_core::yaml::load("a: 7\nb: 7.0\nc: true\nd: .inf\ne: x\n").unwrap();
        let Value::Mapping(m) = m else { unreachable!() };
        let get = |k| num(&m, k, Num::int(0), "t").map(|n| n.text);
        assert_eq!(get("a").unwrap(), "7");
        assert_eq!(get("b").unwrap(), "7.0");
        assert_eq!(get("c").unwrap(), "True");
        assert_eq!(get("d").unwrap(), "inf");
        assert!(get("e").is_err());
        assert_eq!(get("missing").unwrap(), "0");
    }

    #[test]
    fn host_suffix_match() {
        assert!(host_matches("a.b.com", "b.com"));
        assert!(host_matches("b.com", "b.com"));
        assert!(!host_matches("ab.com", "b.com"));
        assert!(!host_matches("com", "b.com"));
    }
}
