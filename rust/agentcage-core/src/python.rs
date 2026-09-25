//! Python's `repr()` and `str()`, over a YAML value.
//!
//! `config.py`'s error strings interpolate the offending value with
//! `{!r}` at ~40 sites, and the golden corpus records every one of them
//! verbatim:
//!
//! ```text
//! ports must be a mapping with 'tcp', 'udp', and/or 'icmp' keys (got: [80, 443])
//! ports.tcp.allow entries must be integers (got: '443')
//! ports.icmp.allow must be a boolean (got: 'yes-please')
//! ```
//!
//! Those are UX — a user reads them — and the port is held to them by a
//! byte comparison, so the formatting has to be CPython's and not
//! Rust's `Debug`. The differences are not cosmetic: `True` not `true`,
//! `None` not `null`, `[80, 443]` with a space after the comma,
//! single-quoted strings that flip to double quotes when the text
//! contains an apostrophe.
//!
//! [`str_of`] is the other half. `config.py` coerces a dozen fields
//! with `str(...)`, so `memory: 512` becomes the string `"512"` and
//! `cpus: 2.5` becomes `"2.5"`. A port that only accepted YAML strings
//! there would reject configs that work today.
//!
//! Both are written against the value tree [`crate::yaml::load`]
//! produces, which is `yaml.safe_load`'s, so the only Python types that
//! can reach them are the six `safe_load` constructs plus the tagged
//! nodes `serde_norway` keeps.

use std::fmt::Write as _;

use crate::har::json::format_float;
use crate::yaml::Value;

/// `type(value).__name__`, for the `(got X)` half of a message.
///
/// The other half of the same job as [`repr`]: `config.py` and
/// `relays/_validate.py` name the offending value's Python *type* at
/// ~15 sites, and the golden corpus and the A4 contract fixtures record
/// every one of them. The mapping is the fixture README's, verbatim:
///
/// | YAML / JSON | `type(x).__name__` |
/// | :-- | :-- |
/// | `null` | `NoneType` |
/// | `true` / `false` | `bool` |
/// | integer | `int` |
/// | fractional number | `float` |
/// | string | `str` |
/// | sequence | `list` |
/// | mapping | `dict` |
///
/// # Divergences
///
/// A `Value::Tagged` has no `safe_load` counterpart, for the reason
/// [`repr`] gives. `object` is the closest Python name and nothing
/// that reaches an error message can be one.
#[must_use]
pub fn type_name(value: &Value) -> &'static str {
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

/// `repr(value)`, for a value that came out of `yaml.safe_load`.
///
/// # Divergences
///
/// A `Value::Tagged` has no Python counterpart — `safe_load` raises on
/// an unknown tag rather than producing an object — so it renders as
/// its tag. Nothing that reaches an error message can be one.
#[must_use]
pub fn repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Number(number) => number_text(number),
        Value::String(text) => repr_str(text),
        Value::Sequence(items) => {
            let rendered: Vec<String> = items.iter().map(repr).collect();
            format!("[{}]", rendered.join(", "))
        }
        Value::Mapping(mapping) => {
            let rendered: Vec<String> = mapping
                .iter()
                .map(|(key, entry)| format!("{}: {}", repr(key), repr(entry)))
                .collect();
            format!("{{{}}}", rendered.join(", "))
        }
        Value::Tagged(tagged) => format!("{}", tagged.tag),
    }
}

/// `str(value)`.
///
/// Identical to [`repr`] except for strings, which `str()` returns
/// unquoted. Containers are not special-cased because Python's `str`
/// of a `list` or `dict` *is* its `repr`.
#[must_use]
pub fn str_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => repr(other),
    }
}

/// `repr()` of a Python `str`.
///
/// CPython prefers `'`, and switches to `"` only when the text contains
/// a `'` and no `"` — so `"it's"` renders as `"it's"` rather than
/// `'it\'s'`.
///
/// Public because half of `config.py`'s `{!r}` sites interpolate a
/// field that is already a `String` — `config.name`, `pa.host`,
/// `w.api_key` — and wrapping each one in a [`Value`] only to unwrap
/// it again would be ceremony around the same six lines.
#[must_use]
pub fn repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            // CPython escapes exactly the non-printable code points
            // here. `char::is_control` covers C0 and C1, which is the
            // part any agentcage value can plausibly contain; the wider
            // `unicodedata` categories CPython also escapes would need
            // a Unicode table for no reachable gain.
            c if c.is_control() => {
                let code = c as u32;
                if code <= 0xff {
                    let _ = write!(out, "\\x{code:02x}");
                } else {
                    let _ = write!(out, "\\u{code:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `repr()` of an `int` or a `float`.
///
/// `serde_norway` keeps the two apart, so an integer prints without a
/// decimal point and a float goes through the same `repr` clone
/// `har.py`'s JSON needs. `1.0` stays `1.0`, not `1`.
fn number_text(number: &serde_norway::Number) -> String {
    if let Some(integer) = number.as_i64() {
        integer.to_string()
    } else if let Some(unsigned) = number.as_u64() {
        unsigned.to_string()
    } else {
        format_float(number.as_f64().unwrap_or(f64::NAN))
    }
}

#[cfg(test)]
mod tests {
    use super::{repr, str_of};
    use crate::yaml::load;

    /// Every shape the corpus's `{!r}` messages actually carry.
    ///
    /// The right-hand column is CPython's, measured with
    /// `repr(yaml.safe_load(...))`.
    #[test]
    fn repr_matches_cpython_on_the_shapes_config_py_reports() {
        for (document, expected) in [
            ("v: [80, 443]", "[80, 443]"),
            ("v: '443'", "'443'"),
            ("v: true", "True"),
            ("v: false", "False"),
            ("v: null", "None"),
            ("v: 9418", "9418"),
            ("v: 1.5", "1.5"),
            ("v: yes-please", "'yes-please'"),
            ("v: {a: 1, b: two}", "{'a': 1, 'b': 'two'}"),
            ("v: []", "[]"),
            ("v: {}", "{}"),
            ("v: [[1], {a: b}]", "[[1], {'a': 'b'}]"),
        ] {
            let value = load(document).expect("load");
            assert_eq!(repr(&value["v"]), expected, "for {document}");
        }
    }

    /// The quote CPython picks depends on the text.
    #[test]
    fn quoting_follows_cpython() {
        for (document, expected) in [
            ("v: \"it's\"", "\"it's\""),
            ("v: \"say \\\"hi\\\"\"", "'say \"hi\"'"),
            ("v: \"both ' and \\\"\"", "'both \\' and \"'"),
            ("v: \"line\\nbreak\"", "'line\\nbreak'"),
            ("v: \"back\\\\slash\"", "'back\\\\slash'"),
        ] {
            let value = load(document).expect("load");
            assert_eq!(repr(&value["v"]), expected, "for {document}");
        }
    }

    /// `str()` differs from `repr()` only for strings.
    #[test]
    fn str_leaves_strings_unquoted() {
        let value = load("s: hello\nn: 512\nf: 2.5\nb: true\nl: [1]\n").expect("load");
        assert_eq!(str_of(&value["s"]), "hello");
        assert_eq!(str_of(&value["n"]), "512");
        assert_eq!(str_of(&value["f"]), "2.5");
        assert_eq!(str_of(&value["b"]), "True");
        assert_eq!(str_of(&value["l"]), "[1]");
    }
}
