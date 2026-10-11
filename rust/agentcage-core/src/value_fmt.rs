//! How a config value is spelled inside an error message, and how a
//! scalar is coerced to a string where a field accepts one.
//!
//! # The message convention
//!
//! Config errors interpolate the offending value, and the golden corpus
//! records ~40 of those messages verbatim:
//!
//! ```text
//! ports must be a mapping with 'tcp', 'udp', and/or 'icmp' keys (got: [80, 443])
//! ports.tcp.allow entries must be integers (got: '443')
//! ports.icmp.allow must be a boolean (got: 'yes-please')
//! ```
//!
//! The value is written as a literal, so a user can tell the string
//! `'443'` from the integer `443` at a glance:
//!
//! | value | [`display_value`] |
//! | :-- | :-- |
//! | `null` | `None` |
//! | `true` / `false` | `True` / `False` |
//! | integer | `9418` |
//! | fractional number | `1.5`, `1e+16`, `-0.0` |
//! | string | `'443'`, or `"it's"` when the text has a `'` and no `"` |
//! | sequence | `[80, 443]` (a space after each comma) |
//! | mapping | `{'a': 1, 'b': 'two'}` |
//!
//! The notation is Python's `repr()` (CPython's, including its
//! shortest-round-trip float spelling). That is not a choice made
//! here: these messages have read this way since the earliest releases,
//! users and scripts match on them, and the corpus holds the
//! implementation to them byte for byte. Rust's `Debug` would print
//! `true`, `"443"` and `[80,443]`, so it cannot be used.
//!
//! [`kind_name`] is the companion for messages that name the value's
//! kind rather than the value — `(got str)`, `(got NoneType)` — using
//! the same vocabulary.
//!
//! # Coercion
//!
//! [`coerce_to_string`] is the lenient half. A dozen fields accept any
//! scalar and use its text, so `memory: 512` becomes `"512"` and
//! `cpus: 2.5` becomes `"2.5"`. Accepting only YAML strings there would
//! reject configs that have always worked. Non-string values coerce to
//! their [`display_value`] text, so `true` becomes `"True"`.
//!
//! Every function here works over the value tree [`crate::yaml::load`]
//! produces: the six YAML core kinds plus the tagged nodes
//! `serde_norway` keeps.

use std::fmt::Write as _;

use crate::har::json::format_float;
use crate::yaml::Value;

/// The name of a value's kind, for the `(got X)` half of a message.
///
/// The counterpart of [`display_value`] for messages that name a kind
/// instead of a value; ~15 config and relay messages do, and the golden
/// corpus and the contract fixtures record every one of them. The
/// mapping is the fixture README's, verbatim:
///
/// | YAML / JSON | `kind_name` |
/// | :-- | :-- |
/// | `null` | `NoneType` |
/// | `true` / `false` | `bool` |
/// | integer | `int` |
/// | fractional number | `float` |
/// | string | `str` |
/// | sequence | `list` |
/// | mapping | `dict` |
///
/// A `Value::Tagged` names itself `object`. No tagged node survives
/// config loading, so none reaches a message.
#[must_use]
pub fn kind_name(value: &Value) -> &'static str {
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

/// A value written as a literal, per the table in the module docs.
///
/// A `Value::Tagged` renders as its tag. No tagged node survives config
/// loading, so none reaches a message.
#[must_use]
pub fn display_value(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Number(number) => number_text(number),
        Value::String(text) => quote_text(text),
        Value::Sequence(items) => {
            let rendered: Vec<String> = items.iter().map(display_value).collect();
            format!("[{}]", rendered.join(", "))
        }
        Value::Mapping(mapping) => {
            let rendered: Vec<String> = mapping
                .iter()
                .map(|(key, entry)| format!("{}: {}", display_value(key), display_value(entry)))
                .collect();
            format!("{{{}}}", rendered.join(", "))
        }
        Value::Tagged(tagged) => format!("{}", tagged.tag),
    }
}

/// A scalar's text, for a field that accepts any scalar as a string.
///
/// Identical to [`display_value`] except for strings, which come back
/// unquoted. Sequences and mappings are not special-cased: their text
/// is their [`display_value`].
#[must_use]
pub fn coerce_to_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => display_value(other),
    }
}

/// A string written as a quoted literal.
///
/// Single quotes by default, switching to double quotes only when the
/// text contains a `'` and no `"` — so `it's` renders as `"it's"`
/// rather than `'it\'s'`. Backslashes, `\n`, `\r`, `\t`, the chosen
/// quote and control characters are escaped.
///
/// Public because half of the call sites interpolate a field that is
/// already a `String` — `config.name`, a relay's host, an API key's
/// name — and wrapping each one in a [`Value`] only to unwrap it again
/// would be ceremony around the same few lines.
#[must_use]
pub fn quote_text(text: &str) -> String {
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
            // The convention escapes every non-printable code point.
            // `char::is_control` covers C0 and C1, which is the part any
            // agentcage value can plausibly contain; the wider Unicode
            // categories (format, separator, unassigned) would need a
            // Unicode table for no reachable gain, so they pass through.
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

/// An integer or a float, written as a literal.
///
/// `serde_norway` keeps the two apart, so an integer prints without a
/// decimal point and a float goes through the same shortest-round-trip
/// [`format_float`] the HAR and capture JSON use. `1.0` stays `1.0`,
/// not `1`.
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
    use super::{coerce_to_string, display_value};
    use crate::yaml::load;

    /// Every shape the corpus's messages actually carry.
    ///
    /// The right-hand column is the pinned spelling, which is also what
    /// CPython's `repr()` prints for the same loaded value.
    #[test]
    fn display_value_matches_the_pinned_shapes() {
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
            assert_eq!(display_value(&value["v"]), expected, "for {document}");
        }
    }

    /// The quote character depends on the text.
    #[test]
    fn quoting_picks_the_quote_by_content() {
        for (document, expected) in [
            ("v: \"it's\"", "\"it's\""),
            ("v: \"say \\\"hi\\\"\"", "'say \"hi\"'"),
            ("v: \"both ' and \\\"\"", "'both \\' and \"'"),
            ("v: \"line\\nbreak\"", "'line\\nbreak'"),
            ("v: \"back\\\\slash\"", "'back\\\\slash'"),
        ] {
            let value = load(document).expect("load");
            assert_eq!(display_value(&value["v"]), expected, "for {document}");
        }
    }

    /// Coercion differs from `display_value` only for strings.
    #[test]
    fn coercion_leaves_strings_unquoted() {
        let value = load("s: hello\nn: 512\nf: 2.5\nb: true\nl: [1]\n").expect("load");
        assert_eq!(coerce_to_string(&value["s"]), "hello");
        assert_eq!(coerce_to_string(&value["n"]), "512");
        assert_eq!(coerce_to_string(&value["f"]), "2.5");
        assert_eq!(coerce_to_string(&value["b"]), "True");
        assert_eq!(coerce_to_string(&value["l"]), "[1]");
    }
}
