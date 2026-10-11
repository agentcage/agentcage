//! The Python value semantics the Policy API's responses are made of.
//!
//! The control host answers a caged agent with text the replaced
//! implementation built from Python builtins applied to agent- and
//! model-supplied JSON: `str(payload.get("domain"))`, `{domain!r}`,
//! `int(args.get("ttl_seconds"))` and the exception messages `int()`
//! raises. Those strings are part of the recorded responses, so they are
//! reproduced here over [`Json`] rather than approximated with Rust's
//! formatting.

use std::fmt::Write as _;

use agentcage_core::config::domain::is_python_space;
use agentcage_core::yaml::Value;

use crate::json::{self, Json, format_float};

/// `str.strip()`.
pub(crate) fn strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

/// `text[:n]`, counted in code points as Python counts.
pub(crate) fn truncate_chars(text: &str, n: usize) -> String {
    match text.char_indices().nth(n) {
        Some((at, _)) => text[..at].to_owned(),
        None => text.to_owned(),
    }
}

/// `text.lower().rstrip(".")`: the normal form of a domain everywhere in
/// the Policy API.
pub(crate) fn normalise_domain(text: &str) -> String {
    text.to_lowercase().trim_end_matches('.').to_owned()
}

/// `repr(float)`: [`format_float`] except for the three values the JSON
/// writer spells differently.
fn float_repr(value: f64) -> String {
    if value.is_nan() {
        "nan".to_owned()
    } else if value.is_infinite() {
        if value > 0.0 { "inf" } else { "-inf" }.to_owned()
    } else {
        format_float(value)
    }
}

/// `repr(value)` for a value that came out of `json.loads`.
pub(crate) fn repr(value: &Json) -> String {
    match value {
        Json::Null => "None".to_owned(),
        Json::Bool(true) => "True".to_owned(),
        Json::Bool(false) => "False".to_owned(),
        Json::Int(i) => i.to_string(),
        Json::BigInt(digits) => digits.clone(),
        Json::Float(f) => float_repr(*f),
        Json::Str(s) => repr_str(s),
        Json::Array(items) => {
            let inner: Vec<String> = items.iter().map(repr).collect();
            format!("[{}]", inner.join(", "))
        }
        Json::Object(pairs) => {
            let inner: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{}: {}", repr_str(k), repr(v)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// `str(value)`: a string unquoted, everything else as its `repr`.
pub(crate) fn str_of(value: &Json) -> String {
    match value {
        Json::Str(s) => s.clone(),
        other => repr(other),
    }
}

/// `str(value or "")`, the coercion every field read applies.
pub(crate) fn str_or_empty(value: Option<&Json>) -> String {
    match value {
        Some(v) if v.is_truthy() => str_of(v),
        _ => String::new(),
    }
}

/// `repr(str)`, CPython's `unicode_repr`.
///
/// `agentcage_core::python::repr_str` covers the control characters a
/// config value can hold; this one faces the caged agent, which can send
/// any code point, so it also escapes the non-printable ones CPython
/// escapes beyond C0/C1: the non-space separators, the format characters
/// and private use. (Unassigned code points, which CPython also escapes,
/// would need a Unicode table; they pass through literally.)
pub(crate) fn repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if !is_printable(c) => {
                let code = c as u32;
                if code < 0x100 {
                    let _ = write!(out, "\\x{code:02x}");
                } else if code < 0x1_0000 {
                    let _ = write!(out, "\\u{code:04x}");
                } else {
                    let _ = write!(out, "\\U{code:08x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `str.isprintable()` for one character, minus unassigned code points.
fn is_printable(c: char) -> bool {
    let code = c as u32;
    !matches!(
        code,
        // Cc
        0x00..=0x1f | 0x7f..=0x9f
        // Zs other than the space itself, Zl, Zp
        | 0xa0 | 0x1680 | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000
        // Cf
        | 0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x890 | 0x891 | 0x8e2 | 0x180e
        | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f
        | 0xfeff | 0xfff9..=0xfffb | 0x110bd | 0x110cd | 0x13430..=0x1343f
        | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a | 0xe0001 | 0xe0020..=0xe007f
        // Co
        | 0xe000..=0xf8ff | 0xf_0000..=0xf_fffd | 0x10_0000..=0x10_fffd
        // Cn noncharacters
        | 0xfdd0..=0xfdef | 0xfffe | 0xffff
    )
}

/// `int(value or 0)`, saturated to `i64` (the callers only compare the
/// result against 0 and 86400), with `int()`'s own error text when
/// Python would raise.
pub(crate) fn int_or_zero(value: Option<&Json>) -> Result<i64, String> {
    let Some(value) = value.filter(|v| v.is_truthy()) else {
        return Ok(0);
    };
    match value {
        Json::Null | Json::Bool(false) => Ok(0),
        Json::Bool(true) => Ok(1),
        Json::Int(i) => Ok(*i),
        Json::BigInt(digits) => Ok(if digits.starts_with('-') {
            i64::MIN
        } else {
            i64::MAX
        }),
        Json::Float(f) => {
            if f.is_nan() {
                Err("cannot convert float NaN to integer".to_owned())
            } else if f.is_infinite() {
                Err("cannot convert float infinity to integer".to_owned())
            } else {
                // `as` saturates, which is the contract above.
                #[allow(clippy::cast_possible_truncation)]
                Ok(f.trunc() as i64)
            }
        }
        Json::Str(s) => int_literal(s)
            .ok_or_else(|| format!("invalid literal for int() with base 10: {}", repr_str(s))),
        Json::Array(_) => Err(not_a_number("list")),
        Json::Object(_) => Err(not_a_number("dict")),
    }
}

fn not_a_number(type_name: &str) -> String {
    format!(
        "int() argument must be a string, a bytes-like object or a real number, not '{type_name}'"
    )
}

/// `int(text)` in base 10: surrounding whitespace, an optional sign, and
/// ASCII digits with single underscores between them. Saturated.
pub(crate) fn int_literal(text: &str) -> Option<i64> {
    let body = strip(text);
    let (negative, digits) = match body.as_bytes().first()? {
        b'-' => (true, &body[1..]),
        b'+' => (false, &body[1..]),
        _ => (false, body),
    };
    let bytes = digits.as_bytes();
    if bytes.is_empty() || bytes[0] == b'_' || bytes[bytes.len() - 1] == b'_' {
        return None;
    }
    let mut value: i64 = 0;
    let mut previous_underscore = false;
    for &b in bytes {
        if b == b'_' {
            if previous_underscore {
                return None;
            }
            previous_underscore = true;
            continue;
        }
        previous_underscore = false;
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.saturating_mul(10).saturating_add(i64::from(b - b'0'));
    }
    Some(if negative { -value } else { value })
}

/// `json.loads(body)` on request bytes: the encoding detection
/// `json.detect_encoding` does (UTF-8, UTF-16 and UTF-32, with or without
/// a BOM), then the parse. `None` wherever Python raised.
pub(crate) fn loads_bytes(body: &[u8]) -> Option<Json> {
    let text = decode_json_bytes(body)?;
    json::parse(&text).ok()
}

fn decode_json_bytes(b: &[u8]) -> Option<String> {
    let starts = |prefix: &[u8]| b.starts_with(prefix);
    if starts(&[0x00, 0x00, 0xfe, 0xff]) {
        return utf32(&b[4..], true);
    }
    if starts(&[0xff, 0xfe, 0x00, 0x00]) {
        return utf32(&b[4..], false);
    }
    if starts(&[0xfe, 0xff]) {
        return utf16(&b[2..], true);
    }
    if starts(&[0xff, 0xfe]) {
        return utf16(&b[2..], false);
    }
    if starts(&[0xef, 0xbb, 0xbf]) {
        return String::from_utf8(b[3..].to_vec()).ok();
    }
    if b.len() >= 4 {
        if b[0] == 0 {
            return if b[1] == 0 {
                utf32(b, true)
            } else {
                utf16(b, true)
            };
        }
        if b[1] == 0 {
            return if b[2] != 0 || b[3] != 0 {
                utf16(b, false)
            } else {
                utf32(b, false)
            };
        }
    } else if b.len() == 2 {
        if b[0] == 0 {
            return utf16(b, true);
        }
        if b[1] == 0 {
            return utf16(b, false);
        }
    }
    String::from_utf8(b.to_vec()).ok()
}

fn utf16(b: &[u8], big_endian: bool) -> Option<String> {
    if b.len() % 2 != 0 {
        return None;
    }
    let units = b.chunks_exact(2).map(|c| {
        if big_endian {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from_le_bytes([c[0], c[1]])
        }
    });
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()
}

fn utf32(b: &[u8], big_endian: bool) -> Option<String> {
    if b.len() % 4 != 0 {
        return None;
    }
    b.chunks_exact(4)
        .map(|c| {
            let code = if big_endian {
                u32::from_be_bytes([c[0], c[1], c[2], c[3]])
            } else {
                u32::from_le_bytes([c[0], c[1], c[2], c[3]])
            };
            char::from_u32(code)
        })
        .collect()
}

/// A YAML value from the grants overlay as `json.dumps` would render the
/// Python object `yaml.safe_load` made of it. Non-string mapping keys
/// become strings the way `json.dumps` coerces them.
pub(crate) fn yaml_to_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Json::Int(i)
            } else if let Some(u) = n.as_u64() {
                Json::BigInt(u.to_string())
            } else {
                Json::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(s) => Json::Str(s.clone()),
        Value::Sequence(items) => Json::Array(items.iter().map(yaml_to_json).collect()),
        Value::Mapping(map) => Json::Object(
            map.iter()
                .map(|(k, v)| (json_key(k), yaml_to_json(v)))
                .collect(),
        ),
        Value::Tagged(tagged) => yaml_to_json(&tagged.value),
    }
}

fn json_key(key: &Value) -> String {
    match key {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_owned(),
        Value::Bool(true) => "true".to_owned(),
        Value::Bool(false) => "false".to_owned(),
        other => agentcage_core::python::str_of(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repr_matches_cpython() {
        // Right-hand sides measured with CPython 3.12.
        assert_eq!(repr_str("x.com\n"), "'x.com\\n'");
        assert_eq!(repr_str("it's"), "\"it's\"");
        assert_eq!(repr_str("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(repr_str("a\u{a0}b"), "'a\\xa0b'");
        assert_eq!(repr_str("\u{200b}\u{2028}é☃"), "'\\u200b\\u2028é☃'");
        assert_eq!(repr_str("\u{e0001}"), "'\\U000e0001'");
        assert_eq!(repr_str("\x00\x7f"), "'\\x00\\x7f'");
        let v = json::parse(r#"{"why": [1, 2.5, null, true, "s", 1e300, -0.0]}"#).unwrap();
        assert_eq!(repr(&v), "{'why': [1, 2.5, None, True, 's', 1e+300, -0.0]}");
    }

    #[test]
    fn int_matches_cpython() {
        let j = |t: &str| json::parse(t).unwrap();
        assert_eq!(int_or_zero(None), Ok(0));
        assert_eq!(int_or_zero(Some(&j("null"))), Ok(0));
        assert_eq!(int_or_zero(Some(&j("\"\""))), Ok(0));
        assert_eq!(int_or_zero(Some(&j("true"))), Ok(1));
        assert_eq!(int_or_zero(Some(&j("1.9"))), Ok(1));
        assert_eq!(int_or_zero(Some(&j("-0.5"))), Ok(0));
        assert_eq!(int_or_zero(Some(&j("\" 1_0 \""))), Ok(10));
        assert_eq!(int_or_zero(Some(&j("\"-3\""))), Ok(-3));
        assert_eq!(
            int_or_zero(Some(&j("1000000000000000000000000000000"))),
            Ok(i64::MAX)
        );
        assert_eq!(
            int_or_zero(Some(&j("\"1.5\""))),
            Err("invalid literal for int() with base 10: '1.5'".to_owned())
        );
        assert!(int_or_zero(Some(&j("\"1__0\""))).is_err());
        assert!(int_or_zero(Some(&j("\"_1\""))).is_err());
        assert_eq!(int_or_zero(Some(&j("[1]"))), Err(not_a_number("list")));
        assert_eq!(
            int_or_zero(Some(&j("Infinity"))),
            Err("cannot convert float infinity to integer".to_owned())
        );
    }

    #[test]
    fn json_bytes_detect_their_encoding() {
        assert!(loads_bytes(b"{\"a\": 1}").is_some());
        assert!(loads_bytes(b"\xef\xbb\xbf{\"a\": 1}").is_some());
        let utf16le: Vec<u8> = "{\"a\": 1}"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(loads_bytes(&utf16le).is_some());
        let mut bom16be = vec![0xfe, 0xff];
        bom16be.extend("[1]".encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(loads_bytes(&bom16be), Some(Json::Array(vec![Json::Int(1)])));
        let wide: Vec<u8> = "[2]"
            .chars()
            .flat_map(|c| (c as u32).to_be_bytes())
            .collect();
        assert_eq!(loads_bytes(&wide), Some(Json::Array(vec![Json::Int(2)])));
        assert!(loads_bytes(b"\xff\xfe{").is_none());
        assert!(loads_bytes(b"{not json").is_none());
    }
}
