//! A JSON value with Python's `dict` semantics, and a `json.dumps` clone.
//!
//! # Why this is not `serde_json`
//!
//! `har.py` reaches `json.dumps` twice, and both calls are byte-sensitive:
//!
//! * `cli.py`'s `cage har` prints `json.dumps(har, indent=2)` — Python
//!   dict order, `ensure_ascii=True`, two-space indent.
//! * `har.py` itself embeds `json.dumps(metadata)` as each entry's
//!   `comment` *string*, so that text is part of the HAR document. The
//!   metadata carries the capture entry's own `inspectors` list, copied
//!   straight out of the capture JSONL, so the key order of objects
//!   *read from the input* survives into the output. The golden corpus
//!   pins it: `{"name": …, "severity": …, "reason": …}` is the fixture's
//!   order, not sorted order.
//!
//! `serde_json::Value` sorts object keys — it is a `BTreeMap` — unless
//! the `preserve_order` feature is enabled, and Cargo unifies features
//! across the workspace: enabling it here would silently reorder every
//! other crate's `Value`, including the audit and fingerprint ports
//! landing alongside this one. A local value type keeps that choice from
//! leaking and keeps `agentcage-core`'s dependency list empty.
//!
//! # What "Python-shaped" means here
//!
//! | `json` module | this module |
//! | :-- | :-- |
//! | insertion-ordered `dict` | [`Json::Object`] is a `Vec` of pairs |
//! | `ensure_ascii=True` (the default) | [`DumpOptions::ensure_ascii`] |
//! | `sort_keys=True` | [`DumpOptions::sort_keys`] |
//! | `indent=2` | [`DumpOptions::indent`] |
//! | `repr()` floats (`1e+16`, `-0.0`) | [`format_float`] |
//! | `NaN` / `Infinity` (accepted by default) | parsed and emitted |
//! | arbitrary-precision `int` | [`Json::BigInt`] keeps the digits |

use std::fmt;
use std::fmt::Write as _;

/// A parsed JSON value, ordered the way Python's `json.loads` orders one.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    /// `null`, Python's `None`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer that fits in an `i64`.
    Int(i64),
    /// An integer that does not. Python's `int` is unbounded, so the
    /// literal digits are kept verbatim and re-emitted unchanged rather
    /// than being rounded into an `f64` — `json.loads` would not round
    /// them either.
    BigInt(String),
    /// A float, including the `NaN` and infinities Python's `json`
    /// accepts and emits by default.
    Float(f64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Json>),
    /// An object, in insertion order. Python's `dict` keeps the position
    /// of a key's *first* appearance and the value of its last, and so
    /// does [`Json::set`].
    Object(Vec<(String, Json)>),
}

impl Json {
    /// A string value, for callers that have something `Into<String>`.
    pub fn string<S: Into<String>>(value: S) -> Self {
        Self::Str(value.into())
    }

    /// The value for `key`, or `None` — Python's `dict.get`, and `None`
    /// for anything that is not an object, where Python would raise.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Set `key`, Python-style: an existing key keeps its position and
    /// takes the new value; a new key goes on the end. No-op on a
    /// non-object.
    pub fn set<S: Into<String>>(&mut self, key: S, value: Self) {
        if let Self::Object(pairs) = self {
            let key = key.into();
            if let Some(slot) = pairs.iter_mut().find(|(k, _)| *k == key) {
                slot.1 = value;
            } else {
                pairs.push((key, value));
            }
        }
    }

    /// The string inside, if this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Python truthiness: empty containers and strings, zero numbers,
    /// `False` and `None` are false; everything else is true.
    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(b) => *b,
            Self::Int(i) => *i != 0,
            // A `BigInt` only exists because it overflowed an i64, so it
            // cannot be zero.
            Self::BigInt(_) => true,
            Self::Float(f) => *f != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::Array(items) => !items.is_empty(),
            Self::Object(pairs) => !pairs.is_empty(),
        }
    }
}

// ── Parsing ──────────────────────────────────────────────────

/// Why a document would not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// What went wrong.
    pub message: String,
    /// The byte offset it went wrong at.
    pub position: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at position {}", self.message, self.position)
    }
}

impl std::error::Error for ParseError {}

/// Parse one JSON document, the way `json.loads` does.
///
/// Like `json.loads` this accepts the non-standard `NaN`, `Infinity` and
/// `-Infinity` literals, rejects control characters inside strings
/// (`strict=True` is the default), and allows surrounding whitespace.
///
/// # Errors
///
/// Returns [`ParseError`] for anything `json.loads` would raise
/// `JSONDecodeError` on.
pub fn parse(text: &str) -> Result<Json, ParseError> {
    let mut p = Parser { src: text, pos: 0 };
    p.skip_whitespace();
    let value = p.parse_value()?;
    p.skip_whitespace();
    if p.pos != text.len() {
        return Err(p.err("Extra data"));
    }
    Ok(value)
}

struct Parser<'a> {
    src: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn err(&self, message: &str) -> ParseError {
        ParseError {
            message: message.to_string(),
            position: self.pos,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.as_bytes().get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, literal: &str) -> bool {
        if self.src[self.pos..].starts_with(literal) {
            self.pos += literal.len();
            true
        } else {
            false
        }
    }

    fn parse_value(&mut self) -> Result<Json, ParseError> {
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::Str(self.parse_string()?)),
            Some(b't') if self.eat("true") => Ok(Json::Bool(true)),
            Some(b'f') if self.eat("false") => Ok(Json::Bool(false)),
            Some(b'n') if self.eat("null") => Ok(Json::Null),
            Some(b'N') if self.eat("NaN") => Ok(Json::Float(f64::NAN)),
            Some(b'I') if self.eat("Infinity") => Ok(Json::Float(f64::INFINITY)),
            Some(b'-') if self.src[self.pos..].starts_with("-Infinity") => {
                self.pos += "-Infinity".len();
                Ok(Json::Float(f64::NEG_INFINITY))
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
            _ => Err(self.err("Expecting value")),
        }
    }

    fn parse_object(&mut self) -> Result<Json, ParseError> {
        self.pos += 1; // '{'
        let mut value = Json::Object(Vec::new());
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(value);
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.err("Expecting property name enclosed in double quotes"));
            }
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Err(self.err("Expecting ':' delimiter"));
            }
            self.pos += 1;
            self.skip_whitespace();
            let item = self.parse_value()?;
            value.set(key, item);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(value);
                }
                _ => return Err(self.err("Expecting ',' delimiter")),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Json, ParseError> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.err("Expecting ',' delimiter")),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.pos += 1; // '"'
        let mut out = String::new();
        loop {
            let rest = &self.src[self.pos..];
            // `"` and `\` are ASCII, so they never appear inside a
            // multi-byte sequence and this scan cannot split a character.
            let stop = rest
                .bytes()
                .position(|b| b == b'"' || b == b'\\' || b < 0x20)
                .ok_or_else(|| self.err("Unterminated string starting at"))?;
            out.push_str(&rest[..stop]);
            self.pos += stop;
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    self.parse_escape(&mut out)?;
                }
                // `json.loads(strict=True)`, which is the default.
                _ => return Err(self.err("Invalid control character at")),
            }
        }
    }

    fn parse_escape(&mut self, out: &mut String) -> Result<(), ParseError> {
        let escape = self.peek().ok_or_else(|| self.err("Unterminated string"))?;
        self.pos += 1;
        let simple = match escape {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.parse_unicode_escape(out),
            _ => return Err(self.err("Invalid \\escape")),
        };
        out.push(simple);
        Ok(())
    }

    fn parse_unicode_escape(&mut self, out: &mut String) -> Result<(), ParseError> {
        let first = self.parse_hex4()?;
        // A high surrogate takes its pair with it, as `json.loads` does.
        if (0xd800..0xdc00).contains(&first) && self.src[self.pos..].starts_with("\\u") {
            let mark = self.pos;
            self.pos += 2;
            let second = self.parse_hex4()?;
            if (0xdc00..0xe000).contains(&second) {
                let combined = 0x1_0000 + ((first - 0xd800) << 10) + (second - 0xdc00);
                out.push(char::from_u32(combined).unwrap_or(char::REPLACEMENT_CHARACTER));
                return Ok(());
            }
            self.pos = mark;
        }
        // Python can hold a lone surrogate in a `str` and Rust cannot, so
        // an unpaired one becomes U+FFFD. `capture.jsonl` is written by
        // `json.dumps`, which never emits one.
        out.push(char::from_u32(first).unwrap_or(char::REPLACEMENT_CHARACTER));
        Ok(())
    }

    fn parse_hex4(&mut self) -> Result<u32, ParseError> {
        let digits = self
            .src
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.err("Invalid \\uXXXX escape"))?;
        let value =
            u32::from_str_radix(digits, 16).map_err(|_| self.err("Invalid \\uXXXX escape"))?;
        self.pos += 4;
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Json, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        // `json`'s number grammar is `-?(?:0|[1-9]\d*)`, so a leading
        // zero ends the integer part and whatever follows it becomes
        // trailing garbage: `json.loads("01")` is an "Extra data" error,
        // not 1.
        if self.peek() == Some(b'0') {
            self.pos += 1;
        } else if self.skip_digits() == 0 {
            return Err(self.err("Expecting value"));
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if self.skip_digits() == 0 {
                return Err(self.err("Expecting value"));
            }
            is_float = true;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if self.skip_digits() == 0 {
                return Err(self.err("Expecting value"));
            }
            is_float = true;
        }
        let text = &self.src[start..self.pos];
        if is_float {
            return text
                .parse::<f64>()
                .map(Json::Float)
                .map_err(|_| self.err("Expecting value"));
        }
        Ok(text
            .parse::<i64>()
            .map_or_else(|_| Json::BigInt(text.to_string()), Json::Int))
    }

    fn skip_digits(&mut self) -> usize {
        let start = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        self.pos - start
    }
}

// ── Serializing ──────────────────────────────────────────────

/// The `json.dumps` keyword arguments this port needs, with Python's
/// defaults.
#[derive(Clone, Copy, Debug)]
pub struct DumpOptions {
    /// `indent`: `None` for the one-line form, `Some(n)` for `n` spaces
    /// per level. Python drops the trailing space from the item
    /// separator when an indent is set, so the one-line form separates
    /// with `", "` and the indented form with `","` plus a newline.
    pub indent: Option<usize>,
    /// `sort_keys`: emit object keys in code-point order instead of
    /// insertion order.
    pub sort_keys: bool,
    /// `ensure_ascii`: escape every non-ASCII character as `\uXXXX`.
    /// True is Python's default, and what `cage har` and the `comment`
    /// string both get.
    pub ensure_ascii: bool,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self {
            indent: None,
            sort_keys: false,
            ensure_ascii: true,
        }
    }
}

impl DumpOptions {
    /// `json.dumps(value, indent=2)` — what `cli.py` writes a HAR with.
    #[must_use]
    pub fn indented() -> Self {
        Self {
            indent: Some(2),
            ..Self::default()
        }
    }
}

/// Render `value` as `json.dumps` would.
#[must_use]
pub fn dumps(value: &Json, options: DumpOptions) -> String {
    let mut out = String::new();
    write_value(&mut out, value, options, 0);
    out
}

fn write_value(out: &mut String, value: &Json, options: DumpOptions, depth: usize) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Int(i) => out.push_str(&i.to_string()),
        Json::BigInt(digits) => out.push_str(digits),
        Json::Float(f) => out.push_str(&format_float(*f)),
        Json::Str(s) => write_string(out, s, options.ensure_ascii),
        Json::Array(items) => write_array(out, items, options, depth),
        Json::Object(pairs) => write_object(out, pairs, options, depth),
    }
}

/// Python emits `[]` and `{}` for empty containers even under `indent`,
/// so the newline and the indent only appear once there is an item.
fn write_array(out: &mut String, items: &[Json], options: DumpOptions, depth: usize) {
    if items.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_separator(out, options, depth + 1, i > 0);
        write_value(out, item, options, depth + 1);
    }
    write_separator(out, options, depth, false);
    out.push(']');
}

fn write_object(out: &mut String, pairs: &[(String, Json)], options: DumpOptions, depth: usize) {
    if pairs.is_empty() {
        out.push_str("{}");
        return;
    }
    let mut order: Vec<&(String, Json)> = pairs.iter().collect();
    if options.sort_keys {
        // Python compares `str` by code point; Rust compares `String` by
        // UTF-8 bytes, and for valid UTF-8 those orders agree.
        order.sort_by(|a, b| a.0.cmp(&b.0));
    }
    out.push('{');
    for (i, (key, item)) in order.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_separator(out, options, depth + 1, i > 0);
        write_string(out, key, options.ensure_ascii);
        out.push_str(": ");
        write_value(out, item, options, depth + 1);
    }
    write_separator(out, options, depth, false);
    out.push('}');
}

/// The whitespace between two items, or before a closing bracket.
fn write_separator(out: &mut String, options: DumpOptions, depth: usize, after_comma: bool) {
    match options.indent {
        Some(width) => {
            out.push('\n');
            for _ in 0..width * depth {
                out.push(' ');
            }
        }
        None if after_comma => out.push(' '),
        None => {}
    }
}

fn write_string(out: &mut String, value: &str, ensure_ascii: bool) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => push_hex_escape(out, c as u32),
            // `ensure_ascii` escapes everything outside `[ -~]`, which
            // includes DEL, and splits astral characters into a
            // surrogate pair.
            c if ensure_ascii && (c as u32) > 0x7e => push_escaped_ascii(out, c),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_escaped_ascii(out: &mut String, ch: char) {
    let code = ch as u32;
    if let Some(offset) = code.checked_sub(0x1_0000) {
        push_hex_escape(out, 0xd800 + (offset >> 10));
        push_hex_escape(out, 0xdc00 + (offset & 0x3ff));
    } else {
        push_hex_escape(out, code);
    }
}

fn push_hex_escape(out: &mut String, code: u32) {
    let _ = write!(out, "\\u{code:04x}");
}

/// Format a float the way Python's `repr` — and so `json.dumps` — does.
///
/// Both languages print the shortest decimal that round-trips, so the
/// digits always agree; the layout does not. Python switches to
/// exponent notation when the decimal point sits at or below -4 or above
/// 16, writes the exponent with a sign and at least two digits
/// (`1e+16`, `1e-05`), and keeps a `.0` on a float with no fraction.
/// Rust's `Display` never uses an exponent and Rust's `LowerExp` always
/// does, so neither is usable directly — but `LowerExp` hands over
/// exactly the shortest digits and decimal exponent to rebuild from.
#[must_use]
pub fn format_float(value: f64) -> String {
    // `json.dumps` emits these three by default; `allow_nan=False` is
    // what turns them into an error, and nothing here passes it.
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    if value == 0.0 {
        return format!("{sign}0.0");
    }

    // `LowerExp` always writes `<digits>e<exponent>`; the fallbacks are
    // there so this function is total rather than because it can happen.
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exponent: i32 = exponent.parse().unwrap_or(0);
    // Where the decimal point falls, counting from the left of `digits`.
    let point = exponent + 1;

    let length = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    if point <= -4 || point > 16 {
        let fraction = &digits[1..];
        let dot = if fraction.is_empty() {
            String::new()
        } else {
            format!(".{fraction}")
        };
        let exponent_sign = if exponent < 0 { '-' } else { '+' };
        return format!(
            "{sign}{}{dot}e{exponent_sign}{:02}",
            &digits[..1],
            exponent.abs()
        );
    }
    if point <= 0 {
        let zeros = "0".repeat(point.unsigned_abs() as usize);
        return format!("{sign}0.{zeros}{digits}");
    }
    if point >= length {
        let zeros = "0".repeat((point - length).unsigned_abs() as usize);
        return format!("{sign}{digits}{zeros}.0");
    }
    let split = point.unsigned_abs() as usize;
    format!("{sign}{}.{}", &digits[..split], &digits[split..])
}

#[cfg(test)]
mod tests {
    use super::{DumpOptions, Json, dumps, format_float, parse};

    /// Every expectation here is `json.dumps` output, read off `CPython`.
    #[test]
    fn floats_render_the_way_python_repr_does() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (2.5, "2.5"),
            (-2.5, "-2.5"),
            (100.0, "100.0"),
            (1234.5, "1234.5"),
            (0.1, "0.1"),
            (1.0 / 3.0, "0.3333333333333333"),
            (123_456_789_012_345.6, "123456789012345.6"),
            // The exponent threshold, from both sides.
            (1e15, "1000000000000000.0"),
            (9_007_199_254_740_993.0, "9007199254740992.0"),
            (1e16, "1e+16"),
            (1e17, "1e+17"),
            (1e-4, "0.0001"),
            (1e-5, "1e-05"),
            (1e-7, "1e-07"),
            (-1e-7, "-1e-07"),
            (1e300, "1e+300"),
            (5e-324, "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
            (f64::INFINITY, "Infinity"),
            (f64::NEG_INFINITY, "-Infinity"),
        ];
        for (value, expected) in cases {
            assert_eq!(format_float(*value), *expected, "formatting {value}");
        }
        assert_eq!(format_float(f64::NAN), "NaN");
    }

    #[test]
    fn strings_escape_the_way_python_does() {
        let ascii = DumpOptions::default();
        let raw = DumpOptions {
            ensure_ascii: false,
            ..DumpOptions::default()
        };
        let cases: &[(&str, &str, &str)] = &[
            ("héllo", "\"h\\u00e9llo\"", "\"héllo\""),
            ("日本", "\"\\u65e5\\u672c\"", "\"日本\""),
            // Astral characters become a surrogate pair.
            ("😀", "\"\\ud83d\\ude00\"", "\"😀\""),
            // DEL is outside `[ -~]`, so `ensure_ascii` escapes it.
            ("a\u{7f}b", "\"a\\u007fb\"", "\"a\u{7f}b\""),
            ("tab\tnl\n", "\"tab\\tnl\\n\"", "\"tab\\tnl\\n\""),
            ("\u{1}", "\"\\u0001\"", "\"\\u0001\""),
            ("q\"\\", "\"q\\\"\\\\\"", "\"q\\\"\\\\\""),
            // U+2028 is not special to `json`: raw when `ensure_ascii`
            // is off, `\uXXXX` when it is on, like any other non-ASCII.
            ("\u{2028}", "\"\\u2028\"", "\"\u{2028}\""),
        ];
        for (value, escaped, raw_expected) in cases {
            let value = Json::string(*value);
            assert_eq!(dumps(&value, ascii), *escaped);
            assert_eq!(dumps(&value, raw), *raw_expected);
        }
    }

    #[test]
    fn objects_keep_insertion_order_until_asked_to_sort() {
        let value = parse(r#"{"b": 1, "a": 2, "c": 3}"#).unwrap();
        assert_eq!(
            dumps(&value, DumpOptions::default()),
            r#"{"b": 1, "a": 2, "c": 3}"#
        );
        let sorted = DumpOptions {
            sort_keys: true,
            ..DumpOptions::default()
        };
        assert_eq!(dumps(&value, sorted), r#"{"a": 2, "b": 1, "c": 3}"#);
    }

    /// Python keeps a repeated key where it first appeared and gives it
    /// the last value.
    #[test]
    fn a_repeated_key_keeps_its_position() {
        let value = parse(r#"{"a": 1, "b": 2, "a": 3}"#).unwrap();
        assert_eq!(dumps(&value, DumpOptions::default()), r#"{"a": 3, "b": 2}"#);
    }

    /// `json.dumps({"a": {}, "b": []}, indent=2)` puts nothing inside an
    /// empty container — no newline, no indent.
    #[test]
    fn indent_leaves_empty_containers_flat() {
        let value = parse(r#"{"a": {}, "b": [], "c": [1]}"#).unwrap();
        assert_eq!(
            dumps(&value, DumpOptions::indented()),
            "{\n  \"a\": {},\n  \"b\": [],\n  \"c\": [\n    1\n  ]\n}"
        );
    }

    #[test]
    fn numbers_survive_the_round_trip() {
        // Python's `int` is unbounded and `json.loads` keeps every digit.
        let big = "123456789012345678901234567890";
        assert_eq!(dumps(&parse(big).unwrap(), DumpOptions::default()), big);
        assert_eq!(parse("-0").unwrap(), Json::Int(0));
        assert_eq!(parse("-0.0").unwrap(), Json::Float(-0.0));
        assert_eq!(
            dumps(&parse("-0.0").unwrap(), DumpOptions::default()),
            "-0.0"
        );
        assert_eq!(parse("1e2").unwrap(), Json::Float(100.0));
        // `json.loads` accepts these three by default.
        assert_eq!(parse("Infinity").unwrap(), Json::Float(f64::INFINITY));
        assert_eq!(parse("-Infinity").unwrap(), Json::Float(f64::NEG_INFINITY));
        assert!(matches!(parse("NaN").unwrap(), Json::Float(f) if f.is_nan()));
    }

    #[test]
    fn escapes_and_malformed_documents() {
        assert_eq!(parse(r#""A😀""#).unwrap(), Json::string("A😀"));
        assert!(parse(r#"  {"a": [1, 2]}  "#).unwrap().get("a").is_some());
        for bad in [
            "",
            "{",
            "{\"a\"}",
            "[1,]",
            "{\"a\": 1} trailing",
            "\"unterminated",
            "\"raw\u{1}control\"",
            "01",
            "1.",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn truthiness_follows_python() {
        for falsy in [
            Json::Null,
            Json::Bool(false),
            Json::Int(0),
            Json::Float(0.0),
            Json::Float(-0.0),
            Json::string(""),
            Json::Array(Vec::new()),
            Json::Object(Vec::new()),
        ] {
            assert!(!falsy.is_truthy(), "{falsy:?} should be falsy");
        }
        for truthy in [Json::Bool(true), Json::Int(-1), Json::string("0")] {
            assert!(truthy.is_truthy(), "{truthy:?} should be truthy");
        }
    }
}
