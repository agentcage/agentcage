//! JSON spelled the way `json.dumps` spells it with default arguments.
//!
//! `{"tool": "decide", "domain": "example.net"}`: a space after every `:`
//! and `,`, and every non-ASCII character escaped as `\uXXXX` (lowercase
//! hex, surrogate pairs above the BMP). The phase scripts grep the mocks'
//! logs for fixed substrings such as `"tool": "decide"`, so the spacing is
//! part of the contract.
//!
//! Keys come out in the order the value serializes them: declaration
//! order for the derived structs the mocks answer with, sorted for a
//! `serde_json::Map`.

use std::io;

use serde::Serialize;
use serde_json::ser::Formatter;

/// Serialize `value` in `json.dumps` form.
///
/// # Panics
/// When `value`'s `Serialize` impl fails, which the mocks' plain structs
/// and `serde_json::Value`s never do; and never for the output, which the
/// formatter keeps ASCII.
#[must_use]
pub fn dumps<T: Serialize + ?Sized>(value: &T) -> String {
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut out, PyFormatter);
    value
        .serialize(&mut ser)
        .expect("serializing a Value into memory cannot fail");
    String::from_utf8(out).expect("the formatter writes ASCII only")
}

struct PyFormatter;

impl Formatter for PyFormatter {
    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        writer.write_all(b": ")
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        // serde_json has already escaped quotes, backslashes and control
        // characters exactly as json.dumps does; what is left is
        // ensure_ascii.
        let mut units = [0u16; 2];
        for ch in fragment.chars() {
            if ch.is_ascii() {
                writer.write_all(&[ch as u8])?;
            } else {
                for unit in ch.encode_utf16(&mut units) {
                    write!(writer, "\\u{unit:04x}")?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::dumps;
    use serde::Serialize;
    use serde_json::json;

    #[derive(Serialize)]
    struct Ordered {
        to: Vec<&'static str>,
        n: u32,
        e: Vec<u32>,
        o: serde_json::Value,
    }

    #[test]
    fn spacing_order_and_escapes_match_json_dumps() {
        // Expected strings are what CPython's json.dumps prints.
        assert_eq!(
            dumps(&Ordered {
                to: vec!["<a>", "<b>"],
                n: 1,
                e: vec![],
                o: json!({}),
            }),
            r#"{"to": ["<a>", "<b>"], "n": 1, "e": [], "o": {}}"#
        );
        // A Map's keys come out sorted.
        assert_eq!(
            dumps(&json!({"b": true, "a": null})),
            r#"{"a": null, "b": true}"#
        );
        assert_eq!(
            dumps(&json!({"s": "caf\u{e9} \u{1F600} \"q\" \\ \n\t\u{1}\u{7f}"})),
            // `|` stands for a backslash before each `u` escape.
            r#"{"s": "caf|u00e9 |ud83d|ude00 \"q\" \\ \n\t|u0001"#
                .replace('|', &char::from(0x5c).to_string())
                + "\u{7f}\"}"
        );
    }
}
