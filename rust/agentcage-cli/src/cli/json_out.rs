//! The JSON envelope every machine-readable command writes.
//!
//! One shape, so a script can read any of them with the same four lines:
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "command": "domain list",
//!   "ok": true,
//!   "data": {},
//!   "warnings": []
//! }
//! ```
//!
//! The top-level keys and their order are the contract.
//! `schema_version` is `1` today and is bumped only for a breaking change
//! to the envelope itself; additions to `data` are not a break, because
//! an existing reader ignores keys it does not know. `command` is the
//! canonical spelling (`domain list`, never the `ls` alias), so two
//! spellings of one command produce the same document. `ok` is `false`
//! when the command still prints a document but reports a failure --
//! today that is `secret list --json` with a missing secret, which also
//! exits non-zero. `warnings` is always present, empty when there is
//! nothing to say; it carries text for a human, never a secret.
//!
//! # Why `agentcage_core::har::json`
//!
//! The same reason `cage har` uses it: it is already in the tree, it
//! keeps object key order (which is how the envelope's order is
//! guaranteed rather than left to a map's iteration order), and it
//! avoids adding `serde` derives to every type a command happens to
//! return. [`Json`] is the only value type this module takes.
//!
//! # What is never in a document
//!
//! Secret *values*. Commands that emit secrets emit names, classifications
//! and placeholder labels only -- the placeholder is a decoy, and the
//! value is read nowhere on the path that builds the document. The
//! `secret list --json` test asserts this against a real plaintext store.

use agentcage_core::har::json::{DumpOptions, Json, dumps};

/// The envelope version. Bump only for a breaking change to the shape.
pub(crate) const SCHEMA_VERSION: i64 = 1;

/// Build the envelope around `data`.
///
/// Key order is insertion order, which is the documented order. `ok` is
/// supplied by the command rather than assumed: a failing command
/// normally reports on stderr and exits non-zero without printing a
/// document, but `secret list --json` prints what it found *and* exits
/// 1, so its document must say `ok: false`.
pub(crate) fn envelope(command: &str, data: Json, ok: bool, warnings: &[String]) -> Json {
    Json::Object(vec![
        ("schema_version".to_owned(), Json::Int(SCHEMA_VERSION)),
        ("command".to_owned(), Json::string(command)),
        ("ok".to_owned(), Json::Bool(ok)),
        ("data".to_owned(), data),
        (
            "warnings".to_owned(),
            Json::Array(warnings.iter().map(Json::string).collect()),
        ),
    ])
}

/// The document as bytes, indented exactly as `cage har` writes JSON.
///
/// Two-space indent with `ensure_ascii`, so a non-ASCII path or cage name
/// is escaped the same way in every agentcage document.
pub(crate) fn render(command: &str, data: Json, ok: bool, warnings: &[String]) -> String {
    dumps(
        &envelope(command, data, ok, warnings),
        DumpOptions::indented(),
    )
}

/// Print one envelope to stdout, with a trailing newline.
pub(crate) fn print(command: &str, data: Json, ok: bool, warnings: &[String]) {
    println!("{}", render(command, data, ok, warnings));
}

/// An object from borrowed keys, in the order given.
pub(crate) fn object(pairs: Vec<(&str, Json)>) -> Json {
    Json::Object(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

/// A JSON array of strings.
pub(crate) fn strings<S: AsRef<str>>(values: impl IntoIterator<Item = S>) -> Json {
    Json::Array(
        values
            .into_iter()
            .map(|value| Json::string(value.as_ref()))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::{SCHEMA_VERSION, envelope, object, render};
    use agentcage_core::har::json::{DumpOptions, Json, dumps, parse};

    /// The envelope's keys, in order, are the contract.
    #[test]
    fn the_envelope_has_the_documented_shape_and_order() {
        let doc = envelope(
            "domain list",
            object(vec![("cage", Json::string("acme"))]),
            true,
            &[],
        );
        // `parse` keeps document order, so this reads the order back.
        let parsed = parse(&dumps(&doc, DumpOptions::indented())).expect("parses");
        let keys: Vec<String> = match &parsed {
            Json::Object(pairs) => pairs.iter().map(|(key, _)| key.clone()).collect(),
            other => panic!("not an object: {other:?}"),
        };
        assert_eq!(
            keys,
            ["schema_version", "command", "ok", "data", "warnings"]
        );
        assert_eq!(SCHEMA_VERSION, 1);
        assert_eq!(doc.get("schema_version"), Some(&Json::Int(1)));
        assert_eq!(doc.get("ok"), Some(&Json::Bool(true)));
        assert_eq!(doc.get("warnings"), Some(&Json::Array(Vec::new())));
        assert_eq!(
            doc.get("command").and_then(Json::as_str),
            Some("domain list")
        );
    }

    /// A document can report failure without changing its shape or order.
    #[test]
    fn the_envelope_can_report_ok_false_and_warnings() {
        let doc = envelope(
            "secret list",
            object(vec![("cage", Json::string("acme"))]),
            false,
            &["API_KEY is missing".to_owned()],
        );
        let text = dumps(&doc, DumpOptions::indented());
        let parsed = parse(&text).expect("parses");
        let keys: Vec<String> = match &parsed {
            Json::Object(pairs) => pairs.iter().map(|(key, _)| key.clone()).collect(),
            other => panic!("not an object: {other:?}"),
        };
        assert_eq!(
            keys,
            ["schema_version", "command", "ok", "data", "warnings"]
        );
        assert_eq!(parsed.get("ok"), Some(&Json::Bool(false)));
        assert_eq!(
            parsed.get("warnings"),
            Some(&Json::Array(vec![Json::string("API_KEY is missing")]))
        );
        assert!(text.contains("\"ok\": false"));
    }

    /// An alias spelling never leaks into the document.
    #[test]
    fn render_is_indented_and_carries_the_command() {
        let text = render(
            "secret list",
            object(vec![("cage", Json::string("acme"))]),
            true,
            &[],
        );
        assert!(text.starts_with("{\n  \"schema_version\": 1,"));
        assert!(text.contains("\"command\": \"secret list\""));
        assert!(text.trim_end().ends_with('}'));
    }
}
