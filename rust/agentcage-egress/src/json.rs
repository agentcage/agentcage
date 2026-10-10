//! JSON exactly as Python's `json` module writes it.
//!
//! Audit lines, capture lines, block bodies and every Policy API response
//! are byte-for-byte what `json.dumps` produced in the implementation this
//! crate replaces: `", "` / `": "` separators, insertion-ordered keys,
//! `ensure_ascii`, `repr()` floats. The host already has that writer (it
//! reads and re-emits the same records), so it is reused rather than
//! re-derived.

pub use agentcage_core::har::json::{DumpOptions, Json, ParseError, dumps, format_float, parse};

/// `json.dumps(value)` with Python's defaults.
#[must_use]
pub fn to_string(value: &Json) -> String {
    dumps(value, DumpOptions::default())
}

/// `json.dumps(value, separators=(",", ":"))`: the compact form.
#[must_use]
pub fn to_compact_string(value: &Json) -> String {
    dumps(
        value,
        DumpOptions {
            separators: Some((",", ":")),
            ..DumpOptions::default()
        },
    )
}

/// Build a JSON object from `(key, value)` pairs, in order.
#[must_use]
pub fn object<K: Into<String>>(pairs: impl IntoIterator<Item = (K, Json)>) -> Json {
    Json::Object(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_block_body_is_byte_exact() {
        let body = object([
            ("blocked", Json::Bool(true)),
            ("reason", Json::string("nope")),
            ("host", Json::string("example.com")),
            ("by", Json::string("agentcage")),
        ]);
        assert_eq!(
            to_string(&body),
            r#"{"blocked": true, "reason": "nope", "host": "example.com", "by": "agentcage"}"#
        );
        assert_eq!(
            to_compact_string(&body),
            r#"{"blocked":true,"reason":"nope","host":"example.com","by":"agentcage"}"#
        );
    }
}
