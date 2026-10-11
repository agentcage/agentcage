//! Shared plumbing for the relay corpus tests: loading and blessing a
//! corpus file, the corpus byte encoding, and JSON → YAML for the relay
//! entries the cases describe.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::config::Value;
use crate::json::{self, DumpOptions, Json};

/// `tests/fixtures/egress/<name>`.
pub(crate) fn corpus_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/egress")
        .join(name)
}

/// The corpus as a JSON tree.
pub(crate) fn load(name: &str) -> Json {
    let text = std::fs::read_to_string(corpus_path(name)).unwrap();
    json::parse(&text).unwrap()
}

/// `AGENTCAGE_BLESS=1`: rewrite the corpus with what Rust produced.
pub(crate) fn blessing() -> bool {
    std::env::var_os("AGENTCAGE_BLESS").is_some_and(|v| v == "1")
}

/// Write a blessed corpus back, in the generator's layout.
pub(crate) fn bless(name: &str, corpus: &Json) {
    let text = json::dumps(
        corpus,
        DumpOptions {
            indent: Some(1),
            ensure_ascii: false,
            ..DumpOptions::default()
        },
    );
    std::fs::write(corpus_path(name), text + "\n").unwrap();
}

/// A corpus byte string: plain UTF-8, `{"b64"}`, or a `{"blob"}` recipe
/// slice.
pub(crate) fn dec(value: &Json) -> Vec<u8> {
    use base64::Engine as _;
    match value {
        Json::Str(s) => s.as_bytes().to_vec(),
        Json::Object(_) if value.get("blob").is_some() => {
            let mut whole = Vec::new();
            for part in arr(value.get("blob").unwrap()) {
                let piece = dec(&arr(part)[0]);
                for _ in 0..int(&arr(part)[1]) {
                    whole.extend_from_slice(&piece);
                }
            }
            let start = usize::try_from(int(value.get("start").unwrap())).unwrap();
            let end = usize::try_from(int(value.get("end").unwrap())).unwrap();
            whole[start..end].to_vec()
        }
        Json::Object(_) => base64::engine::general_purpose::STANDARD
            .decode(value.get("b64").and_then(Json::as_str).unwrap())
            .unwrap(),
        other => panic!("not a byte string: {other:?}"),
    }
}

/// The corpus encoding of `data`.
pub(crate) fn enc(data: &[u8]) -> Json {
    use base64::Engine as _;
    match std::str::from_utf8(data) {
        Ok(s) => Json::Str(s.to_owned()),
        Err(_) => json::object([(
            "b64",
            Json::Str(base64::engine::general_purpose::STANDARD.encode(data)),
        )]),
    }
}

/// [`enc`], or a digest for anything over 4 KiB.
pub(crate) fn enc_out(data: &[u8]) -> Json {
    if data.len() > 4096 {
        let hex = hex(&Sha256::digest(data));
        return json::object([
            ("sha256", Json::Str(hex)),
            ("len", Json::Int(i64::try_from(data.len()).unwrap())),
        ]);
    }
    enc(data)
}

pub(crate) fn arr(value: &Json) -> &[Json] {
    match value {
        Json::Array(items) => items,
        other => panic!("not an array: {other:?}"),
    }
}

pub(crate) fn int(value: &Json) -> i64 {
    match value {
        Json::Int(n) => *n,
        other => panic!("not an int: {other:?}"),
    }
}

pub(crate) fn text(value: &Json) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("not a string: {value:?}"))
}

pub(crate) fn boolean(value: Option<&Json>) -> bool {
    matches!(value, Some(Json::Bool(true)))
}

/// A JSON tree as the YAML value the config loader would produce.
pub(crate) fn yaml(value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Int(n) => Value::Number((*n).into()),
        Json::Float(f) => Value::Number((*f).into()),
        Json::BigInt(s) | Json::Str(s) => Value::String(s.clone()),
        Json::Array(items) => Value::Sequence(items.iter().map(yaml).collect()),
        Json::Object(pairs) => {
            let mut m = crate::config::Mapping::new();
            for (k, v) in pairs {
                m.insert(Value::String(k.clone()), yaml(v));
            }
            Value::Mapping(m)
        }
    }
}

/// `record` without its `ts` (the audit writer's, not the relay's).
pub(crate) fn without_ts(record: &Json) -> Json {
    match record {
        Json::Object(pairs) => {
            Json::Object(pairs.iter().filter(|(k, _)| k != "ts").cloned().collect())
        }
        other => other.clone(),
    }
}

/// Merge `extra` (a JSON object) over `base`.
pub(crate) fn merged(base: Json, extra: &Json) -> Json {
    let mut out = base;
    if let Json::Object(pairs) = extra {
        for (k, v) in pairs {
            out.set(k.clone(), v.clone());
        }
    }
    out
}

/// Lower-case hex, as Python's `hexdigest()`.
pub(crate) fn hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    data.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
