//! The unit JSON, read back.
//!
//! `generate_units` writes one `<cage>.json` per cage and `start()`
//! reads it to build two `container run` argvs. There is no schema
//! version in it, so every read has to tolerate the shapes older
//! agentcages wrote — which is exactly what the Python's
//! `meta.get("key") or <default>` chain does, and why this is a wrapper
//! over a `Value` rather than a `#[derive(Deserialize)]` struct.
//!
//! The distinction that matters: `meta.get(k) or []` treats a present
//! `null`, a present `[]` and an absent key identically, and so does
//! every accessor here. A `Deserialize` impl would have had to choose
//! between rejecting the first and silently accepting a wrong type,
//! and both are worse than the Python's shrug.

use std::collections::BTreeMap;

use serde_json::Value;

/// A cage's `<name>.json`.
#[derive(Clone, Debug)]
pub struct Meta(Value);

impl Meta {
    /// Parse the document.
    ///
    /// # Errors
    ///
    /// The `serde_json` message when the bytes are not JSON. A
    /// non-object document parses: `meta.get` on it answers `None` for
    /// everything, which is what the Python's `json.loads` + `.get`
    /// would do only for an object — but a cage whose unit JSON is a
    /// list is broken either way, and failing on the first `get` is
    /// not better than failing on everything.
    pub fn parse(text: &str) -> Result<Self, serde_json::Error> {
        Ok(Self(serde_json::from_str(text)?))
    }

    /// `meta.get(key)`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    /// `meta.get(key) or ""`.
    #[must_use]
    pub fn string(&self, key: &str) -> String {
        self.0
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    /// `meta.get(key) or []`, keeping only the string entries.
    #[must_use]
    pub fn strings(&self, key: &str) -> Vec<String> {
        self.0
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `[int(p) for p in (meta.get(key) or [])]`.
    ///
    /// A JSON number or a numeric string both answer, because `int()`
    /// takes either and the metadata has carried both across versions.
    /// A value `int()` would raise on is dropped rather than failing
    /// the start: the port cannot reproduce a traceback as a feature,
    /// and a port number that is not a number is not one.
    #[must_use]
    pub fn ports(&self, key: &str) -> Vec<u32> {
        self.0
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| match item {
                        Value::Number(number) => {
                            number.as_u64().and_then(|n| u32::try_from(n).ok())
                        }
                        Value::String(text) => text.trim().parse().ok(),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `bool(meta.get(key, False))` — Python truthiness, so `0`, `""`
    /// and `[]` are all false.
    #[must_use]
    pub fn truthy(&self, key: &str) -> bool {
        match self.0.get(key) {
            None | Some(Value::Null) => false,
            Some(Value::Bool(value)) => *value,
            Some(Value::Number(number)) => number.as_f64().is_some_and(|n| n != 0.0),
            Some(Value::String(text)) => !text.is_empty(),
            Some(Value::Array(items)) => !items.is_empty(),
            Some(Value::Object(map)) => !map.is_empty(),
        }
    }

    /// `(meta.get(key) or {}).items()`, for the string-valued maps.
    ///
    /// Ordered, because `container.env` reaches `-e` in this order and
    /// the unit JSON is written with `sort_keys=True`; a `BTreeMap`
    /// reproduces that without re-sorting.
    #[must_use]
    pub fn map(&self, key: &str) -> BTreeMap<String, String> {
        self.0
            .get(key)
            .and_then(Value::as_object)
            .map(|object| {
                object
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The `env:NAME` / `systemd-creds:NAME` tail of a key source.
    ///
    /// `src.partition(":")[2]`, which is `""` for a source with no
    /// colon and for an absent one.
    #[must_use]
    pub fn key_source_name(&self, key: &str) -> String {
        let source = self.string(key);
        source
            .split_once(':')
            .map(|(_, name)| name.to_owned())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::Meta;

    fn meta(text: &str) -> Meta {
        Meta::parse(text).expect("valid JSON")
    }

    /// `or []` erases the difference between absent, null and empty.
    #[test]
    fn absent_null_and_empty_read_the_same() {
        let m = meta(r#"{"a": null, "b": []}"#);
        assert!(m.strings("a").is_empty());
        assert!(m.strings("b").is_empty());
        assert!(m.strings("missing").is_empty());
    }

    #[test]
    fn ports_accept_numbers_and_numeric_strings() {
        let m = meta(r#"{"p": [80, "443", 8080, "nope", null]}"#);
        assert_eq!(m.ports("p"), vec![80, 443, 8080]);
    }

    #[test]
    fn truthiness_is_pythons() {
        let m = meta(
            r#"{"t": true, "f": false, "zero": 0, "one": 1,
                         "empty": "", "text": "x", "list": [], "items": [1]}"#,
        );
        assert!(m.truthy("t"));
        assert!(!m.truthy("f"));
        assert!(!m.truthy("zero"));
        assert!(m.truthy("one"));
        assert!(!m.truthy("empty"));
        assert!(m.truthy("text"));
        assert!(!m.truthy("list"));
        assert!(m.truthy("items"));
        assert!(!m.truthy("missing"));
    }

    #[test]
    fn a_key_source_without_a_colon_has_no_name() {
        let m = meta(r#"{"with": "env:API_KEY", "without": "API_KEY"}"#);
        assert_eq!(m.key_source_name("with"), "API_KEY");
        assert_eq!(m.key_source_name("without"), "");
        assert_eq!(m.key_source_name("missing"), "");
    }

    #[test]
    fn a_map_keeps_only_string_values_in_sorted_order() {
        let m = meta(r#"{"env": {"B": "2", "A": "1", "N": null}}"#);
        let env = m.map("env");
        assert_eq!(
            env.keys().collect::<Vec<_>>(),
            vec![&"A".to_owned(), &"B".to_owned()]
        );
    }
}
