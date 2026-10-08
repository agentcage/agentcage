//! Stable deployment fingerprints used by `cage update` no-op detection.
//!
//! A port of `src/agentcage/fingerprint.py`, and the one module in this
//! crate where "close enough" is indistinguishable from broken.
//!
//! # Why byte-identity is the requirement
//!
//! `cage update` decides whether a cage needs redeploying by hashing its
//! inputs and comparing the digest with the `fingerprint.json` the last
//! deploy left on disk. At cutover every cage on every machine carries a
//! `fingerprint.json` that the *Python* wrote (see
//! `tests/fixtures/state-compat/`), and the Rust binary has to agree
//! with it on first run, with no migration step. There are only two ways
//! to get that wrong and both are bad:
//!
//! * **Hash too eagerly** — any byte of divergence and every cage looks
//!   changed, so the first `cage update` after the upgrade rebuilds the
//!   world for nothing, on everyone's machine at once.
//! * **Hash something unstable** — a value that depends on the machine,
//!   the interpreter, the filesystem or a hash seed, and `cage update`
//!   rebuilds forever, or stops noticing real changes.
//!
//! So everything here is pinned against fixtures the Python produced
//! rather than against a reading of the Python: `tests/golden_fingerprint.rs`
//! reproduces all 125 golden-corpus `fingerprint.json` files and the
//! deployed-cage one in `tests/fixtures/state-compat/`.
//!
//! # The shape
//!
//! Five inputs are hashed separately, and the five digests are then
//! hashed together:
//!
//! ```text
//! cage_yaml       sha256(stable_json(yaml.safe_load(cage.yaml)))
//! resolved_config sha256(stable_json(resolved config))            ┐
//! units           sha256(stable_json({unit name: unit text}))     ├ components
//! image_digests   sha256(stable_json({image: digest}))            │
//! scaffold_version sha256(scaffold version string)                ┘
//!
//! fingerprint     sha256(stable_json({"version": 1, "components": …}))
//! ```
//!
//! The per-component digests are not load-bearing on their own — the
//! top-level `fingerprint` is the only value compared — but they make a
//! `fingerprint.json` diff say *which* input moved, which is the whole
//! reason they are written out.
//!
//! # The serialiser
//!
//! [`stable_json`] is
//! `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
//! Note `ensure_ascii=False`: unlike `cage har`'s serialisation in
//! [`crate::har`], a non-ASCII domain or header name is hashed as raw
//! UTF-8, not as `\uXXXX`. The codebase is not consistent about this and
//! the difference changes the digest, so the two call sites are spelled
//! out separately rather than sharing a default.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::har::json::{self, DumpOptions, Json};
use crate::yaml;

/// The fingerprint format version, stamped into every `fingerprint.json`.
///
/// [`fingerprint_matches`] refuses to compare across versions, so
/// bumping this makes every existing cage look changed exactly once.
/// `fingerprint.py`'s `FINGERPRINT_VERSION`.
pub const FINGERPRINT_VERSION: i64 = 1;

/// `json.dumps(…, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
const STABLE: DumpOptions = DumpOptions {
    indent: None,
    sort_keys: true,
    ensure_ascii: false,
    separators: Some((",", ":")),
};

/// Serialize a JSON-compatible value deterministically.
///
/// `fingerprint.py`'s `stable_json`. Sorted keys and no optional
/// whitespace, so two equal values always produce the same bytes and
/// therefore the same digest.
///
/// Key order comes from [`DumpOptions::sort_keys`], which sorts by the
/// UTF-8 bytes of each key. Python sorts `str` by code point. Those two
/// orders agree for every valid string, because UTF-8 is defined so that
/// byte-wise comparison reproduces code-point comparison — see
/// `sorts_keys_by_code_point` below, which pins it with keys that would
/// disagree under any other encoding.
#[must_use]
pub fn stable_json(value: &Json) -> String {
    json::dumps(value, STABLE)
}

/// `hashlib.sha256(value).hexdigest()`, over UTF-8 for a `str`.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ── Errors ───────────────────────────────────────────────────

/// Why a fingerprint could not be computed.
///
/// Every variant is something `json.dumps` raises `TypeError` on, or
/// something `yaml.safe_load` refuses outright. Python fails loudly in
/// all of these cases and so does this — a fingerprint that silently
/// papered over an unrepresentable value would be a digest with no
/// meaning.
#[derive(Debug)]
pub enum Error {
    /// The `cage.yaml` text did not parse.
    Yaml(yaml::Error),
    /// A mapping key that `json.dumps` will not accept. Python allows
    /// `str`, `int`, `float`, `bool` and `None` keys and coerces the
    /// last four to strings; agentcage configs have only string keys, so
    /// rather than guess at Python's cross-type sort order for a shape
    /// no config has, this refuses. Carries the path to the mapping.
    NonStringKey {
        /// Dotted path to the offending mapping, `<root>` at the top.
        path: String,
        /// The key, as YAML would show it.
        key: String,
    },
    /// A YAML node carrying an explicit tag. `yaml.safe_load` has no
    /// constructor for a non-standard tag and raises `ConstructorError`,
    /// so there is no digest to reproduce here either.
    Tagged {
        /// Dotted path to the tagged node.
        path: String,
        /// The tag, as written.
        tag: String,
    },
    /// A value handed in as an already-parsed mapping was not one.
    /// `fingerprint.py` does `dict(cage_yaml)`, which raises for
    /// anything else.
    NotAMapping {
        /// Which argument it was.
        argument: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yaml(error) => write!(f, "{error}"),
            Self::NonStringKey { path, key } => write!(
                f,
                "the key {key} at {path} is not a string. agentcage can only \
                 fingerprint configurations whose mapping keys are strings; \
                 quote it."
            ),
            Self::Tagged { path, tag } => write!(
                f,
                "the value at {path} carries the tag {tag}, which agentcage \
                 cannot read. Remove the tag."
            ),
            Self::NotAMapping { argument } => {
                write!(f, "{argument} is not a mapping")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Yaml(error) => Some(error),
            _ => None,
        }
    }
}

impl From<yaml::Error> for Error {
    fn from(error: yaml::Error) -> Self {
        Self::Yaml(error)
    }
}

// ── YAML to JSON ─────────────────────────────────────────────

/// Convert a `yaml.safe_load` result into the JSON value `json.dumps`
/// would be handed.
///
/// Python does not convert at all — PyYAML's safe loader produces the
/// same `dict`/`list`/`str`/`int`/`float`/`bool`/`None` objects the
/// `json` module serializes, so the two libraries meet in the middle on
/// their own. Rust has two separate value types, so the meeting has to
/// be written down.
///
/// The mapping is total except for the two cases Python also rejects: a
/// key `json.dumps` will not take, and a tag `safe_load` will not
/// construct.
fn json_from_yaml(value: &yaml::Value, path: &mut Vec<String>) -> Result<Json, Error> {
    Ok(match value {
        yaml::Value::Null => Json::Null,
        yaml::Value::Bool(flag) => Json::Bool(*flag),
        yaml::Value::Number(number) => number_to_json(number),
        yaml::Value::String(text) => Json::Str(text.clone()),
        yaml::Value::Sequence(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                path.push(format!("[{index}]"));
                out.push(json_from_yaml(item, path)?);
                path.pop();
            }
            Json::Array(out)
        }
        yaml::Value::Mapping(mapping) => {
            let mut out = Vec::with_capacity(mapping.len());
            for (key, item) in mapping {
                let yaml::Value::String(key) = key else {
                    return Err(Error::NonStringKey {
                        path: display_path(path),
                        key: display_key(key),
                    });
                };
                path.push(key.clone());
                let item = json_from_yaml(item, path)?;
                path.pop();
                out.push((key.clone(), item));
            }
            Json::Object(out)
        }
        yaml::Value::Tagged(tagged) => {
            return Err(Error::Tagged {
                path: display_path(path),
                tag: tagged.tag.to_string(),
            });
        }
    })
}

/// A YAML number as the `json` module's encoder sees it.
///
/// PyYAML's `int` is unbounded, so a literal too large for an `i64`
/// keeps its digits rather than becoming a float — `json.dumps` would
/// print all of them. `serde_norway` parses such a literal as `u64` or,
/// past that, as `f64`; only the `u64` step is recoverable, and a
/// literal past `u64::MAX` is already outside what any agentcage config
/// could mean.
fn number_to_json(number: &yaml::Number) -> Json {
    if let Some(value) = number.as_i64() {
        Json::Int(value)
    } else if let Some(value) = number.as_u64() {
        Json::BigInt(value.to_string())
    } else {
        Json::Float(number.as_f64().unwrap_or(f64::NAN))
    }
}

/// `a.b[0].c`, or `<root>` at the top.
fn display_path(path: &[String]) -> String {
    if path.is_empty() {
        return "<root>".to_string();
    }
    let mut out = String::new();
    for step in path {
        if step.starts_with('[') {
            out.push_str(step);
        } else {
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(step);
        }
    }
    out
}

/// A non-string key, rendered for an error message.
fn display_key(key: &yaml::Value) -> String {
    yaml::dump(key).map_or_else(|_| format!("{key:?}"), |text| text.trim_end().to_string())
}

// ── Normalization ────────────────────────────────────────────

/// A cage configuration, in either form `fingerprint.py` accepts.
///
/// The Python signature is `str | Mapping[str, Any]`: callers that have
/// the file's text pass that, callers that already parsed it pass the
/// mapping. Both reach the same serializer, so both are kept.
#[derive(Clone, Copy, Debug)]
pub enum CageYaml<'a> {
    /// The text of a `cage.yaml`, to be parsed with `yaml.safe_load`.
    Text(&'a str),
    /// An already-parsed configuration, which must be a mapping.
    Parsed(&'a Json),
}

/// Return a canonical JSON form of a cage configuration.
///
/// Parsing YAML before serializing means comments, whitespace, and
/// mapping-key order do not affect the result. Sequence order remains
/// significant because it can affect generated container arguments and
/// policy evaluation.
///
/// # Errors
///
/// [`Error::Yaml`] for text that does not parse, and the conversion
/// errors of [`json_from_yaml`]. Passing [`CageYaml::Parsed`] something
/// that is not an object is [`Error::NotAMapping`].
pub fn normalize_cage_yaml(cage_yaml: CageYaml<'_>) -> Result<String, Error> {
    match cage_yaml {
        CageYaml::Text(text) => {
            let parsed = json_from_yaml(&yaml::load(text)?, &mut Vec::new())?;
            // `yaml.safe_load(cage_yaml) or {}`. The `or` catches more
            // than the empty file it is there for: every falsy YAML
            // document — `null`, `false`, `0`, `""`, `[]`, `{}` — becomes
            // an empty mapping, and so hashes identically. Python's
            // truthiness is what decides that, not emptiness, which is
            // why this asks `Json` rather than checking for null.
            Ok(stable_json(&if parsed.is_truthy() {
                parsed
            } else {
                Json::Object(Vec::new())
            }))
        }
        CageYaml::Parsed(value) => {
            if !matches!(value, Json::Object(_)) {
                return Err(Error::NotAMapping {
                    argument: "cage_yaml",
                });
            }
            Ok(stable_json(value))
        }
    }
}

// ── The fingerprint ──────────────────────────────────────────

/// The inputs `cage update` derives a fingerprint from.
///
/// A struct rather than five positional arguments because four of the
/// five are stringly typed and transposing two of them would produce a
/// perfectly plausible wrong digest.
#[derive(Clone, Copy, Debug)]
pub struct Inputs<'a> {
    /// The cage's configuration.
    pub cage_yaml: CageYaml<'a>,
    /// The fully resolved configuration, as a JSON object.
    pub resolved_config: &'a Json,
    /// Rendered unit files, by filename. Empty for backends that render
    /// no units — `apple-container` builds `container run` argv and a
    /// launchd plist instead.
    pub units: &'a BTreeMap<String, String>,
    /// Pinned image digests, by image reference.
    pub image_digests: &'a BTreeMap<String, String>,
    /// The scaffold version, or the empty string for a cage that has no
    /// scaffold. Hashed as a plain string, not through [`stable_json`].
    pub scaffold_version: &'a str,
}

/// The five per-input digests.
///
/// These exist for diagnostics: a `fingerprint.json` diff that moves one
/// line says which input changed, where a single top-level hash would
/// only say that something did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Components {
    /// `sha256` of the normalized `cage.yaml`.
    pub cage_yaml: String,
    /// `sha256` of the resolved configuration.
    pub resolved_config: String,
    /// `sha256` of the rendered units.
    pub units: String,
    /// `sha256` of the pinned image digests.
    pub image_digests: String,
    /// `sha256` of the scaffold version.
    pub scaffold_version: String,
}

/// A computed fingerprint, as written to `fingerprint.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint {
    /// Always [`FINGERPRINT_VERSION`] when freshly computed.
    pub version: i64,
    /// The per-input digests.
    pub components: Components,
    /// The single value `cage update` compares.
    pub fingerprint: String,
}

impl Components {
    /// The `components` object, in the order `fingerprint.py` builds it.
    ///
    /// Insertion order is not load-bearing — [`stable_json`] sorts — but
    /// keeping the Python's order makes the two sources read the same.
    fn to_json(&self) -> Json {
        Json::Object(vec![
            ("cage_yaml".to_string(), Json::string(&self.cage_yaml)),
            (
                "resolved_config".to_string(),
                Json::string(&self.resolved_config),
            ),
            ("units".to_string(), Json::string(&self.units)),
            (
                "image_digests".to_string(),
                Json::string(&self.image_digests),
            ),
            (
                "scaffold_version".to_string(),
                Json::string(&self.scaffold_version),
            ),
        ])
    }
}

impl Fingerprint {
    /// The `payload` the top-level hash is taken over: everything but
    /// the hash itself.
    fn payload(&self) -> Json {
        Json::Object(vec![
            ("version".to_string(), Json::Int(self.version)),
            ("components".to_string(), self.components.to_json()),
        ])
    }

    /// The whole document, ready to be written as `fingerprint.json`.
    ///
    /// `{**payload, "fingerprint": …}` — the payload's keys first, then
    /// the hash.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let mut value = self.payload();
        value.set("fingerprint", Json::string(&self.fingerprint));
        value
    }
}

/// A `{name: text}` mapping, as `stable_json` sees it.
///
/// `BTreeMap` iterates in byte order and `stable_json` sorts by byte
/// order, so the two agree and the insertion order never matters.
fn string_map_to_json(map: &BTreeMap<String, String>) -> Json {
    Json::Object(
        map.iter()
            .map(|(key, value)| (key.clone(), Json::string(value)))
            .collect(),
    )
}

/// Compute a versioned fingerprint from resolved deployment inputs.
///
/// The component hashes make `fingerprint.json` useful for diagnostics
/// while the top-level hash provides a single stable comparison value.
///
/// # Errors
///
/// Anything [`normalize_cage_yaml`] can fail on, plus
/// [`Error::NotAMapping`] if `resolved_config` is not a JSON object —
/// `fingerprint.py` does `dict(resolved_config)`, which raises.
pub fn compute_fingerprint(inputs: Inputs<'_>) -> Result<Fingerprint, Error> {
    if !matches!(inputs.resolved_config, Json::Object(_)) {
        return Err(Error::NotAMapping {
            argument: "resolved_config",
        });
    }
    let components = Components {
        cage_yaml: sha256_hex(normalize_cage_yaml(inputs.cage_yaml)?.as_bytes()),
        resolved_config: sha256_hex(stable_json(inputs.resolved_config).as_bytes()),
        units: sha256_hex(stable_json(&string_map_to_json(inputs.units)).as_bytes()),
        image_digests: sha256_hex(
            stable_json(&string_map_to_json(inputs.image_digests)).as_bytes(),
        ),
        // The one input hashed as itself rather than through
        // `stable_json`: it is already a bare string.
        scaffold_version: sha256_hex(inputs.scaffold_version.as_bytes()),
    };
    let mut fingerprint = Fingerprint {
        version: FINGERPRINT_VERSION,
        components,
        fingerprint: String::new(),
    };
    fingerprint.fingerprint = sha256_hex(stable_json(&fingerprint.payload()).as_bytes());
    Ok(fingerprint)
}

/// Return whether two supported, well-formed fingerprints match.
///
/// `stored` is whatever was read off disk, so it is deliberately typed
/// as an arbitrary JSON value: a truncated, hand-edited or
/// future-versioned `fingerprint.json` has to answer "no match" rather
/// than fail.
///
/// One deliberate narrowing from the Python. `stored.get("version") ==
/// FINGERPRINT_VERSION` is true in Python for `true` and `1.0` as well
/// as `1`, because `==` coerces across `bool`, `int` and `float`. This
/// requires the integer. `json.dumps` has never written anything but `1`
/// there, so the only way to reach the difference is by hand-editing the
/// file into a shape Python would have accepted — and the cost of
/// refusing is one rebuild, against a silent wrong answer.
#[must_use]
pub fn fingerprint_matches(stored: &Json, current: &Fingerprint) -> bool {
    stored.get("version") == Some(&Json::Int(FINGERPRINT_VERSION))
        && stored.get("fingerprint").and_then(Json::as_str) == Some(current.fingerprint.as_str())
}

// ── The scaffold build context ───────────────────────────────

/// State this tool writes into a scaffold cage's directory, which must
/// not feed back into the hash of that directory.
///
/// `fingerprint.py`'s `_STATE_ARTIFACTS`. A `fingerprint.json` written
/// into the context would change the context, which would change the
/// fingerprint, which would rewrite `fingerprint.json` — `cage update`
/// would never converge.
const STATE_ARTIFACTS: &[&str] = &[
    "cage.yaml",
    "metadata.json",
    "fingerprint.json",
    "proxy-config.yaml",
    "dns-allowlist.conf",
    "pending_secrets.json",
    "cage-env",
    "creds",
];

/// Whether a path relative to the context root is derived deployment
/// state rather than build input.
///
/// Matches on the *first* component, so `creds/anything.cred` is
/// excluded along with `creds` itself.
#[must_use]
pub fn is_state_artifact(relative_posix: &str) -> bool {
    let first = relative_posix.split('/').next().unwrap_or_default();
    STATE_ARTIFACTS.contains(&first)
}

/// Hash the frozen build context staged for an existing scaffold cage.
///
/// VM updates copy this context into the guest before rebuilding, while
/// the other backends build it directly. Derived deployment state is
/// excluded so writing a fingerprint cannot invalidate itself.
///
/// This is the pure half of `fingerprint.scaffold_context_version`: this
/// crate does no I/O (see the crate docs), so the caller supplies the
/// relative POSIX paths of every *file* under the context root and a
/// `read` closure for their bytes. The ordering, the exclusion and the
/// framing — which are the parts that change the digest — stay here; the
/// other half of the Python function is the directory walk, which lands
/// in `agentcage-cli` with the scaffold commands (RUST-PORT-PLAN.md
/// Track D, PR D14). That half still owes: `state_dir.resolve()` as the
/// root, an *absolute* `containerfile` overriding it with its own parent
/// instead, `""` for an empty `containerfile` and `"missing"` for a root
/// that is not a directory.
///
/// Nothing pins that half yet. A7's state fixtures do not capture a
/// staged scaffold build context — it needs a real scaffold build — so
/// the walk has no golden input to check against, only this digest,
/// which is checked against the Python directly in the unit test below.
///
/// Sorting is by the relative POSIX path, exactly as the Python sorts
/// `root.rglob("*")` by `Path.as_posix()`. The Python sorts directories
/// into that list too and drops them afterwards, which cannot change the
/// relative order of the files that remain.
///
/// # Errors
///
/// Whatever `read` returns; the walk is abandoned at the first failure.
pub fn scaffold_context_digest<E>(
    relative_paths: &[String],
    mut read: impl FnMut(&str) -> Result<Vec<u8>, E>,
) -> Result<String, E> {
    let mut ordered: Vec<&String> = relative_paths
        .iter()
        .filter(|path| !is_state_artifact(path))
        .collect();
    ordered.sort();

    let mut digest = Sha256::new();
    for path in ordered {
        // Path and contents are each terminated rather than
        // length-prefixed, which is what the Python does. The trailing
        // separators are what keep `a/b` + `c` from colliding with `a`
        // + `bc`.
        digest.update(path.as_bytes());
        digest.update(b"\0");
        digest.update(read(path)?);
        digest.update(b"\0");
    }
    let mut out = String::with_capacity(64);
    for byte in digest.finalize() {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::Infallible;

    use super::{
        CageYaml, Error, FINGERPRINT_VERSION, Fingerprint, Inputs, compute_fingerprint,
        fingerprint_matches, is_state_artifact, normalize_cage_yaml, scaffold_context_digest,
        stable_json,
    };
    use crate::har::json::{Json, parse};

    fn json(text: &str) -> Json {
        parse(text).expect("test JSON")
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn fingerprint_of(cage_yaml: &str) -> Fingerprint {
        compute_fingerprint(Inputs {
            cage_yaml: CageYaml::Text(cage_yaml),
            resolved_config: &json(r#"{"name": "demo"}"#),
            units: &map(&[("demo.container", "[Container]\n")]),
            image_digests: &map(&[("img", "sha256:00")]),
            scaffold_version: "",
        })
        .expect("computes")
    }

    /// Every expectation here is `fingerprint.stable_json` output, read
    /// off `CPython` with PyYAML in the loop.
    #[test]
    fn stable_json_is_sorted_compact_and_not_ascii_escaped() {
        assert_eq!(
            stable_json(&json(r#"{"b": 1, "a": [1, {"d": null, "c": true}]}"#)),
            r#"{"a":[1,{"c":true,"d":null}],"b":1}"#
        );
        // `ensure_ascii=False`, which is where this differs from the
        // `har.py` serializer next door.
        assert_eq!(
            stable_json(&json(r#"{"k": "héllo 日本 😀"}"#)),
            "{\"k\":\"héllo 日本 😀\"}"
        );
        assert_eq!(stable_json(&Json::Object(Vec::new())), "{}");
        assert_eq!(stable_json(&json("[]")), "[]");
    }

    /// Python sorts `str` keys by code point; this sorts by UTF-8 byte.
    /// UTF-8 is ordered so the two agree, and these keys are the ones
    /// that would expose it if it did not: an ASCII key against a
    /// two-byte one, a two-byte against a three-byte, and a character
    /// outside the BMP that needs a surrogate pair in UTF-16 — the
    /// encoding under which `"\u{10000}" < "\u{ffff}"` would come out
    /// the other way round.
    #[test]
    fn sorts_keys_by_code_point() {
        let value = Json::Object(vec![
            ("\u{10000}".to_string(), Json::Int(4)),
            ("\u{ffff}".to_string(), Json::Int(3)),
            ("é".to_string(), Json::Int(2)),
            ("z".to_string(), Json::Int(1)),
        ]);
        assert_eq!(
            stable_json(&value),
            "{\"z\":1,\"é\":2,\"\u{ffff}\":3,\"\u{10000}\":4}"
        );
    }

    /// `yaml.safe_load` first, so formatting cannot reach the digest.
    #[test]
    fn normalization_ignores_comments_whitespace_and_key_order() {
        let a = "# a comment\nname: demo\ndomains:\n  - a.example\n  - b.example\n";
        let b = "domains: [a.example,   b.example]\nname:    demo\n";
        let expected = r#"{"domains":["a.example","b.example"],"name":"demo"}"#;
        for text in [a, b] {
            assert_eq!(
                normalize_cage_yaml(CageYaml::Text(text)).expect("parses"),
                expected
            );
        }
        // Sequence order is not normalized: it changes container argv
        // and policy evaluation, so it has to change the digest.
        let reversed = "name: demo\ndomains: [b.example, a.example]\n";
        assert_ne!(
            normalize_cage_yaml(CageYaml::Text(reversed)).expect("parses"),
            expected
        );
    }

    /// `yaml.safe_load(text) or {}` — every falsy document, not just the
    /// empty one.
    #[test]
    fn every_falsy_document_normalizes_to_an_empty_mapping() {
        for text in [
            "",
            "   \n",
            "# only a comment\n",
            "null\n",
            "false\n",
            "0\n",
            "''\n",
            "[]\n",
            "{}\n",
        ] {
            assert_eq!(
                normalize_cage_yaml(CageYaml::Text(text)).expect("parses"),
                "{}",
                "{text:?} should normalize to an empty mapping"
            );
        }
        // Truthy non-mappings are *not* coerced; `stable_json` takes
        // them as they are.
        assert_eq!(
            normalize_cage_yaml(CageYaml::Text("- a\n- b\n")).expect("parses"),
            r#"["a","b"]"#
        );
    }

    /// The YAML 1.1 spellings `serde_norway` would otherwise read as
    /// strings reach the digest as booleans, because `yaml::load` (PR
    /// B2) resolves them the way PyYAML does. A fingerprint computed
    /// from `tls: no` has to equal one computed from `tls: false`.
    #[test]
    fn yaml_1_1_booleans_reach_the_digest_as_booleans() {
        assert_eq!(
            normalize_cage_yaml(CageYaml::Text("tls: no\n")).expect("parses"),
            r#"{"tls":false}"#
        );
        assert_eq!(
            normalize_cage_yaml(CageYaml::Text("tls: 'no'\n")).expect("parses"),
            r#"{"tls":"no"}"#
        );
    }

    #[test]
    fn a_fingerprint_is_hex_and_versioned() {
        let value = fingerprint_of("name: demo\n");
        assert_eq!(value.version, FINGERPRINT_VERSION);
        for digest in [
            &value.fingerprint,
            &value.components.cage_yaml,
            &value.components.units,
        ] {
            assert_eq!(digest.len(), 64, "{digest} is not a sha256 hex digest");
            assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        // sha256(""), the empty scaffold version.
        assert_eq!(
            value.components.scaffold_version,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Changing any one input has to move the top-level hash, or
    /// `cage update` stops noticing real changes.
    #[test]
    fn every_input_reaches_the_top_level_hash() {
        let base = Inputs {
            cage_yaml: CageYaml::Text("name: demo\n"),
            resolved_config: &json(r#"{"name": "demo"}"#),
            units: &map(&[("demo.container", "[Container]\n")]),
            image_digests: &map(&[("img", "sha256:00")]),
            scaffold_version: "",
        };
        let original = compute_fingerprint(base).expect("computes").fingerprint;

        let cases = [
            compute_fingerprint(Inputs {
                cage_yaml: CageYaml::Text("name: other\n"),
                ..base
            }),
            compute_fingerprint(Inputs {
                resolved_config: &json(r#"{"name": "other"}"#),
                ..base
            }),
            compute_fingerprint(Inputs {
                units: &map(&[("demo.container", "[Container]\nX=1\n")]),
                ..base
            }),
            compute_fingerprint(Inputs {
                image_digests: &map(&[("img", "sha256:11")]),
                ..base
            }),
            compute_fingerprint(Inputs {
                scaffold_version: "abc",
                ..base
            }),
        ];
        for (index, case) in cases.into_iter().enumerate() {
            assert_ne!(
                case.expect("computes").fingerprint,
                original,
                "input {index} did not reach the hash"
            );
        }
    }

    #[test]
    fn matching_needs_the_version_and_the_hash() {
        let current = fingerprint_of("name: demo\n");
        assert!(fingerprint_matches(&current.to_json(), &current));

        let hash = &current.fingerprint;
        for stored in [
            json("null"),
            json("[]"),
            json(r#""a string""#),
            json("{}"),
            json(&format!(r#"{{"fingerprint": "{hash}"}}"#)),
            json(&format!(r#"{{"version": 2, "fingerprint": "{hash}"}}"#)),
            json(r#"{"version": 1, "fingerprint": "beef"}"#),
            json(r#"{"version": 1}"#),
        ] {
            assert!(
                !fingerprint_matches(&stored, &current),
                "{stored:?} should not match"
            );
        }
    }

    /// The document written to `fingerprint.json`.
    #[test]
    fn to_json_carries_the_payload_and_the_hash() {
        let value = fingerprint_of("name: demo\n").to_json();
        assert_eq!(value.get("version"), Some(&Json::Int(1)));
        assert!(value.get("fingerprint").and_then(Json::as_str).is_some());
        let components = value.get("components").expect("components");
        for key in [
            "cage_yaml",
            "resolved_config",
            "units",
            "image_digests",
            "scaffold_version",
        ] {
            assert!(components.get(key).is_some(), "missing component {key}");
        }
    }

    #[test]
    fn unrepresentable_configurations_are_refused() {
        assert!(matches!(
            normalize_cage_yaml(CageYaml::Text("1: a\n")),
            Err(Error::NonStringKey { .. })
        ));
        assert!(matches!(
            normalize_cage_yaml(CageYaml::Text("k: !Custom {}\n")),
            Err(Error::Tagged { .. })
        ));
        assert!(matches!(
            normalize_cage_yaml(CageYaml::Text("name: [unclosed\n")),
            Err(Error::Yaml(_))
        ));
        assert!(matches!(
            normalize_cage_yaml(CageYaml::Parsed(&json("[]"))),
            Err(Error::NotAMapping { .. })
        ));
        assert!(matches!(
            compute_fingerprint(Inputs {
                cage_yaml: CageYaml::Text("name: demo\n"),
                resolved_config: &json("[]"),
                units: &BTreeMap::new(),
                image_digests: &BTreeMap::new(),
                scaffold_version: "",
            }),
            Err(Error::NotAMapping { .. })
        ));
    }

    /// Both spellings of the same configuration reach the same digest.
    #[test]
    fn the_two_input_forms_agree() {
        let text = fingerprint_of("name: demo\n");
        let parsed = compute_fingerprint(Inputs {
            cage_yaml: CageYaml::Parsed(&json(r#"{"name": "demo"}"#)),
            resolved_config: &json(r#"{"name": "demo"}"#),
            units: &map(&[("demo.container", "[Container]\n")]),
            image_digests: &map(&[("img", "sha256:00")]),
            scaffold_version: "",
        })
        .expect("computes");
        assert_eq!(text, parsed);
    }

    #[test]
    fn state_artifacts_are_excluded_by_their_first_component() {
        for relative in [
            "cage.yaml",
            "fingerprint.json",
            "creds",
            "creds/ANTHROPIC_API_KEY.cred",
            "cage-env/placeholders.env",
        ] {
            assert!(is_state_artifact(relative), "{relative} should be excluded");
        }
        for relative in [
            "Containerfile",
            "src/cage.yaml",
            "creds.txt",
            "cage-environment",
        ] {
            assert!(!is_state_artifact(relative), "{relative} should be kept");
        }
    }

    /// Pinned against the Python: this digest is what
    /// `fingerprint.scaffold_context_version` returns for a directory
    /// holding exactly these three files, with `fingerprint.json` and
    /// `creds/key.cred` beside them to prove the exclusion.
    #[test]
    fn scaffold_context_digest_matches_the_python() {
        let files = [
            ("Containerfile", "FROM scratch\n"),
            ("app/main.py", "print('hi')\n"),
            ("README.md", "# demo\n"),
            ("fingerprint.json", "{}"),
            ("creds/key.cred", "secret"),
            ("cage.yaml", "name: demo\n"),
        ];
        let paths: Vec<String> = files.iter().map(|(name, _)| (*name).to_string()).collect();
        let digest = scaffold_context_digest::<Infallible>(&paths, |path| {
            Ok(files
                .iter()
                .find(|(name, _)| *name == path)
                .expect("known path")
                .1
                .as_bytes()
                .to_vec())
        })
        .expect("reads");
        assert_eq!(
            digest,
            "cc5276997b27ad7f0e4588ef839f9e2a9729864b9dd20eba95027d677d76ec39"
        );
    }
}
