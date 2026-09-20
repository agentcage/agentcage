//! YAML, on the Rust side of a boundary whose other side is PyYAML.
//!
//! Every YAML file agentcage writes is read by something else:
//! `proxy-config.yaml` by the mitmproxy addon inside the egress
//! container, `cage.yaml` by the user and then by the next `cage`
//! invocation. The addon is Python and stays Python forever
//! (RUST-PORT-PLAN.md, scope decision), so this module is one half of a
//! cross-language contract, not a convenience wrapper.
//!
//! Use [`load`] and [`dump`] rather than `serde_norway` directly. The
//! difference is not stylistic.
//!
//! # The hazard
//!
//! PyYAML implements YAML **1.1**. Every Rust YAML crate implements
//! YAML **1.2**. The schemas disagree about which plain scalars are
//! strings:
//!
//! | Written plain | YAML 1.2 / Rust | YAML 1.1 / `yaml.safe_load` |
//! | :-- | :-- | :-- |
//! | `yes` `Yes` `YES` `on` `On` `ON` | `"yes"` … | `True` |
//! | `no` `No` `NO` `off` `Off` `OFF` | `"no"` … | `False` |
//! | `1:30` `12:00:00` `-1:30` `1:30.5` | `"1:30"` … | `90`, `43200`, `-90`, `90.5` |
//! | `1_000` `1_000.5` | `"1_000"` … | `1000`, `1000.5` |
//! | `2024-01-02` `2024-01-02T03:04:05` | `"2024-01-02"` … | `datetime.date` / `datetime` |
//! | `=` `<<` | `"="`, `"<<"` | **`ConstructorError`** |
//!
//! The direction matters. PyYAML *quotes* `'no'` when it writes, so
//! Python→Rust and Python→Python are both safe. **Only Rust→Python
//! corrupts**, which is why a Rust round-trip test passes while the bug
//! is live, and why the test that actually proves this module correct
//! shells out to `yaml.safe_load`
//! (`tests/yaml_pyyaml_crossing.rs`).
//!
//! What it costs, concretely: the host writes `proxy-config.yaml` and
//! the egress proxy reads it. A domain, a header name, a relay field or
//! a secret key whose value is the string `no` arrives inside the
//! security boundary as `False`.
//!
//! # What this module does about it
//!
//! [`dump`] writes the structure itself and quotes every scalar that
//! PyYAML would not read back as a string — see [`emit`] for how, and
//! [`pyyaml`] for the predicate, which is PyYAML's own implicit-resolver
//! table transliterated rather than a list of tokens someone tested.
//!
//! [`load`] resolves the reading side at parse time, so it hands Track
//! C's validators the same values `yaml.safe_load` hands `config.py`.
//! That needs the scalar's *style*, which every serde YAML crate throws
//! away, so it costs a second parse by a pure-Rust event parser — see
//! [`style`] for the mechanism, the alignment rules and how it fails
//! closed.
//!
//! # The reading side, in full
//!
//! A user's hand-written `cage.yaml` must not change meaning across the
//! port. Measured against PyYAML 6.0.3:
//!
//! | In `cage.yaml` | PyYAML gives | [`load`] gives | |
//! | :-- | :-- | :-- | :-- |
//! | `tls: no` | `False` | `Bool(false)` | **resolved** — [`style`] |
//! | `tls: 'no'` | `"no"` | `String("no")` | **resolved** — the quote is honoured, so `bool()` still says `True` as it does today |
//! | `tls: !!str no` | `"no"` | `String("no")` | **resolved** — an explicit tag is not a plain scalar |
//! | `no: 1` (a key) | `{False: 1}` | `{Bool(false): 1}` | **resolved** — keys are rewritten too |
//! | `port: 0755` | `493` | `String("0755")` | a string where an int is wanted: a loud type error |
//! | `size: 1_000` | `1000` | `String("1_000")` | same |
//! | `at: 1:30` | `90` | `String("1:30")` | same |
//! | `when: 2024-01-02` | `datetime.date` | `String(…)` | no field takes a date |
//! | `n: 1e3` | `"1e3"` | `Number(1000.0)` | the port is *more* permissive |
//! | `n: 0o17` | `"0o17"` | `Number(15)` | same |
//! | `k: !!bool no` | `False` | **error** | `serde_norway` refuses the tag; loud, not silent |
//! | `<<: *anchor` | merged into the mapping | merged into the mapping | **resolved** — [`merge`]. PR B2 left this open as the one reader divergence that was neither resolved nor loud; PR C1 closed it, because the quiet wrong answer is an emptied `domains.allow` |
//! | `k: <<`, `k: =` | **raises** | **error** | **resolved** — [`merge`]; PyYAML has no constructor for either tag outside key position |
//!
//! The booleans are resolved because they are the only row that can flip
//! a *value* without changing its type — and `relays/_validate.py:76` is
//! `bool(upstream.get("tls", True))`, so the flip lands on whether a
//! relay carrying credentials upstream uses TLS. Everything below the
//! line yields a value of the wrong type for its field, which the
//! validators reject with a message; they are listed so a later reader
//! can see they were weighed rather than missed.
//!
//! [`python_bool`] is the other half of that story: `config.py` coerces
//! with `bool(x)`, and reproducing *that* faithfully is why the quoted
//! `'no'` has to stay a string.
//!
//! # Why `serde_norway`
//!
//! The ADR is in the PR body; the short version:
//!
//! - `serde_yaml` is deprecated (`0.9.34+deprecated`, 2024-03-25).
//! - `serde_yml` is [RUSTSEC-2025-0068]: unsound and unmaintained. That
//!   advisory's own "recommended alternatives" are the two forks below.
//! - `serde_yaml_ng` is the other maintained fork, and still depends on
//!   dtolnay's `unsafe-libyaml`, which is itself unmaintained.
//! - `serde_norway` is the fork that also took over the C shim, as
//!   `unsafe-libyaml-norway`, and has shipped fixes to it
//!   (0.2.15 vs 0.2.11).
//! - `saphyr` and `yaml-rust2` are pure-Rust and healthier as projects,
//!   but have no serde integration, and `config.py` is 2,473 lines that
//!   want `#[derive(Deserialize)]`.
//!
//! Mapping order — the hard requirement, because `save_raw_config` uses
//! `sort_keys=False` and key order in `cage.yaml` is visible to the user
//! after `cage edit` — comes from `Mapping` being an `IndexMap`. It is
//! asserted, not assumed: [`eq_with_key_order`] is order-sensitive,
//! [`dump`] checks itself with it, and `tests/yaml_config_roundtrip.rs`
//! runs every committed config through it.
//!
//! The crate is named in exactly two files (this module and
//! `Cargo.toml`), and the rest of the port goes through the re-exports
//! here, so a future swap is a change to this directory.
//!
//! [RUSTSEC-2025-0068]: https://rustsec.org/advisories/RUSTSEC-2025-0068

mod emit;
mod merge;
pub mod pyyaml;
mod style;

use serde::Serialize;
use serde::de::DeserializeOwned;

pub use serde_norway::{Error, Location, Mapping, Number, Sequence, Value};

/// Build a [`Error`] from a message of our own.
///
/// `serde_norway::Error` is kept as *the* error type rather than wrapped:
/// it carries a [`Location`] for parse failures, which is what
/// `config.py:954`'s hand-written "line N, column M" message exists to
/// produce, and a wrapper would have to re-expose it anyway.
fn custom_error(message: impl std::fmt::Display) -> Error {
    <Error as serde::ser::Error>::custom(message)
}

/// Parse a YAML document, the way `yaml.safe_load` does.
///
/// An empty document gives [`Value::Null`], matching `safe_load("")`
/// returning `None` — which is why `state.py` writes
/// `yaml.safe_load(f) or {}`.
///
/// Plain `yes`/`no`/`on`/`off` come back as [`Value::Bool`], exactly as
/// PyYAML resolves them, while the quoted `'no'` stays a string. That
/// needs the scalar's *style*, which the serde YAML crates discard, so
/// it costs a second parse — see [`style`] for how, and for why any
/// disagreement between the two parses is an error rather than a guess.
///
/// Callers that know the filename should use [`load_named`], so a
/// failure says which file it was.
///
/// # Errors
///
/// Malformed YAML, more than one document, duplicate keys, or a
/// disagreement between the two parses. The error carries a
/// [`Location`] when it came from the parser.
pub fn load(text: &str) -> Result<Value, Error> {
    load_named("<yaml>", text)
}

/// [`load`], with a name to put in error messages.
///
/// `source` is a display name — the path the text was read from. This
/// crate does no I/O (see the crate docs), so the caller that opened the
/// file is the one that knows what to call it.
///
/// # Errors
///
/// As [`load`].
pub fn load_named(source: &str, text: &str) -> Result<Value, Error> {
    // `serde_norway` first, and it stays authoritative: it is the one
    // that decides what the document *is*. It also produces the better
    // message for a malformed file, a duplicate key or a second
    // document, so letting it fail first is deliberate.
    let mut value: Value = serde_norway::from_str(text)?;

    match style::shape_of(source, text)? {
        Some(shape) => {
            style::resolve_1_1_booleans(source, &mut value, &shape)?;
            // `<<` merge keys, after the boolean pass and before the
            // caller sees the tree: PyYAML flattens them during
            // construction, so a config that shares a block between
            // two sections has to arrive merged or every merged
            // setting reads as "never written". See `merge`.
            merge::apply(source, &mut value, &shape)?;
        }
        // No document in the stream: an empty file, or only comments.
        // `serde_norway` says `Null` for both, and if it ever says
        // something else the two parses disagree and that is an error.
        None if value.is_null() => {}
        None => {
            return Err(custom_error(format!(
                "{source}: the style pass found no YAML document but the value pass \
                 produced one. This is a bug in agentcage's YAML layer; please report \
                 it with the file attached."
            )));
        }
    }

    Ok(value)
}

/// Parse a YAML document into a typed value.
///
/// Goes through [`load`], so the YAML 1.1 boolean spellings reach `T`'s
/// `Deserialize` as real booleans.
///
/// # Errors
///
/// Anything [`load`] can fail on, plus YAML that does not fit `T`.
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    serde_norway::from_value(load(text)?)
}

/// [`from_str`], with a name to put in error messages.
///
/// # Errors
///
/// As [`from_str`].
pub fn from_str_named<T: DeserializeOwned>(source: &str, text: &str) -> Result<T, Error> {
    serde_norway::from_value(load_named(source, text)?)
}

/// Render a [`Value`] as YAML that PyYAML reads back unchanged.
///
/// Block style, two-space indent, sequences at their key's indentation:
/// the shape `yaml.safe_dump(default_flow_style=False, sort_keys=False)`
/// produces, and the shape every config in the repo is already written
/// in. Key order is preserved. Comments are not — `state.py:195` says
/// the Python implementation drops them too.
///
/// # Errors
///
/// Complex mapping keys, custom tags, and any failure of the emitter's
/// own round-trip self-check. See [`emit`].
pub fn dump(value: &Value) -> Result<String, Error> {
    emit::dump(value)
}

/// Serialize any [`Serialize`] type to YAML, with the same guarantees as
/// [`dump`].
///
/// # Errors
///
/// Anything [`dump`] can fail on, plus a failure to serialize `T`.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    let value = serde_norway::to_value(value)?;
    dump(&value)
}

/// Would `yaml.safe_load` read this plain scalar as something other than
/// a string?
///
/// The emitter's quoting rule, exposed because the golden corpus and any
/// future writer of YAML-adjacent files (`dns-allowlist.conf` is not
/// YAML, but the domains in it come from the same place) may want to ask
/// the same question.
#[must_use]
pub fn is_yaml_1_1_ambiguous(scalar: &str) -> bool {
    pyyaml::resolves_to_non_string(scalar)
}

/// Compare two values, **including mapping key order**.
///
/// [`Value`]'s own `PartialEq` uses `IndexMap`'s, which ignores order —
/// two mappings with the same pairs in a different order are equal. That
/// is the wrong answer here twice over: `cage edit` shows the user their
/// own key order, and `save_raw_config` passes `sort_keys=False`
/// precisely to keep it.
#[must_use]
pub fn eq_with_key_order(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Mapping(left), Value::Mapping(right)) => {
            left.len() == right.len()
                && left.iter().zip(right.iter()).all(
                    |((left_key, left_value), (right_key, right_value))| {
                        eq_with_key_order(left_key, right_key)
                            && eq_with_key_order(left_value, right_value)
                    },
                )
        }
        (Value::Sequence(left), Value::Sequence(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right.iter())
                    .all(|(left, right)| eq_with_key_order(left, right))
        }
        (left, right) => left == right,
    }
}

/// Python's `bool(x)` on a value that came out of [`load`].
///
/// Not a YAML concern at all — it is `config.py`'s coercion, and it is
/// here because reproducing it correctly is the whole reason [`load`]
/// does a second parse.
///
/// `relays/_validate.py:76` is `tls = bool(upstream.get("tls", True))`,
/// and `config.py` has nine more of these. CPython's `bool` is truthy
/// for any non-empty string, so:
///
/// ```text
/// tls: no       load() -> Bool(false)    -> false   (TLS off)
/// tls: 'no'     load() -> String("no")   -> true    (TLS on)
/// tls: "false"  load() -> String("false")-> true    (TLS on)
/// tls: ""       load() -> String("")     -> false
/// tls: []       load() -> Sequence([])   -> false
/// ```
///
/// The second line is a bug in the Python: someone who writes `'no'`
/// means "off" and gets "on". It is reproduced here rather than fixed
/// because it fails *safe* — the mistake leaves TLS enabled — and
/// because a port is not the place to change what an existing config
/// means. Fixing it is a behaviour change that belongs in its own
/// commit, on both sides of the boundary at once.
///
/// Fields that must be a *real* boolean (`config.py:945`, `:1255`,
/// `:1320`) are a different check: those reject a string outright, so
/// they want `matches!(value, Value::Bool(_))` and not this.
#[must_use]
pub fn python_bool(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Sequence(items) => !items.is_empty(),
        Value::Mapping(mapping) => !mapping.is_empty(),
        // `bool(x)` on an arbitrary object is `True`; a tagged node is
        // as close as this gets to one.
        Value::Tagged(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{Value, dump, eq_with_key_order, is_yaml_1_1_ambiguous, load, python_bool};

    #[test]
    fn empty_document_is_null_like_pyyaml() {
        assert_eq!(load("").expect("load"), Value::Null);
        assert_eq!(load("# just a comment\n").expect("load"), Value::Null);
    }

    #[test]
    fn key_order_survives_a_round_trip() {
        let source = "zebra: 1\napple: 2\nmango: 3\n";
        let value = load(source).expect("load");
        let rendered = dump(&value).expect("dump");
        assert_eq!(rendered, source);
        assert!(eq_with_key_order(&load(&rendered).expect("reload"), &value));
    }

    #[test]
    fn eq_with_key_order_is_stricter_than_value_eq() {
        let one = load("a: 1\nb: 2\n").expect("load");
        let other = load("b: 2\na: 1\n").expect("load");
        assert_eq!(one, other, "Value's own PartialEq ignores key order");
        assert!(
            !eq_with_key_order(&one, &other),
            "eq_with_key_order must not"
        );
    }

    /// The four corners, in Rust. `yaml_pyyaml_crossing.rs` asserts the
    /// same table against a running PyYAML, which is the version that
    /// counts; this one keeps `cargo test` honest without an
    /// interpreter.
    #[test]
    fn plain_and_quoted_booleans_are_different_values() {
        // Plain: PyYAML resolves it, so we do.
        assert_eq!(load("tls: no\n").expect("load")["tls"], Value::Bool(false));
        assert_eq!(
            load("tls: false\n").expect("load")["tls"],
            Value::Bool(false)
        );

        // Quoted: PyYAML leaves it a string, so we do -- and
        // `bool("no")` is how it stays `True` in Python today.
        assert_eq!(
            load("tls: 'no'\n").expect("load")["tls"],
            Value::String("no".to_owned())
        );
        assert_eq!(
            load("tls: \"false\"\n").expect("load")["tls"],
            Value::String("false".to_owned())
        );

        // And the coercion `config.py` actually applies.
        assert!(!python_bool(&load("tls: no\n").expect("load")["tls"]));
        assert!(python_bool(&load("tls: 'no'\n").expect("load")["tls"]));
        assert!(!python_bool(&load("tls: false\n").expect("load")["tls"]));
        assert!(python_bool(&load("tls: \"false\"\n").expect("load")["tls"]));
    }

    #[test]
    fn every_1_1_spelling_resolves_when_plain() {
        for (text, expected) in [
            ("yes", true),
            ("Yes", true),
            ("YES", true),
            ("on", true),
            ("On", true),
            ("ON", true),
            ("no", false),
            ("No", false),
            ("NO", false),
            ("off", false),
            ("Off", false),
            ("OFF", false),
        ] {
            assert_eq!(
                load(&format!("tls: {text}\n")).expect("load")["tls"],
                Value::Bool(expected),
                "tls: {text}"
            );
            assert_eq!(
                load(&format!("tls: '{text}'\n")).expect("load")["tls"],
                Value::String(text.to_owned()),
                "tls: '{text}'"
            );
        }
    }

    #[test]
    fn spellings_pyyaml_does_not_take_stay_strings() {
        for text in ["y", "Y", "n", "N", "yEs", "nope", "no-cache", "yes-man"] {
            assert_eq!(
                load(&format!("k: {text}\n")).expect("load")["k"],
                Value::String(text.to_owned()),
                "k: {text}"
            );
        }
    }

    #[test]
    fn resolution_reaches_keys_and_nested_positions() {
        let value = load("no: 1\nlist:\n- off\n- 'off'\nnested:\n  deep: ON\n").expect("load");
        assert_eq!(value[Value::Bool(false)], Value::Number(1.into()));
        assert_eq!(value["list"][0], Value::Bool(false));
        assert_eq!(value["list"][1], Value::String("off".to_owned()));
        assert_eq!(value["nested"]["deep"], Value::Bool(true));
    }

    #[test]
    fn block_scalars_and_tags_are_not_plain() {
        assert_eq!(
            load("k: |-\n  no\n").expect("load")["k"],
            Value::String("no".to_owned())
        );
        assert_eq!(
            load("k: !!str no\n").expect("load")["k"],
            Value::String("no".to_owned())
        );
    }

    #[test]
    fn typed_deserialization_takes_the_1_1_spellings() {
        #[derive(Debug, serde::Deserialize)]
        struct Upstream {
            tls: bool,
        }

        // No `deserialize_with` anywhere: `load` already turned the
        // plain `no` into a boolean, so plain `#[derive(Deserialize)]`
        // is all Track C needs.
        let off: Upstream = super::from_str("tls: no\n").expect("no");
        assert!(!off.tls);
        let on: Upstream = super::from_str("tls: true\n").expect("true");
        assert!(on.tls);

        // A quoted spelling is a string, and a `bool` field refuses it
        // -- which is `config.py:1255`'s behaviour, not a regression.
        let error = super::from_str::<Upstream>("tls: 'no'\n").expect_err("quoted");
        assert!(error.to_string().contains("invalid type"), "{error}");
    }

    #[test]
    fn a_resolved_boolean_round_trips_through_dump() {
        // `no` becomes `false` on the way out. That is a formatting
        // change and the same one `yaml.safe_dump` makes, since PyYAML
        // also emits `false` for a `False` it read from `no`.
        let value = load("tls: no\n").expect("load");
        assert_eq!(dump(&value).expect("dump"), "tls: false\n");
        let quoted = load("tls: 'no'\n").expect("load");
        assert_eq!(dump(&quoted).expect("dump"), "tls: 'no'\n");
    }

    #[test]
    fn the_ambiguity_predicate_is_reachable_from_the_public_api() {
        assert!(is_yaml_1_1_ambiguous("no"));
        assert!(is_yaml_1_1_ambiguous("2024-01-02"));
        assert!(!is_yaml_1_1_ambiguous("api.anthropic.com"));
    }
}
