//! Structural validation for `protocol_relays` entries.
//!
//! The Rust half of the port's sharpest cross-language contract.
//!
//! # Why this module is not in [`crate::config`]
//!
//! Its Python original is not in `config.py` either. It lives at
//! `src/agentcage/data/proxy/relays/_validate.py`, and its docstring
//! says why:
//!
//! > Lives under `data/proxy/relays/` so both sides of the trust
//! > boundary import the same code: the CLI imports it as
//! > `agentcage.data.proxy.relays._validate`; the proxy container
//! > imports it as `relays._validate` (the proxy ships in its own image
//! > without the CLI package on the path).
//!
//! That arrangement does not survive the port. Rust cannot import a
//! Python module, and `data/proxy/**` stays Python forever
//! (RUST-PORT-PLAN.md, scope decision), so the proxy keeps importing
//! `_validate.py` and the host reads this file instead. **One
//! implementation became two, and they have to agree forever.**
//!
//! They disagree cheaply: these error strings are what
//! `agentcage cage create` prints. Two validators that refuse the same
//! config with different wording — or report a *different one* of two
//! problems first — send an operator round in circles.
//!
//! # The oracle is neither implementation
//!
//! `tests/fixtures/contracts/validate_relay_entry.json` (PR A4) holds
//! 107 `(entry, ok, error)` cases covering every `raise ValueError`
//! branch in `_validate.py`, plus six `order-*` cases pinning which of
//! two problems is reported first. pytest asserts the Python against
//! it; `tests/contract_relay_entry.rs` asserts this module against it.
//!
//! `host == proxy` cannot be written across a language boundary, and it
//! also passes when both sides drift *together*. `host == fixture` and
//! `proxy == fixture` survives the split and catches the joint drift.
//! So if this module and `_validate.py` ever disagree, the fixture says
//! which one moved — and neither is automatically right.
//!
//! # Faithfulness
//!
//! Everything here is Python semantics, not Rust's, and the awkward
//! parts are the point:
//!
//! - `entry.get("name", "")` followed by `if not (name and ...)` is
//!   *Python truthiness* over the raw YAML value, so `name: 0` is
//!   missing and `name: 123` is present. [`crate::yaml::python_bool`].
//! - `int(port)` truncates a float and swallows its own exception into
//!   `port = 0`, so `993.7` is a valid port and `0.5` is not.
//! - `bool(tls)` makes the *string* `"false"` truthy, so
//!   `tls: "false"` leaves TLS on. That is a bug, and it is reproduced
//!   rather than fixed: it fails safe, and a port is not the place to
//!   change what an existing config means.
//! - `x or ""` runs *before* the `isinstance` check, so `ca_file: 0`
//!   is an empty path and `ca_file: 1` is a type error.
//!
//! The comments on each refusal are ported with it. They explain *why*
//! a config is refused rather than accepted with a precedence rule, and
//! those reasons outlive the language.
//!
//! # Dependency-free, like its original
//!
//! `_validate.py` is "intentionally dependency-free apart from stdlib
//! so it loads cleanly in the proxy environment". The same restraint
//! applies here: this module reaches for [`crate::yaml`] and
//! [`crate::python`] and nothing in [`crate::config`] but its error
//! type. In particular [`coerce_port`] spells out CPython's `int()`
//! itself rather than borrowing the config parser's, which keeps the
//! boundary module readable next to the Python without a detour
//! through a parser the proxy side has no counterpart for.

use std::borrow::Cow;

use crate::config::ConfigError;
use crate::python::{repr, str_of, type_name};
use crate::yaml::{Mapping, Value, python_bool};

/// `KNOWN_RELAY_TYPES` — the protocols a relay can speak.
///
/// Sorted, because [`validate_relay_type`]'s message renders
/// `", ".join(sorted(KNOWN_RELAY_TYPES))` and the set is user-visible
/// there. Pinned by `shared_constants.json`.
pub const KNOWN_RELAY_TYPES: [&str; 2] = ["imap", "smtp"];

/// `_WRITE_MODES` — the IMAP write policy.
///
/// "organise" permits filing and flagging but refuses anything that
/// destroys mail — see `relays/imap.py`. Sorted for the same reason as
/// [`KNOWN_RELAY_TYPES`], and pinned by `shared_constants.json`.
pub const WRITE_MODES: [&str; 3] = ["full", "none", "organise"];

/// What a `source_validator` hook is.
///
/// `_validate.py` takes source-scheme validation as an optional
/// callable because the canonical validator
/// (`agentcage.secret_resolver.validate_source`) is not importable
/// inside the proxy container. The host passes it; the proxy passes
/// `None`.
///
/// It is `FnMut` so a test can record the arguments it receives —
/// which the fixture pins, in order, as `source_validator_calls`.
pub type SourceValidator<'a> = &'a mut dyn FnMut(&str) -> Result<(), ConfigError>;

/// `validate_relay_type` — the `type:` key.
///
/// # Errors
///
/// [`ConfigError::Value`] when the name is not one of
/// [`KNOWN_RELAY_TYPES`].
pub fn validate_relay_type(name: &str) -> Result<(), ConfigError> {
    if KNOWN_RELAY_TYPES.contains(&name) {
        return Ok(());
    }
    Err(ConfigError::value(format!(
        "unknown protocol_relays type: '{name}'. Valid: {}",
        KNOWN_RELAY_TYPES.join(", ")
    )))
}

/// Validate one `protocol_relays` YAML entry.
///
/// `source_validator` is called for `auth.user_source` and
/// `auth.password_source` if provided; pass `None` from contexts (like
/// the proxy container) where the canonical validator is not
/// importable.
///
/// # Errors
///
/// [`ConfigError::Value`] on any structural problem, with the message
/// `_validate.py` would have raised, byte for byte.
// The checks are in one function, in `_validate.py`'s order, for the
// same reason `config::parse::load` is one function: the order is
// observable. An entry with two problems reports whichever check comes
// first, and six `order-*` fixture cases exist only to pin that.
#[allow(clippy::too_many_lines)]
pub fn validate_relay_entry(
    entry: &Value,
    mut source_validator: Option<SourceValidator<'_>>,
) -> Result<(), ConfigError> {
    let Value::Mapping(entry) = entry else {
        return Err(ConfigError::value(format!(
            "protocol_relays entry must be a mapping (got {})",
            type_name(entry)
        )));
    };

    // `entry.get(key, "")`: an absent key is the empty string, an
    // explicit null is None, and both are falsy. The repr in the
    // message is of whatever was actually there, so a missing `listen`
    // reads `listen=''` and an explicit `listen: null` reads
    // `listen=None` — the operator can tell which mistake they made.
    let empty = Value::String(String::new());
    let name = entry.get("name").unwrap_or(&empty);
    let rtype = entry.get("type").unwrap_or(&empty);
    let listen = entry.get("listen").unwrap_or(&empty);
    if !(python_bool(name) && python_bool(rtype) && python_bool(listen)) {
        return Err(ConfigError::value(format!(
            "protocol_relays entry requires name/type/listen (got name={}, type={}, listen={})",
            repr(name),
            repr(rtype),
            repr(listen)
        )));
    }

    // `validate_relay_type(rtype)` is handed the raw value, and its
    // message interpolates it with `str()` inside literal quotes
    // rather than with `repr()`. So a `type: 123` reads `'123'`.
    validate_relay_type(&str_of(rtype))?;

    // Every path from here names the relay — `protocol_relays[mail]` —
    // because a config with three relays has to say which one. `str()`
    // again, not `repr()`: no quotes around the name.
    let at = format!("protocol_relays[{}]", str_of(name));

    // ── upstream ────────────────────────────────────────
    let upstream = falsy_to_empty_mapping(entry.get("upstream"), &format!("{at}.upstream"))?;
    // `str()` on whatever is there would turn `host: [1]` into the
    // string "[1]", which is non-empty and therefore "present" — a
    // config that validates and then fails DNS resolution with a name
    // nobody wrote. A string or nothing; anything else is named.
    let host = match upstream.get("host") {
        // A falsy host is the empty string, type unexamined: `host: 0`
        // and `host: []` both mean "absent" and get the
        // requires-host-and-port message, not a type complaint.
        Some(value) if python_bool(value) => match value {
            Value::String(text) => text.clone(),
            other => {
                return Err(ConfigError::value(format!(
                    "{at}.upstream.host must be a string (got {})",
                    type_name(other)
                )));
            }
        },
        _ => String::new(),
    };
    // `port: "993"` and `port: 993.7` coerce on purpose — YAML makes
    // both easy to write and both mean a port. `port: true` does not:
    // `bool` is an `int` subclass in Python, so it coerced to **1** and
    // named a port the operator never wrote.
    if matches!(upstream.get("port"), Some(Value::Bool(_))) {
        return Err(ConfigError::value(format!(
            "{at}.upstream.port must be a number (got bool) — note that YAML reads bare yes/no/on/off as booleans; quote the port if you meant a number"
        )));
    }
    let port = coerce_port(upstream.get("port"));
    if host.is_empty() || !(1..=65535).contains(&port) {
        return Err(ConfigError::value(format!(
            "{at}.upstream requires host and port in [1, 65535]"
        )));
    }

    // `bool(upstream.get("tls", True))`, not `is True`: the string
    // `"false"` is truthy, so `tls: "false"` leaves TLS ON. Wrong, and
    // wrong in the safe direction, so it is reproduced. See
    // `crate::yaml::python_bool`.
    let tls = upstream.get("tls").is_none_or(python_bool);
    let ca_file = falsy_to_empty_string(
        upstream.get("ca_file"),
        &format!("{at}.upstream.ca_file must be a path string"),
    )?;
    let ca_pem = falsy_to_empty_string(
        upstream.get("ca_pem"),
        &format!("{at}.upstream.ca_pem must be a PEM string"),
    )?;
    if !ca_pem.is_empty() && !ca_pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(ConfigError::value(format!(
            "{at}.upstream.ca_pem does not look like PEM — expected a \
             '-----BEGIN CERTIFICATE-----' block. To point at a file on disk, use \
             upstream.ca_file."
        )));
    }
    // ca_file is the operator-facing form; the CLI reads it and hands the
    // proxy the resolved ca_pem. Both set at once is ambiguous about
    // which one wins, so say so instead of picking silently.
    if !ca_file.is_empty() && !ca_pem.is_empty() {
        return Err(ConfigError::value(format!(
            "{at}.upstream sets both ca_file and ca_pem; use one. ca_file is read at \
             deploy time and becomes ca_pem in the proxy's config."
        )));
    }
    let servername = falsy_to_empty_string(
        upstream.get("tls_servername"),
        &format!("{at}.upstream.tls_servername must be a string"),
    )?;
    // These only mean something on a TLS connection. Silently ignoring
    // them on a plaintext upstream would read as "the certificate is
    // verified" in a config review when nothing is verified at all.
    if !tls {
        for (key, value) in [
            ("ca_file", &ca_file),
            ("ca_pem", &ca_pem),
            ("tls_servername", &servername),
        ] {
            if !value.is_empty() {
                return Err(ConfigError::value(format!(
                    "{at}.upstream.{key} requires upstream.tls: true (got tls: false, \
                     which connects in plaintext and verifies nothing)"
                )));
            }
        }
    }

    // ── policy ──────────────────────────────────────────
    //
    // `upstream` refuses a non-mapping outright; `policy` guarded with
    // `isinstance` and no else branch, so a mistyped `policy:` — a
    // list, a bare string — skipped every check below it in silence,
    // `write_mode` included. The relay then reached `policy.get(...)`
    // on a list and died with an `AttributeError` naming nothing. This
    // is the block that gates writes to a mailbox; both sides of the
    // boundary now say so.
    //
    // Falsy stays "absent": `policy: null` and `policy: []` normalise
    // to `{}` through `or {}` before the type is ever examined, so
    // only a *truthy* non-mapping is an error.
    match entry.get("policy") {
        Some(value) if python_bool(value) && !matches!(value, Value::Mapping(_)) => {
            return Err(ConfigError::value(format!(
                "{at}.policy must be a mapping (got {})",
                type_name(value)
            )));
        }
        _ => {}
    }
    if let Some(policy) = mapping_or_skip(entry.get("policy")) {
        let mode = policy.get("write_mode");
        if let Some(mode) = mode.filter(|value| !matches!(value, Value::Null)) {
            let lowered = match mode {
                Value::String(text) => {
                    let lowered = text.to_lowercase();
                    WRITE_MODES
                        .contains(&lowered.as_str())
                        .then_some(lowered)
                        .ok_or(())
                }
                _ => Err(()),
            };
            let Ok(lowered) = lowered else {
                return Err(ConfigError::value(format!(
                    "{at}.policy.write_mode must be one of {} (got {})",
                    WRITE_MODES.join(", "),
                    repr(mode)
                )));
            };
            // readonly is the older spelling of the same thing. Both set and
            // disagreeing is ambiguous, and guessing which the operator meant
            // is exactly the wrong call for a policy that gates writes.
            if let Some(readonly) = policy.get("readonly") {
                let implied = if python_bool(readonly) {
                    "none"
                } else {
                    "full"
                };
                if implied != lowered {
                    return Err(ConfigError::value(format!(
                        "{at}.policy sets readonly={} and write_mode={}, which contradict. \
                         Use write_mode alone.",
                        repr(readonly),
                        repr(mode)
                    )));
                }
            }
        }
        for key in ["folder_allowlist", "folder_denylist"] {
            match policy.get(key) {
                None | Some(Value::Null | Value::Sequence(_)) => {}
                Some(other) => {
                    return Err(ConfigError::value(format!(
                        "{at}.policy.{key} must be a list (got {})",
                        type_name(other)
                    )));
                }
            }
        }
    }

    // ── auth ────────────────────────────────────────────
    let auth = falsy_to_empty_mapping(entry.get("auth"), &format!("{at}.auth"))?;
    if let Some(validate_source) = source_validator.as_mut() {
        for key in ["user_source", "password_source"] {
            match auth.get(key) {
                Some(value) if python_bool(value) => validate_source(&str_of(value))?,
                _ => {}
            }
        }
    }

    Ok(())
}

// ── helpers ─────────────────────────────────────────────

/// `x.get(key) or {}`, then `isinstance(..., dict)`.
///
/// The `or {}` runs first, so a falsy value — absent, null, `0`, `[]`,
/// `{}` — is an empty mapping and only a *truthy* non-mapping is
/// refused. `message` is the full sentence bar the mapping clause,
/// because the two callers word it identically and neither carries a
/// `(got X)` suffix.
fn falsy_to_empty_mapping<'a>(
    value: Option<&'a Value>,
    at: &str,
) -> Result<Cow<'a, Mapping>, ConfigError> {
    match value {
        Some(value) if python_bool(value) => match value {
            Value::Mapping(mapping) => Ok(Cow::Borrowed(mapping)),
            _ => Err(ConfigError::value(format!("{at} must be a mapping"))),
        },
        _ => Ok(Cow::Owned(Mapping::new())),
    }
}

/// `str` where `x.get(key, "") or ""` came first.
///
/// The ordering is what makes `ca_file: 0` an empty path and
/// `ca_file: 1` a type error: `0 or ""` is `""`, which is a `str`, and
/// the `isinstance` check never sees the integer. Reproducing it means
/// testing truthiness *before* the type.
fn falsy_to_empty_string(value: Option<&Value>, sentence: &str) -> Result<String, ConfigError> {
    match value {
        Some(value) if python_bool(value) => match value {
            Value::String(text) => Ok(text.clone()),
            other => Err(ConfigError::value(format!(
                "{sentence} (got {})",
                type_name(other)
            ))),
        },
        _ => Ok(String::new()),
    }
}

/// `x.get("policy") or {}` followed by `if isinstance(policy, dict)`.
///
/// The caller refuses a truthy non-mapping before this runs, so what
/// reaches here is a mapping or a falsy value that means "absent".
fn mapping_or_skip(value: Option<&Value>) -> Option<&Mapping> {
    match value {
        Some(Value::Mapping(mapping)) => Some(mapping),
        _ => None,
    }
}

/// `int(upstream.get("port", 0) or 0)`, with the `except` arm folded in.
///
/// `_validate.py` catches `TypeError` and `ValueError` and sets
/// `port = 0`, which then fails the range check — so every conversion
/// failure produces the same "requires host and port" message rather
/// than a type complaint. Anything this returns outside `[1, 65535]`
/// means the same thing.
///
/// The truncation is CPython's: `int(993.7)` is 993 and `int(0.5)` is
/// 0, so a fractional port is silently floored toward zero and only
/// the sub-one case is refused. Both are fixture cases
/// (`ok-port-float-truncates`, `err-port-float-sub-one`).
fn coerce_port(value: Option<&Value>) -> i64 {
    // `or 0` first: a falsy port is 0 and never reaches `int()`.
    let Some(value) = value.filter(|value| python_bool(value)) else {
        return 0;
    };
    match value {
        // Unreachable: the caller refuses `port: true` by type before
        // coercion, because `int(True)` is 1 and a relay pointed at
        // port 1 is never what the operator wrote. Kept so this
        // function still totals `int()` on its own.
        Value::Bool(_) => 1,
        Value::Number(number) => number
            .as_i64()
            .or_else(|| {
                number
                    .as_u64()
                    .and_then(|unsigned| i64::try_from(unsigned).ok())
            })
            .unwrap_or_else(|| {
                let float = number.as_f64().unwrap_or(f64::NAN);
                if float.is_finite() {
                    #[allow(clippy::cast_possible_truncation)]
                    let truncated = float.trunc() as i64;
                    truncated
                } else {
                    // `int(float('inf'))` is an OverflowError, which is
                    // neither TypeError nor ValueError — so Python would
                    // propagate it rather than fall back to 0. No YAML
                    // scalar reaches here (`.inf` is a float and PyYAML
                    // resolves it, but a relay port written `.inf` is not
                    // a config anyone has); 0 keeps the refusal loud.
                    0
                }
            }),
        // CPython's `int(str)`: surrounding whitespace, an optional
        // sign, decimal digits with underscores *between* digits.
        // Anything else is the ValueError that becomes 0.
        Value::String(text) => parse_python_int(text).unwrap_or(0),
        // `int(list)` / `int(dict)` is a TypeError -> 0.
        _ => 0,
    }
}

/// CPython's `int(str)` in base 10.
///
/// Shares its rules with `config::parse`'s copy and is written out
/// again here rather than shared, so this module stays as
/// self-contained as the Python one it mirrors.
fn parse_python_int(text: &str) -> Option<i64> {
    let trimmed = text.trim();
    if trimmed.is_empty()
        || trimmed.contains("__")
        || trimmed.starts_with('_')
        || trimmed.ends_with('_')
        || trimmed.contains("-_")
        || trimmed.contains("+_")
    {
        return None;
    }
    trimmed.replace('_', "").parse::<i64>().ok()
}

#[cfg(test)]
mod tests {
    use super::{KNOWN_RELAY_TYPES, WRITE_MODES, validate_relay_entry, validate_relay_type};
    use crate::config::ConfigError;
    use crate::yaml::load;

    fn check(document: &str) -> Result<(), ConfigError> {
        validate_relay_entry(&load(document).expect("yaml"), None)
    }

    fn message(document: &str) -> String {
        check(document)
            .expect_err("should refuse")
            .message()
            .to_owned()
    }

    /// The sets render in the order their messages promise.
    #[test]
    fn the_user_visible_sets_are_sorted() {
        let mut sorted = KNOWN_RELAY_TYPES;
        sorted.sort_unstable();
        assert_eq!(KNOWN_RELAY_TYPES, sorted);
        let mut sorted = WRITE_MODES;
        sorted.sort_unstable();
        assert_eq!(WRITE_MODES, sorted);
    }

    #[test]
    fn a_known_type_passes_and_an_unknown_one_names_the_valid_set() {
        assert!(validate_relay_type("imap").is_ok());
        assert_eq!(
            validate_relay_type("pop3")
                .expect_err("should refuse")
                .message(),
            "unknown protocol_relays type: 'pop3'. Valid: imap, smtp"
        );
    }

    /// The YAML path, which the JSON fixture cannot reach.
    ///
    /// `tls: no` is `False` to PyYAML and to `crate::yaml::load`, and
    /// `tls: 'no'` is the string — which `bool()` says is True. The
    /// fixture is JSON and has no way to write either, so this is the
    /// only place the two spellings meet the validator.
    #[test]
    fn yaml_1_1_booleans_reach_the_tls_check() {
        let base = "name: mail\ntype: imap\nlisten: 127.0.0.1:11143\nupstream:\n  \
                    host: imap.example.com\n  port: 993\n  tls_servername: bridge.internal\n  ";
        assert_eq!(
            message(&format!("{base}tls: no\n")),
            "protocol_relays[mail].upstream.tls_servername requires upstream.tls: true \
             (got tls: false, which connects in plaintext and verifies nothing)"
        );
        // Quoted, so a string, so truthy, so TLS stays on.
        assert!(check(&format!("{base}tls: 'no'\n")).is_ok());
    }

    /// The coercions in front of the `raise` branches.
    ///
    /// The fixture reaches every `raise`, but coverage of the branches
    /// is not coverage of the coercions ahead of them, and three of
    /// those coercions used to accept input no operator meant. Each
    /// expectation below is measured against `_validate.py` on CPython
    /// 3.13 rather than reasoned about — the two sides of this trust
    /// boundary have to agree exactly, and the fixture is regenerated
    /// from the same run.
    ///
    /// | Input | Now |
    /// | :-- | :-- |
    /// | `port: true` | refused — `int(True)` was 1, a valid port |
    /// | `host: [1]` | refused — `str([1] or "")` was the text `[1]`, non-empty, so the host looked present |
    /// | `policy: [..]` / `policy: none` | refused — the `isinstance` guard had no else branch, so a mistyped policy skipped the whole block, `write_mode` included |
    /// | `host: 0` | still "absent", not a type error: truthiness before type |
    /// | `ca_file: 0` | still accepted — `0 or ""` is `""`, so the `isinstance` check never sees the integer |
    ///
    /// The last two are the ordering this validator has always used for
    /// `ca_file`/`ca_pem`, and the new host check follows it rather
    /// than inventing a second convention.
    #[test]
    fn the_coercions_in_front_of_the_raise_branches() {
        let relay = |extra: &str| {
            format!(
                "name: mail\ntype: imap\nlisten: 'a:1'\nupstream:\n  host: h\n  port: 993\n{extra}"
            )
        };
        assert_eq!(
            message("name: mail\ntype: imap\nlisten: 'a:1'\nupstream:\n  host: h\n  port: true\n"),
            "protocol_relays[mail].upstream.port must be a number (got bool) — note that \
             YAML reads bare yes/no/on/off as booleans; quote the port if you meant a number"
        );
        assert_eq!(
            message("name: mail\ntype: imap\nlisten: 'a:1'\nupstream:\n  host: [1]\n  port: 993\n"),
            "protocol_relays[mail].upstream.host must be a string (got list)"
        );
        // ... but a falsy host is "absent", type unexamined.
        assert_eq!(
            message("name: mail\ntype: imap\nlisten: 'a:1'\nupstream:\n  host: 0\n  port: 993\n"),
            "protocol_relays[mail].upstream requires host and port in [1, 65535]"
        );
        assert_eq!(
            message(&relay("policy:\n- 'write_mode: bogus'\n")),
            "protocol_relays[mail].policy must be a mapping (got list)"
        );
        assert_eq!(
            message(&relay("policy: none\n")),
            "protocol_relays[mail].policy must be a mapping (got str)"
        );
        // Falsy is "absent" here too, so an empty list is `{}`.
        assert!(check(&relay("policy: []\n")).is_ok());
        // `0 or ""` is a str, so the type check never fires.
        assert!(check(&relay("  ca_file: 0\n")).is_ok());
        assert!(check(&relay("  ca_file: {}\n")).is_ok());
    }

    /// A non-string `type:` reaches the message as `str()`, not
    /// `repr()` — the quotes in `'{name}'` are literal.
    ///
    /// No fixture case covers this: the fixture's `type` values are all
    /// strings.
    #[test]
    fn a_numeric_type_renders_without_a_second_pair_of_quotes() {
        assert_eq!(
            message("name: mail\ntype: 123\nlisten: 'a:1'\n"),
            "unknown protocol_relays type: '123'. Valid: imap, smtp"
        );
    }

    /// The source hook sees both keys, in order, `str()`-coerced.
    #[test]
    fn the_source_validator_hook_receives_both_keys() {
        let document = load(
            "name: mail\ntype: imap\nlisten: 'a:1'\nupstream:\n  host: h\n  port: 1\n\
             auth:\n  user_source: env:U\n  password_source: env:P\n",
        )
        .expect("yaml");
        let mut seen: Vec<String> = Vec::new();
        let mut record = |source: &str| {
            seen.push(source.to_owned());
            Ok(())
        };
        validate_relay_entry(&document, Some(&mut record)).expect("valid");
        assert_eq!(seen, ["env:U", "env:P"]);
    }

    /// A hook that raises stops the validation with its own message.
    #[test]
    fn the_source_validator_hooks_error_propagates() {
        let document = load(
            "name: mail\ntype: imap\nlisten: 'a:1'\nupstream:\n  host: h\n  port: 1\n\
             auth:\n  user_source: vault:U\n",
        )
        .expect("yaml");
        let mut refuse =
            |source: &str| Err(ConfigError::value(format!("unknown scheme in {source}")));
        assert_eq!(
            validate_relay_entry(&document, Some(&mut refuse))
                .expect_err("should refuse")
                .message(),
            "unknown scheme in vault:U"
        );
    }
}
