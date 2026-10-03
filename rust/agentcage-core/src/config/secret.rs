//! The three value checks `load_config` makes on a secret.
//!
//! Ported from `secret_resolver.validate_env_name` /
//! `validate_source` and `config.validate_transform`. They live together
//! here because they are the same kind of thing — a name or a scheme
//! checked against a closed set at parse time, so a typo surfaces on
//! `cage create` instead of as an empty credential at runtime — and
//! because two of them are reached from more than one place:
//! `validate_source` gates `secret_injection[].source` *and* a protocol
//! relay's `auth.user_source` / `auth.password_source` (PR C3 calls the
//! same function; the corpus case `err-relay-auth-source-scheme` is that
//! path), and `validate_env_name` guards a string that is later
//! interpolated into a generated quadlet `ExecStartPre` shell command.
//!
//! That last point is the security one. The POSIX identifier charset
//! contains no shell metacharacters, so a name that passes here cannot
//! inject into the command line agentcage builds around it. The check is
//! the boundary, not the quoting.

use super::ConfigError;
use super::types::KNOWN_TRANSFORMS;
use crate::python::repr_str;

type Checked = Result<(), ConfigError>;

/// `secret_resolver.KNOWN_SCHEMES`, minus the empty string.
///
/// The empty scheme is a member in Python because `validate_source`
/// returns early on an empty source; it is excluded from the message's
/// `Valid schemes:` list there with `KNOWN_SCHEMES - {""}` and sorted, so
/// this is that list already sorted.
pub const KNOWN_SOURCE_SCHEMES: [&str; 4] = ["cmd", "env", "podman", "systemd-creds"];

/// `secret_store.KNOWN_BACKENDS`, sorted.
///
/// `cage.yaml`'s `secrets.backend`. Sorted here because the error message
/// interpolates `", ".join(sorted(KNOWN_BACKENDS))` — it is a `frozenset`
/// in Python, so the sort is what makes the message deterministic.
pub const KNOWN_BACKENDS: [&str; 4] = ["auto", "keychain", "plaintext", "systemd-creds"];

/// `validate_env_name` — the name must be a safe POSIX identifier.
///
/// # Errors
///
/// [`ConfigError::Value`] when the name is empty or contains anything
/// outside `[A-Za-z_][A-Za-z0-9_]*`. The charset is the defence: the name
/// is interpolated into generated quadlet `ExecStartPre` bash commands,
/// and no character that survives this check is a shell metacharacter.
pub fn validate_env_name(env_name: &str) -> Checked {
    if env_name.is_empty() {
        return Err(ConfigError::value(
            "secret_injection rule requires a non-empty env name",
        ));
    }
    let bytes = env_name.as_bytes();
    let head_ok = bytes[0].is_ascii_alphabetic() || bytes[0] == b'_';
    let tail_ok = bytes[1..]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    if head_ok && tail_ok {
        return Ok(());
    }
    Err(ConfigError::value(format!(
        "invalid env name: {}. Must match [A-Za-z_][A-Za-z0-9_]*",
        repr_str(env_name)
    )))
}

/// `validate_source` — the `scheme:NAME` prefix must be one agentcage
/// knows.
///
/// An empty source is fine: it means "this rule names no source", which
/// the resolver handles elsewhere.
///
/// # Errors
///
/// [`ConfigError::Value`] for an unrecognised scheme, so a typo is caught
/// at config-parse time rather than materializing as an empty credential
/// at runtime.
pub fn validate_source(source: &str) -> Checked {
    if source.is_empty() {
        return Ok(());
    }
    // `source.partition(":")[0]` — everything before the first colon, or
    // the whole string when there is none.
    let scheme = source.split(':').next().unwrap_or(source);
    if KNOWN_SOURCE_SCHEMES.contains(&scheme) {
        return Ok(());
    }
    Err(ConfigError::value(format!(
        "unknown secret source scheme: '{scheme}'. Valid schemes: {}",
        KNOWN_SOURCE_SCHEMES.join(", ")
    )))
}

/// `validate_transform` — reject an unknown transform name at parse time.
///
/// # Errors
///
/// [`ConfigError::Value`] when the name is not in
/// [`KNOWN_TRANSFORMS`]. That set is the
/// schema's view of what the in-cage transforms registry can dispatch;
/// `validate_config` keeps a matching *warning* for the apple-container
/// backend, which is unreachable precisely because this check already
/// ran, and exists so a future divergence between the two surfaces
/// loudly rather than as a silent runtime drop.
pub fn validate_transform(name: &str) -> Checked {
    if name.is_empty() || KNOWN_TRANSFORMS.contains(&name) {
        return Ok(());
    }
    // `sorted(KNOWN_TRANSFORMS)`. The constant is already in sorted
    // order — it holds one element — but sort before joining so it stays
    // true when a second transform lands.
    let mut valid = KNOWN_TRANSFORMS.to_vec();
    valid.sort_unstable();
    Err(ConfigError::value(format!(
        "unknown secret_injection transform: '{name}'. Valid: {}",
        valid.join(", ")
    )))
}

/// `invalid secrets.scope: …` / `invalid secrets.backend: …`.
///
/// The two enum checks `load_config` makes on the `secrets:` section.
/// They take the already-stringified value because `config.py` applies
/// `str()` with no `or` fallback — an explicit `scope: null` becomes the
/// text `None` and the message reads `invalid secrets.scope: 'None'`.
///
/// # Errors
///
/// [`ConfigError::Value`] naming the field and listing the valid values.
pub fn validate_enum(field: &str, value: &str, valid: &[&str]) -> Checked {
    if valid.contains(&value) {
        return Ok(());
    }
    Err(ConfigError::value(format!(
        "invalid {field}: {}. Valid: {}",
        repr_str(value),
        valid.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::{validate_enum, validate_env_name, validate_source, validate_transform};
    use crate::config::types::VALID_SECRET_SCOPES;

    fn message(result: Result<(), crate::config::ConfigError>) -> String {
        result.expect_err("expected a refusal").message().to_owned()
    }

    #[test]
    fn env_names_are_posix_identifiers() {
        assert!(validate_env_name("GH_TOKEN").is_ok());
        assert!(validate_env_name("_private1").is_ok());
        assert_eq!(
            message(validate_env_name("not-a-valid-name")),
            "invalid env name: 'not-a-valid-name'. Must match [A-Za-z_][A-Za-z0-9_]*"
        );
        // A leading digit is the other half of the pattern.
        assert!(validate_env_name("1TOKEN").is_err());
        assert_eq!(
            message(validate_env_name("")),
            "secret_injection rule requires a non-empty env name"
        );
    }

    #[test]
    fn source_schemes_are_a_closed_set() {
        assert!(validate_source("").is_ok());
        assert!(validate_source("env:TOKEN").is_ok());
        assert!(validate_source("systemd-creds:TOKEN").is_ok());
        assert_eq!(
            message(validate_source("vault:TOKEN")),
            "unknown secret source scheme: 'vault'. Valid schemes: cmd, env, podman, systemd-creds"
        );
        // No colon at all: the whole string is the scheme.
        assert_eq!(
            message(validate_source("vault")),
            "unknown secret source scheme: 'vault'. Valid schemes: cmd, env, podman, systemd-creds"
        );
    }

    #[test]
    fn transforms_are_a_closed_set() {
        assert!(validate_transform("").is_ok());
        assert!(validate_transform("google-jwt-bearer").is_ok());
        assert_eq!(
            message(validate_transform("nope")),
            "unknown secret_injection transform: 'nope'. Valid: google-jwt-bearer"
        );
    }

    #[test]
    fn an_explicit_null_scope_reaches_the_message_as_the_text_none() {
        assert_eq!(
            message(validate_enum("secrets.scope", "None", &VALID_SECRET_SCOPES)),
            "invalid secrets.scope: 'None'. Valid: auto, user, system"
        );
    }
}
