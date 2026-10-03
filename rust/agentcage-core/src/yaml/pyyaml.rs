//! PyYAML's YAML 1.1 implicit resolver, transliterated.
//!
//! [`resolves_to_non_string`] answers one question: **if this exact text
//! appeared as a plain (unquoted) scalar, would `yaml.safe_load` give
//! back something other than a `str`?**
//!
//! That is the predicate the emitter needs. Everything a Rust YAML crate
//! emits plain is a YAML *1.2* plain scalar, and PyYAML resolves plain
//! scalars under YAML *1.1*. Where the two schemas disagree, the value
//! changes type as it crosses into the egress container — see the module
//! docs on [`super`] for what that costs.
//!
//! # Why a transliteration and not a guess list
//!
//! The hazard is not a list of tokens, it is a set of *patterns*. The
//! measurement that motivated this PR named `1:30`; but `12:00:00`,
//! `1:30:15`, `190:20:30`, `1:30.5` and `-1:30` are the same sexagesimal
//! rule, and `2024-01-02` is a timestamp rule nobody had looked for. A
//! hand-kept list of the tokens somebody happened to test is a list that
//! is wrong the first time a user names a header `<<`.
//!
//! So this is PyYAML's `resolver.py` implicit-resolver table, branch for
//! branch, with the regexes turned into scanners (no `regex` dependency:
//! this crate has none yet, and these six patterns do not need one). The
//! branches are transcribed from PyYAML 6.0's
//! `Resolver.add_implicit_resolver` calls:
//!
//! | Tag | Pattern source |
//! | :-- | :-- |
//! | `bool` | `yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF` |
//! | `float` | decimal-with-dot, `.5`, sexagesimal-with-dot, `±.inf`, `.nan` |
//! | `int` | `0b…`, `0…` octal, decimal, `0x…`, sexagesimal |
//! | `merge` | `<<` |
//! | `null` | `~`, `null`, `Null`, `NULL`, empty |
//! | `timestamp` | `YYYY-MM-DD` and the full date-time form |
//! | `value` | `=` |
//!
//! `merge` and `value` are the two that do not merely change type:
//! `safe_load` has no constructor for either tag and *raises*
//! `ConstructorError`. A relay header named `<<` written unquoted would
//! not corrupt the proxy's config, it would stop the proxy loading it at
//! all.
//!
//! The transcription is not trusted on its own. `tests/fixtures/
//! yaml_1_1_scalars.json` carries a corpus that exercises every branch
//! and its near misses, and `yaml_pyyaml_crossing.rs` feeds each entry to
//! a real `yaml.safe_load` and asserts this module agreed.
//!
//! # Deliberate omissions
//!
//! PyYAML's `bool` list does **not** include the bare `y`/`n` that the
//! YAML 1.1 spec allows, so neither does this. Checked against PyYAML
//! 6.0.3: `y`, `Y`, `n`, `N` load as strings. Adding them would quote
//! scalars PyYAML is perfectly happy with, which is harmless but would
//! make the emitter disagree with the fixture.

/// Every spelling PyYAML's `bool` resolver accepts.
///
/// Ordered as PyYAML lists them. The first six pairs are the YAML
/// 1.1-only spellings — the ones YAML 1.2 dropped, and therefore the
/// ones a Rust crate will happily emit unquoted.
const BOOL_SPELLINGS: &[(&str, bool)] = &[
    ("yes", true),
    ("Yes", true),
    ("YES", true),
    ("no", false),
    ("No", false),
    ("NO", false),
    ("on", true),
    ("On", true),
    ("ON", true),
    ("off", false),
    ("Off", false),
    ("OFF", false),
    ("true", true),
    ("True", true),
    ("TRUE", true),
    ("false", false),
    ("False", false),
    ("FALSE", false),
];

/// How many of [`BOOL_SPELLINGS`] are YAML 1.1-only.
///
/// The first twelve: `yes`/`no`/`on`/`off` in the three cases PyYAML
/// accepts. YAML 1.2 kept only `true`/`false`, so these twelve are
/// exactly the boolean spellings the two schemas disagree about.
const BOOL_SPELLINGS_1_1_ONLY: usize = 12;

/// Would `yaml.safe_load` resolve this plain scalar to something that is
/// not a `str`?
///
/// `true` covers both outcomes that matter: a silent type change
/// (`no` → `False`, `1:30` → `90`, `2024-01-02` → a `date`) and a hard
/// `ConstructorError` (`=`, `<<`).
#[must_use]
pub fn resolves_to_non_string(scalar: &str) -> bool {
    // Ordered by how cheap the check is, not by PyYAML's table order:
    // the predicate is an OR, so order is not observable.
    is_null(scalar)
        || is_bool(scalar).is_some()
        || is_value_or_merge(scalar)
        || is_int(scalar)
        || is_float(scalar)
        || is_timestamp(scalar)
}

/// The boolean this scalar spells for PyYAML, if any.
///
/// Covers all eighteen spellings, 1.1 and 1.2 alike.
#[must_use]
pub fn is_bool(scalar: &str) -> Option<bool> {
    BOOL_SPELLINGS
        .iter()
        .find(|(text, _)| *text == scalar)
        .map(|(_, value)| *value)
}

/// The boolean this scalar spells *only* under YAML 1.1.
///
/// `yes`/`Yes`/`YES`/`no`/`No`/`NO`/`on`/`On`/`ON`/`off`/`Off`/`OFF`, and
/// nothing else. `true` and `false` are excluded on purpose: a YAML 1.2
/// parser already resolves those to booleans, so a `Value::String` still
/// holding the *text* `"false"` got there by being quoted — and
/// `config.py:1255` exists specifically to reject that
/// (`bool("false")` is `True`, the trap its comment names). See
/// [`super::bool_1_1`] for where this is used and what it deliberately
/// does not do.
#[must_use]
pub fn is_bool_1_1_only(scalar: &str) -> Option<bool> {
    BOOL_SPELLINGS[..BOOL_SPELLINGS_1_1_ONLY]
        .iter()
        .find(|(text, _)| *text == scalar)
        .map(|(_, value)| *value)
}

/// PyYAML's `null` resolver: `~`, `null`, `Null`, `NULL`, or empty.
fn is_null(scalar: &str) -> bool {
    matches!(scalar, "" | "~" | "null" | "Null" | "NULL")
}

/// PyYAML's `value` (`=`) and `merge` (`<<`) resolvers.
///
/// Both tags exist in `SafeLoader`'s resolver table and in neither its
/// constructor table, so a plain `=` or `<<` makes `safe_load` raise.
fn is_value_or_merge(scalar: &str) -> bool {
    matches!(scalar, "=" | "<<")
}

/// Strip a leading `+` or `-`, reporting whether one was there.
fn strip_sign(scalar: &str) -> (&str, bool) {
    scalar
        .strip_prefix(['+', '-'])
        .map_or((scalar, false), |rest| (rest, true))
}

/// `[0-9_]+`, with at least one character.
fn digits_and_underscores(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit() || b == b'_')
}

/// `(?:0|[1-9][0-9_]*)` — PyYAML's plain decimal integer.
///
/// Note the leading-zero exclusion: `0755` does *not* match here, it
/// matches the octal branch, which is why PyYAML reads it as 493.
fn is_decimal_int(text: &str) -> bool {
    match text.as_bytes() {
        [b'0'] => true,
        [first, rest @ ..] if first.is_ascii_digit() && *first != b'0' => {
            rest.iter().all(|b| b.is_ascii_digit() || *b == b'_')
        }
        _ => false,
    }
}

/// The `(?::[0-5]?[0-9])+` tail shared by both sexagesimal branches.
///
/// `parts` is the text already split on `:`, minus the leading group.
fn sexagesimal_tail(parts: &[&str]) -> bool {
    !parts.is_empty()
        && parts.iter().all(|part| match part.as_bytes() {
            [only] => only.is_ascii_digit(),
            [tens, ones] => (b'0'..=b'5').contains(tens) && ones.is_ascii_digit(),
            _ => false,
        })
}

/// PyYAML's `int` resolver.
///
/// `0b[0-1_]+ | 0[0-7_]+ | (0|[1-9][0-9_]*) | 0x[0-9a-fA-F_]+ |
/// [1-9][0-9_]*(:[0-5]?[0-9])+`, each with an optional sign.
fn is_int(scalar: &str) -> bool {
    let (body, _) = strip_sign(scalar);
    if body.is_empty() {
        return false;
    }

    if let Some(bits) = body.strip_prefix("0b") {
        return !bits.is_empty() && bits.bytes().all(|b| matches!(b, b'0' | b'1' | b'_'));
    }
    if let Some(hex) = body.strip_prefix("0x") {
        return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit() || b == b'_');
    }
    if let Some(octal) = body.strip_prefix('0')
        && !octal.is_empty()
        && octal.bytes().all(|b| matches!(b, b'0'..=b'7' | b'_'))
    {
        return true;
    }
    if is_decimal_int(body) {
        return true;
    }

    // Sexagesimal: `1:30` is ninety minutes' worth of seconds to YAML
    // 1.1. The leading group is `[1-9][0-9_]*`, so `0:30` is not one.
    let mut groups = body.split(':');
    let Some(head) = groups.next() else {
        return false;
    };
    let head_ok = matches!(head.as_bytes(), [first, rest @ ..]
        if first.is_ascii_digit() && *first != b'0'
            && rest.iter().all(|b| b.is_ascii_digit() || *b == b'_'));
    head_ok && sexagesimal_tail(&groups.collect::<Vec<_>>())
}

/// PyYAML's `float` resolver.
///
/// Five branches, and the details of each matter:
/// - `[-+]?[0-9][0-9_]*\.[0-9_]*(?:[eE][-+][0-9]+)?` — the exponent's
///   sign is **mandatory**, which is why `1e3` is a string to PyYAML
///   even though every other YAML parser calls it a float.
/// - `\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?` — no sign allowed, so `-.5` is
///   a string.
/// - `[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*` — sexagesimal float.
///   Its leading group allows `0`, unlike the integer branch.
/// - `[-+]?\.(?:inf|Inf|INF)` and `\.(?:nan|NaN|NAN)`.
fn is_float(scalar: &str) -> bool {
    let (body, signed) = strip_sign(scalar);

    if matches!(body, ".inf" | ".Inf" | ".INF") {
        return true;
    }
    if !signed && matches!(body, ".nan" | ".NaN" | ".NAN") {
        return true;
    }

    // `.5`, `.5e+3` — unsigned only.
    if !signed
        && let Some(fraction) = body.strip_prefix('.')
        && let Some((digits, exponent)) = split_exponent(fraction)
        && matches!(digits.as_bytes(), [first, rest @ ..]
            if first.is_ascii_digit()
                && rest.iter().all(|b| b.is_ascii_digit() || *b == b'_'))
        && exponent_ok(exponent)
    {
        return true;
    }

    let Some((mantissa, exponent)) = split_exponent(body) else {
        return false;
    };
    let Some((whole, fraction)) = mantissa.split_once('.') else {
        return false;
    };
    // The fraction may be empty (`1.`) or all underscores; PyYAML's
    // `[0-9_]*` says so.
    if !fraction.bytes().all(|b| b.is_ascii_digit() || b == b'_') {
        return false;
    }

    // Sexagesimal float (`1:30.5`) carries no exponent in PyYAML's
    // pattern, so reject one here rather than in the shared tail.
    if whole.contains(':') {
        if exponent.is_some() {
            return false;
        }
        let mut groups = whole.split(':');
        let Some(head) = groups.next() else {
            return false;
        };
        return digits_and_underscores(head)
            && head.as_bytes()[0].is_ascii_digit()
            && sexagesimal_tail(&groups.collect::<Vec<_>>());
    }

    exponent_ok(exponent)
        && matches!(whole.as_bytes(), [first, rest @ ..]
            if first.is_ascii_digit()
                && rest.iter().all(|b| b.is_ascii_digit() || *b == b'_'))
}

/// Split `text` at its `e`/`E`, if it has one.
///
/// Returns `None` only when the text has more than one, which no branch
/// of PyYAML's float pattern allows.
fn split_exponent(text: &str) -> Option<(&str, Option<&str>)> {
    match text.split_once(['e', 'E']) {
        None => Some((text, None)),
        Some((mantissa, exponent)) if !exponent.contains(['e', 'E']) => {
            Some((mantissa, Some(exponent)))
        }
        Some(_) => None,
    }
}

/// `[-+][0-9]+` — PyYAML requires the sign on a float exponent.
fn exponent_ok(exponent: Option<&str>) -> bool {
    match exponent {
        None => true,
        Some(text) => match text.as_bytes() {
            [b'+' | b'-', digits @ ..] => {
                !digits.is_empty() && digits.iter().all(u8::is_ascii_digit)
            }
            _ => false,
        },
    }
}

/// PyYAML's `timestamp` resolver.
///
/// Two branches: a bare `YYYY-MM-DD` with fixed-width month and day, and
/// the full date-time form, which allows one-or-two-digit month, day and
/// hour, a `T`/`t`/space separator, an optional fractional second and an
/// optional `Z` or `±HH[:MM]` offset.
///
/// This is the branch the original measurement missed entirely. A relay
/// field, a header value or a domain-like string that happens to look
/// like a date comes back from `safe_load` as a `datetime.date`, and
/// everything downstream that expected `str` sees an object.
fn is_timestamp(scalar: &str) -> bool {
    let bytes = scalar.as_bytes();

    // `[0-9]{4}-[0-9]{2}-[0-9]{2}`
    if bytes.len() == 10
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..].iter().all(u8::is_ascii_digit)
    {
        return true;
    }

    // `[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}`, then the time part.
    let Some(rest) = split_fixed_digits(scalar, 4) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix('-') else {
        return false;
    };
    let Some(rest) = take_digits(rest, 1, 2) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix('-') else {
        return false;
    };
    let Some(rest) = take_digits(rest, 1, 2) else {
        return false;
    };

    // `(?:[Tt]|[ \t]+)`
    let rest = if let Some(after) = rest.strip_prefix(['T', 't']) {
        after
    } else {
        let after = rest.trim_start_matches([' ', '\t']);
        if after.len() == rest.len() {
            return false;
        }
        after
    };

    // `[0-9]{1,2}:[0-9]{2}:[0-9]{2}`
    let Some(rest) = take_digits(rest, 1, 2) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(':') else {
        return false;
    };
    let Some(rest) = take_digits(rest, 2, 2) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(':') else {
        return false;
    };
    let Some(rest) = take_digits(rest, 2, 2) else {
        return false;
    };

    // `(?:\.[0-9]*)?`
    let rest = match rest.strip_prefix('.') {
        None => rest,
        Some(fraction) => fraction.trim_start_matches(|c: char| c.is_ascii_digit()),
    };

    // `(?:[ \t]*(?:Z|[-+][0-9]{1,2}(?::[0-9]{2})?))?`
    let rest = rest.trim_start_matches([' ', '\t']);
    if rest.is_empty() {
        return true;
    }
    if rest == "Z" {
        return true;
    }
    let Some(offset) = rest.strip_prefix(['+', '-']) else {
        return false;
    };
    let Some(offset) = take_digits(offset, 1, 2) else {
        return false;
    };
    if offset.is_empty() {
        return true;
    }
    let Some(minutes) = offset.strip_prefix(':') else {
        return false;
    };
    take_digits(minutes, 2, 2).is_some_and(str::is_empty)
}

/// Drop exactly `count` leading ASCII digits, or `None` if they are not
/// all digits.
fn split_fixed_digits(text: &str, count: usize) -> Option<&str> {
    if text.len() < count || !text.as_bytes()[..count].iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(&text[count..])
}

/// Consume between `min` and `max` ASCII digits, returning the rest.
fn take_digits(text: &str, min: usize, max: usize) -> Option<&str> {
    let taken = text
        .bytes()
        .take(max)
        .take_while(u8::is_ascii_digit)
        .count();
    if taken < min {
        return None;
    }
    Some(&text[taken..])
}

#[cfg(test)]
mod tests {
    use super::{is_bool, is_bool_1_1_only, resolves_to_non_string};

    /// The twelve spellings the whole PR is about.
    #[test]
    fn the_1_1_only_booleans_are_the_twelve() {
        let expected = [
            ("yes", true),
            ("Yes", true),
            ("YES", true),
            ("no", false),
            ("No", false),
            ("NO", false),
            ("on", true),
            ("On", true),
            ("ON", true),
            ("off", false),
            ("Off", false),
            ("OFF", false),
        ];
        for (text, value) in expected {
            assert_eq!(is_bool_1_1_only(text), Some(value), "{text:?}");
            assert_eq!(is_bool(text), Some(value), "{text:?}");
            assert!(resolves_to_non_string(text), "{text:?}");
        }
        for text in ["true", "True", "TRUE", "false", "False", "FALSE"] {
            assert_eq!(
                is_bool_1_1_only(text),
                None,
                "{text:?} is a 1.2 spelling; quoting it means the user meant a string"
            );
            assert!(is_bool(text).is_some(), "{text:?}");
        }
    }

    /// PyYAML does not take the spec's bare `y`/`n`.
    #[test]
    fn single_letter_booleans_are_strings() {
        for text in ["y", "Y", "n", "N", "yEs", "nO", "oFF"] {
            assert_eq!(is_bool(text), None, "{text:?}");
            assert!(!resolves_to_non_string(text), "{text:?}");
        }
    }

    #[test]
    fn integers() {
        for text in [
            "0", "7", "-7", "+7", "1_000", "0755", "-0755", "0b1010", "0x1F", "0x_1f", "010",
        ] {
            assert!(resolves_to_non_string(text), "{text:?} should be an int");
        }
        for text in ["08080", "0o17", "1.2.3", "_1", "0x", "0b", "1-2", ""] {
            // The empty string is null, not an int, but it is still
            // non-string; check the others only.
            if text.is_empty() {
                continue;
            }
            assert!(
                !resolves_to_non_string(text),
                "{text:?} should stay a string"
            );
        }
    }

    #[test]
    fn sexagesimals() {
        for text in [
            "1:30",
            "12:00:00",
            "1:30:15",
            "190:20:30",
            "-1:30",
            "1:30.5",
            "0:30.5",
        ] {
            assert!(resolves_to_non_string(text), "{text:?} should be numeric");
        }
        for text in ["0:30", "1:60", "1:305", "12:34:56Z", ":30", "1:"] {
            assert!(
                !resolves_to_non_string(text),
                "{text:?} should stay a string"
            );
        }
    }

    #[test]
    fn floats() {
        for text in [
            "1.5", "-1.5", "1.", ".5", "1_000.5", "1.5e+3", ".inf", "-.inf", ".nan",
        ] {
            assert!(resolves_to_non_string(text), "{text:?} should be a float");
        }
        for text in ["1e3", "1.5e3", "-.5", "-.nan", ".", "1.2.3"] {
            assert!(
                !resolves_to_non_string(text),
                "{text:?} should stay a string"
            );
        }
    }

    #[test]
    fn timestamps() {
        for text in [
            "2024-01-02",
            "2024-01-02T03:04:05",
            "2024-01-02 03:04:05",
            "2024-1-2t3:04:05.5Z",
            "2024-01-02 03:04:05.123 +05:30",
            "2024-01-02T03:04:05-07",
        ] {
            assert!(resolves_to_non_string(text), "{text:?} should be a date");
        }
        for text in [
            "2024-1-2",
            "2024-01-02T03:04",
            "24-01-02",
            "2024-01-02T03:04:05+",
            "2024-01-02Z",
        ] {
            assert!(
                !resolves_to_non_string(text),
                "{text:?} should stay a string"
            );
        }
    }

    #[test]
    fn nulls_values_and_merges() {
        for text in ["", "~", "null", "Null", "NULL", "=", "<<"] {
            assert!(resolves_to_non_string(text), "{text:?}");
        }
        for text in ["nil", "None", "NuLL", "<<<", "=="] {
            assert!(!resolves_to_non_string(text), "{text:?}");
        }
    }

    /// The scalars agentcage actually puts in YAML: domains, header
    /// names, relay fields, secret keys. None of them may be quoted by
    /// accident, or every config in the repo grows quotes.
    #[test]
    fn ordinary_config_scalars_are_left_alone() {
        for text in [
            "api.anthropic.com",
            "claude-code",
            "ANTHROPIC_API_KEY",
            "imap",
            "read-only",
            "1.2.3",
            "v0.40.1",
            "/workspace",
            "sha256:abc",
            "no-cache",
            "yes-man",
            "On-Behalf-Of",
        ] {
            assert!(
                !resolves_to_non_string(text),
                "{text:?} must not be quoted; it is an ordinary string"
            );
        }
    }
}
