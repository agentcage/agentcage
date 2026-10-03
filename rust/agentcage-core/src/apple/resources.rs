//! `_normalize_cpus` / `_normalize_memory` — Apple's `container run`
//! is stricter than podman about both.
//!
//! Two small functions with one shared rule: a value that does not
//! match the shape they know is **passed through unchanged**, so
//! operator novelty reaches Apple's own error reporting rather than
//! being silently mangled into something that runs.

/// `_normalize_cpus` — Apple's `--cpus` rejects a fraction, so ceil it.
///
/// Podman takes `0.5` and `1.5`; Apple wants `1` and `2`. Rounding
/// **up** is deliberate: the value is a cap the operator wrote, and a
/// cage that gets slightly more than asked is a better failure than one
/// that gets less. A value that is already integral keeps its integer
/// form (`2.0` → `2`), and one that does not parse as a float is
/// returned as it came in.
#[must_use]
pub fn normalize_cpus(value: &str) -> String {
    // `float(value)` — Python accepts surrounding whitespace, a sign,
    // and `inf`/`nan` spellings; `str::parse::<f64>` accepts the same
    // set, which is why this is a parse rather than a hand-written
    // scan.
    let Ok(parsed) = value.trim().parse::<f64>() else {
        return value.to_owned();
    };
    // `int(f)` raises on a non-finite float, and the Python would
    // propagate that. Here there is no exception to propagate and a
    // panicking cast would be worse than Apple's own complaint, so a
    // non-finite value takes the pass-through branch.
    if !parsed.is_finite() {
        return value.to_owned();
    }
    #[allow(clippy::cast_possible_truncation)]
    let truncated = parsed.trunc();
    if (parsed - truncated).abs() > 0.0 {
        format!("{}", parsed.ceil())
    } else {
        format!("{truncated}")
    }
}

/// `_normalize_memory` — Apple's `--memory` wants an UPPERCASE suffix.
///
/// `512m` and `2g`, which podman and docker take, are rejected. The
/// suffix is uppercased in place; everything that does not match
/// `<number><suffix?>` is passed through, so a raw byte count still
/// reaches Apple unchanged.
///
/// The accepted shape is the Python's regex,
/// `^(\d+(?:\.\d+)?)\s*([kKmMgGtTpP][iI]?[bB]?)?\Z`, hand-written
/// because this crate carries no regex engine. Note what that pattern
/// allows and this therefore allows too: whitespace *between* the
/// number and the suffix (`512 m`), which collapses on output.
#[must_use]
pub fn normalize_memory(value: &str) -> String {
    let trimmed = value.trim();
    let rest = trimmed;

    // `\d+(?:\.\d+)?` — ASCII digits only. Python's `\d` on a `str`
    // matches Unicode decimal digits as well, but `int`/`float` would
    // then accept them and Apple would not; no config in the corpus
    // reaches that, and narrowing to ASCII here is the safer of the
    // two divergences.
    let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    if digits == 0 {
        return value.to_owned();
    }
    let (integer, rest) = rest.split_at(digits);
    let (fraction, rest) = match rest.strip_prefix('.') {
        Some(after) => {
            let count = after.len() - after.trim_start_matches(|c: char| c.is_ascii_digit()).len();
            if count == 0 {
                // `123.` — the regex needs at least one digit after
                // the dot, so the whole value is unmatched.
                return value.to_owned();
            }
            let (digits, rest) = after.split_at(count);
            (Some(digits), rest)
        }
        None => (None, rest),
    };

    // `\s*` between the number and the suffix.
    let rest = rest.trim_start_matches(char::is_whitespace);

    // `([kKmMgGtTpP][iI]?[bB]?)?` and then `\Z`.
    let Some(suffix) = parse_suffix(rest) else {
        return value.to_owned();
    };

    let number = match fraction {
        Some(fraction) => format!("{integer}.{fraction}"),
        None => integer.to_owned(),
    };
    format!("{number}{}", suffix.to_uppercase())
}

/// `[kKmMgGtTpP][iI]?[bB]?` anchored to the end, or `None` when the
/// remainder is not that.
fn parse_suffix(rest: &str) -> Option<&str> {
    if rest.is_empty() {
        return Some(rest);
    }
    let mut chars = rest.char_indices();
    let (_, unit) = chars.next()?;
    if !matches!(
        unit,
        'k' | 'K' | 'm' | 'M' | 'g' | 'G' | 't' | 'T' | 'p' | 'P'
    ) {
        return None;
    }
    let mut consumed = unit.len_utf8();
    if let Some((_, next)) = chars.next() {
        let mut next = next;
        if matches!(next, 'i' | 'I') {
            consumed += next.len_utf8();
            match chars.next() {
                Some((_, after)) => next = after,
                None => return Some(rest),
            }
        }
        if matches!(next, 'b' | 'B') {
            consumed += next.len_utf8();
        }
    }
    // `\Z` — anything left over means the value did not match.
    if consumed == rest.len() {
        Some(rest)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_cpus, normalize_memory};

    #[test]
    fn a_fractional_cpu_count_is_ceiled() {
        assert_eq!(normalize_cpus("0.5"), "1");
        assert_eq!(normalize_cpus("1.5"), "2");
        assert_eq!(normalize_cpus("2.0"), "2");
        assert_eq!(normalize_cpus("4"), "4");
    }

    #[test]
    fn an_unparseable_cpu_count_is_passed_through() {
        assert_eq!(normalize_cpus("all"), "all");
        assert_eq!(normalize_cpus(""), "");
        // Non-finite: `int(float('inf'))` raises in Python, and a cast
        // here would saturate silently. Pass-through instead.
        assert_eq!(normalize_cpus("inf"), "inf");
    }

    #[test]
    fn a_lowercase_memory_suffix_is_uppercased() {
        assert_eq!(normalize_memory("512m"), "512M");
        assert_eq!(normalize_memory("2g"), "2G");
        assert_eq!(normalize_memory("2G"), "2G");
        assert_eq!(normalize_memory("1gi"), "1GI");
        assert_eq!(normalize_memory("1gib"), "1GIB");
        assert_eq!(normalize_memory("1.5g"), "1.5G");
        assert_eq!(normalize_memory("4096"), "4096");
    }

    /// The `\s*` the pattern allows, and the whitespace `.strip()`
    /// removes around the whole value.
    #[test]
    fn whitespace_collapses_the_way_the_pattern_says() {
        assert_eq!(normalize_memory("  512m  "), "512M");
        assert_eq!(normalize_memory("512 m"), "512M");
    }

    #[test]
    fn an_unmatched_memory_value_is_passed_through() {
        assert_eq!(normalize_memory("512mb-ish"), "512mb-ish");
        assert_eq!(normalize_memory("half"), "half");
        assert_eq!(normalize_memory("512."), "512.");
        assert_eq!(normalize_memory(".5g"), ".5g");
        assert_eq!(normalize_memory("512x"), "512x");
        assert_eq!(normalize_memory(""), "");
    }
}
