//! `os.path.expanduser` and `os.path.expandvars`, as CPython means them.
//!
//! One caller today — `resolve_relay_ca_files` does
//! `Path(os.path.expanduser(os.path.expandvars(str(ca_file))))` on the
//! operator's `upstream.ca_file` — but the semantics are worth having
//! exactly right rather than approximately, because the two functions
//! both have a *leave it alone* branch that a naive version turns into
//! an empty string:
//!
//! * `expandvars("$NOPE/x")` is `"$NOPE/x"`, not `"/x"`. An unset
//!   variable is left literally in place, so a typo'd
//!   `ca_file: $CERTDIR/ca.pem` fails with a path the operator can
//!   recognise instead of one they cannot.
//! * `expanduser("~build/x")` with no such user is `"~build/x"`.
//!
//! The one deliberate divergence is that `~user` is never expanded
//! here, only `~` and `~/...`. CPython reaches `pwd.getpwnam`, which
//! needs libc, and the workspace forbids `unsafe`. Leaving the path
//! untouched is CPython's own behaviour when the lookup *fails*, so a
//! `~otheruser` path degrades to "no such user" rather than to
//! something wrong — and no agentcage config in the repo, the corpus or
//! the state fixture uses one.

use std::path::PathBuf;

/// `os.path.expandvars` — substitute `$name` and `${name}` from the
/// process environment.
#[must_use]
pub fn expandvars(text: &str) -> String {
    expandvars_with(text, &|name| std::env::var(name).ok())
}

/// [`expandvars`] against a caller-supplied environment.
///
/// The environment is a parameter because the workspace forbids
/// `unsafe`, and since Rust 2024 `std::env::set_var` is `unsafe` — so
/// a test cannot plant a variable to check the substitution branch.
/// Threading the lookup through is the only way that branch is
/// reachable, and it is the better shape anyway: the substitution rule
/// is pure, and only the caller has an opinion about where names come
/// from.
///
/// CPython's `posixpath.expandvars` matches `\$(\w+|\{[^}]*\})` with
/// the ASCII flag, so `\w` is `[A-Za-z0-9_]`, and an unmatched or unset
/// name is copied through verbatim.
#[must_use]
pub fn expandvars_with(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    if !text.contains('$') {
        return text.to_owned();
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            // Copy one UTF-8 character, not one byte: `$` and `{` are
            // ASCII, so scanning byte-wise is safe, but the copy has to
            // respect character boundaries.
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
                i += 1;
            }
            out.push_str(&text[start..i]);
            continue;
        }
        // `\$(\w+|\{[^}]*\})`, in that order: braces only match when
        // they close.
        let rest = &text[i + 1..];
        let (name, consumed) = if let Some(stripped) = rest.strip_prefix('{') {
            // The braced alternative matches only when the brace
            // closes: `expandvars("${unclosed")` is `"${unclosed"`.
            let Some(end) = stripped.find('}') else {
                out.push('$');
                i += 1;
                continue;
            };
            // `$`, `{`, the name, `}` -- the whole `${name}`.
            (&stripped[..end], end + 3)
        } else {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            if end == 0 {
                // A bare `$`, or `$-`: no match, emit and move on.
                out.push('$');
                i += 1;
                continue;
            }
            (&rest[..end], end + 1)
        };
        match lookup(name) {
            Some(value) => out.push_str(&value),
            // `except KeyError: i = j` — the whole match is kept.
            None => out.push_str(&text[i..i + consumed]),
        }
        i += consumed;
    }
    out
}

/// `os.path.expanduser` for `~` and `~/...`.
///
/// `home` is what `$HOME` resolved to — [`crate::Paths::home`], so a
/// test's sandbox home is honoured rather than the developer's real
/// one. Trailing slashes are stripped from it, as CPython does, and a
/// bare `~` with an empty home yields `/`.
#[must_use]
pub fn expanduser(text: &str, home: &std::path::Path) -> PathBuf {
    let Some(rest) = text.strip_prefix('~') else {
        return PathBuf::from(text);
    };
    // `i = path.find('/', 1)`: anything between the `~` and the first
    // slash is a username, which is not expanded here.
    if !rest.is_empty() && !rest.starts_with('/') {
        return PathBuf::from(text);
    }
    let home = home.to_string_lossy();
    let home = home.trim_end_matches('/');
    let joined = format!("{home}{rest}");
    if joined.is_empty() {
        return PathBuf::from("/");
    }
    PathBuf::from(joined)
}

#[cfg(test)]
mod tests {
    use super::{expanduser, expandvars, expandvars_with};
    use std::path::{Path, PathBuf};

    #[test]
    fn an_unset_variable_is_left_alone() {
        assert_eq!(
            expandvars("$AGENTCAGE_NO_SUCH_VAR/ca.pem"),
            "$AGENTCAGE_NO_SUCH_VAR/ca.pem"
        );
        assert_eq!(
            expandvars("${AGENTCAGE_NO_SUCH_VAR}/ca.pem"),
            "${AGENTCAGE_NO_SUCH_VAR}/ca.pem"
        );
    }

    #[test]
    fn a_lone_dollar_and_an_unclosed_brace_survive() {
        assert_eq!(expandvars("cost: $"), "cost: $");
        assert_eq!(expandvars("$-x"), "$-x");
        assert_eq!(expandvars("${unclosed"), "${unclosed");
        assert_eq!(expandvars("no variables here"), "no variables here");
    }

    #[test]
    fn a_set_variable_is_substituted_in_both_spellings() {
        let env = |name: &str| (name == "CERTDIR").then(|| "/certs".to_owned());
        assert_eq!(expandvars_with("$CERTDIR/ca.pem", &env), "/certs/ca.pem");
        assert_eq!(expandvars_with("${CERTDIR}/ca.pem", &env), "/certs/ca.pem");
        assert_eq!(
            expandvars_with("a${CERTDIR}b$CERTDIR", &env),
            "a/certsb/certs"
        );
        // `${}` is a legal match with an empty name, which is never set.
        assert_eq!(expandvars_with("${}", &env), "${}");
        // A non-ASCII tail is copied a character at a time, not a byte.
        assert_eq!(expandvars_with("café/$CERTDIR", &env), "café//certs");
    }

    #[test]
    fn tilde_expands_against_the_home_it_is_given() {
        let home = Path::new("/home/agentcage-fixture");
        assert_eq!(
            expanduser("~/fixture-ca.pem", home),
            PathBuf::from("/home/agentcage-fixture/fixture-ca.pem")
        );
        assert_eq!(
            expanduser("~", home),
            PathBuf::from("/home/agentcage-fixture")
        );
        assert_eq!(
            expanduser("/absolute/ca.pem", home),
            PathBuf::from("/absolute/ca.pem")
        );
        // A trailing slash on HOME does not double up.
        assert_eq!(
            expanduser("~/x", Path::new("/home/luca/")),
            PathBuf::from("/home/luca/x")
        );
    }

    #[test]
    fn a_username_is_left_for_the_filesystem_to_reject() {
        assert_eq!(
            expanduser("~build/ca.pem", Path::new("/home/luca")),
            PathBuf::from("~build/ca.pem")
        );
    }
}
