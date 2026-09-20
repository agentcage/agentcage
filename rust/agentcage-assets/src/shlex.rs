//! Just enough of Python's `shlex.split(s)` to parse a `COPY` line.
//!
//! `egress_hash.egress_copy_sources` runs `shlex.split` over the tail of
//! every `COPY` instruction, and on `ValueError` skips the line. Which
//! sources a Containerfile contributes therefore depends on Python's
//! lexer, so this reproduces it rather than approximating it — the
//! egress content hash is a cross-language contract and "close enough"
//! is a divergent image tag.
//!
//! Scope: POSIX mode with `whitespace_split=True` and `comments=False`,
//! which is exactly what `shlex.split(s)` is. In particular `#` is an
//! ordinary character, unbalanced quotes and a trailing backslash are
//! errors, and inside double quotes a backslash escapes only `"` and
//! `\` — `"a\b"` lexes to `a\b`, not `ab`.

/// Characters Python's `shlex` treats as whitespace.
const WHITESPACE: [char; 4] = [' ', '\t', '\r', '\n'];

/// Split `input` the way `shlex.split(input)` does.
///
/// # Errors
///
/// Returns `Err` where Python raises `ValueError`: an unterminated quote
/// (`No closing quotation`) or a trailing backslash (`No escaped
/// character`). The caller's only use for the distinction is to skip the
/// line, so the error carries no payload.
pub fn split(input: &str) -> Result<Vec<String>, ShlexError> {
    let mut tokens = Vec::new();
    let mut token: Option<String> = None;
    let mut chars = input.chars();

    while let Some(c) = chars.next() {
        if WHITESPACE.contains(&c) {
            if let Some(done) = token.take() {
                tokens.push(done);
            }
            continue;
        }

        let buf = token.get_or_insert_with(String::new);
        match c {
            '\\' => buf.push(chars.next().ok_or(ShlexError)?),
            '\'' => {
                // Single quotes: everything is literal, including
                // backslashes, until the next single quote.
                loop {
                    match chars.next().ok_or(ShlexError)? {
                        '\'' => break,
                        other => buf.push(other),
                    }
                }
            }
            '"' => loop {
                match chars.next().ok_or(ShlexError)? {
                    '"' => break,
                    '\\' => {
                        // `escapedquotes = '"'`: inside double quotes the
                        // escape only applies to the quote and to itself.
                        // Anything else keeps the backslash.
                        let next = chars.next().ok_or(ShlexError)?;
                        if next != '"' && next != '\\' {
                            buf.push('\\');
                        }
                        buf.push(next);
                    }
                    other => buf.push(other),
                }
            },
            other => buf.push(other),
        }
    }

    if let Some(done) = token {
        tokens.push(done);
    }
    Ok(tokens)
}

/// Python's `ValueError` from `shlex.split`, with the message dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct ShlexError;

#[cfg(test)]
mod tests {
    use super::{ShlexError, split};

    fn ok(input: &str) -> Vec<String> {
        split(input).expect("lexes")
    }

    /// The cases measured against `CPython` 3.13's `shlex.split`.
    ///
    /// Each expectation here was produced by running the Python, not by
    /// reading the docs — `"a\b"` in particular does not do what a shell
    /// programmer expects.
    #[test]
    fn matches_cpython() {
        assert_eq!(ok("a b"), ["a", "b"]);
        assert_eq!(
            ok("COPY --chown=1:1 a b"),
            ["COPY", "--chown=1:1", "a", "b"]
        );
        assert_eq!(ok("a#b"), ["a#b"]);
        assert_eq!(ok(r#"a "b c" d"#), ["a", "b c", "d"]);
        assert_eq!(ok(r"a\ b"), ["a b"]);
        assert_eq!(ok("  a \t b  "), ["a", "b"]);
        assert_eq!(ok(""), Vec::<String>::new());
        assert_eq!(ok(r#""""#), [""]);
        assert_eq!(ok("''"), [""]);
        assert_eq!(ok(r"'a\b'"), [r"a\b"]);
        assert_eq!(ok(r#""a\b""#), [r"a\b"]);
        assert_eq!(ok(r#""a\"b""#), [r#"a"b"#]);
        assert_eq!(ok(r#""a\\b""#), [r"a\b"]);
        assert_eq!(ok("a'b'c"), ["abc"]);
    }

    /// Where Python raises, so does this — and the caller skips the line.
    #[test]
    fn raises_where_python_raises() {
        assert_eq!(split(r"a \"), Err(ShlexError));
        assert_eq!(split(r#"a "b"#), Err(ShlexError));
        assert_eq!(split("a 'b"), Err(ShlexError));
        assert_eq!(split(r#""a\"#), Err(ShlexError));
    }
}
