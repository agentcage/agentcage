//! `urlparse` + `parse_qs`, narrowed to the query string.
//!
//! `_build_query_string` only ever wants one field of the parse, so this
//! skips the scheme/netloc/path split and reproduces the two steps that
//! decide where the query starts and what it contains:
//!
//! 1. `urlsplit` strips leading C0-control-or-space characters, removes
//!    every tab, CR and LF *anywhere* in the URL, then takes the
//!    fragment off at the first `#` and the query at the first `?` of
//!    what is left. (Scheme and netloc cannot contain either character,
//!    so skipping them changes nothing.)
//! 2. `parse_qs(keep_blank_values=True)` splits on `&`, drops empty
//!    fields, splits each one at its first `=`, turns `+` into a space,
//!    percent-decodes with UTF-8 and `errors="replace"`, then groups the
//!    values under their key.
//!
//! That grouping is the part worth spelling out. `parse_qs` returns a
//! dict, and `_build_query_string` walks it key by key, so
//! `a=1&b=2&a=3` comes out as `a=1, a=3, b=2` — *not* in pair order.

/// Every leading character `urlsplit` strips: U+0000 through U+0020.
const C0_CONTROL_OR_SPACE: &[char] = &[
    '\u{0}', '\u{1}', '\u{2}', '\u{3}', '\u{4}', '\u{5}', '\u{6}', '\u{7}', '\u{8}', '\u{9}',
    '\u{a}', '\u{b}', '\u{c}', '\u{d}', '\u{e}', '\u{f}', '\u{10}', '\u{11}', '\u{12}', '\u{13}',
    '\u{14}', '\u{15}', '\u{16}', '\u{17}', '\u{18}', '\u{19}', '\u{1a}', '\u{1b}', '\u{1c}',
    '\u{1d}', '\u{1e}', '\u{1f}', ' ',
];

/// The query parameters of `url`, as `(name, value)` pairs in the order
/// `_build_query_string` emits them.
#[must_use]
pub fn query_pairs(url: &str) -> Vec<(String, String)> {
    let query = extract_query(url);
    group_by_key(parse_pairs(&query))
}

/// `urlsplit(url).query`.
fn extract_query(url: &str) -> String {
    let sanitized: String = url
        .trim_start_matches(C0_CONTROL_OR_SPACE)
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let without_fragment = sanitized.split('#').next().unwrap_or("");
    without_fragment
        .split_once('?')
        .map_or_else(String::new, |(_, query)| query.to_string())
}

/// `parse_qsl(query, keep_blank_values=True)`.
fn parse_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|field| !field.is_empty())
        .map(|field| {
            // `str.partition("=")`: everything after the *first* `=`
            // is the value, and a field with no `=` has an empty one.
            let (name, value) = field.split_once('=').unwrap_or((field, ""));
            (unquote_plus(name), unquote_plus(value))
        })
        .collect()
}

/// `parse_qs`'s dict: first appearance fixes a key's position, and its
/// values follow in the order they were seen.
fn group_by_key(pairs: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut keys: Vec<String> = Vec::new();
    let mut grouped: Vec<Vec<String>> = Vec::new();
    for (name, value) in pairs {
        if let Some(index) = keys.iter().position(|k| *k == name) {
            grouped[index].push(value);
        } else {
            keys.push(name);
            grouped.push(vec![value]);
        }
    }
    keys.into_iter()
        .zip(grouped)
        .flat_map(|(name, values)| values.into_iter().map(move |v| (name.clone(), v)))
        .collect()
}

/// `unquote_plus(s, errors="replace")`.
///
/// `+` becomes a space, then `%XX` becomes a byte. Python decodes each
/// run of percent-decoded bytes as UTF-8 with replacement, so a
/// multi-byte character split across escapes still comes back whole and
/// an invalid sequence becomes U+FFFD; anything that is not a valid
/// escape — `%zz`, a trailing `%` — is left as the literal text it is.
fn unquote_plus(text: &str) -> String {
    let text = text.replace('+', " ");
    if !text.contains('%') {
        return text;
    }
    let mut out = String::new();
    let mut bytes: Vec<u8> = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if ch == '%' {
            if let Some(byte) = text
                .get(index + 1..index + 3)
                .filter(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                bytes.push(byte);
                chars.next();
                chars.next();
                continue;
            }
            bytes.push(b'%');
            continue;
        }
        if ch.is_ascii() {
            bytes.push(ch as u8);
        } else {
            // A non-ASCII character ends the byte run, exactly where
            // Python's `_asciire` split would end it.
            flush(&mut out, &mut bytes);
            out.push(ch);
        }
    }
    flush(&mut out, &mut bytes);
    out
}

fn flush(out: &mut String, bytes: &mut Vec<u8>) {
    if !bytes.is_empty() {
        out.push_str(&String::from_utf8_lossy(bytes));
        bytes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::query_pairs;

    /// Each expectation is `_build_query_string(url)` read off `CPython`.
    #[test]
    fn matches_python_for_the_shapes_the_corpus_misses() {
        let cases: &[(&str, &[(&str, &str)])] = &[
            (
                "https://a/b?key=val&page=2",
                &[("key", "val"), ("page", "2")],
            ),
            // Grouped by key, so the repeat jumps ahead of `b`.
            (
                "http://x/?a=1&b=2&a=3",
                &[("a", "1"), ("a", "3"), ("b", "2")],
            ),
            ("http://x/?a=1&a=1", &[("a", "1"), ("a", "1")]),
            // `keep_blank_values=True`, so a bare name survives.
            ("http://x/?flag", &[("flag", "")]),
            ("http://x/?a=", &[("a", "")]),
            ("http://x/?=v", &[("", "v")]),
            ("http://x/?a=b%20c&d=e+f", &[("a", "b c"), ("d", "e f")]),
            // A broken escape stays literal.
            ("http://x/?%zz=1&%=2", &[("%zz", "1"), ("%", "2")]),
            (
                "http://x/?a=%E6%97%A5%E6%9C%AC",
                &[("a", "\u{65e5}\u{672c}")],
            ),
            // Invalid UTF-8 becomes U+FFFD, `errors="replace"`.
            ("http://x/?a=%ff", &[("a", "\u{fffd}")]),
            // The fragment comes off first, so this URL has no query.
            ("http://x/#frag?a=1", &[]),
            ("http://x/?a=1#f=2", &[("a", "1")]),
            // Empty fields are dropped.
            ("http://x/?&&a=1&&", &[("a", "1")]),
            // Leading C0-or-space is stripped and tabs/newlines are
            // removed from anywhere in the URL.
            ("  \u{1}http://x/?a=1", &[("a", "1")]),
            ("http://x/?a\t=1\n2", &[("a", "12")]),
            ("", &[]),
            ("http://x/", &[]),
        ];
        for (url, expected) in cases {
            let expected: Vec<(String, String)> = expected
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect();
            assert_eq!(query_pairs(url), expected, "for {url:?}");
        }
    }
}
