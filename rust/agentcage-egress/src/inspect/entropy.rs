//! The Shannon entropy inspector (opt-in).
//!
//! Encrypted or compressed data sits near 8 bits/byte, text and JSON
//! around 3.5–5.5, so a high-entropy outbound body is a strong hint of
//! exfiltration. Three checks, in order, the first hit wins:
//!
//! 1. the body (threshold 7.0, bodies under 256 bytes skipped, global and
//!    per-host content-type exemptions);
//! 2. each query parameter value (threshold 5.5, values under 64 bytes
//!    skipped), except parameters on the host's allowlist — CDN signature
//!    parameters are allowlisted by default;
//! 3. each path segment, with the URL threshold and minimum.
//!
//! A host whose parameter allowlist contains `"*"` skips both URL checks.
//!
//! The URL is split and its query decoded the way Python's
//! `urllib.parse.urlparse` / `parse_qs` do, so the same parameter names,
//! values and segments are measured.

use super::pyconf::{self, Num};
use super::{Action, Context, Inspector, Severity, Verdict, shannon_entropy};
use crate::config::Value;
use crate::json::Json;

/// The name verdicts and config sections use.
pub const NAME: &str = "entropy";

/// The built-in per-host URL parameter allowlist (CDN signatures).
const DEFAULT_HOST_URL_PARAM_ALLOWLIST: [(&str, &[&str]); 5] = [
    ("cloudfront.net", &["Policy", "Signature", "Key-Pair-Id"]),
    (
        "xethub.hf.co",
        &[
            "Policy",
            "Signature",
            "Key-Pair-Id",
            "X-Amz-Signature",
            "X-Amz-Credential",
        ],
    ),
    ("amazonaws.com", &["X-Amz-Signature", "X-Amz-Credential"]),
    ("storage.googleapis.com", &["X-Goog-Signature"]),
    ("blob.core.windows.net", &["sig", "se", "sp"]),
];

/// The entropy inspector.
#[derive(Clone, Debug, PartialEq)]
pub struct EntropyInspector {
    threshold: Num,
    min_body_bytes: Num,
    action: Action,
    exempt_content_types: Vec<String>,
    host_exempt_content_types: Vec<(String, Vec<String>)>,
    check_url_params: bool,
    check_url_path: bool,
    url_threshold: Num,
    url_min_value_bytes: Num,
    /// Lowercased host → lowercased parameter names.
    host_url_param_allowlist: Vec<(String, Vec<String>)>,
}

impl EntropyInspector {
    /// Build from a config section; every default is the replaced
    /// implementation's. `host_url_param_allowlist` is merged shallowly
    /// over the built-in one: a key the operator repeats replaces the
    /// built-in list for that key.
    ///
    /// # Errors
    ///
    /// A key holds a value of the wrong type.
    pub fn from_config(section: &Value) -> Result<Self, String> {
        let map = pyconf::section(section, NAME)?;

        // `merged = dict(defaults); merged.update(user)`, then
        // `{h.lower(): {p.lower() for p in params}}` — keys merge before
        // lowercasing, and a later key that lowercases onto an earlier
        // one replaces it in place.
        let mut merged: indexmap::IndexMap<String, Vec<String>> = DEFAULT_HOST_URL_PARAM_ALLOWLIST
            .iter()
            .map(|(h, ps)| {
                (
                    (*h).to_owned(),
                    ps.iter().map(|p| (*p).to_owned()).collect(),
                )
            })
            .collect();
        match map.get("host_url_param_allowlist") {
            None => {}
            Some(Value::Mapping(user)) => {
                for (h, ps) in user {
                    let Value::String(h) = h else {
                        return Err(format!(
                            "{NAME}.host_url_param_allowlist keys must be host names"
                        ));
                    };
                    let ps =
                        pyconf::str_items(ps, &format!("{NAME}.host_url_param_allowlist.{h}"))?;
                    merged.insert(h.clone(), ps);
                }
            }
            Some(v) => {
                return Err(format!(
                    "{NAME}.host_url_param_allowlist must be a mapping (got {})",
                    agentcage_core::python::type_name(v)
                ));
            }
        }
        let mut allow: indexmap::IndexMap<String, Vec<String>> = indexmap::IndexMap::new();
        for (h, ps) in merged {
            allow.insert(
                h.to_lowercase(),
                ps.iter().map(|p| p.to_lowercase()).collect(),
            );
        }

        Ok(Self {
            threshold: pyconf::num(map, "threshold", Num::float(7.0), NAME)?,
            min_body_bytes: pyconf::num(map, "min_body_bytes", Num::int(256), NAME)?,
            action: super::content_type::action_of(&pyconf::string(map, "action", "block", NAME)?),
            exempt_content_types: pyconf::str_list(
                map,
                "exempt_content_types",
                &["image/", "application/gzip", "application/zip"],
                NAME,
            )?,
            host_exempt_content_types: pyconf::host_lists(map, "host_exempt_content_types", NAME)?,
            check_url_params: pyconf::flag(map, "check_url_params", true),
            check_url_path: pyconf::flag(map, "check_url_path", true),
            url_threshold: pyconf::num(map, "url_threshold", Num::float(5.5), NAME)?,
            url_min_value_bytes: pyconf::num(map, "url_min_value_bytes", Num::int(64), NAME)?,
            host_url_param_allowlist: allow.into_iter().collect(),
        })
    }

    fn verdict(&self, reason: String, metadata: Vec<(String, Json)>) -> Verdict {
        let mut v = Verdict::new(NAME, self.action, reason, Severity::Error);
        v.metadata = metadata;
        v
    }

    fn check_body(&self, ctx: &Context) -> Option<Verdict> {
        let entropy = ctx.body_entropy?;
        #[allow(clippy::cast_precision_loss)] // a body length, far below 2^53
        if (ctx.body_size as f64) < self.min_body_bytes.value {
            return None;
        }
        let ct = ctx.content_type.as_str();
        if self
            .exempt_content_types
            .iter()
            .any(|p| ct.starts_with(p.as_str()))
        {
            return None;
        }
        let host = ctx.host.to_lowercase();
        for (h, prefixes) in &self.host_exempt_content_types {
            if pyconf::host_matches(&host, h) && prefixes.iter().any(|p| ct.starts_with(p.as_str()))
            {
                return None;
            }
        }
        if entropy >= self.threshold.value {
            return Some(self.verdict(
                format!(
                    "high entropy body: {entropy:.2} (threshold {})",
                    self.threshold.text
                ),
                vec![
                    ("entropy".to_owned(), Json::Float(entropy)),
                    ("threshold".to_owned(), self.threshold.json.clone()),
                    (
                        "body_size".to_owned(),
                        Json::Int(i64::try_from(ctx.body_size).unwrap_or(i64::MAX)),
                    ),
                    ("content_type".to_owned(), Json::string(ct)),
                ],
            ));
        }
        None
    }

    /// Whether `value` is long enough to measure, as
    /// `len(value_bytes) >= url_min_value_bytes`.
    fn long_enough(&self, len: usize) -> bool {
        #[allow(clippy::cast_precision_loss)] // a URL component length
        let len = len as f64;
        len >= self.url_min_value_bytes.value
    }

    fn check_url_params(&self, ctx: &Context, url: &SplitUrl<'_>) -> Option<Verdict> {
        if !self.check_url_params || url.query.is_empty() {
            return None;
        }
        let host = ctx.host.to_lowercase();
        let mut allowed: Vec<&str> = Vec::new();
        for (h, params) in &self.host_url_param_allowlist {
            if pyconf::host_matches(&host, h) {
                allowed.extend(params.iter().map(String::as_str));
            }
        }
        if allowed.contains(&"*") {
            return None;
        }
        for (key, values) in parse_qs(url.query) {
            if allowed.contains(&key.to_lowercase().as_str()) {
                continue;
            }
            for val in values {
                let bytes = val.as_bytes();
                if !self.long_enough(bytes.len()) {
                    continue;
                }
                let ent = shannon_entropy(bytes);
                if ent >= self.url_threshold.value {
                    return Some(self.verdict(
                        format!(
                            "high entropy URL param '{key}': {ent:.2} (threshold {})",
                            self.url_threshold.text
                        ),
                        vec![
                            ("entropy".to_owned(), Json::Float(ent)),
                            ("url_threshold".to_owned(), self.url_threshold.json.clone()),
                            ("param".to_owned(), Json::string(&key)),
                            (
                                "param_length".to_owned(),
                                Json::Int(i64::try_from(bytes.len()).unwrap_or(i64::MAX)),
                            ),
                        ],
                    ));
                }
            }
        }
        None
    }

    fn check_url_path(&self, ctx: &Context, url: &SplitUrl<'_>) -> Option<Verdict> {
        if !self.check_url_path || url.path.is_empty() {
            return None;
        }
        let host = ctx.host.to_lowercase();
        for (h, params) in &self.host_url_param_allowlist {
            if pyconf::host_matches(&host, h) && params.iter().any(|p| p == "*") {
                return None;
            }
        }
        for segment in url.path.split('/') {
            if segment.is_empty() || !self.long_enough(segment.len()) {
                continue;
            }
            let ent = shannon_entropy(segment.as_bytes());
            if ent >= self.url_threshold.value {
                return Some(self.verdict(
                    format!(
                        "high entropy URL path segment: {ent:.2} (threshold {})",
                        self.url_threshold.text
                    ),
                    vec![
                        ("entropy".to_owned(), Json::Float(ent)),
                        ("url_threshold".to_owned(), self.url_threshold.json.clone()),
                        (
                            "segment_length".to_owned(),
                            Json::Int(i64::try_from(segment.len()).unwrap_or(i64::MAX)),
                        ),
                    ],
                ));
            }
        }
        None
    }
}

impl Inspector for EntropyInspector {
    fn name(&self) -> &str {
        NAME
    }

    fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
        if let Some(v) = self.check_body(ctx) {
            return Some(v);
        }
        if !self.check_url_params && !self.check_url_path {
            return None;
        }
        let cleaned = clean_url(&ctx.url);
        let url = match split_url(&cleaned) {
            Ok(url) => url,
            // `urlparse` raised, which escaped the inspector in the
            // replaced implementation (and the flow went through
            // unfiltered). Fail closed instead (D1).
            Err(e) => {
                return Some(Verdict::new(
                    NAME,
                    Action::Block,
                    format!("inspector {NAME} failed: {e}"),
                    Severity::Error,
                ));
            }
        };
        if let Some(v) = self.check_url_params(ctx, &url) {
            return Some(v);
        }
        self.check_url_path(ctx, &url)
    }
}

// ── urllib.parse, the parts used here ──────────────────────────

/// The path (params split off) and query of a URL.
#[derive(Debug, PartialEq, Eq)]
struct SplitUrl<'a> {
    path: &'a str,
    query: &'a str,
}

/// `urlsplit`'s input cleanup: leading C0 controls and spaces stripped,
/// every tab, CR and LF removed.
fn clean_url(url: &str) -> String {
    url.trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect()
}

/// Schemes `urlparse` splits `;params` off the path for.
const USES_PARAMS: [&str; 16] = [
    "", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtsps", "rtspu",
    "sip", "sips", "mms", "sftp", "tel",
];

/// `urlparse(url)` reduced to `(path, query)`, on an already
/// [`clean_url`]ed string.
fn split_url(url: &str) -> Result<SplitUrl<'_>, &'static str> {
    let mut rest = url;
    let mut scheme = String::new();
    if let Some(i) = rest.find(':') {
        let candidate = &rest[..i];
        let first_ok = candidate
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic());
        if i > 0
            && first_ok
            && candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            scheme = candidate.to_ascii_lowercase();
            rest = &rest[i + 1..];
        }
    }
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let netloc = &after[..end];
        if netloc.contains('[') != netloc.contains(']') {
            return Err("Invalid IPv6 URL");
        }
        rest = &after[end..];
    }
    if let Some(i) = rest.find('#') {
        rest = &rest[..i];
    }
    let (mut path, query) = rest.split_once('?').unwrap_or((rest, ""));
    if USES_PARAMS.contains(&scheme.as_str()) && path.contains(';') {
        // `_splitparams`: the first `;` after the last `/`, or the first
        // `;` at all when there is no `/`.
        let cut = match path.rfind('/') {
            Some(slash) => path[slash..].find(';').map(|j| slash + j),
            None => path.find(';'),
        };
        if let Some(cut) = cut {
            path = &path[..cut];
        }
    }
    Ok(SplitUrl { path, query })
}

/// `parse_qs(query, keep_blank_values=False)`: `&`-separated pairs, a
/// pair without `=` or with an empty value dropped, `+` as space, then
/// percent-decoding; values grouped under their name in first-seen order.
fn parse_qs(query: &str) -> Vec<(String, Vec<String>)> {
    let mut out: indexmap::IndexMap<String, Vec<String>> = indexmap::IndexMap::new();
    for pair in query.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        let name = unquote(&name.replace('+', " "));
        let value = unquote(&value.replace('+', " "));
        out.entry(name).or_default().push(value);
    }
    out.into_iter().collect()
}

/// `urllib.parse.unquote(s)` (UTF-8, `errors="replace"`).
///
/// Python decodes `%XX` only inside runs of ASCII characters, each run
/// decoded to text on its own; non-ASCII characters pass through. An
/// invalid escape stays literal.
fn unquote(s: &str) -> String {
    if !s.contains('%') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut run_start = None;
    for (i, c) in s.char_indices() {
        if c.is_ascii() {
            run_start.get_or_insert(i);
        } else {
            if let Some(start) = run_start.take() {
                out.push_str(&unquote_ascii(&s[start..i]));
            }
            out.push(c);
        }
    }
    if let Some(start) = run_start {
        out.push_str(&unquote_ascii(&s[start..]));
    }
    out
}

fn unquote_ascii(run: &str) -> String {
    let b = run.as_bytes();
    let mut bytes = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let (Some(hi), Some(lo)) = (
                b.get(i + 1).and_then(|c| (*c as char).to_digit(16)),
                b.get(i + 2).and_then(|c| (*c as char).to_digit(16)),
            ) {
                bytes.push(u8::try_from(hi * 16 + lo).unwrap_or_default());
                i += 3;
                continue;
            }
        }
        bytes.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlparse_splits_like_python() {
        let s = |u: &str| {
            let c = clean_url(u);
            split_url(&c).map(|x| (x.path.to_owned(), x.query.to_owned()))
        };
        let ok = |p: &str, q: &str| Ok((p.to_owned(), q.to_owned()));
        assert_eq!(s("https://h/a/b?x=1#f"), ok("/a/b", "x=1"));
        assert_eq!(s("https://h/a;p/b;q?x"), ok("/a;p/b", "x"));
        assert_eq!(s("https://h?x=1"), ok("", "x=1"));
        assert_eq!(s("https://h#a?b"), ok("", ""));
        assert_eq!(s("  https://h/a\tb"), ok("/ab", ""));
        assert_eq!(s("mailto:x;y"), ok("x;y", ""));
        assert_eq!(s("1http://h/p"), ok("1http://h/p", ""));
        assert_eq!(s("https://[::1/p"), Err("Invalid IPv6 URL"));
    }

    #[test]
    fn parse_qs_like_python() {
        assert_eq!(
            parse_qs("a=1&b&c=&a=2&&d=x+y%20z&e=%zz%4"),
            vec![
                ("a".to_owned(), vec!["1".to_owned(), "2".to_owned()]),
                ("d".to_owned(), vec!["x y z".to_owned()]),
                ("e".to_owned(), vec!["%zz%4".to_owned()]),
            ]
        );
        assert_eq!(unquote("%C3%A9é%C3"), "éé\u{fffd}");
    }
}
