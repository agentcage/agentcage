//! The content-type mismatch inspector.
//!
//! A body declared as text (JSON, XML, `text/*`, form data) that is
//! actually high-entropy, or that carries a large base64 blob, is a
//! common way to disguise exfiltration as ordinary API traffic. On by
//! default; `content_type: false` turns it off.

use std::sync::LazyLock;

use regex::Regex;

use super::pyconf::{self, Num};
use super::{Action, Context, Inspector, Severity, Verdict};
use crate::config::Value;
use crate::json::Json;

/// The name verdicts and config sections use.
pub const NAME: &str = "content-type";

/// Content-type prefixes treated as text.
const TEXT_CT_PREFIXES: [&str; 5] = [
    "application/json",
    "application/xml",
    "text/",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
];

/// `^[A-Za-z0-9+/=\-_\s]{64,}$` with `re.MULTILINE`. Python's `\s` in a
/// `str` pattern also matches U+001C–U+001F, which the `regex` crate's
/// Unicode `\s` does not, so they are added to the class explicitly. The
/// rest is a regular language, so the leftmost-first match the `regex`
/// crate finds is the one Python's backtracking search finds.
static BASE64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!("(?m)^[{BASE64_CLASS}]{{64,}}$")).expect("static pattern compiles")
});

/// The base64 scan's character class (without brackets).
pub(crate) const BASE64_CLASS: &str = r"A-Za-z0-9+/=\-_\s\x1C-\x1F";

/// Map a configured `action` string to a verdict action: `"block"`
/// blocks, anything else flags (the pipeline treats every non-`block`
/// verdict as a flag).
pub(crate) fn action_of(action: &str) -> Action {
    if action == "block" {
        Action::Block
    } else {
        Action::Flag
    }
}

/// The content-type mismatch inspector.
#[derive(Clone, Debug, PartialEq)]
pub struct ContentTypeInspector {
    entropy_ceiling: Num,
    detect_base64: bool,
    base64_min_len: Num,
    action: Action,
    host_exempt_content_types: Vec<(String, Vec<String>)>,
}

impl ContentTypeInspector {
    /// Build from a config section. Defaults: `entropy_ceiling` 6.5,
    /// `detect_base64` true, `base64_min_len` 256, `action` block, no
    /// host exemptions.
    ///
    /// # Errors
    ///
    /// A key holds a value of the wrong type.
    pub fn from_config(section: &Value) -> Result<Self, String> {
        let map = pyconf::section(section, NAME)?;
        Ok(Self {
            entropy_ceiling: pyconf::num(map, "entropy_ceiling", Num::float(6.5), NAME)?,
            detect_base64: pyconf::flag(map, "detect_base64", true),
            base64_min_len: pyconf::num(map, "base64_min_len", Num::int(256), NAME)?,
            action: action_of(&pyconf::string(map, "action", "block", NAME)?),
            host_exempt_content_types: pyconf::host_lists(map, "host_exempt_content_types", NAME)?,
        })
    }
}

impl Inspector for ContentTypeInspector {
    fn name(&self) -> &str {
        NAME
    }

    fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
        let text = ctx.body_text.as_deref().filter(|t| !t.is_empty())?;
        let ct = ctx.content_type.as_str();
        if ct.is_empty() || !TEXT_CT_PREFIXES.iter().any(|p| ct.starts_with(p)) {
            return None;
        }
        let host = ctx.host.to_lowercase();
        for (h, prefixes) in &self.host_exempt_content_types {
            if pyconf::host_matches(&host, h) && prefixes.iter().any(|p| ct.starts_with(p.as_str()))
            {
                return None;
            }
        }

        if let Some(entropy) = ctx.body_entropy {
            if entropy > self.entropy_ceiling.value {
                let mut v = Verdict::new(
                    NAME,
                    self.action,
                    format!(
                        "content-type mismatch: {ct} declared but body entropy is {entropy:.2} (expected <{})",
                        self.entropy_ceiling.text
                    ),
                    Severity::Error,
                );
                v.metadata = vec![
                    ("content_type".to_owned(), Json::string(ct)),
                    ("entropy".to_owned(), Json::Float(entropy)),
                    ("ceiling".to_owned(), self.entropy_ceiling.json.clone()),
                ];
                return Some(v);
            }
        }

        if self.detect_base64 {
            if let Some(m) = BASE64_RE.find(text) {
                // `len(match.group())`: code points.
                let len = m.as_str().chars().count();
                #[allow(clippy::cast_precision_loss)] // a body length, far below 2^53
                let long_enough = len as f64 >= self.base64_min_len.value;
                if long_enough {
                    let mut v = Verdict::new(
                        NAME,
                        self.action,
                        format!("large base64 blob ({len} chars) in {ct} body"),
                        Severity::Warning,
                    );
                    v.metadata = vec![
                        ("content_type".to_owned(), Json::string(ct)),
                        (
                            "base64_length".to_owned(),
                            Json::Int(i64::try_from(len).unwrap_or(i64::MAX)),
                        ),
                    ];
                    return Some(v);
                }
            }
        }
        None
    }
}
