//! The secret / credential leak inspector.
//!
//! Scans the URL, every header value and the body text for 20 built-in
//! credential patterns plus the operator's `extra_patterns`. A match is
//! let through when the request goes to that credential's own API
//! (`allow_to_domains`, with built-in defaults such as `anthropic_key` →
//! `anthropic.com`). Bodies declared binary (images, audio, video,
//! octet-stream, PDF) are not scanned — random bytes match patterns by
//! accident — but their URL and headers still are.
//!
//! The default action on HTTP is **flag**. Protocol relays block by
//! default instead (an email body is a deliberate exfiltration channel),
//! unless the operator set `action` explicitly: that is what
//! [`SecretsInspector::action_explicit`] and [`RelaySecrets`] are for.

use std::sync::{Arc, LazyLock};

use agentcage_core::python::type_name;
use indexmap::IndexMap;
use regex::Regex;

use super::pyconf;
use super::{Action, Context, Inspector, Severity, Verdict};
use crate::config::{Mapping, Value, truthy};
use crate::json::Json;

/// The name verdicts and config sections use.
pub const NAME: &str = "secrets";

/// The built-in patterns, in scan order. `brave_api_key` is matched by
/// [`brave_match`] instead: its boundaries are a lookbehind and a
/// lookahead, which the `regex` crate does not support.
const BUILTIN_PATTERNS: [(&str, &str); 20] = [
    (
        "openai_key",
        r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,250}T3BlbkFJ[A-Za-z0-9_-]{20,250}",
    ),
    (
        "anthropic_key",
        r"sk-ant-(?:api|admin)\d+-[a-zA-Z0-9_-]{20,250}",
    ),
    ("aws_access_key", r"AKIA[A-Z2-7]{16}"),
    ("github_token", r"gh[ps]_[A-Za-z0-9]{36}"),
    ("github_pat", r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"),
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("google_oauth_access_token", r"ya29\.[A-Za-z0-9_-]{50,}"),
    (
        "slack_token",
        r"xox[bpors]-[0-9]{10,20}-[a-zA-Z0-9-]{1,255}",
    ),
    ("stripe_key", r"[sr]k_(live|test)_[0-9a-zA-Z]{24,255}"),
    ("private_key", r"-----BEGIN[ A-Z]{0,20}PRIVATE KEY-----"),
    ("gitlab_token", r"glpat-[A-Za-z0-9\-_]{20,255}"),
    ("huggingface_token", r"hf_[a-zA-Z]{34}"),
    ("databricks_token", r"dapi[0-9a-f]{32}"),
    (
        "azure_jwt",
        r"eyJ[A-Za-z0-9_-]{50,4096}\.eyJ[A-Za-z0-9_-]{50,4096}",
    ),
    ("openrouter_key", r"sk-or-v1-[a-f0-9]{64}"),
    ("perplexity_key", r"pplx-[a-zA-Z0-9]{48}"),
    ("brave_api_key", ""),
    ("telegram_bot_token", r"[0-9]{5,16}:[A-Za-z0-9_-]{35}"),
    (
        "discord_bot_token",
        r"[MNO][A-Za-z0-9_-]{23,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,255}",
    ),
    ("firecrawl_key", r"fc-[a-f0-9]{32}"),
];

/// Where each built-in credential may legitimately go.
const BUILTIN_ALLOW_TO_DOMAINS: [(&str, &[&str]); 18] = [
    ("openai_key", &["openai.com"]),
    ("anthropic_key", &["anthropic.com"]),
    ("aws_access_key", &["amazonaws.com"]),
    ("github_token", &["github.com", "githubusercontent.com"]),
    ("github_pat", &["github.com", "githubusercontent.com"]),
    ("google_api_key", &["googleapis.com", "google.com"]),
    (
        "google_oauth_access_token",
        &["googleapis.com", "google.com"],
    ),
    ("slack_token", &["slack.com"]),
    ("stripe_key", &["stripe.com"]),
    ("gitlab_token", &["gitlab.com"]),
    ("huggingface_token", &["huggingface.co", "hf.co"]),
    ("databricks_token", &["databricks.com"]),
    ("openrouter_key", &["openrouter.ai"]),
    ("perplexity_key", &["perplexity.ai"]),
    ("brave_api_key", &["search.brave.com"]),
    ("telegram_bot_token", &["api.telegram.org"]),
    ("discord_bot_token", &["discord.com"]),
    ("firecrawl_key", &["firecrawl.dev", "api.firecrawl.dev"]),
];

/// Content-type prefixes whose bodies are opaque binary.
const BINARY_BODY_CONTENT_TYPE_PREFIXES: [&str; 5] = [
    "image/",
    "audio/",
    "video/",
    "application/octet-stream",
    "application/pdf",
];

/// Room for the two `{50,4096}` repetitions in `azure_jwt`, which the
/// default compiled-size limit refuses.
const REGEX_SIZE_LIMIT: usize = 64 << 20;

fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
}

/// How one pattern is matched.
#[derive(Clone, Debug)]
enum Matcher {
    Regex(Regex),
    /// `re.escape(value)`: a plain substring.
    Literal(String),
    /// The hand-coded `brave_api_key` pattern.
    Brave,
}

impl Matcher {
    fn is_match(&self, text: &str) -> bool {
        match self {
            Self::Regex(r) => r.is_match(text),
            Self::Literal(l) => text.contains(l.as_str()),
            Self::Brave => brave_match(text),
        }
    }
}

impl PartialEq for Matcher {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Regex(a), Self::Regex(b)) => a.as_str() == b.as_str(),
            (Self::Literal(a), Self::Literal(b)) => a == b,
            (Self::Brave, Self::Brave) => true,
            _ => false,
        }
    }
}

static BUILTINS: LazyLock<Vec<(&'static str, Matcher)>> = LazyLock::new(|| {
    BUILTIN_PATTERNS
        .iter()
        .map(|(name, pattern)| {
            let m = if *name == "brave_api_key" {
                Matcher::Brave
            } else {
                Matcher::Regex(compile(pattern).expect("built-in pattern compiles"))
            };
            (*name, m)
        })
        .collect()
});

/// `[A-Za-z0-9_-]`, the base64url alphabet the Brave boundaries use.
fn brave_class(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// `(?<![A-Za-z0-9_-])BSAI[a-zA-Z0-9_-]{28}(?![A-Za-z0-9_-])`.
///
/// Every character the pattern looks at is ASCII, and a UTF-8
/// continuation or lead byte is never in the class, so a byte scan
/// decides exactly what the character-level lookarounds decide.
fn brave_match(text: &str) -> bool {
    let b = text.as_bytes();
    let mut from = 0;
    while let Some(off) = text[from..].find("BSAI") {
        let i = from + off;
        let body = i + 4..i + 32;
        let bounded_before = i == 0 || !brave_class(b[i - 1]);
        let body_ok = b
            .get(body.clone())
            .is_some_and(|s| s.iter().all(|&c| brave_class(c)));
        let bounded_after = b.get(i + 32).is_none_or(|&c| !brave_class(c));
        if bounded_before && body_ok && bounded_after {
            return true;
        }
        from = i + 1;
    }
    false
}

fn is_binary_body_content_type(content_type: &str) -> bool {
    if content_type.is_empty() {
        return false;
    }
    let ct = content_type.split(';').next().unwrap_or_default();
    let ct = pyconf::py_strip(ct).to_lowercase();
    BINARY_BODY_CONTENT_TYPE_PREFIXES
        .iter()
        .any(|p| ct.starts_with(p))
}

/// The secrets inspector.
#[derive(Clone, Debug, PartialEq)]
pub struct SecretsInspector {
    enabled: bool,
    action: Action,
    action_explicit: bool,
    /// Name → matcher, in scan order. An extra pattern named like an
    /// earlier one replaces it in place.
    patterns: Vec<(String, Matcher)>,
    /// Pattern name → lowercased domains it may go to.
    allow_to_domains: Vec<(String, Vec<String>)>,
}

impl SecretsInspector {
    /// Build from a config section. Keys: `enabled` (default true),
    /// `action` (`"block"`, anything else flags; default flag),
    /// `extra_patterns` (`[{name, pattern}]` or `[{name, env}]`, the
    /// latter matching the env var's value literally and skipped while it
    /// is unset or empty), `allow_to_domains` (`{pattern: [domain]}`,
    /// merged over the built-ins unless `builtin_allow_to_domains` is
    /// false).
    ///
    /// # Errors
    ///
    /// A key holds a value of the wrong type, an extra pattern lacks its
    /// `name` or `pattern`, or a pattern does not compile. Patterns are
    /// compiled by the `regex` crate: its syntax is Python's for ordinary
    /// patterns, but lookaround and backreferences are refused (a reload
    /// that adds one fails closed rather than scanning without it).
    pub fn from_config(section: &Value) -> Result<Self, String> {
        let map = pyconf::section(section, NAME)?;
        let enabled = pyconf::flag(map, "enabled", true);
        let action_explicit = map.contains_key("action");
        let action = match map.get("action") {
            Some(Value::String(s)) if s == "block" => Action::Block,
            _ => Action::Flag,
        };
        let mut patterns: IndexMap<String, Matcher> = IndexMap::new();
        let mut allow: IndexMap<String, Vec<String>> = IndexMap::new();
        if enabled {
            for (name, m) in BUILTINS.iter() {
                patterns.insert((*name).to_owned(), m.clone());
            }
            match map.get("extra_patterns") {
                None => {}
                Some(Value::Sequence(extras)) => {
                    for p in extras {
                        if let Some((name, m)) = extra_pattern(p)? {
                            patterns.insert(name, m);
                        }
                    }
                }
                Some(v) => {
                    return Err(format!(
                        "{NAME}.extra_patterns must be a list (got {})",
                        type_name(v)
                    ));
                }
            }
            if pyconf::flag(map, "builtin_allow_to_domains", true) {
                for (name, domains) in BUILTIN_ALLOW_TO_DOMAINS {
                    allow.insert(
                        name.to_owned(),
                        domains.iter().map(|d| d.to_lowercase()).collect(),
                    );
                }
            }
            match map.get("allow_to_domains") {
                Some(v) if !truthy(v) => {}
                None => {}
                Some(Value::Mapping(user)) => {
                    for (name, domains) in user {
                        let Value::String(name) = name else {
                            return Err(format!(
                                "{NAME}.allow_to_domains keys must be pattern names"
                            ));
                        };
                        let domains =
                            pyconf::str_items(domains, &format!("{NAME}.allow_to_domains.{name}"))?;
                        allow.insert(
                            name.clone(),
                            domains.iter().map(|d| d.to_lowercase()).collect(),
                        );
                    }
                }
                Some(v) => {
                    return Err(format!(
                        "{NAME}.allow_to_domains must be a mapping (got {})",
                        type_name(v)
                    ));
                }
            }
        }
        Ok(Self {
            enabled,
            action,
            action_explicit,
            patterns: patterns.into_iter().collect(),
            allow_to_domains: allow.into_iter().collect(),
        })
    }

    /// Whether the operator set `action` (to anything) in this config.
    /// Relays block by default only when they did not.
    #[must_use]
    pub fn action_explicit(&self) -> bool {
        self.action_explicit
    }

    /// The configured action.
    #[must_use]
    pub fn action(&self) -> Action {
        self.action
    }

    /// The pattern names, in scan order.
    #[must_use]
    pub fn pattern_names(&self) -> Vec<&str> {
        self.patterns.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// The names of the patterns that match `text`, in scan order,
    /// ignoring `allow_to_domains`.
    #[must_use]
    pub fn matching_patterns(&self, text: &str) -> Vec<&str> {
        self.patterns
            .iter()
            .filter(|(_, m)| m.is_match(text))
            .map(|(n, _)| n.as_str())
            .collect()
    }

    /// Whether pattern `name` may go to `host` (lowercased).
    fn allowed_to(&self, name: &str, host: &str) -> bool {
        self.allow_to_domains
            .iter()
            .find(|(n, _)| n == name)
            .is_some_and(|(_, domains)| domains.iter().any(|d| pyconf::host_matches(host, d)))
    }
}

/// One `extra_patterns` entry, or `None` for an env pattern whose
/// variable is unset or empty.
fn extra_pattern(p: &Value) -> Result<Option<(String, Matcher)>, String> {
    let Value::Mapping(p) = p else {
        return Err(format!(
            "{NAME}.extra_patterns entries must be mappings (got {})",
            type_name(p)
        ));
    };
    let field = |p: &Mapping, key: &str| -> Result<String, String> {
        match p.get(key) {
            Some(Value::String(s)) => Ok(s.clone()),
            Some(v) => Err(format!(
                "{NAME}.extra_patterns[].{key} must be a string (got {})",
                type_name(v)
            )),
            None => Err(format!("{NAME}.extra_patterns[] entry has no {key:?}")),
        }
    };
    match p.get("env") {
        Some(env) if truthy(env) => {
            let Value::String(env) = env else {
                return Err(format!(
                    "{NAME}.extra_patterns[].env must be a string (got {})",
                    type_name(env)
                ));
            };
            // The process env, as the replaced implementation read it
            // (not the staged-secrets lookup).
            let value = std::env::var(env).unwrap_or_default();
            if value.is_empty() {
                return Ok(None);
            }
            Ok(Some((field(p, "name")?, Matcher::Literal(value))))
        }
        _ => {
            let name = field(p, "name")?;
            let pattern = field(p, "pattern")?;
            let regex = compile(&pattern)
                .map_err(|e| format!("{NAME}.extra_patterns[{name}]: invalid pattern: {e}"))?;
            Ok(Some((name, Matcher::Regex(regex))))
        }
    }
}

impl Inspector for SecretsInspector {
    fn name(&self) -> &str {
        NAME
    }

    fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
        if !self.enabled {
            return None;
        }
        let mut targets: Vec<&str> = Vec::with_capacity(ctx.headers.len() + 2);
        targets.push(&ctx.url);
        targets.extend(ctx.headers.iter().map(|(_, v)| v.as_str()));
        if let Some(text) = ctx.body_text.as_deref() {
            if !text.is_empty() && !is_binary_body_content_type(&ctx.content_type) {
                targets.push(text);
            }
        }
        let host = ctx.host.to_lowercase();
        for (name, matcher) in &self.patterns {
            if !targets.iter().any(|t| matcher.is_match(t)) {
                continue;
            }
            // Every target of an allowed pattern is allowed too: the
            // exemption depends on the host only.
            if self.allowed_to(name, &host) {
                continue;
            }
            let mut v = Verdict::new(
                NAME,
                self.action,
                format!("secret detected: {name}"),
                Severity::Critical,
            );
            v.metadata = vec![("pattern".to_owned(), Json::string(name))];
            return Some(v);
        }
        None
    }
}

/// The relay channel's view of the secrets inspector: the same detection,
/// but a default `flag` becomes `block` unless the operator chose the
/// action explicitly.
#[derive(Clone, Debug)]
pub struct RelaySecrets {
    inner: Arc<SecretsInspector>,
}

impl RelaySecrets {
    /// Wrap the chain's secrets inspector.
    #[must_use]
    pub fn new(inner: Arc<SecretsInspector>) -> Self {
        Self { inner }
    }

    fn adjust(&self, verdict: Option<Verdict>) -> Option<Verdict> {
        let mut verdict = verdict?;
        if !self.inner.action_explicit {
            verdict.action = Action::Block;
        }
        Some(verdict)
    }
}

impl Inspector for RelaySecrets {
    fn name(&self) -> &str {
        NAME
    }

    fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
        self.adjust(self.inner.inspect_request(ctx))
    }

    fn inspect_response(&self, ctx: &Context) -> Option<Verdict> {
        self.adjust(self.inner.inspect_response(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brave_boundaries() {
        let key = format!("BSAI{}", "a".repeat(28));
        assert!(brave_match(&key));
        assert!(brave_match(&format!("x={key}&")));
        assert!(brave_match(&format!("é{key}é")));
        assert!(!brave_match(&format!("a{key}")));
        assert!(!brave_match(&format!("{key}a")));
        assert!(!brave_match(&key[..31]));
        // A rejected candidate does not hide a later good one.
        assert!(brave_match(&format!("-{key}x {key}")));
    }

    #[test]
    fn a_ten_thousand_char_candidate_scans_in_bounded_time() {
        let s = SecretsInspector::from_config(&Value::Null).unwrap();
        let body = format!("sk-ant-api03-{}", "a".repeat(10_000));
        let ctx = Context {
            host: "evil.com".to_owned(),
            body_text: Some(body),
            ..Context::default()
        };
        let t0 = std::time::Instant::now();
        let v = s.inspect_request(&ctx).unwrap();
        assert_eq!(v.action, Action::Flag);
        assert!(t0.elapsed() < std::time::Duration::from_secs(1));
    }
}
