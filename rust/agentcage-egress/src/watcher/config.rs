//! The `agents.watcher` block, parsed defensively.
//!
//! The host validates the block, but the egress never trusts upstream
//! validation: a hand edit of the re-rendered proxy config could deform
//! any value. So a malformed value falls back to the default *with a
//! warning*, and the watcher then runs fail-closed — an unusable agent
//! config records scan failures, it never widens anything.
//!
//! Every fallback is the host's own default, not one of the egress's: the
//! host copies the operator's block into the proxy config as written, so
//! an omitted key runs at the value here while the host validates and
//! budgets against its own. `tests/fixtures/contracts/agents_defaults.json`
//! pins the pair.

use agentcage_core::python;

use crate::config::{Config, Mapping, Value};

use super::pyval;

/// The capture writer's default `max_body_size`.
const DEFAULT_CAPTURE_MAX_BODY: i64 = 10_485_760;

/// Per-tick capture read bound (bytes). A first scan on a huge capture
/// file is chunked across ticks instead of being read whole.
pub const CAP_READ_CHUNK: u64 = 8 * 1024 * 1024;

/// Floor for the single-line cap; the effective cap is derived from
/// `capture.max_body_size` (see [`WatcherConfig::line_cap`]).
pub const MIN_LINE_CAP: u64 = 4 * CAP_READ_CHUNK;

/// The parsed `agents.watcher` block plus the one capture setting the
/// watcher derives from.
#[derive(Clone, Debug, PartialEq)]
pub struct WatcherConfig {
    /// The raw block, kept so a reload can tell "unchanged" (keep the
    /// running watcher and its scan state) from "changed" (rebuild).
    pub block: Value,
    /// `enable`, by Python truthiness.
    pub enable: bool,
    /// Mean seconds between scans, floored at 60.
    pub interval_seconds: f64,
    /// How far back a reset scan of capture reaches, in `[1, 86400]`.
    pub window_seconds: f64,
    /// Per-scan capture sample cap, floored at 10.
    pub max_flows: usize,
    /// Apply revocations, or only record them as findings.
    pub auto_revoke: bool,
    /// Collapse repeated flow shapes in the digest.
    pub dedup_samples: bool,
    /// Spend ceiling for one digest, in estimated tokens; 0 = unbounded.
    pub max_digest_tokens: usize,
    /// The operator's trusted context, stripped and cut to 4096 chars.
    pub context: String,
    /// LLM provider key (`anthropic`, `openai`, `openrouter`), not
    /// lowercased: a mixed-case value means a deformed config, and the
    /// provider lookup then fails as recorded scan failures.
    pub provider: String,
    /// Model name.
    pub model: String,
    /// The key's `source:` reference (`env:NAME`); the value is resolved
    /// through [`crate::secret_lookup`] on every (re)load.
    pub api_key: String,
    /// Per-call LLM timeout.
    pub timeout_seconds: f64,
    /// Completion budget for the forced `review` call.
    pub max_tokens: i64,
    /// Provider base URL override, trailing slashes stripped.
    pub base_url: String,
    /// The longest capture line the tail will wait for: four body slots of
    /// `capture.max_body_size`, base64-inflated, plus slack — never below
    /// [`MIN_LINE_CAP`]. A fixed cap sat below what capture legitimately
    /// writes for a large transfer, which was then dropped as oversized.
    pub line_cap: u64,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self::parse(&Config::default(), &mut |_| {})
    }
}

impl WatcherConfig {
    /// Parse the watcher block of `cfg`, reporting each fallback through
    /// `warn` with the replaced implementation's exact message.
    pub fn parse(cfg: &Config, warn: &mut dyn FnMut(&str)) -> Self {
        let block = watcher_block(cfg);
        let empty = Mapping::new();
        let m = match &block {
            Value::Mapping(m) => m,
            _ => &empty,
        };

        let interval = num(m, "interval_seconds", 900.0, "900.0", warn);
        let window = num(m, "window_seconds", 3600.0, "3600.0", warn);
        let max_flows = int_num(m, "max_flows", 200.0, "200.0", warn);
        let auto_revoke = flag(m, "auto_revoke", warn);
        let dedup_samples = flag(m, "dedup_samples", warn);
        let max_digest_tokens = int_num(m, "max_digest_tokens", 8000.0, "8000.0", warn);
        let context = match m.get("context") {
            None => String::new(),
            Some(Value::String(s)) => pyval::prefix(py_strip(s), 4096),
            Some(other) => {
                warn(&format!(
                    "agentcage: agents.watcher.context is not a string in the proxy \
                     config (got {}) — ignoring it",
                    python::type_name(other)
                ));
                String::new()
            }
        };
        // `str(cfg.get(key, "") or "")`.
        let text = |key: &str| match m.get(key) {
            Some(v) if crate::config::truthy(v) => python::str_of(v),
            _ => String::new(),
        };
        let timeout = num(m, "timeout_seconds", 30.0, "30.0", warn);
        let max_tokens = int_num(m, "max_tokens", 8192.0, "8192", warn);

        Self {
            enable: m.get("enable").is_some_and(crate::config::truthy),
            // `max(60.0, x)` returns its first argument unless the second
            // is greater, so a NaN lands on the floor.
            interval_seconds: if interval > 60.0 { interval } else { 60.0 },
            window_seconds: {
                let w = if window > 1.0 { window } else { 1.0 };
                if w < 86400.0 { w } else { 86400.0 }
            },
            max_flows: usize::try_from(max_flows.max(10)).unwrap_or(usize::MAX),
            auto_revoke,
            dedup_samples,
            max_digest_tokens: usize::try_from(max_digest_tokens.max(0)).unwrap_or(0),
            context,
            provider: text("provider"),
            model: text("model"),
            api_key: text("api_key"),
            timeout_seconds: timeout,
            max_tokens,
            base_url: text("base_url").trim_end_matches('/').to_owned(),
            line_cap: line_cap(cfg),
            block,
        }
    }
}

/// `((cfg.get("agents") or {}).get("watcher")) or {}`, as the raw value: a
/// non-mapping block is returned as is so the caller can warn about it.
pub(crate) fn watcher_block(cfg: &Config) -> Value {
    let agents = cfg.section("agents");
    match agents.get("watcher") {
        Some(v) if crate::config::truthy(v) => v.clone(),
        _ => Value::Mapping(Mapping::new()),
    }
}

fn line_cap(cfg: &Config) -> u64 {
    let body = match cfg.section("capture").get("max_body_size") {
        None => DEFAULT_CAPTURE_MAX_BODY,
        Some(v) => crate::config::as_i64(Some(v)).unwrap_or(DEFAULT_CAPTURE_MAX_BODY),
    };
    // `int(body * 4 * 4 / 3)`: true division, then truncation.
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    let derived = (body as f64 * 4.0 * 4.0 / 3.0).trunc() as i64 + (1 << 20);
    u64::try_from(derived).unwrap_or(0).max(MIN_LINE_CAP)
}

/// `_num`: absent/null/`""` → default; `float(raw)` or a warning and the
/// default.
fn num(m: &Mapping, key: &str, default: f64, shown: &str, warn: &mut dyn FnMut(&str)) -> f64 {
    let Some(raw) = m.get(key) else {
        return default;
    };
    match raw {
        Value::Null => return default,
        Value::String(s) if s.is_empty() => return default,
        _ => {}
    }
    if let Some(f) = py_float(raw) {
        return f;
    }
    warn(&format!(
        "agentcage: agents.watcher.{key} is not a number ({}) — using {shown}",
        python::repr(raw)
    ));
    default
}

/// `int(_num(...))`. A non-finite number cannot become an `int` — the
/// replaced implementation raised and lost the whole watcher; here it is
/// warned about and defaulted like any other non-number.
fn int_num(m: &Mapping, key: &str, default: f64, shown: &str, warn: &mut dyn FnMut(&str)) -> i64 {
    let f = num(m, key, default, shown, warn);
    #[allow(clippy::cast_possible_truncation)]
    if f.is_finite() {
        f.trunc() as i64
    } else {
        warn(&format!(
            "agentcage: agents.watcher.{key} is not a number ({}) — using {shown}",
            pyval::float_str(f)
        ));
        default as i64
    }
}

/// Only a real boolean counts: `auto_revoke: "false"` must not read as
/// true through truthiness, enabling the very thing the operator wrote
/// "false" next to.
fn flag(m: &Mapping, key: &str, warn: &mut dyn FnMut(&str)) -> bool {
    match m.get(key) {
        None => true,
        Some(Value::Bool(b)) => *b,
        Some(other) => {
            warn(&format!(
                "agentcage: agents.watcher.{key} is not a boolean ({}) — using the default (true)",
                python::repr(other)
            ));
            true
        }
    }
}

/// Python `float(x)` on a loaded YAML value.
fn py_float(v: &Value) -> Option<f64> {
    match v {
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        Value::Number(n) => n.as_f64(),
        Value::String(s) => {
            let t = py_strip(s);
            if t.starts_with('_') || t.ends_with('_') || t.contains("__") {
                return None;
            }
            let cleaned: String = t.chars().filter(|c| *c != '_').collect();
            cleaned.parse().ok()
        }
        _ => None,
    }
}

/// `str.strip()`: Python's whitespace, which adds the four C0 separators
/// to Unicode's.
fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}
