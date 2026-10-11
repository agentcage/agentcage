//! The request body size inspector.
//!
//! `max_bytes` is the global cap (0 disables). `host_max_bytes` overrides
//! it per host, by suffix: the longest matching key wins, so a tight
//! subdomain limit is not widened by a looser apex entry, and an override
//! can be larger or smaller than the global (or 0, which disables the
//! check for that host).

use agentcage_core::python::type_name;

use super::pyconf::{self, Num};
use super::{Action, Context, Inspector, Severity, Verdict};
use crate::config::Value;
use crate::json::Json;

/// The name verdicts and config sections use.
pub const NAME: &str = "body-size";

/// The body size inspector.
#[derive(Clone, Debug, PartialEq)]
pub struct BodySizeInspector {
    max_bytes: Num,
    /// `{h.lower(): int(v)}` in config order.
    host_max_bytes: Vec<(String, Num)>,
}

impl BodySizeInspector {
    /// Build from a config section (`{"max_bytes": …, "host_max_bytes":
    /// {…}}`). Defaults: no cap, no overrides.
    ///
    /// # Errors
    ///
    /// The section is not a mapping, `max_bytes` is not a number, or a
    /// `host_max_bytes` value is not something `int()` accepts.
    pub fn from_config(section: &Value) -> Result<Self, String> {
        let map = pyconf::section(section, NAME)?;
        let max_bytes = pyconf::num(map, "max_bytes", Num::int(0), NAME)?;
        let mut host_max_bytes: indexmap::IndexMap<String, Num> = indexmap::IndexMap::new();
        match map.get("host_max_bytes") {
            None => {}
            Some(Value::Mapping(raw)) => {
                for (h, v) in raw {
                    let Value::String(h) = h else {
                        return Err(format!("{NAME}.host_max_bytes keys must be host names"));
                    };
                    let limit = pyconf::int_like(v).ok_or_else(|| {
                        format!(
                            "{NAME}.host_max_bytes.{h} must be an integer (got {})",
                            type_name(v)
                        )
                    })?;
                    host_max_bytes.insert(h.to_lowercase(), Num::int(limit));
                }
            }
            Some(v) => {
                return Err(format!(
                    "{NAME}.host_max_bytes must be a mapping (got {})",
                    type_name(v)
                ));
            }
        }
        Ok(Self {
            max_bytes,
            host_max_bytes: host_max_bytes.into_iter().collect(),
        })
    }

    fn limit_for_host(&self, host: &str) -> &Num {
        if self.host_max_bytes.is_empty() {
            return &self.max_bytes;
        }
        let host = host.to_lowercase();
        let mut best_len = None;
        let mut best = &self.max_bytes;
        for (h, limit) in &self.host_max_bytes {
            // Length in code points, as `len(h)`; strictly longer wins,
            // so the first of two equal-length matches stays.
            let len = h.chars().count();
            if pyconf::host_matches(&host, h) && best_len.is_none_or(|b| len > b) {
                best_len = Some(len);
                best = limit;
            }
        }
        best
    }
}

impl Inspector for BodySizeInspector {
    fn name(&self) -> &str {
        NAME
    }

    fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
        let limit = self.limit_for_host(&ctx.host);
        if limit.is_zero() {
            return None;
        }
        #[allow(clippy::cast_precision_loss)] // compared as Python compares an int with a limit
        let size = ctx.body_size as f64;
        // Not `<=`: a NaN limit compares false both ways in Python too,
        // and must not block.
        if size.partial_cmp(&limit.value) != Some(std::cmp::Ordering::Greater) {
            return None;
        }
        let mut verdict = Verdict::new(
            NAME,
            Action::Block,
            format!("body too large: {} > {}", ctx.body_size, limit.text),
            Severity::Warning,
        );
        verdict.metadata = vec![
            (
                "body_size".to_owned(),
                Json::Int(i64::try_from(ctx.body_size).unwrap_or(i64::MAX)),
            ),
            ("max_bytes".to_owned(), limit.json.clone()),
            ("host".to_owned(), Json::string(&ctx.host)),
        ];
        Some(verdict)
    }
}
