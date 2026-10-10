//! Block (or flag) messages whose body, URL or headers match a
//! configured regular expression.
//!
//! ```yaml
//! inspectors:
//!   - name: dlp
//!     path: dlp_regex_inspector.wasm
//!     config:
//!       action: block            # or flag; default block
//!       severity: error          # default error
//!       responses: false         # also scan responses; default false
//!       patterns:
//!         - name: project-codename
//!           regex: '(?i)\bblue[- ]?falcon\b'
//!         - name: us-ssn
//!           regex: '\b\d{3}-\d{2}-\d{4}\b'
//! ```
//!
//! The reason names the pattern and where it matched, never the matched
//! text: reasons are written to the audit log and returned to the cage.

use agentcage_inspector_sdk::{
    Action, Context, Inspector, Severity, Value, Verdict, export_inspector,
};
use regex::Regex;

/// The inspector's configuration.
#[derive(Debug)]
pub struct Dlp {
    patterns: Vec<(String, Regex)>,
    action: Action,
    severity: Severity,
    responses: bool,
}

impl Default for Dlp {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            action: Action::Block,
            severity: Severity::Error,
            responses: false,
        }
    }
}

impl Inspector for Dlp {
    fn configure(&mut self, config: &Value) -> Result<(), String> {
        let patterns = config
            .get("patterns")
            .and_then(Value::as_array)
            .filter(|p| !p.is_empty())
            .ok_or("patterns must be a non-empty list of {name, regex}")?;
        for (i, entry) in patterns.iter().enumerate() {
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .ok_or(format!("patterns[{i}].name must be a string"))?;
            let source = entry
                .get("regex")
                .and_then(Value::as_str)
                .ok_or(format!("patterns[{i}].regex must be a string"))?;
            let regex = Regex::new(source).map_err(|e| format!("patterns[{i}].regex: {e}"))?;
            self.patterns.push((name.to_owned(), regex));
        }
        self.action = match config.get("action").and_then(Value::as_str) {
            None | Some("block") => Action::Block,
            Some("flag") => Action::Flag,
            Some(other) => return Err(format!("action must be block or flag, not {other:?}")),
        };
        self.severity = match config.get("severity").and_then(Value::as_str) {
            None | Some("error") => Severity::Error,
            Some("debug") => Severity::Debug,
            Some("info") => Severity::Info,
            Some("warning") => Severity::Warning,
            Some("critical") => Severity::Critical,
            Some(other) => return Err(format!("unknown severity {other:?}")),
        };
        self.responses = config
            .get("responses")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(())
    }

    fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
        self.scan(ctx)
    }

    fn inspect_response(&self, ctx: &Context) -> Option<Verdict> {
        if self.responses { self.scan(ctx) } else { None }
    }
}

impl Dlp {
    fn scan(&self, ctx: &Context) -> Option<Verdict> {
        for (name, regex) in &self.patterns {
            let place = if ctx.body_text.as_deref().is_some_and(|t| regex.is_match(t)) {
                "body"
            } else if regex.is_match(&ctx.url) {
                "url"
            } else if ctx.headers.iter().any(|(_, v)| regex.is_match(v)) {
                "headers"
            } else {
                continue;
            };
            return Some(
                Verdict::new(
                    self.action,
                    format!("DLP pattern {name:?} matched in the {place}"),
                )
                .with_severity(self.severity)
                .with_metadata("pattern", name.clone()),
            );
        }
        None
    }
}

export_inspector!(Dlp);
