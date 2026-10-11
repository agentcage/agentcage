//! Require a tracing header on every outbound request.
//!
//! ```yaml
//! inspectors:
//!   - name: header-policy
//!     path: header_policy_inspector.wasm
//!     config:
//!       required_header: X-Trace-ID   # default
//!       block_on_missing: true        # default false: flag only
//! ```

use agentcage_inspector_sdk::{Context, Inspector, Severity, Value, Verdict, export_inspector};

/// The inspector's configuration.
#[derive(Debug)]
pub struct HeaderPolicy {
    required_header: String,
    block_on_missing: bool,
}

impl Default for HeaderPolicy {
    fn default() -> Self {
        Self {
            required_header: "x-trace-id".to_owned(),
            block_on_missing: false,
        }
    }
}

impl Inspector for HeaderPolicy {
    fn configure(&mut self, config: &Value) -> Result<(), String> {
        if let Some(name) = config.get("required_header") {
            let name = name.as_str().ok_or("required_header must be a string")?;
            if name.is_empty() {
                return Err("required_header must not be empty".to_owned());
            }
            self.required_header = name.to_ascii_lowercase();
        }
        if let Some(block) = config.get("block_on_missing") {
            self.block_on_missing = block
                .as_bool()
                .ok_or("block_on_missing must be a boolean")?;
        }
        Ok(())
    }

    fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
        if ctx.has_header(&self.required_header) {
            return None;
        }
        let reason = format!("Missing mandatory header: {}", self.required_header);
        let verdict = if self.block_on_missing {
            Verdict::block(reason).with_severity(Severity::Error)
        } else {
            Verdict::flag(reason)
        };
        Some(verdict.with_metadata("target_host", ctx.host.clone()))
    }
}

export_inspector!(HeaderPolicy);
