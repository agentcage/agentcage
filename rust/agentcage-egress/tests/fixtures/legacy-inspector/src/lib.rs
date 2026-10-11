//! A custom inspector as a plugin built against
//! `agentcage:inspector@1.0.0` looks: `configure`, `inspect-request` and
//! `inspect-response`, no `phases`. Every call flags, naming the method
//! and the phase it was handed, so the egress tests can see which calls
//! a pre-1.1 component still gets (all of them).

#[allow(unsafe_code, missing_docs, clippy::all, clippy::pedantic)]
mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "inspector",
    });
}

use bindings::agentcage::inspector::types as abi;

struct Legacy;

fn flag(method: &str, ctx: &abi::Context) -> Option<abi::Verdict> {
    Some(abi::Verdict {
        action: abi::Action::Flag,
        reason: format!("legacy {method} {:?}", ctx.phase),
        severity: abi::Severity::Info,
        metadata: vec![],
    })
}

impl bindings::Guest for Legacy {
    fn configure(_config: String) -> Result<(), String> {
        Ok(())
    }

    fn inspect_request(ctx: abi::Context) -> Option<abi::Verdict> {
        flag("request", &ctx)
    }

    fn inspect_response(ctx: abi::Context) -> Option<abi::Verdict> {
        flag("response", &ctx)
    }
}

bindings::export!(Legacy with_types_in bindings);
