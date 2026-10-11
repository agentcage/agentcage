//! A custom inspector that misbehaves on request, for the egress's
//! fail-closed tests. `config: {"mode": "<mode>"}` picks the behaviour of
//! `inspect-request`; `inspect-response` always describes its context.
//!
//! It implements the raw bindings rather than the SDK trait so it can
//! also break the ABI's rules (metadata that is not JSON), which the SDK
//! makes impossible.

use std::cell::RefCell;

use agentcage_inspector_sdk::bindings::{self, agentcage::inspector::types as abi};

thread_local! {
    static MODE: RefCell<String> = const { RefCell::new(String::new()) };
}

struct Misbehave;

fn verdict(reason: String, metadata: Vec<abi::MetadataEntry>) -> abi::Verdict {
    abi::Verdict {
        action: abi::Action::Flag,
        reason,
        severity: abi::Severity::Info,
        metadata,
    }
}

fn describe(ctx: &abi::Context) -> abi::Verdict {
    let prior: Vec<String> = ctx
        .prior_results
        .iter()
        .map(|p| {
            let meta: Vec<String> = p
                .metadata
                .iter()
                .map(|m| format!("{}={}", m.key, m.value))
                .collect();
            format!("{}:{}", p.inspector, meta.join(","))
        })
        .collect();
    let headers: Vec<String> = ctx
        .headers
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    verdict(
        format!(
            "{:?} {:?} {} {} [{}] ct={} body={:?} text={:?} size={} entropy={:?} prior=[{}]",
            ctx.phase,
            ctx.direction,
            ctx.method,
            ctx.url,
            headers.join(";"),
            ctx.content_type,
            ctx.body.as_ref().map(Vec::len),
            ctx.body_text,
            ctx.body_size,
            ctx.body_entropy,
            prior.join(";"),
        ),
        vec![abi::MetadataEntry {
            key: "host".into(),
            value: format!("{:?}", ctx.host),
        }],
    )
}

impl bindings::Guest for Misbehave {
    fn configure(config: String) -> Result<(), String> {
        agentcage_inspector_sdk::__private::quiet_panics();
        let mode = config
            .split("\"mode\":")
            .nth(1)
            .and_then(|rest| rest.split('"').nth(1))
            .unwrap_or("describe")
            .to_owned();
        match mode.as_str() {
            "refuse" => return Err("mode refuse says no".into()),
            "configure-panic" => panic!("configure panicked"),
            _ => {}
        }
        MODE.with(|m| *m.borrow_mut() = mode);
        Ok(())
    }

    fn inspect_request(ctx: abi::Context) -> Option<abi::Verdict> {
        let mode = MODE.with(|m| m.borrow().clone());
        match mode.as_str() {
            "abstain" => None,
            "panic" => panic!("inspect panicked"),
            "loop" => {
                let mut n: u64 = 0;
                loop {
                    n = std::hint::black_box(n.wrapping_add(1));
                }
            }
            "alloc" => {
                let mut hoard: Vec<Vec<u8>> = Vec::new();
                loop {
                    hoard.push(vec![1u8; 1 << 20]);
                    std::hint::black_box(&hoard);
                }
            }
            "bad-metadata" => Some(verdict(
                "x".into(),
                vec![abi::MetadataEntry {
                    key: "k".into(),
                    value: "{not json".into(),
                }],
            )),
            "env" => Some(verdict(format!("{:?}", std::env::var("HOME")), vec![])),
            "fs" => Some(verdict(
                format!("{:?}", std::fs::read("/etc/passwd").map(|b| b.len())),
                vec![],
            )),
            "clock" => Some(verdict(
                format!("{:?}", std::time::SystemTime::now()),
                vec![],
            )),
            "hashmap" => {
                let mut m = std::collections::HashMap::new();
                m.insert(ctx.host.clone(), 1);
                Some(verdict(format!("{}", m.len()), vec![]))
            }
            "block" => Some(abi::Verdict {
                action: abi::Action::Block,
                reason: format!("blocked {}", ctx.host),
                severity: abi::Severity::Critical,
                metadata: vec![],
            }),
            _ => Some(describe(&ctx)),
        }
    }

    fn inspect_response(ctx: abi::Context) -> Option<abi::Verdict> {
        Some(describe(&ctx))
    }
}

bindings::__agentcage_export_inspector_world!(Misbehave with_types_in bindings);
