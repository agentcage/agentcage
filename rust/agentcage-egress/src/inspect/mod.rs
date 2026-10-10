//! The inspector contract and the chain that runs it.
//!
//! An inspector looks at one request (or response, or WebSocket message,
//! or relayed mail) through an [`Context`] and either abstains or returns a
//! [`Verdict`] that flags or blocks it. The chain runs inspectors in order,
//! appends every verdict to [`Context::prior_results`] so later inspectors
//! can see it, and stops at the first `block`.
//!
//! Built-in inspectors live in the submodules and are native Rust; custom
//! ones are WebAssembly components loaded by [`crate::plugin`] behind the
//! same [`Inspector`] trait.

pub mod body_size;
pub mod content_type;
#[cfg(test)]
mod corpus;
pub mod domain;
pub mod entropy;
pub mod secrets;

use crate::json::Json;

/// What a verdict asks for.
///
/// There is no `Allow`: an inspector that has nothing to report abstains
/// by returning `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Refuse the request.
    Block,
    /// Let it through, but record why it looked suspicious.
    Flag,
}

impl Action {
    /// The wire spelling used in audit and capture records.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Flag => "flag",
        }
    }
}

/// How serious a verdict is, in the five levels audit records carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// `debug`
    Debug,
    /// `info`
    Info,
    /// `warning`, the default.
    Warning,
    /// `error`
    Error,
    /// `critical`
    Critical,
}

impl Severity {
    /// The wire spelling used in audit and capture records.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    /// Parse the wire spelling; anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "debug" => Self::Debug,
            "info" => Self::Info,
            "warning" => Self::Warning,
            "error" => Self::Error,
            "critical" => Self::Critical,
            _ => return None,
        })
    }
}

/// One inspector's finding.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    /// The reporting inspector's name (`domain`, `secrets`, …).
    pub inspector: String,
    /// Block or flag.
    pub action: Action,
    /// Human-readable reason, carried verbatim into the 403 body and the
    /// audit record.
    pub reason: String,
    /// Severity.
    pub severity: Severity,
    /// Free-form details. Never written to the audit record; available to
    /// later inspectors through [`Context::prior_results`].
    pub metadata: Vec<(String, Json)>,
}

impl Verdict {
    /// A verdict with no metadata.
    #[must_use]
    pub fn new(
        inspector: impl Into<String>,
        action: Action,
        reason: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            inspector: inspector.into(),
            action,
            reason: reason.into(),
            severity,
            metadata: Vec::new(),
        }
    }
}

/// Which side of an exchange is being inspected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// An outbound request (or a cage-to-world WebSocket message, or a
    /// relayed mail).
    Request,
    /// A response (or a world-to-cage WebSocket message).
    Response,
}

/// Everything an inspector may look at, computed once per exchange.
///
/// Inspectors see the request as the cage sent it — placeholders, not
/// real secret values — because the context is built before injection.
#[derive(Clone, Debug, Default)]
pub struct Context {
    /// The full URL.
    pub url: String,
    /// The upstream host (after re-targeting to the Host/SNI name).
    pub host: String,
    /// The request method (for a response, the request's).
    pub method: String,
    /// Header name/value pairs in wire order, duplicates kept.
    pub headers: Vec<(String, String)>,
    /// The `Content-Type` header value, or `""`.
    pub content_type: String,
    /// The decoded (Content-Encoding removed) body, or `None` when there is
    /// no body.
    pub body_bytes: Option<Vec<u8>>,
    /// The body as text, decoded the way [`crate::text::get_text`] does, or
    /// `None` when there is no body or it cannot be decoded.
    pub body_text: Option<String>,
    /// Length of `body_bytes`.
    pub body_size: usize,
    /// Shannon entropy of `body_bytes` in bits per byte, or `None` for an
    /// empty body.
    pub body_entropy: Option<f64>,
    /// Verdicts already returned by earlier inspectors in this chain.
    pub prior_results: Vec<Verdict>,
}

/// An inspector, built-in or plugin.
///
/// Implementations must be pure over their input plus their own
/// configuration: the chain runs on a blocking worker thread and the same
/// instance serves concurrent exchanges.
pub trait Inspector: Send + Sync + std::fmt::Debug {
    /// The name verdicts and config sections use.
    fn name(&self) -> &str;

    /// Inspect an outbound request. `None` abstains.
    fn inspect_request(&self, ctx: &Context) -> Option<Verdict>;

    /// Inspect a response. `None` abstains; no built-in inspects
    /// responses.
    fn inspect_response(&self, _ctx: &Context) -> Option<Verdict> {
        None
    }
}

/// Run `inspectors` over `ctx` in order.
///
/// `skip` returns true for an inspector that must not run on this exchange
/// (the domain inspector on reverse-proxied traffic). Every verdict is
/// returned in invocation order and appended to `ctx.prior_results`; the
/// first `block` ends the chain and is the last element returned.
pub fn run_chain(
    inspectors: &[std::sync::Arc<dyn Inspector>],
    ctx: &mut Context,
    phase: Phase,
    skip: &dyn Fn(&dyn Inspector) -> bool,
) -> Vec<Verdict> {
    let mut results = Vec::new();
    for inspector in inspectors {
        if skip(inspector.as_ref()) {
            continue;
        }
        let verdict = match phase {
            Phase::Request => inspector.inspect_request(ctx),
            Phase::Response => inspector.inspect_response(ctx),
        };
        let Some(verdict) = verdict else { continue };
        let block = verdict.action == Action::Block;
        ctx.prior_results.push(verdict.clone());
        results.push(verdict);
        if block {
            break;
        }
    }
    results
}

/// Shannon entropy in bits per byte (0.0 – 8.0); `0.0` for no data.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[usize::from(b)] += 1;
    }
    #[allow(clippy::cast_precision_loss)]
    let len = data.len() as f64;
    let mut entropy = 0.0;
    // Python's `Counter` iterates in first-seen order, and float addition
    // is not associative, so sum in that order to reproduce its result to
    // the last bit.
    let mut seen = [false; 256];
    for &b in data {
        let i = usize::from(b);
        if seen[i] {
            continue;
        }
        seen[i] = true;
        #[allow(clippy::cast_precision_loss)]
        let p = counts[i] as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Debug)]
    struct Fixed(&'static str, Option<Action>);

    impl Inspector for Fixed {
        fn name(&self) -> &str {
            self.0
        }
        fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
            let action = self.1?;
            Some(Verdict::new(
                self.0,
                action,
                format!("seen {}", ctx.prior_results.len()),
                Severity::Warning,
            ))
        }
    }

    #[test]
    fn the_chain_stops_at_the_first_block_and_accumulates_prior_results() {
        let chain: Vec<Arc<dyn Inspector>> = vec![
            Arc::new(Fixed("a", Some(Action::Flag))),
            Arc::new(Fixed("b", None)),
            Arc::new(Fixed("c", Some(Action::Block))),
            Arc::new(Fixed("d", Some(Action::Flag))),
        ];
        let mut ctx = Context::default();
        let out = run_chain(&chain, &mut ctx, Phase::Request, &|_| false);
        let names: Vec<_> = out.iter().map(|v| v.inspector.as_str()).collect();
        assert_eq!(names, ["a", "c"]);
        assert_eq!(out[1].reason, "seen 1");
        assert_eq!(ctx.prior_results.len(), 2);
    }

    #[test]
    fn skipped_inspectors_do_not_run() {
        let chain: Vec<Arc<dyn Inspector>> = vec![
            Arc::new(Fixed("domain", Some(Action::Block))),
            Arc::new(Fixed("b", Some(Action::Flag))),
        ];
        let mut ctx = Context::default();
        let out = run_chain(&chain, &mut ctx, Phase::Request, &|i| i.name() == "domain");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].inspector, "b");
    }

    #[test]
    fn entropy_matches_python() {
        assert!((shannon_entropy(b"") - 0.0).abs() < f64::EPSILON);
        assert!((shannon_entropy(b"aaaa") - 0.0).abs() < f64::EPSILON);
        assert!((shannon_entropy(b"ab") - 1.0).abs() < f64::EPSILON);
    }
}
