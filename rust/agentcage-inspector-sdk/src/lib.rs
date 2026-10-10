//! Write agentcage custom inspectors in Rust.
//!
//! A custom inspector is a WebAssembly component the egress proxy loads
//! next to its built-in inspectors. It sees every request (and response,
//! and WebSocket message) the cage exchanges, and may flag or block it.
//! This crate is the guest side of that contract: implement [`Inspector`]
//! for a type, hand it to [`export_inspector!`], and build for
//! `wasm32-wasip2`.
//!
//! ```ignore
//! use agentcage_inspector_sdk::{export_inspector, Context, Inspector, Value, Verdict};
//!
//! #[derive(Default)]
//! struct NoExfil {
//!     word: String,
//! }
//!
//! impl Inspector for NoExfil {
//!     fn configure(&mut self, config: &Value) -> Result<(), String> {
//!         self.word = config["forbidden_word"].as_str().unwrap_or("EXFIL").to_owned();
//!         Ok(())
//!     }
//!
//!     fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
//!         let text = ctx.body_text.as_deref()?;
//!         text.contains(&self.word)
//!             .then(|| Verdict::block(format!("body contains forbidden word: {}", self.word)))
//!     }
//! }
//!
//! export_inspector!(NoExfil);
//! ```
//!
//! ```text
//! cargo build --release --target wasm32-wasip2
//! ```
//!
//! # What the egress guarantees
//!
//! * `configure` runs once per instance, before any inspection, with the
//!   cage.yaml entry's `config:` mapping (`{}` when absent). Each call
//!   starts from `Default::default()`, so a configuration replaces the
//!   previous one whole; an `Err` keeps the previous one.
//! * A plugin has no capabilities: no filesystem, network, environment
//!   or wall clock. It sees only the [`Context`] it is handed.
//! * Every call runs under a fuel (CPU) and memory budget. A panic, a
//!   trap or an exhausted budget is reported as a `block` with the reason
//!   `inspector <name> failed: …`: a broken plugin fails closed.
//! * The egress may run several instances of a plugin at once, and may
//!   replace an instance at any time (after a failure, on a config
//!   change). Do not rely on state carried between calls.
//!
//! The ABI is the WIT world in `wit/inspector.wit`
//! (`agentcage:inspector@1.0.0`); plugins built against any 1.x SDK keep
//! loading across egress upgrades.

use std::cell::RefCell;

// The generated bindings name their runtime by absolute path (see
// `runtime_path` below) so they resolve the same in a plugin crate,
// where the export macro expands, and in this one.
extern crate self as agentcage_inspector_sdk;

pub use serde_json::{self, Value, json};

/// The bindings `wit-bindgen` generates for `wit/inspector.wit`.
///
/// Internal: plugins use the types at the crate root, which do not change
/// shape when the binding generator does.
#[doc(hidden)]
#[allow(
    unsafe_code,
    missing_docs,
    unreachable_pub,
    clippy::pedantic,
    clippy::all,
    missing_debug_implementations
)]
pub mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "inspector",
        pub_export_macro: true,
        export_macro_name: "__agentcage_export_inspector_world",
        runtime_path: "::agentcage_inspector_sdk::__wit_bindgen_rt",
    });
}

#[doc(hidden)]
pub use wit_bindgen::rt as __wit_bindgen_rt;

use bindings::agentcage::inspector::types as wit;

/// What a verdict asks for.
///
/// There is no `Allow`: an inspector with nothing to report returns
/// `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Refuse the exchange: the cage gets a 403 (or the message is
    /// dropped) and the audit record says `blocked`.
    Block,
    /// Let it through, but audit it as `flagged` with the reason.
    Flag,
}

/// How serious a verdict is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// `debug`
    Debug,
    /// `info`
    Info,
    /// `warning`, the default.
    #[default]
    Warning,
    /// `error`
    Error,
    /// `critical`
    Critical,
}

/// Which way the flow runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// From the cage to the world: the forward and transparent proxy, and
    /// the protocol relays.
    Outbound,
    /// From the world to a port the cage exposes (the reverse proxy).
    Inbound,
}

/// What kind of message is being inspected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Phase {
    /// An HTTP request, or a relayed mail.
    Request,
    /// An HTTP response.
    Response,
    /// One complete WebSocket message: [`Inspector::inspect_request`] sees
    /// the ones the cage sends, [`Inspector::inspect_response`] the ones
    /// it receives.
    WebSocket,
}

/// A finding an inspector earlier in the chain already reported.
#[derive(Clone, Debug, PartialEq)]
pub struct PriorResult {
    /// The reporting inspector's name (`secrets`, `entropy`, …).
    pub inspector: String,
    /// Block or flag. (A block ends the chain, so a plugin only ever sees
    /// flags here.)
    pub action: Action,
    /// The reason it gave.
    pub reason: String,
    /// The severity it gave.
    pub severity: Severity,
    /// The details it attached.
    pub metadata: Vec<(String, Value)>,
}

/// Everything an inspector may look at, computed once per exchange.
///
/// Requests are seen as the cage sent them: secret placeholders, not the
/// real values, because inspection runs before injection.
#[derive(Clone, Debug, PartialEq)]
pub struct Context {
    /// The full URL.
    pub url: String,
    /// The upstream host name.
    pub host: String,
    /// The request method (for a response, the request's).
    pub method: String,
    /// Header name/value pairs in wire order, case and duplicates kept.
    pub headers: Vec<(String, String)>,
    /// The `Content-Type` header value, or `""`.
    pub content_type: String,
    /// The body with any `Content-Encoding` removed; `None` when the
    /// message has no body.
    pub body: Option<Vec<u8>>,
    /// The body decoded as text (the declared charset, else UTF-8 for
    /// JSON/HTML/XML/JS/CSS, else Latin-1); `None` when there is no body
    /// or it does not decode.
    pub body_text: Option<String>,
    /// Length of `body` in bytes.
    pub body_size: u64,
    /// Shannon entropy of `body` in bits per byte; `None` for an empty
    /// body.
    pub body_entropy: Option<f64>,
    /// Verdicts already returned by earlier inspectors in the chain.
    pub prior_results: Vec<PriorResult>,
    /// Which way the flow runs.
    pub direction: Direction,
    /// What kind of message this is.
    pub phase: Phase,
}

impl Context {
    /// The first value of header `name` (ASCII case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every value of header `name` (ASCII case-insensitive), in wire
    /// order.
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether header `name` is present (ASCII case-insensitive).
    #[must_use]
    pub fn has_header(&self, name: &str) -> bool {
        self.header(name).is_some()
    }
}

/// An inspector's finding.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    /// Block or flag.
    pub action: Action,
    /// Human-readable reason, carried verbatim into the 403 body and the
    /// audit record. Do not echo secrets into it.
    pub reason: String,
    /// Severity; [`Severity::Warning`] unless set.
    pub severity: Severity,
    /// Free-form details, visible to later inspectors and never written
    /// to the audit record.
    pub metadata: Vec<(String, Value)>,
}

impl Verdict {
    /// A `block` verdict with severity `warning`.
    #[must_use]
    pub fn block(reason: impl Into<String>) -> Self {
        Self::new(Action::Block, reason)
    }

    /// A `flag` verdict with severity `warning`.
    #[must_use]
    pub fn flag(reason: impl Into<String>) -> Self {
        Self::new(Action::Flag, reason)
    }

    /// A verdict with severity `warning` and no metadata.
    #[must_use]
    pub fn new(action: Action, reason: impl Into<String>) -> Self {
        Self {
            action,
            reason: reason.into(),
            severity: Severity::default(),
            metadata: Vec::new(),
        }
    }

    /// This verdict with `severity`.
    #[must_use]
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// This verdict with one more metadata entry.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }
}

/// A custom inspector.
///
/// The type must be `Default`: each [`configure`](Self::configure) starts
/// from a fresh default value. Every method has a default, so implement
/// only what the inspector needs.
pub trait Inspector: Default + 'static {
    /// Take this instance's configuration (the cage.yaml entry's
    /// `config:`, `{}` when absent). An `Err` refuses it; the message is
    /// reported to the operator and the previous configuration stays.
    ///
    /// # Errors
    ///
    /// Whatever the inspector finds wrong with `config`.
    fn configure(&mut self, config: &Value) -> Result<(), String> {
        let _ = config;
        Ok(())
    }

    /// Inspect a message the cage sends. `None` abstains.
    fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
        let _ = ctx;
        None
    }

    /// Inspect a message the cage receives. `None` abstains.
    fn inspect_response(&self, ctx: &Context) -> Option<Verdict> {
        let _ = ctx;
        None
    }
}

/// Deserialize a typed configuration from `config`.
///
/// ```ignore
/// #[derive(serde::Deserialize)]
/// struct Cfg { required_header: String }
///
/// let cfg: Cfg = agentcage_inspector_sdk::parse_config(config)?;
/// ```
///
/// # Errors
///
/// The deserializer's message, prefixed with `invalid config: `.
pub fn parse_config<T: serde::de::DeserializeOwned>(config: &Value) -> Result<T, String> {
    T::deserialize(config).map_err(|e| format!("invalid config: {e}"))
}

/// Export `$ty` (an [`Inspector`]) as this component's
/// `agentcage:inspector` implementation. Invoke it once, at the crate
/// root of a `cdylib` crate built for `wasm32-wasip2`.
#[macro_export]
macro_rules! export_inspector {
    ($ty:ty) => {
        const _: () = {
            ::std::thread_local! {
                static INSTANCE: ::std::cell::RefCell<::std::option::Option<$ty>> =
                    const { ::std::cell::RefCell::new(::std::option::Option::None) };
            }

            struct Component;

            impl $crate::bindings::Guest for Component {
                fn configure(
                    config: ::std::string::String,
                ) -> ::std::result::Result<(), ::std::string::String> {
                    INSTANCE.with(|cell| $crate::__private::configure::<$ty>(cell, &config))
                }

                fn inspect_request(
                    ctx: $crate::__private::WitContext,
                ) -> ::std::option::Option<$crate::__private::WitVerdict> {
                    INSTANCE.with(|cell| {
                        $crate::__private::inspect::<$ty>(cell, ctx, <$ty as $crate::Inspector>::inspect_request)
                    })
                }

                fn inspect_response(
                    ctx: $crate::__private::WitContext,
                ) -> ::std::option::Option<$crate::__private::WitVerdict> {
                    INSTANCE.with(|cell| {
                        $crate::__private::inspect::<$ty>(cell, ctx, <$ty as $crate::Inspector>::inspect_response)
                    })
                }
            }

            $crate::bindings::__agentcage_export_inspector_world!(Component with_types_in $crate::bindings);
        };
    };
}

/// Glue for [`export_inspector!`]; not part of the API.
#[doc(hidden)]
pub mod __private {
    use super::{
        Action, Context, Direction, Inspector, Phase, PriorResult, RefCell, Severity, Value,
        Verdict, wit,
    };

    pub use wit::{Context as WitContext, Verdict as WitVerdict};

    /// `configure`: parse, configure a fresh default, swap it in only on
    /// success.
    ///
    /// # Errors
    ///
    /// The config is not JSON, or the inspector refused it.
    pub fn configure<T: Inspector>(cell: &RefCell<Option<T>>, config: &str) -> Result<(), String> {
        quiet_panics();
        let value: Value =
            serde_json::from_str(config).map_err(|e| format!("config is not JSON: {e}"))?;
        let mut fresh = T::default();
        fresh.configure(&value)?;
        *cell.borrow_mut() = Some(fresh);
        Ok(())
    }

    /// Replace the default panic hook with one that does nothing.
    ///
    /// The default hook reads `RUST_BACKTRACE` and writes the message to
    /// stderr, and a plugin has neither: the write itself would trap as
    /// an unknown import, so the egress would report that instead of the
    /// panic. With this hook a panic goes straight to the abort, which the
    /// egress reports as a wasm `unreachable` trap.
    pub fn quiet_panics() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    }

    /// `inspect-*`: convert, call, convert back.
    pub fn inspect<T: Inspector>(
        cell: &RefCell<Option<T>>,
        ctx: WitContext,
        method: impl FnOnce(&T, &Context) -> Option<Verdict>,
    ) -> Option<WitVerdict> {
        let ctx = from_wit_context(ctx);
        let mut slot = cell.borrow_mut();
        let inspector = slot.get_or_insert_with(T::default);
        method(inspector, &ctx).map(to_wit_verdict)
    }

    fn from_wit_context(ctx: WitContext) -> Context {
        Context {
            url: ctx.url,
            host: ctx.host,
            method: ctx.method,
            headers: ctx.headers,
            content_type: ctx.content_type,
            body: ctx.body,
            body_text: ctx.body_text,
            body_size: ctx.body_size,
            body_entropy: ctx.body_entropy,
            prior_results: ctx
                .prior_results
                .into_iter()
                .map(|r| PriorResult {
                    inspector: r.inspector,
                    action: from_wit_action(r.action),
                    reason: r.reason,
                    severity: from_wit_severity(r.severity),
                    metadata: from_wit_metadata(r.metadata),
                })
                .collect(),
            direction: match ctx.direction {
                wit::Direction::Outbound => Direction::Outbound,
                wit::Direction::Inbound => Direction::Inbound,
            },
            phase: match ctx.phase {
                wit::Phase::Request => Phase::Request,
                wit::Phase::Response => Phase::Response,
                wit::Phase::Websocket => Phase::WebSocket,
            },
        }
    }

    fn from_wit_action(action: wit::Action) -> Action {
        match action {
            wit::Action::Block => Action::Block,
            wit::Action::Flag => Action::Flag,
        }
    }

    fn from_wit_severity(severity: wit::Severity) -> Severity {
        match severity {
            wit::Severity::Debug => Severity::Debug,
            wit::Severity::Info => Severity::Info,
            wit::Severity::Warning => Severity::Warning,
            wit::Severity::Error => Severity::Error,
            wit::Severity::Critical => Severity::Critical,
        }
    }

    fn from_wit_metadata(entries: Vec<wit::MetadataEntry>) -> Vec<(String, Value)> {
        entries
            .into_iter()
            .map(|e| {
                // The egress always sends JSON; keep the raw text rather
                // than lose an entry if that ever changes.
                let value = serde_json::from_str(&e.value).unwrap_or(Value::String(e.value));
                (e.key, value)
            })
            .collect()
    }

    fn to_wit_verdict(verdict: Verdict) -> WitVerdict {
        WitVerdict {
            action: match verdict.action {
                Action::Block => wit::Action::Block,
                Action::Flag => wit::Action::Flag,
            },
            reason: verdict.reason,
            severity: match verdict.severity {
                Severity::Debug => wit::Severity::Debug,
                Severity::Info => wit::Severity::Info,
                Severity::Warning => wit::Severity::Warning,
                Severity::Error => wit::Severity::Error,
                Severity::Critical => wit::Severity::Critical,
            },
            metadata: verdict
                .metadata
                .into_iter()
                .map(|(key, value)| wit::MetadataEntry {
                    key,
                    value: value.to_string(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Word(String);

    impl Inspector for Word {
        fn configure(&mut self, config: &Value) -> Result<(), String> {
            self.0 = config["word"]
                .as_str()
                .ok_or("config.word must be a string")?
                .to_owned();
            Ok(())
        }

        fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
            ctx.body_text
                .as_deref()?
                .contains(&self.0)
                .then(|| Verdict::block(format!("saw {}", self.0)).with_metadata("n", 1))
        }
    }

    fn wit_ctx(body: &str) -> WitContextAlias {
        wit::Context {
            url: "https://example.com/".into(),
            host: "example.com".into(),
            method: "POST".into(),
            headers: vec![("X-A".into(), "1".into()), ("x-a".into(), "2".into())],
            content_type: "text/plain".into(),
            body: Some(body.as_bytes().to_vec()),
            body_text: Some(body.into()),
            body_size: body.len() as u64,
            body_entropy: None,
            prior_results: vec![wit::PriorResult {
                inspector: "secrets".into(),
                action: wit::Action::Flag,
                reason: "r".into(),
                severity: wit::Severity::Error,
                metadata: vec![wit::MetadataEntry {
                    key: "k".into(),
                    value: "{\"a\": [1]}".into(),
                }],
            }],
            direction: wit::Direction::Outbound,
            phase: wit::Phase::Request,
        }
    }

    type WitContextAlias = wit::Context;

    #[test]
    fn a_failed_configure_keeps_the_previous_instance() {
        let cell = RefCell::new(None::<Word>);
        __private::configure(&cell, r#"{"word": "EXFIL"}"#).unwrap();
        let err = __private::configure(&cell, r#"{"word": 3}"#).unwrap_err();
        assert_eq!(err, "config.word must be a string");
        assert!(__private::configure(&cell, "not json").is_err());
        assert_eq!(cell.borrow().as_ref().unwrap().0, "EXFIL");
    }

    #[test]
    fn verdicts_and_contexts_cross_the_boundary_intact() {
        let cell = RefCell::new(None::<Word>);
        __private::configure(&cell, r#"{"word": "EXFIL"}"#).unwrap();
        assert!(__private::inspect(&cell, wit_ctx("fine"), Inspector::inspect_request).is_none());
        let v = __private::inspect(&cell, wit_ctx("an EXFIL"), Inspector::inspect_request).unwrap();
        assert!(matches!(v.action, wit::Action::Block));
        assert!(matches!(v.severity, wit::Severity::Warning));
        assert_eq!(v.reason, "saw EXFIL");
        assert_eq!(v.metadata[0].key, "n");
        assert_eq!(v.metadata[0].value, "1");

        let mut seen = None;
        __private::inspect(&cell, wit_ctx("x"), |_: &Word, c| {
            seen = Some(c.clone());
            None
        });
        let seen = seen.unwrap();
        assert_eq!(seen.header_values("x-a").collect::<Vec<_>>(), ["1", "2"]);
        assert_eq!(seen.header("X-A"), Some("1"));
        assert_eq!(seen.prior_results[0].metadata[0].1, json!({"a": [1]}));
        assert_eq!(seen.prior_results[0].severity, Severity::Error);
    }

    #[test]
    fn typed_configs_parse() {
        #[derive(serde::Deserialize)]
        struct Cfg {
            n: u32,
        }
        let cfg: Cfg = parse_config(&json!({"n": 4})).unwrap();
        assert_eq!(cfg.n, 4);
        let err = parse_config::<Cfg>(&json!({})).err().unwrap();
        assert!(err.starts_with("invalid config: missing field"), "{err}");
    }
}
