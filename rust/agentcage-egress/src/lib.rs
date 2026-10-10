//! agentcage's per-cage egress proxy.
//!
//! Every byte a cage sends to the network leaves through this process. It
//! runs inside the cage's egress container, started by
//! `supervisor-egress.sh` after iptables and dnsmasq are up, and it owns:
//!
//! * the listeners: the forward proxy (`:8080`, `CONNECT` and absolute-form
//!   HTTP), the transparent listener (`:8443`, behind an iptables `REDIRECT`
//!   of every inspected port) and one reverse listener per inbound port
//!   ([`proxy`]);
//! * TLS interception with a CA generated per cage on first start ([`ca`]);
//! * the per-request pipeline: SNI/Host match, rate limit, inspector chain,
//!   secret injection and redaction, audit and capture ([`flow`],
//!   [`inspect`], [`inject`], [`audit`], [`capture`]);
//! * the control plane: the Policy API vhost, the grants overlay and its DNS
//!   publish, the LLM decider and the traffic watcher ([`policy`], [`llm`],
//!   [`watcher`]);
//! * the IMAP and SMTP protocol relays ([`relays`]);
//! * custom inspectors, loaded as WebAssembly components ([`plugin`]).
//!
//! The behaviour is specified by `EGRESS-PORT-PLAN.md` §5 and pinned by the
//! language-neutral corpora under `tests/fixtures/egress/`, which were
//! recorded from the implementation this crate replaces.

pub mod audit;
pub mod ca;
pub mod capture;
pub mod config;
pub mod engine;
pub mod flow;
pub mod inject;
pub mod inspect;
pub mod json;
pub mod llm;
pub mod message;
pub mod plugin;
pub mod policy;
pub mod proxy;
pub mod relays;
pub mod secret_lookup;
pub mod text;
pub mod transforms;
pub mod watcher;

/// The agentcage version this egress was built as.
///
/// Reported by the Policy API's `/v1/health` and checked against the
/// config's `agentcage_version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
