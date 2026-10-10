//! The record kinds the request pipeline emits.
//!
//! Field sets and order are the replaced implementation's, byte for byte
//! (pinned by `tests/fixtures/egress/audit_lines.json`), except for the
//! two kinds this port adds, `upstream_error` (plan D5) and
//! `config_reload_failed` (plan D1), whose shapes are defined here.
//!
//! Every builder takes the record's timestamp explicitly; producers pass
//! `DateTime::now_utc()`.

use agentcage_core::har::datetime::DateTime;

use super::AuditSink;
use crate::config::{self, Config};
use crate::inspect::Verdict;
use crate::json::{Json, object};
use crate::message::Request;

/// What happened to a request, as audit and capture records spell it.
///
/// Ordered by severity, which is how a WebSocket's capture decision
/// escalates with its frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Decision {
    /// `allowed`
    Allowed,
    /// `flagged`: allowed, with at least one inspector's flag.
    Flagged,
    /// `blocked`
    Blocked,
}

impl Decision {
    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Flagged => "flagged",
            Self::Blocked => "blocked",
        }
    }
}

/// Which way a flow goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Cage to world (forward and transparent listeners).
    Outbound,
    /// World to cage (a reverse listener on an inbound port).
    Inbound,
}

impl Direction {
    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Inbound => "inbound",
        }
    }
}

/// Whether allowed requests (HTTP and relay commands) reach the durable
/// log.
///
/// `logging.allowed_requests` wins whenever it is present, even as
/// `false`; the legacy top-level `log_allowed` is the fallback only when
/// it is absent; with neither the answer is off, the host's documented
/// default. Pinned to the host by
/// `tests/fixtures/contracts/logging_defaults.json`.
#[must_use]
pub fn log_allowed(cfg: &Config) -> bool {
    let logging = cfg.section("logging");
    if let Some(value) = config::mget(logging, "allowed_requests") {
        return config::truthy(value);
    }
    cfg.get("log_allowed").is_some_and(config::truthy)
}

/// An inspector chain's verdicts as audit and capture records list them:
/// `[{name, action, reason, severity}, …]`.
#[must_use]
pub fn inspectors_json(results: &[Verdict]) -> Json {
    Json::Array(
        results
            .iter()
            .map(|r| {
                object([
                    ("name", Json::string(r.inspector.clone())),
                    ("action", Json::string(r.action.as_str())),
                    ("reason", Json::string(r.reason.clone())),
                    ("severity", Json::string(r.severity.as_str())),
                ])
            })
            .collect(),
    )
}

/// One HTTP (or WebSocket message) decision record.
///
/// The request fields are read when the record is built, which for an
/// allowed or flagged request is after injection: a rule that injects
/// into the URL has its secret in `url` and `path`. The sink's redaction
/// swaps it back to the placeholder.
#[derive(Clone, Debug, PartialEq)]
pub struct HttpDecision {
    /// When the decision was made.
    pub ts: DateTime,
    /// Outbound or inbound.
    pub direction: Direction,
    /// The request method.
    pub method: String,
    /// The request host (after re-targeting).
    pub host: String,
    /// The upstream port.
    pub port: u16,
    /// The request path and query.
    pub path: String,
    /// The full URL.
    pub url: String,
    /// The decision.
    pub decision: Decision,
    /// The reason (`""` for a plain allowed request).
    pub reason: String,
    /// The client address of an inbound request (`""` when none).
    pub source: String,
    /// Names of the rules whose secrets were injected.
    pub secrets_injected: Vec<String>,
    /// Names of the rules whose secrets were redacted from the response.
    pub secrets_redacted: Vec<String>,
    /// Every verdict the chain returned, in order.
    pub inspectors: Vec<Verdict>,
}

impl HttpDecision {
    /// A record for `req` as it is now, stamped with the current time,
    /// with no source, secrets or verdicts.
    #[must_use]
    pub fn new(
        req: &Request,
        direction: Direction,
        decision: Decision,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            ts: DateTime::now_utc(),
            direction,
            method: req.method.clone(),
            host: req.host.clone(),
            port: req.port,
            path: req.path.clone(),
            url: req.url(),
            decision,
            reason: reason.into(),
            source: String::new(),
            secrets_injected: Vec::new(),
            secrets_redacted: Vec::new(),
            inspectors: Vec::new(),
        }
    }

    /// The record: `ts, direction, method, host, port, path, url,
    /// decision, reason`, then `source`, `secrets_injected`,
    /// `secrets_redacted` and `inspectors`, each only when non-empty.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let mut entry = object([
            ("ts", Json::string(self.ts.isoformat())),
            ("direction", Json::string(self.direction.as_str())),
            ("method", Json::string(self.method.clone())),
            ("host", Json::string(self.host.clone())),
            ("port", Json::Int(i64::from(self.port))),
            ("path", Json::string(self.path.clone())),
            ("url", Json::string(self.url.clone())),
            ("decision", Json::string(self.decision.as_str())),
            ("reason", Json::string(self.reason.clone())),
        ]);
        if !self.source.is_empty() {
            entry.set("source", Json::string(self.source.clone()));
        }
        let names = |v: &[String]| Json::Array(v.iter().cloned().map(Json::Str).collect());
        if !self.secrets_injected.is_empty() {
            entry.set("secrets_injected", names(&self.secrets_injected));
        }
        if !self.secrets_redacted.is_empty() {
            entry.set("secrets_redacted", names(&self.secrets_redacted));
        }
        if !self.inspectors.is_empty() {
            entry.set("inspectors", inspectors_json(&self.inspectors));
        }
        entry
    }

    /// Emit the record.
    ///
    /// An allowed request that injected or redacted a secret is always
    /// logged: which requests received a credential is the audit trail
    /// that matters. Any other allowed request reaches the durable sinks
    /// only when `log_allowed` (see [`log_allowed`]); otherwise it goes
    /// to the watcher only ([`AuditSink::emit_ring_only`]), since
    /// exfiltration lives in allowed traffic.
    pub fn emit(&self, sink: &dyn AuditSink, log_allowed: bool) {
        let entry = self.to_json();
        if self.decision == Decision::Allowed
            && !log_allowed
            && self.secrets_injected.is_empty()
            && self.secrets_redacted.is_empty()
        {
            sink.emit_ring_only(entry);
        } else {
            sink.emit(entry);
        }
    }
}

/// The best identifier for the destination of a non-HTTP flow: the TLS
/// SNI when there is one (the cage committed to it), else the connected
/// peer, else the original destination `SO_ORIGINAL_DST` preserved, as
/// `host:port` (an IPv6 address is not bracketed), else `<unknown>`.
#[must_use]
pub fn tcp_bypass_target(
    sni: Option<&str>,
    peer: Option<(&str, u16)>,
    original_dst: Option<(&str, u16)>,
) -> String {
    if let Some(sni) = sni.filter(|s| !s.is_empty()) {
        return sni.to_owned();
    }
    [peer, original_dst]
        .into_iter()
        .flatten()
        .find(|(host, _)| !host.is_empty())
        .map_or_else(|| "<unknown>".to_owned(), |(h, p)| format!("{h}:{p}"))
}

/// A non-HTTP flow on an intercepted port, closed before any upstream
/// socket opened: `{ts, kind: "tcp_bypass_blocked", direction:
/// "outbound", decision: "blocked", reason, host}`, `host` being
/// [`tcp_bypass_target`].
#[must_use]
pub fn tcp_bypass_blocked(ts: DateTime, target: &str) -> Json {
    object([
        ("ts", Json::string(ts.isoformat())),
        ("kind", Json::string("tcp_bypass_blocked")),
        ("direction", Json::string("outbound")),
        ("decision", Json::string("blocked")),
        (
            "reason",
            Json::string(format!(
                "non-http TCP bypass: cage opened a raw TCP/TLS flow to {target} that does \
                 not speak HTTP; the L7 allowlist, inspectors, and secret-injection policy \
                 do not apply to raw byte streams"
            )),
        ),
        ("host", Json::string(target)),
    ])
}

/// A grant-only host that resolved to a non-global address: `{ts, kind:
/// "private_peer_blocked", direction: "outbound", decision: "blocked",
/// reason, host, peer_ip, phase}`.
///
/// The record's `reason` is also the error the pipeline puts on the
/// refused connection.
#[must_use]
pub fn private_peer_blocked(ts: DateTime, host: &str, peer_ip: &str, phase: &str) -> Json {
    let reason = format!(
        "granted domain {host} resolves to non-global address {peer_ip}; refusing the \
         upstream connection. A grant is a NAME, and DNS can point that name at an internal \
         address after the fact (rebinding) or by design (localtest.me). Operator-configured \
         baseline domains are unaffected."
    );
    object([
        ("ts", Json::string(ts.isoformat())),
        ("kind", Json::string("private_peer_blocked")),
        ("direction", Json::string("outbound")),
        ("decision", Json::string("blocked")),
        ("reason", Json::string(reason)),
        ("host", Json::string(host)),
        ("peer_ip", Json::string(peer_ip)),
        ("phase", Json::string(phase)),
    ])
}

/// A relay that could not be configured, built or started: `{kind,
/// relay, error}` with `kind` one of `relay_config_invalid`,
/// `relay_init_failed`, `relay_start_failed`. No `ts`: the writer
/// appends it, after the other fields, as it did in the replaced
/// implementation.
#[must_use]
pub fn relay_failure(kind: &str, relay: &str, error: &str) -> Json {
    object([
        ("kind", Json::string(kind)),
        ("relay", Json::string(relay)),
        ("error", Json::string(error)),
    ])
}

/// The upstream of an allowed request failed (refused, reset, TLS or
/// protocol error, timeout), and the cage got a 502 (plan D5): `{ts,
/// kind: "upstream_error", direction, method, host, port, path, url,
/// decision: "error", reason}`.
///
/// It carries the HTTP fields (and so `method`) so the host's `cage
/// audit` lists it with the request it belongs to; the request's own
/// `allowed` record was written before the upstream was tried. `reason`
/// is the transport error as text.
#[must_use]
pub fn upstream_error(ts: DateTime, req: &Request, direction: Direction, reason: &str) -> Json {
    object([
        ("ts", Json::string(ts.isoformat())),
        ("kind", Json::string("upstream_error")),
        ("direction", Json::string(direction.as_str())),
        ("method", Json::string(req.method.clone())),
        ("host", Json::string(req.host.clone())),
        ("port", Json::Int(i64::from(req.port))),
        ("path", Json::string(req.path.clone())),
        ("url", Json::string(req.url())),
        ("decision", Json::string("error")),
        ("reason", Json::string(reason)),
    ])
}

/// A config edit that could not be applied; the last good config stays
/// live (plan D1): `{ts, kind: "config_reload_failed", path, reason}`,
/// `reason` being `config reload failed, keeping the last good config:
/// <error>`. One record per file version, not per poll.
#[must_use]
pub fn config_reload_failed(ts: DateTime, path: &str, error: &str) -> Json {
    object([
        ("ts", Json::string(ts.isoformat())),
        ("kind", Json::string("config_reload_failed")),
        ("path", Json::string(path)),
        (
            "reason",
            Json::string(format!(
                "config reload failed, keeping the last good config: {error}"
            )),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::MemorySink;
    use crate::inspect::{Action, Severity};
    use crate::json;

    fn ts() -> DateTime {
        DateTime::from_parts((2026, 10, 10), (0, 0, 0, 0), Some(0)).unwrap()
    }

    fn req() -> Request {
        Request {
            method: "GET".into(),
            scheme: "https".into(),
            host: "api.example.com".into(),
            port: 443,
            path: "/x".into(),
            ..Request::default()
        }
    }

    #[test]
    fn log_allowed_follows_the_shared_contract_fixture() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/contracts/logging_defaults.json"
        );
        let doc = json::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
        let Some(Json::Array(cases)) = doc.get("cases") else {
            panic!("no cases")
        };
        assert!(!cases.is_empty());
        for case in cases {
            let id = case.get("id").and_then(Json::as_str).unwrap();
            let yaml = json::to_string(case.get("proxy_config").unwrap());
            let cfg = Config::parse(id, &yaml).unwrap();
            let want = case.get("allowed_requests") == Some(&Json::Bool(true));
            assert_eq!(log_allowed(&cfg), want, "{id}");
        }
    }

    #[test]
    fn plain_allowed_goes_to_the_ring_only_unless_logged_or_secret_bearing() {
        let sink = MemorySink::default();
        let mut rec = HttpDecision::new(&req(), Direction::Outbound, Decision::Allowed, "");
        rec.emit(&sink, false);
        assert_eq!((sink.entries().len(), sink.ring_only().len()), (0, 1));
        rec.emit(&sink, true);
        assert_eq!(sink.entries().len(), 1);
        rec.secrets_redacted = vec!["K".into()];
        rec.emit(&sink, false);
        assert_eq!(sink.entries().len(), 2);
        rec.secrets_redacted.clear();
        rec.decision = Decision::Flagged;
        rec.emit(&sink, false);
        assert_eq!((sink.entries().len(), sink.ring_only().len()), (3, 1));
    }

    #[test]
    fn the_new_kinds_have_their_documented_shapes() {
        assert_eq!(
            json::to_string(&upstream_error(
                ts(),
                &req(),
                Direction::Outbound,
                "connection refused"
            )),
            r#"{"ts": "2026-10-10T00:00:00+00:00", "kind": "upstream_error", "direction": "outbound", "method": "GET", "host": "api.example.com", "port": 443, "path": "/x", "url": "https://api.example.com/x", "decision": "error", "reason": "connection refused"}"#
        );
        assert_eq!(
            json::to_string(&config_reload_failed(
                ts(),
                "/etc/agentcage/config.yaml",
                "bad"
            )),
            r#"{"ts": "2026-10-10T00:00:00+00:00", "kind": "config_reload_failed", "path": "/etc/agentcage/config.yaml", "reason": "config reload failed, keeping the last good config: bad"}"#
        );
        assert_eq!(
            json::to_string(&relay_failure("relay_init_failed", "mail", "boom")),
            r#"{"kind": "relay_init_failed", "relay": "mail", "error": "boom"}"#
        );
    }

    #[test]
    fn inspectors_keep_chain_order_and_wire_spellings() {
        let v = [
            Verdict::new("a", Action::Flag, "r1", Severity::Info),
            Verdict::new("b", Action::Block, "r2", Severity::Critical),
        ];
        assert_eq!(
            json::to_string(&inspectors_json(&v)),
            r#"[{"name": "a", "action": "flag", "reason": "r1", "severity": "info"}, {"name": "b", "action": "block", "reason": "r2", "severity": "critical"}]"#
        );
    }
}
