//! The per-request pipeline (plan §5.1, steps 1–12) and the response
//! side: block, 429 and 502 responses, capture staging, redaction.
//!
//! [`Pipeline`] is the [`FlowHandler`] the proxy core calls. It is a
//! port of the replaced implementation's `request`, `response`,
//! `websocket_message`, `tcp_start` and `server_connect` hooks, in their
//! order and with their reason strings and audit records, plus the
//! decided changes:
//!
//! * **D1, fail closed.** An internal error on a flow (a body whose
//!   Content-Encoding cannot be removed, an injection that cannot be
//!   applied, a worker that died) is a JSON 502 and an `internal_error`
//!   audit record, never an unfiltered pass.
//! * **D3, D5, D6.** Refused forward-proxy ports and oversized bodies
//!   are 403 / 413 with a `blocked` record; an upstream failure is a JSON
//!   502 with an `upstream_error` record.
//! * **The peer guard resolves once.** The proxy hands
//!   [`FlowHandler::server_connect`] the addresses it will dial, so a
//!   grant-only host is judged on exactly those, and the
//!   `server_connected` backstop (and its short DNS cache) has nothing
//!   left to catch.
//!
//! CPU-bound work — the inspector chain, injection (which may mint a
//! token over the network), redaction of large bodies, the Policy API's
//! decider call — runs on blocking workers, so one large body never
//! stalls the runtime.

use std::borrow::Cow;
use std::sync::Arc;

use agentcage_core::config::is_global_ip;
use agentcage_core::har::datetime::DateTime;
use agentcage_core::python::repr_str;

use crate::audit::{self, AuditSink as _, Decision, Direction as AuditDirection, HttpDecision};
use crate::capture::{FlowInfo, capture_inspectors};
use crate::engine::{Engine, Live};
use crate::inspect::{
    Action, Context, Direction as InspectDirection, Phase, Verdict, run_chain, shannon_entropy,
};
use crate::json::{self, Json, object};
use crate::message::{Request, Response};
use crate::policy::{CONTENT_TYPE, ControlRequest};
use crate::proxy::{
    BodyBudget, ConnInfo, ConnectDecision, ConnectTarget, Direction, FlowEnd, FlowHandler, Refusal,
    RequestAction, Reservation, ResponseStream, UpstreamError, WsMessage, WsVerdict, make_response,
    parse_authority, retarget_to_host,
};
use crate::text;

mod stream;

/// The headers a reverse (inbound) flow drops instead of forwarding:
/// client attribution the egress cannot vouch for.
const FORWARDING_HEADERS: [&str; 5] = [
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
    "forwarded",
];

/// One forwarded flow's state, from the request hook to its end.
#[derive(Debug)]
pub struct Flow {
    id: String,
    direction: AuditDirection,
    live: Arc<Live>,
}

/// The request pipeline over the shared [`Engine`].
#[derive(Debug, Clone)]
pub struct Pipeline {
    engine: Arc<Engine>,
    /// The proxy's body budget, once bound: decoded copies of buffered
    /// bodies are accounted on it too.
    budget: Arc<std::sync::OnceLock<Arc<BodyBudget>>>,
}

impl Pipeline {
    /// A pipeline over `engine`.
    #[must_use]
    pub fn new(engine: Arc<Engine>) -> Self {
        Self {
            engine,
            budget: Arc::default(),
        }
    }

    /// The engine.
    #[must_use]
    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }
}

fn audit_direction(conn: &ConnInfo) -> AuditDirection {
    match conn.direction() {
        Direction::Inbound => AuditDirection::Inbound,
        Direction::Outbound => AuditDirection::Outbound,
    }
}

/// The flow's direction as custom inspectors are handed it.
fn inspect_direction(direction: AuditDirection) -> InspectDirection {
    match direction {
        AuditDirection::Inbound => InspectDirection::Inbound,
        AuditDirection::Outbound => InspectDirection::Outbound,
    }
}

/// `{"blocked": <b>, "reason": r, "host": h, "by": "agentcage"}`.
fn block_body(blocked: bool, reason: &str, host: &str) -> Vec<u8> {
    json::to_string(&object([
        ("blocked", Json::Bool(blocked)),
        ("reason", Json::string(reason)),
        ("host", Json::string(host)),
        ("by", Json::string("agentcage")),
    ]))
    .into_bytes()
}

fn json_response(status: u16, body: Vec<u8>) -> Response {
    make_response(status, &[("Content-Type", "application/json")], body)
}

/// A fresh flow id (a random UUID, as flow ids were).
fn flow_id() -> String {
    let mut b = [0u8; 16];
    if getrandom::fill(&mut b).is_err() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        b = n.to_be_bytes();
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = b.iter().fold(String::new(), |mut out, x| {
        use std::fmt::Write as _;
        let _ = write!(out, "{x:02x}");
        out
    });
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// Run `f` on a blocking worker; a worker that panicked is an internal
/// error (D1).
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("worker failed: {e}"))
}

fn headers_text(headers: &crate::message::Headers) -> Vec<(String, String)> {
    headers.to_strings()
}

/// The inspection context of a message whose decoded body is `content`
/// (`headers` are the message's own), built before injection so
/// inspectors see placeholders.
fn context(
    req: &Request,
    headers: &crate::message::Headers,
    content: Vec<u8>,
    direction: AuditDirection,
) -> Context {
    // `get_text` over the decoded body: the lenient decode it starts from
    // is the strict one whenever the strict one succeeds, which it did.
    let content_type = headers.get("content-type").unwrap_or_default();
    let body_text = text::decode_text(&content_type, &content);
    let size = content.len();
    let entropy = (!content.is_empty()).then(|| shannon_entropy(&content));
    Context {
        url: req.url(),
        host: req.host.clone(),
        method: req.method.clone(),
        headers: headers_text(headers),
        content_type,
        body_bytes: Some(content.into()),
        body_text: Some(body_text),
        body_size: size,
        body_entropy: entropy,
        prior_results: Vec::new(),
        direction: inspect_direction(direction),
        websocket: false,
    }
}

/// The inspection context of a request. A body without a
/// Content-Encoding is moved into the context rather than copied (the
/// second value says so); [`restore_body`] puts it back once the chain
/// has run.
///
/// # Errors
///
/// The body's Content-Encoding cannot be removed.
fn request_context(
    req: &mut Request,
    direction: AuditDirection,
) -> Result<(Context, bool), text::DecodeError> {
    let (content, moved) = match text::decoded_body(&req.headers, &req.body)? {
        Cow::Owned(decoded) => (decoded, false),
        Cow::Borrowed(_) => (std::mem::take(&mut req.body), true),
    };
    Ok((context(req, &req.headers, content, direction), moved))
}

/// Give a request back the body [`request_context`] moved out of it.
fn restore_body(req: &mut Request, ctx: &mut Context, moved: bool) {
    if moved {
        // Unshared again once the chain is done with it: no copy.
        req.body = ctx.body_bytes.take().map(Vec::from).unwrap_or_default();
    }
}

/// The body capture records: the lenient decode, borrowed (no copy)
/// when the body has no Content-Encoding.
fn lenient_body<'a>(headers: &crate::message::Headers, raw: &'a [u8]) -> Cow<'a, [u8]> {
    text::decoded_body_lenient(headers, raw)
}

/// Run the live chain over `ctx` off the runtime; the context comes
/// back with the verdicts.
async fn run_inspectors(
    live: &Arc<Live>,
    mut ctx: Context,
    phase: Phase,
    skip_domain: bool,
) -> Result<(Vec<Verdict>, Context), String> {
    let live = Arc::clone(live);
    blocking(move || {
        let chain = &live.chain;
        let results = run_chain(chain.inspectors(), &mut ctx, phase, &|i| {
            skip_domain && chain.is_domain(i)
        });
        (results, ctx)
    })
    .await
}

/// The Host header's host part, as the SNI/Host rule compares it: the
/// port stripped (`rsplit(":", 1)[0]`), but an IPv6 literal unbracketed
/// whole rather than cut at its last colon.
fn host_header_name(header: &str) -> String {
    if header.starts_with('[') {
        parse_authority(header).0
    } else {
        header
            .rsplit_once(':')
            .map_or(header, |(h, _)| h)
            .to_owned()
    }
}

/// An HTTP decision record for `req` as it is now, with the chain's
/// verdicts.
fn record(
    req: &Request,
    direction: AuditDirection,
    decision: Decision,
    reason: &str,
    results: &[Verdict],
) -> HttpDecision {
    let mut rec = HttpDecision::new(req, direction, decision, reason);
    rec.inspectors = results.to_vec();
    rec
}

fn normalise(name: &str) -> String {
    name.to_lowercase().trim_end_matches('.').to_owned()
}

impl Pipeline {
    /// Hold `n` bytes of a body copy (a decoded one) on the body budget
    /// until the returned reservation drops; refused (the flow fails
    /// closed) when the budget stays full.
    async fn hold_copy(&self, n: usize) -> Result<Option<Reservation>, String> {
        let Some(budget) = self.budget.get() else {
            return Ok(None);
        };
        let mut held = Reservation::new(budget);
        if held.grow_to(n).await {
            Ok(Some(held))
        } else {
            Err(UpstreamError::BodyBudgetExhausted {
                limit: budget.limit(),
            }
            .to_string())
        }
    }

    /// [`request_context`], with a decoded copy of a compressed body held
    /// on the body budget while it lives.
    async fn held_context(
        &self,
        req: &mut Request,
        direction: AuditDirection,
    ) -> Result<(Context, bool, Option<Reservation>), String> {
        let (ctx, moved) = request_context(req, direction).map_err(|e| e.to_string())?;
        let copy = self
            .hold_copy(if moved { 0 } else { ctx.body_size })
            .await?;
        Ok((ctx, moved, copy))
    }

    /// D1: a flow that hit an internal error gets a 502 and a record.
    fn internal_error(&self, req: &Request, direction: AuditDirection, error: &str) -> Response {
        let reason = format!("internal error: {error}");
        self.engine.audit.emit(audit::internal_error(
            DateTime::now_utc(),
            req,
            direction,
            &reason,
        ));
        let (reason, _) = self.engine.injector.redact_text(&reason);
        json_response(502, block_body(false, &reason, &req.host))
    }

    async fn control(&self, conn: &ConnInfo, req: &Request) -> Option<Response> {
        let api = self.engine.policy()?;
        if !api.enabled() || conn.direction() == Direction::Inbound {
            return None;
        }
        if !api.is_control_host(conn.sni.as_deref(), req.host_header().as_deref()) {
            return None;
        }
        let method = req.method.clone();
        let path = req.path.clone();
        let body = lenient_body(&req.headers, &req.body).into_owned();
        let headers = headers_text(&req.headers);
        let answer = blocking(move || {
            api.handle(&ControlRequest {
                method: &method,
                path: &path,
                body: &body,
                headers: &headers,
            })
        })
        .await;
        let answer = match answer {
            Ok(answer) => answer,
            Err(e) => return Some(self.internal_error(req, AuditDirection::Outbound, &e)),
        };
        for record in answer.audit {
            self.engine.audit.emit(record);
        }
        Some(make_response(
            answer.status,
            &[("Content-Type", CONTENT_TYPE)],
            answer.body,
        ))
    }

    /// Step 4: TLS SNI and HTTP Host must name the same host.
    fn sni_host_mismatch(&self, conn: &ConnInfo, req: &Request, live: &Live) -> Option<Response> {
        let sni = conn.sni.as_deref().filter(|s| !s.is_empty())?;
        let host_hdr = req.host_header().filter(|h| !h.is_empty())?;
        if normalise(sni) == normalise(&host_header_name(&host_hdr)) {
            return None;
        }
        let reason = format!(
            "SNI/Host header mismatch: TLS was established with SNI={} but HTTP Host header \
             is {}; agentcage requires strict equality so audit identity, allowlist \
             decisions, and secret-injection routing all reference the same upstream",
            repr_str(sni),
            repr_str(&host_hdr)
        );
        record(
            req,
            AuditDirection::Outbound,
            Decision::Blocked,
            "sni-host mismatch",
            &[],
        )
        .emit(&*self.engine.audit, live.log_allowed);
        Some(json_response(403, block_body(true, &reason, &host_hdr)))
    }

    /// A request the chain blocked: 403, audit, and a capture entry of
    /// the never-forwarded request with any literal secret redacted.
    fn blocked(
        &self,
        live: &Live,
        req: &mut Request,
        direction: AuditDirection,
        source: &str,
        results: &[Verdict],
    ) -> Response {
        let reason = results
            .iter()
            .find(|r| r.action == Action::Block)
            .map(|r| r.reason.clone())
            .unwrap_or_default();
        let resp = json_response(403, block_body(true, &reason, &req.host));
        let mut rec = record(req, direction, Decision::Blocked, &reason, results);
        source.clone_into(&mut rec.source);
        rec.emit(&*self.engine.audit, live.log_allowed);
        let capture = &self.engine.capture;
        if capture.should_capture(Decision::Blocked, &req.host)
            && self.engine.injector.redact_request(req).is_ok()
        {
            let flow = FlowInfo {
                id: flow_id(),
                direction,
                decision: Decision::Blocked,
                host: req.host.clone(),
                method: req.method.clone(),
                path: req.path.clone(),
            };
            let content = lenient_body(&req.headers, &req.body);
            let resp_content = resp.body.clone();
            capture.record_blocked_request(
                &flow,
                &capture_inspectors(results, &*self.engine.injector),
                (req, &content),
                Some((&resp, &resp_content)),
            );
        }
        resp
    }

    /// Steps 6 and 7: the per-host rate limit and the rebind backstop.
    fn host_gates(&self, req: &Request, live: &Live) -> Option<Response> {
        let engine = &self.engine;
        // Step 6: rate limit.
        if !engine.rate_allows(&req.host, live) {
            let reason = "rate limit exceeded";
            record(
                req,
                AuditDirection::Outbound,
                Decision::Blocked,
                reason,
                &[],
            )
            .emit(&*engine.audit, live.log_allowed);
            return Some(json_response(429, block_body(true, reason, &req.host)));
        }
        // Step 7: rebind backstop.
        let key = normalise(&req.host);
        if engine.is_poisoned(&key) {
            let reason = format!(
                "granted domain {key} was observed resolving to a non-global address; \
                 refusing further requests"
            );
            record(
                req,
                AuditDirection::Outbound,
                Decision::Blocked,
                &reason,
                &[],
            )
            .emit(&*engine.audit, live.log_allowed);
            return Some(json_response(403, block_body(true, &reason, &req.host)));
        }
        None
    }

    async fn request_inner(
        &self,
        conn: &ConnInfo,
        req: &mut Request,
    ) -> Result<RequestAction<Flow>, String> {
        let engine = &self.engine;
        // Step 1: a request sent right after an edit sees it.
        if engine.config_changed() {
            let e = Arc::clone(engine);
            let _ = blocking(move || e.reload_if_changed()).await;
        }
        // Step 2.
        let reverse = conn.direction() == Direction::Inbound;
        let direction = audit_direction(conn);
        // Step 3: the Policy API control host, egress path only.
        if let Some(resp) = self.control(conn, req).await {
            return Ok(RequestAction::Respond(resp));
        }
        let live = engine.live();
        if !reverse {
            // Step 4.
            if let Some(resp) = self.sni_host_mismatch(conn, req, &live) {
                return Ok(RequestAction::Respond(resp));
            }
            // Step 5: follow the Host name, keep the destination port.
            retarget_to_host(req);
        }
        if let Some(resp) = self.host_gates(req, &live) {
            return Ok(RequestAction::Respond(resp));
        }
        // Step 8: injection policy (no mutation), then step 9: the
        // context, before injection.
        let inject_result = engine
            .injector
            .check_injection_policy(req)
            .map_err(|e| e.to_string())?;
        let (mut ctx, moved, _copy) = self.held_context(req, direction).await?;
        let mut results = Vec::new();
        if let Some(verdict) = inject_result {
            results.push(verdict.clone());
            ctx.prior_results.push(verdict);
        }
        // Step 10: reverse-only header handling.
        let mut source = String::new();
        if reverse {
            source = conn.client_addr.ip().to_string();
            for name in FORWARDING_HEADERS {
                req.headers.remove(name);
            }
            let proto = if conn.tls { "https" } else { "http" };
            let host_hdr = req
                .host_header()
                .unwrap_or_else(|| format!("{}:{}", req.host, req.port));
            if req.headers.get("origin").is_some_and(|o| !o.is_empty()) {
                req.headers.set("origin", format!("{proto}://{host_hdr}"));
            }
        }
        // Step 11: the chain, off the runtime; no domain check inbound.
        let (verdicts, mut ctx) = run_inspectors(&live, ctx, Phase::Request, reverse).await?;
        restore_body(req, &mut ctx, moved);
        drop(ctx);
        results.extend(verdicts);
        // Step 12: verdict.
        if results.iter().any(|r| r.action == Action::Block) {
            let resp = self.blocked(&live, req, direction, &source, &results);
            return Ok(RequestAction::Respond(resp));
        }
        let snapshot = engine
            .capture
            .snapshot_request(req, &lenient_body(&req.headers, &req.body));
        let injector = Arc::clone(&engine.injector);
        let mut owned = std::mem::take(req);
        let (owned, injected) = blocking(move || {
            let injected = injector.inject_request(&mut owned);
            (owned, injected)
        })
        .await?;
        *req = owned;
        let injected = injected.map_err(|e| e.to_string())?;
        let flagged: Vec<&Verdict> = results
            .iter()
            .filter(|r| r.action == Action::Flag)
            .collect();
        let (decision, reason) = if flagged.is_empty() {
            (Decision::Allowed, String::new())
        } else {
            let reasons: Vec<&str> = flagged.iter().map(|r| r.reason.as_str()).collect();
            (Decision::Flagged, reasons.join("; "))
        };
        let mut rec = record(req, direction, decision, &reason, &results);
        rec.source.clone_from(&source);
        rec.secrets_injected = injected;
        rec.emit(&*engine.audit, live.log_allowed);
        let id = flow_id();
        if let Some(snapshot) = snapshot {
            engine.capture.stage(
                FlowInfo {
                    id: id.clone(),
                    direction,
                    decision,
                    host: req.host.clone(),
                    method: req.method.clone(),
                    path: req.path.clone(),
                },
                capture_inspectors(&results, &*engine.injector),
                snapshot,
            );
        }
        Ok(RequestAction::Forward(Flow {
            id,
            direction,
            live,
        }))
    }

    async fn response_inner(
        &self,
        flow: &Flow,
        req: &mut Request,
        resp: &mut Response,
    ) -> Result<(), String> {
        let engine = &self.engine;
        // The upstream already has the injected request; put the
        // placeholders back for everything that records it.
        engine
            .injector
            .redact_request(req)
            .map_err(|e| e.to_string())?;
        engine
            .capture
            .refresh_request(&flow.id, req, &lenient_body(&req.headers, &req.body));
        // The body decoded once, for the inspectors, redaction and capture
        // alike (`None`: it has no Content-Encoding and is read in place).
        // A body that cannot be decoded fails the flow closed here.
        let decoded = match text::decoded_body(&resp.headers, &resp.body) {
            Ok(Cow::Owned(decoded)) => Some(decoded),
            Ok(Cow::Borrowed(_)) => None,
            Err(e) => return Err(e.to_string()),
        };
        let _copy = match &decoded {
            Some(copy) => self.hold_copy(copy.len()).await?,
            None => None,
        };
        // No built-in inspects responses: unless a plugin (or a refusing
        // chain) does, the context — a copy of the body, its text and its
        // entropy — is never built.
        let mut decoded = decoded;
        let results = if flow.live.chain.inspects_responses() {
            // The body (decoded, or the response's own) is moved into the
            // context and taken back after the chain, not copied.
            let content = match decoded.take() {
                Some(decoded) => (decoded, true),
                None => (std::mem::take(&mut resp.body), false),
            };
            let ctx = context(req, &resp.headers, content.0, flow.direction);
            let (results, mut ctx) =
                run_inspectors(&flow.live, ctx, Phase::Response, false).await?;
            let body = ctx.body_bytes.take().map(Vec::from).unwrap_or_default();
            if content.1 {
                decoded = Some(body);
            } else {
                resp.body = body;
            }
            results
        } else {
            Vec::new()
        };
        if let Some(block) = results.iter().find(|r| r.action == Action::Block) {
            // The reason can quote a secret the server echoed: redacted
            // before it is JSON-encoded into the 403.
            let (reason, mut redacted) = engine.injector.redact_text(&block.reason);
            *resp = json_response(403, block_body(true, &reason, &req.host));
            for name in engine
                .injector
                .redact_response(resp)
                .map_err(|e| e.to_string())?
            {
                if !redacted.contains(&name) {
                    redacted.push(name);
                }
            }
            let mut rec = record(req, flow.direction, Decision::Blocked, &reason, &results);
            rec.secrets_redacted = redacted;
            rec.emit(&*engine.audit, flow.live.log_allowed);
            let body = resp.body.clone();
            engine.capture.finish_blocked_response(
                &flow.id,
                capture_inspectors(&results, &*engine.injector),
                (resp, &body),
            );
            return Ok(());
        }
        let injector = Arc::clone(&engine.injector);
        let mut owned = std::mem::take(resp);
        let (owned, redacted, decoded) = blocking(move || {
            let (r, decoded) = injector.redact_response_decoded(&mut owned, decoded);
            (owned, r, decoded)
        })
        .await?;
        *resp = owned;
        redacted.map_err(|e| e.to_string())?;
        let websocket = resp.status == 101
            && resp
                .headers
                .get("upgrade")
                .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
            && req.headers.get("sec-websocket-version").as_deref() == Some("13");
        // What redaction left decoded, else the body as it is now (no
        // Content-Encoding, or rewritten without one).
        let content = decoded.as_deref().unwrap_or(&resp.body);
        engine
            .capture
            .finish_response(&flow.id, (resp, content), websocket);
        Ok(())
    }

    /// Whether (and how) to relay a response body as it arrives rather
    /// than buffer it: only when no response inspector needs it whole, its
    /// Content-Encoding can be removed as it streams, and a capture entry
    /// needs no more than a prefix of it. `None` keeps the buffered path,
    /// which also fails closed on anything the head already shows wrong.
    fn stream_plan(
        &self,
        flow: &Flow,
        req: &mut Request,
        head: &mut Response,
    ) -> Option<stream::PipelineStream> {
        use crate::text::stream::StreamEncoding;
        let engine = &self.engine;
        if flow.live.chain.inspects_responses() {
            return None;
        }
        let codec = match StreamEncoding::of(head.headers.get("content-encoding").as_deref()) {
            StreamEncoding::Buffered => return None,
            StreamEncoding::Identity => None,
            StreamEncoding::Codec(codec) => Some(codec),
        };
        let capture = match engine.capture.streamed_body_limit(&flow.id) {
            None => None,
            Some(None) => return None,
            Some(Some(limit)) => Some(limit),
        };
        // What the response hook does before the body: the request put
        // back to placeholders for every record, the headers redacted.
        engine.injector.redact_request(req).ok()?;
        engine
            .capture
            .refresh_request(&flow.id, req, &lenient_body(&req.headers, &req.body));
        let redactor = engine.injector.stream_redactor();
        let decode = redactor.as_ref().and(codec);
        if let Some(redactor) = &redactor {
            stream::redact_head(head, redactor.forms());
        }
        if decode.is_some() {
            head.headers.remove("content-encoding");
        }
        if redactor.is_some() {
            // The body may change length.
            head.headers.remove("content-length");
        }
        let recorded = Request {
            method: req.method.clone(),
            scheme: req.scheme.clone(),
            host: req.host.clone(),
            port: req.port,
            path: req.path.clone(),
            http_version: req.http_version.clone(),
            headers: req.headers.clone(),
            body: Vec::new(),
        };
        let plan = stream::Plan {
            decode,
            capture: capture.map(|limit| (limit, if decode.is_none() { codec } else { None })),
            redactor,
        };
        Some(stream::PipelineStream::new(
            Arc::clone(engine),
            flow.id.clone(),
            flow.direction,
            recorded,
            head.clone(),
            plan,
        ))
    }

    async fn websocket_inner(
        &self,
        conn: &ConnInfo,
        flow: &Flow,
        req: &Request,
        msg: &mut WsMessage,
    ) -> Result<WsVerdict, String> {
        if msg.content.is_empty() {
            return Ok(WsVerdict::Forward);
        }
        let engine = &self.engine;
        // Taken before the inspectors run: the frame's arrival.
        let frame_ts = DateTime::now_utc().isoformat();
        let body = msg.content.clone();
        let ctx = Context {
            url: req.url(),
            host: req.host.clone(),
            method: "WEBSOCKET".to_owned(),
            headers: headers_text(&req.headers),
            content_type: "application/x-websocket-frame".to_owned(),
            body_bytes: Some(bytes::Bytes::copy_from_slice(&body)),
            body_text: Some(String::from_utf8_lossy(&body).into_owned()),
            body_size: body.len(),
            body_entropy: Some(shannon_entropy(&body)),
            prior_results: Vec::new(),
            direction: inspect_direction(flow.direction),
            websocket: true,
        };
        let reverse = conn.direction() == Direction::Inbound;
        let (verdict, decision) = if msg.from_client == reverse {
            let outcome = self.ws_inbound(&flow.live, req, ctx, reverse).await?;
            // Real secrets never reach the cage.
            msg.content = engine.injector.redact_ws_content(&body).0;
            outcome
        } else {
            self.ws_outbound(&flow.live, req, ctx, msg, reverse).await?
        };
        let recorded = engine.injector.redact_ws_content(&body).0;
        engine.capture.add_ws_frame(
            &flow.id,
            msg.from_client,
            msg.is_text,
            &recorded,
            &frame_ts,
            decision,
        );
        Ok(verdict)
    }

    /// A cage → world message: injection policy, request chain, then
    /// injection only if it is forwarded.
    async fn ws_outbound(
        &self,
        live: &Arc<Live>,
        req: &Request,
        mut ctx: Context,
        msg: &mut WsMessage,
        reverse: bool,
    ) -> Result<(WsVerdict, Decision), String> {
        let engine = &self.engine;
        let body = msg.content.clone();
        let mut results = Vec::new();
        if let Some(v) = engine.injector.check_ws_injection_policy(&body, &req.host) {
            results.push(v.clone());
            ctx.prior_results.push(v);
        }
        results.extend(run_inspectors(live, ctx, Phase::Request, reverse).await?.0);
        if let Some(block) = results.iter().find(|r| r.action == Action::Block) {
            let reason = format!("websocket: {}", block.reason);
            record(
                req,
                AuditDirection::Outbound,
                Decision::Blocked,
                &reason,
                &results,
            )
            .emit(&*engine.audit, live.log_allowed);
            return Ok((WsVerdict::Drop, Decision::Blocked));
        }
        let injector = Arc::clone(&engine.injector);
        let host = req.host.clone();
        let (content, injected) =
            blocking(move || injector.inject_ws_content(&body, &host)).await?;
        msg.content = content;
        let flagged: Vec<&str> = results
            .iter()
            .filter(|r| r.action == Action::Flag)
            .map(|r| r.reason.as_str())
            .collect();
        let (decision, reason) = if flagged.is_empty() {
            (Decision::Allowed, "websocket".to_owned())
        } else {
            (
                Decision::Flagged,
                format!("websocket: {}", flagged.join("; ")),
            )
        };
        if decision == Decision::Flagged || live.log_allowed || !injected.is_empty() {
            let mut rec = record(req, AuditDirection::Outbound, decision, &reason, &results);
            rec.secrets_injected = injected;
            rec.emit(&*engine.audit, live.log_allowed);
        }
        Ok((WsVerdict::Forward, decision))
    }

    /// A world → cage message: the response chain.
    async fn ws_inbound(
        &self,
        live: &Arc<Live>,
        req: &Request,
        ctx: Context,
        reverse: bool,
    ) -> Result<(WsVerdict, Decision), String> {
        let engine = &self.engine;
        let results = run_inspectors(live, ctx, Phase::Response, reverse).await?.0;
        if let Some(block) = results.iter().find(|r| r.action == Action::Block) {
            let reason = format!("websocket: {}", block.reason);
            record(
                req,
                AuditDirection::Inbound,
                Decision::Blocked,
                &reason,
                &results,
            )
            .emit(&*engine.audit, live.log_allowed);
            return Ok((WsVerdict::Drop, Decision::Blocked));
        }
        let decision = if results.iter().any(|r| r.action == Action::Flag) {
            Decision::Flagged
        } else {
            Decision::Allowed
        };
        if live.log_allowed {
            record(
                req,
                AuditDirection::Inbound,
                Decision::Allowed,
                "websocket",
                &results,
            )
            .emit(&*engine.audit, live.log_allowed);
        }
        Ok((WsVerdict::Forward, decision))
    }
}

impl FlowHandler for Pipeline {
    type Flow = Flow;

    async fn request(&self, conn: &ConnInfo, req: &mut Request) -> RequestAction<Flow> {
        match self.request_inner(conn, req).await {
            Ok(action) => action,
            Err(e) => RequestAction::Respond(self.internal_error(req, audit_direction(conn), &e)),
        }
    }

    async fn response(
        &self,
        _conn: &ConnInfo,
        flow: &mut Flow,
        req: &mut Request,
        resp: &mut Response,
    ) {
        if let Err(e) = self.response_inner(flow, req, resp).await {
            self.engine.capture.release(&flow.id);
            *resp = self.internal_error(req, flow.direction, &e);
        }
    }

    fn response_head(
        &self,
        _conn: &ConnInfo,
        flow: &mut Flow,
        req: &mut Request,
        head: &mut Response,
    ) -> impl std::future::Future<Output = Option<Box<dyn ResponseStream>>> + Send {
        std::future::ready(
            self.stream_plan(flow, req, head)
                .map(|stream| Box::new(stream) as Box<dyn ResponseStream>),
        )
    }

    async fn websocket_message(
        &self,
        conn: &ConnInfo,
        flow: &mut Flow,
        req: &Request,
        msg: &mut WsMessage,
    ) -> WsVerdict {
        match self.websocket_inner(conn, flow, req, msg).await {
            Ok(verdict) => verdict,
            Err(e) => {
                // Fail closed: the message is dropped and recorded.
                self.engine.audit.emit(audit::internal_error(
                    DateTime::now_utc(),
                    req,
                    flow.direction,
                    &format!("internal error: {e}"),
                ));
                WsVerdict::Drop
            }
        }
    }

    fn body_budget(&self, budget: &Arc<BodyBudget>) {
        let _ = self.budget.set(Arc::clone(budget));
    }

    fn flow_end(&self, _conn: &ConnInfo, flow: Flow, _end: FlowEnd) {
        self.engine.capture.release(&flow.id);
    }

    fn upstream_error(
        &self,
        _conn: &ConnInfo,
        flow: Flow,
        req: &Request,
        err: &UpstreamError,
    ) -> Response {
        self.engine.capture.release(&flow.id);
        let reason = err.to_string();
        self.engine.audit.emit(audit::upstream_error(
            DateTime::now_utc(),
            req,
            flow.direction,
            &reason,
        ));
        let (reason, _) = self.engine.injector.redact_text(&reason);
        json_response(err.status(), block_body(false, &reason, &req.host))
    }

    fn transport_refusal(
        &self,
        conn: &ConnInfo,
        req: Option<&Request>,
        refusal: &Refusal,
    ) -> Response {
        let (status, reason, host) = match refusal {
            Refusal::ForwardPort { host, port } => (
                403,
                format!(
                    "port {port} is not an inspected port; the forward proxy only connects to \
                     inspected ports (ports.tcp.allow)"
                ),
                host.clone(),
            ),
            Refusal::RequestBodyTooLarge { limit } => (
                413,
                format!("request body exceeds the egress limit of {limit} bytes"),
                req.map(|r| r.host.clone()).unwrap_or_default(),
            ),
            Refusal::BodyBudgetExhausted { limit } => (
                503,
                UpstreamError::BodyBudgetExhausted { limit: *limit }.to_string(),
                req.map(|r| r.host.clone()).unwrap_or_default(),
            ),
        };
        if let Some(req) = req {
            let live = self.engine.live();
            record(req, audit_direction(conn), Decision::Blocked, &reason, &[])
                .emit(&*self.engine.audit, live.log_allowed);
        }
        json_response(status, block_body(true, &reason, &host))
    }

    fn tcp_bypass(&self, conn: &ConnInfo) {
        let server = conn.server_addr.as_ref().map(|a| (a.host.as_str(), a.port));
        let target = audit::tcp_bypass_target(conn.sni.as_deref(), None, server);
        self.engine
            .audit
            .emit(audit::tcp_bypass_blocked(DateTime::now_utc(), &target));
    }

    fn server_connect(
        &self,
        _conn: &ConnInfo,
        target: &ConnectTarget,
        resolved: &[std::net::IpAddr],
    ) -> ConnectDecision {
        let allow = ConnectDecision::Allow(resolved.to_vec());
        let dom = &self.engine.domain;
        if dom.grant_count() == 0 {
            return allow;
        }
        let candidates = [Some(target.host.as_str()), target.sni.as_deref()];
        let Some(name) = candidates
            .into_iter()
            .flatten()
            .find(|h| !h.is_empty() && dom.is_grant_only(h))
        else {
            return allow;
        };
        // Every answer, not just the first: a rebinding payload returns a
        // public address beside the internal one.
        let bad = resolved.iter().find(|ip| !is_global_ip(**ip));
        let Some(bad) = bad else {
            return allow;
        };
        let ip = match bad {
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
            std::net::IpAddr::V4(v4) => v4.to_string(),
        };
        let record = audit::private_peer_blocked(DateTime::now_utc(), name, &ip, "server_connect");
        let reason = record
            .get("reason")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_owned();
        self.engine.poison(&normalise(name));
        self.engine.audit.emit(record);
        ConnectDecision::Refuse(reason)
    }

    fn is_passthrough(&self, _conn: &ConnInfo, candidate: &str) -> bool {
        self.engine.live().passthrough.matches(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_names_strip_ports_but_keep_ipv6_literals() {
        assert_eq!(host_header_name("example.com:443"), "example.com");
        assert_eq!(host_header_name("example.com"), "example.com");
        assert_eq!(host_header_name("[::1]:443"), "::1");
        assert_eq!(host_header_name("[::1]"), "::1");
    }

    #[test]
    fn flow_ids_are_uuid_shaped() {
        let id = flow_id();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert_ne!(id, flow_id());
    }

    #[test]
    fn block_bodies_are_byte_exact() {
        assert_eq!(
            block_body(true, "nope", "h"),
            br#"{"blocked": true, "reason": "nope", "host": "h", "by": "agentcage"}"#
        );
    }
}
