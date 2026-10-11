//! The Policy API vhost (`agentcage.local`), the grants overlay, the
//! grant sweeper and the DNS publish of granted names.
//!
//! The Policy API is not a listener: it is a synthetic host the request
//! pipeline answers in-process, before any other step, when a cage's
//! *outbound* request targets the control host (SNI and Host both equal
//! it; without SNI, the Host alone — [`PolicyApi::is_control_host`]). No
//! upstream connection is ever opened for it. Never on reverse (inbound)
//! flows: Host and SNI are client-controlled there.
//!
//! | Route | Result |
//! | :-- | :-- |
//! | any, body over 8 KiB | 413 + audit |
//! | `GET /v1/health` | 200, no audit |
//! | `GET /v1/allowlist` | 200 + `policy_introspect` |
//! | `POST /v1/allowlist/requests` | the decision flow ([`PolicyApi::handle`]) |
//! | `POST /v1/allowlist/removals` | give back a live runtime grant |
//! | anything else | 404 |
//!
//! Paths are compared exactly, query string included.
//!
//! Trust model: the egress never grants without a positive decision from
//! the operator's LLM decider, and a decider error is always a deny.
//! Grants only widen the domain inspector's allow set; every other check
//! still applies to a granted host.
//!
//! [`PolicyApi::handle`] is the router as a function over
//! [`ControlRequest`] → [`ControlResponse`] (status, body bytes, audit
//! records); it blocks for the decider call, so the pipeline runs it on a
//! blocking worker. Files go through [`PolicyPaths`], the clock, request
//! ids, the secret lookup and the HTTP transport through [`PolicyEnv`],
//! so the whole flow runs against temp dirs and a scripted decider in
//! tests (`tests/fixtures/egress/policy_api.json`).

mod overlay;
mod prompt;
mod pyfmt;
mod settings;

use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use agentcage_core::audit::Timestamp;
use agentcage_core::config::AUTO_NEVER_GRANT;
use agentcage_core::config::{LabelPolicy, encoded_private_ip, valid_domain};
use agentcage_core::har::datetime::DateTime;

use crate::config::Config;
use crate::inspect::domain::DomainInspector;
use crate::json::{self, Json, object};
use crate::llm::{self, HttpTransport, LlmClient, ToolCall, ToolCaller as _};

pub use overlay::{DEFAULT_DNS_PUBLISH, DEFAULT_GRANTS_DIR, PolicyPaths};
pub use prompt::{SYSTEM_PROMPT, decide_tool, system_prompt};
pub use settings::{ConfigError, DEFAULT_CONTROL_HOST, MAX_CONTEXT_CHARS, decider_enabled};

use pyfmt::{
    int_or_zero, loads_bytes, normalise_domain, repr_str, str_or_empty, strip, truncate_chars,
    yaml_to_json,
};
use settings::Settings;

/// Request bodies above this many bytes are refused before parsing.
pub const MAX_BODY: usize = 8 * 1024;

/// The most live grants at once.
pub const MAX_GRANTS: usize = 32;

/// The longest grant a decider can give, in seconds; longer is clamped.
pub const MAX_TTL_SECONDS: i64 = 86_400;

/// How often the pipeline should call [`PolicyApi::sweeper_tick`].
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// The `Content-Type` of every control-host response.
pub const CONTENT_TYPE: &str = "application/json";

/// One request to the control host.
#[derive(Clone, Copy, Debug)]
pub struct ControlRequest<'a> {
    /// The method as sent (compared upper-cased).
    pub method: &'a str,
    /// The request target's path, query string included.
    pub path: &'a str,
    /// The decoded request body.
    pub body: &'a [u8],
    /// The request headers in wire order. Not consulted today: the
    /// control host is unauthenticated by design (only the caged agent
    /// can reach it).
    pub headers: &'a [(String, String)],
}

/// The control host's answer.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlResponse {
    /// The status code.
    pub status: u16,
    /// The JSON body, exactly as the replaced implementation wrote it.
    /// Served as [`CONTENT_TYPE`].
    pub body: Vec<u8>,
    /// Audit records to emit, in order (each `{kind, ts, ...}`).
    pub audit: Vec<Json>,
}

/// Everything ambient the Policy API reads: the clock, randomness, the
/// secret lookup, the environment's version stamp and the decider's
/// transport.
pub trait PolicyEnv: Send + Sync + std::fmt::Debug {
    /// `datetime.now(timezone.utc)`.
    fn now_utc(&self) -> DateTime;
    /// A monotonic clock in seconds (the rate bucket's).
    fn monotonic(&self) -> f64;
    /// A fresh request id: `req_` + 24 hex digits.
    fn request_id(&self) -> String;
    /// Resolve a secret by name ([`crate::secret_lookup::read_secret`]).
    fn read_secret(&self, name: &str) -> String;
    /// `AGENTCAGE_VERSION`, or `""`.
    fn version_env(&self) -> String;
    /// The HTTP transport the decider's client uses.
    fn transport(&self) -> Arc<dyn HttpTransport>;
}

/// The production [`PolicyEnv`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEnv;

static START: std::sync::LazyLock<std::time::Instant> =
    std::sync::LazyLock::new(std::time::Instant::now);

impl PolicyEnv for SystemEnv {
    fn now_utc(&self) -> DateTime {
        DateTime::now_utc()
    }

    fn monotonic(&self) -> f64 {
        START.elapsed().as_secs_f64()
    }

    fn request_id(&self) -> String {
        let mut bytes = [0u8; 12];
        if getrandom::fill(&mut bytes).is_err() {
            // No entropy source at all is not a reason to refuse a
            // request; the id only correlates a response with its audit
            // line. Fall back to the hasher's per-process random keys.
            use std::hash::{BuildHasher as _, Hasher as _};
            let mut h = std::collections::hash_map::RandomState::new().build_hasher();
            h.write_u128(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
            );
            let a = h.finish().to_be_bytes();
            bytes[..8].copy_from_slice(&a);
        }
        let mut out = String::from("req_");
        for b in bytes {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    fn read_secret(&self, name: &str) -> String {
        crate::secret_lookup::read_secret(name)
    }

    fn version_env(&self) -> String {
        std::env::var("AGENTCAGE_VERSION").unwrap_or_default()
    }

    fn transport(&self) -> Arc<dyn HttpTransport> {
        Arc::new(llm::UreqTransport)
    }
}

/// The config-derived half of the state, swapped whole on a reload.
#[derive(Debug)]
struct Live {
    settings: Settings,
    /// The decider's key, resolved when the settings were applied (a
    /// `secret set` re-stages it and bumps the config, so a reload re-reads
    /// it).
    api_key: String,
}

/// The control-plane token bucket: runtime state that survives reloads.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: f64,
}

/// What the overlay lock guards. Every read-modify-write of the grants
/// (reconcile, grant, revoke, sweep, persist, publish) holds it, so the
/// sweeper and concurrent requests never interleave half-updates. It is
/// never held across the decider call.
#[derive(Debug, Default)]
struct OverlayState {
    mtime: Option<SystemTime>,
    /// Requests past the `max_grants` gate whose decision is pending.
    /// Counting them closes the overshoot where N concurrent requests all
    /// saw 31 grants and all got granted.
    reserved: usize,
}

/// The Policy API: one per egress, reconfigured in place on reload.
#[derive(Debug)]
pub struct PolicyApi {
    env: Arc<dyn PolicyEnv>,
    paths: PolicyPaths,
    dom: RwLock<Arc<DomainInspector>>,
    live: RwLock<Arc<Live>>,
    bucket: Mutex<Bucket>,
    overlay: Mutex<OverlayState>,
}

/// The outcome of [`PolicyApi::revoke_live_grant`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revocation {
    /// The grant was live and is gone (overlay persisted, DNS republished).
    Revoked,
    /// Not a live grant (perhaps baseline, perhaps nothing at all).
    NotGranted,
}

/// A decider verdict, normalised.
struct Verdict {
    decision: String,
    /// Operator-facing (the audit record).
    reason: String,
    /// What the caged agent is told instead, when it must not see
    /// `reason` (a provider error body).
    agent_reason: Option<String>,
    ttl_seconds: i64,
    decided_by: Option<String>,
}

impl Verdict {
    fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: "deny".to_owned(),
            reason: reason.into(),
            agent_reason: None,
            ttl_seconds: 0,
            decided_by: None,
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn read<T: Clone>(m: &RwLock<T>) -> T {
    m.read().unwrap_or_else(PoisonError::into_inner).clone()
}

fn respond(status: u16, body: &Json, audit: Vec<Json>) -> ControlResponse {
    ControlResponse {
        status,
        body: json::to_string(body).into_bytes(),
        audit,
    }
}

fn error_body(message: impl Into<String>) -> Json {
    object([("error", Json::string(message))])
}

impl PolicyApi {
    /// Build from the proxy config, then replay the overlay into `dom`
    /// and publish the granted names (an egress restart starts with an
    /// empty DNS dir, so previously granted zones must be republished).
    ///
    /// # Errors
    ///
    /// The decider block is malformed in a way the Python raised on.
    pub fn new(
        config: &Config,
        dom: Arc<DomainInspector>,
        paths: PolicyPaths,
        env: Arc<dyn PolicyEnv>,
    ) -> Result<Self, ConfigError> {
        let settings = Settings::parse(config)?;
        let api_key = env.read_secret(&settings.api_key_name);
        let tokens = settings.rate_burst;
        let api = Self {
            bucket: Mutex::new(Bucket {
                tokens,
                last: env.monotonic(),
            }),
            env,
            paths,
            dom: RwLock::new(dom),
            live: RwLock::new(Arc::new(Live { settings, api_key })),
            overlay: Mutex::new(OverlayState::default()),
        };
        api.reconcile(&mut lock(&api.overlay));
        Ok(api)
    }

    /// Apply a hot-reloaded config to this live instance.
    ///
    /// Config-derived fields (host, context, LLM client, rate-limit
    /// parameters, the enable flag) are re-read, the API key included.
    /// Runtime state is kept: the bucket's tokens survive (clamped to a
    /// smaller burst, never refilled — a reload must not hand the cage a
    /// fresh burst of decider calls), and so does the overlay mtime. A
    /// replaced domain inspector gets the overlay replayed into it.
    ///
    /// # Errors
    ///
    /// The block is malformed; nothing of it was applied.
    pub fn reconfigure(
        &self,
        config: &Config,
        dom: Arc<DomainInspector>,
    ) -> Result<(), ConfigError> {
        let settings = Settings::parse(config)?;
        let api_key = self.env.read_secret(&settings.api_key_name);
        let burst = settings.rate_burst;
        *self.live.write().unwrap_or_else(PoisonError::into_inner) =
            Arc::new(Live { settings, api_key });
        {
            let mut bucket = lock(&self.bucket);
            bucket.tokens = bucket.tokens.min(burst);
        }
        let replaced = {
            let mut current = self.dom.write().unwrap_or_else(PoisonError::into_inner);
            if Arc::ptr_eq(&current, &dom) {
                false
            } else {
                *current = dom;
                true
            }
        };
        if replaced {
            self.reconcile(&mut lock(&self.overlay));
        }
        Ok(())
    }

    fn live(&self) -> Arc<Live> {
        read(&self.live)
    }

    /// The domain inspector the grants live in.
    #[must_use]
    pub fn domain(&self) -> Arc<DomainInspector> {
        read(&self.dom)
    }

    /// Whether `agents.decider.enable` is set (the pipeline routes to the
    /// control host only then).
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.live().settings.enable
    }

    /// The control host, lowercased, trailing dot stripped.
    #[must_use]
    pub fn host(&self) -> String {
        self.live().settings.host.clone()
    }

    /// True if a flow targets the control host. With an SNI, both it and
    /// the Host header (port stripped) must equal the control host — a
    /// mismatch falls through to the pipeline's SNI/Host check, which
    /// rejects it; without one, the Host header decides.
    #[must_use]
    pub fn is_control_host(&self, sni: Option<&str>, host_header: Option<&str>) -> bool {
        let host = self.host();
        let header = host_header.unwrap_or("");
        let header = header.rsplit_once(':').map_or(header, |(h, _)| h);
        let header = normalise_domain(header);
        let sni = normalise_domain(sni.unwrap_or(""));
        if sni.is_empty() {
            header == host
        } else {
            sni == host && header == host
        }
    }

    fn version(&self, live: &Live) -> String {
        let env = self.env.version_env();
        let env = strip(&env);
        if env.is_empty() {
            live.settings.agentcage_version.clone()
        } else {
            env.to_owned()
        }
    }

    fn event(&self, audit: &mut Vec<Json>, kind: &str, fields: Vec<(&str, Json)>) {
        let mut entry = vec![
            ("kind".to_owned(), Json::string(kind)),
            (
                "ts".to_owned(),
                Json::string(self.env.now_utc().isoformat()),
            ),
        ];
        entry.extend(fields.into_iter().map(|(k, v)| (k.to_owned(), v)));
        audit.push(Json::Object(entry));
    }

    fn now_ts(&self) -> Timestamp {
        Timestamp::parse_iso(&self.env.now_utc().isoformat())
            .unwrap_or_else(|| Timestamp::from_unix_micros(0))
    }

    // ── Router ───────────────────────────────────────────────

    /// Answer one control-host request. Every path gets a synthesized
    /// response; nothing is ever forwarded upstream. Blocks for the
    /// decider call on `POST /v1/allowlist/requests`.
    #[must_use]
    pub fn handle(&self, request: &ControlRequest<'_>) -> ControlResponse {
        let path = request.path;
        let method = request.method.to_uppercase();
        let live = self.live();
        let mut audit = Vec::new();

        // The general body-size inspector does not run on the control
        // host, so the cap is enforced here, before any parsing.
        if request.body.len() > MAX_BODY {
            self.event(
                &mut audit,
                "policy_request",
                vec![
                    ("path", Json::string(path)),
                    ("method", Json::string(&method)),
                    ("decision", Json::string("rejected")),
                    ("reason", Json::string("body too large")),
                ],
            );
            return respond(413, &error_body("request body too large"), audit);
        }

        let enabled = live.settings.enable;
        if method == "GET" && path == "/v1/health" {
            return respond(200, &self.health(&live), audit);
        }
        if !enabled {
            // Feature off at runtime: everything 404s so the agent stops
            // probing.
            return respond(404, &error_body("policy api disabled"), audit);
        }
        match (method.as_str(), path) {
            ("GET", "/v1/allowlist") => {
                let body = self.allowlist(&live);
                self.event(
                    &mut audit,
                    "policy_introspect",
                    vec![("path", Json::string(path))],
                );
                respond(200, &body, audit)
            }
            ("POST", "/v1/allowlist/requests") => self.handle_request(&live, request.body, audit),
            ("POST", "/v1/allowlist/removals") => self.handle_removal(&live, request.body, audit),
            _ => respond(404, &error_body("not found"), audit),
        }
    }

    fn health(&self, live: &Live) -> Json {
        let on = Json::Bool(live.settings.enable);
        object([
            ("status", Json::string("ok")),
            ("version", Json::string(self.version(live))),
            (
                "features",
                object([
                    ("introspection", on.clone()),
                    ("request", on.clone()),
                    // Self-removal rides the request switch: both let the
                    // agent manage its own runtime grants.
                    ("removal", on),
                ]),
            ),
            ("host", Json::string(&live.settings.host)),
        ])
    }

    fn allowlist(&self, live: &Live) -> Json {
        let dom = self.domain();
        let mut passthrough = live.settings.passthrough.clone();
        passthrough.sort();
        object([
            ("mode", dom.mode().map_or(Json::Null, Json::Str)),
            (
                "baseline",
                Json::Array(dom.baseline_list().into_iter().map(Json::Str).collect()),
            ),
            (
                "granted",
                Json::Array(
                    dom.granted_entries()
                        .iter()
                        .map(|(_, e)| yaml_to_json(&crate::config::Value::Mapping(e.clone())))
                        .collect(),
                ),
            ),
            (
                "passthrough",
                Json::Array(passthrough.into_iter().map(Json::Str).collect()),
            ),
            ("requestable", Json::Bool(live.settings.enable)),
            ("context", Json::string(&live.settings.context)),
            ("version", Json::string(self.version(live))),
        ])
    }

    /// The JSON object payload, or `None` for a 400.
    fn payload(body: &[u8]) -> Option<Json> {
        let body: &[u8] = if body.is_empty() { b"{}" } else { body };
        match loads_bytes(body)? {
            obj @ Json::Object(_) => Some(obj),
            _ => None,
        }
    }

    // ── POST /v1/allowlist/requests ─────────────────────────

    #[allow(clippy::too_many_lines)] // the gates in their pinned order
    fn handle_request(&self, live: &Live, body: &[u8], mut audit: Vec<Json>) -> ControlResponse {
        let Some(payload) = Self::payload(body) else {
            return respond(400, &error_body("invalid JSON body"), audit);
        };
        let domain = normalise_domain(&str_or_empty(payload.get("domain")));
        let reason = truncate_chars(&str_or_empty(payload.get("reason")), 1000);

        // A justification is required: the decider's whole job is to
        // judge the agent's explanation, so an empty one never reaches it.
        if strip(&reason).is_empty() {
            self.event(
                &mut audit,
                "policy_request",
                vec![
                    ("domain", Json::string(&domain)),
                    ("decision", Json::string("rejected")),
                    ("reason", Json::string("missing justification")),
                ],
            );
            return respond(
                400,
                &error_body("a non-empty 'reason' justification is required"),
                audit,
            );
        }

        let dom = self.domain();
        if !dom.is_allowlist() {
            return respond(
                400,
                &error_body("request endpoint requires allowlist mode"),
                audit,
            );
        }

        if !valid_domain(&domain, LabelPolicy::StrictDotted) {
            self.event(
                &mut audit,
                "policy_request",
                vec![
                    ("domain", Json::string(&domain)),
                    ("decision", Json::string("rejected")),
                    ("reason", Json::string("invalid domain syntax")),
                ],
            );
            return respond(
                400,
                &error_body(format!("invalid domain: {}", repr_str(&domain))),
                audit,
            );
        }

        // Already allowed and not expired: idempotent success, no decider.
        // An expired baseline entry or grant is blocking the domain at L7,
        // so it falls through for a fresh decision instead.
        if dom.matched_expired_at(&domain, self.now_ts()).is_none()
            && (dom.matches(&domain) || dom.is_granted(&domain))
        {
            let body = object([
                ("id", Json::string(self.env.request_id())),
                ("status", Json::string("already_allowed")),
                ("domain", Json::string(&domain)),
                ("reason", Json::string("already in baseline or granted")),
            ]);
            self.event(
                &mut audit,
                "policy_request",
                vec![
                    ("domain", Json::string(&domain)),
                    ("decision", Json::string("already_allowed")),
                ],
            );
            return respond(200, &body, audit);
        }

        if is_never_grant(&domain, &live.settings.host) {
            let body = object([
                ("id", Json::string(self.env.request_id())),
                ("status", Json::string("denied")),
                ("domain", Json::string(&domain)),
                (
                    "reason",
                    Json::string(format!(
                        "{domain} is on the operator's never_grant list and cannot be granted \
                         by the policy API"
                    )),
                ),
                (
                    "suggestion",
                    Json::string(
                        "request a different, non-internal domain; this one is permanently \
                         denied by policy",
                    ),
                ),
                ("retryable", Json::Bool(false)),
                ("decided_by", Json::string("decider")),
            ]);
            self.event(
                &mut audit,
                "policy_request",
                vec![
                    ("domain", Json::string(&domain)),
                    ("decision", Json::string("denied")),
                    ("reason", Json::string("never_grant")),
                    ("decided_by", Json::string("decider")),
                ],
            );
            return respond(403, &body, audit);
        }

        // Capacity, counting decisions still in flight.
        let Some(mut slot) = self.reserve_slot(&dom) else {
            let body = object([
                ("id", Json::string(self.env.request_id())),
                ("status", Json::string("denied")),
                ("domain", Json::string(&domain)),
                (
                    "reason",
                    Json::string(format!(
                        "max_grants ({MAX_GRANTS}) reached; no room for another grant"
                    )),
                ),
                (
                    "suggestion",
                    Json::string(
                        "wait for an existing grant to expire, or ask the operator to remove \
                         one with `agentcage domain rm`, then re-request",
                    ),
                ),
                ("retryable", Json::Bool(true)),
                ("decided_by", Json::string("decider")),
            ]);
            self.event(
                &mut audit,
                "policy_request",
                vec![
                    ("domain", Json::string(&domain)),
                    ("decision", Json::string("denied")),
                    ("reason", Json::string("max_grants reached")),
                    ("decided_by", Json::string("decider")),
                ],
            );
            return respond(409, &body, audit);
        };

        if !self.check_rate_limit(live) {
            let body = object([
                ("id", Json::string(self.env.request_id())),
                ("status", Json::string("denied")),
                ("domain", Json::string(&domain)),
                ("reason", Json::string("request rate limit exceeded")),
                (
                    "suggestion",
                    Json::string("wait a few seconds and re-request the same domain"),
                ),
                ("retryable", Json::Bool(true)),
                ("decided_by", Json::string("decider")),
            ]);
            self.event(
                &mut audit,
                "policy_request",
                vec![
                    ("domain", Json::string(&domain)),
                    ("decision", Json::string("rejected")),
                    ("reason", Json::string("rate limit")),
                ],
            );
            return respond(429, &body, audit);
        }

        self.decide(live, &dom, &domain, &reason, &mut slot, audit)
    }

    /// Take a `max_grants` slot, or `None` when full. The slot is held
    /// until the returned guard drops, after the decision is applied.
    fn reserve_slot(&self, dom: &DomainInspector) -> Option<SlotGuard<'_>> {
        let mut state = lock(&self.overlay);
        if dom.grant_count() + state.reserved >= MAX_GRANTS {
            return None;
        }
        state.reserved += 1;
        Some(SlotGuard {
            api: self,
            released: false,
        })
    }

    fn check_rate_limit(&self, live: &Live) -> bool {
        let rps = live.settings.rate_rps;
        if rps == 0.0 {
            return true;
        }
        let mut bucket = lock(&self.bucket);
        let now = self.env.monotonic();
        let elapsed = now - bucket.last;
        bucket.last = now;
        bucket.tokens = live.settings.rate_burst.min(bucket.tokens + elapsed * rps);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    // ── The decider ─────────────────────────────────────────

    fn decide(
        &self,
        live: &Live,
        dom: &DomainInspector,
        domain: &str,
        reason: &str,
        slot: &mut SlotGuard<'_>,
        mut audit: Vec<Json>,
    ) -> ControlResponse {
        let s = &live.settings;
        if s.provider.is_empty() || s.model.is_empty() || live.api_key.is_empty() {
            self.event(
                &mut audit,
                "policy_request",
                vec![
                    ("domain", Json::string(domain)),
                    ("decision", Json::string("denied")),
                    ("reason", Json::string("llm provider not configured")),
                    ("decided_by", Json::string("decider")),
                ],
            );
            return respond(503, &error_body("llm provider not configured"), audit);
        }

        // Fail closed, unconditionally: no path out of here grants
        // without a parsed "grant".
        let verdict = self.call_decider(live, dom, domain, reason);
        let decided_by = verdict
            .decided_by
            .clone()
            .unwrap_or_else(|| format!("decider:agent:{}", s.provider));
        let llm_reason = truncate_chars(&verdict.reason, 1000);
        let ttl_override = verdict.ttl_seconds;

        if verdict.decision != "grant" {
            let shown = match &verdict.agent_reason {
                Some(r) => r.clone(),
                None if llm_reason.is_empty() => {
                    "denied by the llm decider agent; no reason provided".to_owned()
                }
                None => llm_reason.clone(),
            };
            self.event(
                &mut audit,
                "policy_request",
                vec![
                    ("domain", Json::string(domain)),
                    ("decision", Json::string("denied")),
                    ("reason", Json::string(&llm_reason)),
                    ("decided_by", Json::string(&decided_by)),
                ],
            );
            return respond(403, &self.deny_body(domain, &shown, &decided_by), audit);
        }

        // 0 is permanent; longer than a day is clamped; negative is
        // out-of-contract output and a deny, never a permanent grant.
        let ttl = ttl_override.min(MAX_TTL_SECONDS);
        if ttl < 0 {
            self.event(
                &mut audit,
                "policy_request",
                vec![
                    ("domain", Json::string(domain)),
                    ("decision", Json::string("denied")),
                    (
                        "reason",
                        Json::string("malformed decider response: negative ttl_seconds"),
                    ),
                    ("decided_by", Json::string(&decided_by)),
                ],
            );
            return respond(
                403,
                &self.deny_body(
                    domain,
                    "denied: malformed decider response (negative ttl_seconds)",
                    &decided_by,
                ),
                audit,
            );
        }
        let expires_at = self.expires_at(ttl);
        let grant_reason = if llm_reason.is_empty() {
            reason.to_owned()
        } else {
            llm_reason.clone()
        };
        self.apply_grant(domain, &grant_reason, &decided_by, &expires_at, slot);
        let body = object([
            ("id", Json::string(self.env.request_id())),
            ("status", Json::string("granted")),
            ("domain", Json::string(domain)),
            ("reason", Json::string(&grant_reason)),
            ("expires_at", Json::string(&expires_at)),
            ("ttl_seconds", Json::Int(ttl)),
            ("decided_by", Json::string(&decided_by)),
        ]);
        self.event(
            &mut audit,
            "policy_request",
            vec![
                ("domain", Json::string(domain)),
                ("decision", Json::string("granted")),
                ("reason", Json::string(&llm_reason)),
                ("decided_by", Json::string(&decided_by)),
                ("expires_at", Json::string(&expires_at)),
            ],
        );
        respond(200, &body, audit)
    }

    fn deny_body(&self, domain: &str, reason: &str, decided_by: &str) -> Json {
        // `suggestion` repeats the reason under the name an agent keys a
        // retry on; a decider denial is always retryable with a better
        // justification.
        object([
            ("id", Json::string(self.env.request_id())),
            ("status", Json::string("denied")),
            ("domain", Json::string(domain)),
            ("reason", Json::string(reason)),
            ("suggestion", Json::string(reason)),
            ("retryable", Json::Bool(true)),
            ("decided_by", Json::string(decided_by)),
        ])
    }

    fn without_key(live: &Live, text: &str) -> String {
        if live.api_key.is_empty() {
            text.to_owned()
        } else {
            text.replace(&live.api_key, "[redacted]")
        }
    }

    fn call_decider(
        &self,
        live: &Live,
        dom: &DomainInspector,
        domain: &str,
        reason: &str,
    ) -> Verdict {
        let s = &live.settings;
        let base = if s.base_url.is_empty() {
            llm::default_base_url(&s.provider).unwrap_or("")
        } else {
            s.base_url.as_str()
        };
        if base.is_empty() {
            return Verdict::deny("no llm base url");
        }
        let Ok(timeout) = Duration::try_from_secs_f64(s.timeout_seconds) else {
            return Verdict::deny("llm error: Timeout value out of range");
        };
        let client = LlmClient::new(
            &s.provider,
            &s.model,
            &live.api_key,
            base,
            timeout,
            self.env.transport(),
        );
        let call = ToolCall {
            system: system_prompt(&s.context),
            user_content: prompt::user_message(domain, reason, dom),
            tool: decide_tool(),
            max_tokens: s.max_tokens,
        };
        let args = match client.call(&call) {
            Ok(args) => args,
            Err(e) => {
                // The client already cut the key out; the cage gets the
                // message without the provider's body.
                let mut v = Verdict::deny(e.message.clone());
                let shown = llm::agent_facing(&e.message);
                if shown != e.message {
                    v.agent_reason = Some(shown.to_owned());
                }
                return v;
            }
        };
        let decision = str_or_empty(args.get("decision")).to_lowercase();
        if decision != "grant" && decision != "deny" {
            return Verdict::deny("llm returned no usable decision");
        }
        match int_or_zero(args.get("ttl_seconds")) {
            Ok(ttl_seconds) => Verdict {
                decision,
                reason: str_or_empty(args.get("reason")),
                agent_reason: None,
                ttl_seconds,
                decided_by: None,
            },
            // The replaced implementation raised here, and its outer
            // handler turned the exception into this deny.
            Err(message) => Verdict {
                decided_by: Some("decider".to_owned()),
                ..Verdict::deny(Self::without_key(
                    live,
                    &format!("llm call failed: {message}"),
                ))
            },
        }
    }

    fn expires_at(&self, ttl: i64) -> String {
        if ttl <= 0 {
            return String::new();
        }
        self.env
            .now_utc()
            .checked_sub_seconds(-ttl)
            .map(|t| t.isoformat())
            .unwrap_or_default()
    }

    /// Reconcile first (so a host-side revoke already on disk cannot be
    /// resurrected by the persist below), then add the fresh grant, then
    /// persist and publish. The `max_grants` slot turns into the grant in
    /// the same critical section, so the gate never counts one decision
    /// twice (as a grant and as a reservation).
    fn apply_grant(
        &self,
        domain: &str,
        reason: &str,
        decided_by: &str,
        expires_at: &str,
        slot: &mut SlotGuard<'_>,
    ) {
        let mut state = lock(&self.overlay);
        self.maybe_reload_locked(&mut state);
        let granted_at = self.env.now_utc().isoformat();
        self.domain()
            .grant_at(domain, expires_at, reason, decided_by, &granted_at);
        state.reserved = state.reserved.saturating_sub(1);
        slot.released = true;
        self.persist_locked(&mut state);
    }

    // ── POST /v1/allowlist/removals ─────────────────────────

    /// Self-service narrowing: the agent gives back a live runtime grant.
    /// No decider (it only shrinks the cage's own egress) and no
    /// justification required. The operator's baseline — including
    /// grants the host already promoted into it — is never the egress's
    /// to edit, so those are refused.
    #[allow(clippy::too_many_lines)] // the gates in their pinned order
    fn handle_removal(&self, live: &Live, body: &[u8], mut audit: Vec<Json>) -> ControlResponse {
        let Some(payload) = Self::payload(body) else {
            return respond(400, &error_body("invalid JSON body"), audit);
        };
        let domain = normalise_domain(&str_or_empty(payload.get("domain")));
        let reason = truncate_chars(&str_or_empty(payload.get("reason")), 1000);
        let dom = self.domain();

        if !dom.is_allowlist() {
            return respond(
                400,
                &error_body("removal endpoint requires allowlist mode"),
                audit,
            );
        }

        // The shared bucket, before the syntax gate, so a stream of
        // invalid domains cannot emit unbounded audit lines.
        if !self.check_rate_limit(live) {
            let body = object([
                ("id", Json::string(self.env.request_id())),
                ("status", Json::string("denied")),
                ("domain", Json::string(&domain)),
                ("reason", Json::string("request rate limit exceeded")),
                (
                    "suggestion",
                    Json::string("wait a few seconds and re-send the removal"),
                ),
                ("retryable", Json::Bool(true)),
            ]);
            self.event(
                &mut audit,
                "policy_removal",
                vec![
                    ("domain", Json::string(&domain)),
                    ("decision", Json::string("rejected")),
                    ("reason", Json::string("rate limit")),
                ],
            );
            return respond(429, &body, audit);
        }

        if !valid_domain(&domain, LabelPolicy::StrictDotted) {
            self.event(
                &mut audit,
                "policy_removal",
                vec![
                    ("domain", Json::string(&domain)),
                    ("decision", Json::string("rejected")),
                    ("reason", Json::string("invalid domain syntax")),
                ],
            );
            return respond(
                400,
                &error_body(format!("invalid domain: {}", repr_str(&domain))),
                audit,
            );
        }

        if self.revoke_live_grant(&domain) == Revocation::Revoked {
            let shown = if reason.is_empty() {
                "removed at the agent's request".to_owned()
            } else {
                reason.clone()
            };
            let mut body = object([
                ("id", Json::string(self.env.request_id())),
                ("status", Json::string("removed")),
                ("domain", Json::string(&domain)),
                ("reason", Json::string(shown)),
            ]);
            // A grant can shadow a baseline suffix; removing it then does
            // not make the domain unreachable, so say so — but only for an
            // active baseline entry, never on the strength of a sibling
            // grant.
            if dom.baseline_active_covers_at(&domain, self.now_ts()) {
                body.set("still_allowed_by_baseline", Json::Bool(true));
            }
            self.event(
                &mut audit,
                "policy_removal",
                vec![
                    ("domain", Json::string(&domain)),
                    ("decision", Json::string("removed")),
                    ("reason", Json::string(&reason)),
                ],
            );
            return respond(200, &body, audit);
        }

        if dom.matches_baseline(&domain) {
            let body = object([
                ("id", Json::string(self.env.request_id())),
                ("status", Json::string("denied")),
                ("domain", Json::string(&domain)),
                (
                    "reason",
                    Json::string(format!(
                        "{domain} matches the operator's static baseline (or a grant already \
                         promoted into it); the policy API can only remove live runtime grants"
                    )),
                ),
                (
                    "suggestion",
                    Json::string(
                        "ask the operator to run `agentcage domain rm` if this domain should \
                         really go away",
                    ),
                ),
                ("retryable", Json::Bool(false)),
            ]);
            self.event(
                &mut audit,
                "policy_removal",
                vec![
                    ("domain", Json::string(&domain)),
                    ("decision", Json::string("denied")),
                    ("reason", Json::string("baseline entry (operator-owned)")),
                ],
            );
            return respond(403, &body, audit);
        }

        let body = object([
            ("id", Json::string(self.env.request_id())),
            ("status", Json::string("not_found")),
            ("domain", Json::string(&domain)),
            (
                "reason",
                Json::string(format!("{domain} is not a live runtime grant")),
            ),
            (
                "suggestion",
                Json::string("GET /v1/allowlist and use the exact domain from the granted list"),
            ),
        ]);
        self.event(
            &mut audit,
            "policy_removal",
            vec![
                ("domain", Json::string(&domain)),
                ("decision", Json::string("not_found")),
            ],
        );
        respond(404, &body, audit)
    }

    // ── Overlay ──────────────────────────────────────────────

    /// Revoke `domain` if it is a live runtime grant: pick up host-side
    /// changes first, then revoke, persist the overlay and republish DNS,
    /// all under the overlay lock. The removal endpoint and the traffic
    /// watcher's revocations both come through here.
    pub fn revoke_live_grant(&self, domain: &str) -> Revocation {
        let mut state = lock(&self.overlay);
        self.maybe_reload_locked(&mut state);
        let dom = self.domain();
        if !dom.is_granted(domain) {
            return Revocation::NotGranted;
        }
        dom.revoke(domain);
        self.persist_locked(&mut state);
        Revocation::Revoked
    }

    /// Reconcile from the overlay if its mtime changed; true if it did.
    pub fn maybe_reload_overlay(&self) -> bool {
        self.maybe_reload_locked(&mut lock(&self.overlay))
    }

    fn maybe_reload_locked(&self, state: &mut OverlayState) -> bool {
        if overlay::mtime(&self.paths.grants_file) == state.mtime {
            return false;
        }
        self.reconcile(state);
        true
    }

    /// Sync the inspector's grants from the overlay file, then republish
    /// DNS (a host revoke narrows, a promote widens, a restart replays).
    /// Expired entries are left to the sweeper.
    fn reconcile(&self, state: &mut OverlayState) {
        state.mtime = overlay::mtime(&self.paths.grants_file);
        let entries = overlay::load(&self.paths.grants_file);
        self.domain().reconcile(&entries);
        self.publish_dns();
    }

    /// Write the in-memory grants to the overlay, then publish DNS
    /// whether or not the write succeeded: the overlay is durability, the
    /// publish is enforcement, and a grant that fails to persist is merely
    /// lost on restart (the safe direction).
    fn persist_locked(&self, state: &mut OverlayState) {
        let entries: Vec<_> = self
            .domain()
            .granted_entries()
            .into_iter()
            .map(|(_, e)| e)
            .collect();
        match overlay::write(&self.paths, &entries) {
            Ok(mtime) => state.mtime = mtime,
            Err(e) => eprintln!("agentcage: cannot persist grants overlay: {e}"),
        }
        self.publish_dns();
    }

    fn publish_dns(&self) {
        let now = self.env.now_utc().isoformat();
        let names = overlay::publishable(&self.domain().granted_entries(), &now);
        if let Err(e) = overlay::publish_dns(&self.paths, &names) {
            // Non-fatal: the grant is enforced at L7 already; only DNS
            // lags, and the operator sees why here.
            eprintln!("agentcage: cannot publish granted domains for DNS: {e}");
        }
    }

    /// One sweeper pass: pick up host-side changes first (an expiry
    /// persist must not rewrite an entry the host just revoked), then drop
    /// expired grants and, if any went, persist. Returns the
    /// `policy_grant_expired` audit records. Call every
    /// [`SWEEP_INTERVAL`].
    pub fn sweeper_tick(&self) -> Vec<Json> {
        let mut state = lock(&self.overlay);
        self.maybe_reload_locked(&mut state);
        let now = self.env.now_utc().isoformat();
        let expired = self.domain().drop_expired_at(&now);
        let mut audit = Vec::new();
        if !expired.is_empty() {
            self.persist_locked(&mut state);
            for d in expired {
                self.event(
                    &mut audit,
                    "policy_grant_expired",
                    vec![
                        ("domain", Json::Str(d)),
                        ("reason", Json::string("ttl expired")),
                    ],
                );
            }
        }
        audit
    }
}

/// Holds one `max_grants` slot until it becomes a grant or is dropped.
struct SlotGuard<'a> {
    api: &'a PolicyApi,
    released: bool,
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let mut state = lock(&self.api.overlay);
        state.reserved = state.reserved.saturating_sub(1);
    }
}

/// The never-grant floor: a hostname encoding a non-global IP, or any
/// suffix in the built-in set plus the control host.
fn is_never_grant(domain: &str, control_host: &str) -> bool {
    if encoded_private_ip(domain).is_some() {
        return true;
    }
    let d = normalise_domain(domain);
    std::iter::once(d.as_str())
        .chain(d.match_indices('.').map(|(i, _)| &d[i + 1..]))
        .any(|suffix| suffix == control_host || AUTO_NEVER_GRANT.contains(&suffix))
}

#[cfg(test)]
mod tests;
