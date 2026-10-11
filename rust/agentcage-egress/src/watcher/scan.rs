//! One watcher and its scan: collect → digest → review → apply.
//!
//! Fail-closed on every LLM outcome. An error, a timeout, a missing tool
//! call or a malformed verdict is a *recorded* scan failure — never a
//! silent all-clear and never a revocation spree. No evidence is lost to
//! a failed scan: the drained ring batch is pushed back to the front of
//! the ring and the capture offset stays uncommitted, so the next tick
//! re-analyses the same window plus anything newer.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use agentcage_core::config::{LabelPolicy, valid_domain};
use agentcage_core::har::datetime::DateTime;
use rand::{Rng as _, SeedableRng as _, TryRngCore as _};

use crate::audit::AuditSink;
use crate::inspect::domain::DomainInspector;
use crate::json::{self, Json};
use crate::llm::{ToolCall, ToolCaller};

use super::ScanRng;
use super::config::WatcherConfig;
use super::digest::{DigestInput, build_digest, est_tokens};
use super::prompt::{self, COMPLIANCE_RETRY};
use super::pyval;
use super::tail::{CaptureTail, TailLimits, TailRead};

/// Per-tick ring drain bound: the digest aggregates everything drained,
/// so a large backlog is cheap for the prompt; this only caps the work.
pub const MAX_DRAIN: usize = 2000;

/// Cadence jitter as a fraction of the interval: each delay is uniform in
/// `[1 - j, 1 + j] × interval`. The mean (and so the mean cost) is
/// unchanged; the predictable safe window right after a scan is gone.
pub const CADENCE_JITTER: f64 = 0.5;

/// Chance that a scan runs at a multiple of the digest budget, so no
/// window is ever safely known to be in cheap mode. Mean cost impact is
/// `(mult - 1) × prob`, about 15 %.
pub const FULL_SCAN_PROB: f64 = 0.05;

/// The full-fidelity budget multiple.
pub const FULL_SCAN_BUDGET_MULT: usize = 4;

/// `findings.jsonl` is rotated to `findings.jsonl.1` past this size, like
/// the capture file, so a chatty model or a long outage cannot fill the
/// grants volume. One generation is kept.
pub const FINDINGS_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// The audit ring, as the watcher uses it.
///
/// The egress's audit writer owns the ring and copies every record into
/// it; the watcher only drains it and, after a failed scan, returns what
/// it drained.
pub trait RingSource: Send + Sync + std::fmt::Debug {
    /// Take up to `max` records from the front in ingestion order,
    /// consuming and discarding the watcher's own (`watcher_*`) records
    /// without counting them. Also reports whether the ring was at its
    /// bound before the drain (entries were likely evicted unseen).
    fn drain(&self, max: usize) -> (Vec<Json>, bool);

    /// Return a failed scan's batch to the front in its original order,
    /// trimmed to the free room by keeping the batch's newest tail, so
    /// live entries that arrived meanwhile are never evicted by it.
    fn push_back(&self, batch: Vec<Json>);
}

impl RingSource for crate::audit::WatcherRing {
    fn drain(&self, max: usize) -> (Vec<Json>, bool) {
        let drained = crate::audit::WatcherRing::drain(self, max);
        (drained.entries, drained.saturated)
    }

    fn push_back(&self, batch: Vec<Json>) {
        crate::audit::WatcherRing::push_back(self, batch);
    }
}

/// The Policy API's revocation path, which the watcher's revocations go
/// through exactly as the removal endpoint's do.
pub trait GrantStore: Send + Sync + std::fmt::Debug {
    /// Revoke `domain` if it is a live runtime grant: pick up host-side
    /// overlay changes first, then revoke, persist the overlay and
    /// republish DNS — per revocation, so a host-side revoke landing
    /// mid-batch cannot be resurrected by one write at the end. False when
    /// it is not a live grant (baseline, hallucinated, already gone).
    fn revoke_live_grant(&self, domain: &str) -> bool;
}

/// The configured LLM agent a [`ToolCaller`] is built for.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentSpec {
    /// `anthropic`, `openai` or `openrouter`.
    pub provider: String,
    /// The model.
    pub model: String,
    /// The resolved key value.
    pub api_key: String,
    /// The base URL (the override, or the provider's default).
    pub base_url: String,
    /// Per-call timeout.
    pub timeout_seconds: f64,
}

/// Builds the wire client for an agent. Implemented over the egress's LLM
/// client; tests script it.
pub trait CallerFactory: Send + Sync + std::fmt::Debug {
    /// A caller for `agent`.
    fn caller(&self, agent: &AgentSpec) -> Arc<dyn ToolCaller>;
}

/// A provider's default base URL, `""` for an unknown provider.
///
/// The same map the decider uses; kept here until the LLM client exposes
/// it.
#[must_use]
pub fn default_base_url(provider: &str) -> &'static str {
    match provider {
        "anthropic" => "https://api.anthropic.com",
        "openai" => "https://api.openai.com",
        // OpenRouter's endpoint is /api/v1/chat/completions, so the base
        // carries the /api/v1 prefix.
        "openrouter" => "https://openrouter.ai/api/v1",
        _ => "",
    }
}

/// Where the watcher reads and writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatcherPaths {
    /// `<grants dir>/watcher`: `findings.jsonl` and `state.json`, on the
    /// one host-visible writable volume the egress already owns, so the
    /// host's `watcher findings` / `watcher status` read them directly.
    pub dir: PathBuf,
    /// `capture.jsonl`, or `None` when capture is off.
    pub capture: Option<PathBuf>,
}

impl WatcherPaths {
    /// `$AGENTCAGE_GRANTS_DIR/watcher` (default `/var/lib/agentcage`) and
    /// `$AGENTCAGE_CAPTURE`.
    #[must_use]
    pub fn from_env() -> Self {
        let grants = std::env::var_os("AGENTCAGE_GRANTS_DIR")
            .filter(|v| !v.is_empty())
            .map_or_else(|| PathBuf::from("/var/lib/agentcage"), PathBuf::from);
        Self {
            dir: grants.join("watcher"),
            capture: std::env::var_os("AGENTCAGE_CAPTURE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
        }
    }

    fn findings(&self) -> PathBuf {
        self.dir.join("findings.jsonl")
    }

    fn state(&self) -> PathBuf {
        self.dir.join("state.json")
    }
}

/// The references a hot reload re-points without rebuilding the watcher.
#[derive(Clone, Debug, Default)]
pub struct RuntimeRefs {
    /// The domain inspector (grants and baseline), if loaded.
    pub domains: Option<Arc<DomainInspector>>,
    /// The Policy API's grant store; `None` without `agents.decider`,
    /// in which case no runtime grants exist to revoke.
    pub grants: Option<Arc<dyn GrantStore>>,
}

/// The re-pointable references plus the resolved key, shared between a
/// watcher and its manager so a reload can refresh them without waiting
/// for a scan in progress.
#[derive(Clone, Debug)]
pub struct RefsHandle(Arc<RefsInner>);

#[derive(Debug)]
struct RefsInner {
    api_key_source: String,
    state: Mutex<(RuntimeRefs, String)>,
}

impl RefsHandle {
    fn new(api_key_source: &str, refs: RuntimeRefs) -> Self {
        let secret = read_key(api_key_source);
        Self(Arc::new(RefsInner {
            api_key_source: api_key_source.to_owned(),
            state: Mutex::new((refs, secret)),
        }))
    }

    /// Re-point the domain inspector and grant store and re-read the key.
    ///
    /// Called on every reload, including when the watcher block is
    /// unchanged and the watcher is kept: toggling `agents.decider` builds
    /// or drops the grant store, and `secret set` re-stages the key file
    /// without changing the config value that names it.
    pub fn refresh(&self, refs: RuntimeRefs) {
        let secret = read_key(&self.0.api_key_source);
        *self.0.state.lock().unwrap_or_else(PoisonError::into_inner) = (refs, secret);
    }

    fn get(&self) -> (RuntimeRefs, String) {
        self.0
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// What a watcher is wired to.
#[derive(Clone, Debug)]
pub struct WatcherDeps {
    /// The audit ring.
    pub ring: Arc<dyn RingSource>,
    /// Where findings and revocations are audited.
    pub audit: Arc<dyn AuditSink>,
    /// The LLM client factory.
    pub llm: Arc<dyn CallerFactory>,
    /// The file locations.
    pub paths: WatcherPaths,
}

/// An operator-facing warning sink.
pub type WarnFn = Arc<dyn Fn(&str) + Send + Sync>;

/// A clock, injectable for tests.
pub type ClockFn = Arc<dyn Fn() -> DateTime + Send + Sync>;

fn default_warn() -> WarnFn {
    Arc::new(|msg: &str| eprintln!("{msg}"))
}

/// A `u64` from the OS, for scan seeds and jitter — nothing the cage can
/// influence. Falls back to the clock if the OS source fails, which only
/// costs unpredictability, never correctness.
fn os_u64() -> u64 {
    rand::rngs::OsRng.try_next_u64().unwrap_or_else(|_| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        #[allow(clippy::cast_possible_truncation)]
        let folded = (nanos ^ (nanos >> 64)) as u64;
        folded
    })
}

/// A uniform `[0, 1)` from the OS.
fn os_unit() -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let unit = (os_u64() >> 11) as f64 / (1u64 << 53) as f64;
    unit
}

/// What one tick did, for the caller's log and for tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TickOutcome {
    /// Nothing drained or read: no model call.
    Quiet,
    /// The review succeeded and was applied.
    Reviewed,
    /// The review failed; the batch is queued for retry.
    Failed,
    /// The watcher was stopped while the model was answering; the batch
    /// was returned and nothing was applied.
    Abandoned,
}

/// The traffic watcher.
///
/// Built by the reload path only while `agents.watcher.enable` is set.
/// The scan state (capture cursor, counters) lives here, so a reload that
/// leaves the watcher block unchanged keeps this instance; the mutable
/// references live in a separate lock so re-pointing them never waits for
/// a scan in progress.
pub struct Watcher {
    cfg: WatcherConfig,
    deps: WatcherDeps,
    refs: RefsHandle,
    tail: CaptureTail,
    consec_failures: u64,
    scans: u64,
    findings_total: u64,
    last_digest_tokens: usize,
    scan_seed: Option<u64>,
    full_fidelity: bool,
    warn: WarnFn,
    clock: ClockFn,
}

impl std::fmt::Debug for Watcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watcher")
            .field("cfg", &self.cfg)
            .field("deps", &self.deps)
            .field("tail", &self.tail)
            .field("scans", &self.scans)
            .field("consec_failures", &self.consec_failures)
            .finish_non_exhaustive()
    }
}

impl Watcher {
    /// A watcher for `cfg`, its key resolved through the egress's secret
    /// lookup.
    #[must_use]
    pub fn new(cfg: WatcherConfig, deps: WatcherDeps, refs: RuntimeRefs) -> Self {
        let tail = CaptureTail::new(deps.paths.capture.clone(), TailLimits::new(cfg.line_cap));
        Self {
            refs: RefsHandle::new(&cfg.api_key, refs),
            cfg,
            deps,
            tail,
            consec_failures: 0,
            scans: 0,
            findings_total: 0,
            last_digest_tokens: 0,
            scan_seed: None,
            full_fidelity: false,
            warn: default_warn(),
            clock: Arc::new(DateTime::now_utc),
        }
    }

    /// Replace the warning sink (default: stderr).
    #[must_use]
    pub fn with_warn(mut self, warn: WarnFn) -> Self {
        self.warn = warn;
        self
    }

    /// Replace the clock (default: the system clock).
    #[must_use]
    pub fn with_clock(mut self, clock: ClockFn) -> Self {
        self.clock = clock;
        self
    }

    /// Replace the capture tail's limits (tests shrink them).
    pub fn set_tail_limits(&mut self, limits: TailLimits) {
        self.tail.set_limits(limits);
    }

    /// The config this watcher was built from.
    #[must_use]
    pub fn config(&self) -> &WatcherConfig {
        &self.cfg
    }

    /// Scans run so far.
    #[must_use]
    pub fn scans(&self) -> u64 {
        self.scans
    }

    /// Whether the latest scan was a full-fidelity one.
    #[must_use]
    pub fn full_fidelity(&self) -> bool {
        self.full_fidelity
    }

    fn warn(&self, msg: &str) {
        (self.warn)(msg);
    }

    fn refs(&self) -> (RuntimeRefs, String) {
        self.refs.get()
    }

    /// The shared handle a reload refreshes through.
    #[must_use]
    pub fn refs_handle(&self) -> RefsHandle {
        self.refs.clone()
    }

    /// [`RefsHandle::refresh`].
    pub fn refresh_runtime_refs(&self, refs: RuntimeRefs) {
        self.refs.refresh(refs);
    }

    /// The resolved key (empty when unset or tombstoned).
    #[must_use]
    pub fn secret(&self) -> String {
        self.refs().1
    }

    /// The next jittered delay: `max(60, interval × U(1 - j, 1 + j))`.
    #[must_use]
    pub fn next_delay(&self) -> std::time::Duration {
        let u = (1.0 - CADENCE_JITTER) + 2.0 * CADENCE_JITTER * os_unit();
        let secs = self.cfg.interval_seconds * u;
        let secs = if secs > 60.0 { secs } else { 60.0 };
        // An infinite interval is a deformed config; sleep "forever"
        // rather than panic on the conversion.
        std::time::Duration::try_from_secs_f64(secs)
            .unwrap_or(std::time::Duration::from_secs(10 * 365 * 86_400))
    }

    /// One scan with a fresh OS seed at the current time.
    pub fn tick(&mut self, stopped: &dyn Fn() -> bool) -> TickOutcome {
        let now = (self.clock)();
        self.tick_with(now, os_u64(), stopped)
    }

    /// One scan at `now` with `seed` driving every random choice.
    ///
    /// `stopped` is checked once the model has answered: a watcher that
    /// was stopped (rebuilt or disabled by a reload) meanwhile returns
    /// its batch to the ring and applies nothing.
    pub fn tick_with(
        &mut self,
        now: DateTime,
        seed: u64,
        stopped: &dyn Fn() -> bool,
    ) -> TickOutcome {
        self.scan_seed = Some(seed);
        let mut rng = ScanRng::seed_from_u64(seed);
        self.full_fidelity = rng.random::<f64>() < FULL_SCAN_PROB;
        let mut budget = self.cfg.max_digest_tokens;
        if self.full_fidelity && budget > 0 {
            budget = budget.saturating_mul(FULL_SCAN_BUDGET_MULT);
        }
        let (entries, saturated) = self.deps.ring.drain(MAX_DRAIN);
        let warn = Arc::clone(&self.warn);
        let read = self.tail.read(
            now,
            self.cfg.window_seconds,
            self.cfg.max_flows,
            Some(&mut rng),
            &mut |m| warn(m),
        );

        // Quiet window: no model call, so a quiet cage costs nothing. The
        // staged offset still commits; nothing was consumed a retry needs.
        if entries.is_empty() && read.samples.is_empty() {
            self.tail.commit(&read);
            self.scans += 1;
            self.write_state(now, 0, 0, 0, false);
            return TickOutcome::Quiet;
        }

        let (refs, secret) = self.refs();
        let policy_events: Vec<Json> = entries
            .iter()
            .filter(|e| pyval::str_get(e, "kind", "").starts_with("policy_"))
            .cloned()
            .collect();
        let granted = match (&refs.domains, &refs.grants) {
            (Some(dom), Some(_)) => dom.granted_entries().into_iter().map(|(d, _)| d).collect(),
            _ => Vec::new(),
        };
        let baseline = refs
            .domains
            .as_ref()
            .map(|d| d.baseline_list())
            .unwrap_or_default();
        let digest = build_digest(
            &DigestInput {
                audit_entries: &entries,
                capture_samples: &read.samples,
                policy_events: &policy_events,
                granted: &granted,
                baseline: &baseline,
                max_flows: i64::try_from(self.cfg.max_flows).unwrap_or(i64::MAX),
                dedup: self.cfg.dedup_samples,
                max_digest_tokens: i64::try_from(budget).unwrap_or(i64::MAX),
                ring_saturated: saturated,
            },
            Some(&mut rng),
        );
        self.last_digest_tokens = est_tokens(&digest);
        self.record_indicator_findings(&digest);

        let verdict = self.review(&digest, &secret);
        if stopped() {
            self.deps.ring.push_back(entries);
            return TickOutcome::Abandoned;
        }
        let Some(verdict) = verdict else {
            self.fail(now, entries);
            return TickOutcome::Failed;
        };
        self.consec_failures = 0;
        self.tail.commit(&read);
        self.record_skip(&read);
        self.apply(now, &verdict, &refs, entries.len());
        TickOutcome::Reviewed
    }

    /// Evasion fingerprints strong enough to stand alone, recorded without
    /// waiting for the model.
    fn record_indicator_findings(&mut self, digest: &Json) {
        let ind = pyval::obj(digest.get("evasion_indicators"));
        let binary = match ind.get("binary_request_bodies_to_granted_hosts") {
            Some(Json::Int(n)) => *n,
            _ => 0,
        };
        if binary > 0 {
            self.record_finding(&finding(
                "medium",
                &format!("{binary} binary request body(ies) sent to a runtime-granted host"),
                "base64/binary request bodies are never excerpted to the model (secret hygiene), \
                 so their content is unreviewable; sending them to a domain the cage was granted \
                 at runtime is a common way to move data past an excerpt-based review",
                "inspect the flows with `agentcage cage har --view inbound` and consider revoking \
                 the grant if the transfer is not expected",
                None,
            ));
        }
        if ind.get("audit_ring_saturated").is_some_and(Json::is_truthy) {
            self.record_finding(&finding(
                "low",
                "audit ring was saturated before this scan",
                "the in-memory audit ring was at capacity when the scan drained it, so earlier \
                 entries in the window were likely evicted unreviewed — a busy cage, or chaff \
                 pushed through the ring to age evidence out",
                "shorten agents.watcher.interval_seconds, or treat the volume itself as \
                 suspicious if the cage has no reason to be this busy",
                None,
            ));
        }
    }

    /// A failed review: queue the batch for retry, leave the capture
    /// offset uncommitted, and record a finding on the first failure and
    /// every tenth consecutive one, so a dead provider cannot flood the
    /// findings file.
    fn fail(&mut self, now: DateTime, entries: Vec<Json>) {
        self.consec_failures += 1;
        let flows = entries.len();
        self.deps.ring.push_back(entries);
        if self.consec_failures == 1 || self.consec_failures % 10 == 0 {
            let detail = format!(
                "the watcher agent's LLM call failed (error, timeout, or unusable response); this \
                 window was NOT analyzed and is queued for retry ({} consecutive failures). \
                 Nothing was revoked.",
                self.consec_failures
            );
            self.record_finding(&finding(
                "medium",
                "watcher scan failed",
                &detail,
                "check the egress logs and the agents.watcher config; the next tick retries \
                 automatically",
                None,
            ));
        }
        self.scans += 1;
        self.write_state(now, flows, 0, 0, true);
    }

    /// A catch-up skip is evidence the watcher chose not to read:
    /// recorded, never silent.
    fn record_skip(&mut self, read: &TailRead) {
        if read.skipped > 0 {
            self.record_finding(&finding(
                "medium",
                &format!(
                    "capture backlog too large: skipped {} bytes of traffic",
                    read.skipped
                ),
                "the capture file was growing faster than the watcher could read it, so the \
                 tail jumped to the live end; the skipped span was NOT analysed",
                "reduce capture volume (capture.min_action, capture.domains, a smaller \
                 capture.max_body_size) or shorten agents.watcher.interval_seconds",
                None,
            ));
        }
    }

    fn apply(&mut self, now: DateTime, verdict: &Verdict, refs: &RuntimeRefs, flows: usize) {
        for f in &verdict.findings {
            self.record_finding(&prompt::normalise_finding(f));
        }
        for r in &verdict.baseline_recommendations {
            let Some(domain) = pyval::truthy(r.get("domain")) else {
                continue;
            };
            let domain = pyval::py_str(domain);
            self.record_finding(&finding(
                "medium",
                &format!("baseline removal recommended: {domain}"),
                &pyval::prefix(&pyval::str_get(r, "reason", ""), 1000),
                "operator decision required — apply with `agentcage domain rm` (the egress \
                 never edits the baseline)",
                Some(&domain),
            ));
        }
        let revoked = self.apply_removals(&verdict.allowlist_removals, refs);
        self.scans += 1;
        self.write_state(now, flows, verdict.findings.len(), revoked.len(), false);
    }

    // ── Review ─────────────────────────────────────────────

    /// The blocking model call. `None` on any failure: unconfigured agent,
    /// provider or network error, no usable tool call, or a verdict whose
    /// shape violates the contract. `None` never triggers a side effect.
    fn review(&self, digest: &Json, secret: &str) -> Option<Verdict> {
        let cfg = &self.cfg;
        if cfg.provider.is_empty() || cfg.model.is_empty() || secret.is_empty() {
            self.warn(
                "agentcage: watcher agent not configured (provider/model/api_key) — scans are skipped",
            );
            return None;
        }
        let base = if cfg.base_url.is_empty() {
            default_base_url(&cfg.provider).to_owned()
        } else {
            cfg.base_url.clone()
        };
        if base.is_empty() {
            self.warn(&format!(
                "agentcage: unknown watcher agent provider {} — scans are skipped",
                agentcage_core::python::repr_str(&cfg.provider)
            ));
            return None;
        }
        let caller = self.deps.llm.caller(&AgentSpec {
            provider: cfg.provider.clone(),
            model: cfg.model.clone(),
            api_key: secret.to_owned(),
            base_url: base,
            timeout_seconds: cfg.timeout_seconds,
        });
        // Up to two attempts, the second only for schema non-compliance (a
        // model that called the tool with empty arguments and put its
        // analysis in prose). Network and provider errors are not retried:
        // the next tick already retries the window, and doubling calls on
        // a dead provider only doubles the bill.
        let digest_text = json::to_string(digest);
        let mut call = ToolCall {
            system: prompt::system_prompt(&cfg.context),
            user_content: digest_text.clone(),
            tool: prompt::review_tool(),
            max_tokens: u32::try_from(cfg.max_tokens.max(0)).unwrap_or(u32::MAX),
        };
        let mut args = Json::Object(Vec::new());
        for attempt in 1..=2 {
            match caller.call(&call) {
                Ok(a) => args = a,
                Err(e) => {
                    self.warn(&format!("agentcage: watcher llm call failed: {e}"));
                    return None;
                }
            }
            if args.is_truthy() && matches!(args.get("findings"), Some(Json::Array(_))) {
                break;
            }
            if attempt == 1 {
                self.warn(
                    "agentcage: watcher llm reply did not satisfy the review tool contract — \
                     retrying once with the contract restated",
                );
                call.user_content = format!("{digest_text}{COMPLIANCE_RETRY}");
            }
        }
        if !args.is_truthy() || !matches!(args, Json::Object(_)) {
            self.warn("agentcage: watcher llm returned no usable review tool call");
            return None;
        }
        Verdict::from_args(&args, &mut |m| self.warn(m))
    }

    // ── Findings + revocations ─────────────────────────────

    /// Persist a finding and re-emit it into the audit stream.
    ///
    /// The audit record carries an inspector-shaped entry (name
    /// `watcher`) so `cage audit --inspector watcher` and severity
    /// filtering work on it, and `decision: flagged` so it shows under
    /// `--decision flagged`. Audit first (it must never be lost to a
    /// volume hiccup), then the durable findings file.
    fn record_finding(&mut self, f: &Json) {
        let field = |k: &str, d: &str| f.get(k).cloned().unwrap_or_else(|| Json::string(d));
        let entry = json::object([
            ("kind", Json::string("watcher_finding")),
            ("ts", Json::Str((self.clock)().isoformat())),
            ("decision", Json::string("flagged")),
            ("method", Json::string("")),
            ("direction", Json::string("")),
            ("host", Json::Str(pyval::str_or(f.get("domain"), ""))),
            ("url", Json::string("")),
            ("path", Json::string("")),
            ("port", Json::Int(0)),
            ("reason", Json::string("")),
            ("severity", field("severity", "")),
            ("title", field("title", "")),
            ("detail", field("detail", "")),
            ("recommendation", field("recommendation", "")),
            (
                "decided_by",
                Json::Str(format!("watcher:agent:{}", self.cfg.provider)),
            ),
            (
                "inspectors",
                Json::Array(vec![json::object([
                    ("name", Json::string("watcher")),
                    ("severity", field("severity", "info")),
                    (
                        "reason",
                        Json::Str(pyval::prefix(&pyval::str_get(f, "title", ""), 200)),
                    ),
                ])]),
            ),
        ]);
        self.deps.audit.emit(entry.clone());
        let line = json::to_compact_string(&entry) + "\n";
        match append_rotating(
            &self.deps.paths.findings(),
            line.as_bytes(),
            FINDINGS_MAX_BYTES,
        ) {
            Ok(()) => self.findings_total += 1,
            Err(e) => self.warn(&format!("agentcage: cannot write watcher finding: {e}")),
        }
    }

    /// Record each removal that names a domain as a finding instead of
    /// acting on it.
    fn degrade_to_findings(
        &mut self,
        removals: &[Json],
        severity: &str,
        title: &dyn Fn(&str) -> String,
        recommendation: &str,
    ) {
        for r in removals {
            let Some(domain) = pyval::truthy(r.get("domain")) else {
                continue;
            };
            let domain = pyval::py_str(domain);
            self.record_finding(&finding(
                severity,
                &title(&domain),
                &pyval::prefix(&pyval::str_get(r, "reason", ""), 1000),
                recommendation,
                Some(&domain),
            ));
        }
    }

    /// Revoke the runtime grants the review damned; returns the domains
    /// revoked.
    ///
    /// Only ever narrows, through the removal endpoint's chain: syntax →
    /// never-revoke floor → must be a live runtime grant (a hallucinated
    /// or baseline domain is structurally unreachable) → revoke + persist.
    fn apply_removals(&mut self, removals: &[Json], refs: &RuntimeRefs) -> Vec<String> {
        if removals.is_empty() {
            return Vec::new();
        }
        if !self.cfg.auto_revoke {
            // "Report, don't act", not "discard the analysis".
            self.degrade_to_findings(
                removals,
                "medium",
                &|d| format!("revocation recommended for {d} (auto_revoke is off)"),
                "revoke the runtime grant with `agentcage cage grants revoke`, or set \
                 agents.watcher.auto_revoke: true to have the watcher apply this itself",
            );
            return Vec::new();
        }
        if refs
            .domains
            .as_ref()
            .is_some_and(|d| d.mode().as_deref() == Some("blocklist"))
        {
            // A reload can flip the mode after config-time validation. In
            // blocklist mode the baseline is the block list, so every
            // narrowing judgement inverts: refuse and say so.
            self.record_finding(&finding(
                "medium",
                "watcher revocations skipped: cage is not in allowlist mode",
                "the domain policy is in blocklist mode, where the static baseline is the block \
                 list, so the analysis's narrowing judgements do not apply",
                "run the cage in allowlist mode to use the watcher, or disable \
                 agents.watcher.enable",
                None,
            ));
            return Vec::new();
        }
        let (Some(dom), Some(store)) = (&refs.domains, &refs.grants) else {
            // No decider ⇒ no runtime grants exist to revoke.
            self.degrade_to_findings(
                removals,
                "low",
                &|d| format!("cannot revoke {d}: runtime grants are disabled"),
                "enable agents.decider for watcher-managed grants, or remove the domain with \
                 `agentcage domain rm`",
            );
            return Vec::new();
        };
        let mut revoked = Vec::new();
        for r in removals {
            let domain = pyval::str_or(r.get("domain"), "")
                .to_lowercase()
                .trim_end_matches('.')
                .to_owned();
            let reason = pyval::prefix(&pyval::str_or(r.get("reason"), ""), 1000);
            if domain.is_empty()
                || !valid_domain(&domain, LabelPolicy::StrictDotted)
                || prompt::is_never_revoke(&domain)
            {
                continue;
            }
            // Must be a live grant, never the baseline.
            if !store.revoke_live_grant(&domain) {
                self.record_finding(&finding(
                    "info",
                    &format!("review asked to revoke {domain}, which is not a runtime grant"),
                    &reason,
                    "if this domain should go, it is operator-owned — use `agentcage domain rm`",
                    Some(&domain),
                ));
                continue;
            }
            revoked.push(domain.clone());
            // A grant can shadow an active baseline suffix, leaving the
            // domain reachable after the revoke; claiming plain "blocked"
            // would lie in the forensic record.
            let still_allowed = dom.baseline_active_covers(&domain);
            self.deps.audit.emit(json::object([
                ("kind", Json::string("watcher_revoke")),
                ("ts", Json::Str((self.clock)().isoformat())),
                ("decision", Json::string("blocked")),
                ("method", Json::string("")),
                ("direction", Json::string("outbound")),
                ("host", Json::Str(domain.clone())),
                ("url", Json::string("")),
                ("path", Json::string("")),
                ("port", Json::Int(0)),
                ("domain", Json::Str(domain.clone())),
                ("reason", Json::Str(reason)),
                ("still_allowed_by_baseline", Json::Bool(still_allowed)),
                (
                    "decided_by",
                    Json::Str(format!("watcher:agent:{}", self.cfg.provider)),
                ),
            ]));
            if still_allowed {
                self.record_finding(&finding(
                    "medium",
                    &format!("revoked {domain}, but the operator's baseline still allows it"),
                    "the runtime grant was revoked; an active static baseline entry also matches \
                     this domain, so the traffic remains reachable",
                    "apply the baseline removal with `agentcage domain rm` if the domain should \
                     really go",
                    Some(&domain),
                ));
            }
        }
        revoked
    }

    // ── Scan state (host-visible) ──────────────────────────

    /// Scan counters next to the findings, for `watcher status`.
    fn write_state(
        &self,
        now: DateTime,
        flows: usize,
        findings: usize,
        revoked: usize,
        failed: bool,
    ) {
        let cap_size = self
            .tail
            .path()
            .and_then(|p| std::fs::metadata(p).ok())
            .map_or(0, |m| m.len());
        let n = |v: u64| Json::Int(i64::try_from(v).unwrap_or(i64::MAX));
        let u = |v: usize| Json::Int(i64::try_from(v).unwrap_or(i64::MAX));
        let seed = match self.scan_seed {
            None => Json::Null,
            Some(s) => i64::try_from(s).map_or_else(|_| Json::BigInt(s.to_string()), Json::Int),
        };
        let state = json::object([
            ("last_scan", Json::Str(now.isoformat())),
            // How far the tail is behind the live end: the counters look
            // healthy either way, this does not.
            (
                "capture_lag_bytes",
                n(cap_size.saturating_sub(self.tail.offset().unwrap_or(0))),
            ),
            ("capture_size_bytes", n(cap_size)),
            ("scans", n(self.scans)),
            ("flows_last_window", u(flows)),
            ("findings_last_scan", u(findings)),
            ("revoked_last_scan", u(revoked)),
            ("findings_total", n(self.findings_total)),
            ("last_scan_failed", Json::Bool(failed)),
            ("consecutive_failed_scans", n(self.consec_failures)),
            ("interval_seconds", Json::Float(self.cfg.interval_seconds)),
            ("digest_tokens_last_scan", u(self.last_digest_tokens)),
            ("max_digest_tokens", u(self.cfg.max_digest_tokens)),
            // Reproducibility: replays this scan's random choices (within
            // this implementation).
            ("scan_seed", seed),
            ("full_fidelity_scan", Json::Bool(self.full_fidelity)),
        ]);
        if let Err(e) = write_atomic(&self.deps.paths.state(), json::to_string(&state).as_bytes()) {
            self.warn(&format!("agentcage: cannot write watcher state: {e}"));
        }
    }
}

/// A validated review verdict.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Verdict {
    /// Model findings (objects only).
    pub findings: Vec<Json>,
    /// Requested revocations (objects only).
    pub allowlist_removals: Vec<Json>,
    /// Baseline removal recommendations (objects only).
    pub baseline_recommendations: Vec<Json>,
}

impl Verdict {
    /// Validate the tool arguments before any side effect: `findings`
    /// must be a list, the other two absent/null or lists. A present but
    /// malformed field is a scan failure, not "no findings".
    pub fn from_args(args: &Json, warn: &mut dyn FnMut(&str)) -> Option<Self> {
        let objects = |v: Option<&Json>| -> Vec<Json> {
            match v {
                Some(Json::Array(items)) => items
                    .iter()
                    .filter(|i| matches!(i, Json::Object(_)))
                    .cloned()
                    .collect(),
                _ => Vec::new(),
            }
        };
        let list_or_null = |v: Option<&Json>| matches!(v, None | Some(Json::Null | Json::Array(_)));
        if !matches!(args.get("findings"), Some(Json::Array(_))) {
            warn(
                "agentcage: watcher verdict malformed (findings is not a list) — recorded as a failed scan",
            );
            return None;
        }
        if !list_or_null(args.get("allowlist_removals")) {
            warn(
                "agentcage: watcher verdict malformed (allowlist_removals is not a list) — \
                 recorded as a failed scan",
            );
            return None;
        }
        if !list_or_null(args.get("baseline_recommendations")) {
            warn(
                "agentcage: watcher verdict malformed (baseline_recommendations is not a list) — \
                 recorded as a failed scan",
            );
            return None;
        }
        Some(Self {
            findings: objects(args.get("findings")),
            allowlist_removals: objects(args.get("allowlist_removals")),
            baseline_recommendations: objects(args.get("baseline_recommendations")),
        })
    }
}

/// A watcher-authored finding in the recorded shape.
fn finding(
    severity: &str,
    title: &str,
    detail: &str,
    recommendation: &str,
    domain: Option<&str>,
) -> Json {
    let mut f = json::object([
        ("severity", Json::string(severity)),
        ("title", Json::string(title)),
        ("detail", Json::string(detail)),
        ("recommendation", Json::string(recommendation)),
    ]);
    if let Some(d) = domain {
        f.set("domain", Json::string(d));
    }
    f
}

/// The watcher key through the decider's channel: `source:NAME` resolved
/// by the egress's one secret lookup (staged file, then env; an empty
/// staged file is a tombstone).
fn read_key(source: &str) -> String {
    let name = source.split_once(':').map_or("", |(_, name)| name);
    crate::secret_lookup::read_secret(name)
}

/// Append `data` to `path`, first rotating it to `<path>.1` once it has
/// reached `cap` bytes.
fn append_rotating(path: &Path, data: &[u8], cap: u64) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if std::fs::metadata(path).is_ok_and(|m| m.len() >= cap) {
        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        if let Err(e) = std::fs::rename(path, &rotated) {
            // Keep appending rather than drop the finding.
            eprintln!("agentcage: watcher findings rotation failed: {e}");
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(data)
}

/// Write `data` to `path` via `<path>.<pid>.tmp` and a rename.
fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}
