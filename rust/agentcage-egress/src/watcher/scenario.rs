//! Scan scenarios with a scripted LLM: the review's fail-closed paths,
//! the compliance retry, push-back and throttling, revocations, the
//! state and findings files, and the reload lifecycle. Ported from
//! `tests/test_watcher.py`.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use agentcage_core::har::datetime::DateTime;

use super::corpus::scratch_dir;
use super::runner::{LoopHandle, WatcherManager};
use super::scan::{
    AgentSpec, CallerFactory, GrantStore, RingSource, RuntimeRefs, TickOutcome, Watcher,
    WatcherDeps, WatcherPaths,
};
use super::tail::TailLimits;
use super::{WatcherConfig, scan};
use crate::audit::{MemorySink, WatcherRing};
use crate::config::{Config, Value};
use crate::inspect::domain::DomainInspector;
use crate::json::{self, Json};
use crate::llm::{LlmError, ToolCall, ToolCaller};

// ── Fakes ────────────────────────────────────────────────────

/// The audit writer's ring, pre-filled.
fn ring_with(cap: usize, items: Vec<Json>) -> WatcherRing {
    let ring = WatcherRing::with_capacity(cap);
    for e in items {
        ring.push(e);
    }
    ring
}

#[derive(Debug, Default)]
struct ScriptedLlm {
    replies: Mutex<VecDeque<Result<Json, LlmError>>>,
    calls: Mutex<Vec<ToolCall>>,
    agents: Mutex<Vec<AgentSpec>>,
}

impl ScriptedLlm {
    fn push(&self, reply: Result<Json, LlmError>) {
        self.replies.lock().unwrap().push_back(reply);
    }

    fn ok(&self, review: &str) {
        self.push(Ok(json::parse(review).unwrap()));
    }

    fn err(&self, msg: &str) {
        self.push(Err(LlmError {
            message: msg.to_owned(),
        }));
    }

    fn calls(&self) -> Vec<ToolCall> {
        self.calls.lock().unwrap().clone()
    }
}

impl ToolCaller for ScriptedLlm {
    fn call(&self, call: &ToolCall) -> Result<Json, LlmError> {
        self.calls.lock().unwrap().push(call.clone());
        self.replies.lock().unwrap().pop_front().unwrap_or_else(|| {
            Err(LlmError {
                message: "no scripted reply".to_owned(),
            })
        })
    }
}

#[derive(Debug)]
struct Factory(Arc<ScriptedLlm>);

impl CallerFactory for Factory {
    fn caller(&self, agent: &AgentSpec) -> Arc<dyn ToolCaller> {
        self.0.agents.lock().unwrap().push(agent.clone());
        Arc::clone(&self.0) as Arc<dyn ToolCaller>
    }
}

/// The Policy API's revocation, over the shared inspector, counting calls.
#[derive(Debug)]
struct FakeStore {
    dom: Arc<DomainInspector>,
    calls: Mutex<usize>,
    revoked: Mutex<usize>,
}

impl FakeStore {
    fn new(dom: &Arc<DomainInspector>) -> Self {
        Self {
            dom: Arc::clone(dom),
            calls: Mutex::new(0),
            revoked: Mutex::new(0),
        }
    }

    fn persisted(&self) -> usize {
        *self.revoked.lock().unwrap()
    }

    fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl GrantStore for FakeStore {
    fn revoke_live_grant(&self, domain: &str) -> bool {
        *self.calls.lock().unwrap() += 1;
        if !self.dom.is_granted(domain) {
            return false;
        }
        self.dom.revoke(domain);
        *self.revoked.lock().unwrap() += 1;
        true
    }
}

// ── Harness ──────────────────────────────────────────────────

struct H {
    w: Watcher,
    ring: Arc<WatcherRing>,
    llm: Arc<ScriptedLlm>,
    audit: Arc<MemorySink>,
    store: Arc<FakeStore>,
    dom: Arc<DomainInspector>,
    dir: PathBuf,
    warnings: Arc<Mutex<Vec<String>>>,
}

fn yaml(text: &str) -> Value {
    agentcage_core::yaml::load(text).unwrap()
}

fn domains(allow: &[&str], granted: &[&str]) -> Arc<DomainInspector> {
    let list: Vec<String> = allow.iter().map(|d| format!("'{d}'")).collect();
    let dom =
        DomainInspector::from_config(&yaml(&format!("allow: [{}]", list.join(", ")))).unwrap();
    for g in granted {
        assert!(dom.grant(g, "", "test", "test"));
    }
    Arc::new(dom)
}

/// The watcher block used by every scenario; `extra` is YAML lines (at
/// the block's indentation) that add keys or override the defaults.
fn watcher_cfg(extra: &str) -> Config {
    let defaults = [
        ("enable", "true"),
        ("interval_seconds", "60"),
        ("window_seconds", "3600"),
        ("max_flows", "100"),
        ("auto_revoke", "true"),
        ("provider", "openai"),
        ("model", "gpt-test"),
        ("api_key", "'env:PATH'"),
    ];
    let overridden: Vec<&str> = extra
        .lines()
        .filter_map(|l| l.trim().split_once(':').map(|(k, _)| k))
        .collect();
    let mut text = String::from("agents:\n  watcher:\n");
    for (k, v) in defaults {
        if !overridden.contains(&k) {
            let _ = writeln!(text, "    {k}: {v}");
        }
    }
    text.push_str(extra);
    Config::parse("t", &text).unwrap()
}

fn deps(
    ring: &Arc<WatcherRing>,
    llm: &Arc<ScriptedLlm>,
    audit: &Arc<MemorySink>,
    dir: &std::path::Path,
) -> WatcherDeps {
    WatcherDeps {
        ring: Arc::clone(ring) as Arc<dyn RingSource>,
        audit: Arc::clone(audit) as Arc<dyn crate::audit::AuditSink>,
        llm: Arc::new(Factory(Arc::clone(llm))),
        paths: WatcherPaths {
            dir: dir.join("watcher"),
            capture: Some(dir.join("capture.jsonl")),
        },
    }
}

fn harness(extra: &str, ring: Vec<Json>, dom: Arc<DomainInspector>, with_store: bool) -> H {
    let dir = scratch_dir("scan");
    let ring = Arc::new(ring_with(5000, ring));
    let llm = Arc::new(ScriptedLlm::default());
    let audit = Arc::new(MemorySink::default());
    let store = Arc::new(FakeStore::new(&dom));
    let warnings = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&warnings);
    let refs = RuntimeRefs {
        domains: Some(Arc::clone(&dom)),
        grants: with_store.then(|| Arc::clone(&store) as Arc<dyn GrantStore>),
    };
    let cfg = WatcherConfig::parse(&watcher_cfg(extra), &mut |_| {});
    let w = Watcher::new(cfg, deps(&ring, &llm, &audit, &dir), refs).with_warn(Arc::new(
        move |m: &str| sink.lock().unwrap().push(m.to_owned()),
    ));
    H {
        w,
        ring,
        llm,
        audit,
        store,
        dom,
        dir,
        warnings,
    }
}

fn flow(host: &str) -> Json {
    json::object([
        ("ts", Json::Str(DateTime::now_utc().isoformat())),
        ("decision", Json::string("allowed")),
        ("host", Json::string(host)),
        ("method", Json::string("POST")),
        ("path", Json::string("/v1/x")),
        ("direction", Json::string("outbound")),
        ("inspectors", Json::Array(Vec::new())),
        ("port", Json::Int(443)),
        ("url", Json::Str(format!("https://{host}/v1/x"))),
        ("reason", Json::string("")),
    ])
}

impl H {
    fn tick(&mut self) -> TickOutcome {
        self.w.tick(&|| false)
    }

    /// Tick with a seed whose full-fidelity roll comes out `full`.
    fn tick_seeded(&mut self, full: bool) -> TickOutcome {
        let seed = seed_with_full_fidelity(full);
        self.w.tick_with(DateTime::now_utc(), seed, &|| false)
    }

    fn findings(&self) -> Vec<Json> {
        let path = self.dir.join("watcher/findings.jsonl");
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| json::parse(l).unwrap())
            .collect()
    }

    fn titles(&self) -> Vec<String> {
        self.findings()
            .iter()
            .map(|f| {
                f.get("title")
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_owned()
            })
            .collect()
    }

    fn state(&self) -> Json {
        json::parse(&std::fs::read_to_string(self.dir.join("watcher/state.json")).unwrap()).unwrap()
    }

    fn audit_kinds(&self, kind: &str) -> Vec<Json> {
        self.audit
            .entries()
            .into_iter()
            .filter(|e| e.get("kind").and_then(Json::as_str) == Some(kind))
            .collect()
    }

    fn write_capture(&self, entries: &[Json]) {
        let text: String = entries.iter().map(|e| json::to_string(e) + "\n").collect();
        std::fs::write(self.dir.join("capture.jsonl"), text).unwrap();
    }
}

impl Drop for H {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn seed_with_full_fidelity(full: bool) -> u64 {
    use rand::{Rng as _, SeedableRng as _};
    (0..10_000u64)
        .find(|s| {
            (super::ScanRng::seed_from_u64(*s).random::<f64>() < scan::FULL_SCAN_PROB) == full
        })
        .expect("a seed")
}

const NO_FINDINGS: &str = r#"{"findings": []}"#;

// ── Fail closed ──────────────────────────────────────────────

#[test]
fn a_scan_failure_is_recorded_not_silent_and_revokes_nothing() {
    let mut h = harness(
        "",
        vec![flow("api.example.com")],
        domains(&[], &["granted.example"]),
        true,
    );
    h.llm.err("timeout");
    assert_eq!(h.tick(), TickOutcome::Failed);
    assert!(h.titles().iter().any(|t| t.contains("scan failed")));
    assert!(h.dom.is_granted("granted.example"));
    assert_eq!(h.store.persisted(), 0);
    assert!(!h.audit_kinds("watcher_finding").is_empty());
    let st = h.state();
    assert_eq!(st.get("last_scan_failed"), Some(&Json::Bool(true)));
    assert_eq!(st.get("consecutive_failed_scans"), Some(&Json::Int(1)));
    assert_eq!(st.get("flows_last_window"), Some(&Json::Int(1)));
}

#[test]
fn a_failed_scan_pushes_back_and_the_retry_is_analysed() {
    let mut h = harness(
        "",
        vec![flow("suspicious.example")],
        domains(&[], &["g.example"]),
        true,
    );
    h.llm.err("timeout");
    h.llm.ok(
        r#"{"findings": [{"severity": "high", "title": "saw the retry", "detail": "evidence", "recommendation": "none"}]}"#,
    );
    h.tick();
    let ring = h.ring.snapshot();
    assert_eq!(ring.len(), 1);
    assert_eq!(
        ring[0].get("host").and_then(Json::as_str),
        Some("suspicious.example")
    );
    assert_eq!(h.tick(), TickOutcome::Reviewed);
    assert!(h.ring.snapshot().is_empty());
    assert_eq!(h.llm.calls().len(), 2);
    assert!(h.titles().iter().any(|t| t == "saw the retry"));
    assert_eq!(
        h.state().get("consecutive_failed_scans"),
        Some(&Json::Int(0))
    );
}

#[test]
fn the_failure_finding_is_throttled_to_the_first_and_every_tenth() {
    let mut h = harness("", vec![flow("a.example")], domains(&[], &[]), true);
    for _ in 0..20 {
        h.llm.err("down");
        h.tick();
    }
    let failures: Vec<String> = h
        .findings()
        .iter()
        .filter(|f| f.get("title").and_then(Json::as_str) == Some("watcher scan failed"))
        .map(|f| f.get("detail").and_then(Json::as_str).unwrap().to_owned())
        .collect();
    assert_eq!(failures.len(), 3);
    assert!(failures[0].contains("(1 consecutive failures)"));
    assert!(failures[1].contains("(10 consecutive failures)"));
    assert!(failures[2].contains("(20 consecutive failures)"));
}

#[test]
fn the_watchers_own_records_are_not_reingested() {
    let own = json::object([
        ("kind", Json::string("watcher_finding")),
        ("decision", Json::string("flagged")),
        ("host", Json::string("self")),
        ("title", Json::string("old noise")),
    ]);
    let mut h = harness("", vec![flow("real.example"), own], domains(&[], &[]), true);
    h.llm.ok(NO_FINDINGS);
    h.tick();
    let calls = h.llm.calls();
    assert_eq!(calls.len(), 1);
    let digest = json::parse(&calls[0].user_content).unwrap();
    assert_eq!(
        digest.get("totals").and_then(|t| t.get("flows")),
        Some(&Json::Int(1))
    );
    assert!(!calls[0].user_content.contains("old noise"));
}

#[test]
fn unconfigured_or_keyless_agents_never_call_the_model() {
    for extra in [
        "    provider: ''\n",
        "    api_key: 'env:AGENTCAGE_WATCHER_TEST_UNSET'\n",
    ] {
        let mut h = harness(extra, vec![flow("a.example")], domains(&[], &[]), true);
        assert_eq!(h.tick(), TickOutcome::Failed);
        assert!(h.llm.calls().is_empty());
        assert!(
            h.warnings
                .lock()
                .unwrap()
                .iter()
                .any(|w| w.contains("not configured"))
        );
    }
    let mut h = harness(
        "    provider: mistral\n",
        vec![flow("a.example")],
        domains(&[], &[]),
        true,
    );
    assert_eq!(h.tick(), TickOutcome::Failed);
    assert!(h.llm.calls().is_empty());
    assert!(h.warnings.lock().unwrap().contains(
        &"agentcage: unknown watcher agent provider 'mistral' — scans are skipped".to_owned()
    ));
}

#[test]
fn malformed_verdicts_are_failed_scans() {
    for bad in [
        r#"{"findings": "no"}"#,
        r#"{"findings": [], "allowlist_removals": "g.example"}"#,
        r#"{"findings": [], "baseline_recommendations": 42}"#,
    ] {
        let mut h = harness(
            "",
            vec![flow("a.example")],
            domains(&[], &["g.example"]),
            true,
        );
        h.llm.ok(bad);
        h.llm.ok(bad);
        assert_eq!(h.tick(), TickOutcome::Failed, "{bad}");
        assert!(h.dom.is_granted("g.example"));
    }
    // Null optional lists are fine.
    let mut h = harness("", vec![flow("a.example")], domains(&[], &[]), true);
    h.llm.ok(r#"{"findings": [], "allowlist_removals": null}"#);
    assert_eq!(h.tick(), TickOutcome::Reviewed);
}

// ── The compliance retry ─────────────────────────────────────

#[test]
fn empty_tool_args_get_exactly_one_retry_with_the_contract_restated() {
    let mut h = harness("", vec![flow("a.example")], domains(&[], &[]), true);
    h.llm.ok("{}");
    h.llm.ok(
        r#"{"findings": [{"severity": "low", "title": "t", "detail": "d", "recommendation": "r"}]}"#,
    );
    assert_eq!(h.tick(), TickOutcome::Reviewed);
    let calls = h.llm.calls();
    assert_eq!(calls.len(), 2);
    assert!(
        calls[1]
            .user_content
            .contains("did not use the `review` tool correctly")
    );
    assert!(!calls[0].user_content.contains("did not use"));
    assert!(calls[1].user_content.starts_with(&calls[0].user_content));
}

#[test]
fn two_non_compliant_replies_fail_closed_and_never_a_third() {
    let mut h = harness("", vec![flow("a.example")], domains(&[], &[]), true);
    for _ in 0..3 {
        h.llm.ok("{}");
    }
    assert_eq!(h.tick(), TickOutcome::Failed);
    assert_eq!(h.llm.calls().len(), 2);
}

#[test]
fn a_network_error_is_not_retried_and_a_compliant_reply_is_one_call() {
    let mut h = harness("", vec![flow("a.example")], domains(&[], &[]), true);
    h.llm.err("provider down");
    h.tick();
    assert_eq!(h.llm.calls().len(), 1);
    h.llm.ok(NO_FINDINGS);
    h.tick();
    assert_eq!(h.llm.calls().len(), 2);
}

#[test]
fn the_call_carries_the_prompt_tool_budget_and_agent() {
    let mut h = harness(
        "    context: payments recon suite\n    max_tokens: 1234\n",
        vec![flow("a.example")],
        domains(&[], &[]),
        true,
    );
    h.llm.ok(NO_FINDINGS);
    h.tick();
    let call = &h.llm.calls()[0];
    assert!(
        call.system
            .contains("BEGIN OPERATOR CONTEXT -----\npayments recon suite\n")
    );
    assert!(call.system.ends_with("enforced gate."));
    assert_eq!(call.tool.name, "review");
    assert_eq!(call.max_tokens, 1234);
    let agent = h.llm.agents.lock().unwrap()[0].clone();
    assert_eq!(agent.base_url, "https://api.openai.com");
    assert_eq!(agent.model, "gpt-test");
    assert!((agent.timeout_seconds - 30.0).abs() < f64::EPSILON);
    assert!(!agent.api_key.is_empty());
}

// ── Revocations ──────────────────────────────────────────────

#[test]
fn a_damned_grant_is_revoked_persisted_and_audited_and_baseline_only_recommended() {
    let mut h = harness(
        "",
        vec![flow("granted.example")],
        domains(&["base.example"], &["granted.example"]),
        true,
    );
    h.llm.ok(
        r#"{"findings": [{"severity": "high", "title": "C2 beacon", "detail": "evidence", "recommendation": "revoke"}],
            "allowlist_removals": [{"domain": "granted.example", "reason": "beaconed every 30s"}],
            "baseline_recommendations": [{"domain": "base.example", "reason": "unused for 30d"}]}"#,
    );
    h.tick();
    assert!(!h.dom.is_granted("granted.example"));
    assert_eq!(h.store.persisted(), 1);
    let revokes = h.audit_kinds("watcher_revoke");
    assert_eq!(revokes.len(), 1);
    let keys: Vec<&str> = match &revokes[0] {
        Json::Object(p) => p.iter().map(|(k, _)| k.as_str()).collect(),
        _ => Vec::new(),
    };
    assert_eq!(
        keys,
        [
            "kind",
            "ts",
            "decision",
            "method",
            "direction",
            "host",
            "url",
            "path",
            "port",
            "domain",
            "reason",
            "still_allowed_by_baseline",
            "decided_by"
        ]
    );
    assert_eq!(
        revokes[0].get("decided_by").and_then(Json::as_str),
        Some("watcher:agent:openai")
    );
    assert!(h.dom.baseline_list().contains(&"base.example".to_owned()));
    let findings = h.findings();
    assert!(findings.iter().any(|f| {
        f.get("title")
            .and_then(Json::as_str)
            .is_some_and(|t| t.contains("base.example"))
            && f.get("recommendation")
                .and_then(Json::as_str)
                .is_some_and(|r| r.contains("domain rm"))
    }));
    assert!(findings.iter().any(|f| {
        f.get("severity") == Some(&Json::string("high"))
            && f.get("title") == Some(&Json::string("C2 beacon"))
    }));
    let st = h.state();
    assert_eq!(st.get("revoked_last_scan"), Some(&Json::Int(1)));
    assert_eq!(st.get("findings_last_scan"), Some(&Json::Int(1)));
    assert_eq!(st.get("findings_total"), Some(&Json::Int(2)));
}

#[test]
fn each_revocation_is_persisted_on_its_own() {
    let mut h = harness(
        "",
        vec![flow("a.example")],
        domains(&[], &["g1.example", "g2.example"]),
        true,
    );
    h.llm.ok(
        r#"{"findings": [], "allowlist_removals": [{"domain": "g1.example", "reason": "b"}, {"domain": "G2.Example.", "reason": "b"}]}"#,
    );
    h.tick();
    assert!(!h.dom.is_granted("g1.example") && !h.dom.is_granted("g2.example"));
    assert_eq!(h.store.persisted(), 2);
    assert_eq!(h.store.calls(), 2);
}

#[test]
fn a_grant_shadowing_an_active_baseline_is_flagged() {
    let mut h = harness(
        "",
        vec![flow("api.example.com")],
        domains(&["example.com"], &["api.example.com"]),
        true,
    );
    h.llm.ok(
        r#"{"findings": [], "allowlist_removals": [{"domain": "api.example.com", "reason": "beacon"}]}"#,
    );
    h.tick();
    assert!(!h.dom.is_granted("api.example.com"));
    let revoke = &h.audit_kinds("watcher_revoke")[0];
    assert_eq!(
        revoke.get("still_allowed_by_baseline"),
        Some(&Json::Bool(true))
    );
    assert!(
        h.titles()
            .iter()
            .any(|t| t.contains("baseline still allows"))
    );
}

#[test]
fn a_baseline_or_hallucinated_domain_is_structurally_refused() {
    let mut h = harness(
        "",
        vec![flow("a.example")],
        domains(&["base.example"], &["g.example"]),
        true,
    );
    h.llm.ok(
        r#"{"findings": [], "allowlist_removals": [{"domain": "base.example", "reason": "hallucinated"}]}"#,
    );
    h.tick();
    assert!(h.dom.is_granted("g.example"));
    assert!(h.titles().iter().any(|t| t.contains("not a runtime grant")));
    assert_eq!(h.store.persisted(), 0);
}

#[test]
fn the_never_revoke_floor_and_bad_syntax_are_skipped_silently() {
    let mut h = harness(
        "",
        vec![flow("a.example")],
        domains(&[], &["g.example"]),
        true,
    );
    h.llm.ok(r#"{"findings": [], "allowlist_removals": [
            {"domain": "metadata.google.internal", "reason": "x"},
            {"domain": "169-254-169-254.nip.io", "reason": "x"},
            {"domain": "not a domain", "reason": "x"}, {"reason": "x"}, "junk"]}"#);
    h.tick();
    assert!(h.dom.is_granted("g.example"));
    assert_eq!(h.store.persisted(), 0);
    assert_eq!(h.store.calls(), 0);
    assert!(h.findings().is_empty());
}

#[test]
fn auto_revoke_off_narrows_nothing_but_records_the_recommendation() {
    let mut h = harness(
        "    auto_revoke: false\n",
        vec![flow("a.example")],
        domains(&[], &["g.example"]),
        true,
    );
    h.llm.ok(
        r#"{"findings": [], "allowlist_removals": [{"domain": "g.example", "reason": "beacon"}]}"#,
    );
    h.tick();
    assert!(h.dom.is_granted("g.example"));
    assert_eq!(h.store.persisted(), 0);
    let titles: Vec<String> = h
        .audit_kinds("watcher_finding")
        .iter()
        .map(|e| {
            e.get("title")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned()
        })
        .collect();
    assert!(
        titles
            .iter()
            .any(|t| t == "revocation recommended for g.example (auto_revoke is off)")
    );
}

#[test]
fn blocklist_mode_skips_revocation_with_a_finding() {
    let dom = DomainInspector::from_config(&yaml("block: ['bad.example']")).unwrap();
    dom.insert_raw_grant("g.example".to_owned(), crate::config::Mapping::new());
    let mut h = harness("", vec![flow("a.example")], Arc::new(dom), true);
    h.llm.ok(
        r#"{"findings": [], "allowlist_removals": [{"domain": "g.example", "reason": "beacon"}]}"#,
    );
    h.tick();
    assert!(h.dom.is_granted("g.example"));
    assert_eq!(h.store.persisted(), 0);
    assert!(h.titles().iter().any(|t| t.contains("allowlist mode")));
}

#[test]
fn without_a_grant_store_removals_degrade_to_findings() {
    let mut h = harness(
        "",
        vec![flow("a.example")],
        domains(&[], &["g.example"]),
        false,
    );
    h.llm.ok(
        r#"{"findings": [], "allowlist_removals": [{"domain": "g.example", "reason": "beacon"}]}"#,
    );
    h.tick();
    assert!(h.dom.is_granted("g.example"));
    assert!(
        h.titles()
            .iter()
            .any(|t| t == "cannot revoke g.example: runtime grants are disabled")
    );
    // No grant store: the digest carries no granted list either.
    let digest = json::parse(&h.llm.calls()[0].user_content).unwrap();
    assert_eq!(
        digest.get("current_granted"),
        Some(&Json::Array(Vec::new()))
    );
}

// ── Quiet scans, indicators, state ───────────────────────────

#[test]
fn a_quiet_cage_never_calls_the_model() {
    let mut h = harness("", Vec::new(), domains(&[], &[]), true);
    h.write_capture(&[]);
    assert_eq!(h.tick(), TickOutcome::Quiet);
    assert!(h.llm.calls().is_empty());
    let st = h.state();
    assert_eq!(st.get("flows_last_window"), Some(&Json::Int(0)));
    assert_eq!(st.get("scans"), Some(&Json::Int(1)));
}

#[test]
fn the_state_file_has_the_host_readers_fields_in_order() {
    let mut h = harness("", vec![flow("a.example")], domains(&[], &[]), true);
    h.llm.ok(NO_FINDINGS);
    h.tick();
    let st = h.state();
    let keys: Vec<&str> = match &st {
        Json::Object(p) => p.iter().map(|(k, _)| k.as_str()).collect(),
        _ => Vec::new(),
    };
    assert_eq!(
        keys,
        [
            "last_scan",
            "capture_lag_bytes",
            "capture_size_bytes",
            "scans",
            "flows_last_window",
            "findings_last_scan",
            "revoked_last_scan",
            "findings_total",
            "last_scan_failed",
            "consecutive_failed_scans",
            "interval_seconds",
            "digest_tokens_last_scan",
            "max_digest_tokens",
            "scan_seed",
            "full_fidelity_scan"
        ]
    );
    assert_eq!(st.get("interval_seconds"), Some(&Json::Float(60.0)));
    assert!(matches!(
        st.get("scan_seed"),
        Some(Json::Int(_) | Json::BigInt(_))
    ));
}

fn binary_capture(host: &str) -> Json {
    json::parse(&format!(
        r#"{{"ts": "{}", "host": "{host}", "direction": "outbound", "decision": "allowed",
            "method": "POST", "path": "/up", "inspectors": [],
            "inbound": {{"request": {{"body": "QUJDREVG", "bodyEncoding": "base64", "bodySize": 6,
                                     "url": "https://{host}/up"}},
                        "response": {{"status": 200, "bodySize": 0}}}},
            "outbound": {{"request": {{}}, "response": {{}}}}}}"#,
        DateTime::now_utc().isoformat()
    ))
    .unwrap()
}

#[test]
fn a_binary_body_to_a_granted_host_is_a_finding_without_the_model() {
    let mut h = harness(
        "",
        vec![flow("a.example")],
        domains(&[], &["drop.example"]),
        true,
    );
    h.write_capture(&[binary_capture("drop.example")]);
    h.llm.ok(NO_FINDINGS);
    h.tick();
    assert!(
        h.titles()
            .contains(&"1 binary request body(ies) sent to a runtime-granted host".to_owned())
    );
    assert!(h.state().get("full_fidelity_scan").is_some());
}

#[test]
fn a_saturated_ring_is_a_finding() {
    let mut h = harness("", Vec::new(), domains(&[], &[]), true);
    h.ring = Arc::new(ring_with(2, vec![flow("a.example"), flow("b.example")]));
    h.w = Watcher::new(
        h.w.config().clone(),
        deps(&h.ring, &h.llm, &h.audit, &h.dir),
        RuntimeRefs::default(),
    );
    h.llm.ok(NO_FINDINGS);
    h.tick();
    assert!(
        h.titles()
            .contains(&"audit ring was saturated before this scan".to_owned())
    );
}

#[test]
fn a_full_fidelity_scan_raises_the_budget() {
    let flood: Vec<Json> = (0..80)
        .map(|i| {
            let mut e = binary_capture(&format!("h{i}.example"));
            e.set("inbound", json::parse(&format!(
                r#"{{"request": {{"body": "{}", "url": "https://h{i}.example/p{i}"}}, "response": {{}}}}"#,
                "x".repeat(400)
            )).unwrap());
            e
        })
        .collect();
    let mut cheap = harness(
        "    max_digest_tokens: 1000\n",
        Vec::new(),
        domains(&[], &[]),
        true,
    );
    cheap.write_capture(&flood);
    cheap.llm.ok(NO_FINDINGS);
    cheap.tick_seeded(false);
    assert!(!cheap.w.full_fidelity());
    let cheap_tokens = cheap.state().get("digest_tokens_last_scan").cloned();
    assert!(matches!(cheap_tokens, Some(Json::Int(n)) if n <= 1000));

    let mut full = harness(
        "    max_digest_tokens: 1000\n",
        Vec::new(),
        domains(&[], &[]),
        true,
    );
    full.write_capture(&flood);
    full.llm.ok(NO_FINDINGS);
    full.tick_seeded(true);
    assert!(full.w.full_fidelity());
    assert_eq!(
        full.state().get("full_fidelity_scan"),
        Some(&Json::Bool(true))
    );
    let full_tokens = full.state().get("digest_tokens_last_scan").cloned();
    assert!(matches!(full_tokens, Some(Json::Int(n)) if n > 1000 && n <= 4000));
}

#[test]
fn a_skipped_backlog_is_recorded_as_a_finding() {
    let mut h = harness("", vec![flow("a.example")], domains(&[], &[]), true);
    let entries: Vec<Json> = (0..200)
        .map(|i| binary_capture(&format!("h{i:03}.example")))
        .collect();
    h.write_capture(&entries);
    h.w.set_tail_limits(TailLimits {
        chunk: 2000,
        max_catchup: 8000,
        line_cap: 32 * 1024 * 1024,
    });
    h.llm.ok(NO_FINDINGS);
    h.tick();
    assert!(
        h.titles()
            .iter()
            .any(|t| t.starts_with("capture backlog too large: skipped "))
    );
}

#[test]
fn a_stopped_tick_returns_its_batch_and_applies_nothing() {
    let mut h = harness(
        "",
        vec![flow("a.example")],
        domains(&[], &["g.example"]),
        true,
    );
    h.llm
        .ok(r#"{"findings": [], "allowlist_removals": [{"domain": "g.example", "reason": "x"}]}"#);
    assert_eq!(h.w.tick(&|| true), TickOutcome::Abandoned);
    assert!(h.dom.is_granted("g.example"));
    assert_eq!(h.ring.snapshot().len(), 1);
}

#[test]
fn jitter_stays_within_bounds_and_the_floor() {
    let h = harness(
        "    interval_seconds: 900\n",
        Vec::new(),
        domains(&[], &[]),
        true,
    );
    let ds: Vec<f64> = (0..300).map(|_| h.w.next_delay().as_secs_f64()).collect();
    assert!(
        ds.iter()
            .all(|d| (450.0 - 1e-6..=1350.0 + 1e-6).contains(d))
    );
    let distinct: std::collections::BTreeSet<u64> =
        ds.iter().map(|d| d.round().to_bits()).collect();
    assert!(distinct.len() > 20);
    let h = harness("", Vec::new(), domains(&[], &[]), true);
    assert!((0..100).all(|_| h.w.next_delay().as_secs_f64() >= 60.0));
}

#[test]
fn findings_rotate_at_the_cap() {
    let dir = scratch_dir("rot");
    let path = dir.join("findings.jsonl");
    std::fs::write(
        &path,
        vec![b'x'; usize::try_from(scan::FINDINGS_MAX_BYTES).unwrap()],
    )
    .unwrap();
    let mut h = harness("", vec![flow("a.example")], domains(&[], &[]), true);
    let target = h.dir.join("watcher");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::rename(&path, target.join("findings.jsonl")).unwrap();
    h.llm.err("down");
    h.tick();
    assert_eq!(h.findings().len(), 1);
    let rotated = std::fs::metadata(target.join("findings.jsonl.1")).unwrap();
    assert_eq!(rotated.len(), scan::FINDINGS_MAX_BYTES);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn finding_records_have_the_audit_shape() {
    let mut h = harness("", vec![flow("a.example")], domains(&[], &[]), true);
    h.llm.ok(
        r#"{"findings": [{"severity": "CRITICAL", "title": "t", "detail": "d", "recommendation": "r", "domain": "x.example"}]}"#,
    );
    h.tick();
    let entry = &h.audit_kinds("watcher_finding")[0];
    let keys: Vec<&str> = match entry {
        Json::Object(p) => p.iter().map(|(k, _)| k.as_str()).collect(),
        _ => Vec::new(),
    };
    assert_eq!(
        keys,
        [
            "kind",
            "ts",
            "decision",
            "method",
            "direction",
            "host",
            "url",
            "path",
            "port",
            "reason",
            "severity",
            "title",
            "detail",
            "recommendation",
            "decided_by",
            "inspectors"
        ]
    );
    assert_eq!(entry.get("host"), Some(&Json::string("x.example")));
    assert_eq!(entry.get("severity"), Some(&Json::string("critical")));
    // The file holds the same record, compact.
    assert_eq!(&h.findings()[0], entry);
}

// ── Lifecycle ────────────────────────────────────────────────

fn manager_setup() -> (WatcherManager, WatcherDeps, Arc<WatcherRing>, PathBuf) {
    let dir = scratch_dir("mgr");
    let ring = Arc::new(ring_with(5000, Vec::new()));
    let llm = Arc::new(ScriptedLlm::default());
    let audit = Arc::new(MemorySink::default());
    let deps = deps(&ring, &llm, &audit, &dir);
    (WatcherManager::new(Arc::new(|_: &str| {})), deps, ring, dir)
}

#[test]
fn an_unchanged_block_keeps_the_watcher_and_its_state_but_refreshes_refs() {
    let dir = scratch_dir("mgr");
    let ring = Arc::new(ring_with(5000, Vec::new()));
    let llm = Arc::new(ScriptedLlm::default());
    let audit = Arc::new(MemorySink::default());
    let deps = deps(&ring, &llm, &audit, &dir);
    let mut m = WatcherManager::new(Arc::new(|_: &str| {}));
    m.apply(&watcher_cfg(""), &deps, RuntimeRefs::default());
    let first = m.watcher().unwrap();
    first.lock().unwrap().tick(&|| false);
    assert_eq!(first.lock().unwrap().scans(), 1);
    // An unrelated edit elsewhere in the config.
    let mut cfg_text = String::from("logging:\n  level: debug\n");
    cfg_text.push_str(
        "agents:\n  watcher:\n    enable: true\n    interval_seconds: 60\n    \
         window_seconds: 3600\n    max_flows: 100\n    auto_revoke: true\n    \
         provider: openai\n    model: gpt-test\n    api_key: 'env:PATH'\n",
    );
    let dom = domains(&[], &["g.example"]);
    let store = Arc::new(FakeStore::new(&dom));
    m.apply(
        &Config::parse("t", &cfg_text).unwrap(),
        &deps,
        RuntimeRefs {
            domains: Some(Arc::clone(&dom)),
            grants: Some(Arc::clone(&store) as Arc<dyn GrantStore>),
        },
    );
    let kept = m.watcher().unwrap();
    assert!(Arc::ptr_eq(&first, &kept));
    assert_eq!(kept.lock().unwrap().scans(), 1);
    // The kept watcher revokes through the refreshed refs.
    ring.push(flow("a.example"));
    llm.ok(r#"{"findings": [], "allowlist_removals": [{"domain": "g.example", "reason": "x"}]}"#);
    kept.lock().unwrap().tick(&|| false);
    assert!(!dom.is_granted("g.example"));
    assert_eq!(store.persisted(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_changed_block_rebuilds_and_a_disabled_one_stops_and_empties_the_ring() {
    let (mut m, deps, ring, dir) = manager_setup();
    m.apply(&watcher_cfg(""), &deps, RuntimeRefs::default());
    let first = m.watcher().unwrap();
    m.apply(
        &watcher_cfg("    model: other\n"),
        &deps,
        RuntimeRefs::default(),
    );
    let second = m.watcher().unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(m.is_enabled());

    ring.push_back(vec![flow("a.example")]);
    m.apply(
        &Config::parse("t", "agents:\n  watcher: {}\n").unwrap(),
        &deps,
        RuntimeRefs::default(),
    );
    assert!(!m.is_enabled());
    assert!(m.watcher().is_none());
    assert!(ring.snapshot().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_non_mapping_block_disables_with_a_warning() {
    let (_, deps, _ring, dir) = manager_setup();
    let warnings = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&warnings);
    let mut m = WatcherManager::new(Arc::new(move |w: &str| {
        sink.lock().unwrap().push(w.to_owned());
    }));
    m.apply(
        &Config::parse("t", "agents:\n  watcher: true\n").unwrap(),
        &deps,
        RuntimeRefs::default(),
    );
    assert!(!m.is_enabled());
    assert_eq!(
        warnings.lock().unwrap().as_slice(),
        ["agentcage: watcher config is not a mapping (got bool) — watcher disabled"]
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn refreshing_refs_repoints_the_grant_store_and_rereads_the_key() {
    let mut h = harness(
        "",
        vec![flow("a.example")],
        domains(&[], &["g.example"]),
        false,
    );
    let handle = h.w.refs_handle();
    let store = Arc::new(FakeStore::new(&h.dom));
    handle.refresh(RuntimeRefs {
        domains: Some(Arc::clone(&h.dom)),
        grants: Some(Arc::clone(&store) as Arc<dyn GrantStore>),
    });
    h.llm
        .ok(r#"{"findings": [], "allowlist_removals": [{"domain": "g.example", "reason": "x"}]}"#);
    h.tick();
    assert!(!h.dom.is_granted("g.example"));
    assert_eq!(store.persisted(), 1);
    assert!(!h.w.secret().is_empty());
}

#[test]
fn the_loop_stops_promptly() {
    let (mut m, deps, _ring, dir) = manager_setup();
    m.apply(&watcher_cfg(""), &deps, RuntimeRefs::default());
    m.start();
    let started = std::time::Instant::now();
    m.shutdown();
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    let w = Arc::new(Mutex::new(Watcher::new(
        WatcherConfig::default(),
        deps.clone(),
        RuntimeRefs::default(),
    )));
    let handle = LoopHandle::spawn(w, Arc::new(|_: &str| {})).unwrap();
    handle.join();
    let _ = std::fs::remove_dir_all(dir);
}
