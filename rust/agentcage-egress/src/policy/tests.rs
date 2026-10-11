use super::*;
use crate::llm::{HttpReply, WireRequest};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

// ── fixtures ─────────────────────────────────────────────────

fn corpus_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/egress/policy_api.json")
}

fn cases() -> Vec<Json> {
    let text = std::fs::read_to_string(corpus_path()).expect("policy_api.json is readable");
    match json::parse(&text)
        .expect("policy_api.json parses")
        .get("cases")
    {
        Some(Json::Array(cases)) => cases.clone(),
        _ => panic!("policy_api.json has no cases"),
    }
}

fn b64decode(text: &str) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("bad base64 {c}"),
        }
    };
    let clean: Vec<u8> = text.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::new();
    for chunk in clean.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c) << (18 - 6 * i);
        }
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    out
}

/// A fixture byte string: plain text, or `{"b64": ...}`.
fn bytes_of(value: &Json) -> Vec<u8> {
    match value {
        Json::Str(s) => s.as_bytes().to_vec(),
        Json::Object(_) => b64decode(value.get("b64").and_then(Json::as_str).unwrap()),
        other => panic!("not a byte string: {other:?}"),
    }
}

fn config_of(value: &Json) -> Config {
    // JSON is a YAML flow document; the loader reads it as PyYAML would.
    Config::parse("case", &json::to_string(value)).expect("case config loads")
}

fn domains_section(config: &Config) -> crate::config::Value {
    match config.get("domains") {
        Some(v) if crate::config::truthy(v) => v.clone(),
        _ => crate::config::Value::Mapping(crate::config::Mapping::new()),
    }
}

// ── the scripted environment ─────────────────────────────────

#[derive(Debug)]
struct Scripted {
    replies: Mutex<VecDeque<Json>>,
    seen: Mutex<Vec<WireRequest>>,
}

impl HttpTransport for Scripted {
    fn post(&self, request: &WireRequest, _timeout: Duration) -> Result<HttpReply, String> {
        lock(&self.seen).push(request.clone());
        let reply = lock(&self.replies)
            .pop_front()
            .expect("decider called more often than scripted");
        if let Some(Json::Str(e)) = reply.get("transport_error") {
            return Err(e.clone());
        }
        let Some(Json::Int(status)) = reply.get("status") else {
            panic!("reply status")
        };
        Ok(HttpReply {
            status: u16::try_from(*status).unwrap(),
            body: bytes_of(reply.get("body").unwrap()),
        })
    }
}

#[derive(Debug)]
struct TestEnv {
    now: DateTime,
    ids: AtomicU64,
    secrets: HashMap<String, String>,
    version: String,
    transport: Arc<Scripted>,
}

impl TestEnv {
    fn new(secrets: HashMap<String, String>, version: &str, replies: Vec<Json>) -> Arc<Self> {
        Arc::new(Self {
            now: DateTime::from_isoformat("2026-03-14T15:09:26.535897+00:00").unwrap(),
            ids: AtomicU64::new(0),
            secrets,
            version: version.to_owned(),
            transport: Arc::new(Scripted {
                replies: Mutex::new(replies.into()),
                seen: Mutex::new(Vec::new()),
            }),
        })
    }
}

impl PolicyEnv for TestEnv {
    fn now_utc(&self) -> DateTime {
        self.now
    }
    fn monotonic(&self) -> f64 {
        // Frozen: a bucket never refills within a case.
        1000.0
    }
    fn request_id(&self) -> String {
        format!("req_{:024x}", self.ids.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn read_secret(&self, name: &str) -> String {
        self.secrets.get(name).cloned().unwrap_or_default()
    }
    fn version_env(&self) -> String {
        self.version.clone()
    }
    fn transport(&self) -> Arc<dyn HttpTransport> {
        self.transport.clone()
    }
}

/// A fresh, removed-on-drop temp dir.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "agentcage-egress-policy-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn set_mtime(path: &Path, secs: u64) {
    let file = std::fs::File::options().write(true).open(path).unwrap();
    file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
        .unwrap();
}

// ── the case runner ──────────────────────────────────────────

fn overlay_after(path: &Path) -> Json {
    let Ok(bytes) = std::fs::read(path) else {
        return Json::Null;
    };
    let parsed = String::from_utf8(bytes.clone())
        .ok()
        .and_then(|t| agentcage_core::yaml::load(&t).ok());
    match parsed {
        Some(v) => object([("parsed", yaml_to_json(&v))]),
        None => object([(
            "raw_b64",
            Json::string(agentcage_core::quadlets::b64_bytes(&bytes)),
        )]),
    }
}

fn run_step(
    api: &PolicyApi,
    dom: &Arc<DomainInspector>,
    paths: &PolicyPaths,
    mtime: &mut u64,
    step: &Json,
) -> Json {
    match step.get("op").and_then(Json::as_str).unwrap() {
        "request" => {
            let body = bytes_of(step.get("body").unwrap());
            let r = api.handle(&ControlRequest {
                method: step.get("method").and_then(Json::as_str).unwrap(),
                path: step.get("path").and_then(Json::as_str).unwrap(),
                body: &body,
                headers: &[],
            });
            object([
                ("status", Json::Int(i64::from(r.status))),
                ("body", Json::Str(String::from_utf8(r.body).unwrap())),
                ("audit", Json::Array(r.audit)),
            ])
        }
        "sweep" => object([("audit", Json::Array(api.sweeper_tick()))]),
        "host_write" => {
            std::fs::write(&paths.grants_file, bytes_of(step.get("overlay").unwrap())).unwrap();
            *mtime += 10;
            set_mtime(&paths.grants_file, *mtime);
            Json::Object(Vec::new())
        }
        "reconfigure" => {
            let cfg = config_of(step.get("config").unwrap());
            dom.configure(&domains_section(&cfg)).unwrap();
            match api.reconfigure(&cfg, dom.clone()) {
                Ok(()) => object([("ok", Json::Bool(true))]),
                Err(_) => object([("raises", Json::Bool(true))]),
            }
        }
        "control_host" => {
            let sni = step.get("sni").and_then(Json::as_str);
            let host = step.get("host_header").and_then(Json::as_str);
            object([("is_control", Json::Bool(api.is_control_host(sni, host)))])
        }
        other => panic!("unknown op {other}"),
    }
}

fn run(case: &Json) -> Json {
    let tmp = TempDir::new("case");
    let grants = tmp.0.join("grants");
    std::fs::create_dir_all(&grants).unwrap();
    let paths = PolicyPaths::new(&grants, tmp.0.join("dns").join("granted"));
    let mtime = 1_700_000_000;
    if let Some(overlay) = case.get("overlay").filter(|v| **v != Json::Null) {
        std::fs::write(&paths.grants_file, bytes_of(overlay)).unwrap();
        set_mtime(&paths.grants_file, mtime);
    }
    let secrets = match case.get("secrets") {
        Some(Json::Object(pairs)) => pairs
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
            .collect(),
        _ => HashMap::new(),
    };
    let version = case.get("env_version").and_then(Json::as_str).unwrap_or("");
    let replies = match case.get("replies") {
        Some(Json::Array(r)) => r.clone(),
        _ => Vec::new(),
    };
    let env = TestEnv::new(secrets, version, replies);

    let config = config_of(case.get("config").unwrap());
    let dom = Arc::new(DomainInspector::from_config(&domains_section(&config)).unwrap());
    let Ok(api) = PolicyApi::new(&config, dom.clone(), paths.clone(), env.clone()) else {
        return object([("init_raises", Json::string("ValueError"))]);
    };

    let Some(Json::Array(script)) = case.get("steps") else {
        panic!("steps")
    };
    let mut mtime = mtime;
    let steps: Vec<Json> = script
        .iter()
        .map(|step| run_step(&api, &dom, &paths, &mut mtime, step))
        .collect();
    let llm_requests = lock(&env.transport.seen)
        .iter()
        .map(|r| {
            object([
                ("url", Json::string(&r.url)),
                (
                    "headers",
                    Json::Array(
                        r.headers
                            .iter()
                            .map(|(k, v)| {
                                Json::Array(vec![
                                    Json::string(k.to_ascii_lowercase()),
                                    Json::string(v),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    "body",
                    Json::Str(String::from_utf8(r.body.clone()).unwrap()),
                ),
            ])
        })
        .collect();
    object([
        ("steps", Json::Array(steps)),
        ("overlay", overlay_after(&paths.grants_file)),
        (
            "dns",
            std::fs::read_to_string(&paths.dns_publish).map_or(Json::Null, Json::Str),
        ),
        ("reload_flag", Json::Bool(paths.dns_reload.exists())),
        ("llm_requests", Json::Array(llm_requests)),
    ])
}

/// The recorded expectation, with the deliberate deviations applied and
/// header names lowercased (urllib capitalises them; HTTP does not care).
fn expected_for(case: &Json) -> Json {
    let mut expected = case.get("expected").unwrap().clone();
    if let Some(Json::Array(reqs)) = expected.get("llm_requests").cloned() {
        let lowered = reqs
            .into_iter()
            .map(|mut r| {
                if let Some(Json::Array(hs)) = r.get("headers").cloned() {
                    let hs = hs
                        .into_iter()
                        .map(|h| match h {
                            Json::Array(kv) => Json::Array(vec![
                                Json::string(kv[0].as_str().unwrap().to_ascii_lowercase()),
                                kv[1].clone(),
                            ]),
                            other => other,
                        })
                        .collect();
                    r.set("headers", Json::Array(hs));
                }
                r
            })
            .collect();
        expected.set("llm_requests", Json::Array(lowered));
    }
    // Plan fix: the caged agent never sees the provider's error body.
    // The audit record (operator-facing) keeps it.
    if case.get("deviation").and_then(Json::as_str) == Some("provider-body")
        && let Some(Json::Array(steps)) = expected.get("steps").cloned()
    {
        let steps = steps
            .into_iter()
            .map(|mut step| {
                if let Some(Json::Str(body)) = step.get("body") {
                    let mut b = json::parse(body).unwrap();
                    for key in ["reason", "suggestion"] {
                        if let Some(Json::Str(r)) = b.get(key) {
                            let cut = llm::agent_facing(r).to_owned();
                            b.set(key, Json::Str(cut));
                        }
                    }
                    step.set("body", Json::Str(json::to_string(&b)));
                }
                step
            })
            .collect();
        expected.set("steps", Json::Array(steps));
    }
    expected
}

fn bless_enabled() -> bool {
    std::env::var_os("AGENTCAGE_BLESS").is_some_and(|v| v == "1")
}

#[test]
fn every_recorded_case_is_reproduced() {
    let all = cases();
    assert!(all.len() >= 70, "only {} cases", all.len());
    let mut failures = Vec::new();
    let mut blessed = Vec::new();
    for case in &all {
        let id = case.get("id").and_then(Json::as_str).unwrap().to_owned();
        let got = run(case);
        let want = expected_for(case);
        if got != want {
            failures.push(format!(
                "{id}:\n  got  {}\n  want {}",
                json::to_string(&got),
                json::to_string(&want)
            ));
        }
        let mut case = case.clone();
        case.set("expected", got);
        blessed.push(case);
    }
    if bless_enabled() && !failures.is_empty() {
        // Re-record what the port does now. Only for a deliberate change;
        // the generator must be updated to match while it exists.
        let text = std::fs::read_to_string(corpus_path()).unwrap();
        let mut doc = json::parse(&text).unwrap();
        doc.set("cases", Json::Array(blessed));
        std::fs::write(
            corpus_path(),
            json::dumps(&doc, json::DumpOptions::indented()) + "\n",
        )
        .unwrap();
        return;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[test]
fn a_wrong_expectation_is_caught() {
    // Mutation sanity check: one changed byte in a recorded body fails.
    let case = cases()
        .into_iter()
        .find(|c| c.get("id").and_then(Json::as_str) == Some("grant-openrouter"))
        .unwrap();
    let got = run(&case);
    let mut want = expected_for(&case);
    let Some(Json::Array(mut steps)) = want.get("steps").cloned() else {
        panic!()
    };
    let body = steps[0]
        .get("body")
        .and_then(Json::as_str)
        .unwrap()
        .to_owned();
    steps[0].set(
        "body",
        Json::Str(body.replace("\"ttl_seconds\": 600", "\"ttl_seconds\": 601")),
    );
    want.set("steps", Json::Array(steps));
    assert_ne!(got, want);
}

// ── behaviour the corpus cannot show ─────────────────────────

fn simple_api(tag: &str, replies: Vec<Json>, rate: &str) -> (TempDir, PolicyApi, Arc<TestEnv>) {
    let tmp = TempDir::new(tag);
    let paths = PolicyPaths::new(tmp.0.join("grants"), tmp.0.join("dns/granted"));
    let env = TestEnv::new(
        HashMap::from([("K".to_owned(), "sk-test".to_owned())]),
        "0.0.0",
        replies,
    );
    let config = Config::parse(
        "t",
        &format!(
            "domains: {{allow: [a.com]}}\nagents:\n  decider: {{enable: true, provider: \
             openrouter, model: m, api_key: 'env:K', rate_limit: {rate}}}\n"
        ),
    )
    .unwrap();
    let dom = Arc::new(DomainInspector::from_config(&domains_section(&config)).unwrap());
    let api = PolicyApi::new(&config, dom, paths, env.clone()).unwrap();
    (tmp, api, env)
}

fn request(api: &PolicyApi, domain: &str) -> ControlResponse {
    let body = format!(r#"{{"domain": "{domain}", "reason": "needed"}}"#);
    api.handle(&ControlRequest {
        method: "POST",
        path: "/v1/allowlist/requests",
        body: body.as_bytes(),
        headers: &[],
    })
}

fn grant_reply() -> Json {
    object([
        ("status", Json::Int(200)),
        (
            "body",
            Json::string(
                r#"{"choices": [{"message": {"tool_calls": [{"function": {"name": "decide", "arguments": "{\"decision\": \"grant\", \"reason\": \"ok\"}"}}]}}]}"#,
            ),
        ),
    ])
}

#[test]
fn a_non_object_reply_is_a_deny_not_a_crash() {
    let reply = object([("status", Json::Int(200)), ("body", Json::string("[]"))]);
    let (_tmp, api, _env) = simple_api("nonobject", vec![reply], "{requests_per_second: 0}");
    let r = request(&api, "x.com");
    assert_eq!(r.status, 403);
    let body = json::parse(std::str::from_utf8(&r.body).unwrap()).unwrap();
    assert_eq!(
        body.get("reason").and_then(Json::as_str),
        Some("llm returned no usable decision")
    );
}

#[test]
fn max_grants_counts_decisions_in_flight() {
    // Fill to one below the cap, then hold a reservation as a concurrent
    // request past the gate would: the next request must 409, not
    // overshoot.
    let (_tmp, api, _env) = simple_api("reserve", vec![], "{requests_per_second: 0}");
    let dom = api.domain();
    for i in 0..MAX_GRANTS - 1 {
        dom.grant_at(&format!("g{i}.example.com"), "", "r", "t", "x");
    }
    let held = api.reserve_slot(&dom).expect("one slot left");
    let r = request(&api, "late.example.com");
    assert_eq!(r.status, 409);
    drop(held);
    assert!(api.reserve_slot(&dom).is_some(), "the slot is released");
}

#[test]
fn concurrent_requests_never_overshoot_max_grants() {
    let replies = vec![grant_reply(); 8];
    let (_tmp, api, _env) = simple_api("race", replies, "{requests_per_second: 0}");
    let dom = api.domain();
    for i in 0..MAX_GRANTS - 3 {
        dom.grant_at(&format!("g{i}.example.com"), "", "r", "t", "x");
    }
    let statuses: Vec<u16> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let api = &api;
                s.spawn(move || request(api, &format!("n{i}.example.com")).status)
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(
        dom.grant_count() <= MAX_GRANTS,
        "{} {statuses:?}",
        dom.grant_count()
    );
    assert_eq!(statuses.iter().filter(|s| **s == 200).count(), 3);
    assert_eq!(statuses.iter().filter(|s| **s == 409).count(), 5);
}

#[test]
fn a_collision_on_both_temp_names_still_publishes_dns() {
    let (tmp, api, _env) = simple_api("collide", vec![grant_reply()], "{requests_per_second: 0}");
    let grants = tmp.0.join("grants");
    std::fs::create_dir_all(&grants).unwrap();
    let pid = api.paths.pid;
    std::fs::write(grants.join(format!("grants.yaml.{pid}.tmp")), "A").unwrap();
    std::fs::write(grants.join(format!("grants.yaml.{pid}.1.tmp")), "B").unwrap();
    assert_eq!(request(&api, "x.com").status, 200);
    // Nothing unlinked, nothing written through, but DNS is enforcement
    // and follows the in-memory grant regardless.
    assert_eq!(
        std::fs::read_to_string(grants.join(format!("grants.yaml.{pid}.tmp"))).unwrap(),
        "A"
    );
    assert!(!api.paths.grants_file.exists());
    assert_eq!(
        std::fs::read_to_string(&api.paths.dns_publish).unwrap(),
        "x.com\n"
    );
}

#[test]
fn a_planted_symlink_is_not_written_through() {
    let (tmp, api, _env) = simple_api("symlink", vec![grant_reply()], "{requests_per_second: 0}");
    let grants = tmp.0.join("grants");
    std::fs::create_dir_all(&grants).unwrap();
    let victim = tmp.0.join("victim");
    std::fs::write(&victim, "PRECIOUS").unwrap();
    let pid = api.paths.pid;
    std::os::unix::fs::symlink(&victim, grants.join(format!("grants.yaml.{pid}.tmp"))).unwrap();
    assert_eq!(request(&api, "x.com").status, 200);
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "PRECIOUS");
    // The counter-suffixed name took the write.
    let overlay = std::fs::read_to_string(&api.paths.grants_file).unwrap();
    assert!(overlay.contains("domain: x.com"), "{overlay}");
    assert!(!grants.join(format!("grants.yaml.{pid}.1.tmp")).exists());
}

#[test]
fn the_overlay_round_trips_through_the_hosts_reader() {
    // The host's `cage grants` reads the file with `load_grants`; the
    // shared parser must see exactly what was granted.
    let (_tmp, api, _env) = simple_api("host", vec![grant_reply()], "{requests_per_second: 0}");
    assert_eq!(request(&api, "x.com").status, 200);
    let text = std::fs::read_to_string(&api.paths.grants_file).unwrap();
    let entries = crate::inspect::domain::parse_overlay(&text);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].get("domain"),
        Some(&crate::config::Value::from("x.com"))
    );
    assert_eq!(
        entries[0].get("expires_at"),
        Some(&crate::config::Value::from(""))
    );
}

#[test]
fn the_watcher_revocation_path() {
    let (_tmp, api, _env) = simple_api("revoke", vec![grant_reply()], "{requests_per_second: 0}");
    assert_eq!(request(&api, "x.com").status, 200);
    assert_eq!(api.revoke_live_grant("x.com"), Revocation::Revoked);
    assert_eq!(api.revoke_live_grant("x.com"), Revocation::NotGranted);
    assert_eq!(api.revoke_live_grant("a.com"), Revocation::NotGranted);
    assert_eq!(std::fs::read_to_string(&api.paths.dns_publish).unwrap(), "");
}

#[test]
fn the_real_env_makes_well_formed_ids() {
    let a = SystemEnv.request_id();
    let b = SystemEnv.request_id();
    assert_ne!(a, b);
    assert_eq!(a.len(), 4 + 24);
    assert!(a.starts_with("req_"));
    assert!(a[4..].bytes().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn decider_enabled_follows_the_addon_gate() {
    let c = |t: &str| Config::parse("t", t).unwrap();
    assert!(decider_enabled(&c("agents: {decider: {enable: true}}")));
    assert!(!decider_enabled(&c("agents: {decider: {enable: false}}")));
    assert!(!decider_enabled(&c("agents: {decider: [1]}")));
    assert!(!decider_enabled(&c("agents: []")));
    assert!(!decider_enabled(&c("{}")));
}

#[test]
fn the_host_and_the_egress_agree_on_the_overlay() {
    // The egress writes; the host reads it with its own reader, revokes
    // one entry and saves with its own writer; the egress picks the
    // revoke up on the next reconcile and narrows DNS.
    let tmp = TempDir::new("interop");
    let host = agentcage_state::Paths::under(&tmp.0);
    let paths = PolicyPaths::new(host.grants_dir("c"), tmp.0.join("dns/granted"));
    let env = TestEnv::new(
        HashMap::from([("K".to_owned(), "sk-test".to_owned())]),
        "0.0.0",
        vec![grant_reply(), grant_reply()],
    );
    let config = Config::parse(
        "t",
        "domains: {allow: [a.com]}\nagents: {decider: {enable: true, provider: openrouter, \
         model: m, api_key: 'env:K', rate_limit: {requests_per_second: 0}}}\n",
    )
    .unwrap();
    let dom = Arc::new(DomainInspector::from_config(&domains_section(&config)).unwrap());
    let api = PolicyApi::new(&config, dom.clone(), paths.clone(), env).unwrap();
    assert_eq!(request(&api, "x.com").status, 200);
    assert_eq!(request(&api, "y.com").status, 200);

    let mut entries = host.load_grants("c");
    let domains: Vec<_> = entries
        .iter()
        .map(|e| e.get("domain").cloned().unwrap())
        .collect();
    let v = crate::config::Value::from;
    assert_eq!(domains, [v("x.com"), v("y.com")]);
    entries.retain(|e| e.get("domain") != Some(&v("x.com")));
    host.save_grants("c", &entries).unwrap();
    // A distinct mtime even on a coarse-grained filesystem.
    set_mtime(&paths.grants_file, 1_800_000_000);

    assert!(api.maybe_reload_overlay());
    assert!(!dom.is_granted("x.com"));
    assert!(dom.is_granted("y.com"));
    assert_eq!(
        std::fs::read_to_string(&paths.dns_publish).unwrap(),
        "y.com\n"
    );
}
