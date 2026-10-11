//! The shared engine: the current config (swapped atomically on reload,
//! with the last good config kept when a reload fails), the inspector
//! chain, the injector, and the per-host state every flow consults.
//!
//! One [`Engine`] per process. The request pipeline ([`crate::flow`])
//! reads [`Engine::live`] once per request, so a flow finishes on the
//! config it started with while a reload swaps in the next one.
//!
//! # Reload (plan D1, §4.2)
//!
//! The config file's mtime is the trigger, checked by a 1 s timer and
//! at the start of every request ([`Engine::reload_if_changed`]). A new
//! version is applied only when everything that can refuse it builds:
//! the YAML parses to a mapping, the inspector chain builds and the rate
//! limit parses. Otherwise the last good config stays live and one
//! `config_reload_failed` record is written per file version (a YAML
//! error is retried on every check, since a read can catch a write in
//! progress; a version that parsed but was refused is not retried — the
//! next edit is). A config that fails at boot leaves a chain that refuses
//! every request ([`Chain::refuse_all`]) until a good version lands.
//!
//! Applying follows the replaced implementation's order: inspector chain
//! (the domain inspector reconfigured in place), injector, rate limit,
//! logging, passthrough, relays (synced in order by one worker task),
//! capture, Policy API (reconfigured in
//! place while enabled, so its token bucket survives), the body cap and
//! budget (`egress:`, see [`crate::limits`]), watcher.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime};

use agentcage_core::config::egress::EgressConfig;
use agentcage_core::har::datetime::DateTime;
use arc_swap::ArcSwap;
use indexmap::IndexMap;

use crate::audit::{self, AuditSink as _, AuditWriter};
use crate::capture::Capture;
use crate::config::{self, Config};
use crate::inject::Injector;
use crate::inspect::chain::{Chain, PluginLoader, build_chain};
use crate::inspect::domain::DomainInspector;
use crate::limits::TransportLink;
use crate::llm::{LlmClient, ToolCaller, UreqTransport};
use crate::plugin::WasmPluginLoader;
use crate::policy::{PolicyApi, PolicyPaths, Revocation, SystemEnv, decider_enabled};
use crate::proxy::PassthroughMatcher;
use crate::relays::RelaySettings;
use crate::relays::manager::RelayManager;
use crate::watcher::{
    AgentSpec, CallerFactory, GrantStore, RuntimeRefs, WatcherDeps, WatcherManager, WatcherPaths,
};

/// How often the config file's mtime is polled.
pub const CONFIG_POLL: Duration = Duration::from_secs(1);

/// The most hosts with a rate-limit bucket; the least recently used one
/// is evicted past this.
pub const RATE_MAX_HOSTS: usize = 4096;

/// The most hosts remembered as poisoned (caught resolving to a
/// non-global address); the oldest is forgotten past this.
pub const POISONED_MAX: usize = 4096;

/// The config-derived state a request reads, swapped whole on reload.
#[derive(Debug)]
pub struct Live {
    /// The config document.
    pub cfg: Config,
    /// The inspector chain.
    pub chain: Chain,
    /// Whether plain allowed requests reach the durable audit sinks.
    pub log_allowed: bool,
    /// `rate_limit.requests_per_second` (0 disables the limiter).
    pub rate: f64,
    /// `rate_limit.burst`.
    pub burst: f64,
    /// `domains.passthrough`.
    pub passthrough: PassthroughMatcher,
    /// `egress:` (the body cap and budget).
    pub limits: EgressConfig,
}

/// A job for the relay worker, which owns the [`RelayManager`] and
/// applies jobs in order (a reload's relay sync never overtakes the one
/// before it).
enum RelayJob {
    Sync(Config, RelaySettings),
    Shutdown(tokio::sync::oneshot::Sender<()>),
}

/// What the engine is built from.
pub struct EngineOptions {
    /// The config file; `None` runs with an empty config (smoke test).
    pub config_path: Option<PathBuf>,
    /// The audit funnel.
    pub audit: Arc<AuditWriter>,
    /// The capture handle.
    pub capture: Arc<Capture>,
    /// Custom inspector loader.
    pub plugins: Arc<dyn PluginLoader + Send + Sync>,
    /// Policy API file locations.
    pub policy_paths: PolicyPaths,
    /// Watcher file locations.
    pub watcher_paths: WatcherPaths,
}

impl std::fmt::Debug for EngineOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineOptions")
            .field("config_path", &self.config_path)
            .finish_non_exhaustive()
    }
}

impl EngineOptions {
    /// Production options from the environment (`AGENTCAGE_AUDIT_LOG`,
    /// `AGENTCAGE_CAPTURE`, `AGENTCAGE_GRANTS_DIR`, `AGENTCAGE_DNS_PUBLISH`)
    /// with custom inspectors loaded from `AGENTCAGE_INSPECTOR_DIRS`.
    #[must_use]
    pub fn from_env(config_path: Option<PathBuf>) -> Self {
        Self {
            config_path,
            audit: Arc::new(AuditWriter::from_env()),
            capture: Arc::new(Capture::from_env()),
            plugins: Arc::new(WasmPluginLoader::from_env()),
            policy_paths: PolicyPaths::from_env(),
            watcher_paths: WatcherPaths::from_env(),
        }
    }
}

#[derive(Debug, Default)]
struct ReloadState {
    /// The mtime of the version applied (or refused after parsing).
    applied: Option<SystemTime>,
    /// The mtime last reported as failing, so a failure is audited once.
    reported: Option<SystemTime>,
}

#[derive(Debug, Default)]
struct RateLimiter {
    /// `host → (tokens, last refill)`, least recently used first.
    buckets: IndexMap<String, (f64, Instant)>,
}

impl RateLimiter {
    /// The replaced implementation's token bucket, per host.
    fn check(&mut self, host: &str, rate: f64, burst: f64, now: Instant) -> bool {
        if rate == 0.0 {
            return true;
        }
        let bucket = if let Some(index) = self.buckets.get_index_of(host) {
            let last = self.buckets.len() - 1;
            self.buckets.move_index(index, last);
            &mut self.buckets[last]
        } else {
            self.buckets.insert(host.to_owned(), (burst, now));
            while self.buckets.len() > RATE_MAX_HOSTS {
                self.buckets.shift_remove_index(0);
            }
            let last = self.buckets.len() - 1;
            &mut self.buckets[last]
        };
        let elapsed = now.saturating_duration_since(bucket.1).as_secs_f64();
        bucket.1 = now;
        bucket.0 = burst.min(bucket.0 + elapsed * rate);
        if bucket.0 >= 1.0 {
            bucket.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The process-wide egress state.
pub struct Engine {
    config_path: Option<PathBuf>,
    live: ArcSwap<Live>,
    /// Bumped every time `live` is replaced (see [`Engine::config_epoch`]).
    epoch: AtomicU64,
    reload: Mutex<ReloadState>,
    /// The audit funnel (stderr, `audit.jsonl`, watcher ring).
    pub audit: Arc<AuditWriter>,
    /// Secret injection and redaction.
    pub injector: Arc<Injector>,
    /// Capture.
    pub capture: Arc<Capture>,
    /// The long-lived domain inspector (it carries the runtime grants).
    pub domain: Arc<DomainInspector>,
    policy: RwLock<Option<Arc<PolicyApi>>>,
    policy_paths: PolicyPaths,
    watcher: Mutex<WatcherManager>,
    watcher_paths: WatcherPaths,
    plugins: Arc<dyn PluginLoader + Send + Sync>,
    relay_jobs: tokio::sync::mpsc::UnboundedSender<RelayJob>,
    relay_worker: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<RelayJob>>>,
    rate: Mutex<RateLimiter>,
    poisoned: Mutex<IndexMap<String, ()>>,
    /// The bound proxy's settings and budget, once attached
    /// ([`Engine::attach_transport`]).
    transport: OnceLock<TransportLink>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("config_path", &self.config_path)
            .finish_non_exhaustive()
    }
}

/// What a config version builds into before anything live is touched.
struct Prepared {
    cfg: Config,
    chain: crate::inspect::chain::PendingChain,
    rate: f64,
    burst: f64,
    limits: EgressConfig,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `float(rl.get("requests_per_second", 10))`, `int(rl.get("burst", 50))`.
pub(crate) fn parse_rate(cfg: &Config) -> Result<(f64, f64), String> {
    let rl = match cfg.get("rate_limit") {
        None => return Ok((10.0, 50.0)),
        Some(v) if !config::truthy(v) => return Ok((10.0, 50.0)),
        Some(config::Value::Mapping(m)) => m,
        Some(_) => return Err("rate_limit must be a mapping".to_owned()),
    };
    let rate = match rl.get("requests_per_second") {
        None => 10.0,
        v => config::as_f64(v)
            .ok_or_else(|| "rate_limit.requests_per_second is not a number".to_owned())?,
    };
    let burst = match rl.get("burst") {
        None => 50,
        v => config::as_i64(v).ok_or_else(|| "rate_limit.burst is not an integer".to_owned())?,
    };
    #[allow(clippy::cast_precision_loss)]
    Ok((rate, burst as f64))
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// The watcher's revocations go through the Policy API, as the removal
/// endpoint's do.
#[derive(Debug)]
struct PolicyGrants(Arc<PolicyApi>);

impl GrantStore for PolicyGrants {
    fn revoke_live_grant(&self, domain: &str) -> bool {
        self.0.revoke_live_grant(domain) == Revocation::Revoked
    }
}

/// The watcher's LLM callers, over the egress's wire client.
#[derive(Debug)]
struct LlmCallers;

impl CallerFactory for LlmCallers {
    fn caller(&self, agent: &AgentSpec) -> Arc<dyn ToolCaller> {
        Arc::new(LlmClient::new(
            agent.provider.clone(),
            agent.model.clone(),
            agent.api_key.clone(),
            agent.base_url.clone(),
            Duration::from_secs_f64(agent.timeout_seconds.max(0.0)),
            Arc::new(UreqTransport),
        ))
    }
}

impl Engine {
    /// Load the config and build everything from it. A config that fails
    /// leaves the engine refusing every request (and audited), never
    /// failing open.
    ///
    /// # Panics
    ///
    /// Never: the empty config always builds.
    #[must_use]
    pub fn boot(options: EngineOptions) -> Arc<Self> {
        let domain = Arc::new(DomainInspector::new());
        let injector = Arc::new(Injector::new());
        options
            .audit
            .set_redactor(Arc::clone(&injector) as Arc<dyn audit::Redactor>);
        let refuse = |reason: &str| Live {
            cfg: Config::default(),
            chain: Chain::refuse_all(Arc::clone(&domain), reason),
            log_allowed: false,
            rate: 10.0,
            burst: 50.0,
            passthrough: PassthroughMatcher::default(),
            limits: EgressConfig::default(),
        };
        let (relay_jobs, relay_rx) = tokio::sync::mpsc::unbounded_channel();
        let engine = Arc::new(Self {
            config_path: options.config_path,
            live: ArcSwap::from_pointee(refuse("no config loaded yet")),
            epoch: AtomicU64::new(0),
            reload: Mutex::new(ReloadState::default()),
            audit: options.audit,
            injector,
            capture: options.capture,
            domain: Arc::clone(&domain),
            policy: RwLock::new(None),
            policy_paths: options.policy_paths,
            watcher: Mutex::new(WatcherManager::default()),
            watcher_paths: options.watcher_paths,
            plugins: options.plugins,
            relay_jobs,
            relay_worker: Mutex::new(Some(relay_rx)),
            rate: Mutex::new(RateLimiter::default()),
            poisoned: Mutex::new(IndexMap::new()),
            transport: OnceLock::new(),
        });
        match engine.config_path.clone() {
            None => {
                let prepared = engine
                    .prepare(Config::default())
                    .expect("the empty config always builds");
                engine.apply(prepared);
            }
            Some(path) => {
                let stamp = mtime(&path);
                match Config::load(&path)
                    .map_err(|e| e.to_string())
                    .and_then(|cfg| engine.prepare(cfg))
                {
                    Ok(prepared) => {
                        lock(&engine.reload).applied = stamp;
                        engine.apply(prepared);
                    }
                    Err(e) => {
                        engine.live.store(Arc::new(refuse(&e)));
                        engine.epoch.fetch_add(1, Ordering::Release);
                        let mut state = lock(&engine.reload);
                        state.reported = stamp;
                        drop(state);
                        engine.audit.emit(audit::config_reload_failed(
                            DateTime::now_utc(),
                            &path.display().to_string(),
                            &e,
                        ));
                    }
                }
            }
        }
        let live = engine.live();
        eprintln!(
            "agentcage loaded: inspectors={:?}, injection_rules={}",
            live.chain.names(),
            engine.injector.rules().len()
        );
        engine
    }

    /// The live config-derived state.
    #[must_use]
    pub fn live(&self) -> Arc<Live> {
        self.live.load_full()
    }

    /// Which config the live state came from: a number bumped on every
    /// (re)load, so the transport can drop pooled upstream connections
    /// opened under an earlier config.
    #[must_use]
    pub fn config_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// The Policy API, while `agents.decider` is enabled.
    #[must_use]
    pub fn policy(&self) -> Option<Arc<PolicyApi>> {
        self.policy
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn prepare(&self, cfg: Config) -> Result<Prepared, String> {
        // The host's own parser: a section `cage create` accepted is
        // never refused here, and one it would refuse is refused here.
        let limits = EgressConfig::from_yaml(cfg.get("egress"))?;
        let chain = build_chain(&cfg, &self.domain, &*self.plugins)?;
        let (rate, burst) = parse_rate(&cfg)?;
        Ok(Prepared {
            cfg,
            chain,
            rate,
            burst,
            limits,
        })
    }

    /// Hand the engine the bound proxy's settings and body budget, so
    /// `egress.max_body_bytes` and `egress.body_budget_bytes` apply now
    /// and on every reload. Once per process; a second call is ignored.
    pub fn attach_transport(&self, link: TransportLink) {
        if self.transport.set(link).is_ok() {
            self.apply_limits(&self.live().limits);
        }
    }

    fn apply_limits(&self, limits: &EgressConfig) {
        if let Some(link) = self.transport.get() {
            for note in link.apply(limits) {
                eprintln!("agentcage: {note}");
            }
        }
    }

    /// Whether the config file's mtime differs from the applied version
    /// (one `stat`; cheap enough for every request).
    #[must_use]
    pub fn config_changed(&self) -> bool {
        let Some(path) = &self.config_path else {
            return false;
        };
        let now = mtime(path);
        now.is_some() && now != lock(&self.reload).applied
    }

    /// Apply a config edit if there is one. Single-flight: a check that
    /// finds another one running returns at once. Blocking (file reads,
    /// secret lookups); async callers run it on a blocking worker.
    pub fn reload_if_changed(&self) {
        let Some(path) = self.config_path.clone() else {
            return;
        };
        let Ok(mut state) = self.reload.try_lock() else {
            return;
        };
        let Some(stamp) = mtime(&path) else {
            return;
        };
        if Some(stamp) == state.applied {
            return;
        }
        let report = |state: &mut ReloadState, error: &str| {
            if state.reported != Some(stamp) {
                state.reported = Some(stamp);
                self.audit.emit(audit::config_reload_failed(
                    DateTime::now_utc(),
                    &path.display().to_string(),
                    error,
                ));
            }
        };
        let cfg = match Config::load(&path) {
            Ok(cfg) => cfg,
            Err(e) => {
                // Retried on the next check: the read may have caught a
                // write in progress.
                report(&mut state, &e.to_string());
                return;
            }
        };
        // Recorded before applying: a refused version is not retried
        // every second; the next edit is.
        state.applied = Some(stamp);
        match self.prepare(cfg) {
            Ok(prepared) => {
                drop(state);
                self.apply(prepared);
                let live = self.live();
                eprintln!(
                    "agentcage: config reloaded, inspectors={:?}",
                    live.chain.names()
                );
            }
            Err(e) => report(&mut state, &e),
        }
    }

    /// Commit a prepared config to every live component.
    fn apply(&self, prepared: Prepared) {
        let Prepared {
            cfg,
            chain,
            rate,
            burst,
            limits,
        } = prepared;
        let chain = chain.commit();
        for warning in chain.warnings() {
            eprintln!("agentcage: {warning}");
        }
        self.injector.configure(cfg.get("secret_injection"));
        let log_allowed = audit::log_allowed(&cfg);
        let passthrough = PassthroughMatcher::new(&config::str_list(config::mget(
            cfg.section("domains"),
            "passthrough",
        )));
        // Relays start once the runtime is serving (`start`); jobs queue
        // until then and are applied in order.
        let _ = self.relay_jobs.send(RelayJob::Sync(
            cfg.clone(),
            RelaySettings {
                log_allowed,
                inspectors: chain.relay_inspectors().into(),
            },
        ));
        let _ = self.capture.reconfigure(&cfg);
        self.apply_policy(&cfg);
        self.apply_limits(&limits);
        self.live.store(Arc::new(Live {
            cfg,
            chain,
            log_allowed,
            rate,
            burst,
            passthrough,
            limits,
        }));
        self.epoch.fetch_add(1, Ordering::Release);
        self.apply_watcher();
    }

    /// Build, reconfigure in place, or drop the Policy API.
    fn apply_policy(&self, cfg: &Config) {
        let mut slot = self.policy.write().unwrap_or_else(PoisonError::into_inner);
        if !decider_enabled(cfg) {
            *slot = None;
            return;
        }
        if let Some(api) = slot.as_ref() {
            if let Err(e) = api.reconfigure(cfg, Arc::clone(&self.domain)) {
                eprintln!("agentcage: agents.decider reconfigure failed: {e}");
                *slot = None;
            }
            return;
        }
        match PolicyApi::new(
            cfg,
            Arc::clone(&self.domain),
            self.policy_paths.clone(),
            Arc::new(SystemEnv),
        ) {
            Ok(api) => {
                eprintln!("agentcage: agents.decider enabled (host={})", api.host());
                *slot = Some(Arc::new(api));
            }
            Err(e) => eprintln!("agentcage: agents.decider init failed: {e}"),
        }
    }

    fn apply_watcher(&self) {
        let live = self.live();
        let ring = self.audit.enable_ring();
        let deps = WatcherDeps {
            ring,
            audit: Arc::clone(&self.audit) as Arc<dyn audit::AuditSink>,
            llm: Arc::new(LlmCallers),
            paths: self.watcher_paths.clone(),
        };
        let refs = RuntimeRefs {
            domains: Some(Arc::clone(&self.domain)),
            grants: self
                .policy()
                .map(|api| Arc::new(PolicyGrants(api)) as Arc<dyn GrantStore>),
        };
        let mut manager = lock(&self.watcher);
        manager.apply(&live.cfg, &deps, refs);
        if !manager.is_enabled() {
            self.audit.disable_ring();
        }
    }

    /// Start the background loops: the watcher thread now; the relay
    /// worker, the config poll and the grant sweeper as runtime tasks.
    pub fn start(self: &Arc<Self>) {
        lock(&self.watcher).start();
        if let Some(mut jobs) = lock(&self.relay_worker).take() {
            let audit = Arc::clone(&self.audit) as Arc<dyn audit::AuditSink>;
            tokio::spawn(async move {
                let mut manager = RelayManager::new(audit);
                while let Some(job) = jobs.recv().await {
                    match job {
                        RelayJob::Sync(cfg, settings) => manager.sync(&cfg, &settings).await,
                        RelayJob::Shutdown(done) => {
                            manager.shutdown().await;
                            let _ = done.send(());
                            return;
                        }
                    }
                }
            });
        }
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(CONFIG_POLL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if engine.config_changed() {
                    let e = Arc::clone(&engine);
                    let _ = tokio::task::spawn_blocking(move || e.reload_if_changed()).await;
                }
            }
        });
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(crate::policy::SWEEP_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(api) = engine.policy() else {
                    continue;
                };
                let records = tokio::task::spawn_blocking(move || api.sweeper_tick()).await;
                for record in records.unwrap_or_default() {
                    engine.audit.emit(record);
                }
            }
        });
    }

    /// Stop the watcher and drain the relays (an IMAP client in IDLE gets
    /// its `BYE`), for an orderly exit.
    pub async fn shutdown(&self) {
        lock(&self.watcher).shutdown();
        let (done, wait) = tokio::sync::oneshot::channel();
        if self.relay_jobs.send(RelayJob::Shutdown(done)).is_ok() {
            let _ = tokio::time::timeout(Duration::from_secs(10), wait).await;
        }
    }

    /// The per-host token bucket: true when `host` may send now.
    pub fn rate_allows(&self, host: &str, live: &Live) -> bool {
        lock(&self.rate).check(host, live.rate, live.burst, Instant::now())
    }

    /// Whether `host` (lowercased, trailing dot stripped) was caught
    /// resolving to a non-global address.
    #[must_use]
    pub fn is_poisoned(&self, host: &str) -> bool {
        lock(&self.poisoned).contains_key(host)
    }

    /// Remember `host` as poisoned.
    pub fn poison(&self, host: &str) {
        let mut set = lock(&self.poisoned);
        set.shift_remove(host);
        set.insert(host.to_owned(), ());
        while set.len() > POISONED_MAX {
            set.shift_remove_index(0);
        }
    }

    /// The set of poisoned hosts (tests).
    #[must_use]
    pub fn poisoned(&self) -> HashSet<String> {
        lock(&self.poisoned).keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::chain::NoPlugins;

    fn tmp(tag: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("agentcage-engine-{tag}-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            lock(&self.0).extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn engine(dir: &Path, yaml: Option<&str>) -> (Arc<Engine>, Buf) {
        let path = dir.join("config.yaml");
        if let Some(yaml) = yaml {
            std::fs::write(&path, yaml).unwrap();
        }
        let out = Buf::default();
        let audit = Arc::new(AuditWriter::new(None).with_stderr(Box::new(out.clone())));
        let options = EngineOptions {
            config_path: Some(path),
            audit,
            capture: Arc::new(Capture::new(None)),
            plugins: Arc::new(NoPlugins),
            policy_paths: PolicyPaths::new(dir.join("grants"), dir.join("dns/granted")),
            watcher_paths: WatcherPaths {
                dir: dir.join("watcher"),
                capture: None,
            },
        };
        (Engine::boot(options), out)
    }

    fn bump(path: &Path, yaml: &str) {
        std::fs::write(path, yaml).unwrap();
        let later = SystemTime::now() + Duration::from_secs(5);
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_modified(later).unwrap();
    }

    #[test]
    fn a_bad_boot_config_refuses_everything_and_a_good_edit_recovers() {
        let dir = tmp("boot");
        let (engine, out) = engine(&dir, Some("rate_limit:\n  requests_per_second: abc\n"));
        assert_eq!(engine.live().chain.names(), ["chain"]);
        let log = String::from_utf8(lock(&out.0).clone()).unwrap();
        assert!(log.contains("\"kind\": \"config_reload_failed\""), "{log}");
        bump(
            &dir.join("config.yaml"),
            "domains:\n  allow: [example.com]\n",
        );
        assert!(engine.config_changed());
        engine.reload_if_changed();
        assert_eq!(engine.live().chain.names()[0], "domain");
    }

    #[test]
    fn a_bad_reload_keeps_the_last_good_config_and_is_audited_once() {
        let dir = tmp("reload");
        let (engine, out) = engine(&dir, Some("rate_limit:\n  requests_per_second: 3\n"));
        assert!((engine.live().rate - 3.0).abs() < f64::EPSILON);
        bump(&dir.join("config.yaml"), "inspectors: 7\n");
        engine.reload_if_changed();
        engine.reload_if_changed();
        assert!((engine.live().rate - 3.0).abs() < f64::EPSILON);
        assert_eq!(engine.live().chain.names()[0], "domain");
        let log = String::from_utf8(lock(&out.0).clone()).unwrap();
        assert_eq!(log.matches("config_reload_failed").count(), 1, "{log}");
        assert!(!engine.config_changed(), "a refused version is not retried");
    }

    #[test]
    fn a_refused_egress_section_keeps_the_last_good_limits() {
        let dir = tmp("limits");
        let (engine, out) = engine(&dir, Some("egress:\n  max_body_bytes: 2097152\n"));
        assert_eq!(engine.live().limits.max_body_bytes, 2 << 20);
        // The budget below the cap: refused, as `cage create` refuses it.
        bump(
            &dir.join("config.yaml"),
            "egress:\n  max_body_bytes: 4194304\n  body_budget_bytes: 2097152\n",
        );
        engine.reload_if_changed();
        assert_eq!(engine.live().limits.max_body_bytes, 2 << 20);
        let log = String::from_utf8(lock(&out.0).clone()).unwrap();
        assert!(
            log.contains("egress.body_budget_bytes (2097152) must be at least"),
            "{log}"
        );
    }

    #[test]
    fn the_rate_limiter_is_a_per_host_token_bucket_bounded_in_hosts() {
        let mut rl = RateLimiter::default();
        let t = Instant::now();
        assert!(rl.check("a", 1.0, 2.0, t));
        assert!(rl.check("a", 1.0, 2.0, t));
        assert!(!rl.check("a", 1.0, 2.0, t));
        assert!(rl.check("a", 1.0, 2.0, t + Duration::from_secs(1)));
        assert!(!rl.check("b", 5.0, 0.0, t), "burst 0 always refuses");
        assert!(rl.check("c", 0.0, 0.0, t), "rate 0 disables");
        for i in 0..(RATE_MAX_HOSTS + 10) {
            rl.check(&format!("h{i}"), 1.0, 1.0, t);
        }
        assert!(rl.buckets.len() <= RATE_MAX_HOSTS);
    }

    #[test]
    fn rate_limit_parsing_follows_float_and_int() {
        let cfg = |y: &str| Config::parse("t", y).unwrap();
        assert_eq!(parse_rate(&cfg("")).unwrap(), (10.0, 50.0));
        assert_eq!(
            parse_rate(&cfg(
                "rate_limit: {requests_per_second: '2.5', burst: 7.9}\n"
            ))
            .unwrap(),
            (2.5, 7.0)
        );
        assert!(parse_rate(&cfg("rate_limit: {burst: '5.0'}\n")).is_err());
        assert!(parse_rate(&cfg("rate_limit: {requests_per_second: null}\n")).is_err());
        assert!(parse_rate(&cfg("rate_limit: [1]\n")).is_err());
    }
}
