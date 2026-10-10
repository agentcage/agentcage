//! Custom inspectors as WebAssembly components (plan D2, §5.7).
//!
//! A custom inspector is a component implementing the
//! `agentcage:inspector@1.0.0` world (`rust/agentcage-inspector-sdk/wit/`),
//! listed in the config as
//!
//! ```yaml
//! inspectors:
//!   - name: header-policy
//!     path: header_policy.wasm
//!     config: {required_header: X-Trace-ID}
//! ```
//!
//! [`load`] turns one such entry into an [`Inspector`] the chain runs
//! like any built-in. What it guarantees:
//!
//! * **Confinement.** `path` must resolve, after following symlinks, to a
//!   regular `.wasm` file inside one of the plugin directories
//!   ([`DEFAULT_DIR`], or the colon-separated `AGENTCAGE_INSPECTOR_DIRS`).
//!   A relative path is looked up in each directory in turn.
//! * **No capabilities.** The component is linked against nothing but its
//!   own exports. Every import it declares (the WASI interfaces Rust's
//!   standard library pulls in for stdio, environment, clocks, random)
//!   is bound to a function that traps, so a plugin that tries to reach
//!   the filesystem, the network, the environment or a clock fails
//!   closed instead of getting an answer. It can instantiate; it can only
//!   compute over the context it is handed.
//! * **Budgets.** Every call (`configure` and each `inspect-*`) gets a
//!   fresh fuel allowance ([`Limits::fuel`]) and runs in a store whose
//!   linear memory may not grow past [`Limits::memory_bytes`].
//! * **Fail closed (D1).** A trap, an exhausted budget, a refused
//!   instantiation or a malformed verdict becomes a `block` verdict with
//!   the reason `inspector <name> failed: …`, and the instance is thrown
//!   away. Only `None` from a healthy call abstains.
//!
//! Compiled components are cached by the SHA-256 of their bytes, so a
//! reload that re-lists an unchanged plugin does not recompile it; every
//! [`load`] still creates fresh instances and calls `configure` on them,
//! so a changed `config:` takes effect.
//!
//! Instances are pooled per loaded plugin: a call checks one out (or
//! instantiates and configures a new one), uses it, and returns it.
//! Per-call instantiation would re-run `configure` on every exchange,
//! which for a plugin that compiles regexes in `configure` costs more
//! than the inspection itself; see the module tests for the measurement.

use std::collections::VecDeque;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use sha2::{Digest, Sha256};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, ResourceLimiter, Store, Trap};

use crate::inspect::{Action, Context, Direction, Inspector, Severity, Verdict};
use crate::json::{self, Json};

/// The generated host bindings for `wit/inspector.wit`.
mod wit {
    wasmtime::component::bindgen!({
        path: "../agentcage-inspector-sdk/wit",
        world: "inspector",
    });
}

use wit::agentcage::inspector::types as abi;

/// Where plugins live inside the egress container. The host mounts the
/// cage's `inspectors/` directory here read-only.
pub const DEFAULT_DIR: &str = "/etc/agentcage/inspectors";

/// The environment variable that replaces [`DEFAULT_DIR`] with a
/// colon-separated list of directories.
pub const DIRS_ENV: &str = "AGENTCAGE_INSPECTOR_DIRS";

/// Per-call resource limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Fuel per call. One unit is roughly one WebAssembly instruction.
    pub fuel: u64,
    /// The most linear memory one instance may hold, in bytes.
    pub memory_bytes: usize,
}

impl Limits {
    /// Fuel for roughly 50 ms of plugin CPU. Measured on an x86-64
    /// development VM (release build, Cranelift, fuel metering on): an
    /// empty loop burns about 25 units per nanosecond, the DLP example
    /// scanning a 1 MiB body about 20 (15 M units in 0.75 ms) -- most
    /// stack-machine operations compile to little or no machine code.
    /// Unlike wall time the budget is deterministic: a given plugin and
    /// input exhaust it, or not, on every machine.
    pub const DEFAULT_FUEL: u64 = 1_000_000_000;
    /// 64 MiB.
    pub const DEFAULT_MEMORY_BYTES: usize = 64 << 20;
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            fuel: Self::DEFAULT_FUEL,
            memory_bytes: Self::DEFAULT_MEMORY_BYTES,
        }
    }
}

/// Load the plugin at `path` as inspector `name`, configured with
/// `config_json` (a JSON object, `{}` for none), using the plugin
/// directories from the environment and the default [`Limits`].
///
/// This is what the chain builder calls for each `inspectors:` entry
/// that has a `path`.
///
/// # Errors
///
/// A one-line, operator-facing message: the path is outside the plugin
/// directories or not a `.wasm` file, the component does not compile or
/// does not implement `agentcage:inspector@1.0.0`, or its `configure`
/// refused the config (or trapped).
pub fn load(name: &str, path: &str, config_json: &str) -> Result<Arc<dyn Inspector>, String> {
    Loader::from_env().load(name, path, config_json)
}

/// Render an `inspectors[].config` value the way it is handed to a
/// plugin's `configure`: as `json.dumps` would render the parsed YAML.
/// A missing (`null`) config becomes `{}`.
#[must_use]
pub fn config_json(config: Option<&serde_norway::Value>) -> String {
    match config {
        None | Some(serde_norway::Value::Null) => "{}".to_owned(),
        Some(value) => json::to_string(&agentcage_core::config::json::from_yaml(value)),
    }
}

/// Resolves and loads plugins under a set of directories and limits.
#[derive(Clone, Debug)]
pub struct Loader {
    dirs: Vec<PathBuf>,
    limits: Limits,
}

impl Loader {
    /// A loader for `dirs` with `limits`.
    #[must_use]
    pub fn new(dirs: Vec<PathBuf>, limits: Limits) -> Self {
        Self { dirs, limits }
    }

    /// The directories from `AGENTCAGE_INSPECTOR_DIRS` (empty entries
    /// ignored), else [`DEFAULT_DIR`]; default limits.
    #[must_use]
    pub fn from_env() -> Self {
        let dirs: Vec<PathBuf> = std::env::var_os(DIRS_ENV)
            .map(|v| {
                std::env::split_paths(&v)
                    .filter(|p| !p.as_os_str().is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let dirs = if dirs.is_empty() {
            vec![PathBuf::from(DEFAULT_DIR)]
        } else {
            dirs
        };
        Self::new(dirs, Limits::default())
    }

    /// Resolve a config `path` to the file it names, confined to the
    /// plugin directories.
    ///
    /// # Errors
    ///
    /// Not a `.wasm` path, not found, not a regular file, or resolving
    /// (symlinks included) to somewhere outside every plugin directory.
    pub fn resolve(&self, path: &str) -> Result<PathBuf, String> {
        let wanted = Path::new(path);
        if wanted.extension().is_none_or(|e| e != "wasm") {
            return Err(format!(
                "custom inspector path {path:?} is not a .wasm component \
                 (Python inspectors are no longer supported; see \
                 docs/how-to/custom-inspectors.md)"
            ));
        }
        let roots: Vec<PathBuf> = self
            .dirs
            .iter()
            .filter_map(|d| std::fs::canonicalize(d).ok())
            .collect();
        let candidates: Vec<PathBuf> = if wanted.is_absolute() {
            vec![wanted.to_path_buf()]
        } else {
            self.dirs.iter().map(|d| d.join(wanted)).collect()
        };
        for candidate in &candidates {
            let Ok(real) = std::fs::canonicalize(candidate) else {
                continue;
            };
            // Prefix check on the canonical path: a symlink (or `..`) that
            // leads out of the directories is refused even though the name
            // it was reached by is inside one.
            if !roots.iter().any(|root| real.starts_with(root)) {
                return Err(format!(
                    "custom inspector path {path:?} (resolved: {:?}) is outside \
                     allowed directories: {:?}",
                    real.display().to_string(),
                    self.dir_list()
                ));
            }
            if !real.is_file() {
                return Err(format!(
                    "custom inspector path {path:?} is not a regular file"
                ));
            }
            return Ok(real);
        }
        Err(format!(
            "custom inspector path {path:?} not found in {:?}",
            self.dir_list()
        ))
    }

    fn dir_list(&self) -> Vec<String> {
        self.dirs.iter().map(|d| d.display().to_string()).collect()
    }

    /// Resolve, compile (or reuse), instantiate and configure one plugin.
    ///
    /// # Errors
    ///
    /// See [`load`].
    pub fn load(
        &self,
        name: &str,
        path: &str,
        config_json: &str,
    ) -> Result<Arc<dyn Inspector>, String> {
        let real = self.resolve(path)?;
        let bytes = std::fs::read(&real)
            .map_err(|e| format!("inspector {name}: cannot read {}: {e}", real.display()))?;
        let plugin = Plugin::new(name, &bytes, config_json, self.limits)?;
        Ok(Arc::new(plugin))
    }
}

/// The one engine every plugin compiles and runs on.
fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        // The egress runs under `prlimit --as=2G`. The default 4 GiB
        // virtual reservation (plus guard region) per linear memory would
        // not fit even once, so memories are mapped at their real size and
        // bounds-checked explicitly; growth may move them.
        config.memory_reservation(0);
        config.memory_guard_size(0);
        config.memory_reservation_for_growth(1 << 20);
        config.memory_may_move(true);
        // A plugin's backtrace is of no use to an operator reading an
        // audit line, and capturing it costs time on every trap.
        config.wasm_backtrace_max_frames(None);
        // Infallible with the options above; a failure here is a build
        // misconfiguration, caught by every test that loads a plugin.
        Engine::new(&config).expect("wasmtime engine configuration is valid")
    })
}

/// Compiled components by content hash, most recently used last. Bounded:
/// a long-lived egress that sees many plugin versions keeps only the
/// newest few.
fn compile(bytes: &[u8]) -> Result<Component, String> {
    const CAP: usize = 16;
    static CACHE: Mutex<VecDeque<([u8; 32], Component)>> = Mutex::new(VecDeque::new());
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    {
        let mut cache = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(i) = cache.iter().position(|(h, _)| *h == hash) {
            let entry = cache.remove(i).expect("index from position");
            let component = entry.1.clone();
            cache.push_back(entry);
            return Ok(component);
        }
    }
    // Compiled outside the lock: Cranelift takes a while on a big
    // component, and an unrelated load should not queue behind it.
    let component = Component::new(engine(), bytes).map_err(|e| one_line(&e))?;
    let mut cache = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    if !cache.iter().any(|(h, _)| *h == hash) {
        if cache.len() == CAP {
            cache.pop_front();
        }
        cache.push_back((hash, component.clone()));
    }
    Ok(component)
}

/// The imports a plugin gets: two harmless answers Rust's standard
/// library asks for on every target, and a trap for everything else.
///
/// * `wasi:cli/environment` answers with no variables, no arguments and
///   no working directory. The standard library reads it lazily (the
///   default panic hook checks `RUST_BACKTRACE`); an empty environment is
///   the same as no environment, without making every such read a trap.
/// * `wasi:random/insecure-seed` seeds `HashMap`'s hasher. Without it
///   any plugin that builds a `HashMap` (the `regex` crate does) cannot
///   even instantiate. The seed is not a capability: it says nothing
///   about the host.
///
/// Any 0.2.x of those two interfaces is served. Every other import is
/// bound to a function that traps when called, so a component instantiates whatever
/// its toolchain declared and fails closed only if it actually reaches
/// for the filesystem, the network, stdio, a clock or `exit`.
fn linker_for(component: &Component) -> wasmtime::Result<Linker<StoreState>> {
    let engine = engine();
    let mut linker = Linker::new(engine);
    // Bound under the exact names the component imports (`…@0.2.12`):
    // the trap stubs below are defined under those exact names too, and
    // an exact match would shadow a semver-compatible one.
    let imports: Vec<String> = component
        .component_type()
        .imports(engine)
        .map(|(name, _)| name.to_owned())
        .collect();
    for name in &imports {
        if name.starts_with("wasi:cli/environment@0.2.") {
            let mut root = linker.root();
            let mut env = root.instance(name)?;
            env.func_wrap("get-environment", |_, (): ()| {
                Ok((Vec::<(String, String)>::new(),))
            })?;
            env.func_wrap("get-arguments", |_, (): ()| Ok((Vec::<String>::new(),)))?;
            env.func_wrap("initial-cwd", |_, (): ()| Ok((None::<String>,)))?;
        } else if name.starts_with("wasi:random/insecure-seed@0.2.") {
            let mut root = linker.root();
            let mut seed = root.instance(name)?;
            seed.func_wrap("insecure-seed", |_, (): ()| {
                // Two values from std's per-process random hash keys: no
                // RNG dependency for a seed that only spreads hash buckets.
                let word = || {
                    use std::hash::{BuildHasher, Hasher};
                    std::collections::hash_map::RandomState::new()
                        .build_hasher()
                        .finish()
                };
                Ok(((word(), word()),))
            })?;
        }
    }
    linker.define_unknown_imports_as_traps(component)?;
    Ok(linker)
}

/// Per-store state: the memory limiter, and whether it said no.
struct StoreState {
    memory_bytes: usize,
    memory_refused: bool,
}

impl ResourceLimiter for StoreState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let ok = desired <= self.memory_bytes;
        self.memory_refused |= !ok;
        Ok(ok)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // A table entry is a pointer on the host side; this caps tables
        // at a few MiB, far beyond what an inspector needs.
        Ok(desired <= 1 << 20)
    }
}

/// One live instance and the store that owns it.
struct Slot {
    store: Store<StoreState>,
    bindings: wit::Inspector,
}

/// A loaded plugin: one compiled component, its config, a pool of
/// configured instances.
struct Plugin {
    name: String,
    component: Component,
    linker: Linker<StoreState>,
    config: String,
    limits: Limits,
    pool: Mutex<Vec<Slot>>,
    pool_cap: usize,
}

impl fmt::Debug for Plugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plugin")
            .field("name", &self.name)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Why a call produced no usable answer.
enum CallError {
    /// The plugin trapped, ran out of fuel or memory, or broke the ABI.
    Failed(String),
    /// `configure` returned `err` (only while creating an instance).
    Refused(String),
}

impl Plugin {
    fn new(name: &str, bytes: &[u8], config: &str, limits: Limits) -> Result<Self, String> {
        let component = compile(bytes).map_err(|e| format!("inspector {name}: {e}"))?;
        let linker =
            linker_for(&component).map_err(|e| format!("inspector {name}: {}", one_line(&e)))?;
        let plugin = Self {
            name: name.to_owned(),
            component,
            linker,
            config: config.to_owned(),
            limits,
            pool: Mutex::new(Vec::new()),
            pool_cap: std::thread::available_parallelism().map_or(4, usize::from),
        };
        // One instance up front: proves the component instantiates and
        // accepts this config before it replaces anything in the chain.
        let slot = plugin.instantiate().map_err(|e| match e {
            CallError::Refused(msg) => format!("inspector {name}: configure refused: {msg}"),
            CallError::Failed(msg) => format!("inspector {name}: {msg}"),
        })?;
        plugin.check_in(slot);
        Ok(plugin)
    }

    fn new_store(&self) -> Store<StoreState> {
        let mut store = Store::new(
            engine(),
            StoreState {
                memory_bytes: self.limits.memory_bytes,
                memory_refused: false,
            },
        );
        store.limiter(|state| state as &mut dyn ResourceLimiter);
        store
    }

    /// A fresh instance, configured.
    fn instantiate(&self) -> Result<Slot, CallError> {
        let mut store = self.new_store();
        let fail = |store: &Store<StoreState>, e: &wasmtime::Error| {
            CallError::Failed(self.describe(store, e))
        };
        store
            .set_fuel(self.limits.fuel)
            .map_err(|e| fail(&store, &e))?;
        let bindings = wit::Inspector::instantiate(&mut store, &self.component, &self.linker)
            .map_err(|e| fail(&store, &e))?;
        store
            .set_fuel(self.limits.fuel)
            .map_err(|e| fail(&store, &e))?;
        match bindings.call_configure(&mut store, &self.config) {
            Ok(Ok(())) => Ok(Slot { store, bindings }),
            Ok(Err(msg)) => Err(CallError::Refused(msg)),
            Err(e) => Err(fail(&store, &e)),
        }
    }

    fn check_out(&self) -> Result<Slot, CallError> {
        let pooled = self
            .pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        match pooled {
            Some(slot) => Ok(slot),
            None => self.instantiate(),
        }
    }

    fn check_in(&self, slot: Slot) {
        let mut pool = self.pool.lock().unwrap_or_else(PoisonError::into_inner);
        if pool.len() < self.pool_cap {
            pool.push(slot);
        }
    }

    /// The operator-facing description of a failed call.
    fn describe(&self, store: &Store<StoreState>, e: &wasmtime::Error) -> String {
        if store.data().memory_refused {
            return format!(
                "exceeded its memory limit of {} MiB",
                self.limits.memory_bytes >> 20
            );
        }
        if matches!(e.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)) {
            return format!("exceeded its CPU budget of {} fuel", self.limits.fuel);
        }
        one_line(e)
    }

    fn failed(&self, msg: &str) -> Verdict {
        Verdict::new(
            self.name.clone(),
            Action::Block,
            format!("inspector {} failed: {msg}", self.name),
            Severity::Error,
        )
    }

    fn call(&self, ctx: &Context, response: bool) -> Option<Verdict> {
        let mut slot = match self.check_out() {
            Ok(slot) => slot,
            Err(CallError::Failed(msg)) => return Some(self.failed(&msg)),
            // The config was accepted at load; a fresh instance refusing
            // it now means the plugin is not deterministic. Still closed.
            Err(CallError::Refused(msg)) => {
                return Some(self.failed(&format!("configure refused: {msg}")));
            }
        };
        let abi_ctx = to_abi(ctx, response);
        let outcome = slot.store.set_fuel(self.limits.fuel).and_then(|()| {
            if response {
                slot.bindings
                    .call_inspect_response(&mut slot.store, &abi_ctx)
            } else {
                slot.bindings
                    .call_inspect_request(&mut slot.store, &abi_ctx)
            }
        });
        match outcome {
            Ok(None) => {
                self.check_in(slot);
                None
            }
            Ok(Some(verdict)) => {
                self.check_in(slot);
                Some(
                    from_abi(&self.name, verdict)
                        .unwrap_or_else(|msg| self.failed(&format!("malformed verdict: {msg}"))),
                )
            }
            // The instance is dropped, not pooled: after a trap its memory
            // and globals are whatever they were mid-call.
            Err(e) => Some(self.failed(&self.describe(&slot.store, &e))),
        }
    }
}

impl Inspector for Plugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
        self.call(ctx, false)
    }

    fn inspect_response(&self, ctx: &Context) -> Option<Verdict> {
        self.call(ctx, true)
    }
}

/// The first line of an error's display, without wasmtime's backtrace
/// or cause chain: it ends up in an audit record and a 403 body.
fn one_line(e: &wasmtime::Error) -> String {
    let text = e.to_string();
    text.lines().next().unwrap_or("").trim().to_owned()
}

fn to_abi_action(action: Action) -> abi::Action {
    match action {
        Action::Block => abi::Action::Block,
        Action::Flag => abi::Action::Flag,
    }
}

fn to_abi_severity(severity: Severity) -> abi::Severity {
    match severity {
        Severity::Debug => abi::Severity::Debug,
        Severity::Info => abi::Severity::Info,
        Severity::Warning => abi::Severity::Warning,
        Severity::Error => abi::Severity::Error,
        Severity::Critical => abi::Severity::Critical,
    }
}

fn to_abi(ctx: &Context, response: bool) -> abi::Context {
    abi::Context {
        url: ctx.url.clone(),
        host: ctx.host.clone(),
        method: ctx.method.clone(),
        headers: ctx.headers.clone(),
        content_type: ctx.content_type.clone(),
        body: ctx.body_bytes.clone(),
        body_text: ctx.body_text.clone(),
        body_size: ctx.body_size as u64,
        body_entropy: ctx.body_entropy,
        prior_results: ctx
            .prior_results
            .iter()
            .map(|v| abi::PriorResult {
                inspector: v.inspector.clone(),
                action: to_abi_action(v.action),
                reason: v.reason.clone(),
                severity: to_abi_severity(v.severity),
                metadata: v
                    .metadata
                    .iter()
                    .map(|(key, value)| abi::MetadataEntry {
                        key: key.clone(),
                        value: json::to_compact_string(value),
                    })
                    .collect(),
            })
            .collect(),
        direction: match ctx.direction {
            Direction::Outbound => abi::Direction::Outbound,
            Direction::Inbound => abi::Direction::Inbound,
        },
        phase: if ctx.websocket {
            abi::Phase::Websocket
        } else if response {
            abi::Phase::Response
        } else {
            abi::Phase::Request
        },
    }
}

/// A plugin's verdict, attributed to the configured `name` (a plugin
/// cannot speak as another inspector). Metadata values must be JSON.
fn from_abi(name: &str, verdict: abi::Verdict) -> Result<Verdict, String> {
    let metadata = verdict
        .metadata
        .into_iter()
        .map(|entry| {
            json::parse(&entry.value)
                .map(|value| (entry.key.clone(), value))
                .map_err(|_| format!("metadata {:?} is not JSON", entry.key))
        })
        .collect::<Result<Vec<(String, Json)>, String>>()?;
    Ok(Verdict {
        inspector: name.to_owned(),
        action: match verdict.action {
            abi::Action::Block => Action::Block,
            abi::Action::Flag => Action::Flag,
        },
        reason: verdict.reason,
        severity: match verdict.severity {
            abi::Severity::Debug => Severity::Debug,
            abi::Severity::Info => Severity::Info,
            abi::Severity::Warning => Severity::Warning,
            abi::Severity::Error => Severity::Error,
            abi::Severity::Critical => Severity::Critical,
        },
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configs_are_handed_over_as_python_would_dump_them() {
        assert_eq!(config_json(None), "{}");
        assert_eq!(config_json(Some(&serde_norway::Value::Null)), "{}");
        let yaml: serde_norway::Value =
            serde_norway::from_str("b: 1\na: [x, 2.0, true, null]\nc: {d: é}\n").unwrap();
        assert_eq!(
            config_json(Some(&yaml)),
            r#"{"b": 1, "a": ["x", 2.0, true, null], "c": {"d": "\u00e9"}}"#
        );
    }

    #[test]
    fn the_plugin_directories_come_from_the_environment_or_the_default() {
        // Reads the variable without setting it: tests run in parallel.
        let loader = Loader::from_env();
        match std::env::var_os(DIRS_ENV) {
            None => assert_eq!(loader.dirs, [PathBuf::from(DEFAULT_DIR)]),
            Some(_) => assert!(!loader.dirs.is_empty()),
        }
        assert_eq!(loader.limits, Limits::default());
    }

    #[test]
    fn a_verdict_is_attributed_to_the_configured_name() {
        let v = from_abi(
            "mine",
            abi::Verdict {
                action: abi::Action::Flag,
                reason: "r".into(),
                severity: abi::Severity::Critical,
                metadata: vec![abi::MetadataEntry {
                    key: "k".into(),
                    value: r#"{"a": [1, "x"]}"#.into(),
                }],
            },
        )
        .unwrap();
        assert_eq!(v.inspector, "mine");
        assert_eq!(v.action, Action::Flag);
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(json::to_string(&v.metadata[0].1), r#"{"a": [1, "x"]}"#);
    }
}
