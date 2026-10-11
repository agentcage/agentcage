//! The watcher's scan loop and its hot-reload lifecycle.
//!
//! The loop runs on a dedicated OS thread rather than as a runtime task.
//! Everything a scan does blocks — reading capture, the LLM call — and a
//! thread that sleeps for a quarter of an hour between scans costs
//! nothing, so the proxy's runtime never carries a slow provider, which
//! is what the replaced implementation went to `to_thread` lengths to
//! guarantee.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use crate::config::{Config, Value};

use super::config::{WatcherConfig, watcher_block};
use super::scan::{RefsHandle, RuntimeRefs, WarnFn, Watcher, WatcherDeps};

/// A stop signal the loop sleeps on.
#[derive(Debug, Default)]
struct Stop {
    flag: AtomicBool,
    lock: Mutex<()>,
    wake: Condvar,
}

impl Stop {
    fn set(&self) {
        self.flag.store(true, Ordering::SeqCst);
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.wake.notify_all();
    }

    fn is_set(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Sleep for `delay` or until stopped; true when stopped.
    fn sleep(&self, delay: Duration) -> bool {
        let guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let (_guard, _) = self
            .wake
            .wait_timeout_while(guard, delay, |()| !self.is_set())
            .unwrap_or_else(PoisonError::into_inner);
        self.is_set()
    }
}

/// A running scan loop.
#[derive(Debug)]
pub struct LoopHandle {
    stop: Arc<Stop>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LoopHandle {
    /// Start scanning: sleep a jittered interval, tick, repeat, until
    /// stopped. A tick that panics is logged and the loop carries on — one
    /// surprise must not end monitoring for the life of the egress.
    ///
    /// # Errors
    ///
    /// The thread could not be spawned.
    pub fn spawn(watcher: Arc<Mutex<Watcher>>, warn: WarnFn) -> std::io::Result<Self> {
        let stop = Arc::new(Stop::default());
        let signal = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("agentcage-watcher".to_owned())
            .spawn(move || {
                loop {
                    let delay = watcher
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .next_delay();
                    if signal.sleep(delay) {
                        return;
                    }
                    let tick = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let mut w = watcher.lock().unwrap_or_else(PoisonError::into_inner);
                        w.tick(&|| signal.is_set());
                    }));
                    if let Err(panic) = tick {
                        let what = panic
                            .downcast_ref::<&str>()
                            .map(ToString::to_string)
                            .or_else(|| panic.downcast_ref::<String>().cloned())
                            .unwrap_or_default();
                        warn(&format!("agentcage: watcher tick failed: {what}"));
                    }
                    if signal.is_set() {
                        return;
                    }
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    /// Ask the loop to stop. It exits after its current sleep is cut short
    /// or its current tick ends; a tick stopped while the model answers
    /// returns its batch and applies nothing. Does not wait.
    pub fn stop(&self) {
        self.stop.set();
    }

    /// Stop and wait for the thread to exit.
    pub fn join(mut self) {
        self.stop.set();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for LoopHandle {
    fn drop(&mut self) {
        // Never block a reload on an in-flight LLM call: signal and let the
        // thread finish on its own.
        self.stop.set();
    }
}

struct Running {
    watcher: Arc<Mutex<Watcher>>,
    refs: RefsHandle,
    block: Value,
    handle: Option<LoopHandle>,
}

/// The watcher's lifecycle across config reloads.
///
/// * Unchanged watcher block: the running watcher and its scan state
///   (capture cursor, counters) are kept — rebuilding would re-analyse
///   the same window, duplicating cost and findings — but its domain
///   inspector, grant store and key are re-pointed.
/// * Block disabled (or not a mapping): the loop stops and the audit ring
///   is emptied, as dropping it did.
/// * Block changed: a new watcher is built, then the old loop stopped
///   and the new one started. The ring is shared, so the fresh-traffic
///   history survives the rebuild; the cursors do not.
pub struct WatcherManager {
    current: Option<Running>,
    running: bool,
    warn: WarnFn,
}

impl std::fmt::Debug for WatcherManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatcherManager")
            .field("enabled", &self.current.is_some())
            .field("running", &self.running)
            .finish_non_exhaustive()
    }
}

impl Default for WatcherManager {
    fn default() -> Self {
        Self::new(Arc::new(|msg: &str| eprintln!("{msg}")))
    }
}

impl WatcherManager {
    /// A manager with no watcher, logging through `warn`.
    #[must_use]
    pub fn new(warn: WarnFn) -> Self {
        Self {
            current: None,
            running: false,
            warn,
        }
    }

    /// Whether a watcher is configured: the audit writer should feed the
    /// ring exactly while this is true.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.current.is_some()
    }

    /// The current watcher, if any.
    #[must_use]
    pub fn watcher(&self) -> Option<Arc<Mutex<Watcher>>> {
        self.current.as_ref().map(|r| Arc::clone(&r.watcher))
    }

    /// Start scan loops from now on (the egress is up). Starts the current
    /// watcher's loop if it has none.
    pub fn start(&mut self) {
        self.running = true;
        if let Some(r) = &mut self.current
            && r.handle.is_none()
        {
            r.handle = spawn(&r.watcher, &self.warn);
        }
    }

    /// Stop every loop (shutdown).
    pub fn shutdown(&mut self) {
        self.running = false;
        if let Some(r) = &mut self.current
            && let Some(h) = r.handle.take()
        {
            h.join();
        }
    }

    /// Apply a (re)loaded config.
    pub fn apply(&mut self, cfg: &Config, deps: &WatcherDeps, refs: RuntimeRefs) {
        let mut block = watcher_block(cfg);
        if !matches!(block, Value::Mapping(_)) {
            (self.warn)(&format!(
                "agentcage: watcher config is not a mapping (got {}) — watcher disabled",
                agentcage_core::python::type_name(&block)
            ));
            block = Value::Mapping(crate::config::Mapping::new());
        }
        if let Some(r) = &self.current
            && r.block == block
        {
            r.refs.refresh(refs);
            return;
        }
        let parsed = WatcherConfig::parse(cfg, &mut |m| (self.warn)(m));
        if !parsed.enable {
            if let Some(old) = self.current.take() {
                drop(old.handle);
                // Emptying the ring is what dropping it did: a later
                // re-enable starts from fresh traffic, not a stale backlog.
                let _ = deps.ring.drain(usize::MAX);
            }
            return;
        }
        let watcher = Watcher::new(parsed, deps.clone(), refs).with_warn(Arc::clone(&self.warn));
        (self.warn)(&format!(
            "agentcage: traffic watcher enabled (interval={}s, provider={})",
            super::pyval::float_str(watcher.config().interval_seconds),
            watcher.config().provider
        ));
        let refs = watcher.refs_handle();
        let watcher = Arc::new(Mutex::new(watcher));
        if let Some(old) = self.current.take() {
            drop(old.handle);
        }
        let handle = if self.running {
            spawn(&watcher, &self.warn)
        } else {
            None
        };
        self.current = Some(Running {
            watcher,
            refs,
            block,
            handle,
        });
    }
}

fn spawn(watcher: &Arc<Mutex<Watcher>>, warn: &WarnFn) -> Option<LoopHandle> {
    match LoopHandle::spawn(Arc::clone(watcher), Arc::clone(warn)) {
        Ok(h) => Some(h),
        Err(e) => {
            warn(&format!("agentcage: cannot start the watcher loop: {e}"));
            None
        }
    }
}
