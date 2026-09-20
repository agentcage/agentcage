//! `backends/vm.py` — a Lima guest with podman and quadlets inside it.
//!
//! Both halves (RUST-PORT-PLAN.md Track E). **E1** is the generation
//! half: the units, the Lima YAML, the argv every `limactl` invocation
//! is built from, the guest-side file pushes and the secret bridging,
//! none of which needs a Lima host to be checked — every command goes
//! through [`CommandRunner`], so a recording fake on a Linux CI runner
//! sees the same argv a real `limactl` would. **E4** is the execution
//! half below the `── execution ──` rule: [`VmBackend::deploy_cage`],
//! [`VmBackend::start`], [`VmBackend::stop`],
//! [`VmBackend::restart`], [`VmBackend::build_artifacts`] and the
//! readiness waits, each of them a loop whose exit condition is a live
//! guest's answer. Their acceptance check is e2e phase 7.
//!
//! # `setsid` vs `setpgid` on `limactl start` — settled
//!
//! D1 built [`agentcage_exec::Command::new_process_group`] as the safe
//! stand-in for the Python's `start_new_session=True`: `setpgid(0, 0)`
//! rather than `setsid()`, because a real `setsid` needs a `pre_exec`
//! closure and this workspace forbids `unsafe_code`. It left the
//! difference for E4 to settle on a real Lima host. Measured here, and
//! the answer is that **the two are equivalent on this path**:
//!
//! * The difference is real and is the controlling terminal. Under a
//!   pty, a `setpgid` child keeps the ctty and a `setsid` child does
//!   not — and a child that *reads* `/dev/tty` from a background
//!   process group is **stopped by SIGTTIN**, where the sessionless one
//!   fails immediately with `ENXIO`. So `setpgid` converts a would-be
//!   prompt into a hang.
//! * `limactl start` never reads the terminal. The one prompt Lima has
//!   is `create`'s configuration survey, and
//!   [`LimaInstance::create`] passes `--yes` precisely to suppress it.
//! * Run live with both binaries under `script(1)`: `cage start`
//!   returned in 30s (Rust) and 33s (Python), and in both cases the
//!   hostagent was left at `ppid=1`, in its own process group, with
//!   **no controlling terminal** — Lima daemonizes it itself, so the
//!   flag on the parent does not decide the daemon's fate. The instance
//!   stayed `Running` after the pty closed either way.
//!
//! The residual risk is narrow and worth knowing: if a future Lima ever
//! prompted on `start`, this would stop rather than fail, and the
//! operator would see agentcage hang with no output. That is the thing
//! to re-check if `limactl start` ever grows an interactive path.
//!
//! Note what this question does **not** touch: the streaming readers.
//! `cage logs --severity` and `cage audit --follow` run their child
//! through [`CommandRunner::stream`] with no process-group flag at all,
//! and their `terminate()` sends SIGTERM to the local `limactl shell`;
//! the guest-side `journalctl -f` goes away with the ssh channel.
//!
//! # Why the guest paths are absolute here and `%h` in the units
//!
//! `quadlets.vm_local_*` return `%h/...` — systemd's home specifier,
//! which podman-quadlet expands before it parses the `Volume=` line. A
//! guest *shell* does not expand it, and neither does `~` once
//! `shlex.quote` has been over it. So every command this module sends
//! into the guest resolves `%h` first, from the guest's own `echo ~`,
//! and `test_vm_backend.py` pins the absence of both markers in the
//! argv that results.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use agentcage_core::config::Config;
use agentcage_core::lima::{LimaFacts, generate_lima_config};
use agentcage_core::quadlets::{
    GenerateOptions, Quadlets, b64, b64_bytes, generate_quadlets, shlex_quote,
    vm_local_cage_env_dir, vm_local_config_dir, vm_local_dns_allowlist_path, vm_local_grants_dir,
    vm_local_grants_file, vm_local_placeholders_env_path, vm_local_proxy_config_path,
    vm_local_watcher_dir,
};
use agentcage_core::yaml::{self, Mapping, Value};
use agentcage_exec::tools::limactl::{LimaInstance, VmPodman};
use agentcage_exec::tools::podman::secret_env_names;
use agentcage_exec::{CommandRunner, ExecError};
use agentcage_state::Paths;

use crate::backend::{BackendError, EGRESS_BUILD_CAPS};
use crate::hostenv::{self, RealQuadletHost};

/// `VmBackend.service_names` — fixed, and not a function of the cage.
pub const SERVICE_NAMES: [&str; 2] = ["cage", "egress"];

/// The floor `generate_units` puts under `container.timeout_start_sec`.
///
/// `VM_MIN_TIMEOUT_START_SEC`. Starting a cage inside a Lima guest has
/// to spin up the virtual disk, extract image layers through the
/// rootless storage driver, wire the per-cage podman network and bind
/// mounts virtiofs forwards from the host. What fits in 60s on bare
/// metal routinely brushes 90-120s in a VM, and the pi scaffold's 60s
/// default reliably times the cage container out on first start — which
/// reaches the operator as "failed because a timeout was exceeded" with
/// no obvious knob.
pub const VM_MIN_TIMEOUT_START_SEC: i64 = 300;

/// The guest directory quadlets are installed into.
///
/// `~/.config/containers/systemd`, resolved inside the guest rather
/// than on the host.
const GUEST_QUADLET_DIR: &str = "~/.config/containers/systemd";

/// Where the in-guest build context is unpacked.
const VM_BUILD_DIR: &str = "/tmp/agentcage-build";

/// `VM_SERVICE_STARTUP_DELAY_S` — the infrastructure units' deadline.
///
/// It replaced an unconditional `sleep(5)`, and it is still 5s: the
/// polling below only removes the idle time from the common case, it
/// does not shorten the ceiling a cold start is allowed.
const VM_SERVICE_STARTUP_DELAY: Duration = Duration::from_secs(5);

/// `VM_SERVICE_STARTUP_POLL_INTERVAL_S`.
const VM_SERVICE_STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// `VM_USER_SESSION_TIMEOUT_S` — issue #319's safety net.
///
/// Deliberately short: see [`VmBackend::wait_user_session_ready`].
const VM_USER_SESSION_TIMEOUT: Duration = Duration::from_secs(20);

/// `VM_USER_SESSION_POLL_INTERVAL_S`.
const VM_USER_SESSION_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// `PROXY_READINESS_TIMEOUT_S` — how long the egress gets to become
/// active before the cage is refused.
///
/// A deadline rather than an iteration count, so the interval below can
/// be tightened without shrinking the ceiling: mitmproxy is usually
/// ready in 2–6s, and a sub-second poll takes that off the median.
const PROXY_READINESS_TIMEOUT: Duration = Duration::from_secs(30);

/// `PROXY_READINESS_POLL_INTERVAL_S`.
const PROXY_READINESS_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// `_USER_SESSION_PROBE`, verbatim — one round-trip for "can rootless
/// podman run a container yet?".
///
/// Answers `no-user-bus` when the socket is absent, and otherwise
/// whatever `is-system-running` says. It matches on **stdout**, not the
/// exit code: `degraded` is a ready state and exits non-zero.
const USER_SESSION_PROBE: &str = "uid=$(id -u); \
     if [ ! -S \"/run/user/$uid/bus\" ]; then echo no-user-bus; exit 0; fi; \
     systemctl --user is-system-running 2>/dev/null || true";

/// The process environment [`VmBackend::stage_secrets`] resolves
/// `env:` sources against.
///
/// A `static` rather than a local because [`crate::secrets::SecretHost`]
/// borrows it. Tests that want a different environment call
/// [`VmBackend::resolve_source_secrets`] and
/// [`VmBackend::bridge_store_secrets`] directly, which is how E1's
/// reach them.
static SYSTEM_ENVIRONMENT: crate::secrets::SystemEnv = crate::secrets::SystemEnv;

/// `_USER_SESSION_READY_STATES`.
///
/// `degraded` counts: it says only that some user unit failed, while the
/// bus and the cgroup delegation are live — which is all podman's
/// sd-bus call needs. Everything else (`initializing`, `starting`,
/// `offline`, `unknown`, or no socket at all) keeps waiting.
const USER_SESSION_READY_STATES: [&str; 2] = ["running", "degraded"];

/// The `vm` backend.
///
/// Holds no Lima instance: one is built per cage name, as the Python
/// does, so a single backend serves `cage list` across cages.
#[derive(Debug)]
pub struct VmBackend<'a> {
    runner: &'a dyn CommandRunner,
    paths: &'a Paths,
    version: &'a str,
    /// `vm._guest_home` — the guest `$HOME` per cage name.
    ///
    /// The Python's is a module-level dict, so it survives for the
    /// life of the process; this one lives on the backend, which the
    /// CLI builds once per command. Same effect for the loops that
    /// motivated it (a reconcile tick doing ensure/pull/push used to
    /// run `echo ~` three times), and no state shared between
    /// unrelated commands.
    ///
    /// Keyed by cage name, not by instance: a destroyed and recreated
    /// guest lands on the identical home.
    guest_home: Mutex<BTreeMap<String, String>>,
    /// `platform.system()` and the guest user name.
    ///
    /// Held rather than read at each use so that the macOS branches —
    /// the `vz` driver, and the prerequisite check that must *not* look
    /// for QEMU or `/dev/kvm` — are reachable from a Linux CI runner.
    /// That is the same trick `test_lima_provisioning.py` plays with
    /// `patch("platform.system")`, made an argument instead of a patch.
    facts: OwnedFacts,
}

/// [`LimaFacts`], owned, so the backend can hold it.
#[derive(Clone, Debug)]
struct OwnedFacts {
    system: String,
    lima_user: String,
}

impl<'a> VmBackend<'a> {
    /// A backend bound to these paths, this runner and this version.
    ///
    /// The host facts come from the process: the build target's OS and
    /// the invoking uid's passwd entry.
    #[must_use]
    pub fn new(paths: &'a Paths, runner: &'a dyn CommandRunner, version: &'a str) -> Self {
        Self::with_facts(
            paths,
            runner,
            version,
            hostenv::system(),
            &hostenv::login_name(),
        )
    }

    /// The same, with the two host facts supplied.
    #[must_use]
    pub fn with_facts(
        paths: &'a Paths,
        runner: &'a dyn CommandRunner,
        version: &'a str,
        system: &str,
        lima_user: &str,
    ) -> Self {
        Self {
            runner,
            paths,
            version,
            guest_home: Mutex::new(BTreeMap::new()),
            facts: OwnedFacts {
                system: system.to_owned(),
                lima_user: lima_user.to_owned(),
            },
        }
    }

    /// `VmBackend._instance` — the Lima instance for a cage.
    #[must_use]
    pub fn instance(&self, name: &str) -> LimaInstance<'a> {
        LimaInstance::new(self.runner, name)
    }

    /// Podman inside that cage's guest.
    #[must_use]
    pub fn podman(&self, name: &str) -> VmPodman<'a> {
        VmPodman::new(self.runner, name)
    }

    /// `VmBackend.service_names`.
    #[must_use]
    pub fn service_names(&self) -> [&'static str; 2] {
        SERVICE_NAMES
    }

    /// The version this backend tags images and stamps units with.
    #[must_use]
    pub fn version(&self) -> &'a str {
        self.version
    }

    // ── prerequisites ────────────────────────────────────────

    /// `lima.prerequisites.check_prerequisites` — the unmet ones.
    ///
    /// An empty list means the host can run this backend. The
    /// `/dev/kvm` and QEMU checks are Linux-only, because on macOS Lima
    /// uses Virtualization.framework and neither exists.
    #[must_use]
    pub fn check_prerequisites(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if !self.runner.has("limactl") {
            issues.push(
                "'limactl' not found in PATH — install Lima: \
                 https://lima-vm.io/docs/installation/"
                    .to_owned(),
            );
        }
        match self.facts.system.as_str() {
            "Darwin" => {}
            "Linux" => {
                if !self.runner.has("qemu-system-x86_64") && !self.runner.has("qemu-system-aarch64")
                {
                    issues.push(
                        "QEMU not found — Lima requires QEMU on Linux. Install: \
                         apt install qemu-system / dnf install qemu-kvm / \
                         pacman -S qemu-full"
                            .to_owned(),
                    );
                }
                if !Path::new("/dev/kvm").exists() {
                    issues.push(
                        "/dev/kvm not found — KVM is required for acceptable VM \
                         performance. Enable virtualization in BIOS and load the \
                         kvm module."
                            .to_owned(),
                    );
                }
            }
            other => {
                issues.push(format!(
                    "unsupported platform: {other} — Lima requires Linux or macOS"
                ));
            }
        }
        issues
    }

    // ── units ────────────────────────────────────────────────

    /// `VmBackend.unit_dir` — `~/.config/agentcage/lima`.
    ///
    /// Home-rooted, **not** `XDG_CONFIG_HOME`-rooted: the Python is an
    /// `os.path.expanduser` with no XDG lookup, the same wart the
    /// quadlet directory and the apple-container root carry, and a cage
    /// deployed by the Python has its `lima.yaml` there.
    #[must_use]
    pub fn unit_dir(&self) -> PathBuf {
        self.paths.lima_dir()
    }

    /// `VmBackend.generate_units` — Lima YAML plus the guest's quadlets.
    ///
    /// The returned map is the Python's dict: `lima.yaml` first, then
    /// one `quadlets/<filename>` per unit, in render order.
    ///
    /// Two things happen here that the container backend does not do.
    ///
    /// **The timeout floor.** `container.timeout_start_sec` is raised to
    /// [`VM_MIN_TIMEOUT_START_SEC`] on a *copy* of the config. The copy
    /// is load-bearing: `cage update` fingerprints the caller's parsed
    /// config, and mutating it in place would make repeated unit
    /// generation report a change that is not one.
    ///
    /// **The store view.** The podman secret store for a vm cage lives
    /// inside the guest, so it can only be queried while the guest
    /// runs. When it does not — the initial create, where the guest
    /// does not exist yet and values arrive through
    /// `pending_secrets.json` after first start, or a stopped guest —
    /// `store_secrets` stays `None` and `Secret=` emission falls back to
    /// the legacy emit-everything behaviour. Issue #262: passing an
    /// empty set instead would drop every directive.
    ///
    /// # Errors
    ///
    /// [`BackendError::Config`] from either renderer.
    pub fn generate_units(
        &self,
        config: &Config,
        config_host_path: &str,
        patches_host_dir: &str,
        deploy_name: &str,
        used_octets: Option<&BTreeSet<u32>>,
        network_octet: Option<u32>,
    ) -> Result<Quadlets, BackendError> {
        let host = RealQuadletHost::new(self.paths.data_root());
        let lima = generate_lima_config(
            config,
            &LimaFacts {
                system: &self.facts.system,
                lima_user: &self.facts.lima_user,
            },
            &host,
        )?;

        let mut effective = config.clone();
        if effective.container.timeout_start_sec < VM_MIN_TIMEOUT_START_SEC {
            effective.container.timeout_start_sec = VM_MIN_TIMEOUT_START_SEC;
        }

        let store_name = if deploy_name.is_empty() {
            config.name.as_str()
        } else {
            deploy_name
        };
        let store_secrets = self.guest_store_view(store_name, deploy_name);

        let state = self.paths.quadlet_state_paths();
        let quadlets = generate_quadlets(
            &effective,
            &GenerateOptions {
                config_host_path,
                patches_host_dir,
                deploy_name,
                // Lima's guest user is unprivileged and the quadlets are
                // `--user` units, as `_deploy_cage` installs them.
                rootless: true,
                used_octets,
                network_octet,
                store_secrets: store_secrets.as_ref(),
                state: &state,
                version: self.version,
            },
            &host,
        )?;

        let mut out = Quadlets::default();
        out.files.insert("lima.yaml".to_owned(), lima.yaml);
        for (filename, body) in quadlets.files {
            out.files.insert(format!("quadlets/{filename}"), body);
        }
        out.warnings = lima.warnings;
        out.warnings.extend(quadlets.warnings);
        Ok(out)
    }

    /// The guest's secret-store view, or `None` when it cannot be read.
    ///
    /// Every failure mode answers `None`: no guest, a stopped guest, a
    /// `limactl` that is not installed, or a listing that failed
    /// in flight. The Python's blanket `except Exception` spelled out,
    /// because which failures collapse to "don't know" is the whole
    /// content of #262.
    fn guest_store_view(&self, cage_name: &str, deploy_name: &str) -> Option<BTreeSet<String>> {
        let instance = self.instance(cage_name);
        if !instance.exists().unwrap_or(false) || !instance.is_running().unwrap_or(false) {
            return None;
        }
        secret_env_names(&self.podman(cage_name), deploy_name)
            .ok()
            .map(|names| names.into_iter().collect())
    }

    /// `VmBackend.install_units` — write the bundle under [`Self::unit_dir`].
    ///
    /// Parent directories are created per file, which is what puts
    /// `quadlets/` there.
    ///
    /// # Errors
    ///
    /// [`BackendError::Assets`] carrying the I/O error, since a unit
    /// that cannot be written is the same class of failure as an asset
    /// tree that cannot be materialized.
    pub fn install_units(&self, units: &Quadlets, quiet: bool) -> Result<(), BackendError> {
        let dest = self.unit_dir();
        fs::create_dir_all(&dest).map_err(BackendError::Assets)?;
        for (filename, content) in &units.files {
            let path = dest.join(filename);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(BackendError::Assets)?;
            }
            fs::write(&path, content).map_err(BackendError::Assets)?;
        }
        if !quiet {
            println!("Installed Lima config to {}/", dest.display());
        }
        Ok(())
    }

    /// Where `start` hands `limactl create` its config.
    #[must_use]
    pub fn lima_config_path(&self) -> PathBuf {
        self.unit_dir().join("lima.yaml")
    }

    /// The host directory `install_units` wrote the guest's quadlets to.
    #[must_use]
    pub fn host_quadlet_dir(&self) -> PathBuf {
        self.unit_dir().join("quadlets")
    }

    // ── guest paths ──────────────────────────────────────────

    /// `vm._abs_path` — resolve a `%h`-prefixed guest path.
    ///
    /// The `echo ~` round-trip happens once per cage name and is then
    /// cached; a path without the specifier is returned untouched and
    /// costs nothing.
    ///
    /// # Errors
    ///
    /// [`ExecError`] when the guest could not be asked.
    pub fn abs_path(&self, name: &str, path: &str) -> Result<String, ExecError> {
        let Some(rest) = path.strip_prefix("%h") else {
            return Ok(path.to_owned());
        };
        Ok(format!("{}{rest}", self.guest_home(name)?))
    }

    /// The guest's `$HOME`, cached per cage name.
    fn guest_home(&self, name: &str) -> Result<String, ExecError> {
        if let Ok(cache) = self.guest_home.lock() {
            if let Some(home) = cache.get(name) {
                return Ok(home.clone());
            }
        }
        let home = self.probe_guest_home(name)?;
        if let Ok(mut cache) = self.guest_home.lock() {
            cache.insert(name.to_owned(), home.clone());
        }
        Ok(home)
    }

    /// One uncached `bash -c 'echo ~'` in the guest.
    ///
    /// Separate from [`Self::guest_home`] because
    /// [`Self::push_config_files`] resolves the home *without* the
    /// cache, exactly as the Python does — it holds `home` as a local
    /// and never consults `_guest_home`. Populating the cache from it
    /// would remove a round-trip from the deploy sequence E4 has to
    /// reproduce, so the wart is kept rather than tidied.
    fn probe_guest_home(&self, name: &str) -> Result<String, ExecError> {
        let out = self.instance(name).exec(&bash_c("echo ~"), true)?;
        Ok(out.stdout_text().trim().to_owned())
    }

    // ── host → guest file pushes ─────────────────────────────

    /// `vm.push_config_files` — mirror the egress's two config files,
    /// and the cage's placeholders, into a guest-local directory.
    ///
    /// The quadlets bind-mount the guest-local copy, not the host path
    /// under `~/.config/agentcage/cages/<name>/`. They have to: Lima's
    /// reverse-sshfs mount caches host writes, so dnsmasq's SIGHUP and
    /// mitmproxy's mtime poll would re-read the same stale bytes
    /// forever after a `domain add`. The host file stays the
    /// authoritative state — `cage backup` and the audit tooling read
    /// it — and this is an additional copy.
    ///
    /// Each file travels base64-encoded through `bash -c`, so content
    /// that looks like a heredoc delimiter, a quote or a newline cannot
    /// break out of the command. Idempotent, and safe on every deploy,
    /// start, restart and domain edit; the cost is one round-trip per
    /// file that exists.
    ///
    /// # Errors
    ///
    /// [`ExecError`] from any of the guest commands.
    pub fn push_config_files(&self, name: &str) -> Result<(), ExecError> {
        let instance = self.instance(name);
        // The Python resolves the home here rather than through
        // `_abs_path`, so this call happens even on a warm cache. See
        // `probe_guest_home`.
        let home = self.probe_guest_home(name)?;
        let absolute = |path: &str| -> String {
            path.strip_prefix("%h")
                .map_or_else(|| path.to_owned(), |rest| format!("{home}{rest}"))
        };

        instance.exec(
            &["mkdir", "-p", &absolute(&vm_local_config_dir(name))].map(str::to_string),
            true,
        )?;

        for (host_path, guest_path) in [
            (
                self.paths.proxy_config_path(name),
                vm_local_proxy_config_path(name),
            ),
            (
                self.paths.dns_allowlist_path(name),
                vm_local_dns_allowlist_path(name),
            ),
        ] {
            if let Some(bytes) = read_if_file(&host_path) {
                instance.exec(&bash_c(&decode_into(&bytes, &absolute(&guest_path))), true)?;
            }
        }

        let placeholders = self.paths.placeholders_env_path(name);
        if let Some(bytes) = read_if_file(&placeholders) {
            instance.exec(
                &["mkdir", "-p", &absolute(&vm_local_cage_env_dir(name))].map(str::to_string),
                true,
            )?;
            instance.exec(
                &bash_c(&decode_into(
                    &bytes,
                    &absolute(&vm_local_placeholders_env_path(name)),
                )),
                true,
            )?;
        }
        Ok(())
    }

    /// `vm.ensure_grants_dir` — create the guest-local overlay directory.
    ///
    /// It must exist *before* the egress unit starts: that unit's
    /// `ExecStartPre` chgrps and chmods the directory, and podman's own
    /// implicit mkdir for a volume source runs later than that. Also
    /// gives the in-guest addon an empty overlay to poll on a first
    /// deploy.
    ///
    /// # Errors
    ///
    /// [`ExecError`] from the guest commands.
    pub fn ensure_grants_dir(&self, name: &str) -> Result<(), ExecError> {
        let path = self.abs_path(name, &vm_local_grants_dir(name))?;
        self.instance(name)
            .exec(&["mkdir", "-p", &path].map(str::to_string), true)?;
        Ok(())
    }

    /// `vm.push_quadlets` — the file-writing half of `_deploy_cage`.
    ///
    /// Split out of `_deploy_cage` so the part that is checkable
    /// without a guest is checkable without a guest: this builds the
    /// same base64 pipeline `push_config_files` uses, one command per
    /// unit file, after resolving the guest's quadlet directory. What
    /// comes after it — `daemon-reload`, the ordered service starts and
    /// the waits — is [`VmBackend::deploy_cage`], below the execution
    /// rule.
    ///
    /// Files are pushed in sorted order. The Python iterates
    /// `Path.iterdir()`, which is `readdir` order and therefore
    /// filesystem-dependent; sorting is the one place this module does
    /// not reproduce the Python exactly, because "whatever the
    /// filesystem says" is not a contract and a test cannot pin it.
    ///
    /// # Errors
    ///
    /// [`ExecError`] from a guest command, or [`BackendError::Assets`]
    /// if the host-side directory cannot be read.
    pub fn push_quadlets(&self, name: &str) -> Result<(), BackendError> {
        let source = self.host_quadlet_dir();
        if !source.is_dir() {
            return Ok(());
        }
        let instance = self.instance(name);
        instance.exec(&bash_c(&format!("mkdir -p {GUEST_QUADLET_DIR}")), true)?;
        let guest_dir = instance
            .exec(&bash_c(&format!("echo {GUEST_QUADLET_DIR}")), true)?
            .stdout_text()
            .trim()
            .to_owned();

        let mut entries: Vec<PathBuf> = fs::read_dir(&source)
            .map_err(BackendError::Assets)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_file())
            .collect();
        entries.sort();

        for path in entries {
            let body = fs::read(&path).map_err(BackendError::Assets)?;
            let filename = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            instance.exec(
                &bash_c(&format!(
                    "echo '{}' | base64 -d > {}/{}",
                    b64_bytes(&body),
                    shlex_quote(&guest_dir),
                    shlex_quote(&filename),
                )),
                true,
            )?;
        }
        Ok(())
    }

    // ── the guest-local grants overlay ───────────────────────

    /// `vm.pull_grants` — read the guest-local overlay.
    ///
    /// Three answers, and the difference between the last two is the
    /// point:
    ///
    /// * `Some(entries)` — the overlay was read;
    /// * `Some(vec![])` — the file is absent, which is a fresh cage's
    ///   normal empty state;
    /// * `None` — the round-trip failed, or the guest reported a read
    ///   failure that is *not* "file missing".
    ///
    /// A caller must not turn `None` into an empty overlay: the
    /// reconcile's merge-on-write would treat the wipe as genuine and
    /// persist it on the next push. The guest is probed with a shell
    /// script rather than a bare `cat` so the two can be told apart —
    /// exit 42 is the "absent" sentinel, and any other non-zero exit is
    /// a real failure.
    ///
    /// Entries that are not mappings are dropped. The Python keeps
    /// them, and then every reader does `entry.get(...)` on them and
    /// raises; nothing that writes this file produces one.
    #[must_use]
    pub fn pull_grants(&self, name: &str) -> Option<Vec<Mapping>> {
        let text = self.read_guest_file(name, &vm_local_grants_file(name))?;
        if text.is_empty() {
            return Some(Vec::new());
        }
        match yaml::load(&text) {
            Ok(Value::Sequence(items)) => Some(
                items
                    .into_iter()
                    .filter_map(|item| match item {
                        Value::Mapping(mapping) => Some(mapping),
                        _ => None,
                    })
                    .collect(),
            ),
            // `if not isinstance(data, list): return []`, and the same
            // for a YAML error — a malformed overlay is empty, not
            // unreachable.
            _ => Some(Vec::new()),
        }
    }

    /// `vm.pull_watcher_output` — one traffic-watcher file from the guest.
    ///
    /// `relative` is `findings.jsonl` or `state.json`. Same sentinel
    /// protocol as [`Self::pull_grants`], for the same reason: a
    /// findings reader must not read an unreachable guest as "no
    /// findings, all clear". `Some("")` is the absent file, `None` is
    /// the failed round-trip.
    #[must_use]
    pub fn pull_watcher_output(&self, name: &str, relative: &str) -> Option<String> {
        let base = vm_local_watcher_dir(name);
        self.read_guest_file(name, &format!("{base}/{relative}"))
    }

    /// The `[ -f … ]`-or-exit-42 probe both readers share.
    ///
    /// `Some("")` for the sentinel, `None` for anything else that went
    /// wrong, including a `limactl` that could not run at all.
    fn read_guest_file(&self, name: &str, guest_path: &str) -> Option<String> {
        let absolute = self.abs_path(name, guest_path).ok()?;
        let quoted = shlex_quote(&absolute);
        let script = format!("if [ -f {quoted} ]; then cat {quoted}; else exit 42; fi");
        let out = self.instance(name).exec(&sh_c(&script), false).ok()?;
        match out.status.code {
            Some(42) => Some(String::new()),
            Some(0) => Some(out.stdout_text()),
            _ => None,
        }
    }

    /// `vm.push_grants` — write the guest-local overlay, atomically.
    ///
    /// Base64 over `limactl shell`, the same host→guest channel
    /// [`Self::push_config_files`] uses, because the Lima mounts cannot
    /// be trusted for host→guest writes. The write is `mktemp` + `mv`
    /// rather than a redirect into `<path>.tmp`: `mktemp` creates with
    /// `O_EXCL` semantics, so a planted symlink at a predictable temp
    /// name cannot be written through in a shared directory, and the
    /// rename means the in-guest addon's mtime poll never sees a
    /// half-written file.
    ///
    /// # Errors
    ///
    /// [`ExecError`] from the guest command, or [`BackendError::State`]
    /// if the entries cannot be emitted as YAML.
    pub fn push_grants(&self, name: &str, entries: &[Mapping]) -> Result<(), BackendError> {
        let absolute = self.abs_path(name, &vm_local_grants_file(name))?;
        let document = Value::Sequence(entries.iter().cloned().map(Value::Mapping).collect());
        let text = yaml::dump(&document).map_err(|source| {
            BackendError::State(agentcage_state::StateError::Yaml {
                path: PathBuf::from(&absolute),
                source,
            })
        })?;
        let target = shlex_quote(&absolute);
        let directory = shlex_quote(dirname(&absolute));
        let script = format!(
            "tmp=$(mktemp {directory}/XXXXXX) && echo '{}' | base64 -d > \"$tmp\" && mv \"$tmp\" {target}",
            b64(&text),
        );
        self.instance(name).exec(&sh_c(&script), true)?;
        Ok(())
    }

    // ── secret bridging ──────────────────────────────────────

    /// `VmBackend._bridge_secrets` — host secrets into the guest store.
    ///
    /// Two sources, in the Python's order: the `.cred` blobs under the
    /// deployment directory, decrypted on the host with `systemd-creds`
    /// and piped in; then whatever the *host's* podman store holds
    /// under this cage's prefix, read back with `--showsecret` and
    /// piped in.
    ///
    /// Every value moves on **stdin**, on both sides of the
    /// `limactl shell`. Nothing is ever an argument: an argv is
    /// readable through `/proc/<pid>/cmdline` by every process on the
    /// host for as long as the command runs, and the guest side would
    /// be readable inside the guest too.
    ///
    /// Best-effort per secret, as the Python is: one that cannot be
    /// bridged warns and the rest continue, because the alternative is
    /// a deploy that aborts halfway with some secrets already in the
    /// guest.
    ///
    /// Returns the `click.echo` lines, stdout and stderr interleaved in
    /// the order they were produced, rather than printing them — see
    /// [`Bridged`].
    ///
    /// # Errors
    ///
    /// Only [`ExecError`] from a `limactl` that could not be run at
    /// all. A secret that fails to bridge is a warning in the result.
    pub fn bridge_secrets(&self, name: &str) -> Result<Bridged, ExecError> {
        let mut out = Bridged::default();
        let instance = self.instance(name);

        // --- systemd-creds encrypted blobs ---
        let creds_dir = self.paths.creds_dir(name);
        if creds_dir.is_dir() {
            let mut files: Vec<PathBuf> = fs::read_dir(&creds_dir)
                .map(|entries| {
                    entries
                        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                        .filter(|path| path.extension().is_some_and(|ext| ext == "cred"))
                        .collect()
                })
                .unwrap_or_default();
            // `Path.iterdir()` order is the filesystem's; sorted here
            // for the same reason `push_quadlets` sorts.
            files.sort();
            for cred in files {
                let key = cred
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let secret = format!("{name}.{key}");
                match self.bridge_one_cred(&instance, &cred, &secret) {
                    Ok(()) => out
                        .messages
                        .push(format!("  Bridged secret (decrypted): {secret}")),
                    Err(error) => out.warnings.push(format!(
                        "warning: failed to bridge encrypted secret {secret}: {error}"
                    )),
                }
            }
        }

        // --- the host's own podman store ---
        //
        // `podman secret ls` without `check=True`: a host that has no
        // podman at all is the normal case on macOS, and the Python's
        // `except FileNotFoundError: return` makes it a silent one.
        let host_podman = agentcage_exec::tools::podman::Podman::new(self.runner);
        let Ok(names) = host_podman.secret_list(&format!("{name}.")) else {
            return Ok(out);
        };
        for secret in names {
            match Self::bridge_one_podman_secret(&instance, &host_podman, &secret) {
                Ok(()) => out.messages.push(format!("  Bridged secret: {secret}")),
                Err(error) => out.warnings.push(format!(
                    "warning: failed to bridge secret {secret}: {error}"
                )),
            }
        }
        Ok(out)
    }

    /// Decrypt one `.cred` on the host and create it in the guest.
    fn bridge_one_cred(
        &self,
        instance: &LimaInstance<'_>,
        cred: &Path,
        secret: &str,
    ) -> Result<(), ExecError> {
        let value = agentcage_exec::tools::creds::SystemdCreds::new(self.runner)
            .decrypt(&cred.display().to_string())?;
        replace_guest_secret(instance, secret, &value)
    }

    /// Read one host secret back and create it in the guest.
    fn bridge_one_podman_secret(
        instance: &LimaInstance<'_>,
        host: &agentcage_exec::tools::podman::Podman<'_>,
        secret: &str,
    ) -> Result<(), ExecError> {
        let value = host.secret_read(secret)?;
        replace_guest_secret(instance, secret, &value)
    }

    /// `VmBackend._create_pending_secrets` — `--set-secret` values.
    ///
    /// `cage create --set-secret` cannot write to the guest store,
    /// because on a first create there is no guest yet; the values are
    /// parked in `pending_secrets.json` and land here on the first
    /// deploy. The file is **always** removed afterwards, including
    /// when a create failed partway: it holds plaintext, and leaving it
    /// behind would mean credentials sitting in the state directory
    /// after the deploy that needed them.
    ///
    /// # Errors
    ///
    /// [`ExecError`] from a guest command. The file is deleted first —
    /// the Python's `finally` — so an error does not leave it on disk.
    pub fn create_pending_secrets(&self, name: &str) -> Result<Vec<String>, ExecError> {
        let path = self.paths.pending_secrets_path(name);
        let Ok(text) = fs::read_to_string(&path) else {
            return Ok(Vec::new());
        };
        let Ok(pending) = serde_json::from_str::<Vec<(String, String)>>(&text) else {
            let _ = fs::remove_file(&path);
            return Ok(Vec::new());
        };
        let instance = self.instance(name);
        let mut messages = Vec::new();
        let mut result = Ok(());
        for (key, value) in pending {
            let secret = format!("{name}.{key}");
            if let Err(error) = replace_guest_secret(&instance, &secret, &value) {
                result = Err(error);
                break;
            }
            messages.push(format!("  Secret '{secret}' set in VM."));
        }
        let _ = fs::remove_file(&path);
        result.map(|()| messages)
    }

    /// `VmBackend._resolve_source_secrets` — `source:` schemes straight
    /// into the guest store.
    ///
    /// Why this exists at all, given `resolve_and_populate`: that
    /// function writes into a *host* podman store and the create path
    /// only calls it for `isolation: container`, while
    /// [`Self::bridge_secrets`] can only mirror a host store that a
    /// macOS host does not have. Without this, a `source:`-schemed
    /// secret — most visibly `domains.auto`'s decider `api_key` — is
    /// referenced by the egress unit and never created, and the egress
    /// dies at start with `no such secret`, taking the cage with it.
    ///
    /// Sources are collected in the Python's order — the injection
    /// rules, then each relay's user and password, then the decider and
    /// watcher API keys — and the first occurrence of an env name wins.
    /// Then the store-held values (`agentcage secret set`, no scheme),
    /// which on a macOS host live in the login keychain and have no
    /// other route into the guest.
    ///
    /// Best-effort throughout: an unresolvable source warns rather than
    /// aborting the deploy, and the egress's `ExecStartPre` tolerates a
    /// missing staged file — the decider then fails closed, which is
    /// the designed posture.
    ///
    /// # Errors
    ///
    /// Only [`ExecError`] from a `limactl` that could not be run.
    pub fn resolve_source_secrets(
        &self,
        name: &str,
        config: Option<&Config>,
        host: &crate::secrets::SecretHost<'_>,
    ) -> Result<Bridged, ExecError> {
        let mut out = Bridged::default();
        // `_deploy_cage` is also reached on paths with no live config
        // (restart, reconcile); there is nothing to resolve without
        // one, and the guest secrets already created stay valid.
        let Some(config) = config else {
            return Ok(out);
        };

        let instance = self.instance(name);
        let state_dir = self.paths.deployment_dir(name);
        let mut seen: BTreeSet<String> = BTreeSet::new();

        for (env_name, source) in source_secrets(config) {
            if !seen.insert(env_name.clone()) {
                continue;
            }
            let value = match host.resolve(&source, &env_name, &state_dir) {
                Ok(crate::secrets::Resolution::Resolved(value)) => value,
                // `if result.action != ResolveAction.RESOLVED: continue`
                // — a quadlet-handled `.cred` or an existing podman
                // secret needs nothing from here.
                Ok(_) => continue,
                Err(error) => {
                    let scheme = source.split(':').next().unwrap_or("");
                    out.warnings.push(format!(
                        "warning: could not resolve secret '{env_name}' \
                         ({scheme}: source): {error}"
                    ));
                    continue;
                }
            };
            let secret = format!("{name}.{env_name}");
            if let Err(error) = replace_guest_secret(&instance, &secret, &value) {
                out.warnings.push(format!(
                    "warning: failed to create secret {secret} in the VM: {error}"
                ));
            }
        }
        Ok(out)
    }

    /// The store-held half of [`Self::resolve_source_secrets`].
    ///
    /// Separate because the store is the caller's to build — it may be
    /// a keychain, a systemd-creds scope or a plaintext file, and
    /// `resolve_store` needs the config to choose. `skip` carries the
    /// env names the source pass already placed, so a value is not
    /// written twice.
    ///
    /// # Errors
    ///
    /// Only [`ExecError`] from a `limactl` that could not be run.
    pub fn bridge_store_secrets(
        &self,
        name: &str,
        config: &Config,
        store: &dyn crate::secrets::SecretStore,
        skip: &BTreeSet<String>,
    ) -> Result<Bridged, ExecError> {
        let mut out = Bridged::default();
        let instance = self.instance(name);
        let state_dir = self.paths.deployment_dir(name);

        let mut wanted = crate::services::expected_secrets(config);
        for (enabled, api_key) in [
            (
                config.agents.decider.enable,
                &config.agents.decider.llm.api_key,
            ),
            (
                config.agents.watcher.enable,
                &config.agents.watcher.llm.api_key,
            ),
        ] {
            if !enabled {
                continue;
            }
            if let Some((_, var)) = api_key.split_once(':') {
                if !var.is_empty() && !wanted.iter().any(|name| name == var) {
                    wanted.push(var.to_owned());
                }
            }
        }

        let mut seen = skip.clone();
        for env_name in wanted {
            if seen.contains(&env_name) {
                continue;
            }
            let Ok(Some(value)) = store.get(name, &env_name, &state_dir) else {
                continue;
            };
            seen.insert(env_name.clone());
            let secret = format!("{name}.{env_name}");
            if let Err(error) = replace_guest_secret(&instance, &secret, &value) {
                out.warnings.push(format!(
                    "warning: failed to create secret {secret} in the VM: {error}"
                ));
            }
        }
        Ok(out)
    }

    // ── argv builders ────────────────────────────────────────

    /// `VmBackend.exec_argv` — a `podman exec` inside the guest.
    ///
    /// Three details this shares with the container backend's builder,
    /// for the reasons written there: `-u` is explicit because the cage
    /// quadlet's `User=` may be empty and `podman exec` would otherwise
    /// inherit the image's `USER`; the gid is pinned so a busybox or
    /// scratch image with no uid-1000 passwd entry does not default to
    /// gid 0; and a cage session carries the *current* placeholders, so
    /// a secret declared after the cage started is usable in a new
    /// session without a restart.
    ///
    /// `--workdir /` is on the outer `limactl shell` rather than the
    /// inner `podman exec`: the caller hands this argv to `execvp`, so
    /// it bypasses [`LimaInstance::shell_command`] and has to carry the
    /// flag itself. Note it does **not** carry `--tty=false`, because
    /// this is the one path that may want a PTY.
    #[must_use]
    pub fn exec_argv(
        &self,
        name: &str,
        service: &str,
        command: &[String],
        interactive: bool,
        as_root: bool,
    ) -> Vec<String> {
        let mut argv = self.shell_prefix(name);
        argv.extend(
            [
                "podman",
                "exec",
                "-u",
                if as_root { "0:0" } else { "1000:1000" },
            ]
            .map(str::to_string),
        );
        if interactive {
            argv.push("-it".to_owned());
        }
        if service == "cage" {
            for (env, placeholder) in crate::services::current_placeholders(self.paths, name) {
                argv.push("--env".to_owned());
                argv.push(format!("{env}={placeholder}"));
            }
        }
        argv.push(format!("{name}-{service}"));
        argv.extend(command.iter().cloned());
        argv
    }

    /// `VmBackend.logs_argv` — the guest's journal for a cage's units.
    ///
    /// `--user-unit`, not `--user -u`: conmon routes a container's
    /// output to the *system* journal even when the unit that started
    /// it is a `--user` one, and only `--user-unit` matches both.
    ///
    /// The journal command is `shlex.join`ed into a single argument
    /// because it runs under `sg systemd-journal -c`. The `sg` is not
    /// decoration: Lima's persistent SSH `ControlMaster` establishes the
    /// session before provisioning runs `usermod -aG systemd-journal`,
    /// so the SSH session's groups are stale for the life of the guest
    /// and the journal is unreadable without re-entering the group.
    #[must_use]
    pub fn logs_argv(
        &self,
        name: &str,
        services: &[String],
        follow: bool,
        lines: u64,
    ) -> Vec<String> {
        let mut journal = vec!["journalctl".to_owned(), "-o".to_owned(), "cat".to_owned()];
        for service in services {
            journal.push("--user-unit".to_owned());
            journal.push(format!("{name}-{service}"));
        }
        if follow {
            journal.push("-f".to_owned());
        }
        if lines != 0 {
            journal.push("-n".to_owned());
            journal.push(lines.to_string());
        }
        self.journal_argv(name, &journal)
    }

    /// `VmBackend.audit_argv` — the egress unit's journal.
    ///
    /// One `--user-unit` filter catches both producers: mitmproxy's
    /// audit lines and dnsmasq's both flow through the egress
    /// container's stderr into conmon and then the journal.
    #[must_use]
    pub fn audit_argv(&self, name: &str, since: Option<&str>, follow: bool) -> Vec<String> {
        let mut journal = vec![
            "journalctl".to_owned(),
            "--user-unit".to_owned(),
            format!("{name}-egress"),
            "-o".to_owned(),
            "cat".to_owned(),
        ];
        if let Some(since) = since {
            journal.push("--since".to_owned());
            journal.push(since.to_owned());
        }
        if follow {
            journal.push("-f".to_owned());
        } else {
            // Over-read: many journal lines are not audit entries.
            journal.push("-n".to_owned());
            journal.push("10000".to_owned());
        }
        self.journal_argv(name, &journal)
    }

    /// `limactl shell … -- sg systemd-journal -c '<journalctl …>'`.
    fn journal_argv(&self, name: &str, journal: &[String]) -> Vec<String> {
        let mut argv = self.shell_prefix(name);
        argv.extend(["sg", "systemd-journal", "-c"].map(str::to_string));
        argv.push(shlex_join(journal));
        argv
    }

    /// The `limactl shell --workdir / <instance> --` the three argv
    /// builders share.
    fn shell_prefix(&self, name: &str) -> Vec<String> {
        vec![
            "limactl".to_owned(),
            "shell".to_owned(),
            "--workdir".to_owned(),
            "/".to_owned(),
            self.instance(name).name().to_owned(),
            "--".to_owned(),
        ]
    }

    /// `limactl copy -r <src>/. <instance>:<dst>/`.
    ///
    /// Built up here with the other argv rather than beside its caller
    /// in the execution half, because it is argv. The guest's home is not
    /// a Lima mount — only `~/.config/agentcage` and
    /// `~/.local/share/agentcage` are shared — so the podman build
    /// context cannot be read from the host filesystem and has to be
    /// copied in. The trailing `/.` and `/` are rsync-style and are
    /// what make this copy the directory's *contents*.
    #[must_use]
    pub fn copy_build_context_argv(
        &self,
        name: &str,
        source: &Path,
        destination: &str,
    ) -> Vec<String> {
        vec![
            "limactl".to_owned(),
            "copy".to_owned(),
            "-r".to_owned(),
            format!("{}/.", source.display()),
            format!("{}:{destination}/", self.instance(name).name()),
        ]
    }

    /// The in-guest egress build, as the argv `_exec_build` runs.
    ///
    /// The six `--cap-add`s are the container backend's
    /// [`EGRESS_BUILD_CAPS`], in that order, because it is the order
    /// that reaches argv. `flags` carries `--no-cache` / `--pull=always`
    /// when `cage create --no-cache` / `--pull` asked for them.
    #[must_use]
    pub fn egress_build_argv(&self, flags: &[String]) -> Vec<String> {
        build_argv(
            flags,
            &format!("agentcage-egress:{}", self.version),
            &format!("{VM_BUILD_DIR}/containers/Containerfile.egress"),
            VM_BUILD_DIR,
        )
    }

    /// The in-guest build of a scaffold's cage image.
    ///
    /// `containerfile` is the basename inside the copied scaffold
    /// directory, which is where `_build_cage_image_in_vm` puts it.
    #[must_use]
    pub fn cage_build_argv(
        &self,
        image: &str,
        containerfile: &str,
        flags: &[String],
    ) -> Vec<String> {
        let scaffold = format!("{VM_BUILD_DIR}/scaffold");
        build_argv(
            flags,
            image,
            &format!("{scaffold}/{containerfile}"),
            &scaffold,
        )
    }

    /// The four units `_deploy_cage` starts before the cage itself.
    ///
    /// Order is the dependency order and is load-bearing: the cage's
    /// `ExecStartPre` polls for mitmproxy's CA certificate, which the
    /// egress generates on its first run, so racing the two turns a
    /// first `cage create` into a near-certain spurious failure.
    #[must_use]
    pub fn infra_services(name: &str) -> [String; 4] {
        [
            format!("{name}-net-network"),
            format!("{name}-certs-volume"),
            format!("{name}-public-certs-volume"),
            format!("{name}-egress"),
        ]
    }

    /// `systemctl --user <action> <unit>.service`, as run in the guest.
    #[must_use]
    pub fn systemctl_argv(action: &str, unit: &str) -> Vec<String> {
        vec![
            "systemctl".to_owned(),
            "--user".to_owned(),
            action.to_owned(),
            format!("{unit}.service"),
        ]
    }

    // ── state queries ────────────────────────────────────────

    /// `VmBackend.is_running` — is that service up inside the guest?
    ///
    /// A guest that is not running answers `false` without asking it
    /// anything.
    #[must_use]
    pub fn is_running(&self, name: &str, service: &str) -> bool {
        let instance = self.instance(name);
        if !instance.is_running().unwrap_or(false) {
            return false;
        }
        instance
            .exec(
                &Self::systemctl_argv("is-active", &format!("{name}-{service}")),
                false,
            )
            .is_ok_and(|out| out.stdout_text().trim() == "active")
    }

    /// `VmBackend.has_resources` — does this cage have a Lima instance?
    ///
    /// A host with no `limactl` answers `false` rather than erroring,
    /// which is what lets `cage destroy` run on a machine where Lima
    /// was uninstalled after the cage was created.
    #[must_use]
    pub fn has_resources(&self, name: &str) -> bool {
        if !self.runner.has("limactl") {
            return false;
        }
        self.instance(name).exists().unwrap_or(false)
    }

    /// `VmBackend.destroy_resources` — the guest and this cage's config.
    ///
    /// Returns the removal descriptions `cage destroy` prints, in the
    /// Python's order. `keep_secrets` is accepted and unused, as in the
    /// Python: the secret store went with the guest.
    ///
    /// The shared `~/.config/agentcage/lima` directory itself survives;
    /// only `lima.yaml` and `quadlets/` inside it are removed.
    ///
    /// # Errors
    ///
    /// [`BackendError::Assets`] if a file could not be removed.
    pub fn destroy_resources(
        &self,
        name: &str,
        _keep_secrets: bool,
    ) -> Result<Vec<String>, BackendError> {
        let mut removed = Vec::new();
        let instance = self.instance(name);
        if instance.exists().unwrap_or(false) {
            instance.delete()?;
            removed.push(format!("lima-instance:{}", instance.name()));
        }

        let lima_yaml = self.lima_config_path();
        if lima_yaml.exists() {
            fs::remove_file(&lima_yaml).map_err(BackendError::Assets)?;
            removed.push(format!("config:{}", lima_yaml.display()));
        }
        let quadlets = self.host_quadlet_dir();
        if quadlets.exists() {
            fs::remove_dir_all(&quadlets).map_err(BackendError::Assets)?;
            removed.push(format!("quadlets:{}", quadlets.display()));
        }
        Ok(removed)
    }

    // ── execution (PR E4) ────────────────────────────────────

    /// `VmBackend.ensure_ready` — nothing to bring up ahead of time.
    ///
    /// The guest is created and started on demand inside [`Self::start`];
    /// a missing `limactl` or QEMU is [`Self::check_prerequisites`]'s to
    /// report.
    pub const fn ensure_ready(&self) {}

    /// `VmBackend.start` — create the guest if it is absent, boot it if
    /// it is down, then deploy into it.
    ///
    /// `quiet` is accepted and ignored, as the Python's is: none of the
    /// progress lines below are guarded by it, and a `cage update` that
    /// printed nothing for four minutes of guest provisioning would be
    /// indistinguishable from a hang.
    ///
    /// # Errors
    ///
    /// [`BackendError::Exec`] if `limactl create` or `limactl start`
    /// failed, and whatever [`Self::deploy_cage`] returns.
    pub fn start(&self, name: &str, _quiet: bool) -> Result<(), BackendError> {
        let instance = self.instance(name);
        let config_path = self.lima_config_path();

        if !instance.exists()? {
            println!("Creating Lima VM instance...");
            let phase = crate::timing::Phase::start("lima.create", Some(name));
            let created = instance.create(&config_path.display().to_string());
            drop(phase);
            created?;
            println!("VM created. Starting...");
        }

        if !instance.is_running()? {
            println!("Starting Lima VM...");
            let phase = crate::timing::Phase::start("lima.start", Some(name));
            let started = instance.start();
            drop(phase);
            started?;
            println!("VM started and provisioned.");
        }

        // `try: ... except Exception: pass` — a cage whose stored config
        // will not load still deploys; `deploy_cage` simply has nothing
        // to resolve `source:` secrets from.
        let config = self
            .paths
            .load_deployment_config(name, &crate::hostenv::RealHost)
            .ok();
        self.deploy_cage(name, config.as_ref())?;
        println!("Started {name} (Lima VM)");
        Ok(())
    }

    /// `VmBackend.stop` — stop the cage's units, then the guest itself.
    ///
    /// The in-guest stops are unchecked and their failures swallowed:
    /// the guest is about to be powered off, so a unit that would not
    /// stop cleanly is about to stop uncleanly anyway. Stopping them
    /// first is what gives podman a chance to write the containers'
    /// final journal lines.
    pub fn stop(&self, name: &str) {
        let instance = self.instance(name);
        if !instance.is_running().unwrap_or(false) {
            return;
        }
        for service in SERVICE_NAMES {
            let _ = instance.exec(
                &Self::systemctl_argv("stop", &format!("{name}-{service}")),
                false,
            );
        }
        if let Err(error) = instance.stop() {
            eprintln!("warning: failed to stop the Lima VM for {name}: {error}");
        }
    }

    /// `VmBackend.restart` — stop, then start.
    ///
    /// A full guest power cycle, not a `systemctl restart`. It is the
    /// Python's, and it is what makes `cage restart` on this backend
    /// adopt a regenerated `lima.yaml`.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::start`] returns.
    pub fn restart(&self, name: &str) -> Result<(), BackendError> {
        self.stop(name);
        self.start(name, false)
    }

    /// `VmBackend.build_artifacts` — the egress and cage images, built
    /// **inside** the guest.
    ///
    /// A guest that is not running is not an error: on a first
    /// `cage create` the instance does not exist yet, and
    /// [`Self::start`] builds from [`Self::deploy_cage`] a moment later.
    /// Saying so out loud matters — the alternative is a `cage create`
    /// that appears to skip the build entirely.
    ///
    /// The build context is copied in with `limactl copy` rather than
    /// read through a mount: only `~/.config/agentcage` and
    /// `~/.local/share/agentcage` are shared with the guest, and the
    /// context is neither. On a single binary it does not exist on disk
    /// at all until [`agentcage_assets::extract::build_context`]
    /// materializes it, which is §2.1 of the plan and the one structural
    /// difference from the Python here.
    ///
    /// # Errors
    ///
    /// [`BackendError::Assets`] if the embedded tree cannot be
    /// extracted, [`BackendError::Exec`] if a guest command could not be
    /// run, [`BackendError::Failed`] if a build exited non-zero.
    pub fn build_artifacts(
        &self,
        config: Option<&Config>,
        deploy_name: &str,
        no_cache: bool,
        pull: bool,
        _quiet: bool,
    ) -> Result<(), BackendError> {
        let instance = self.instance(deploy_name);
        if !instance.is_running()? {
            println!("VM is not running — skipping image build (will build on start)");
            return Ok(());
        }

        let context = agentcage_assets::extract::build_context().map_err(BackendError::Assets)?;

        println!("Copying build context into VM...");
        let _ = instance.exec(&["rm", "-rf", VM_BUILD_DIR].map(str::to_string), false);
        instance.exec(&["mkdir", "-p", VM_BUILD_DIR].map(str::to_string), true)?;
        let phase = crate::timing::Phase::start("copy.build_context", Some(deploy_name));
        let copied =
            self.run_checked(&self.copy_build_context_argv(deploy_name, &context, VM_BUILD_DIR));
        drop(phase);
        copied?;

        let mut flags: Vec<String> = Vec::new();
        if no_cache {
            flags.push("--no-cache".to_owned());
        }
        if pull {
            flags.push("--pull=always".to_owned());
        }

        // Issue #319's safety net, in front of the FIRST in-guest podman
        // invocation. Provisioning is what guarantees the user D-Bus;
        // this only catches a guest that slipped through, and turns
        // "podman build failed" into a message that names the
        // precondition. Normally one probe and no sleep.
        let phase = crate::timing::Phase::start("wait.user_session", Some(deploy_name));
        Self::wait_user_session_ready(&instance);
        drop(phase);

        let tag = format!("agentcage-egress:{}", self.version);
        println!(
            "Building egress image inside VM (agentcage-egress:{})...",
            self.version
        );
        let phase = crate::timing::Phase::start("build.egress", Some(deploy_name));
        let built = Self::exec_build(
            &instance,
            &self.egress_build_argv(&flags),
            &format!("build of {tag}"),
        );
        drop(phase);
        built?;

        if let Some(config) = config {
            if !config.container.image.is_empty() {
                if config.container.build.containerfile.is_empty() {
                    println!("Pulling {} inside VM...", config.container.image);
                    let phase = crate::timing::Phase::start("pull.cage", Some(deploy_name));
                    let _ = instance.exec(
                        &["podman", "pull", &config.container.image].map(str::to_string),
                        false,
                    );
                    drop(phase);
                } else {
                    let phase = crate::timing::Phase::start("build.cage", Some(deploy_name));
                    let built = self.build_cage_image_in_vm(&instance, config, deploy_name, &flags);
                    drop(phase);
                    built?;
                }
            }
        }

        let _ = instance.exec(&["rm", "-rf", VM_BUILD_DIR].map(str::to_string), false);
        Ok(())
    }

    /// `_build_cage_image_in_vm` — copy a scaffold's context in and
    /// build it.
    ///
    /// The Containerfile is the **staged** copy in the cage's state
    /// directory, which is what `cage create` and `cage update` froze;
    /// the scaffold source is the fallback for a cage whose staging did
    /// not happen. A Containerfile found at neither is a warning rather
    /// than a failure, because the cage image may simply already be in
    /// the guest — the Python's shape, and the cage unit's own start
    /// will say otherwise if it is not.
    fn build_cage_image_in_vm(
        &self,
        instance: &LimaInstance<'_>,
        config: &Config,
        deploy_name: &str,
        flags: &[String],
    ) -> Result<(), BackendError> {
        let declared = &config.container.build.containerfile;
        let basename = Path::new(declared)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let state_dir = self.paths.deployment_dir(deploy_name);

        let mut containerfile = state_dir.join(&basename);
        if !containerfile.exists() {
            let scaffold = self
                .paths
                .load_metadata(deploy_name)
                .ok()
                .and_then(|meta| {
                    meta.get("scaffold")
                        .and_then(agentcage_core::har::json::Json::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_default();
            if !scaffold.is_empty() {
                let root =
                    agentcage_assets::extract::ensure_extracted().map_err(BackendError::Assets)?;
                containerfile = root.join("scaffolds").join(&scaffold).join(declared);
            }
        }
        if !containerfile.exists() {
            eprintln!(
                "warning: Containerfile not found for {}",
                config.container.image
            );
            return Ok(());
        }

        let source = containerfile.parent().unwrap_or(Path::new("."));
        let guest_scaffold = format!("{VM_BUILD_DIR}/scaffold");
        instance.exec(&["mkdir", "-p", &guest_scaffold].map(str::to_string), true)?;
        self.run_checked(&self.copy_build_context_argv(deploy_name, source, &guest_scaffold))?;

        println!("Building {} inside VM...", config.container.image);
        let name = containerfile
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self::exec_build(
            instance,
            &self.cage_build_argv(&config.container.image, &name, flags),
            &format!("build of {}", config.container.image),
        )
    }

    /// `VmBackend._deploy_cage` — everything between a booted guest and
    /// a running cage.
    ///
    /// The order is the Python's and every step of it is load-bearing:
    ///
    /// 1. Quadlets into the guest's `~/.config/containers/systemd`.
    /// 2. The guest-local mirrors of `proxy-config.yaml`,
    ///    `dns-allowlist.conf` and `placeholders.env`, plus the grants
    ///    overlay directory — which must exist *before* the egress
    ///    unit's `ExecStartPre` chgrps it.
    /// 3. Secrets: the host's bridged in, the pending ones created, the
    ///    `source:`-schemed ones resolved straight into the guest store.
    /// 4. The in-guest image builds.
    /// 5. `daemon-reload`, then the infrastructure units, then — only
    ///    once the egress is **active** — the cage.
    ///
    /// Step 5's ordering is the one a reader is most likely to tidy
    /// away. The cage unit's `ExecStartPre` is a 30-attempt poll for
    /// mitmproxy's CA certificate, which the egress generates on its
    /// first run; starting the two together turns a first `cage create`
    /// into a near-certain spurious failure that the operator reads as a
    /// real one.
    ///
    /// # Errors
    ///
    /// [`BackendError::Failed`] when the egress never becomes active or
    /// the cage service will not start — after the unit's own
    /// diagnostics have been printed. [`BackendError::Exec`] from a
    /// guest command that could not be run.
    pub fn deploy_cage(&self, name: &str, config: Option<&Config>) -> Result<(), BackendError> {
        if !self.host_quadlet_dir().is_dir() {
            return Ok(());
        }
        let instance = self.instance(name);

        let phase = crate::timing::Phase::start("deploy.quadlets", Some(name));
        let pushed = self.push_quadlets(name);
        drop(phase);
        pushed?;

        let phase = crate::timing::Phase::start("deploy.vm_local_config", Some(name));
        let mirrored = self
            .push_config_files(name)
            .and_then(|()| self.ensure_grants_dir(name));
        drop(phase);
        mirrored?;

        let phase = crate::timing::Phase::start("deploy.bridge_secrets", Some(name));
        let bridged = self.bridge_secrets(name);
        drop(phase);
        bridged?.report();

        let phase = crate::timing::Phase::start("deploy.pending_secrets", Some(name));
        let pending = self.create_pending_secrets(name);
        drop(phase);
        for message in pending? {
            println!("{message}");
        }

        let phase = crate::timing::Phase::start("deploy.source_secrets", Some(name));
        let resolved = self.stage_secrets(name, config);
        drop(phase);
        resolved?.report();

        self.build_artifacts(config, name, false, false, false)?;

        instance.exec(
            &["systemctl", "--user", "daemon-reload"].map(str::to_string),
            true,
        )?;

        let infra = Self::infra_services(name);
        let phase = crate::timing::Phase::start("systemd.start", Some(name));
        for service in &infra {
            Self::systemctl_start(&instance, service, false);
        }
        let pending = Self::wait_infra_active(&instance, &infra);
        let _ = instance.exec(
            &["systemctl", "--user", "reset-failed"].map(str::to_string),
            false,
        );
        for service in &pending {
            println!("Retrying {service}...");
            Self::systemctl_start(&instance, service, true);
        }
        drop(phase);

        println!("Waiting for egress to be ready...");
        let egress = format!("{name}-egress");
        let phase = crate::timing::Phase::start("systemd.wait_egress", Some(name));
        let active = Self::wait_active(
            &instance,
            &egress,
            PROXY_READINESS_TIMEOUT,
            PROXY_READINESS_POLL_INTERVAL,
        );
        drop(phase);
        if !active {
            // Not "start the cage anyway": its `ExecStartPre` would
            // spin for 30s and fail on the same root cause, with the
            // egress's actual reason lost behind it.
            Self::dump_service_failure(&instance, &egress);
            return Err(BackendError::Failed(format!(
                "egress {egress} did not become active within {}s; cage not started",
                PROXY_READINESS_TIMEOUT.as_secs()
            )));
        }

        let cage = format!("{name}-cage");
        let phase = crate::timing::Phase::start("systemd.start_cage", Some(name));
        let outcome = Self::start_cage_service(&instance, &cage);
        drop(phase);
        outcome
    }

    /// The last step of [`Self::deploy_cage`]: start the cage, and
    /// insist that it came up.
    ///
    /// [`Self::systemctl_start`] surfaces a failure but does not raise —
    /// the infrastructure loop above needs to continue past one dead
    /// unit. The cage is different: a deploy without it is meaningless,
    /// and before this check `cage create` printed "Updated cage X" over
    /// a cage whose status was `failed`.
    fn start_cage_service(instance: &LimaInstance<'_>, cage: &str) -> Result<(), BackendError> {
        if Self::is_active(instance, cage) {
            return Ok(());
        }
        let _ = instance.exec(
            &["systemctl", "--user", "reset-failed"].map(str::to_string),
            false,
        );
        Self::systemctl_start(instance, cage, false);
        let state = Self::unit_state(instance, cage);
        if state == "active" {
            return Ok(());
        }
        Err(BackendError::Failed(format!(
            "cage {cage} failed to start (state={}); see diagnostic output above",
            if state.is_empty() { "unknown" } else { &state }
        )))
    }

    /// `_resolve_source_secrets` — both halves of it.
    ///
    /// E1 split the Python's one function in two so the store half could
    /// take a caller-chosen [`crate::secrets::SecretStore`]; this is the
    /// seam that puts them back together, with the `seen` set the
    /// Python shares between them.
    ///
    /// A store that cannot be resolved at all is the Python's bare
    /// `except: return` — it means no encrypting backend is usable
    /// here, and the source pass has already done what it could.
    fn stage_secrets(&self, name: &str, config: Option<&Config>) -> Result<Bridged, ExecError> {
        let Some(config) = config else {
            return Ok(Bridged::default());
        };
        let host = crate::secrets::SecretHost::detect(self.runner, &SYSTEM_ENVIRONMENT);

        let mut out = self.resolve_source_secrets(name, Some(config), &host)?;
        let skip = source_secret_env_names(config);

        let podman = agentcage_exec::tools::podman::Podman::new(self.runner);
        let Ok(store) = crate::secrets::resolve_store(
            config,
            &host,
            Some(&podman),
            "",
            crate::secrets::Platform::host(),
        ) else {
            return Ok(out);
        };
        let stored = self.bridge_store_secrets(name, config, store.as_ref(), &skip)?;
        out.messages.extend(stored.messages);
        out.warnings.extend(stored.warnings);
        Ok(out)
    }

    // ── the waits ────────────────────────────────────────────

    /// `_wait_infra_active` — poll until every unit is active, or the
    /// deadline.
    ///
    /// Returns the units still not active, which the caller retries.
    /// This replaced a blanket `sleep(5)`: on a warm restart the units
    /// are up in a few hundred milliseconds, and the deadline is
    /// unchanged so a cold run is not affected.
    fn wait_infra_active(instance: &LimaInstance<'_>, services: &[String]) -> Vec<String> {
        let deadline = Instant::now() + VM_SERVICE_STARTUP_DELAY;
        let mut pending: Vec<String> = services.to_vec();
        while !pending.is_empty() {
            pending.retain(|service| !Self::is_active(instance, service));
            if pending.is_empty() || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(VM_SERVICE_STARTUP_POLL_INTERVAL);
        }
        pending
    }

    /// Poll one unit until it is `active`, or the deadline.
    fn wait_active(
        instance: &LimaInstance<'_>,
        unit: &str,
        timeout: Duration,
        interval: Duration,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if Self::is_active(instance, unit) {
                return true;
            }
            std::thread::sleep(interval);
        }
        false
    }

    /// `systemctl --user is-active <unit>.service`, as a bool.
    fn is_active(instance: &LimaInstance<'_>, unit: &str) -> bool {
        Self::unit_state(instance, unit) == "active"
    }

    /// The unit's state token, or `""` when the guest could not answer.
    fn unit_state(instance: &LimaInstance<'_>, unit: &str) -> String {
        instance
            .exec(&Self::systemctl_argv("is-active", unit), false)
            .map(|out| out.stdout_trimmed())
            .unwrap_or_default()
    }

    /// `_wait_user_session_ready` — can rootless podman run a container
    /// yet?
    ///
    /// Rootless podman defaults to the systemd cgroup manager, which
    /// needs the guest user's D-Bus at `/run/user/<uid>/bus`. Without it
    /// every container creation dies at its first `RUN` step with
    /// `sd-bus call: Interactive authentication required` — issue #319.
    ///
    /// The **cause** is fixed in provisioning, not here: apt installs
    /// `dbus-user-session` underneath a `user@<uid>.service` that Lima's
    /// own SSH bring-up already started, and a running user manager never
    /// loads a socket unit that appears beneath it, so the bus stays
    /// absent for the whole boot. `provision.sh.j2` restarts that
    /// manager. This is defense in depth and should resolve on its first
    /// probe; the ceiling is short precisely because a guest that needs
    /// to wait is in a state waiting cannot repair.
    ///
    /// The caller proceeds either way. A timeout is a hint, not a
    /// verdict, and failing here would throw away the real podman
    /// diagnostic [`Self::exec_build`] surfaces (#322).
    ///
    /// Deliberately **not** probed: `loginctl show-user … Linger`. It is
    /// a logind D-Bus round-trip, and the provisioning script documents
    /// logind wedging during bring-up with its calls blocking for 25s —
    /// a poll loop over that turns a hiccup into a multi-minute stall.
    fn wait_user_session_ready(instance: &LimaInstance<'_>) -> bool {
        let deadline = Instant::now() + VM_USER_SESSION_TIMEOUT;
        let mut announced = false;
        loop {
            let state = Self::probe_user_session(instance);
            if USER_SESSION_READY_STATES.contains(&state.as_str()) {
                if announced {
                    println!("Guest systemd user session ready ({state}).");
                }
                return true;
            }
            if Instant::now() >= deadline {
                crate::output::pause_active_spinner(|| {
                    eprintln!(
                        "warning: the guest's systemd user D-Bus \
                         (/run/user/<uid>/bus) is still absent after {}s; last \
                         probe reported '{state}'. Rootless podman needs it for \
                         its systemd cgroup manager. This usually means the \
                         guest's user dbus.socket never came up (a provisioning \
                         fault, not a slow start — see #319), so recreating the \
                         VM is more likely to help than retrying. Building \
                         anyway — if the build fails, podman's own error is \
                         printed below.",
                        VM_USER_SESSION_TIMEOUT.as_secs()
                    );
                });
                return false;
            }
            if !announced {
                announced = true;
                println!(
                    "Waiting for the guest systemd user session \
                     (rootless podman needs its user D-Bus; state: {state})..."
                );
            }
            std::thread::sleep(VM_USER_SESSION_POLL_INTERVAL);
        }
    }

    /// One round-trip of [`USER_SESSION_PROBE`].
    ///
    /// Never fails: this runs on the happy path in front of a build, so
    /// a flaky `limactl shell` must degrade to "not ready yet" rather
    /// than pre-empting the build it exists to protect.
    fn probe_user_session(instance: &LimaInstance<'_>) -> String {
        let Ok(out) = instance.exec(&bash_c(USER_SESSION_PROBE), false) else {
            return "probe failed".to_owned();
        };
        let state = out.stdout_trimmed();
        if state.is_empty() {
            "unknown".to_owned()
        } else {
            state
        }
    }

    // ── the diagnostics ──────────────────────────────────────

    /// `_systemctl_start` — start (or restart) a unit, and say why if it
    /// would not.
    ///
    /// Does not fail the deploy. The predecessor of this printed the
    /// `CalledProcessError` repr, which named the command and the exit
    /// code and told the operator nothing about the unit.
    fn systemctl_start(instance: &LimaInstance<'_>, unit: &str, restart: bool) {
        let action = if restart { "restart" } else { "start" };
        match instance.exec(&Self::systemctl_argv(action, unit), false) {
            Ok(out) if out.success() => {}
            Ok(out) => {
                eprintln!("warning: failed to {action} {unit}");
                let stderr = out.stderr_text();
                if !stderr.is_empty() {
                    eprintln!("{}", stderr.trim_end());
                }
                Self::dump_service_failure(instance, unit);
            }
            Err(error) => eprintln!("warning: failed to {action} {unit}: {error}"),
        }
    }

    /// `_dump_service_failure` — `systemctl status` plus the unit's last
    /// 40 journal lines.
    ///
    /// Best-effort throughout: this runs on an error path and the
    /// original failure is what matters, so a diagnostic that fails is
    /// swallowed rather than replacing it.
    ///
    /// The journal filter here is `--user -u`, **not** the `--user-unit`
    /// that [`Self::logs_argv`] uses. That is the Python's, and the
    /// difference is real: `--user -u` reads the unit's own systemd
    /// records — "control process exited", "failed with result" — which
    /// is what a unit that never started has to show. `--user-unit`
    /// would reach the container's output, of which there is none.
    fn dump_service_failure(instance: &LimaInstance<'_>, unit: &str) {
        if let Ok(out) = instance.exec(
            &[
                "systemctl",
                "--user",
                "status",
                &format!("{unit}.service"),
                "--no-pager",
                "-l",
            ]
            .map(str::to_string),
            false,
        ) {
            let text = out.stdout_text();
            if !text.is_empty() {
                eprintln!("{}", text.trim_end());
            }
        }
        if let Ok(out) = instance.exec(
            &[
                "journalctl",
                "--user",
                "-u",
                &format!("{unit}.service"),
                "--no-pager",
                "-n",
                "40",
            ]
            .map(str::to_string),
            false,
        ) {
            let text = out.stdout_text();
            if !text.is_empty() {
                eprintln!("{}", text.trim_end());
            }
        }
    }

    /// `_exec_build` — run an in-guest build, surfacing its output when
    /// it fails.
    ///
    /// `LimaInstance::exec` captures, so a failed in-guest `podman
    /// build` used to reach the operator as a bare non-zero exit whose
    /// only content was the (very long) `limactl shell …` command line —
    /// podman's actual error was stranded on the exception and never
    /// printed. Issue #319: a first `cage create` on a fresh host failed
    /// here and the reason could not be determined from agentcage's
    /// output at all.
    ///
    /// A build log is many lines and fights the spinner for the same
    /// terminal line, so the spinner is paused while it is dumped.
    fn exec_build(
        instance: &LimaInstance<'_>,
        command: &[String],
        what: &str,
    ) -> Result<(), BackendError> {
        let out = instance.exec(command, false)?;
        if out.success() {
            return Ok(());
        }
        let stdout = out.stdout_text();
        let stderr = out.stderr_text();
        crate::output::pause_active_spinner(|| {
            eprintln!(
                "error: {what} failed inside the VM (exit status {})",
                out.status.code_or(1)
            );
            let stdout = stdout.trim_end();
            let stderr = stderr.trim_end();
            if !stdout.is_empty() {
                eprintln!("{stdout}");
            }
            if !stderr.is_empty() {
                eprintln!("{stderr}");
            }
            if stdout.is_empty() && stderr.is_empty() {
                eprintln!("(the build produced no output)");
            }
        });
        Err(BackendError::Failed(format!("{what} failed inside the VM")))
    }

    /// One host-side command, checked.
    ///
    /// The two `limactl copy` invocations are the only commands this
    /// module runs on the *host* rather than through
    /// [`LimaInstance::exec`], because a directory copy has no in-guest
    /// equivalent.
    fn run_checked(&self, argv: &[String]) -> Result<(), ExecError> {
        let (program, rest) = argv.split_first().expect("argv is never empty");
        let command = agentcage_exec::Command::new(program.clone()).args(rest.iter().cloned());
        self.runner.run(&command)?.check(program)?;
        Ok(())
    }
}

/// The env names [`VmBackend::resolve_source_secrets`] will have taken.
///
/// The Python's `_resolve_source_secrets` is one function with one
/// `seen` set spanning both halves, and the split into
/// [`VmBackend::resolve_source_secrets`] and
/// [`VmBackend::bridge_store_secrets`] would lose that. It adds a name
/// to `seen` **before** resolving it, so a source that fails to resolve
/// still shadows the store — this returns the same names, which is what
/// the caller passes as the store pass's `skip`.
#[must_use]
pub fn source_secret_env_names(config: &Config) -> BTreeSet<String> {
    source_secrets(config)
        .into_iter()
        .map(|(env_name, _)| env_name)
        .collect()
}

/// What a secret-bridging pass wants to say.
///
/// `agentcage-cli`'s command bodies print; the backend returns. Kept in
/// two lists rather than one because the Python writes the successes to
/// stdout and the failures to stderr, and a caller that merged them
/// would send warnings into a pipe that is being parsed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bridged {
    /// `click.echo(...)` — one per bridged secret.
    pub messages: Vec<String>,
    /// `click.echo(..., err=True)` — one per secret that did not make it.
    pub warnings: Vec<String>,
}

impl Bridged {
    /// Print what the Python printed, where it printed it.
    ///
    /// Successes to stdout and failures to stderr, in that order rather
    /// than interleaved: the two streams are separate pipes by the time
    /// anything reads them, so the original interleaving is not
    /// recoverable and pretending otherwise would only look precise.
    pub fn report(&self) {
        for message in &self.messages {
            println!("{message}");
        }
        for warning in &self.warnings {
            eprintln!("{warning}");
        }
    }
}

/// `podman secret rm` then `podman secret create <name> -`, in the guest.
///
/// The `rm` is unchecked: "there was no such secret" is the normal case
/// on a first deploy, and podman has no replace verb.
fn replace_guest_secret(
    instance: &LimaInstance<'_>,
    secret: &str,
    value: &str,
) -> Result<(), ExecError> {
    instance.exec(
        &["podman", "secret", "rm", secret].map(str::to_string),
        false,
    )?;
    instance.exec_with_secret(
        &["podman", "secret", "create", secret, "-"].map(str::to_string),
        value,
    )?;
    Ok(())
}

/// The `podman build` argv shared by the two in-guest builds.
fn build_argv(flags: &[String], tag: &str, containerfile: &str, context: &str) -> Vec<String> {
    let mut argv = vec!["podman".to_owned(), "build".to_owned()];
    argv.extend(flags.iter().cloned());
    for capability in EGRESS_BUILD_CAPS {
        argv.push(format!("--cap-add={capability}"));
    }
    argv.extend(["-t", tag, "-f", containerfile, context].map(str::to_string));
    argv
}

/// `(env_name, source)` for every `source:`-schemed secret in a config.
///
/// The Python's collection order, which decides which duplicate wins.
fn source_secrets(config: &Config) -> Vec<(String, String)> {
    let mut sources: Vec<(String, String)> = Vec::new();
    for rule in &config.secret_injection {
        if !rule.source.is_empty() {
            sources.push((rule.env.clone(), rule.source.clone()));
        }
    }
    for relay in &config.protocol_relays {
        for source in [&relay.auth.user_source, &relay.auth.password_source] {
            // `scheme, _, var = src.partition(":")` then `if scheme and
            // var` — an unschemed value and a scheme with nothing after
            // it are both skipped.
            if let Some((scheme, var)) = source.split_once(':') {
                if !scheme.is_empty() && !var.is_empty() {
                    sources.push((var.to_owned(), source.clone()));
                }
            }
        }
    }
    // The decider's and watcher's API keys: staged into the guest's
    // secret store, never into the cage's environment, the same
    // egress-only invariant a relay credential has.
    for (enabled, api_key) in [
        (
            config.agents.decider.enable,
            &config.agents.decider.llm.api_key,
        ),
        (
            config.agents.watcher.enable,
            &config.agents.watcher.llm.api_key,
        ),
    ] {
        if !enabled {
            continue;
        }
        if let Some((scheme, var)) = api_key.split_once(':') {
            if !scheme.is_empty() && !var.is_empty() {
                sources.push((var.to_owned(), api_key.clone()));
            }
        }
    }
    sources
}

/// `["bash", "-c", script]`.
fn bash_c(script: &str) -> Vec<String> {
    vec!["bash".to_owned(), "-c".to_owned(), script.to_owned()]
}

/// `["sh", "-c", script]` — what the two guest *readers* use.
///
/// Not `bash`: the probes only need POSIX test and `cat`, and the
/// Python spells them `sh`. The difference is pinned by
/// `test_vm_backend.py`, which dispatches on `cmd[0]`.
fn sh_c(script: &str) -> Vec<String> {
    vec!["sh".to_owned(), "-c".to_owned(), script.to_owned()]
}

/// The base64-decode-into-a-file pipeline, for one file's bytes.
fn decode_into(bytes: &[u8], guest_path: &str) -> String {
    format!(
        "echo '{}' | base64 -d > {}",
        b64_bytes(bytes),
        shlex_quote(guest_path)
    )
}

/// `shlex.join`.
fn shlex_join(parts: &[String]) -> String {
    parts
        .iter()
        .map(|part| shlex_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `os.path.dirname`, for a guest path.
fn dirname(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some(("", _)) => "/",
        Some((head, _)) => head,
        None => "",
    }
}

/// The file's bytes, or `None` when it is not a regular file.
///
/// `p.is_file()` then `p.read_bytes()`, collapsed into one call so the
/// answer cannot change between them.
fn read_if_file(path: &Path) -> Option<Vec<u8>> {
    if !path.is_file() {
        return None;
    }
    fs::read(path).ok()
}
