//! `AppleContainerBackend` — the execution half (docs/history/rust-port-plan.md E5).
//!
//! Two sibling microVMs per cage, started in a fixed order, because
//! each step needs the previous one's result:
//!
//! 1. create the per-cage network (idempotent);
//! 2. stage the secrets, then run `<name>-egress`;
//! 3. wait for the supervisor's readiness marker, then wipe the staged
//!    cleartext — the egress has it in memory by then;
//! 4. read the egress sibling's address;
//! 5. run `<name>` with `AGENTCAGE_EGRESS_IP` so `cage-init.sh` can
//!    point its default route at the sibling.
//!
//! Step 3 before step 4 is not an ordering convenience: the address is
//! populated asynchronously and can still be absent *after* the marker
//! appears, which is why step 4 polls (see [`AppleBackend::container_ip`]).
//!
//! # What is different about this backend, and must stay different
//!
//! * **Secrets are staged to persistent disk.** The container backend
//!   stages into a tmpfs under `$XDG_RUNTIME_DIR`; macOS has neither.
//!   The mitigation is temporal rather than spatial —
//!   [`AppleBackend::wipe_staged_secrets`] removes the cleartext as
//!   soon as the egress is ready, and the durable copy lives in the
//!   keychain — and it must not be "fixed" toward the Linux shape.
//! * **The cage VM never sees the secrets directory.** That is the
//!   whole point of the two-microVM model: `container exec --user 0`
//!   on the cage cannot read an injected secret, because the secret is
//!   in a different VM's filesystem.
//! * **There is no unit manager.** `install_units` writes a JSON
//!   document, `start` reads it back, and the mask-mountpoint
//!   bookkeeping the quadlet backend does in `ExecStartPre` /
//!   `ExecStopPost` happens here instead (see [`super::masks`]).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agentcage_core::apple;
use agentcage_core::config::Config;
use agentcage_core::quadlets::Quadlets;
use agentcage_exec::tools::apple::{AppleContainer, container_networks, container_state};
use agentcage_exec::{CommandRunner, ExecError};
use agentcage_state::Paths;

use crate::backend::BackendError;
use crate::output;

use super::meta::Meta;
use super::run_argv::{CageInputs, EgressPaths, cage_argv, egress_argv};

/// How long to wait for the egress supervisor's readiness marker, and
/// how often to look.
///
/// Module constants for the same reason the Python makes them class
/// attributes: a test has to be able to drive them to ~0 without
/// subclassing.
const READY_TIMEOUT: Duration = Duration::from_secs(30);
/// See [`READY_TIMEOUT`].
const READY_POLL: Duration = Duration::from_millis(100);

/// How long to wait for Apple's network plugin to publish an address.
///
/// Short, because by this point the supervisor is already up: this
/// absorbs the gap between "running" and "has an address", not a boot.
const IP_TIMEOUT: Duration = Duration::from_secs(10);
/// See [`IP_TIMEOUT`].
const IP_POLL: Duration = Duration::from_millis(200);

/// The process environment, for [`crate::secrets::SecretHost`].
///
/// A `static` rather than a local because `SecretHost` borrows it; the
/// vm backend has one of its own for the same reason.
static SYSTEM_ENVIRONMENT: crate::secrets::SystemEnv = crate::secrets::SystemEnv;

/// `isolation: apple-container` — Apple's `container` CLI, two microVMs.
#[derive(Debug)]
pub struct AppleBackend<'a> {
    paths: &'a Paths,
    runner: &'a dyn CommandRunner,
    version: &'a str,
}

impl<'a> AppleBackend<'a> {
    /// A backend bound to this host's paths and runner.
    #[must_use]
    pub fn new(paths: &'a Paths, runner: &'a dyn CommandRunner, version: &'a str) -> Self {
        Self {
            paths,
            runner,
            version,
        }
    }

    /// The `container`(1) wrapper.
    #[must_use]
    pub fn cli(&self) -> AppleContainer<'a> {
        AppleContainer::new(self.runner)
    }

    /// The paths this backend reads and writes.
    ///
    /// Exposed for the dispatch, which reads the live placeholders for
    /// a cage `exec` session and needs the same [`Paths`] this backend
    /// was built with rather than a second one.
    #[must_use]
    pub fn paths(&self) -> &'a Paths {
        self.paths
    }

    /// The runner every `container(1)` call goes through.
    ///
    /// Exposed for [`AppleImages`], which `cage update` builds from the
    /// same runner so a recording fake sees both.
    #[must_use]
    pub fn runner(&self) -> &'a dyn CommandRunner {
        self.runner
    }

    /// The version this backend tags images with.
    #[must_use]
    pub fn version(&self) -> &'a str {
        self.version
    }

    // ── layout ───────────────────────────────────────────────

    /// `unit_dir` — the apple root itself, not a subdirectory of it.
    #[must_use]
    pub fn unit_dir(&self) -> PathBuf {
        self.paths.apple_root().to_path_buf()
    }

    /// `<unit_dir>/<name>.json`.
    #[must_use]
    pub fn unit_path(&self, name: &str) -> PathBuf {
        self.unit_dir().join(format!("{name}.json"))
    }

    /// The container name for a service: `cage` is the cage itself,
    /// `egress` is the sibling.
    ///
    /// An unrecognized service is treated as `cage`, which is the
    /// Python's fall-through — it keeps `cage verify` and `cage status`
    /// working when they iterate a service list this backend did not
    /// produce.
    fn target(name: &str, service: &str) -> String {
        if service == "egress" {
            format!("{name}-egress")
        } else {
            name.to_owned()
        }
    }

    // ── the protocol ─────────────────────────────────────────

    /// `check_prerequisites`.
    #[must_use]
    pub fn check_prerequisites(&self) -> Vec<String> {
        super::prereq::check_prerequisites(self.runner)
    }

    /// `ensure_ready` — start the apiserver if it is down.
    ///
    /// The apiserver does not survive a reboot and has to be restarted
    /// each boot with `container system start`. While it is down every
    /// `container` subcommand fails with an XPC connection error, which
    /// used to surface from `start()` as "wrapped image not found" —
    /// the image probe being the first thing to ask. Best-effort and
    /// idempotent: if it still will not come up,
    /// [`Self::check_prerequisites`] reports it alongside everything
    /// else.
    pub fn ensure_ready(&self, quiet: bool) {
        let cli = self.cli();
        match cli.system_running() {
            Ok(true) => return,
            // A missing binary is `except FileNotFoundError: pass` —
            // `check_prerequisites` reports it with an install hint and
            // there is nothing to recover here.
            Err(error) if error.is_not_found() => return,
            Ok(false) | Err(_) => {}
        }
        if !quiet {
            output::echo("Apple container apiserver not running — starting it…");
        }
        let _ = cli.run(["system", "start", "--enable-kernel-install"], false);
    }

    /// The shared egress image's tag, `<repo>:<version>-<hash>`.
    #[must_use]
    pub fn egress_image(&self) -> String {
        super::image::egress_image_name_embedded()
    }

    /// `generate_units` — the cage's metadata JSON.
    ///
    /// The signature carries `config_host_path`, `patches_host_dir`,
    /// `used_octets` and `network_octet` to match the other backends
    /// and ignores all four, as the Python does: Apple networks are
    /// per-cage with an auto-allocated subnet, so there is no shared
    /// `10.89.x` pool to coordinate against.
    ///
    /// # Errors
    ///
    /// [`BackendError::Config`] when `container.volumes` carries an
    /// `np` option it cannot compose with. That is a refusal rather
    /// than a warning in the Python too, and it happens before
    /// anything else, so a bad spec fails the deploy instead of being
    /// quietly dropped.
    pub fn generate_units(
        &self,
        config: &Config,
        deploy_name: &str,
    ) -> Result<Quadlets, BackendError> {
        let host = crate::hostenv::RealQuadletHost::new(self.paths.data_root());
        let volumes = super::volumes::user_volume_argv(&config.container.volumes, &host).map_err(
            |error| {
                BackendError::Config(agentcage_core::config::ConfigError::runtime(
                    error.to_string(),
                ))
            },
        )?;
        for warning in &volumes.warnings {
            output::echo_err(warning);
        }
        Ok(Quadlets {
            files: apple::generate_units(config, deploy_name, &volumes.argv, &host)
                .into_iter()
                .collect(),
            // The volume warnings are printed above rather than
            // returned: this backend's renderer has no warning channel
            // of its own, and `_user_volume_argv` is where every one of
            // them comes from.
            warnings: Vec::new(),
        })
    }

    /// `install_units` — write the JSON into the apple root.
    ///
    /// # Errors
    ///
    /// [`BackendError::Failed`] when the directory or a file cannot be
    /// written.
    pub fn install_units(&self, units: &Quadlets, quiet: bool) -> Result<(), BackendError> {
        let dest = self.unit_dir();
        std::fs::create_dir_all(&dest)
            .map_err(|error| BackendError::Failed(format!("{}: {error}", dest.display())))?;
        for (filename, content) in &units.files {
            let path = dest.join(filename);
            std::fs::write(&path, content)
                .map_err(|error| BackendError::Failed(format!("{}: {error}", path.display())))?;
        }
        if !quiet {
            output::echo(&format!(
                "Installed apple-container unit metadata to {}/",
                dest.display()
            ));
        }
        Ok(())
    }

    /// `is_running`.
    #[must_use]
    pub fn is_running(&self, name: &str, service: &str) -> bool {
        let target = Self::target(name, service);
        let data = self.cli().inspect(&target).ok().flatten();
        container_state(data.as_ref()).as_deref() == Some("running")
    }

    /// `has_resources` — a unit JSON or a state directory is enough.
    #[must_use]
    pub fn has_resources(&self, name: &str) -> bool {
        self.unit_path(name).exists() || self.paths.apple_state_dir(name).exists()
    }

    /// `stop` — both microVMs, then the mask mount points.
    ///
    /// The cleanup runs after the cage VM is down on purpose: a mount
    /// that is still live can make an empty directory look occupied,
    /// and `rmdir` would then keep it.
    pub fn stop(&self, name: &str) {
        let cli = self.cli();
        let _ = cli.run(["stop", name], false);
        let _ = cli.run(["stop", &format!("{name}-egress")], false);
        super::masks::cleanup(&self.paths.apple_mask_mountpoints(name));
    }

    /// `restart`.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::start`] failed with.
    pub fn restart(&self, name: &str) -> Result<(), BackendError> {
        self.stop(name);
        self.start(name, false)
    }

    /// `destroy_resources` — and what went, for `cage destroy` to list.
    ///
    /// The shared egress image is **not** removed: sibling cages use
    /// it, quite possibly pinned to this exact tag. Superseded egress
    /// tags are left alone for the same reason; `container image
    /// delete` them by hand if the disk matters.
    ///
    /// # Errors
    ///
    /// [`BackendError::Failed`] when the state directory cannot be
    /// removed. Every other step is best-effort and reports only what
    /// actually went.
    pub fn destroy_resources(
        &self,
        name: &str,
        keep_secrets: bool,
    ) -> Result<Vec<String>, BackendError> {
        let cli = self.cli();
        let mut removed = Vec::new();

        let plist = self.paths.apple_launchd_plist(name);
        if plist.exists() {
            self.uninstall_launchd_plist(name);
            removed.push(format!("launchd:{}", plist.display()));
        }

        // The cage first, then the sibling. `start` brings them up the
        // other way round; doing it in this order here just reads
        // better in the output.
        for target in [name.to_owned(), format!("{name}-egress")] {
            if cli.inspect(&target).ok().flatten().is_none() {
                continue;
            }
            let _ = cli.run(["stop", &target], false);
            if cli
                .run(["delete", "-f", &target], false)
                .is_ok_and(|out| out.success())
            {
                removed.push(format!("container:{target}"));
            }
        }

        // Before the state tree goes, since that would take the
        // bookkeeping file with it. A no-op when `stop` already ran.
        super::masks::cleanup(&self.paths.apple_mask_mountpoints(name));

        // `network delete` is idempotent in Apple's CLI; the exit code
        // is what says whether there was anything there.
        if cli
            .run(["network", "delete", &format!("{name}-net")], false)
            .is_ok_and(|out| out.success())
        {
            removed.push(format!("network:{name}-net"));
        }

        let wrapper = super::wrapper::wrapped_image_name(name);
        if cli.image_inspect(&wrapper).ok().flatten().is_some()
            && cli
                .run(["image", "delete", &wrapper], false)
                .is_ok_and(|out| out.success())
        {
            removed.push(format!("image:{wrapper}"));
        }

        // Scoped secrets, before the unit JSON and the state tree go:
        // the unit JSON is where the store is named, and under
        // `secrets.backend: plaintext` the store *is* a file in the
        // deployment directory. Reading them afterwards finds neither.
        if !keep_secrets {
            removed.extend(self.forget_secrets(name));
        }

        let unit = self.unit_path(name);
        if unit.exists() && std::fs::remove_file(&unit).is_ok() {
            removed.push(format!("unit:{}", unit.display()));
        }
        let state = self.paths.apple_state_dir(name);
        if state.exists() {
            std::fs::remove_dir_all(&state)
                .map_err(|error| BackendError::Failed(format!("{}: {error}", state.display())))?;
            removed.push(format!("state:{}", state.display()));
        }
        Ok(removed)
    }

    /// Remove a CA left behind by an earlier cage of this name
    /// (`EGRESS-PORT-PLAN.md` D11).
    ///
    /// For `cage create`, `run` and `cage restore`, on a name that has
    /// no deployment. The egress microVM keeps its CA in the per-cage
    /// `certs/` directory and publishes the public half to
    /// `public-certs/`; [`Self::start`] creates both only if they are
    /// missing and the egress generates a CA only into an empty store.
    /// So a state tree left by a `cage destroy` that could not remove
    /// it would hand the earlier cage's CA to the new one. Only those
    /// two directories go: the rest of the tree is rewritten by the
    /// deploy anyway.
    ///
    /// Returns what was removed, for the caller's notice.
    ///
    /// # Errors
    ///
    /// [`BackendError::Failed`] when a leftover directory could not be
    /// removed: the create must not go ahead on top of it.
    pub fn purge_stale_ca(&self, name: &str) -> Result<Vec<String>, BackendError> {
        let mut removed = Vec::new();
        for dir in [
            self.paths.apple_certs_dir(name),
            self.paths.apple_public_certs_dir(name),
        ] {
            if !dir.exists() {
                continue;
            }
            std::fs::remove_dir_all(&dir).map_err(|error| {
                BackendError::Failed(format!(
                    "{dir} is left over from an earlier cage named '{name}' \
                     and could not be removed ({error}), and a new cage must \
                     not inherit its CA. Remove it by hand, then retry",
                    dir = dir.display()
                ))
            })?;
            removed.push(format!("certs:{}", dir.display()));
        }
        Ok(removed)
    }

    // ── argv the CLI dispatches through ──────────────────────

    /// `exec_argv`.
    ///
    /// `placeholders` is the env → placeholder map the cage session is
    /// re-handed, because Apple's `container exec` has no `--env` and
    /// the values have to arrive as an `env` prefix inside the VM.
    ///
    /// # Errors
    ///
    /// [`apple::AppleArgvError`] for an unknown service, or when
    /// `container(1)` is not installed.
    pub fn exec_argv(
        &self,
        name: &str,
        service: &str,
        command: &[String],
        interactive: bool,
        as_root: bool,
        placeholders: &[(String, String)],
    ) -> Result<Vec<String>, apple::AppleArgvError> {
        apple::exec_argv(
            self.cli().binary().as_deref(),
            name,
            service,
            command,
            interactive,
            as_root,
            placeholders,
        )
    }

    /// `logs_argv`.
    ///
    /// # Errors
    ///
    /// [`apple::AppleArgvError`] when `container(1)` is not installed.
    pub fn logs_argv(
        &self,
        name: &str,
        services: &[String],
        follow: bool,
    ) -> Result<Vec<String>, apple::AppleArgvError> {
        apple::logs_argv(self.cli().binary().as_deref(), name, services, follow)
    }

    /// `audit_argv` — the only audit path in agentcage that reads a
    /// file rather than a journal.
    #[must_use]
    pub fn audit_argv(&self, name: &str, follow: bool) -> Vec<String> {
        apple::audit_argv(
            &self.paths.apple_audit_file(name).display().to_string(),
            follow,
        )
    }
}

// ── the lifecycle ────────────────────────────────────────────

impl AppleBackend<'_> {
    /// `start` — the cage's two sibling microVMs.
    ///
    /// # Errors
    ///
    /// [`BackendError::Failed`] for every refusal here, because each
    /// one already says what to do about it. The five preconditions at
    /// the top name the **cage** and `agentcage cage update <name>`
    /// rather than the internal call that noticed (origin: #409): the
    /// wrapper tag is derived and appears nowhere in the operator's
    /// `cage.yaml`, so quoting it alone sends people grepping their
    /// config for a string that is not in it.
    //
    // Long on purpose, and not split: the body *is* an ordered
    // sequence, every step of which depends on the one before it, and
    // the five preconditions at the top have to run before any of it.
    // Splitting it into `start_egress` / `start_cage` would move the
    // ordering into the call site and the reasons for it somewhere
    // else again.
    #[allow(clippy::too_many_lines)]
    pub fn start(&self, name: &str, quiet: bool) -> Result<(), BackendError> {
        let unit_path = self.unit_path(name);
        let meta = match std::fs::read_to_string(&unit_path) {
            Ok(text) => Meta::parse(&text).map_err(|error| {
                BackendError::Failed(format!(
                    "apple-container unit metadata at {} is not readable JSON \
                     ({error}); run `agentcage cage update {name}` to \
                     regenerate it from the stored cage.yaml",
                    unit_path.display()
                ))
            })?,
            Err(_) => {
                return Err(BackendError::Failed(format!(
                    "apple-container unit metadata missing at {}; run \
                     `agentcage cage update {name}` to regenerate it from the \
                     stored cage.yaml",
                    unit_path.display()
                )));
            }
        };

        // A backstop for callers that are not the CLI's create/update
        // path, which gates on `ensure_ready` already: `start` is also
        // reached from backup/restore. `ensure_ready` is idempotent and
        // best-effort, so if the apiserver is still down afterwards say
        // so, rather than letting the image probe below report the
        // misleading "no built image".
        self.ensure_ready(quiet);
        let cli = self.cli();
        if !cli.system_running().unwrap_or(false) {
            return Err(BackendError::Failed(format!(
                "Apple container apiserver is not running and could not be \
                 started automatically — run 'container system start \
                 --enable-kernel-install' manually and retry (`agentcage \
                 cage start {name}`)"
            )));
        }

        let wrapper_image = super::wrapper::wrapped_image_name(name);
        if cli.image_inspect(&wrapper_image).ok().flatten().is_none() {
            return Err(BackendError::Failed(format!(
                "cage '{name}' has no built image — run 'agentcage cage \
                 update {name}' to build it (expected '{wrapper_image}' in \
                 the local image store)"
            )));
        }
        let egress_image = self.egress_image();
        if cli.image_inspect(&egress_image).ok().flatten().is_none() {
            return Err(BackendError::Failed(format!(
                "cage '{name}' is missing the shared egress image — run \
                 'agentcage cage update {name}' to rebuild it (expected \
                 '{egress_image}' in the local image store)"
            )));
        }

        // Start is idempotent on every other backend, so prior
        // incarnations of either container go first.
        for target in [name.to_owned(), format!("{name}-egress")] {
            if cli.inspect(&target).ok().flatten().is_some() {
                let _ = cli.run(["stop", &target], false);
                let _ = cli.run(["delete", "-f", &target], false);
            }
        }

        // The per-cage state directories, created on demand. 1777 on
        // all three: virtiofs maps host ownership into the guest
        // identity-wise, so uid 200 (mitmproxy) and 201 (dnsmasq) can
        // only write here if the host-side mode lets them. The sticky
        // bit stops cross-uid deletion. The legacy single-VM model used
        // the same trick and it is preserved verbatim.
        let logs_dir = self.paths.apple_logs_dir(name);
        let certs_dir = self.paths.apple_certs_dir(name);
        let public_certs_dir = self.paths.apple_public_certs_dir(name);
        for dir in [&logs_dir, &certs_dir, &public_certs_dir] {
            std::fs::create_dir_all(dir)
                .map_err(|error| BackendError::Failed(format!("{}: {error}", dir.display())))?;
            set_mode(dir, 0o1777);
        }

        let egress_cfg_dir = self.paths.apple_egress_config_dir(name);
        if !egress_cfg_dir.is_dir() {
            return Err(BackendError::Failed(format!(
                "egress config dir {} missing — run `cage update`",
                egress_cfg_dir.display()
            )));
        }

        // Re-render the bind-mounted egress config from the *current*
        // host state before (re)starting.
        //
        // `dnsmasq.conf` and `dns-allowlist.conf` encode the cage's DNS
        // upstream as `server=/<apex>/<resolver-ip>`, where the
        // resolver is auto-detected from the host's `/etc/resolv.conf`
        // at render time. Those files are otherwise only rewritten by
        // `build_artifacts` (create/update) and `reload_domains`
        // (domain add/rm) — not by start. So a laptop that changed
        // networks since the last `cage update` (Wi-Fi switch, VPN up
        // or down, a reboot on a different LAN) would come back up
        // forwarding DNS to an address that no longer exists: every
        // uncached lookup times out and the cage "cannot reach the
        // network" while verify and status both report green. The files
        // are bind-mounted rather than baked, so re-rendering here
        // picks up the live resolver with no rebuild, and start and
        // restart self-heal across a host network change.
        //
        // Best-effort: a host with no detectable resolver right now
        // keeps the previously rendered files rather than failing a
        // start that would otherwise have worked.
        let refreshed = self
            .paths
            .load_deployment_config(name, &crate::hostenv::RealHost)
            .map_err(|error| error.to_string())
            .and_then(|config| {
                super::egress_config::render_egress_config(
                    self.paths,
                    &config,
                    name,
                    self.version,
                    &crate::hostenv::RealHost,
                )
                .map(|_| ())
                .map_err(|error| error.to_string())
            });
        if let Err(error) = refreshed {
            if !quiet {
                output::echo_err(&format!(
                    "warning: could not refresh DNS config for {name} from the \
                     current host resolver ({error}); starting with the existing \
                     rendered config — if DNS fails inside the cage, run \
                     `agentcage cage update {name}`"
                ));
            }
        }

        // Clear any stale readiness marker before the first run. The
        // egress supervisor touches it at the end of its step F.
        let ready_marker = self.paths.apple_ready_marker(name);
        let _ = std::fs::remove_file(&ready_marker);

        // 1. The per-cage network. `network create` exits non-zero when
        // it is already there, which is tolerated rather than probed —
        // the post-error inspect would slow down the common case. The
        // subnet is auto-allocated by Apple's network plugin; there is
        // no shared `10.89.x` pool to coordinate on.
        let network = format!("{name}-net");
        let _ = cli.run(["network", "create", &network], false);

        // 2. The egress sibling. Secrets are resolved and written
        // before it runs, because its addon reads them at startup.
        let staged_envs = self.stage_secrets(name, &meta);

        let secrets_dir = self.paths.apple_secrets_dir(name);
        let grants_dir = self.paths.grants_dir(name);
        let inspectors_dir = self.paths.inspectors_dir(name);
        let grants_wanted = meta.truthy("decider_enabled")
            || meta.truthy("has_expiring_domains")
            || meta.truthy("watcher_enabled");
        if grants_wanted {
            let _ = std::fs::create_dir_all(&grants_dir);
            // The egress addon (uid 200) rewrites `grants.yaml` with an
            // atomic temp-and-rename, so the *directory* has to be
            // writable by it. 0777, with the operator owning it and the
            // addon reaching it through the world bit. Not chowned to
            // 200: that would lock the operator and the shared cleanup
            // helper out.
            //
            // macOS hosts are single-user by default and the grants
            // directory is shared into the guest over a mount only the
            // operator's account can traverse, so the subgid mapping
            // the Linux backend uses (`podman unshare chgrp` → 0770)
            // does not apply the same way. On a *shared* macOS host
            // this 0777 is a known limitation: another local account
            // could plant entries the addon then promotes into the
            // baseline. `egress.container.j2` has the hardened path.
            set_mode(&grants_dir, 0o777);
        }
        let egress_paths = EgressPaths {
            logs: &logs_dir,
            certs: &certs_dir,
            public_certs: &public_certs_dir,
            egress_config: &egress_cfg_dir,
            // Only when it actually has files: an empty bind would
            // shadow the egress image's own empty directory.
            secrets: has_entries(&secrets_dir).then_some(secrets_dir.as_path()),
            grants: grants_wanted.then_some(grants_dir.as_path()),
            inspectors: has_entries(&inspectors_dir).then_some(inspectors_dir.as_path()),
        };
        let argv = egress_argv(
            name,
            &network,
            &egress_image,
            self.version,
            &meta,
            &egress_paths,
        );
        let outcome = output::pause_active_spinner(|| cli.run_streaming(argv, false));
        let code = exit_code(&outcome);
        if code != Some(0) {
            return Err(BackendError::Failed(format!(
                "`container run` for egress sibling failed (exit {})",
                code.map_or_else(|| "unknown".to_owned(), |c| c.to_string())
            )));
        }

        // 3. Wait for the supervisor's marker, which virtiofs surfaces
        // on the host.
        self.wait_supervisor_ready(name, &ready_marker)?;

        // 3b. The egress has the secrets in memory now, so the
        // transiently staged cleartext can go. The durable copy is in
        // the keychain and the next start re-stages from it.
        if !staged_envs.is_empty() {
            self.wipe_staged_secrets(name);
        }

        // 4. The egress sibling's address, which the cage uses as its
        // default-route gateway.
        let egress_ip = self.container_ip_polled(&format!("{name}-egress"))?;

        // 5. The cage itself.
        let host = crate::hostenv::RealQuadletHost::new(self.paths.data_root());
        let volumes = super::volumes::user_volume_argv(&meta.strings("volumes"), &host)
            .map_err(|error| BackendError::Failed(error.to_string()))?;
        for warning in &volumes.warnings {
            output::echo_err(warning);
        }
        let tmpfs = meta.strings("tmpfs");
        // The `np` targets the cage argv will cover with a tmpfs of
        // their own, which the copy-up scan has to know about so it
        // does not seed a target that is already seeded.
        let np_targets: BTreeSet<String> = volumes
            .argv
            .iter()
            .filter(|entry| agentcage_core::volume_mounts::is_non_persistent_volume(entry))
            .filter_map(|entry| {
                let (source, target, _) = agentcage_core::volume_mounts::split_volume_spec(entry);
                (!target.is_empty() && Path::new(source).is_dir()).then(|| {
                    let normalized = target.trim_end_matches('/');
                    if normalized.is_empty() {
                        "/".to_owned()
                    } else {
                        normalized.to_owned()
                    }
                })
            })
            .collect();
        let seeds = super::volumes::tmpfs_copyup_seeds(&tmpfs, &volumes.argv, &np_targets, &host);
        for warning in &seeds.warnings {
            output::echo_err(warning);
        }

        // Masks the host cannot accommodate: an ancestor of the target
        // exists and is not a directory, which is exactly what a git
        // worktree's or submodule's `.git` file is. Emitting those makes
        // the runtime answer ENOTDIR and the cage never starts — the
        // failure `agentcage run <scaffold>` hit in a worktree, with an
        // error naming neither the mask nor the reason. Skip them and
        // say so; see `unmaskable_masks` for why that costs #170
        // nothing here.
        let unmaskable = agentcage_core::volume_mounts::unmaskable_masks(
            &tmpfs,
            &super::volumes::mask_mount_targets(&volumes.argv),
            &|path| std::fs::symlink_metadata(path).is_ok(),
            &|path| std::fs::metadata(path).is_ok_and(|m| m.is_dir()),
        );
        for mask in &unmaskable {
            output::echo_err(&format!(
                "warning: skipping tmpfs mask '{}' — '{}' is a file (this \
                 project is a git worktree or submodule), so the mount point \
                 cannot be created. The hooks directory it protects (#170) is \
                 not reachable through this bind either; it lives in the main \
                 repository.",
                mask.target, mask.blocker
            ));
        }

        let placeholders = self.placeholders(name, &meta);
        let inputs = CageInputs {
            public_certs: &public_certs_dir,
            egress_config: &egress_cfg_dir,
            egress_ip: &egress_ip,
            staged_envs: &staged_envs,
            placeholders: &placeholders,
            volume_entries: &volumes.argv,
            copyup_seeds: &seeds.seeds,
            unmaskable: &unmaskable,
        };
        let argv = cage_argv(
            name,
            &network,
            &wrapper_image,
            self.version,
            &meta,
            &inputs,
            &|path| Path::new(path).is_dir(),
        );

        // A mask nested under a host bind makes the in-guest OCI
        // runtime create the mount point *through* the bind, onto the
        // host (#320). Record which of those are absent right now, so
        // stop and destroy can retire exactly those, and only while
        // they are still empty.
        super::masks::record(
            &self.paths.apple_mask_mountpoints(name),
            &tmpfs,
            &super::volumes::mask_mount_targets(&volumes.argv),
        );

        let outcome = output::pause_active_spinner(|| cli.run_streaming(argv, false));
        let code = exit_code(&outcome);
        if code != Some(0) {
            // Clean up the orphaned sibling, or the "already exists"
            // probe at the top of the next start blocks the retry.
            let _ = cli.run(["stop", &format!("{name}-egress")], false);
            let _ = cli.run(["delete", "-f", &format!("{name}-egress")], false);
            return Err(BackendError::Failed(format!(
                "`container run` for cage failed (exit {})",
                code.map_or_else(|| "unknown".to_owned(), |c| c.to_string())
            )));
        }

        // The launchd job, if the cage opted into autostart. Read from
        // the metadata so the choice survives a reload.
        if meta.truthy("autostart") {
            self.install_launchd_plist(name);
        }
        if !quiet {
            output::echo(&format!(
                "Started {name} (apple-container, 2-microVM model)"
            ));
        }
        Ok(())
    }

    /// env → placeholder, the live config's merged over the metadata's.
    ///
    /// The metadata snapshot was baked at create/update time; the
    /// stored `cage.yaml` is current. Preferring the live one means a
    /// plain restart picks up a placeholder change, which is the parity
    /// the container and vm backends get for free from their
    /// `EnvironmentFile`. The snapshot stays as the fallback, and a
    /// missing `cage.yaml` is not an error here.
    fn placeholders(&self, name: &str, meta: &Meta) -> BTreeMap<String, String> {
        let mut placeholders = meta.map("secret_env_placeholders");
        // The same read `cage exec` does for its `env` prefix, and for
        // the same reason: it is the live `secret_injection` block,
        // with every shape the field has had absorbed and every
        // unfilled placeholder already dropped.
        placeholders.extend(crate::services::current_placeholders(self.paths, name));
        placeholders
    }

    /// `_wait_supervisor_ready` — block until the marker appears, or
    /// the egress exits, or the deadline.
    ///
    /// The "egress exited" branch exists so an operator sees a real
    /// error instead of a successful return that then fails on the
    /// first request. Note the `state not in ("running", None)` shape:
    /// a container that `inspect` cannot describe *yet* is still
    /// booting, and only a state it can describe and that is not
    /// `running` is a death.
    ///
    /// # Errors
    ///
    /// [`BackendError::Failed`] on either the exit or the timeout,
    /// naming `container logs` in both cases.
    fn wait_supervisor_ready(&self, name: &str, marker: &Path) -> Result<(), BackendError> {
        let egress = format!("{name}-egress");
        let cli = self.cli();
        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            if marker.exists() {
                return Ok(());
            }
            let data = cli.inspect(&egress).ok().flatten();
            let state = container_state(data.as_ref());
            if data.is_some() && state.as_deref().is_some_and(|state| state != "running") {
                return Err(BackendError::Failed(format!(
                    "egress sibling '{egress}' exited before becoming ready \
                     (state={state:?}); see `container logs {egress}`",
                    state = state.unwrap_or_default()
                )));
            }
            std::thread::sleep(READY_POLL);
        }
        Err(BackendError::Failed(format!(
            "egress sibling '{egress}' did not signal ready within {}s; see \
             `container logs {egress}` for the supervisor's last step",
            READY_TIMEOUT.as_secs()
        )))
    }

    /// `_container_ip` — the IPv4 address Apple's plugin assigned.
    ///
    /// The address lives under `networks[].ipv4Address` in CIDR form
    /// and the mask is stripped. `address` / `Address` are checked
    /// after it, and a flat `network.address` after that, because the
    /// schema has moved twice; `container_networks` already absorbs the
    /// v1.0.0 nesting. `None` means no address is populated **yet**,
    /// which is a state and not a failure — the caller polls.
    #[must_use]
    pub fn container_ip(&self, target: &str) -> Option<String> {
        let data = self.cli().inspect(target).ok().flatten()?;
        let first = |value: &serde_json::Value| -> Option<String> {
            ["ipv4Address", "address", "Address"]
                .iter()
                .filter_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
                .map(str::trim)
                .find(|address| !address.is_empty())
                .map(|address| {
                    address
                        .split_once('/')
                        .map_or(address, |(head, _)| head)
                        .to_owned()
                })
        };
        for network in container_networks(Some(&data)) {
            if let Some(address) = first(&network) {
                return Some(address);
            }
        }
        data.get("network").and_then(first)
    }

    /// [`Self::container_ip`], polled.
    ///
    /// Apple's runtime populates the address asynchronously, and
    /// `inspect` can still answer `networks: []` *after* the
    /// supervisor's ready marker has appeared. This absorbs that race.
    ///
    /// # Errors
    ///
    /// [`BackendError::Failed`] when nothing arrives inside
    /// [`IP_TIMEOUT`].
    fn container_ip_polled(&self, target: &str) -> Result<String, BackendError> {
        let deadline = Instant::now() + IP_TIMEOUT;
        while Instant::now() < deadline {
            if let Some(address) = self.container_ip(target) {
                return Ok(address);
            }
            std::thread::sleep(IP_POLL);
        }
        Err(BackendError::Failed(format!(
            "could not resolve IP of {target} within {}s — `container \
             inspect` returned no address. Check `container logs {target}`.",
            IP_TIMEOUT.as_secs()
        )))
    }

    /// Delete this cage's secrets from whichever store holds them.
    ///
    /// The container backend removes its `<name>.*` podman secrets in
    /// `destroy_resources`, and `cage destroy` tells the operator so —
    /// "Scoped secrets will also be removed." On this backend that was
    /// a false promise: the Python takes `keep_secrets` and marks it
    /// unused, so a destroyed cage left its values in the macOS
    /// keychain under `agentcage / <cage>.<KEY>`, with nothing left on
    /// disk to say they were ever there. Observed on a real destroy.
    ///
    /// The protocol is name-only, so the four fields `resolve_store`
    /// reads are rebuilt from the unit JSON exactly as
    /// [`Self::stage_secrets`] rebuilds them. A cage whose unit JSON
    /// has already gone resolves the default store, which is the one
    /// `secret set` would have used, so the common case still cleans
    /// up.
    ///
    /// Best-effort throughout. A store that will not resolve, or a key
    /// that will not delete, must not fail the destroy: a cage that
    /// cannot be removed because its secrets cannot be is worse than a
    /// leftover the operator can find with `security
    /// find-generic-password`.
    fn forget_secrets(&self, name: &str) -> Vec<String> {
        let meta = std::fs::read_to_string(self.unit_path(name))
            .ok()
            .and_then(|text| Meta::parse(&text).ok());
        let backend = match meta.as_ref().map(|m| m.string("secrets_backend")) {
            Some(backend) if !backend.is_empty() => backend,
            _ => "auto".to_owned(),
        };
        let shim = Config {
            isolation: "apple-container".to_owned(),
            secrets: agentcage_core::config::SecretsConfig {
                backend,
                scope: "auto".to_owned(),
                allow_plaintext: meta
                    .as_ref()
                    .is_some_and(|m| m.truthy("secrets_allow_plaintext")),
            },
            ..Config::default()
        };

        let state_dir = self.paths.deployment_dir(name);
        let host = crate::secrets::SecretHost::detect(self.runner, &SYSTEM_ENVIRONMENT);
        let Ok(store) =
            crate::secrets::resolve_store(&shim, &host, None, "", crate::secrets::Platform::host())
        else {
            return Vec::new();
        };
        let Ok(mut keys) = store.names(name, &state_dir) else {
            return Vec::new();
        };
        keys.sort();
        keys.into_iter()
            .filter(|key| store.delete(name, key, &state_dir).is_ok())
            .map(|key| format!("secret:{name}.{key}"))
            .collect()
    }

    /// `_wipe_staged_secrets` — remove the cleartext once the egress
    /// has it.
    ///
    /// Best-effort per file: a secret that cannot be removed is worth
    /// neither failing the start nor a warning the operator cannot act
    /// on, which is the Python's `except OSError: pass`.
    fn wipe_staged_secrets(&self, name: &str) {
        let dir = self.paths.apple_secrets_dir(name);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// `os.chmod`, best-effort.
///
/// Every caller here is setting a mode the guest needs rather than one
/// the host enforces, and a filesystem that will not take it (an
/// exported share, a `noexec` mount) is not a reason to fail a start
/// that may still work. The Python does not check either.
fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

/// Whether a directory exists and has at least one entry.
///
/// `secrets_dir.is_dir() and any(secrets_dir.iterdir())`.
fn has_entries(path: &Path) -> bool {
    std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_some())
}

/// The exit status of a `container` call that was not `check`ed.
///
/// `None` when the process could not be run at all, which is not the
/// same as a non-zero exit and must not be reported as one.
fn exit_code(outcome: &Result<agentcage_exec::Output, ExecError>) -> Option<i32> {
    outcome.as_ref().ok().and_then(|output| output.status.code)
}

// ── secrets ──────────────────────────────────────────────────

impl AppleBackend<'_> {
    /// `_stage_secrets` — resolve each value into
    /// `<secrets_dir>/<env>`, 0600.
    ///
    /// Returns the `secret_injection` envs that actually got a value,
    /// which is what decides the cage's `-e NAME={{NAME}}` flags.
    /// Relay-only envs are **never** returned: their value is staged
    /// into the bind mount for the egress to read, but the cage
    /// workload must not learn even the placeholder.
    ///
    /// # On `systemd-creds:` sources
    ///
    /// They resolve here exactly like `env:` ones, by name, from the
    /// configured store — the scheme is effectively decorative on this
    /// backend. The container backend's quadlet path would add the name
    /// to `creds_secrets` (a systemd `ExecStartPre` decrypts
    /// `<state>/creds/NAME.cred`) and to `proxy_secrets` (a podman
    /// `Secret=` exposes it as `$NAME` inside the proxy), and the
    /// addon's `_read_secret` finds it in the environment. Apple's
    /// runtime has neither systemd-creds nor a podman secret store, so
    /// `secret set` stores the cleartext under the bare name and this
    /// retrieves it by that name and writes it where the addon looks:
    /// `/home/acproxy/secrets/NAME`. That is the channel standing in
    /// for the podman `Secret=` env.
    ///
    /// Which is why the store is resolved with **no** source scheme. A
    /// `source_scheme` of `systemd-creds` would select the
    /// systemd-creds store, whose `get` fails on a Mac where the binary
    /// does not exist, and staging would break for exactly the cages
    /// that asked for the more careful spelling.
    fn stage_secrets(&self, name: &str, meta: &Meta) -> BTreeSet<String> {
        let mut staged = BTreeSet::new();

        let placeholders = meta.map("secret_env_placeholders");
        let mut secret_envs = meta.strings("secret_envs");
        if secret_envs.is_empty() {
            secret_envs = placeholders.keys().cloned().collect();
        }
        let relay_secret_envs = meta.strings("relay_secret_envs");
        // The decider's and watcher's `api_key` names, parsed only so a
        // missing value can be *named* accurately below rather than
        // mislabelled a relay credential. Both are already in
        // `relay_secret_envs` — `generate_units` puts them there — so
        // they are staged like any other credential.
        let decider_name = meta.key_source_name("decider_api_key_source");
        let watcher_name = meta.key_source_name("watcher_api_key_source");

        let mut all: Vec<String> = secret_envs.clone();
        all.extend(
            relay_secret_envs
                .iter()
                .filter(|env| !secret_envs.contains(env))
                .cloned(),
        );
        if all.is_empty() {
            return staged;
        }

        // `start` is metadata-driven and has no `Config`, so the four
        // fields `resolve_store` reads are rebuilt from the unit JSON
        // the renderer baked. Everything else on a `Config` is
        // irrelevant to the choice of store.
        let backend = match meta.string("secrets_backend") {
            backend if backend.is_empty() => "auto".to_owned(),
            backend => backend,
        };
        let shim = Config {
            isolation: "apple-container".to_owned(),
            secrets: agentcage_core::config::SecretsConfig {
                backend,
                // systemd-creds-only and never read on this backend;
                // `auto` is what the Python's own shim passes.
                scope: "auto".to_owned(),
                allow_plaintext: meta.truthy("secrets_allow_plaintext"),
            },
            ..Config::default()
        };

        let state_dir = self.paths.deployment_dir(name);
        let host = crate::secrets::SecretHost::detect(self.runner, &SYSTEM_ENVIRONMENT);
        let mut provided: BTreeMap<String, String> = BTreeMap::new();
        match crate::secrets::resolve_store(
            &shim,
            &host,
            None,
            "",
            crate::secrets::Platform::host(),
        ) {
            Ok(store) => {
                for env in &all {
                    if let Ok(Some(value)) = store.get(name, env, &state_dir) {
                        provided.insert(env.clone(), value);
                    }
                }
            }
            Err(error) => output::echo_err(&format!(
                "warning: could not read secrets for {name}: {error}"
            )),
        }

        let dir = self.paths.apple_secrets_dir(name);
        if std::fs::create_dir_all(&dir).is_err() {
            output::echo_err(&format!(
                "warning: could not create the secrets directory {} for \
                 {name}; the egress will start with no injected secrets",
                dir.display()
            ));
            return staged;
        }
        set_mode(&dir, 0o700);
        // Drop stale files so a removed rule does not linger in the
        // bind mount.
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }

        let relay_only: BTreeSet<&String> = relay_secret_envs
            .iter()
            .filter(|env| !secret_envs.contains(env))
            .collect();
        for env in &all {
            let Some(value) = provided.get(env) else {
                output::echo_err(&missing_secret_warning(
                    env,
                    &decider_name,
                    &watcher_name,
                    relay_only.contains(env),
                ));
                continue;
            };
            if relay_only.contains(env) {
                // A relay credential: the file goes into the bind
                // mount and no `-e` reaches the cage.
                write_secret(&dir, env, value);
                continue;
            }
            if placeholders.get(env).is_none_or(String::is_empty) {
                // Pre-0.21.1 unit JSON, which recorded the env names
                // but not their placeholders. Refuse the cleartext
                // fallback: without a placeholder the only way to give
                // the workload the value would be to give it the value.
                continue;
            }
            write_secret(&dir, env, value);
            staged.insert(env.clone());
        }
        staged
    }
}

/// `<dir>/<env>`, 0600.
///
/// The mode is set after the write rather than at create time, which
/// leaves a window the Python has too. It is narrow and the directory
/// above is already 0700, so the file is unreachable by anyone else
/// throughout.
fn write_secret(dir: &Path, env: &str, value: &str) {
    let path = dir.join(env);
    if std::fs::write(&path, value).is_err() {
        output::echo_err(&format!(
            "warning: could not stage secret '{env}' to {}",
            path.display()
        ));
        return;
    }
    set_mode(&path, 0o600);
}

/// The warning for a secret with no value, named by what it is for.
///
/// Four different consequences, so four different messages: the
/// decider fails closed on every request, the watcher silently skips
/// every scan, a relay starts with empty credentials, and a plain
/// injection rule leaves its placeholder unsubstituted. Collapsing
/// them would make the common case — a forgotten `--set-secret` —
/// indistinguishable from a misconfigured decider.
fn missing_secret_warning(
    env: &str,
    decider_name: &str,
    watcher_name: &str,
    relay_only: bool,
) -> String {
    if !decider_name.is_empty() && env == decider_name {
        return format!(
            "warning: agents.decider.api_key env '{env}' not provided via \
             --set-secret; the decider will fail closed (503 'llm provider \
             not configured') on every domain request"
        );
    }
    if !watcher_name.is_empty() && env == watcher_name {
        return format!(
            "warning: agents.watcher.api_key env '{env}' not provided via \
             --set-secret; the traffic watcher will skip every scan until it \
             is set"
        );
    }
    if relay_only {
        return format!(
            "warning: protocol_relays env '{env}' not provided via \
             --set-secret; the relay will fail to start with empty credentials"
        );
    }
    format!(
        "warning: secret_injection env '{env}' not provided via --set-secret; \
         placeholder will NOT be substituted in cage requests"
    )
}

// ── the launchd job ──────────────────────────────────────────

impl AppleBackend<'_> {
    /// `_install_launchd_plist` — write it, then try to load it.
    ///
    /// # The persistence model (#185)
    ///
    /// **The file on disk is the persistence.** launchd auto-loads
    /// `~/Library/LaunchAgents/` at the next Aqua login regardless of
    /// anything that happens after the write. The `launchctl bootstrap`
    /// below is a convenience for the common local-Terminal case and
    /// not correctness.
    ///
    /// It needs a gate, though: `bootstrap gui/<uid>` from an SSH
    /// session exits 0 and silently does nothing, because the GUI
    /// domain is not addressable from a non-GUI session context. That
    /// was the pre-#185 bug — the job looked installed and never
    /// loaded. So the domain is probed first and, when it is not
    /// reachable, the operator is told the plist is on disk and will
    /// activate at the next login.
    pub fn install_launchd_plist(&self, name: &str) {
        let Some(binary) = self.cli().binary() else {
            output::echo_err(
                "warning: cannot install launchd autostart — Apple \
                 `container` CLI not found",
            );
            return;
        };
        let plist = self.paths.apple_launchd_plist(name);
        if let Some(parent) = plist.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let state_dir = self.paths.apple_state_dir(name);
        let _ = std::fs::create_dir_all(&state_dir);
        let text = apple::plist_text(name, &binary, &state_dir.display().to_string());
        if let Err(error) = std::fs::write(&plist, text) {
            output::echo_err(&format!(
                "warning: could not write {}: {error} — autostart will NOT \
                 trigger at next login",
                plist.display()
            ));
            return;
        }

        let label = apple::plist_label(name);
        let domain = format!("gui/{}", crate::hostenv::uid());
        if !self.gui_domain_reachable(&domain) {
            output::echo_err(&format!(
                "note: plist written to {}; autostart will activate at next \
                 GUI login (immediate-load not available from this \
                 SSH/non-GUI context — see #185)",
                plist.display()
            ));
            return;
        }
        // `bootout` any prior version so `bootstrap` does not refuse
        // with "service is already loaded". Its own failure is benign:
        // it means the service was not loaded.
        let _ = self.launchctl(&["bootout", &format!("{domain}/{label}")]);
        let bootstrap = self.launchctl(&["bootstrap", &domain, &plist.display().to_string()]);
        let bootstrap_stderr = match &bootstrap {
            Ok(output) if output.success() => return,
            Ok(output) => output.stderr_text().trim().to_owned(),
            Err(error) => error.to_string(),
        };
        // Fall back to the legacy `load -w`. Worst case the outcome is
        // what it was before #185.
        let _ = self.launchctl(&["unload", &plist.display().to_string()]);
        let fallback = self.launchctl(&["load", "-w", &plist.display().to_string()]);
        let fallback_stderr = match &fallback {
            Ok(output) if output.success() => return,
            Ok(output) => output.stderr_text().trim().to_owned(),
            Err(error) => error.to_string(),
        };
        output::echo_err(&format!(
            "warning: launchctl bootstrap+load both failed for {}: \
             bootstrap='{bootstrap_stderr}' load='{fallback_stderr}' — \
             autostart will NOT trigger at next login",
            plist.display()
        ));
    }

    /// `_uninstall_launchd_plist` — unload if possible, remove always.
    ///
    /// Deliberately **not** gated on the GUI domain being reachable,
    /// unlike the install. Over SSH the `bootout` and `unload` do
    /// nothing, and that is fine: removing the file is what guarantees
    /// the job will not come back at the next login, so persistence
    /// cannot survive a destroy by hiding behind an unreachable domain.
    pub fn uninstall_launchd_plist(&self, name: &str) {
        let plist = self.paths.apple_launchd_plist(name);
        if !plist.exists() {
            return;
        }
        let label = apple::plist_label(name);
        let domain = format!("gui/{}", crate::hostenv::uid());
        // `bootout` for a plist installed by the current path, `unload`
        // for one installed by the legacy fallback. Both best-effort.
        let _ = self.launchctl(&["bootout", &format!("{domain}/{label}")]);
        let _ = self.launchctl(&["unload", &plist.display().to_string()]);
        let _ = std::fs::remove_file(&plist);
    }

    /// `_gui_domain_reachable` — `launchctl print gui/<uid>` exits 0.
    ///
    /// `~/Library/LaunchAgents/` plists live in the per-user *GUI*
    /// domain, which is only addressable from a session that owns the
    /// Aqua console. Over SSH the session is the non-GUI `user/<uid>`
    /// context and the domain is not there, which is the whole reason
    /// this probe exists.
    fn gui_domain_reachable(&self, domain: &str) -> bool {
        self.launchctl(&["print", domain])
            .is_ok_and(|output| output.success())
    }

    /// `subprocess.run(["launchctl", ...], capture_output=True)`.
    fn launchctl(&self, args: &[&str]) -> Result<agentcage_exec::Output, ExecError> {
        self.runner.run(
            &agentcage_exec::Command::new("launchctl")
                .args(args.iter().map(|arg| (*arg).to_owned()))
                .captured(),
        )
    }
}

// ── build ────────────────────────────────────────────────────

impl AppleBackend<'_> {
    /// `build_artifacts` — two images and three rendered config files.
    ///
    /// The order is forced by the dependencies between the steps:
    ///
    /// 1. the shared `agentcage-egress` image, built once per host per
    ///    distinct set of build inputs;
    /// 2. the cage's own image, from its **staged** Containerfile —
    ///    before the wrapper, whose `FROM <user image>` names the tag
    ///    this step produces;
    /// 3. the user image made available locally, checking the local
    ///    store before any registry;
    /// 4. the cage's CMD resolved;
    /// 5. the three egress config files rendered host-side;
    /// 6. the per-cage wrapper image.
    ///
    /// Step 3's order matters more than it reads. A scaffold build
    /// produces a `localhost/…` tag that can never resolve in a
    /// registry, so pulling unconditionally meant every scaffold `cage
    /// create` burned a multi-second `image pull` that was guaranteed
    /// to fail — printing an alarming connection error on the happy
    /// path — and only "worked" through the local fallback afterwards.
    /// A mistyped or unbuilt `localhost/` tag surfaced as that same
    /// cryptic error instead of "not built".
    ///
    /// `--pull` overrides the use-local shortcut for a genuinely remote
    /// ref, because the operator asked for the registry's latest. A
    /// `localhost/` ref is still never pulled: its freshness comes from
    /// the `--no-cache` rebuild in step 2, not from a pull.
    ///
    /// # Errors
    ///
    /// [`BackendError`] from any step. Each message names what to do.
    pub fn build_artifacts(
        &self,
        config: &Config,
        deploy_name: &str,
        no_cache: bool,
        pull: bool,
        quiet: bool,
    ) -> Result<(), BackendError> {
        let user_image = config.container.image.clone();
        if user_image.is_empty() {
            return Err(BackendError::Failed(
                "cage has no container.image set".to_owned(),
            ));
        }
        let cli = self.cli();

        // 1.
        self.build_egress_image_if_missing(no_cache, pull, quiet)?;

        // 2. From the cage's own frozen copy, never the live scaffold:
        // a scaffold is a one-shot generator, not a live dependency, so
        // an agentcage upgrade that changes one cannot leak into an
        // existing cage on `cage update`.
        if !config.container.build.containerfile.is_empty() {
            let staged = self
                .paths
                .deployment_dir(deploy_name)
                .join(&config.container.build.containerfile);
            if staged.is_file() {
                let context = staged.parent().unwrap_or(Path::new(".")).to_path_buf();
                super::build::build_image_from_staged(
                    self.runner,
                    &user_image,
                    &staged,
                    &context,
                    &config.container.build.args,
                    quiet,
                    super::image::BuildFlags { no_cache, pull },
                )?;
            } else if !quiet {
                output::echo_err(&format!(
                    "warning: no staged Containerfile at {}; relying on a \
                     prebuilt or pullable {user_image}",
                    staged.display()
                ));
            }
        }

        // 3.
        let force_pull_remote = pull && !user_image.starts_with("localhost/");
        if cli.image_inspect(&user_image).ok().flatten().is_some() && !force_pull_remote {
            if !quiet {
                output::echo(&format!("Using local image: {user_image}"));
            }
        } else if user_image.starts_with("localhost/") {
            return Err(BackendError::Failed(format!(
                "image '{user_image}' is a local-only ('localhost/') \
                 reference but is not present in the local image store. It is \
                 never pulled from a registry. If it should be built from a \
                 Containerfile, set 'container.build.containerfile' (and, for \
                 a scaffold, ensure 'container.image' matches the tag the \
                 build produces, e.g. \
                 'localhost/agentcage-scaffold-<name>:latest'); otherwise \
                 build/load it first with 'container build -t {user_image} \
                 ...'."
            )));
        } else {
            if !quiet {
                output::echo(&format!("Pulling user image: {user_image}"));
            }
            let pulled = output::pause_active_spinner(|| {
                cli.run_streaming(["image", "pull", &user_image], false)
            });
            if exit_code(&pulled) != Some(0)
                && cli.image_inspect(&user_image).ok().flatten().is_none()
            {
                return Err(BackendError::Failed(format!(
                    "failed to pull user image '{user_image}' and it is not \
                     built locally"
                )));
            }
        }

        // 4. `cage.yaml`'s `container.command:` wins over the image's
        // own CMD — explicit intent, and portable across backends.
        // Without that precedence this backend silently ignored the
        // field and ran the base image's CMD instead, which for an
        // `ubuntu` base is `/bin/bash`: it exits immediately under
        // `run -d` with no TTY.
        let user_cmd = if config.container.command.is_empty() {
            super::wrapper::user_cmd(self.runner, &user_image).map_err(|error| {
                BackendError::Failed(format!(
                    "cannot determine cage entrypoint: {error}; set CMD in \
                     your Containerfile or use a scaffold that provides one"
                ))
            })?
        } else {
            config.container.command.clone()
        };

        // 5.
        super::egress_config::render_egress_config(
            self.paths,
            config,
            deploy_name,
            self.version,
            &crate::hostenv::RealHost,
        )
        .map_err(|error| BackendError::Failed(error.to_string()))?;

        // 6.
        if !quiet {
            output::echo(&format!(
                "Building apple-container wrapper for {deploy_name}..."
            ));
        }
        self.build_wrapper(deploy_name, &user_image, &user_cmd, no_cache)?;
        if !quiet {
            output::echo(&format!(
                "Built {}",
                super::wrapper::wrapped_image_name(deploy_name)
            ));
        }
        Ok(())
    }

    /// `_build_egress_image_if_missing`.
    ///
    /// The "already present" short-circuit is only safe because the tag
    /// carries a hash of the build inputs: editing `supervisor-egress.sh`
    /// or any `COPY`ed file yields a tag that is by definition not
    /// present, so the fix rebuilds and ships. A version-only tag would
    /// keep serving the stale image within a release, which is how the
    /// #186 log-permission fix failed to reach hosts that already had
    /// `agentcage-egress:0.32.0`.
    ///
    /// `--no-cache` / `--pull` rebuild even when the tag *is* present:
    /// the operator asked for a clean rebuild, and the shared image is
    /// part of what they asked about.
    ///
    /// # Errors
    ///
    /// [`BackendError::Assets`] if the embedded tree cannot be
    /// materialized, [`BackendError::Failed`] if the build fails.
    fn build_egress_image_if_missing(
        &self,
        no_cache: bool,
        pull: bool,
        quiet: bool,
    ) -> Result<(), BackendError> {
        let image = self.egress_image();
        let cli = self.cli();
        if !(no_cache || pull) && cli.image_inspect(&image).ok().flatten().is_some() {
            if !quiet {
                output::echo(&format!(
                    "Egress image {image} already present; skipping rebuild"
                ));
            }
            return Ok(());
        }
        if !quiet {
            output::echo(&format!("Building shared egress image {image}..."));
        }
        // The Python's build context is the installed package's own
        // `data/` directory; a single binary has none, so the embedded
        // tree is materialized into a cache directory instead
        // (docs/history/rust-port-plan.md section 2.1). The Containerfile expects
        // that directory as the context so its
        // `COPY containers/supervisor-egress.sh` resolves.
        let context = agentcage_assets::extract::build_context().map_err(BackendError::Assets)?;
        let argv = super::image::egress_build_argv(
            &image,
            &context,
            super::image::BuildFlags { no_cache, pull },
        );
        let outcome = output::pause_active_spinner(|| cli.run_streaming(argv, false));
        if exit_code(&outcome) != Some(0) {
            return Err(BackendError::Failed(format!(
                "`container build` for the shared egress image {image} failed"
            )));
        }
        Ok(())
    }

    /// `build_wrapper` — render, stage, build.
    ///
    /// The build context is a temporary directory holding exactly two
    /// files, the Containerfile and `cage-init.sh`, and it is removed
    /// afterwards whether the build succeeded or not.
    ///
    /// # Errors
    ///
    /// [`BackendError::Failed`] from the render, the staging or the
    /// build.
    fn build_wrapper(
        &self,
        deploy_name: &str,
        user_image: &str,
        user_cmd: &[String],
        no_cache: bool,
    ) -> Result<(), BackendError> {
        let image = super::wrapper::wrapped_image_name(deploy_name);
        let containerfile = super::wrapper::render_wrapper_containerfile(user_image, user_cmd)
            .map_err(BackendError::Failed)?;

        let context = staging_dir(deploy_name)?;
        let result = (|| -> Result<(), BackendError> {
            let path = context.join("Containerfile");
            std::fs::write(&path, &containerfile)
                .map_err(|error| BackendError::Failed(format!("{}: {error}", path.display())))?;
            super::wrapper::stage_build_context(&context).map_err(BackendError::Failed)?;
            let mut argv = vec![
                "build".to_owned(),
                "-t".to_owned(),
                image.clone(),
                "-f".to_owned(),
                path.display().to_string(),
            ];
            if no_cache {
                argv.push("--no-cache".to_owned());
            }
            argv.push(context.display().to_string());
            let outcome = output::pause_active_spinner(|| self.cli().run_streaming(argv, false));
            if exit_code(&outcome) != Some(0) {
                return Err(BackendError::Failed(format!(
                    "`container build` for the wrapper image {image} failed"
                )));
            }
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&context);
        result
    }
}

/// `tempfile.TemporaryDirectory(prefix="agentcage-apple-build-")`.
///
/// Under the OS temporary directory, with the pid and the cage name in
/// it so two concurrent builds cannot collide. Created fresh: a
/// leftover from a crashed build would otherwise contribute files to
/// the context.
fn staging_dir(deploy_name: &str) -> Result<PathBuf, BackendError> {
    let dir = std::env::temp_dir().join(format!(
        "agentcage-apple-build-{}-{deploy_name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)
        .map_err(|error| BackendError::Failed(format!("{}: {error}", dir.display())))?;
    Ok(dir)
}

// ── the live DNS reload ──────────────────────────────────────

/// The egress-side reload script.
///
/// When the runtime servers-file exists, raise the supervisor's reload
/// flag; otherwise SIGHUP dnsmasq through its pidfile.
///
/// Raising the flag rather than regenerating the file is the whole
/// point. The supervisor runs inside the egress microVM from the same
/// image and is the **single** render implementation, so there is no
/// drift between host and guest: its 1s liveness loop sees the flag,
/// re-renders BASELINE + GRANTED zones — granted zones come from
/// `/home/acproxy/dns/granted`, written by the proxy addon inside the
/// egress — and SIGHUPs dnsmasq within about a second. Regenerating
/// from the host's baseline *alone*, which an earlier version did with
/// a `sed`, overwrote the served file with baseline-only lines and
/// clobbered every in-flight policy-API granted zone out of dnsmasq on
/// every operator `domain add`/`rm` (the round-11 finding).
///
/// The fallback matters too: with no runtime file the egress reads the
/// bind-mounted file directly, so a plain SIGHUP is enough. It signals
/// the pid rather than using `pkill` because dnsmasq runs under
/// `setpriv --reuid=acdns` and the pidfile is the only thing that
/// names it unambiguously.
const EGRESS_RELOAD_SH: &str = "rt=/run/agentcage/dns-allowlist.egress.conf; \
     if [ -f \"$rt\" ]; then : > /home/acproxy/dns/reload; \
     else kill -HUP \"$(cat /home/acdns/dnsmasq.pid)\" 2>/dev/null || true; fi";

/// The cage-side reload script.
///
/// Regenerating the cage-local servers-file from the BASELINE only is
/// **intentional** and must not be "fixed" to match the egress side.
/// The cage-local file is baseline-scoped by design: an unknown or
/// granted zone gets the TEST-NET sinkhole answer and the request still
/// reaches the egress's transparent interception, where SNI and Host
/// are the enforcement authority, and the real upstream resolution
/// happens at the egress — which does carry the granted zones. The cage
/// has no supervisor and no granted-zones source of its own, so there
/// is no flag for it to raise.
const CAGE_RELOAD_SH: &str = "p=/run/agentcage/dnsmasq.pid; \
     up=$(ip route 2>/dev/null | awk \"/^default/{print \\$3; exit}\"); \
     [ -n \"$up\" ] && [ -f /run/agentcage/dns-allowlist.cage.conf ] && \
     sed \"s#/[^/]*\\$#/$up#\" /etc/agentcage/dns-allowlist.conf \
     > /run/agentcage/dns-allowlist.cage.conf 2>/dev/null; \
     [ -f \"$p\" ] && kill -HUP \"$(cat \"$p\")\" || true";

impl AppleBackend<'_> {
    /// `reload_domains` — apply an allowlist change to a running cage
    /// in place.
    ///
    /// No rebuild and no restart, so an interactive `agentcage run`
    /// session survives a `domain add`. The egress bind-mounts the
    /// three rendered files read-only, and
    /// [`super::egress_config::render_egress_config`] rewrites them
    /// **in place** — same inode — so virtiofs surfaces the new bytes
    /// inside the running microVM without the mount being recreated.
    ///
    /// Then, in order:
    ///
    /// 1. validate the rewritten allowlist *inside* the egress with
    ///    `dnsmasq --test`, and on failure put the old file back, so a
    ///    malformed allowlist cannot silently break DNS;
    /// 2. make the egress pick up the new baseline
    ///    ([`EGRESS_RELOAD_SH`]);
    /// 3. regenerate and SIGHUP the **cage-local** dnsmasq
    ///    ([`CAGE_RELOAD_SH`]) — the load-bearing one, since the
    ///    workload resolves through `127.0.0.1:53` inside the cage;
    /// 4. nothing for `proxy-config.yaml`: the mitmproxy addon polls
    ///    its mtime per request and hot-reloads itself.
    ///
    /// # Errors
    ///
    /// [`BackendError::Failed`] when the render fails, or when dnsmasq
    /// rejects the new allowlist — in which case the previous file has
    /// already been restored.
    pub fn reload_domains(&self, config: &Config, name: &str) -> Result<(), BackendError> {
        let allow_dest = self
            .paths
            .apple_egress_config_dir(name)
            .join("dns-allowlist.conf");
        let previous = std::fs::read_to_string(&allow_dest).ok();

        super::egress_config::render_egress_config(
            self.paths,
            config,
            name,
            self.version,
            &crate::hostenv::RealHost,
        )
        .map_err(|error| BackendError::Failed(error.to_string()))?;

        // With the egress down the rewrite is the whole job: the next
        // start reads the new files and there is nothing to signal.
        if !self.is_running(name, "egress") {
            return Ok(());
        }
        let container = format!("{name}-egress");
        let cli = self.cli();

        // 1.
        let probe = cli.run(
            [
                "exec",
                &container,
                "dnsmasq",
                "--test",
                "--servers-file=/etc/agentcage/dns-allowlist.conf",
            ],
            false,
        );
        if exit_code(&probe) != Some(0) {
            if let Some(previous) = previous {
                let _ = std::fs::write(&allow_dest, previous);
            }
            let detail = probe
                .as_ref()
                .ok()
                .map(|output| {
                    let stderr = output.stderr_text();
                    let text = if stderr.trim().is_empty() {
                        output.stdout_text()
                    } else {
                        stderr
                    };
                    text.trim().to_owned()
                })
                .unwrap_or_default();
            return Err(BackendError::Failed(format!(
                "dnsmasq rejected the new allowlist; reverted it and left the \
                 egress serving the previous config. Details:\n{detail}"
            )));
        }

        // 2.
        let _ = cli.run(["exec", &container, "sh", "-c", EGRESS_RELOAD_SH], false);

        // 3. Best-effort throughout: the cage's dnsmasq is itself
        // optional, since a base image may not have one.
        if self.is_running(name, "cage") {
            let _ = cli.run(["exec", name, "sh", "-c", CAGE_RELOAD_SH], false);
        }

        // 4. Nothing to do.
        Ok(())
    }
}

// ── the image store, for `cage update` ───────────────────────

/// Apple's image store, as an [`ImageInspector`].
///
/// `cage update` fingerprints the digests of every image that can
/// affect a deployment, and on this backend those images are in
/// Apple's store rather than podman's. A host-podman inspect of them
/// would answer `unavailable` for every reference — a digest set that
/// never matches the previous one, so `cage update` would rebuild on
/// every invocation, and `cage update` is defined by *not* doing that.
/// The vm backend has the same problem with the guest's store and
/// solves it the same way.
#[derive(Debug)]
pub struct AppleImages<'a> {
    runner: &'a dyn CommandRunner,
}

impl<'a> AppleImages<'a> {
    /// An inspector over this host's `container` image store.
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Self { runner }
    }
}

impl agentcage_exec::tools::podman::ImageInspector for AppleImages<'_> {
    fn pull(&self, reference: &str) -> Result<bool, ExecError> {
        // Streaming, because Apple's CLI writes its own fetch progress
        // and a pull is the slowest thing `cage update` does.
        let outcome = output::pause_active_spinner(|| {
            AppleContainer::new(self.runner).run_streaming(["image", "pull", reference], false)
        });
        Ok(exit_code(&outcome) == Some(0))
    }

    fn image_inspect(&self, reference: &str) -> Result<serde_json::Value, ExecError> {
        // `Ok(None)` is an image that is not there. The caller turns an
        // `Err` into the identity `"unavailable"`, which is exactly
        // what `_image_identity(None)` answers in the Python, so the
        // two spellings agree on the recorded value.
        AppleContainer::new(self.runner)
            .image_inspect(reference)?
            .ok_or_else(|| ExecError::not_found(reference))
    }
}

#[cfg(test)]
mod tests {
    use agentcage_exec::FakeRunner;
    use agentcage_state::{Paths, TestDir};

    use super::AppleBackend;

    /// A deployed apple cage whose store is the plaintext file store.
    ///
    /// `plaintext` keeps the values in the deployment directory rather
    /// than the macOS keychain, so this exercises the real store code
    /// without touching the operator's login keychain — and so it runs
    /// on Linux CI, where that keychain does not exist at all.
    fn staged(dir: &TestDir, name: &str) -> Paths {
        let paths = Paths::under(dir.path());
        std::fs::create_dir_all(paths.apple_root()).expect("apple root");
        std::fs::write(
            paths.apple_root().join(format!("{name}.json")),
            r#"{"name":"x","secrets_backend":"plaintext","secrets_allow_plaintext":true}"#,
        )
        .expect("unit json");
        std::fs::create_dir_all(paths.deployment_dir(name)).expect("deployment dir");
        std::fs::write(
            paths.deployment_dir(name).join("pending_secrets.json"),
            r#"[["API_KEY","a-value"],["OTHER_KEY","b-value"]]"#,
        )
        .expect("store");
        paths
    }

    fn stored(paths: &Paths, name: &str) -> String {
        std::fs::read_to_string(paths.deployment_dir(name).join("pending_secrets.json"))
            .unwrap_or_default()
    }

    /// `cage destroy` promises "Scoped secrets will also be removed".
    ///
    /// It was a false promise here: the flag was accepted and dropped,
    /// so a destroyed cage left its values in the store — in the
    /// keychain, where nothing on disk was left to say they existed.
    #[test]
    fn destroy_forgets_the_cages_secrets() {
        let dir = TestDir::new("apple-destroy-secrets");
        let paths = staged(&dir, "demo");
        let runner = FakeRunner::new();
        // No `container` binary anywhere, so every runtime call is a
        // no-op and what is left under test is the store half alone.
        runner.assume_missing();
        let backend = AppleBackend::new(&paths, &runner, "0.0.0");

        let removed = backend.forget_secrets("demo");

        assert!(
            !stored(&paths, "demo").contains("a-value"),
            "the value survived: {}",
            stored(&paths, "demo")
        );
        assert_eq!(
            removed,
            vec![
                "secret:demo.API_KEY".to_owned(),
                "secret:demo.OTHER_KEY".to_owned()
            ],
            "reported the way the container backend reports its podman secrets"
        );
    }

    /// `--keep-secrets` has to mean it, or the flag is a lie in the
    /// other direction.
    #[test]
    fn destroy_keeps_secrets_when_asked() {
        let dir = TestDir::new("apple-destroy-keep");
        let paths = staged(&dir, "demo");
        let runner = FakeRunner::new();
        runner.assume_missing();
        let backend = AppleBackend::new(&paths, &runner, "0.0.0");

        let removed = backend
            .destroy_resources("demo", true)
            .expect("destroy succeeds");

        assert!(
            stored(&paths, "demo").contains("a-value"),
            "the value was removed despite --keep-secrets"
        );
        assert!(
            !removed.iter().any(|r| r.starts_with("secret:")),
            "{removed:?}"
        );
    }

    /// A store that cannot be resolved must not fail the destroy: a
    /// cage that cannot be removed because its secrets cannot be is
    /// worse than a leftover the operator can see.
    #[test]
    fn an_unresolvable_store_does_not_fail_the_destroy() {
        let dir = TestDir::new("apple-destroy-unresolvable");
        let paths = Paths::under(dir.path());
        std::fs::create_dir_all(paths.apple_root()).expect("apple root");
        // systemd-creds is unavailable here, so `resolve_store` refuses.
        std::fs::write(
            paths.apple_root().join("demo.json"),
            r#"{"name":"x","secrets_backend":"systemd-creds"}"#,
        )
        .expect("unit json");
        let runner = FakeRunner::new();
        runner.assume_missing();
        let backend = AppleBackend::new(&paths, &runner, "0.0.0");

        assert!(backend.forget_secrets("demo").is_empty());
    }

    /// The apple-container half of "a relay or agent credential is the
    /// secret store's entry NAME, whatever its scheme, on every
    /// backend" — the behaviour the container and vm backends now
    /// match. Each is staged from the store under the name after the
    /// colon (`env:` and `systemd-creds:` alike) into the egress-only
    /// bind mount, and never becomes a cage `-e` flag. Nothing here
    /// reads the host environment.
    #[test]
    fn relay_and_agent_credentials_are_staged_from_the_store_by_name() {
        let dir = TestDir::new("apple-relay-agent-staging");
        let paths = Paths::under(dir.path());
        std::fs::create_dir_all(paths.deployment_dir("demo")).expect("deployment dir");
        std::fs::write(
            paths.deployment_dir("demo").join("pending_secrets.json"),
            r#"[["MAIL_USER","stored-user"],["MAIL_PW","stored-password"],["DECIDER_KEY","stored-key"]]"#,
        )
        .expect("store");
        // What `generate_units` records for a relay with
        // `user_source: env:MAIL_USER` / `password_source:
        // systemd-creds:MAIL_PW` and a decider on `env:DECIDER_KEY`.
        let meta = super::Meta::parse(
            r#"{"name":"demo","secrets_backend":"plaintext","secrets_allow_plaintext":true,
                "relay_secret_envs":["MAIL_USER","MAIL_PW","DECIDER_KEY"],
                "decider_api_key_source":"env:DECIDER_KEY"}"#,
        )
        .expect("unit json");
        let runner = FakeRunner::new();
        runner.assume_missing();
        let backend = AppleBackend::new(&paths, &runner, "0.0.0");

        let cage_envs = backend.stage_secrets("demo", &meta);

        assert!(cage_envs.is_empty(), "{cage_envs:?} would reach the cage");
        let secrets = paths.apple_secrets_dir("demo");
        for (name, value) in [
            ("MAIL_USER", "stored-user"),
            ("MAIL_PW", "stored-password"),
            ("DECIDER_KEY", "stored-key"),
        ] {
            assert_eq!(
                std::fs::read_to_string(secrets.join(name)).ok().as_deref(),
                Some(value),
                "{name}"
            );
        }
    }
}
