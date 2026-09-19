//! `backends/container.py` — rootless podman plus quadlet units.
//!
//! The one backend this PR ports (RUST-PORT-PLAN.md Track D, D6). The
//! `vm` and `apple-container` backends are Track E; everything here that
//! they would share — unit installation, quadlet removal — already lives
//! in `agentcage-state`, so this file is the podman-and-systemd half
//! only.
//!
//! # What it does *not* do
//!
//! `backends/container.py:70` gets its podman build context for free:
//! the installed package's own `data/` directory is on disk, so
//! `build_artifacts` just points `podman build` at it. A single binary
//! has no such directory, so the context comes from
//! [`agentcage_assets::extract::build_context`], which materializes the
//! embedded tree into a cache dir keyed on the binary's version and
//! content hash. That is §2.1 of the plan, and it is the only structural
//! difference between this file and the Python it ports.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use agentcage_core::config::{Config, ConfigError};
use agentcage_core::quadlets::{GenerateOptions, Quadlets, generate_quadlets};
use agentcage_exec::tools::podman::{BuildOptions, Podman, secret_env_names};
use agentcage_exec::{CommandRunner, ExecError};
use agentcage_state::{Paths, Units};

use crate::hostenv::RealQuadletHost;

/// The capability set the egress image's build needs.
///
/// `setfcap` for dnsmasq's `NET_BIND_SERVICE` file capability; the rest
/// mirror the legacy proxy build's user creation and `apt-get install`
/// steps. Order is the Python's, because it is the order that reaches
/// argv and the order the argv test pins.
pub const EGRESS_BUILD_CAPS: [&str; 6] = [
    "CAP_CHOWN",
    "CAP_FOWNER",
    "CAP_SETUID",
    "CAP_SETGID",
    "CAP_DAC_OVERRIDE",
    "CAP_SETFCAP",
];

/// The two services a v0.22 cage runs.
///
/// `ContainerBackend.service_names`. Not a function of the cage: the
/// shape is fixed, and `cage list` / `cage show` / `verify` all count
/// against it.
pub const SERVICE_NAMES: [&str; 2] = ["cage", "egress"];

/// What went wrong deploying.
#[derive(Debug)]
pub enum BackendError {
    /// podman or systemctl could not be run, or exited non-zero where
    /// the Python would have raised.
    Exec(ExecError),
    /// The renderer refused the config.
    Config(ConfigError),
    /// A state read or write failed.
    State(agentcage_state::StateError),
    /// The embedded asset tree could not be materialized.
    Assets(std::io::Error),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exec(e) => write!(f, "{e}"),
            Self::Config(e) => write!(f, "{e}"),
            Self::State(e) => write!(f, "{e}"),
            Self::Assets(e) => write!(f, "could not materialize the build context: {e}"),
        }
    }
}

impl std::error::Error for BackendError {}

impl From<ExecError> for BackendError {
    fn from(error: ExecError) -> Self {
        Self::Exec(error)
    }
}

impl From<ConfigError> for BackendError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<agentcage_state::StateError> for BackendError {
    fn from(error: agentcage_state::StateError) -> Self {
        Self::State(error)
    }
}

/// `ContainerBackend`.
#[derive(Debug)]
pub struct ContainerBackend<'a> {
    podman: Podman<'a>,
    units: Units<'a>,
    paths: &'a Paths,
    version: &'a str,
}

impl<'a> ContainerBackend<'a> {
    /// A backend bound to these paths, this runner and this version.
    ///
    /// `version` is `importlib.metadata.version("agentcage")` in the
    /// Python: it tags the egress image, it is stamped into the cage
    /// quadlet, and it is written into `metadata.json`. One value, so
    /// the three cannot drift.
    #[must_use]
    pub fn new(paths: &'a Paths, runner: &'a dyn CommandRunner, version: &'a str) -> Self {
        Self::with_elevation(paths, runner, version, agentcage_exec::Elevation::detect())
    }

    /// The same, with the `runuser` prefix decided by the caller.
    ///
    /// What the argv tests use, so the recorded sequence does not depend
    /// on whether the suite happens to run under `sudo`.
    #[must_use]
    pub fn with_elevation(
        paths: &'a Paths,
        runner: &'a dyn CommandRunner,
        version: &'a str,
        elevation: agentcage_exec::Elevation,
    ) -> Self {
        Self {
            podman: Podman::with_elevation(runner, elevation.clone()),
            units: Units::with_elevation(paths, runner, elevation),
            paths,
            version,
        }
    }

    /// The podman wrapper, for callers that need one more verb.
    #[must_use]
    pub fn podman(&self) -> &Podman<'a> {
        &self.podman
    }

    /// The unit lifecycle.
    #[must_use]
    pub fn units(&self) -> &Units<'a> {
        &self.units
    }

    /// `check_prerequisites` — one issue string per unmet requirement.
    ///
    /// Only ever "Podman is not available" for this backend, and it is
    /// a list rather than a bool because the caller prints every issue
    /// under one header and the other two backends have several.
    #[must_use]
    pub fn check_prerequisites(&self) -> Vec<String> {
        if self.podman.info().is_err() {
            vec!["Podman is not available".to_owned()]
        } else {
            Vec::new()
        }
    }

    /// `ensure_ready` — nothing to recover.
    ///
    /// Rootless podman's systemd socket activation brings the service
    /// up on demand when the quadlets start. Kept as a method so the
    /// create/update path reads the same as the Python's.
    pub const fn ensure_ready(&self) {}

    /// The egress image tag for this version.
    #[must_use]
    pub fn egress_image(&self) -> String {
        format!("agentcage-egress:{}", self.version)
    }

    /// `build_artifacts` — build the static egress image.
    ///
    /// The user's own image is built and pulled by the create/update
    /// path, not here; this is the sidecar that mitmproxy and dnsmasq
    /// run in, and it is shared by every cage on the host.
    ///
    /// # Errors
    ///
    /// [`BackendError::Assets`] if the embedded tree cannot be
    /// extracted, [`BackendError::Exec`] if the build fails.
    pub fn build_artifacts(
        &self,
        no_cache: bool,
        pull: bool,
        quiet: bool,
    ) -> Result<(), BackendError> {
        let context = agentcage_assets::extract::build_context().map_err(BackendError::Assets)?;
        let containerfile = context.join("containers").join("Containerfile.egress");
        let tag = self.egress_image();
        if !quiet {
            println!("Building egress image ({tag})...");
        }
        self.podman.build_image(
            &tag,
            &context.display().to_string(),
            &BuildOptions {
                containerfile: Some(containerfile.display().to_string()),
                cap_add: EGRESS_BUILD_CAPS.iter().map(|c| (*c).to_owned()).collect(),
                no_cache,
                pull,
                build_args: Vec::new(),
                quiet,
            },
        )?;
        Ok(())
    }

    /// `generate_units` — render this cage's quadlets.
    ///
    /// Two probes happen before the render and both are the Python's:
    /// `podman info` decides `rootless=`, and the secret store's env
    /// names make `Secret=` emission store-aware (issue #262). A failed
    /// store query falls back to `None`, which is the legacy
    /// emit-everything behaviour.
    ///
    /// # Errors
    ///
    /// [`BackendError::Exec`] if `podman info` fails — the Python lets
    /// that propagate too, since a host without podman cannot deploy a
    /// container cage. [`BackendError::Config`] on a refusal from the
    /// renderer.
    pub fn generate_units(
        &self,
        config: &Config,
        config_host_path: &str,
        patches_host_dir: &str,
        deploy_name: &str,
        used_octets: Option<&BTreeSet<u32>>,
        network_octet: Option<u32>,
    ) -> Result<Quadlets, BackendError> {
        let info = self.podman.info()?;
        // `.get("host", {}).get("security", {}).get("rootless", True)`
        // — the default is True, which matters: a podman whose info
        // omits the key is assumed rootless, as the Python assumes.
        let rootless = info
            .get("host")
            .and_then(|h| h.get("security"))
            .and_then(|s| s.get("rootless"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let store_secrets: Option<BTreeSet<String>> = secret_env_names(&self.podman, deploy_name)
            .ok()
            .map(|names| names.into_iter().collect());
        let state = self.paths.quadlet_state_paths();
        let host = RealQuadletHost::new(self.paths.data_root());
        let quadlets = generate_quadlets(
            config,
            &GenerateOptions {
                config_host_path,
                patches_host_dir,
                deploy_name,
                rootless,
                used_octets,
                network_octet,
                store_secrets: store_secrets.as_ref(),
                state: &state,
                version: self.version,
            },
            &host,
        )?;
        Ok(quadlets)
    }

    /// `install_units` — write each unit where its extension says and
    /// `daemon-reload`.
    ///
    /// # Errors
    ///
    /// [`BackendError::State`] on a failed write or reload.
    pub fn install_units(&self, quadlets: &Quadlets, quiet: bool) -> Result<(), BackendError> {
        self.units.install(
            quadlets
                .files
                .iter()
                .map(|(name, body)| (name.as_str(), body.as_str())),
        )?;
        if !quiet {
            println!(
                "Installed quadlet files to {}/",
                self.paths.quadlet_dir().display()
            );
        }
        Ok(())
    }

    /// `start` — restart the network and volume units, then start the
    /// cage.
    ///
    /// The restarts come first and their failures are *warnings*, which
    /// is the Python's deliberate shape: systemd may still consider a
    /// network or volume unit active from a previous run whose podman
    /// resources `cage destroy` already removed, and restarting is how
    /// they get recreated. A genuine failure surfaces on the cage unit
    /// below.
    ///
    /// # Errors
    ///
    /// [`BackendError::State`] only from `start`ing the cage service —
    /// the warnings above never fail the deploy.
    pub fn start(&self, name: &str, quiet: bool) -> Result<(), BackendError> {
        for unit in [
            format!("{name}-net-network.service"),
            format!("{name}-certs-volume.service"),
            format!("{name}-public-certs-volume.service"),
        ] {
            if let Err(error) = self.units.restart(&unit) {
                if !quiet {
                    let what = if unit.ends_with("-net-network.service") {
                        "network service"
                    } else {
                        "volume service"
                    };
                    eprintln!("warning: failed to restart {what}: {error}");
                }
            }
        }
        if self.units.has_podman_storage_volume(name) {
            // The Python swallows this one without a warning.
            let _ = self
                .units
                .restart(&format!("{name}-podman-storage-volume.service"));
        }
        self.units.start(&format!("{name}-cage.service"))?;
        if !quiet {
            println!("Started {name}-cage");
        }
        Ok(())
    }

    /// `stop` — stop both services, warning on each failure.
    pub fn stop(&self, name: &str) {
        for service in SERVICE_NAMES {
            if let Err(error) = self.units.stop(&format!("{name}-{service}.service")) {
                eprintln!("warning: failed to stop {name}-{service}: {error}");
            }
        }
    }

    /// `restart` — restart both services, warning on each failure.
    pub fn restart(&self, name: &str) {
        for service in SERVICE_NAMES {
            if let Err(error) = self.units.restart(&format!("{name}-{service}.service")) {
                eprintln!("warning: failed to restart {name}-{service}: {error}");
            }
        }
    }

    /// `is_running` — whether `<name>-<service>` is a running container.
    ///
    /// A podman that cannot be reached answers `false`, as the Python's
    /// `container_running` does by returning the subprocess's non-zero
    /// exit.
    #[must_use]
    pub fn is_running(&self, name: &str, service: &str) -> bool {
        self.podman
            .container_running(&format!("{name}-{service}"))
            .unwrap_or(false)
    }

    /// How many of this cage's services are up, out of how many.
    #[must_use]
    pub fn running_count(&self, name: &str) -> (usize, usize) {
        let running = SERVICE_NAMES
            .iter()
            .filter(|service| self.is_running(name, service))
            .count();
        (running, SERVICE_NAMES.len())
    }

    /// `has_resources` — whether any of this cage's quadlet files exist.
    #[must_use]
    pub fn has_resources(&self, name: &str) -> bool {
        agentcage_state::QUADLET_SUFFIXES.iter().any(|suffix| {
            self.paths
                .quadlet_dir()
                .join(format!("{name}{suffix}"))
                .exists()
        })
    }

    /// `destroy_resources` — quadlets, podman network, volumes, and
    /// (unless kept) the cage's scoped secrets.
    ///
    /// Returns the removal descriptions `cage destroy` prints, in the
    /// Python's order: quadlet filenames, then `network:`, then the
    /// three `volume:`s, then each `secret:`.
    ///
    /// # Errors
    ///
    /// [`BackendError::State`] if a quadlet file cannot be unlinked or
    /// the reload fails. Podman removals are best-effort and report
    /// only what actually went away.
    pub fn destroy_resources(
        &self,
        name: &str,
        keep_secrets: bool,
    ) -> Result<Vec<String>, BackendError> {
        let mut removed = self.units.remove_quadlets(name)?;

        if self
            .podman
            .network_remove(&format!("{name}-net"))
            .unwrap_or(false)
        {
            removed.push(format!("network:{name}-net"));
        }
        for volume in [
            format!("agentcage-certs-{name}"),
            format!("agentcage-public-certs-{name}"),
            format!("agentcage-podman-{name}"),
        ] {
            if self.podman.volume_remove(&volume).unwrap_or(false) {
                removed.push(format!("volume:{volume}"));
            }
        }

        if !keep_secrets {
            let prefix = format!("{name}.");
            for secret in self.podman.secret_list(&prefix).unwrap_or_default() {
                if self.podman.secret_remove(&secret).unwrap_or(false) {
                    removed.push(format!("secret:{secret}"));
                }
            }
        }
        Ok(removed)
    }

    /// `container_log_driver` — the driver podman actually picked.
    ///
    /// Read back rather than derived: podman selects `journald` only
    /// when conmon can write there and falls back to `k8s-file`
    /// silently otherwise, per container, at run time.
    #[must_use]
    pub fn container_log_driver(&self, container: &str) -> String {
        self.podman
            .container_inspect(container)
            .ok()
            .and_then(|info| {
                info.get("HostConfig")?
                    .get("LogConfig")?
                    .get("Type")?
                    .as_str()
                    .map(str::to_lowercase)
            })
            .unwrap_or_default()
    }

    /// `audit_reads_journal` — whether this cage's audit stream is in
    /// the journal.
    ///
    /// An unreadable container answers `true`: the journal is then the
    /// only place history could still live.
    #[must_use]
    pub fn audit_reads_journal(&self, name: &str) -> bool {
        let driver = self.container_log_driver(&format!("{name}-egress"));
        !matches!(driver.as_str(), "k8s-file" | "json-file")
    }

    /// `audit_argv` — the command that prints this cage's audit stream.
    ///
    /// Reading the wrong source is silent — the proxy looks healthy and
    /// `cage audit` simply prints nothing — so the source is chosen to
    /// match the driver rather than assumed.
    #[must_use]
    pub fn audit_argv(&self, name: &str, since: Option<&str>, follow: bool) -> Vec<String> {
        if self.audit_reads_journal(name) {
            let mut argv = vec![
                "journalctl".to_owned(),
                "--user".to_owned(),
                "-u".to_owned(),
                format!("{name}-egress"),
                "-o".to_owned(),
                "cat".to_owned(),
            ];
            if let Some(since) = since {
                argv.push("--since".to_owned());
                argv.push(since.to_owned());
            }
            if follow {
                argv.push("-f".to_owned());
            } else {
                // Over-read; many lines are not audit entries.
                argv.push("-n".to_owned());
                argv.push("10000".to_owned());
            }
            return argv;
        }

        // `podman logs` takes Go durations / RFC3339, not journalctl's
        // "10 minutes ago", so `since` is not forwarded. The caller
        // applies the time filter post-parse on every backend.
        //
        // `_podman_cmd()`, not a bare `podman`: under `sudo` the
        // elevation prefix is what reaches the operator's own podman.
        let mut argv = self.podman.base().arg("logs").argv();
        if follow {
            argv.push("-f".to_owned());
        } else {
            argv.push("--tail".to_owned());
            argv.push("10000".to_owned());
        }
        argv.push(format!("{name}-egress"));
        argv
    }

    /// The quadlet directory, for the failure hint `cage create` prints.
    #[must_use]
    pub fn unit_dir(&self) -> &Path {
        self.paths.quadlet_dir()
    }
}

/// `services.patches_work_dir` — the shared patches directory, created.
///
/// # Errors
///
/// [`std::io::Error`] if it cannot be created.
pub fn patches_work_dir(paths: &Paths) -> std::io::Result<PathBuf> {
    let dir = paths.patches_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
