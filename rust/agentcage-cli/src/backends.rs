//! `backends/__init__.py` — the backend a cage's `isolation:` names.
//!
//! The Python's `get_backend(config)` returns one of three objects that
//! answer to the same protocol (`backend.py`), and every command body
//! calls it rather than naming a backend. There is no such protocol
//! here: the three backends were ported one at a time, each with the
//! argv shape its own tests assert, and a trait over them would have
//! had to be invented before two of them existed.
//!
//! So this is the dispatch, spelled as an enum. Two arms, because two
//! backends can execute: `container` (PR D6) and `vm` (PRs E1 + E4).
//! `apple-container`'s execution half is E5, and until it lands an
//! `apple-container` cage takes the [`AnyBackend::refusal`] path rather
//! than being addressed by the wrong runtime — the failure mode that
//! makes this enum worth having, since a container-backend probe of a
//! `vm` cage does not error, it answers *"not running"*.
//!
//! # What the arms do and do not share
//!
//! Only the protocol surface is here. Anything one backend has and the
//! other does not — the container backend's log-driver probe, the vm
//! backend's guest-local grants overlay — stays on the concrete type and
//! is reached by matching. The enum exists to stop a command body from
//! *assuming* a backend, not to pretend the two are interchangeable.

use std::collections::BTreeSet;
use std::path::PathBuf;

use agentcage_core::config::Config;
use agentcage_core::quadlets::Quadlets;
use agentcage_exec::CommandRunner;
use agentcage_state::Paths;

use crate::backend::{BackendError, ContainerBackend, SERVICE_NAMES};
use crate::vm::VmBackend;

/// The backend a cage's `isolation:` selects.
#[derive(Debug)]
pub enum AnyBackend<'a> {
    /// `isolation: container` — rootless podman and quadlets on the host.
    Container(ContainerBackend<'a>),
    /// `isolation: vm` — a Lima guest with podman and quadlets inside.
    Vm(VmBackend<'a>),
}

impl<'a> AnyBackend<'a> {
    /// `get_backend(config)`.
    ///
    /// An unrecognized isolation resolves to the container backend,
    /// which is the Python's fall-through — `apple-container` reaches
    /// that arm here too, and every command that could act on one gates
    /// on [`Self::refusal`] first.
    #[must_use]
    pub fn new(
        isolation: &str,
        paths: &'a Paths,
        runner: &'a dyn CommandRunner,
        version: &'a str,
    ) -> Self {
        if isolation == "vm" {
            Self::Vm(VmBackend::new(paths, runner, version))
        } else {
            Self::Container(ContainerBackend::new(paths, runner, version))
        }
    }

    /// The Track E refusal for a backend that cannot be executed yet,
    /// or `None` when this one can.
    ///
    /// `verb` names the command, so `cage start` on an
    /// `apple-container` cage says `cage start` and not the name of
    /// whichever helper happened to notice.
    #[must_use]
    pub fn refusal(isolation: &str, verb: &str) -> Option<String> {
        (isolation != "container" && isolation != "vm").then(|| {
            format!(
                "error: `{verb}` on the '{isolation}' backend is not ported yet \
                 (RUST-PORT-PLAN.md Track E)"
            )
        })
    }

    /// The container backend, when this is one.
    ///
    /// For the handful of call sites that genuinely need podman on the
    /// host — the log-driver probe, the live secret channel — and that
    /// have nothing to do on the other arm.
    #[must_use]
    pub fn as_container(&self) -> Option<&ContainerBackend<'a>> {
        match self {
            Self::Container(backend) => Some(backend),
            Self::Vm(_) => None,
        }
    }

    /// The vm backend, when this is one.
    #[must_use]
    pub fn as_vm(&self) -> Option<&VmBackend<'a>> {
        match self {
            Self::Vm(backend) => Some(backend),
            Self::Container(_) => None,
        }
    }

    // ── the protocol ─────────────────────────────────────────

    /// `check_prerequisites` — one string per unmet requirement.
    #[must_use]
    pub fn check_prerequisites(&self) -> Vec<String> {
        match self {
            Self::Container(backend) => backend.check_prerequisites(),
            Self::Vm(backend) => backend.check_prerequisites(),
        }
    }

    /// `ensure_ready` — recover whatever can be recovered first.
    pub fn ensure_ready(&self) {
        match self {
            Self::Container(backend) => backend.ensure_ready(),
            Self::Vm(backend) => backend.ensure_ready(),
        }
    }

    /// `build_artifacts` — the images this deploy needs.
    ///
    /// The container backend builds only the egress image and ignores
    /// the config: a container cage's own image is built and pulled by
    /// the create/update path on the host, before this. The vm backend
    /// cannot do that — the host's podman store is not the guest's — so
    /// it builds or pulls the cage image too, which is why the config
    /// is a parameter at all.
    ///
    /// # Errors
    ///
    /// [`BackendError`] from the build.
    pub fn build_artifacts(
        &self,
        config: Option<&Config>,
        deploy_name: &str,
        no_cache: bool,
        pull: bool,
        quiet: bool,
    ) -> Result<(), BackendError> {
        match self {
            Self::Container(backend) => backend.build_artifacts(no_cache, pull, quiet),
            Self::Vm(backend) => {
                backend.build_artifacts(config, deploy_name, no_cache, pull, quiet)
            }
        }
    }

    /// `generate_units` — render this cage's units.
    ///
    /// # Errors
    ///
    /// [`BackendError`] from the renderer.
    pub fn generate_units(
        &self,
        config: &Config,
        config_host_path: &str,
        patches_host_dir: &str,
        deploy_name: &str,
        used_octets: Option<&BTreeSet<u32>>,
        network_octet: Option<u32>,
    ) -> Result<Quadlets, BackendError> {
        match self {
            Self::Container(backend) => backend.generate_units(
                config,
                config_host_path,
                patches_host_dir,
                deploy_name,
                used_octets,
                network_octet,
            ),
            Self::Vm(backend) => backend.generate_units(
                config,
                config_host_path,
                patches_host_dir,
                deploy_name,
                used_octets,
                network_octet,
            ),
        }
    }

    /// `install_units` — write them where this backend keeps them.
    ///
    /// # Errors
    ///
    /// [`BackendError`] from the write or the reload.
    pub fn install_units(&self, units: &Quadlets, quiet: bool) -> Result<(), BackendError> {
        match self {
            Self::Container(backend) => backend.install_units(units, quiet),
            Self::Vm(backend) => backend.install_units(units, quiet),
        }
    }

    /// `start`.
    ///
    /// # Errors
    ///
    /// [`BackendError`] if the cage did not come up.
    pub fn start(&self, name: &str, quiet: bool) -> Result<(), BackendError> {
        match self {
            Self::Container(backend) => backend.start(name, quiet),
            Self::Vm(backend) => backend.start(name, quiet),
        }
    }

    /// `stop`.
    pub fn stop(&self, name: &str) {
        match self {
            Self::Container(backend) => backend.stop(name),
            Self::Vm(backend) => backend.stop(name),
        }
    }

    /// `restart`.
    ///
    /// The container backend restarts two systemd units and reports
    /// each failure as a warning; the vm backend power-cycles the guest
    /// and can fail outright, which is why this returns a `Result` where
    /// `ContainerBackend::restart` does not.
    ///
    /// # Errors
    ///
    /// [`BackendError`] from the vm arm only.
    pub fn restart(&self, name: &str) -> Result<(), BackendError> {
        match self {
            Self::Container(backend) => {
                backend.restart(name);
                Ok(())
            }
            Self::Vm(backend) => backend.restart(name),
        }
    }

    /// `is_running` — is that service up?
    #[must_use]
    pub fn is_running(&self, name: &str, service: &str) -> bool {
        match self {
            Self::Container(backend) => backend.is_running(name, service),
            Self::Vm(backend) => backend.is_running(name, service),
        }
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

    /// `has_resources` — is there anything of this cage's to remove?
    #[must_use]
    pub fn has_resources(&self, name: &str) -> bool {
        match self {
            Self::Container(backend) => backend.has_resources(name),
            Self::Vm(backend) => backend.has_resources(name),
        }
    }

    /// `destroy_resources` — and what was removed, for `cage destroy`
    /// to print.
    ///
    /// # Errors
    ///
    /// [`BackendError`] if something could not be removed.
    pub fn destroy_resources(
        &self,
        name: &str,
        keep_secrets: bool,
    ) -> Result<Vec<String>, BackendError> {
        match self {
            Self::Container(backend) => backend.destroy_resources(name, keep_secrets),
            Self::Vm(backend) => backend.destroy_resources(name, keep_secrets),
        }
    }

    /// `exec_argv` — the argv that runs a command inside a service.
    #[must_use]
    pub fn exec_argv(
        &self,
        name: &str,
        service: &str,
        command: &[String],
        interactive: bool,
        as_root: bool,
    ) -> Vec<String> {
        match self {
            Self::Container(backend) => {
                backend.exec_argv(name, service, command, interactive, as_root)
            }
            Self::Vm(backend) => backend.exec_argv(name, service, command, interactive, as_root),
        }
    }

    /// `audit_argv` — the argv that prints a cage's audit stream.
    #[must_use]
    pub fn audit_argv(&self, name: &str, since: Option<&str>, follow: bool) -> Vec<String> {
        match self {
            Self::Container(backend) => backend.audit_argv(name, since, follow),
            Self::Vm(backend) => backend.audit_argv(name, since, follow),
        }
    }

    /// `unit_dir` — where this backend's units are installed, for the
    /// hint `cage create` prints when a deploy fails.
    #[must_use]
    pub fn unit_dir(&self) -> PathBuf {
        match self {
            Self::Container(backend) => backend.unit_dir().to_path_buf(),
            Self::Vm(backend) => backend.unit_dir(),
        }
    }

    /// The version-pinned egress image tag.
    #[must_use]
    pub fn egress_image(&self) -> String {
        match self {
            Self::Container(backend) => backend.egress_image(),
            Self::Vm(backend) => format!("agentcage-egress:{}", backend.version()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AnyBackend;

    #[test]
    fn only_apple_container_is_refused() {
        assert!(AnyBackend::refusal("container", "cage start").is_none());
        assert!(AnyBackend::refusal("vm", "cage start").is_none());
        let refusal = AnyBackend::refusal("apple-container", "cage start").expect("refused");
        assert!(refusal.contains("`cage start`"), "{refusal}");
        assert!(refusal.contains("apple-container"), "{refusal}");
    }
}
