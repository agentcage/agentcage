//! `backends/__init__.py` — the backend a cage's `isolation:` names.
//!
//! The Python's `get_backend(config)` returns one of three objects that
//! answer to the same protocol (`backend.py`), and every command body
//! calls it rather than naming a backend. There is no such protocol
//! here: the three backends were ported one at a time, each with the
//! argv shape its own tests assert, and a trait over them would have
//! had to be invented before two of them existed.
//!
//! So this is the dispatch, spelled as an enum. Three arms, one per
//! backend that can execute: `container` (PR D6), `vm` (PRs E1 + E4)
//! and `apple-container` (PRs E2/E2b/E3 + E5). Addressing a cage with
//! the wrong runtime is the failure mode that makes this enum worth
//! having, since a container-backend probe of a `vm` cage does not
//! error — it answers *"not running"*.
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

use crate::apple::backend::AppleBackend;
use crate::backend::{BackendError, ContainerBackend, SERVICE_NAMES};
use crate::vm::VmBackend;

/// The backend a cage's `isolation:` selects.
#[derive(Debug)]
pub enum AnyBackend<'a> {
    /// `isolation: container` — rootless podman and quadlets on the host.
    Container(ContainerBackend<'a>),
    /// `isolation: vm` — a Lima guest with podman and quadlets inside.
    Vm(VmBackend<'a>),
    /// `isolation: apple-container` — two sibling Apple microVMs.
    Apple(AppleBackend<'a>),
}

impl<'a> AnyBackend<'a> {
    /// `get_backend(config)`.
    ///
    /// An unrecognized isolation resolves to the container backend,
    /// which is the Python's fall-through. Note that the fall-through
    /// is reached only by a spelling `validate_config` has already
    /// refused, so in practice the three named arms are the three that
    /// happen.
    #[must_use]
    pub fn new(
        isolation: &str,
        paths: &'a Paths,
        runner: &'a dyn CommandRunner,
        version: &'a str,
    ) -> Self {
        match isolation {
            "vm" => Self::Vm(VmBackend::new(paths, runner, version)),
            "apple-container" => Self::Apple(AppleBackend::new(paths, runner, version)),
            _ => Self::Container(ContainerBackend::new(paths, runner, version)),
        }
    }

    /// The Track E refusal for a backend that cannot be executed, or
    /// `None` when this one can.
    ///
    /// Every backend can execute now that E5 has landed, so this
    /// always answers `None` and is kept for one reason: an isolation
    /// spelling that reaches [`Self::new`]'s fall-through would
    /// otherwise be driven by the container backend silently. It is
    /// the guard that turns "a future backend was added and a command
    /// forgot about it" into a refusal instead of a wrong runtime.
    ///
    /// `verb` names the command, so the message says `cage start`
    /// rather than the name of whichever helper noticed.
    #[must_use]
    pub fn refusal(isolation: &str, verb: &str) -> Option<String> {
        const EXECUTABLE: [&str; 3] = ["container", "vm", "apple-container"];
        (!EXECUTABLE.contains(&isolation)).then(|| {
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
            _ => None,
        }
    }

    /// The vm backend, when this is one.
    #[must_use]
    pub fn as_vm(&self) -> Option<&VmBackend<'a>> {
        match self {
            Self::Vm(backend) => Some(backend),
            _ => None,
        }
    }

    /// The apple backend, when this is one.
    ///
    /// For the two commands that have to reach past the protocol:
    /// `domain add`/`rm`, whose live reload is this backend's own, and
    /// `cage exec`, whose argv needs the placeholder map.
    #[must_use]
    pub fn as_apple(&self) -> Option<&AppleBackend<'a>> {
        match self {
            Self::Apple(backend) => Some(backend),
            _ => None,
        }
    }

    // ── the protocol ─────────────────────────────────────────

    /// `check_prerequisites` — one string per unmet requirement.
    #[must_use]
    pub fn check_prerequisites(&self) -> Vec<String> {
        match self {
            Self::Container(backend) => backend.check_prerequisites(),
            Self::Vm(backend) => backend.check_prerequisites(),
            Self::Apple(backend) => backend.check_prerequisites(),
        }
    }

    /// `ensure_ready` — recover whatever can be recovered first.
    pub fn ensure_ready(&self) {
        match self {
            Self::Container(backend) => backend.ensure_ready(),
            Self::Vm(backend) => backend.ensure_ready(),
            // The only arm whose recovery prints: bringing the Apple
            // apiserver up is slow enough to be worth narrating, and
            // `quiet` is how the Python decides.
            Self::Apple(backend) => backend.ensure_ready(false),
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
            Self::Apple(backend) => match config {
                Some(config) => backend.build_artifacts(config, deploy_name, no_cache, pull, quiet),
                // Like the vm arm, this backend builds the cage's own
                // image as well as the shared egress one, so it cannot
                // work from nothing. The container arm can, which is
                // why the parameter is an `Option` at all.
                None => Err(BackendError::Failed(
                    "apple-container needs the cage's config to build its \
                     images; this is a `cage create`/`cage update` path only"
                        .to_owned(),
                )),
            },
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
            // The other four arguments are the quadlet path's. Apple
            // networks are per-cage with an auto-allocated subnet, so
            // there is no shared `10.89.x` pool to coordinate against,
            // and the cage's config is bind-mounted rather than named
            // in a unit. The Python ignores them here too.
            Self::Apple(backend) => backend.generate_units(config, deploy_name),
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
            Self::Apple(backend) => backend.install_units(units, quiet),
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
            Self::Apple(backend) => backend.start(name, quiet),
        }
    }

    /// `stop`.
    pub fn stop(&self, name: &str) {
        match self {
            Self::Container(backend) => backend.stop(name),
            Self::Vm(backend) => backend.stop(name),
            Self::Apple(backend) => backend.stop(name),
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
            Self::Apple(backend) => backend.restart(name),
        }
    }

    /// `is_running` — is that service up?
    #[must_use]
    pub fn is_running(&self, name: &str, service: &str) -> bool {
        match self {
            Self::Container(backend) => backend.is_running(name, service),
            Self::Vm(backend) => backend.is_running(name, service),
            Self::Apple(backend) => backend.is_running(name, service),
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
            Self::Apple(backend) => backend.has_resources(name),
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
            // This arm used to drop `keep_secrets`, on the reasoning
            // that the state tree goes with the cage anyway. It does
            // not: the keychain is not under the state tree, so a
            // destroyed cage left its values there forever while
            // `cage destroy` said it had removed them.
            Self::Apple(backend) => backend.destroy_resources(name, keep_secrets),
        }
    }

    /// `exec_argv` — the argv that runs a command inside a service.
    ///
    /// Fallible for the apple arm alone, which is why the protocol
    /// returns a `Result` at all: that backend refuses a service name
    /// it does not have (`BackendUnsupported` in the Python) and
    /// refuses again when `container(1)` is not installed. The other
    /// two compose an argv for any service name and let podman
    /// complain.
    ///
    /// # Errors
    ///
    /// A message ready to print, already phrased for the operator.
    pub fn exec_argv(
        &self,
        name: &str,
        service: &str,
        command: &[String],
        interactive: bool,
        as_root: bool,
    ) -> Result<Vec<String>, String> {
        match self {
            Self::Container(backend) => {
                Ok(backend.exec_argv(name, service, command, interactive, as_root))
            }
            Self::Vm(backend) => {
                Ok(backend.exec_argv(name, service, command, interactive, as_root))
            }
            // The placeholders are read here rather than passed in
            // because the Python reads them here: a cage session gets
            // the decoy tokens that are in the stored config *at exec
            // time*, so a `secret set` since the last start is
            // reflected without a restart. Apple's `container exec`
            // has no `--env`, so they arrive as an `env(1)` prefix
            // inside the VM.
            Self::Apple(backend) => {
                let placeholders = crate::services::current_placeholders(backend.paths(), name);
                backend
                    .exec_argv(name, service, command, interactive, as_root, &placeholders)
                    .map_err(|error| error.to_string())
            }
        }
    }

    /// `audit_argv` — the argv that prints a cage's audit stream.
    #[must_use]
    pub fn audit_argv(&self, name: &str, since: Option<&str>, follow: bool) -> Vec<String> {
        match self {
            Self::Container(backend) => backend.audit_argv(name, since, follow),
            Self::Vm(backend) => backend.audit_argv(name, since, follow),
            // `since` is dropped, as the Python drops it: this is a
            // `tail` over a bind-mounted file, not a journal query.
            Self::Apple(backend) => backend.audit_argv(name, follow),
        }
    }

    /// `unit_dir` — where this backend's units are installed, for the
    /// hint `cage create` prints when a deploy fails.
    #[must_use]
    pub fn unit_dir(&self) -> PathBuf {
        match self {
            Self::Container(backend) => backend.unit_dir().to_path_buf(),
            Self::Vm(backend) => backend.unit_dir(),
            Self::Apple(backend) => backend.unit_dir(),
        }
    }

    /// The version-pinned egress image tag.
    #[must_use]
    pub fn egress_image(&self) -> String {
        match self {
            Self::Container(backend) => backend.egress_image(),
            Self::Vm(backend) => format!("agentcage-egress:{}", backend.version()),
            // The only arm whose tag carries a content hash as well as
            // the version, which is what makes its "already built"
            // short-circuit safe. See `apple::image`.
            Self::Apple(backend) => backend.egress_image(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AnyBackend;

    /// Every backend that exists executes; the guard is for one that
    /// does not yet.
    #[test]
    fn the_three_real_backends_are_not_refused() {
        for isolation in ["container", "vm", "apple-container"] {
            assert!(
                AnyBackend::refusal(isolation, "cage start").is_none(),
                "{isolation} is refused but is ported"
            );
        }
    }

    /// An isolation nobody implemented refuses, and names itself and
    /// the verb while doing it. This is what stops `new`'s
    /// container-backend fall-through from silently driving a future
    /// backend with podman.
    #[test]
    fn an_unknown_backend_is_refused_by_name() {
        let refusal = AnyBackend::refusal("gvisor", "cage start").expect("refused");
        assert!(refusal.contains("`cage start`"), "{refusal}");
        assert!(refusal.contains("gvisor"), "{refusal}");
    }
}
