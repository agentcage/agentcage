//! Which podman answers for a cage — `cli._podman_for_cage`
//! (`cli.py:54`).
//!
//! A `container` cage keeps its secrets in the host's podman store. A
//! `vm` cage keeps them in a *different* store, inside its Lima guest,
//! reachable only as `limactl shell <instance> -- podman …`. The two
//! are the same argv behind different transports, which is why the
//! Python can hand either object to the same code and why this is an
//! enum rather than two call paths.
//!
//! # Why the running check is part of the decision
//!
//! The guest's store only exists while the guest runs. The Python asks
//! `LimaInstance(name).is_running()` and falls back to **host** podman
//! when it does not, which is not a graceful degradation so much as the
//! only thing it can do: there is nothing to ask. Every caller below
//! therefore has to tolerate a host answer about a stopped vm cage —
//! `secret list` showing every key `MISSING` is the honest reading of
//! "the store is unreachable", and it is what the Python prints.
//!
//! # The one thing this deliberately does not fix
//!
//! `cage restore` does **not** use this router, and that is faithful
//! rather than an omission. `cli.py:3973` computes its handle *after*
//! the `--force` destroy has run `state.remove_deployment`, so
//! `deployment_exists` is false and the router returns host podman
//! every time — including for a vm tarball, whose secrets then land in
//! the host store where that cage's containers cannot see them. See
//! [`crate::cli`]'s `cage restore` body, where the ordering is pinned
//! with a test, and RUST-PORT-PLAN.md's bug table.

use agentcage_exec::tools::limactl::{LimaInstance, VmPodman};
use agentcage_exec::tools::podman::Podman;
use agentcage_exec::{CommandRunner, ExecError};

/// A cage's secret store, wherever it lives.
///
/// Only the operations `secret_store.py` and the backup paths actually
/// call are here; [`VmPodman`] implements that same subset and nothing
/// more, because a `limactl shell` wrapper around every podman verb
/// would be a wrapper around verbs no caller uses.
#[derive(Debug)]
pub enum CagePodman<'a> {
    /// Host podman: a `container` cage, or a `vm` cage whose guest is
    /// not running and therefore has no store to ask.
    Host(Podman<'a>),
    /// Podman inside the Lima guest of a running `vm` cage.
    Guest(VmPodman<'a>),
}

impl<'a> CagePodman<'a> {
    /// The handle for `cage_name`, chosen the way `_podman_for_cage`
    /// chooses it.
    ///
    /// `isolation` is the cage's stored one. The caller has already
    /// loaded the config by the time it needs a store, so this takes
    /// the string rather than re-reading the file — which also keeps
    /// the `secret set --declare` case right, where the config in hand
    /// is newer than the one on disk.
    #[must_use]
    pub fn for_cage(runner: &'a dyn CommandRunner, isolation: &str, cage_name: &str) -> Self {
        if isolation == "vm" {
            let instance = LimaInstance::new(runner, cage_name);
            // `is_running` errors on exactly one thing: `limactl` is
            // not installed. That means the same as a stopped guest --
            // there is no store to ask -- and every caller already
            // handles that answer. `LimaInstance.is_running` on the
            // Python side swallows it the same way.
            if instance.is_running().unwrap_or(false) {
                return Self::Guest(VmPodman::new(runner, cage_name));
            }
        }
        Self::Host(Podman::new(runner))
    }

    /// Whether this is the guest store.
    ///
    /// For the two messages that have to say *which* store they could
    /// not reach, and for tests that assert the routing rather than
    /// the argv.
    #[must_use]
    pub const fn is_guest(&self) -> bool {
        matches!(self, Self::Guest(_))
    }

    /// `podman inspect <name>` for a container, in whichever store.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] when there is no such container.
    pub fn container_inspect(&self, name: &str) -> Result<serde_json::Value, ExecError> {
        match self {
            Self::Host(p) => p.container_inspect(name),
            Self::Guest(p) => p.container_inspect(name),
        }
    }

    /// Secret names with this prefix, leniently — an unreachable store
    /// reads as empty, which is what `secret list` wants.
    ///
    /// # Errors
    ///
    /// Only if the underlying command could not be run at all.
    pub fn secret_list(&self, prefix: &str) -> Result<Vec<String>, ExecError> {
        match self {
            Self::Host(p) => p.secret_list(prefix),
            Self::Guest(p) => p.secret_list(prefix),
        }
    }

    /// Whether a secret of this name is in the store.
    ///
    /// # Errors
    ///
    /// Only if the underlying command could not be run at all.
    pub fn secret_exists(&self, name: &str) -> Result<bool, ExecError> {
        match self {
            Self::Host(p) => p.secret_exists(name),
            Self::Guest(p) => p.secret_exists(name),
        }
    }

    /// Create it, with the value on stdin.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn secret_create(&self, name: &str, value: &str) -> Result<(), ExecError> {
        match self {
            Self::Host(p) => p.secret_create(name, value),
            Self::Guest(p) => p.secret_create(name, value),
        }
    }

    /// Remove it, reporting whether it went.
    ///
    /// # Errors
    ///
    /// Only if the underlying command could not be run at all.
    pub fn secret_remove(&self, name: &str) -> Result<bool, ExecError> {
        match self {
            Self::Host(p) => p.secret_remove(name),
            Self::Guest(p) => p.secret_remove(name),
        }
    }

    /// Read its value back.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] when there is no such secret.
    pub fn secret_read(&self, name: &str) -> Result<String, ExecError> {
        match self {
            Self::Host(p) => p.secret_read(name),
            Self::Guest(p) => p.secret_read(name),
        }
    }
}

impl crate::secrets::store::PodmanSecrets for CagePodman<'_> {
    fn secret_exists(&self, name: &str) -> Result<bool, ExecError> {
        Self::secret_exists(self, name)
    }

    fn secret_create(&self, name: &str, value: &str) -> Result<(), ExecError> {
        Self::secret_create(self, name, value)
    }

    fn secret_remove(&self, name: &str) -> Result<bool, ExecError> {
        Self::secret_remove(self, name)
    }

    fn secret_read(&self, name: &str) -> Result<String, ExecError> {
        Self::secret_read(self, name)
    }
}
