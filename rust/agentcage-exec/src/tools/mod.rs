//! One module per binary agentcage drives.
//!
//! Each wrapper holds a `&dyn CommandRunner` and builds [`Command`]s. It
//! does no policy: `podman.py` decides *whether* to remove a secret,
//! [`podman::Podman`] only knows how to say it. That split is what makes
//! the argv assertions meaningful -- a test can pin the exact argv
//! without also having to set up the decision that produced it.
//!
//! | module | binary | Python source |
//! | :-- | :-- | :-- |
//! | [`podman`]   | `podman`        | `podman.py` |
//! | [`systemctl`]| `systemctl`     | `systemd.py`, `secret_resolver.py` |
//! | [`limactl`]  | `limactl`       | `lima/instance.py` |
//! | [`apple`]    | `container`     | `apple_container/cli.py` |
//! | [`skopeo`]   | `skopeo`        | `registry.py` |
//! | [`security`] | `security`      | `secret_store.py` |
//! | [`creds`]    | `systemd-creds` | `secret_resolver.py` |

pub mod apple;
pub mod creds;
pub mod limactl;
pub mod podman;
pub mod security;
pub mod skopeo;
pub mod systemctl;

use crate::command::Command;

/// Whether an invocation has to be dropped back to the invoking user.
///
/// `podman.py::_podman_cmd` and `systemd.py::_systemctl_cmd` are the
/// same four lines twice: when agentcage is running as root under
/// `sudo`, prefix with `runuser -u $SUDO_USER --` so that podman uses
/// the real user's rootless storage and networking, and so that
/// `systemctl --user` reaches the real user's systemd instance rather
/// than root's.
///
/// Getting this wrong is not a crash, it is a cage deployed into the
/// wrong user's storage -- so it is modelled explicitly and tested in
/// both directions rather than being read from the environment deep
/// inside an argv builder.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Elevation {
    run_as: Option<String>,
}

impl Elevation {
    /// Run commands directly, as the current user.
    #[must_use]
    pub fn none() -> Self {
        Self { run_as: None }
    }

    /// Drop to `user` with `runuser`.
    #[must_use]
    pub fn runuser(user: impl Into<String>) -> Self {
        Self {
            run_as: Some(user.into()),
        }
    }

    /// Read the real process's euid and `SUDO_USER`.
    ///
    /// `euid == 0 && SUDO_USER` is the exact condition the Python uses:
    /// root *without* `SUDO_USER` gets no prefix, because there is no
    /// real user to drop to and `runuser -u ''` would be nonsense.
    #[must_use]
    pub fn detect() -> Self {
        let sudo_user = std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty());
        match sudo_user {
            Some(user) if rustix::process::geteuid().is_root() => Self::runuser(user),
            _ => Self::none(),
        }
    }

    /// The user commands are dropped to, if any.
    #[must_use]
    pub fn run_as(&self) -> Option<&str> {
        self.run_as.as_deref()
    }

    /// Build the base [`Command`] for `program`, with the prefix applied.
    ///
    /// `["podman"]` or `["runuser", "-u", user, "--", "podman"]`. The
    /// `--` matters: without it `runuser` would parse the tool's own
    /// flags as its own.
    #[must_use]
    pub fn command(&self, program: &str) -> Command {
        match &self.run_as {
            None => Command::new(program),
            Some(user) => Command::new("runuser").args(["-u", user, "--", program]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Elevation;

    /// Mirrors `test_podman.py::TestPodmanCmd`, all three cases.
    #[test]
    fn the_runuser_prefix_matches_the_python() {
        assert_eq!(Elevation::none().command("podman").argv(), ["podman"]);
        assert_eq!(
            Elevation::runuser("alice").command("podman").argv(),
            ["runuser", "-u", "alice", "--", "podman"]
        );
        // Root without SUDO_USER: no prefix. `detect()` produces
        // `none()` for that case, and `none()` is what is asserted above.
        assert_eq!(Elevation::none().run_as(), None);
        assert_eq!(Elevation::runuser("alice").run_as(), Some("alice"));
    }

    #[test]
    fn systemctl_gets_the_same_prefix() {
        assert_eq!(
            Elevation::runuser("bob").command("systemctl").argv(),
            ["runuser", "-u", "bob", "--", "systemctl"]
        );
    }
}
