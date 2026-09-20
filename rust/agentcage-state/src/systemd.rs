//! Unit lifecycle: the files on disk, and the `systemctl --user` calls
//! that have to follow them.
//!
//! # What lives where, and why D1 did not finish this
//!
//! `systemd.py` is six `subprocess.run` calls behind one
//! `shutil.which("systemctl")` guard, and D1 put exactly that behind
//! [`agentcage_exec::tools::systemctl::Systemctl`]. What it could not
//! put there is the half that is not a subprocess: a unit only takes
//! effect once its *file* is in the right directory, and which
//! directory that is depends on the unit's extension.
//!
//! | extension | directory | why |
//! | :-- | :-- | :-- |
//! | `.container`, `.network`, `.volume` | `~/.config/containers/systemd` | quadlets, transpiled into units by the systemd generator |
//! | `.service` | `~/.config/systemd/user` | a native unit; the generator never sees it |
//!
//! Put a `.service` in the quadlet directory and the generator ignores
//! it; put a `.container` in the user unit directory and systemd tries
//! to parse a quadlet as a unit file. Both fail quietly, at boot,
//! which is the worst time. So the routing is code with a test rather
//! than a convention.
//!
//! Neither directory honours `XDG_CONFIG_HOME` — both are
//! `os.path.expanduser(...)` in `backends/container.py` — which is why
//! they come from [`Paths`] rather than from an XDG lookup here. See
//! [`crate::paths`].
//!
//! # Every operation is a no-op without systemd
//!
//! macOS has no `systemctl`, and a container-backed cage created on
//! Linux can still be cleaned up from a Mac. Without the guard those
//! paths die with `FileNotFoundError`. The check is
//! [`agentcage_exec::CommandRunner::which`] rather than "try it and
//! catch not-found" — that is what `shutil.which` does, and it keeps
//! the decision inspectable, so
//! [`agentcage_exec::FakeRunner::stub_missing`] can reach the macOS
//! branch from a Linux CI runner. It is the only way that branch gets
//! covered at all.
//!
//! [`Units::install`] therefore still *writes the files* when there is
//! no systemd, and only skips the daemon-reload. That matches the
//! Python: `install_units` writes unconditionally and calls
//! `systemd.daemon_reload()`, which is the function that no-ops.

use std::fs;

use agentcage_exec::tools::systemctl::Systemctl;
use agentcage_exec::{CommandRunner, ExecError};

use crate::error::{Result, StateError};
use crate::paths::Paths;

/// The quadlet filenames a cage owns, as suffixes of its name.
///
/// `backends/container.py::_QUADLET_FILES`, including the two legacy
/// entries, and the Python's reason for keeping them is worth
/// repeating: `cage destroy` must still be able to clean up a stuck
/// pre-v0.22 three-service cage even though every other command
/// refuses to operate on one.
pub const QUADLET_SUFFIXES: [&str; 8] = [
    "-cage.container",
    "-egress.container",
    "-net.network",
    "-certs.volume",
    "-public-certs.volume",
    "-podman-storage.volume",
    // legacy v0.21 layout — kept for `cage destroy` cleanup only
    "-proxy.container",
    "-dns.container",
];

/// Unit files plus the systemd instance they are installed into.
#[derive(Debug)]
pub struct Units<'a> {
    paths: &'a Paths,
    systemctl: Systemctl<'a>,
}

impl<'a> Units<'a> {
    /// A lifecycle bound to these state paths and this runner.
    #[must_use]
    pub fn new(paths: &'a Paths, runner: &'a dyn CommandRunner) -> Self {
        Self {
            paths,
            systemctl: Systemctl::new(runner),
        }
    }

    /// The same, with the elevation decided by the caller.
    ///
    /// Under `sudo`, plain `systemctl --user` reaches *root's* user
    /// instance, where the cage's units are not.
    #[must_use]
    pub fn with_elevation(
        paths: &'a Paths,
        runner: &'a dyn CommandRunner,
        elevation: agentcage_exec::Elevation,
    ) -> Self {
        Self {
            paths,
            systemctl: Systemctl::with_elevation(runner, elevation),
        }
    }

    /// The underlying wrapper, for callers that need one more verb.
    #[must_use]
    pub fn systemctl(&self) -> &Systemctl<'a> {
        &self.systemctl
    }

    /// Whether this host has systemd at all.
    #[must_use]
    pub fn available(&self) -> bool {
        self.systemctl.available()
    }

    /// Where a unit file with this name belongs.
    ///
    /// The routing rule in one place, so the two call sites that need
    /// it — installing and removing — cannot drift apart.
    #[must_use]
    pub fn unit_dir_for(&self, filename: &str) -> &std::path::Path {
        if filename.ends_with(".service") {
            self.paths.user_unit_dir()
        } else {
            self.paths.quadlet_dir()
        }
    }

    /// `backends/container.py::install_units` — write every unit to
    /// the directory its extension calls for, then `daemon-reload`.
    ///
    /// Both directories are created whether or not a unit of that kind
    /// is in this batch, as the Python does: a later `cage create`
    /// with a watcher `.service` would otherwise find no directory.
    ///
    /// Returns the paths written, in the order given, and whether the
    /// daemon-reload actually ran (`false` on a host without systemd).
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] on a failed write, [`StateError::Systemd`]
    /// if the reload itself fails.
    pub fn install<'u, I>(&self, units: I) -> Result<Installed>
    where
        I: IntoIterator<Item = (&'u str, &'u str)>,
    {
        for dir in [self.paths.quadlet_dir(), self.paths.user_unit_dir()] {
            fs::create_dir_all(dir).map_err(|e| StateError::io(dir, "create directory", e))?;
        }
        let mut written = Vec::new();
        for (filename, content) in units {
            let path = self.unit_dir_for(filename).join(filename);
            fs::write(&path, content).map_err(|e| StateError::io(&path, "write unit", e))?;
            written.push(path);
        }
        let reloaded = self.daemon_reload()?;
        Ok(Installed { written, reloaded })
    }

    /// `backends/container.py::destroy_resources`' first half — remove
    /// this cage's quadlet files, then `daemon-reload`.
    ///
    /// Returns the filenames that were actually there, in
    /// [`QUADLET_SUFFIXES`] order, which is what `cage destroy` prints
    /// as its removal list.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] on a failed unlink, [`StateError::Systemd`]
    /// if the reload fails.
    pub fn remove_quadlets(&self, name: &str) -> Result<Vec<String>> {
        let dir = self.paths.quadlet_dir();
        let mut removed = Vec::new();
        for suffix in QUADLET_SUFFIXES {
            let filename = format!("{name}{suffix}");
            let path = dir.join(&filename);
            if !path.exists() {
                continue;
            }
            fs::remove_file(&path).map_err(|e| StateError::io(&path, "remove unit", e))?;
            removed.push(filename);
        }
        self.daemon_reload()?;
        Ok(removed)
    }

    /// Whether this cage has a `<name>-podman-storage.volume` quadlet.
    ///
    /// `start()` restarts that volume unit only when the file is
    /// there, because a cage without nested containers never had one
    /// and `systemctl restart` on a unit that does not exist is an
    /// error rather than a no-op.
    #[must_use]
    pub fn has_podman_storage_volume(&self, name: &str) -> bool {
        self.paths
            .quadlet_dir()
            .join(format!("{name}-podman-storage.volume"))
            .exists()
    }

    // ── the six operations from systemd.py ──────────────
    //
    // Thin by design. The wrapper builds the argv and holds the
    // which-guard; what these add is the crate's own error type, so a
    // caller does not have to handle two.

    /// `systemctl --user daemon-reload`. `Ok(false)` = no systemd.
    ///
    /// # Errors
    ///
    /// [`StateError::Systemd`] on a non-zero exit.
    pub fn daemon_reload(&self) -> Result<bool> {
        self.systemctl.daemon_reload().map_err(into_state)
    }

    /// `systemctl --user start <unit>`. `Ok(false)` = no systemd.
    ///
    /// # Errors
    ///
    /// [`StateError::Systemd`] on a non-zero exit.
    pub fn start(&self, unit: &str) -> Result<bool> {
        self.systemctl.start_unit(unit).map_err(into_state)
    }

    /// `systemctl --user stop <unit>`. `Ok(false)` = no systemd.
    ///
    /// # Errors
    ///
    /// [`StateError::Systemd`] on a non-zero exit.
    pub fn stop(&self, unit: &str) -> Result<bool> {
        self.systemctl.stop_unit(unit).map_err(into_state)
    }

    /// `systemctl --user restart <unit>`. `Ok(false)` = no systemd.
    ///
    /// # Errors
    ///
    /// [`StateError::Systemd`] on a non-zero exit.
    pub fn restart(&self, unit: &str) -> Result<bool> {
        self.systemctl.restart_unit(unit).map_err(into_state)
    }

    /// `systemctl --user enable <unit>`. `Ok(false)` = no systemd.
    ///
    /// Only a native `.service` needs this: a quadlet-generated unit
    /// is activated by the generator, while a hand-written unit's
    /// `[Install] WantedBy=` only names a symlink that nothing creates
    /// unless `enable` is called.
    ///
    /// # Errors
    ///
    /// [`StateError::Systemd`] on a non-zero exit.
    pub fn enable(&self, unit: &str) -> Result<bool> {
        self.systemctl.enable_unit(unit).map_err(into_state)
    }

    /// `systemctl --user disable <unit>`. `Ok(false)` = no systemd.
    ///
    /// Note that `disable` alone does not stop a running instance;
    /// the legacy cleanup path uses `disable --now` for that.
    ///
    /// # Errors
    ///
    /// [`StateError::Systemd`] on a non-zero exit.
    pub fn disable(&self, unit: &str) -> Result<bool> {
        self.systemctl.disable_unit(unit).map_err(into_state)
    }
}

/// What [`Units::install`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Installed {
    /// Every unit file written, in the order it was given.
    pub written: Vec<std::path::PathBuf>,
    /// Whether `daemon-reload` ran. `false` on a host with no systemd.
    pub reloaded: bool,
}

fn into_state(error: ExecError) -> StateError {
    StateError::Systemd(error)
}

#[cfg(test)]
mod tests {
    use super::Units;
    use crate::paths::Paths;
    use crate::testdir::TestDir;
    use agentcage_exec::{Elevation, FakeRunner, Reply};
    use std::fs;

    #[test]
    fn a_service_and_a_quadlet_go_to_different_directories() {
        let dir = TestDir::new("units-install");
        let paths = Paths::under(dir.path());
        let fake = FakeRunner::new();
        fake.assume_installed().push(Reply::status(0));

        let units = Units::with_elevation(&paths, &fake, Elevation::none());
        let installed = units
            .install([
                ("acme-cage.container", "[Container]\n"),
                ("acme-net.network", "[Network]\n"),
                ("acme-watcher.service", "[Service]\n"),
            ])
            .unwrap();

        assert!(installed.reloaded);
        assert_eq!(
            fs::read_to_string(paths.quadlet_dir().join("acme-cage.container")).unwrap(),
            "[Container]\n"
        );
        assert!(paths.quadlet_dir().join("acme-net.network").is_file());
        assert_eq!(
            fs::read_to_string(paths.user_unit_dir().join("acme-watcher.service")).unwrap(),
            "[Service]\n"
        );
        // NOT in the quadlet dir, where the generator would ignore it.
        assert!(!paths.quadlet_dir().join("acme-watcher.service").exists());

        fake.assert_argv(&[&["systemctl", "--user", "daemon-reload"]]);
        fake.assert_drained();
    }

    #[test]
    fn removal_takes_the_legacy_names_too_and_reloads_once() {
        let dir = TestDir::new("units-remove");
        let paths = Paths::under(dir.path());
        fs::create_dir_all(paths.quadlet_dir()).unwrap();
        for suffix in ["-cage.container", "-net.network", "-proxy.container"] {
            fs::write(paths.quadlet_dir().join(format!("acme{suffix}")), "x").unwrap();
        }
        fs::write(paths.quadlet_dir().join("other-cage.container"), "x").unwrap();

        let fake = FakeRunner::new();
        fake.assume_installed().push(Reply::status(0));
        let units = Units::with_elevation(&paths, &fake, Elevation::none());
        let removed = units.remove_quadlets("acme").unwrap();

        assert_eq!(
            removed,
            [
                "acme-cage.container",
                "acme-net.network",
                "acme-proxy.container"
            ]
        );
        assert!(paths.quadlet_dir().join("other-cage.container").is_file());
        fake.assert_argv(&[&["systemctl", "--user", "daemon-reload"]]);
    }

    #[test]
    fn the_podman_storage_probe_is_a_file_check_not_a_systemctl_call() {
        let dir = TestDir::new("units-storage");
        let paths = Paths::under(dir.path());
        fs::create_dir_all(paths.quadlet_dir()).unwrap();
        let fake = FakeRunner::new();
        fake.assume_installed();
        let units = Units::with_elevation(&paths, &fake, Elevation::none());

        assert!(!units.has_podman_storage_volume("acme"));
        fs::write(
            paths.quadlet_dir().join("acme-podman-storage.volume"),
            "[Volume]\n",
        )
        .unwrap();
        assert!(units.has_podman_storage_volume("acme"));
        assert_eq!(fake.call_count(), 0);
    }

    #[test]
    fn without_systemd_the_files_are_still_written() {
        // The macOS branch: `install_units` writes unconditionally and
        // it is `daemon_reload` that no-ops.
        let dir = TestDir::new("units-no-systemd");
        let paths = Paths::under(dir.path());
        let fake = FakeRunner::new();
        fake.stub_missing("systemctl");

        let units = Units::with_elevation(&paths, &fake, Elevation::none());
        let installed = units
            .install([("acme-cage.container", "[Container]\n")])
            .unwrap();

        assert!(!installed.reloaded);
        assert!(paths.quadlet_dir().join("acme-cage.container").is_file());
        assert_eq!(fake.call_count(), 0, "nothing was spawned");
    }
}
