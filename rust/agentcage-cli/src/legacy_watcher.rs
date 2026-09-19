//! Remove the legacy host-side grants-watcher supervision from a cage.
//!
//! The port of `src/agentcage/legacy_watcher.py` (RUST-PORT-PLAN.md
//! Track D, PR D16). This is migration code, and the reason it exists is
//! not recoverable from reading it, so the Python's reasoning is carried
//! here verbatim in substance:
//!
//! > The egress-local DNS-apply rework deleted the host-side grants
//! > watcher — the systemd user unit on Linux hosts, the launchd plist
//! > on macOS hosts, and the in-guest systemd user unit for VM cages.
//! > Cages created BEFORE that rework still carry those artifacts, and
//! > their command no longer exists: the unit's `ExecStart` / plist
//! > `ProgramArguments` runs `agentcage cage grants <name> watch
//! > --interval 1`, and the `watch` subcommand was removed with the
//! > watcher. On an upgraded Linux host the enabled
//! > `WantedBy=default.target` unit therefore fails at every boot until
//! > systemd's start limit kills it; on macOS the `KeepAlive=true` plist
//! > relaunches the failing command indefinitely (launchd throttles to
//! > ~10s — a permanent crash loop).
//!
//! [`LegacyWatcher::remove`] removes the artifacts. It is called from
//! `cage destroy` and `cage update` and is:
//!
//! * **idempotent** — every step is best-effort; missing files, missing
//!   launchd services and unreachable VMs are silent no-ops, so it is
//!   safe to call on every cage, including ones created entirely
//!   post-rework;
//! * **never fatal** — cleanup failures are collected as warnings and
//!   handed back, never raised, because a stale watcher must not block a
//!   cage destroy/update.
//!
//! # What the Rust changes, and why
//!
//! Four deliberate divergences from the Python. Each one is a bug the
//! port is in a position to fix rather than reproduce.
//!
//! 1. **The cage name is validated before it is used.** The Python
//!    interpolates `name` straight into a filesystem path *and* into a
//!    `sh -c` string sent to the guest. The name arrives from a legacy
//!    cage's persisted metadata — written by a version of agentcage
//!    whose validator is not this one's — so a `name` of `../../x` walks
//!    out of `~/.config/systemd/user`, and a name containing `;` runs
//!    arbitrary commands inside the VM. [`is_removable_name`] gates
//!    everything on `config.py`'s own `^[a-z0-9][a-z0-9-]{0,62}$`, so
//!    the only paths this module can construct are ones it fully
//!    determines. See [`LegacyWatcher::remove`].
//! 2. **A Linux host with no systemd no longer crashes.** The Python
//!    calls `subprocess.run(["systemctl", ...])` unguarded;
//!    `FileNotFoundError` is *not* suppressed by `check=False`, so on a
//!    systemd-less Linux host that still has the unit file — a restored
//!    home directory, a distro migration — the cleanup raises out of
//!    `cage destroy`. Here the `systemctl` calls are skipped (via
//!    [`agentcage_exec::CommandRunner::which`], the same guard
//!    `systemd.py` uses everywhere else) and the stale file is still
//!    removed: with no systemd there is nothing holding a reference to
//!    it, and leaving it behind re-arms the crash loop the day systemd
//!    is installed.
//! 3. **`systemctl` gets the `runuser` prefix.** `systemd.py`'s note
//!    says the legacy helper "shells out directly for `disable --now`"
//!    because [`Systemctl::disable_unit`] cannot express `--now` — not
//!    because the elevation prefix is unwanted. Under `sudo`, a bare
//!    `systemctl --user` talks to *root's* user instance, where the
//!    cage's units are not, so the Python's `disable --now` silently
//!    does nothing before the file is deleted and systemd is left
//!    holding the reference. [`Elevation`] fixes that.
//! 4. **`launchctl` missing is a no-op, not an error.** Same shape as
//!    (2), for the same reason.
//!
//! # What it does *not* change
//!
//! The ordering, which is the whole correctness argument: `disable
//! --now` **before** the unit file is unlinked, `daemon-reload`
//! **after**. Reversed, systemd still holds a reference to a unit whose
//! fragment has vanished — `disable` can no longer find it to remove the
//! `WantedBy=` symlink, and a running instance keeps running. The
//! Python's early `return` on a failed unlink is carried too: there is
//! no point reloading the generator view when nothing changed.
//!
//! And the macOS asymmetry: `launchctl bootout` runs *unconditionally*,
//! before the plist is looked at, while the Linux branch bails when the
//! unit file is absent. That is not an accident to tidy up — a
//! partially-removed legacy cage can have the plist deleted by hand
//! while the job is still bootstrapped in the live GUI domain, and the
//! unconditional bootout is the only thing that reaches it. It does mean
//! a second run on macOS issues a second `bootout`; `bootout` on an
//! unregistered label is a lookup that exits non-zero and changes
//! nothing, so the property that matters — no second *destructive* call
//! — still holds. See `tests/legacy_watcher.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use agentcage_exec::tools::{Elevation, limactl::LimaInstance, systemctl::Systemctl};
use agentcage_exec::{Command, CommandRunner};

/// Which host the cleanup is running on.
///
/// Explicit rather than read from `cfg!(target_os)` at the point of use,
/// for the reason [`agentcage_exec::FakeRunner::stub_missing`] exists:
/// CI has no macOS runner, and a branch that cannot be reached from a
/// Linux test runner is a branch that is not tested. `sys.platform ==
/// "darwin"` in the Python.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// A Linux host: a systemd user unit.
    Linux,
    /// A macOS host: a launchd user agent.
    MacOs,
}

impl Host {
    /// The host this binary is running on.
    #[must_use]
    pub fn detect() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }
}

/// `config.py:1604`'s cage-name rule: `^[a-z0-9][a-z0-9-]{0,62}$`.
///
/// Hand-written rather than a regex because it is three conditions and
/// the crate has no regex dependency; the important part is that it is
/// the *same* three conditions.
///
/// This is the safety gate for the whole module. Everything downstream
/// builds a path or a shell word out of `name`, and the value does not
/// come from the current validator — it comes off disk, from a cage
/// created by an older agentcage. A name that does not match is refused
/// rather than sanitised: there is no legitimate legacy cage whose name
/// this rejects, so anything that fails it is either corruption or an
/// attempt at one of the two injections in the module docs.
#[must_use]
pub fn is_removable_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    if name.len() > 63 {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Best-effort removal of the pre-rework watcher artifacts for a cage.
///
/// Holds the host facts the cleanup needs — where `~` is, which host
/// this is, whose GUI domain launchd should be addressed in, whether
/// `sudo` means commands have to be dropped back to a real user — so
/// that a test can state them instead of inheriting them from whatever
/// machine `cargo test` is on.
#[derive(Debug)]
pub struct LegacyWatcher<'a> {
    runner: &'a dyn CommandRunner,
    host: Host,
    /// `None` when `$HOME` is unset; see [`LegacyWatcher::remove`].
    home: Option<PathBuf>,
    uid: u32,
    elevation: Elevation,
}

impl<'a> LegacyWatcher<'a> {
    /// A cleanup configured from this process's environment.
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Self {
            runner,
            host: Host::detect(),
            // `os.path.expanduser("~")`. The `pwd` fallback the Python
            // gets for free is deliberately *not* reproduced: see
            // [`LegacyWatcher::remove`] for why an unknown home is
            // refused rather than guessed.
            home: std::env::var_os("HOME").map(PathBuf::from),
            // `os.getuid()` -- the real uid, which is what launchd's
            // `gui/<uid>` domain is keyed on. Not the effective one: a
            // plist bootstrapped by the operator lives in the
            // operator's GUI domain even when agentcage is re-entered
            // under `sudo`.
            uid: nix::unistd::getuid().as_raw(),
            elevation: Elevation::detect(),
        }
    }

    /// Pretend to be `host`.
    #[must_use]
    pub fn with_host(mut self, host: Host) -> Self {
        self.host = host;
        self
    }

    /// Treat `home` as `~`.
    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Pretend `$HOME` is unset.
    #[must_use]
    pub fn without_home(mut self) -> Self {
        self.home = None;
        self
    }

    /// Address launchd's `gui/<uid>` domain as `uid`.
    #[must_use]
    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    /// Use an explicit [`Elevation`] instead of detecting one.
    #[must_use]
    pub fn with_elevation(mut self, elevation: Elevation) -> Self {
        self.elevation = elevation;
        self
    }

    /// Host path of the legacy per-cage grants-watcher systemd user unit.
    ///
    /// `legacy_watcher._grants_service_path`. `None` when the name is
    /// not one this module is willing to build a path from, or when
    /// `$HOME` is unknown — the two cases where the Python would
    /// construct a path it should not.
    #[must_use]
    pub fn grants_service_path(&self, name: &str) -> Option<PathBuf> {
        if !is_removable_name(name) {
            return None;
        }
        Some(
            self.home
                .as_ref()?
                .join(".config/systemd/user")
                .join(format!("{name}-grants.service")),
        )
    }

    /// Host path of the legacy per-cage grants-watcher launchd plist.
    ///
    /// `legacy_watcher._grants_plist_path`.
    #[must_use]
    pub fn grants_plist_path(&self, name: &str) -> Option<PathBuf> {
        if !is_removable_name(name) {
            return None;
        }
        Some(
            self.home
                .as_ref()?
                .join("Library/LaunchAgents")
                .join(format!("io.agentcage.{name}.grants.plist")),
        )
    }

    /// The launchd label, `io.agentcage.<name>.grants`.
    #[must_use]
    fn grants_label(name: &str) -> String {
        format!("io.agentcage.{name}.grants")
    }

    /// The systemd unit name, `<name>-grants.service`.
    #[must_use]
    fn grants_unit(name: &str) -> String {
        format!("{name}-grants.service")
    }

    /// Remove the watcher artifacts for `name`, returning any warnings.
    ///
    /// `isolation` is the cage's isolation setting (`vm` triggers the
    /// in-guest cleanup); anything else (or empty) is a host-local cage.
    ///
    /// Returns rather than prints, so the caller owns the output stream
    /// and a test can assert on the text. The return type is
    /// deliberately not a `Result`: "never fatal" is a property of the
    /// signature here, not a discipline the callers have to keep.
    ///
    /// An unusable name or an unknown `$HOME` stops everything, host-
    /// local *and* in-guest. Both are cases where the Python would go on
    /// to act on a path it did not fully determine — a relative
    /// `.config/systemd/user/x-grants.service` resolved against whatever
    /// the cwd happens to be, or a `rm -f` in the guest whose argument
    /// the cage name got to choose.
    #[must_use]
    pub fn remove(&self, name: &str, isolation: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        if !is_removable_name(name) {
            warnings.push(format!(
                "refusing to clean the legacy grants watcher for {name:?}: \
                 not a valid cage name"
            ));
            return warnings;
        }
        if self.home.is_none() {
            warnings.push(format!(
                "could not clean the legacy grants watcher for '{name}': $HOME is unset"
            ));
            return warnings;
        }
        match self.host {
            Host::MacOs => self.remove_macos(name, &mut warnings),
            Host::Linux => self.remove_linux(name, &mut warnings),
        }
        if isolation == "vm" {
            self.remove_vm(name, &mut warnings);
        }
        warnings
    }

    /// The Linux host artifact: a systemd user unit.
    fn remove_linux(&self, name: &str, warnings: &mut Vec<String>) {
        let Some(path) = self.grants_service_path(name) else {
            return;
        };
        // Bail before touching systemctl at all, so a post-rework cage
        // -- the overwhelmingly common case, since this runs on every
        // destroy and update -- costs nothing, not even a PATH lookup.
        if !is_file(&path) {
            return;
        }
        let unit = Self::grants_unit(name);
        let systemctl = Systemctl::with_elevation(self.runner, self.elevation.clone());
        // See the module docs: absent systemd means nothing can be
        // holding the unit, so the file still goes, but the two
        // systemctl round trips are skipped rather than crashed on.
        let systemd = systemctl.available();
        if systemd {
            // `disable --now` so a currently-running watcher stops
            // before its unit file vanishes; `disable` on its own does
            // not stop a running instance, which is exactly why
            // `systemd.disable_unit` is not the call here. Best-effort:
            // a legacy unit systemd has already forgotten exits
            // non-zero, and that is a clean system, not a failure.
            let _ = self.runner.run(
                &systemctl
                    .base()
                    .args(["disable", "--now", unit.as_str()])
                    .captured(),
            );
        }
        if let Err(e) = fs::remove_file(&path) {
            warnings.push(format!(
                "could not remove legacy grants watcher unit {}: {e}",
                path.display()
            ));
            return;
        }
        if systemd {
            // Only after the unlink, and only if it happened: this
            // refreshes the generator's view of a directory that just
            // changed.
            let _ = self
                .runner
                .run(&systemctl.base().args(["daemon-reload"]).captured());
        }
    }

    /// The macOS host artifact: a launchd user agent.
    fn remove_macos(&self, name: &str, warnings: &mut Vec<String>) {
        let Some(path) = self.grants_plist_path(name) else {
            return;
        };
        // `bootout`, not `unload` -- the plist was registered in the
        // per-user GUI domain. Both a missing service and a missing file
        // are fine, and the call is unconditional on purpose: see the
        // module docs on the partially-removed cage whose plist is gone
        // but whose job is still bootstrapped.
        let _ = self.runner.run(
            &Command::new("launchctl")
                .args([
                    "bootout",
                    &format!("gui/{}", self.uid),
                    &Self::grants_label(name),
                ])
                .captured(),
        );
        if !is_file(&path) {
            return;
        }
        if let Err(e) = fs::remove_file(&path) {
            warnings.push(format!(
                "could not remove legacy grants watcher plist {}: {e}",
                path.display()
            ));
        }
    }

    /// The in-guest unit of a VM cage (best-effort, needs the VM up).
    ///
    /// The VM watcher ran inside the guest as a systemd user unit, so
    /// removal needs a `limactl shell` round trip. If the VM is
    /// unreachable the unit dies with the VM's disk when the cage is
    /// destroyed; for an update on a running VM this stops the crash
    /// loop immediately.
    fn remove_vm(&self, name: &str, warnings: &mut Vec<String>) {
        let instance = LimaInstance::new(self.runner, name);
        match instance.is_running() {
            Ok(true) => {}
            // Not running: nothing to stop, and the guest filesystem is
            // not reachable to clean. Same silent no-op as the Python.
            Ok(false) => return,
            Err(e) => {
                warnings.push(Self::vm_warning(name, &e.to_string()));
                return;
            }
        }
        let unit = Self::grants_unit(name);
        // One shell: stop+disable, remove the file, refresh systemd. All
        // best-effort (`|| true` here spelled as a trailing `true`) so a
        // partial manual removal still exits 0 and never fails the
        // host-side destroy/update.
        //
        // `unit` is interpolated into a shell string. That is only safe
        // because `is_removable_name` already ran: `[a-z0-9-]` contains
        // no shell metacharacter, no quote and no space, so there is
        // exactly one word here however hostile the metadata was.
        let script = format!(
            "systemctl --user disable --now {unit} 2>/dev/null; \
             rm -f \"$HOME/.config/systemd/user/{unit}\" 2>/dev/null; \
             systemctl --user daemon-reload 2>/dev/null; true"
        );
        let argv = vec!["sh".to_string(), "-c".to_string(), script];
        if let Err(e) = instance.exec(&argv, false) {
            warnings.push(Self::vm_warning(name, &e.to_string()));
        }
    }

    /// The Python's in-VM warning, verbatim.
    fn vm_warning(name: &str, detail: &str) -> String {
        format!(
            "could not clean the in-VM legacy grants watcher for '{name}' \
             (VM unreachable?): {detail}"
        )
    }
}

/// `Path.is_file()`: follows symlinks, and a broken link is not a file.
///
/// Note what the *removal* then does with a symlink: `fs::remove_file`,
/// like Python's `Path.unlink`, unlinks the name and never follows it.
/// So a symlink planted at the unit path costs its target nothing — only
/// the link in `~/.config/systemd/user` goes, which is the entry this
/// module is here to remove.
fn is_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file())
}

/// Remove the legacy watcher artifacts for `name`, printing warnings.
///
/// The shape `cage destroy` and `cage update` call:
/// `legacy_watcher.remove_legacy_grants_watcher(cfg.name, cfg.isolation)`
/// in `cli.py:1189` and `cli.py:1424`.
pub fn remove_legacy_grants_watcher(runner: &dyn CommandRunner, name: &str, isolation: &str) {
    for warning in LegacyWatcher::new(runner).remove(name, isolation) {
        eprintln!("warn: {warning}");
    }
}

#[cfg(test)]
mod tests {
    use super::is_removable_name;

    #[test]
    fn the_name_gate_is_config_pys_rule() {
        assert!(is_removable_name("a"));
        assert!(is_removable_name("my-cage-1"));
        assert!(is_removable_name(&"a".repeat(63)));

        assert!(!is_removable_name(""));
        assert!(!is_removable_name(&"a".repeat(64)));
        // Leading character is the narrower class.
        assert!(!is_removable_name("-lead"));
        assert!(!is_removable_name("Upper"));
        // The two injections the gate exists for.
        assert!(!is_removable_name("../../../etc/cron.d/x"));
        assert!(!is_removable_name("x; rm -rf $HOME"));
        assert!(!is_removable_name("x y"));
        assert!(!is_removable_name("x\u{0}y"));
        // Non-ASCII lowercase is not `[a-z]`.
        assert!(!is_removable_name("café"));
    }
}
