//! The port of `tests/test_legacy_watcher.py`, plus what it does not say.
//!
//! # Which Python test this is
//!
//! RUST-PORT-PLAN.md's Track D table names
//! `tests/test_v021_legacy_cage.py` as D16's acceptance check. That file
//! tests a *different* piece of migration code: the v0.21 legacy-cage
//! detector at the CLI entry point (`cage stop` on a v0.21 cage exits 2
//! with a migration message; `cage destroy` and `cage list` are exempt).
//! It never imports `legacy_watcher`, and it is a `CliRunner` test of a
//! command tree that D5-D7 own.
//!
//! The file that actually covers `legacy_watcher.py` is
//! `tests/test_legacy_watcher.py`, four tests. This is the port of that
//! one. The detector belongs with the commands whose entry it guards.
//!
//! # What is carried across
//!
//! All four Python tests and every assertion in them:
//!
//! | `test_legacy_watcher.py` | here |
//! | :-- | :-- |
//! | `test_noop_when_nothing_installed` — `ran == []` | [`a_clean_system_shells_out_to_nothing`] |
//! | `test_linux_removes_unit_and_disables` — `disable`+`--now`+unit is argv[-1]; a `daemon-reload` call; the unit path was unlinked | [`linux_disables_the_unit_then_removes_it`] |
//! | `test_darwin_bootout_and_unlink` — a `launchctl` call carrying the label; the plist path was unlinked | [`macos_boots_the_job_out_and_removes_the_plist`] |
//! | `test_vm_branch_swallow_errors` — an unreachable VM does not raise | [`an_unreachable_vm_is_a_warning_not_a_failure`] |
//!
//! Two of the four are stronger here than in the Python, for reasons
//! that are about the test rather than the code:
//!
//! * The Python's assertions are `any(... for c in calls)` over a list
//!   of argv, because `monkeypatch`ing `subprocess.run` gives you a pile
//!   of calls and no ordering contract. [`FakeRunner::assert_argv`] pins
//!   the *whole sequence*, which is what makes
//!   [`linux_disables_the_unit_then_removes_it`] able to say
//!   `daemon-reload` came second rather than merely that it happened.
//! * `test_linux_removes_unit_and_disables` and
//!   `test_darwin_bootout_and_unlink` each open with `if sys.platform
//!   [!]= "darwin": return`, so on any one machine two of the four tests
//!   are silently skipped — and CI is Linux, so the macOS branch has
//!   never run anywhere. [`Host`] is a parameter here, and both run
//!   everywhere.
//!
//! The Python's `monkeypatch.setattr(Path, "is_file", ...)` /
//! `(Path, "unlink", ...)` is not reproduced: a real directory under
//! `$TMPDIR` is both simpler and a stronger claim, because it proves the
//! file is *gone* rather than that a patched method was called with it.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use agentcage_cli::legacy_watcher::{Host, LegacyWatcher, is_removable_name};
use agentcage_exec::tools::Elevation;
use agentcage_exec::{Command, CommandRunner, ExecError, FakeRunner, LineStream, Output, Reply};

// ── plumbing ─────────────────────────────────────────────────

/// A throwaway directory, removed when the value drops.
///
/// `tempfile` is not in this workspace's dependency tree; these paths
/// are created by the test process under its own temp dir and hold
/// fixture text, so nothing here needs that crate's properties.
#[derive(Debug)]
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("agentcage-d16-{label}-{}-{n}", std::process::id()));
        fs::create_dir_all(&path).expect("temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A home directory with the legacy Linux artifact in it.
fn home_with_unit(dir: &TempDir, cage: &str) -> PathBuf {
    let units = dir.path().join(".config/systemd/user");
    fs::create_dir_all(&units).expect("unit dir");
    fs::write(
        units.join(format!("{cage}-grants.service")),
        "[Service]\nExecStart=agentcage cage grants x watch --interval 1\n",
    )
    .expect("unit file");
    dir.path().to_path_buf()
}

/// A home directory with the legacy macOS artifact in it.
fn home_with_plist(dir: &TempDir, cage: &str) -> PathBuf {
    let agents = dir.path().join("Library/LaunchAgents");
    fs::create_dir_all(&agents).expect("agents dir");
    fs::write(
        agents.join(format!("io.agentcage.{cage}.grants.plist")),
        "<plist><dict><key>KeepAlive</key><true/></dict></plist>",
    )
    .expect("plist file");
    dir.path().to_path_buf()
}

/// A runner that notes, for each call, which paths existed at the
/// moment the call was made.
///
/// The ordering claim this module rests on — `disable --now` *before*
/// the unit file is unlinked, `daemon-reload` *after* — cannot be made
/// by looking at argv alone. Both orderings produce the same two
/// commands. So the probe has to be taken while the process is
/// mid-flight, which is what this does: it forwards to a [`FakeRunner`]
/// and, on the way through, records whether each watched path was on
/// disk.
#[derive(Debug)]
struct ProbingRunner {
    inner: FakeRunner,
    watched: Vec<PathBuf>,
    /// One entry per call: its argv, and which of `watched` existed.
    seen: Mutex<Vec<(Vec<String>, Vec<bool>)>>,
}

impl ProbingRunner {
    fn new(inner: FakeRunner, watched: Vec<PathBuf>) -> Self {
        Self {
            inner,
            watched,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn probe(&self, command: &Command) {
        let existed = self.watched.iter().map(|p| p.exists()).collect();
        self.seen
            .lock()
            .expect("probe lock")
            .push((command.argv(), existed));
    }

    /// Whether `watched[index]` was on disk when the call whose argv
    /// contains `needle` was made.
    fn existed_during(&self, needle: &str, index: usize) -> bool {
        let seen = self.seen.lock().expect("probe lock");
        let (_, existed) = seen
            .iter()
            .find(|(argv, _)| argv.iter().any(|a| a == needle))
            .unwrap_or_else(|| panic!("no call containing {needle:?} in {seen:#?}"));
        existed[index]
    }
}

impl CommandRunner for ProbingRunner {
    fn run(&self, command: &Command) -> Result<Output, ExecError> {
        self.probe(command);
        self.inner.run(command)
    }

    fn stream(&self, command: &Command) -> Result<Box<dyn LineStream>, ExecError> {
        self.probe(command);
        self.inner.stream(command)
    }

    fn which(&self, program: &str) -> Option<PathBuf> {
        self.inner.which(program)
    }
}

/// `limactl list --json <instance>` answering "this VM is up".
fn lima_running() -> Reply {
    Reply::ok(r#"{"name":"agentcage-oldcage","status":"Running"}"#)
}

/// The exact shell one-liner the in-guest cleanup sends.
fn guest_script(cage: &str) -> String {
    format!(
        "systemctl --user disable --now {cage}-grants.service 2>/dev/null; \
         rm -f \"$HOME/.config/systemd/user/{cage}-grants.service\" 2>/dev/null; \
         systemctl --user daemon-reload 2>/dev/null; true"
    )
}

// ── the four Python tests ────────────────────────────────────

/// `test_noop_when_nothing_installed`, both hosts.
///
/// > Post-rework cages have no artifacts: every path is a no-op, never
/// > raises, and never shells out to systemctl/launchctl.
///
/// The Python asserts `ran == []` and its comment claims "darwin/linux
/// branch bails before bootout/disable". Only half of that is true:
/// `_remove_macos_watcher` runs `launchctl bootout` *before* it looks at
/// the plist, so on a Mac this test would see one call. It passes
/// because CI is Linux and the darwin branch is unreachable there.
///
/// Both halves are asserted here, separately and honestly. The Linux
/// half is the Python's claim. The macOS half is the real behaviour, and
/// [`the_unconditional_bootout_is_deliberate`] says why it is kept.
#[test]
fn a_clean_system_shells_out_to_nothing() {
    let dir = TempDir::new("clean");
    let fake = FakeRunner::new();
    let warnings = LegacyWatcher::new(&fake)
        .with_host(Host::Linux)
        .with_home(dir.path())
        .remove("ghost", "container");

    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(fake.call_count(), 0, "{:?}", fake.argv_sequence());
    // Not even a PATH lookup: the missing unit file is decided first.
    assert!(fake.which_lookups().is_empty());
}

/// The macOS half of the case above — see that test's doc comment.
#[test]
fn a_clean_macos_system_still_boots_the_job_out() {
    let dir = TempDir::new("clean-mac");
    let fake = FakeRunner::new();
    fake.push(Reply::failed(
        3,
        "Boot-out failed: 36: Operation now in progress",
    ));

    let warnings = LegacyWatcher::new(&fake)
        .with_host(Host::MacOs)
        .with_home(dir.path())
        .with_uid(501)
        .remove("ghost", "container");

    assert!(warnings.is_empty(), "{warnings:?}");
    fake.assert_argv(&[&[
        "launchctl",
        "bootout",
        "gui/501",
        "io.agentcage.ghost.grants",
    ]]);
}

/// `test_linux_removes_unit_and_disables`.
///
/// Its three assertions — a `disable` call carrying `--now` with the
/// unit last, a `daemon-reload` call, and the unit path unlinked — plus
/// the ordering the Python cannot see (`any(...)` over an unordered
/// pile): disable first, reload second, and the unlink between them.
#[test]
fn linux_disables_the_unit_then_removes_it() {
    let dir = TempDir::new("linux");
    let home = home_with_unit(&dir, "oldcage");
    let unit = home.join(".config/systemd/user/oldcage-grants.service");
    assert!(unit.is_file(), "fixture");

    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push_all([Reply::success(), Reply::success()]);
    let runner = ProbingRunner::new(fake, vec![unit.clone()]);

    let warnings = LegacyWatcher::new(&runner)
        .with_host(Host::Linux)
        .with_home(&home)
        .remove("oldcage", "container");

    assert!(warnings.is_empty(), "{warnings:?}");
    runner.inner.assert_argv(&[
        &[
            "systemctl",
            "--user",
            "disable",
            "--now",
            "oldcage-grants.service",
        ],
        &["systemctl", "--user", "daemon-reload"],
    ]);
    assert!(!unit.exists(), "the unit file is gone");

    // The ordering, which is not optional: `disable` has to reach a unit
    // systemd can still resolve to a fragment, and `daemon-reload` has
    // to see a directory that has already changed.
    assert!(
        runner.existed_during("disable", 0),
        "disable --now ran while the unit file was still on disk"
    );
    assert!(
        !runner.existed_during("daemon-reload", 0),
        "daemon-reload ran after the unit file was unlinked"
    );
}

/// `test_darwin_bootout_and_unlink`.
///
/// `bootouts and any("io.agentcage.oldcage.grants" in ...)` plus
/// `plist in removed`, tightened to the full argv — including the
/// `gui/<uid>` domain, which is the part that decides whether the
/// bootout reaches anything at all.
#[test]
fn macos_boots_the_job_out_and_removes_the_plist() {
    let dir = TempDir::new("macos");
    let home = home_with_plist(&dir, "oldcage");
    let plist = home.join("Library/LaunchAgents/io.agentcage.oldcage.grants.plist");
    assert!(plist.is_file(), "fixture");

    let fake = FakeRunner::new();
    fake.push(Reply::success());

    let warnings = LegacyWatcher::new(&fake)
        .with_host(Host::MacOs)
        .with_home(&home)
        .with_uid(501)
        .remove("oldcage", "container");

    assert!(warnings.is_empty(), "{warnings:?}");
    fake.assert_argv(&[&[
        "launchctl",
        "bootout",
        "gui/501",
        "io.agentcage.oldcage.grants",
    ]]);
    assert!(!plist.exists(), "the plist is gone");
    // `bootout`, not `unload`: the job lives in the per-user GUI domain.
    assert!(!fake.argv(0).contains(&"unload".to_string()));
}

/// `test_vm_branch_swallow_errors`.
///
/// > An unreachable VM must not raise out of cleanup.
///
/// The Python gets there by patching `_remove_vm_watcher` to a no-op,
/// which means the branch it is named for never executes. Here the
/// branch runs for real against a `limactl` that is not installed, which
/// is what an unreachable VM looks like from this side, and the warning
/// text is pinned.
#[test]
fn an_unreachable_vm_is_a_warning_not_a_failure() {
    let dir = TempDir::new("vm-down");
    let fake = FakeRunner::new();
    fake.on(["limactl"], Reply::NotFound);

    let warnings = LegacyWatcher::new(&fake)
        .with_host(Host::Linux)
        .with_home(dir.path())
        .remove("oldcage", "vm");

    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].starts_with(
            "could not clean the in-VM legacy grants watcher for 'oldcage' (VM unreachable?): "
        ),
        "{warnings:?}"
    );
}

// ── what the Python file does not cover ──────────────────────

/// The in-guest removal itself, which no Python test reaches.
///
/// The one-liner is pinned verbatim because its three steps are the same
/// ordering argument as the host-side branch, spelled in `sh`, and
/// because `2>/dev/null` + the trailing `true` are what make a
/// partially-removed guest exit 0.
#[test]
fn a_running_vm_gets_the_in_guest_cleanup() {
    let dir = TempDir::new("vm-up");
    let fake = FakeRunner::new();
    fake.on(["limactl", "list"], lima_running());
    fake.push(Reply::success());

    let warnings = LegacyWatcher::new(&fake)
        .with_host(Host::Linux)
        .with_home(dir.path())
        .remove("oldcage", "vm");

    assert!(warnings.is_empty(), "{warnings:?}");
    fake.assert_argv(&[
        &["limactl", "list", "--json", "agentcage-oldcage"],
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-oldcage",
            "--",
            "sh",
            "-c",
            &guest_script("oldcage"),
        ],
    ]);
}

/// A stopped VM is left alone: there is nothing running to stop and no
/// guest filesystem to reach.
#[test]
fn a_stopped_vm_is_not_shelled_into() {
    let dir = TempDir::new("vm-stopped");
    let fake = FakeRunner::new();
    fake.on(
        ["limactl", "list"],
        Reply::ok(r#"{"name":"agentcage-oldcage","status":"Stopped"}"#),
    );

    let warnings = LegacyWatcher::new(&fake)
        .with_host(Host::Linux)
        .with_home(dir.path())
        .remove("oldcage", "vm");

    assert!(warnings.is_empty(), "{warnings:?}");
    fake.assert_argv(&[&["limactl", "list", "--json", "agentcage-oldcage"]]);
}

/// A container cage never touches `limactl`, whatever else it does.
#[test]
fn a_container_cage_does_not_reach_for_lima() {
    let dir = TempDir::new("no-lima");
    let home = home_with_unit(&dir, "oldcage");
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push_all([Reply::success(), Reply::success()]);

    let _ = LegacyWatcher::new(&fake)
        .with_host(Host::Linux)
        .with_home(&home)
        .remove("oldcage", "");

    assert!(
        fake.argv_sequence().iter().all(|argv| argv[0] != "limactl"),
        "{:?}",
        fake.argv_sequence()
    );
}

/// **Idempotency.** Two runs back to back leave the same state, and the
/// second issues no destructive call.
///
/// This is the property that lets `cage destroy` and `cage update` call
/// the cleanup unconditionally on every cage. The second run here sees
/// exactly what a cage created after the rework sees, which is the same
/// thing [`a_clean_system_shells_out_to_nothing`] asserts from the other
/// direction.
#[test]
fn running_the_cleanup_twice_is_the_same_as_running_it_once() {
    let dir = TempDir::new("twice");
    let home = home_with_unit(&dir, "oldcage");
    let unit = home.join(".config/systemd/user/oldcage-grants.service");

    let first = FakeRunner::new();
    first.assume_installed();
    first.push_all([Reply::success(), Reply::success()]);
    let warnings = LegacyWatcher::new(&first)
        .with_host(Host::Linux)
        .with_home(&home)
        .remove("oldcage", "container");
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(first.call_count(), 2);
    assert!(!unit.exists());

    let second = FakeRunner::new();
    second.assume_installed();
    let warnings = LegacyWatcher::new(&second)
        .with_host(Host::Linux)
        .with_home(&home)
        .remove("oldcage", "container");

    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(
        second.call_count(),
        0,
        "second run shelled out: {:?}",
        second.argv_sequence()
    );
    assert!(!unit.exists(), "state is unchanged by the second run");
}

/// The macOS side of idempotency, and the one call that does repeat.
///
/// `bootout` is unconditional (see the module docs: a plist deleted by
/// hand can leave the job bootstrapped, and this is the only thing that
/// reaches it), so a second run issues a second `bootout`. That is a
/// lookup which exits non-zero and changes nothing. What must not repeat
/// is the removal, and it does not.
#[test]
fn the_unconditional_bootout_is_deliberate() {
    let dir = TempDir::new("mac-twice");
    let home = home_with_plist(&dir, "oldcage");
    let plist = home.join("Library/LaunchAgents/io.agentcage.oldcage.grants.plist");

    for _ in 0..2 {
        let fake = FakeRunner::new();
        fake.push(Reply::failed(3, "Boot-out failed: 3: No such process"));
        let warnings = LegacyWatcher::new(&fake)
            .with_host(Host::MacOs)
            .with_home(&home)
            .with_uid(501)
            .remove("oldcage", "container");
        assert!(warnings.is_empty(), "{warnings:?}");
        fake.assert_argv(&[&[
            "launchctl",
            "bootout",
            "gui/501",
            "io.agentcage.oldcage.grants",
        ]]);
    }
    assert!(!plist.exists());
}

/// A **partially-removed** legacy cage: the file is still there, but
/// systemd has already forgotten the unit, so `disable --now` fails.
///
/// The Python's `check=False` and this code's discarded result both say
/// the same thing — a non-zero `disable` is a clean system, not an
/// error. The file still goes and the reload still happens, because
/// otherwise a half-finished earlier run would strand the artifact
/// forever.
#[test]
fn a_disable_that_fails_does_not_stop_the_removal() {
    let dir = TempDir::new("partial");
    let home = home_with_unit(&dir, "oldcage");
    let unit = home.join(".config/systemd/user/oldcage-grants.service");

    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push_all([
        Reply::failed(1, "Failed to disable unit: Unit file does not exist.\n"),
        Reply::success(),
    ]);

    let warnings = LegacyWatcher::new(&fake)
        .with_host(Host::Linux)
        .with_home(&home)
        .remove("oldcage", "container");

    assert!(warnings.is_empty(), "{warnings:?}");
    assert!(!unit.exists());
    fake.assert_argv(&[
        &[
            "systemctl",
            "--user",
            "disable",
            "--now",
            "oldcage-grants.service",
        ],
        &["systemctl", "--user", "daemon-reload"],
    ]);
}

/// **No systemd at all**, on a host that still has the unit file.
///
/// The Python raises `FileNotFoundError` here — `check=False` does not
/// suppress it, only a non-zero exit. The file is removed anyway,
/// because nothing can be holding a reference to it and leaving it
/// re-arms the crash loop if systemd ever appears.
#[test]
fn a_host_without_systemd_removes_the_file_and_runs_nothing() {
    let dir = TempDir::new("no-systemd");
    let home = home_with_unit(&dir, "oldcage");
    let unit = home.join(".config/systemd/user/oldcage-grants.service");

    let fake = FakeRunner::new();
    fake.stub_missing("systemctl");

    let warnings = LegacyWatcher::new(&fake)
        .with_host(Host::Linux)
        .with_home(&home)
        .remove("oldcage", "container");

    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(fake.call_count(), 0, "{:?}", fake.argv_sequence());
    assert_eq!(fake.which_lookups(), ["systemctl"]);
    assert!(!unit.exists(), "the stale unit is still removed");
}

/// Under `sudo`, `systemctl --user` has to reach the invoking operator's
/// instance — root's has none of these units.
#[test]
fn the_runuser_prefix_is_applied_under_sudo() {
    let dir = TempDir::new("sudo");
    let home = home_with_unit(&dir, "oldcage");
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push_all([Reply::success(), Reply::success()]);

    let _ = LegacyWatcher::new(&fake)
        .with_host(Host::Linux)
        .with_home(&home)
        .with_elevation(Elevation::runuser("luca"))
        .remove("oldcage", "container");

    fake.assert_argv(&[
        &[
            "runuser",
            "-u",
            "luca",
            "--",
            "systemctl",
            "--user",
            "disable",
            "--now",
            "oldcage-grants.service",
        ],
        &[
            "runuser",
            "-u",
            "luca",
            "--",
            "systemctl",
            "--user",
            "daemon-reload",
        ],
    ]);
}

// ── deletion safety ──────────────────────────────────────────

/// A name that is not a cage name deletes nothing and runs nothing.
///
/// `name` reaches this module from a legacy cage's persisted metadata,
/// written by a version of agentcage whose validator is not this one's.
/// The two things it would otherwise get to choose are a path outside
/// `~/.config/systemd/user` and a word inside a `sh -c` string sent to
/// the guest.
#[test]
fn a_name_that_is_not_a_cage_name_is_refused() {
    let dir = TempDir::new("hostile");
    let decoy = dir.path().join("keep-me");
    fs::write(&decoy, "not yours").expect("decoy");

    for name in [
        "../../keep-me",
        "oldcage; rm -rf $HOME",
        "old cage",
        "OLDCAGE",
        "",
        &"a".repeat(64),
    ] {
        let fake = FakeRunner::new();
        let watcher = LegacyWatcher::new(&fake)
            .with_host(Host::Linux)
            .with_home(dir.path());

        assert_eq!(watcher.grants_service_path(name), None, "{name:?}");
        assert_eq!(watcher.grants_plist_path(name), None, "{name:?}");

        let warnings = watcher.remove(name, "vm");
        assert_eq!(warnings.len(), 1, "{name:?}: {warnings:?}");
        assert!(
            warnings[0].contains("not a valid cage name"),
            "{warnings:?}"
        );
        // Nothing ran — including the VM branch, whose shell string is
        // the injection this gate exists for.
        assert_eq!(fake.call_count(), 0, "{:?}", fake.argv_sequence());
    }
    assert!(decoy.exists(), "the decoy was never touched");
    assert!(is_removable_name("oldcage"));
}

/// The path is always constructed here, never accepted from a caller.
///
/// There is no `remove(path)`. The only inputs are a cage name that has
/// passed [`is_removable_name`] and a `$HOME`, and the two path methods
/// are the only way to turn them into a path — so what can be unlinked
/// is exactly `~/.config/systemd/user/<name>-grants.service` and
/// `~/Library/LaunchAgents/io.agentcage.<name>.grants.plist`.
#[test]
fn the_only_two_paths_it_can_build() {
    let fake = FakeRunner::new();
    let watcher = LegacyWatcher::new(&fake).with_home("/home/luca");
    assert_eq!(
        watcher.grants_service_path("oldcage").unwrap(),
        Path::new("/home/luca/.config/systemd/user/oldcage-grants.service")
    );
    assert_eq!(
        watcher.grants_plist_path("oldcage").unwrap(),
        Path::new("/home/luca/Library/LaunchAgents/io.agentcage.oldcage.grants.plist")
    );
}

/// A symlink planted at the unit path costs its target nothing.
///
/// `is_file` follows the link, so the entry is recognised; `remove_file`
/// does not, so only the link goes. Same as `Path.is_file()` +
/// `Path.unlink()` in the Python, asserted rather than assumed — this is
/// the module that deletes things.
#[test]
fn a_symlinked_unit_removes_the_link_not_the_target() {
    let dir = TempDir::new("symlink");
    let home = dir.path().to_path_buf();
    let units = home.join(".config/systemd/user");
    fs::create_dir_all(&units).expect("unit dir");
    let target = dir.path().join("precious");
    fs::write(&target, "do not delete").expect("target");
    let link = units.join("oldcage-grants.service");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push_all([Reply::success(), Reply::success()]);

    let warnings = LegacyWatcher::new(&fake)
        .with_host(Host::Linux)
        .with_home(&home)
        .remove("oldcage", "container");

    assert!(warnings.is_empty(), "{warnings:?}");
    assert!(
        !link.exists() && fs::symlink_metadata(&link).is_err(),
        "the link is gone"
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "do not delete");
}

/// An unknown `$HOME` stops everything rather than resolving a relative
/// path against whatever the cwd happens to be.
#[test]
fn an_unknown_home_removes_nothing() {
    let fake = FakeRunner::new();
    let warnings = LegacyWatcher::new(&fake)
        .without_home()
        .with_host(Host::Linux)
        .remove("oldcage", "vm");

    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("$HOME is unset"), "{warnings:?}");
    assert_eq!(fake.call_count(), 0);
}

/// A unit file that cannot be unlinked warns and stops — it does not go
/// on to `daemon-reload` a directory that has not changed.
///
/// `legacy_watcher.py`'s `except OSError: print(...); return`.
#[test]
fn an_unremovable_unit_warns_and_skips_the_reload() {
    let dir = TempDir::new("readonly");
    let home = home_with_unit(&dir, "oldcage");
    let units = home.join(".config/systemd/user");
    let unit = units.join("oldcage-grants.service");

    // Unlink permission lives on the *directory*, not the file.
    let mut perms = fs::metadata(&units).expect("dir meta").permissions();
    let original = perms.clone();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o500);
    fs::set_permissions(&units, perms).expect("chmod");

    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push(Reply::success());

    let warnings = LegacyWatcher::new(&fake)
        .with_host(Host::Linux)
        .with_home(&home)
        .remove("oldcage", "container");

    fs::set_permissions(&units, original).expect("chmod back");

    // Running as root defeats the permission bits; the claim only means
    // anything as an unprivileged user.
    if nix::unistd::getuid().is_root() {
        return;
    }
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].starts_with(&format!(
            "could not remove legacy grants watcher unit {}: ",
            unit.display()
        )),
        "{warnings:?}"
    );
    fake.assert_argv(&[&[
        "systemctl",
        "--user",
        "disable",
        "--now",
        "oldcage-grants.service",
    ]]);
    assert!(unit.exists());
}
