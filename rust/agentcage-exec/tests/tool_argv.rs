//! argv assertions for the six non-podman tools.
//!
//! `test_podman.py` has a Rust counterpart in `podman_argv.rs`; the
//! other tools' Python tests are spread across `test_systemd.py`,
//! `test_lima_*.py`, `test_vm_backend.py`, `test_apple_container*.py`
//! and `test_secret_store.py`, and D2, D3, E1, E2b and E3 port the logic
//! around them. What is pinned here is the *seam*: the exact argv each
//! wrapper produces, so those PRs inherit a contract rather than
//! inventing one.

use agentcage_exec::tools::apple::{AppleContainer, container_state};
use agentcage_exec::tools::creds::{PROBE_NAME, Scope, SystemdCreds};
use agentcage_exec::tools::limactl::LimaInstance;
use agentcage_exec::tools::security::{KeychainTarget, Security};
use agentcage_exec::tools::skopeo::{LIST_TAGS_TIMEOUT, Skopeo};
use agentcage_exec::tools::systemctl::Systemctl;
use agentcage_exec::{Elevation, FakeRunner, Reply, Stdin};

// ---------------------------------------------------------------------
// systemctl  --  systemd.py
// ---------------------------------------------------------------------

/// All six unit operations, in one sequence, with `--user` on every one.
#[test]
fn systemctl_operations_are_user_scoped() {
    let fake = FakeRunner::new();
    fake.assume_installed();
    for _ in 0..6 {
        fake.push(Reply::status(0));
    }

    let s = Systemctl::with_elevation(&fake, Elevation::none());
    assert!(s.daemon_reload().unwrap());
    assert!(s.start_unit("myapp-cage.service").unwrap());
    assert!(s.stop_unit("myapp-cage.service").unwrap());
    assert!(s.restart_unit("myapp-cage.service").unwrap());
    assert!(s.enable_unit("myapp-watcher.service").unwrap());
    assert!(s.disable_unit("myapp-watcher.service").unwrap());

    fake.assert_argv(&[
        &["systemctl", "--user", "daemon-reload"],
        &["systemctl", "--user", "start", "myapp-cage.service"],
        &["systemctl", "--user", "stop", "myapp-cage.service"],
        &["systemctl", "--user", "restart", "myapp-cage.service"],
        &["systemctl", "--user", "enable", "myapp-watcher.service"],
        &["systemctl", "--user", "disable", "myapp-watcher.service"],
    ]);
    fake.assert_drained();
}

/// The `runuser` prefix comes before `systemctl`, and `--user` after --
/// otherwise `systemctl --user` reaches root's instance, not the
/// operator's, and the cage's units are not there.
#[test]
fn systemctl_under_sudo_drops_to_the_real_user_first() {
    let fake = FakeRunner::new();
    fake.assume_installed().push(Reply::status(0));
    Systemctl::with_elevation(&fake, Elevation::runuser("alice"))
        .daemon_reload()
        .unwrap();
    fake.assert_call(
        0,
        &[
            "runuser",
            "-u",
            "alice",
            "--",
            "systemctl",
            "--user",
            "daemon-reload",
        ],
    );
}

/// The macOS branch, reached from a Linux test runner.
///
/// `systemd.py` no-ops every operation when `shutil.which("systemctl")`
/// is `None`, so that cleaning up a container-backed cage from a Mac
/// does not die with `FileNotFoundError`. CI has no macOS runner, so
/// without a stubbable probe this branch would never be executed
/// anywhere.
#[test]
fn systemctl_is_a_no_op_without_systemd() {
    let fake = FakeRunner::new();
    fake.stub_missing("systemctl");
    let s = Systemctl::with_elevation(&fake, Elevation::none());

    assert!(!s.available());
    assert!(!s.daemon_reload().unwrap());
    assert!(!s.start_unit("anything.service").unwrap());
    assert!(!s.stop_unit("anything.service").unwrap());

    assert_eq!(fake.call_count(), 0, "nothing was spawned");
}

/// A failing unit operation is an error, because `systemd.py` passes
/// `check=True` everywhere.
#[test]
fn a_failing_unit_operation_is_an_error() {
    let fake = FakeRunner::new();
    fake.assume_installed()
        .push(Reply::failed(5, "Unit myapp-cage.service not found."));
    let err = Systemctl::with_elevation(&fake, Elevation::none())
        .start_unit("myapp-cage.service")
        .unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");
}

/// `secret_resolver.py::_systemd_version`: no `--user`, no elevation
/// prefix, and every failure collapses to 0.
#[test]
fn the_systemd_version_probe_is_unadorned() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok("systemd 256 (256.11-1-arch)\n+PAM +AUDIT\n"));
    let s = Systemctl::with_elevation(&fake, Elevation::runuser("alice"));
    assert_eq!(s.systemd_version(), 256);
    fake.assert_call(0, &["systemctl", "--version"]);

    fake.push(Reply::NotFound);
    assert_eq!(s.systemd_version(), 0);
    fake.push(Reply::ok("not a version line"));
    assert_eq!(s.systemd_version(), 0);
}

// ---------------------------------------------------------------------
// limactl  --  lima/instance.py
// ---------------------------------------------------------------------

/// The instance name, and the four lifecycle commands.
#[test]
fn lima_lifecycle_commands() {
    let fake = FakeRunner::new();
    for _ in 0..4 {
        fake.push(Reply::status(0));
    }
    let inst = LimaInstance::new(&fake, "myapp");
    assert_eq!(inst.name(), "agentcage-myapp");

    inst.create("/tmp/lima.yaml").unwrap();
    inst.start().unwrap();
    inst.stop().unwrap();
    inst.delete().unwrap();

    fake.assert_argv(&[
        &[
            "limactl",
            "create",
            "--yes",
            "--name=agentcage-myapp",
            "/tmp/lima.yaml",
        ],
        &["limactl", "start", "agentcage-myapp"],
        &["limactl", "stop", "agentcage-myapp"],
        &["limactl", "delete", "--force", "agentcage-myapp"],
    ]);
}

/// `start_new_session=True`: the hostagent daemon must not stay in
/// agentcage's process group.
#[test]
fn lima_start_detaches_the_hostagent() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    LimaInstance::new(&fake, "myapp").start().unwrap();
    assert!(fake.call(0).command.is_new_process_group());
    // ...and only that one does.
    fake.push(Reply::status(0));
    LimaInstance::new(&fake, "myapp").stop().unwrap();
    assert!(!fake.call(1).command.is_new_process_group());
}

/// `--workdir /` and `--tty=false` are both load-bearing; see
/// `LimaInstance::shell_command`.
#[test]
fn lima_shell_pins_the_workdir_and_refuses_a_pty() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok(""));
    LimaInstance::new(&fake, "myapp")
        .exec(&["podman".to_string(), "info".to_string()], true)
        .unwrap();
    fake.assert_call(
        0,
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-myapp",
            "--",
            "podman",
            "info",
        ],
    );
}

/// The VM backend's secret delivery: the value goes down the pipe, and
/// `--tty=false` is what keeps the line discipline from cooking it.
#[test]
fn lima_secret_delivery_uses_stdin_through_two_hops() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok(""));
    LimaInstance::new(&fake, "myapp")
        .exec_with_secret(
            &[
                "podman".to_string(),
                "secret".to_string(),
                "create".to_string(),
                "myapp.KEY".to_string(),
                "-".to_string(),
            ],
            "hunter2",
        )
        .unwrap();

    let call = fake.call(0);
    assert!(call.argv().contains(&"--tty=false".to_string()));
    assert_eq!(call.argv().last().unwrap(), "-");
    assert_eq!(call.stdin_text().as_deref(), Some("hunter2"));
    assert!(!call.argv().iter().any(|a| a.contains("hunter2")));
    assert!(!format!("{call:?}").contains("hunter2"));
}

/// `limactl list --json <name>`, and both ways of answering "no".
#[test]
fn lima_status_reads_the_json_listing() {
    let fake = FakeRunner::new();
    fake.push_all([
        Reply::ok(r#"{"name": "agentcage-myapp", "status": "Running"}"#),
        Reply::ok(r#"{"name": "agentcage-myapp", "status": "Stopped"}"#),
        Reply::failed(1, "instance not found"),
    ]);
    let inst = LimaInstance::new(&fake, "myapp");
    assert!(inst.is_running().unwrap());
    assert!(!inst.is_running().unwrap());
    assert!(!inst.is_running().unwrap());
    fake.assert_call(0, &["limactl", "list", "--json", "agentcage-myapp"]);
}

/// A missing `limactl` is not the same as a stopped instance, and it
/// must not be reported as one.
#[test]
fn a_missing_limactl_is_reported_rather_than_swallowed() {
    let fake = FakeRunner::new();
    fake.push(Reply::NotFound);
    let err = LimaInstance::new(&fake, "myapp").is_running().unwrap_err();
    assert!(err.is_not_found());
}

// ---------------------------------------------------------------------
// container(1)  --  apple_container/cli.py
// ---------------------------------------------------------------------

/// `PATH` first, then the .pkg and Homebrew locations -- the whole
/// reason `container_binary()` exists.
#[test]
fn the_container_binary_falls_back_to_the_pkg_location() {
    let on_path = FakeRunner::new();
    on_path.stub_which("container", "/usr/bin/container");
    assert_eq!(
        AppleContainer::new(&on_path).binary().as_deref(),
        Some("/usr/bin/container")
    );

    let pkg = FakeRunner::new();
    pkg.stub_missing("container")
        .stub_which("/usr/local/bin/container", "/usr/local/bin/container");
    assert_eq!(
        AppleContainer::new(&pkg).binary().as_deref(),
        Some("/usr/local/bin/container")
    );

    let brew = FakeRunner::new();
    brew.stub_missing("container")
        .stub_missing("/usr/local/bin/container")
        .stub_which("/opt/homebrew/bin/container", "/opt/homebrew/bin/container");
    assert_eq!(
        AppleContainer::new(&brew).binary().as_deref(),
        Some("/opt/homebrew/bin/container")
    );

    let absent = FakeRunner::new();
    absent.assume_missing();
    assert_eq!(AppleContainer::new(&absent).binary(), None);
}

/// The resolved path is argv[0], not the literal `container`.
#[test]
fn container_commands_use_the_resolved_path() {
    let fake = FakeRunner::new();
    fake.stub_which("container", "/usr/local/bin/container")
        .push_all([
            Reply::ok("apiserver status: running\n"),
            Reply::ok(r#"[{"status": {"state": "running"}}]"#),
            Reply::ok(r#"[{"Id": "img"}]"#),
        ]);
    let c = AppleContainer::new(&fake);

    assert!(c.system_running().unwrap());
    let data = c.inspect("myapp-cage").unwrap();
    assert_eq!(container_state(data.as_ref()).as_deref(), Some("running"));
    assert!(c.image_inspect("myimg").unwrap().is_some());

    fake.assert_argv(&[
        &["/usr/local/bin/container", "system", "status"],
        &["/usr/local/bin/container", "inspect", "myapp-cage"],
        &["/usr/local/bin/container", "image", "inspect", "myimg"],
    ]);
}

/// Without the binary, `system_running` is `false` and `inspect` is
/// `None` -- the Python's `except FileNotFoundError` -- and nothing is
/// spawned.
#[test]
fn container_calls_degrade_when_the_binary_is_missing() {
    let fake = FakeRunner::new();
    fake.assume_missing();
    let c = AppleContainer::new(&fake);
    assert!(!c.system_running().unwrap());
    assert_eq!(c.inspect("myapp-cage").unwrap(), None);
    assert_eq!(fake.call_count(), 0);
}

/// A non-zero exit and unparseable JSON both answer `None`, without
/// erroring.
#[test]
fn container_inspect_answers_none_rather_than_failing() {
    let fake = FakeRunner::new();
    fake.stub_which("container", "/usr/local/bin/container")
        .push_all([Reply::failed(1, "not found"), Reply::ok("not json")]);
    let c = AppleContainer::new(&fake);
    assert_eq!(c.inspect("gone").unwrap(), None);
    assert_eq!(c.inspect("weird").unwrap(), None);
}

// ---------------------------------------------------------------------
// skopeo  --  registry.py
// ---------------------------------------------------------------------

/// `skopeo list-tags docker://<image>`, with the 30s limit.
#[test]
fn skopeo_list_tags() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok(
        r#"{"Repository": "docker.io/library/ubuntu", "Tags": ["24.04", "latest"]}"#,
    ));
    let tags = Skopeo::new(&fake)
        .list_tags("docker.io/library/ubuntu")
        .unwrap();
    assert_eq!(tags, ["24.04", "latest"]);
    fake.assert_call(
        0,
        &["skopeo", "list-tags", "docker://docker.io/library/ubuntu"],
    );
    assert_eq!(
        fake.call(0).command.timeout_limit(),
        Some(LIST_TAGS_TIMEOUT)
    );
}

/// The case `ExecError::NotFound` exists for: `registry.py` prints
/// "skopeo is not installed" for this and stays silent for the others,
/// so the caller has to be able to tell them apart.
#[test]
fn a_missing_skopeo_is_distinguishable_from_a_failing_one() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::NotFound, Reply::failed(1, "no such repository")]);
    let s = Skopeo::new(&fake);
    assert!(s.list_tags("img").unwrap_err().is_not_found());
    assert!(!s.list_tags("img").unwrap_err().is_not_found());
}

/// A timeout is its own outcome too; `registry.py` returns `None` for
/// it, silently.
#[test]
fn a_registry_timeout_is_its_own_error() {
    let fake = FakeRunner::new();
    fake.push(Reply::TimedOut);
    let err = Skopeo::new(&fake).list_tags("img").unwrap_err();
    assert!(!err.is_not_found());
    assert!(err.to_string().contains("timed out"), "{err}");
}

// ---------------------------------------------------------------------
// security(1)  --  secret_store.py
// ---------------------------------------------------------------------

/// The write probe: an add followed by a delete, because a read probe
/// passes over headless SSH where a write does not.
#[test]
fn the_keychain_write_probe_adds_and_deletes() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::status(0), Reply::status(0)]);
    assert!(
        Security::new(&fake)
            .writable(&KeychainTarget::login())
            .unwrap()
    );
    fake.assert_argv(&[
        &[
            "security",
            "add-generic-password",
            "-s",
            "agentcage",
            "-a",
            "__agentcage_probe__",
            "-w",
            "x",
            "-U",
        ],
        &[
            "security",
            "delete-generic-password",
            "-s",
            "agentcage",
            "-a",
            "__agentcage_probe__",
        ],
    ]);
}

/// A failed add means not writable, and nothing is deleted.
#[test]
fn a_failed_probe_add_does_not_delete() {
    let fake = FakeRunner::new();
    fake.push(Reply::failed(
        1,
        "SecKeychainItemCreateFromContent: User interaction is not allowed.",
    ));
    assert!(
        !Security::new(&fake)
            .writable(&KeychainTarget::login())
            .unwrap()
    );
    assert_eq!(fake.call_count(), 1);
}

/// The System-keychain target: `sudo -n` in front, the keychain path at
/// the end.
#[test]
fn the_system_keychain_probe_uses_sudo_n() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::status(0), Reply::status(0)]);
    Security::new(&fake)
        .writable(&KeychainTarget::system())
        .unwrap();
    fake.assert_call(
        0,
        &[
            "sudo",
            "-n",
            "security",
            "add-generic-password",
            "-s",
            "agentcage",
            "-a",
            "__agentcage_probe__",
            "-w",
            "x",
            "-U",
            "/Library/Keychains/System.keychain",
        ],
    );
}

/// **The finding.** `KeychainStore.set` is the only place in agentcage
/// where secret material travels in argv, where `ps` can read it. This
/// pins the argv the Python produces -- so E2b's port is a port and not
/// a rewrite -- and pins that nothing this crate prints reveals it.
#[test]
fn keychain_set_puts_the_cleartext_in_argv_and_that_is_the_bug() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    Security::new(&fake)
        .add(&KeychainTarget::login(), "myapp.API_KEY", "hunter2")
        .unwrap();

    // Byte-for-byte what secret_store.py:224-230 builds.
    assert_eq!(
        fake.call(0).raw_argv(),
        [
            "security",
            "add-generic-password",
            "-s",
            "agentcage",
            "-a",
            "myapp.API_KEY",
            "-w",
            "hunter2",
            "-U",
        ]
    );
    // Nothing went on stdin, which is the problem.
    assert_eq!(fake.call(0).command.stdin_spec(), &Stdin::Inherit);
    // The redacted view is what every message in this crate uses.
    assert_eq!(fake.argv(0)[7], "<redacted>");
    assert!(!format!("{:?}", fake.calls()).contains("hunter2"));
}

/// `find-generic-password -w` asks for the password to be printed, so
/// its bare `-w` carries nothing.
#[test]
fn keychain_get_has_no_secret_in_argv() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok("hunter2\n"));
    let value = Security::new(&fake)
        .find(&KeychainTarget::login(), "myapp.API_KEY")
        .unwrap();
    assert_eq!(value.as_deref(), Some("hunter2"));
    let call = fake.call(0);
    assert_eq!(*call.command.secret_arg_indices(), [] as [usize; 0]);
    assert_eq!(call.raw_argv().last().unwrap(), "-w");
}

/// An absent item is `None`, not an error.
#[test]
fn keychain_get_reports_absence_as_none() {
    let fake = FakeRunner::new();
    fake.push(Reply::failed(44, "The specified item could not be found"));
    assert_eq!(
        Security::new(&fake)
            .find(&KeychainTarget::login(), "myapp.MISSING")
            .unwrap(),
        None
    );
}

// ---------------------------------------------------------------------
// systemd-creds  --  secret_resolver.py
// ---------------------------------------------------------------------

/// The encrypt command, in both scopes. The value is on stdin; `--name`
/// carries the env variable name, which is not secret.
#[test]
fn systemd_creds_encrypt_keeps_the_value_on_stdin() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::status(0), Reply::status(0)]);
    let creds = SystemdCreds::new(&fake);

    creds
        .encrypt(
            Scope::System,
            "API_KEY",
            "/state/creds/API_KEY.cred",
            "hunter2",
        )
        .unwrap();
    creds
        .encrypt(
            Scope::User,
            "API_KEY",
            "/state/creds/API_KEY.cred",
            "hunter2",
        )
        .unwrap();

    fake.assert_argv(&[
        &[
            "systemd-creds",
            "encrypt",
            "--name",
            "API_KEY",
            "-",
            "/state/creds/API_KEY.cred",
        ],
        &[
            "systemd-creds",
            "--user",
            "encrypt",
            "--name",
            "API_KEY",
            "-",
            "/state/creds/API_KEY.cred",
        ],
    ]);
    for call in fake.calls() {
        assert_eq!(call.stdin_text().as_deref(), Some("hunter2"));
        assert!(!call.raw_argv().iter().any(|a| a.contains("hunter2")));
    }
}

/// The capability probe: encrypt a literal to stdout and throw it away,
/// with the shorter limit.
#[test]
fn the_systemd_creds_probe_encrypts_to_stdout() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::status(0), Reply::status(1)]);
    let creds = SystemdCreds::new(&fake);
    assert!(creds.works(Scope::User));
    assert!(!creds.works(Scope::System));
    fake.assert_argv(&[
        &[
            "systemd-creds",
            "--user",
            "encrypt",
            "--name",
            PROBE_NAME,
            "-",
            "-",
        ],
        &["systemd-creds", "encrypt", "--name", PROBE_NAME, "-", "-"],
    ]);
}

/// `auto` prefers `user` for a non-root invoker, and skips the user
/// probe entirely for root -- root's per-user key is not the operator's.
#[test]
fn scope_detection_prefers_user_for_a_non_root_invoker() {
    let non_root = FakeRunner::new();
    non_root.push(Reply::status(0));
    assert_eq!(
        SystemdCreds::new(&non_root).detect_scope(true),
        Some(Scope::User)
    );
    assert_eq!(non_root.argv(0)[1], "--user");

    let as_root = FakeRunner::new();
    as_root.push(Reply::status(0));
    assert_eq!(
        SystemdCreds::new(&as_root).detect_scope(false),
        Some(Scope::System)
    );
    assert_eq!(as_root.call_count(), 1, "root never probes the user scope");

    let neither = FakeRunner::new();
    neither.push_all([Reply::status(1), Reply::status(1)]);
    assert_eq!(SystemdCreds::new(&neither).detect_scope(true), None);
}

/// A timeout during the probe answers "no", as `except Exception` does.
#[test]
fn a_probe_timeout_answers_no() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::TimedOut, Reply::NotFound]);
    let creds = SystemdCreds::new(&fake);
    assert!(!creds.works(Scope::User));
    assert!(!creds.works(Scope::System));
}
