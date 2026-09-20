//! argv for every `systemctl` invocation the unit lifecycle makes.
//!
//! D1 pinned the *wrapper's* argv in
//! `agentcage-exec/tests/tool_argv.rs`: six unit operations, the
//! `runuser` prefix, the missing-binary no-op and the version probe.
//! What is pinned here is what `state`/`systemd` does *with* it —
//! which operations a deploy, a teardown and a restart actually issue,
//! in what order, and which of them are file operations that must
//! spawn nothing at all.
//!
//! The distinction matters because the commonest way to get this wrong
//! is not a malformed argv, it is an extra `daemon-reload` per unit
//! file instead of one per batch, or a `systemctl restart` on a
//! `-podman-storage.volume` unit that this cage never had — which is
//! an error, not a no-op, and takes a `cage start` down with it.
//!
//! Every test below ends in an `assert_argv` or an
//! `assert_eq!(fake.call_count(), 0)`, so no invocation reaches
//! systemd without a line in this file describing it.

use agentcage_exec::{Elevation, FakeRunner, Reply};
use agentcage_state::{Paths, QUADLET_SUFFIXES, StateError, TestDir, Units};
use std::fs;

fn sandbox(label: &str) -> (TestDir, Paths) {
    let dir = TestDir::new(label);
    let paths = Paths::under(dir.path());
    (dir, paths)
}

// ─────────────────────────────────────────────────────────
// the six operations, straight through
// ─────────────────────────────────────────────────────────

#[test]
fn every_unit_operation_is_user_scoped() {
    let (_dir, paths) = sandbox("systemd-verbs");
    let fake = FakeRunner::new();
    fake.assume_installed();
    for _ in 0..6 {
        fake.push(Reply::status(0));
    }
    let units = Units::with_elevation(&paths, &fake, Elevation::none());

    assert!(units.daemon_reload().unwrap());
    assert!(units.start("acme-cage.service").unwrap());
    assert!(units.stop("acme-cage.service").unwrap());
    assert!(units.restart("acme-egress.service").unwrap());
    assert!(units.enable("acme-watcher.service").unwrap());
    assert!(units.disable("acme-watcher.service").unwrap());

    fake.assert_argv(&[
        &["systemctl", "--user", "daemon-reload"],
        &["systemctl", "--user", "start", "acme-cage.service"],
        &["systemctl", "--user", "stop", "acme-cage.service"],
        &["systemctl", "--user", "restart", "acme-egress.service"],
        &["systemctl", "--user", "enable", "acme-watcher.service"],
        &["systemctl", "--user", "disable", "acme-watcher.service"],
    ]);
    fake.assert_drained();
}

#[test]
fn under_sudo_every_operation_drops_to_the_real_user_first() {
    // `runuser -u <user> --` comes *before* `systemctl`, and `--user`
    // after. Reversed, `systemctl --user` reaches root's user instance
    // rather than the operator's, where the cage's units are not —
    // which is not a crash, it is a cage deployed into the wrong
    // user's storage.
    let (_dir, paths) = sandbox("systemd-sudo");
    let fake = FakeRunner::new();
    fake.assume_installed();
    for _ in 0..2 {
        fake.push(Reply::status(0));
    }
    let units = Units::with_elevation(&paths, &fake, Elevation::runuser("alice"));

    units.daemon_reload().unwrap();
    units.restart("acme-net-network.service").unwrap();

    fake.assert_argv(&[
        &[
            "runuser",
            "-u",
            "alice",
            "--",
            "systemctl",
            "--user",
            "daemon-reload",
        ],
        &[
            "runuser",
            "-u",
            "alice",
            "--",
            "systemctl",
            "--user",
            "restart",
            "acme-net-network.service",
        ],
    ]);
    fake.assert_drained();
}

#[test]
fn a_failing_unit_operation_is_an_error() {
    // `systemd.py` passes `check=True` to every call.
    let (_dir, paths) = sandbox("systemd-fail");
    let fake = FakeRunner::new();
    fake.assume_installed()
        .push(Reply::failed(5, "Unit acme-cage.service not found."));
    let units = Units::with_elevation(&paths, &fake, Elevation::none());

    let error = units.start("acme-cage.service").unwrap_err();
    assert!(matches!(error, StateError::Systemd(_)), "{error:?}");
    assert!(error.to_string().contains("not found"), "{error}");
    fake.assert_argv(&[&["systemctl", "--user", "start", "acme-cage.service"]]);
}

// ─────────────────────────────────────────────────────────
// installing and removing unit files
// ─────────────────────────────────────────────────────────

#[test]
fn a_deploy_reloads_once_for_the_whole_batch() {
    // Not once per file. `install_units` writes every unit and then
    // calls `systemd.daemon_reload()` exactly once, which is both
    // faster and the only ordering that is correct: a reload between
    // two files of one cage can leave the generator looking at half a
    // deployment.
    let (_dir, paths) = sandbox("systemd-install");
    let fake = FakeRunner::new();
    fake.assume_installed().push(Reply::status(0));
    let units = Units::with_elevation(&paths, &fake, Elevation::none());

    let installed = units
        .install([
            ("acme-net.network", "[Network]\n"),
            ("acme-certs.volume", "[Volume]\n"),
            ("acme-public-certs.volume", "[Volume]\n"),
            ("acme-egress.container", "[Container]\n"),
            ("acme-cage.container", "[Container]\n"),
            ("acme-watcher.service", "[Service]\n"),
        ])
        .unwrap();

    assert!(installed.reloaded);
    assert_eq!(installed.written.len(), 6);
    fake.assert_argv(&[&["systemctl", "--user", "daemon-reload"]]);
    fake.assert_drained();

    // Five quadlets in the quadlet directory, the native unit in the
    // systemd-user one.
    let quadlets = fs::read_dir(paths.quadlet_dir()).unwrap().count();
    let natives = fs::read_dir(paths.user_unit_dir()).unwrap().count();
    assert_eq!((quadlets, natives), (5, 1));
    assert!(paths.user_unit_dir().join("acme-watcher.service").is_file());
}

#[test]
fn a_teardown_removes_the_legacy_names_too_and_reloads_once() {
    let (_dir, paths) = sandbox("systemd-teardown");
    fs::create_dir_all(paths.quadlet_dir()).unwrap();
    for suffix in QUADLET_SUFFIXES {
        fs::write(paths.quadlet_dir().join(format!("acme{suffix}")), "x").unwrap();
    }
    // Another cage's units, which must survive.
    fs::write(paths.quadlet_dir().join("other-cage.container"), "x").unwrap();

    let fake = FakeRunner::new();
    fake.assume_installed().push(Reply::status(0));
    let units = Units::with_elevation(&paths, &fake, Elevation::none());

    let removed = units.remove_quadlets("acme").unwrap();
    assert_eq!(
        removed,
        [
            "acme-cage.container",
            "acme-egress.container",
            "acme-net.network",
            "acme-certs.volume",
            "acme-public-certs.volume",
            "acme-podman-storage.volume",
            // The pre-v0.22 three-service layout. `cage destroy` must
            // still clean up a stuck v0.21 cage even though every
            // other command refuses to touch one.
            "acme-proxy.container",
            "acme-dns.container",
        ]
    );
    assert!(paths.quadlet_dir().join("other-cage.container").is_file());
    fake.assert_argv(&[&["systemctl", "--user", "daemon-reload"]]);
    fake.assert_drained();
}

#[test]
fn removing_a_cage_that_has_no_units_still_reloads_and_removes_nothing() {
    let (_dir, paths) = sandbox("systemd-teardown-empty");
    fs::create_dir_all(paths.quadlet_dir()).unwrap();
    let fake = FakeRunner::new();
    fake.assume_installed().push(Reply::status(0));
    let units = Units::with_elevation(&paths, &fake, Elevation::none());

    assert!(units.remove_quadlets("ghost").unwrap().is_empty());
    fake.assert_argv(&[&["systemctl", "--user", "daemon-reload"]]);
}

// ─────────────────────────────────────────────────────────
// the file checks that must not become systemctl calls
// ─────────────────────────────────────────────────────────

#[test]
fn the_nested_podman_volume_is_probed_on_disk_not_through_systemd() {
    // `backends/container.py::start` guards the
    // `-podman-storage-volume.service` restart with
    // `if (self.unit_dir() / f"{name}-podman-storage.volume").exists()`.
    // A cage without nested containers never had that quadlet, and
    // `systemctl restart` on a unit that does not exist is an error,
    // not a no-op.
    let (_dir, paths) = sandbox("systemd-storage-probe");
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

    assert_eq!(fake.call_count(), 0, "a file check spawned a process");
}

#[test]
fn the_unit_router_spawns_nothing() {
    let (_dir, paths) = sandbox("systemd-router");
    let fake = FakeRunner::new();
    fake.assume_installed();
    let units = Units::with_elevation(&paths, &fake, Elevation::none());

    for quadlet in [
        "acme-cage.container",
        "acme-net.network",
        "acme-certs.volume",
    ] {
        assert_eq!(units.unit_dir_for(quadlet), paths.quadlet_dir());
    }
    assert_eq!(
        units.unit_dir_for("acme-watcher.service"),
        paths.user_unit_dir()
    );
    assert_eq!(fake.call_count(), 0);
}

// ─────────────────────────────────────────────────────────
// the host with no systemd
// ─────────────────────────────────────────────────────────

#[test]
fn without_systemd_nothing_is_spawned_and_the_files_still_land() {
    // macOS has no `systemctl`, and a container-backed cage created on
    // Linux can still be cleaned up from a Mac. `install_units` writes
    // unconditionally; it is `daemon_reload` that no-ops. The probe is
    // `shutil.which`, which is why `FakeRunner::stub_missing` can
    // reach this branch from a Linux CI runner — the only way it is
    // covered at all.
    let (_dir, paths) = sandbox("systemd-absent");
    fs::create_dir_all(paths.quadlet_dir()).unwrap();
    fs::write(paths.quadlet_dir().join("acme-cage.container"), "old").unwrap();

    let fake = FakeRunner::new();
    fake.stub_missing("systemctl");
    let units = Units::with_elevation(&paths, &fake, Elevation::none());

    assert!(!units.available());
    let installed = units
        .install([("acme-cage.container", "[Container]\n")])
        .unwrap();
    assert!(!installed.reloaded);
    assert_eq!(
        fs::read_to_string(paths.quadlet_dir().join("acme-cage.container")).unwrap(),
        "[Container]\n"
    );

    assert_eq!(
        units.remove_quadlets("acme").unwrap(),
        ["acme-cage.container"]
    );
    assert!(!paths.quadlet_dir().join("acme-cage.container").exists());

    assert!(!units.daemon_reload().unwrap());
    assert!(!units.start("acme-cage.service").unwrap());
    assert!(!units.stop("acme-cage.service").unwrap());
    assert!(!units.restart("acme-cage.service").unwrap());
    assert!(!units.enable("acme-watcher.service").unwrap());
    assert!(!units.disable("acme-watcher.service").unwrap());

    assert_eq!(
        fake.call_count(),
        0,
        "something reached a missing systemctl"
    );
    // And the decision was made by a `which` lookup, not by trying.
    assert!(fake.which_lookups().iter().any(|p| p == "systemctl"));
}

// ─────────────────────────────────────────────────────────
// the sequences a backend actually issues
// ─────────────────────────────────────────────────────────

#[test]
fn a_container_backend_start_restarts_the_substrate_then_starts_the_cage() {
    // `backends/container.py::start` in argv. The network and the two
    // cert volumes are *restarted* rather than started, because
    // systemd may still consider them active from a previous run even
    // though `cage destroy` removed the podman resources underneath.
    // Only then is the cage unit started.
    let (_dir, paths) = sandbox("systemd-start-sequence");
    fs::create_dir_all(paths.quadlet_dir()).unwrap();
    let fake = FakeRunner::new();
    fake.assume_installed();
    for _ in 0..4 {
        fake.push(Reply::status(0));
    }
    let units = Units::with_elevation(&paths, &fake, Elevation::none());

    for unit in [
        "acme-net-network.service",
        "acme-certs-volume.service",
        "acme-public-certs-volume.service",
    ] {
        units.restart(unit).unwrap();
    }
    assert!(!units.has_podman_storage_volume("acme"));
    units.start("acme-cage.service").unwrap();

    fake.assert_argv(&[
        &["systemctl", "--user", "restart", "acme-net-network.service"],
        &[
            "systemctl",
            "--user",
            "restart",
            "acme-certs-volume.service",
        ],
        &[
            "systemctl",
            "--user",
            "restart",
            "acme-public-certs-volume.service",
        ],
        &["systemctl", "--user", "start", "acme-cage.service"],
    ]);
    fake.assert_drained();
}

#[test]
fn a_nested_container_cage_adds_the_storage_volume_to_that_sequence() {
    let (_dir, paths) = sandbox("systemd-start-nested");
    fs::create_dir_all(paths.quadlet_dir()).unwrap();
    fs::write(
        paths.quadlet_dir().join("acme-podman-storage.volume"),
        "[Volume]\n",
    )
    .unwrap();
    let fake = FakeRunner::new();
    fake.assume_installed();
    for _ in 0..2 {
        fake.push(Reply::status(0));
    }
    let units = Units::with_elevation(&paths, &fake, Elevation::none());

    assert!(units.has_podman_storage_volume("acme"));
    units.restart("acme-podman-storage-volume.service").unwrap();
    units.start("acme-cage.service").unwrap();

    fake.assert_argv(&[
        &[
            "systemctl",
            "--user",
            "restart",
            "acme-podman-storage-volume.service",
        ],
        &["systemctl", "--user", "start", "acme-cage.service"],
    ]);
    fake.assert_drained();
}

#[test]
fn a_stop_walks_the_services_and_keeps_going_past_a_failure() {
    // `backends/container.py::stop` wraps each `systemd.stop_unit` in
    // its own `try`, printing a warning and carrying on: a cage whose
    // egress already died must still have its workload stopped.
    let (_dir, paths) = sandbox("systemd-stop");
    let fake = FakeRunner::new();
    fake.assume_installed()
        .push(Reply::status(0))
        .push(Reply::failed(5, "Unit acme-egress.service not loaded."))
        .push(Reply::status(0));
    let units = Units::with_elevation(&paths, &fake, Elevation::none());

    let mut warnings = Vec::new();
    for service in ["cage", "egress", "dns"] {
        if let Err(error) = units.stop(&format!("acme-{service}.service")) {
            warnings.push(error.to_string());
        }
    }

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("not loaded"), "{warnings:?}");
    fake.assert_argv(&[
        &["systemctl", "--user", "stop", "acme-cage.service"],
        &["systemctl", "--user", "stop", "acme-egress.service"],
        &["systemctl", "--user", "stop", "acme-dns.service"],
    ]);
    fake.assert_drained();
}
