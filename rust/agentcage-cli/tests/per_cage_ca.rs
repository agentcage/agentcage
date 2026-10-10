//! A new CA per cage (`EGRESS-PORT-PLAN.md` D11), on every backend.
//!
//! The egress generates its CA on first start into a store that belongs
//! to one cage: the `agentcage-certs-<name>` podman volume (on the host
//! for `container`, in the cage's own Lima guest for `vm`), or
//! `<apple_root>/<name>/certs` on `apple-container`. It generates one
//! only into an *empty* store, so the guarantee is entirely about that
//! store's lifetime:
//!
//! * `cage create` / `run` / `cage restore` under a name with no
//!   deployment purge whatever store an earlier cage of that name left
//!   behind, and refuse to go ahead when they cannot;
//! * `cage destroy` reports a certs volume it could not remove instead
//!   of reporting success over it.
//!
//! Two more guards keep a store from being *reached* from outside its
//! cage, and are tested where they live: validation refuses a
//! `named_volumes` key (or bare `volumes` source) in agentcage's own
//! volume namespace (`agentcage_core::quadlets::reserved_volume`, the
//! `err-named-volume-reserved` / `err-volume-reserved-source` golden
//! cases), and `cage restore` refuses an archive carrying such a volume
//! and imports only what the manifest lists (`cli::cage::backup`).
//!
//! The e2e half — two cages, two fingerprints; destroy + create, a new
//! fingerprint — is in `tests/e2e/phase1_lifecycle.sh` and
//! `phase5_backup.sh`.

use std::fs;

use agentcage_cli::apple::backend::AppleBackend;
use agentcage_cli::backend::ContainerBackend;
use agentcage_cli::backends::AnyBackend;
use agentcage_cli::vm::VmBackend;
use agentcage_exec::{Elevation, FakeRunner, Reply};
use agentcage_state::{Paths, TestDir};

fn container<'a>(paths: &'a Paths, fake: &'a FakeRunner) -> ContainerBackend<'a> {
    ContainerBackend::with_elevation(paths, fake, "9.9.9", Elevation::none())
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

// ── container: create ──────────────────────────────────────────

/// Both certs volumes left by an earlier `acme` are removed, and
/// reported, before the new `acme` is deployed.
#[test]
fn a_leftover_ca_volume_is_purged_before_a_container_create() {
    let dir = TestDir::new("ca-purge-container");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push_all([
        Reply::success(), // volume exists agentcage-certs-acme
        Reply::success(), // volume rm agentcage-certs-acme
        Reply::success(), // volume exists agentcage-public-certs-acme
        Reply::success(), // volume rm agentcage-public-certs-acme
    ]);

    let removed = container(&paths, &fake)
        .purge_stale_ca("acme")
        .expect("purged");

    assert_eq!(
        removed,
        [
            "volume:agentcage-certs-acme",
            "volume:agentcage-public-certs-acme"
        ]
    );
    fake.assert_argv(&[
        &["podman", "volume", "exists", "agentcage-certs-acme"],
        &["podman", "volume", "rm", "agentcage-certs-acme"],
        &["podman", "volume", "exists", "agentcage-public-certs-acme"],
        &["podman", "volume", "rm", "agentcage-public-certs-acme"],
    ]);
}

/// The common case: nothing left over, nothing removed, nothing said.
#[test]
fn a_clean_name_purges_nothing() {
    let dir = TestDir::new("ca-purge-clean");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push_all([Reply::status(1), Reply::status(1)]);

    let removed = container(&paths, &fake)
        .purge_stale_ca("acme")
        .expect("nothing to purge");

    assert!(removed.is_empty(), "{removed:?}");
    fake.assert_argv(&[
        &["podman", "volume", "exists", "agentcage-certs-acme"],
        &["podman", "volume", "exists", "agentcage-public-certs-acme"],
    ]);
}

/// A leftover that will not go is a refusal, not a warning: the create
/// would otherwise hand the old CA to the new cage.
#[test]
fn a_leftover_ca_volume_that_cannot_be_removed_refuses_the_create() {
    let dir = TestDir::new("ca-purge-stuck");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push_all([
        Reply::success(),
        Reply::failed(
            2,
            "Error: volume is being used by the following container(s)",
        ),
    ]);

    let error = container(&paths, &fake)
        .purge_stale_ca("acme")
        .expect_err("refused");

    let message = error.to_string();
    assert!(message.contains("agentcage-certs-acme"), "{message}");
    assert!(
        message.contains("podman volume rm agentcage-certs-acme"),
        "{message}"
    );
    assert!(message.contains("agentcage cage destroy acme"), "{message}");
    // Nothing after the refusal: the public volume is not even probed.
    assert_eq!(fake.call_count(), 2);
}

// ── container: destroy ─────────────────────────────────────────

/// A volume `rm` that failed because the volume is *gone* is not news.
#[test]
fn a_volume_that_is_already_gone_is_not_reported() {
    let dir = TestDir::new("ca-destroy-gone");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push_all([Reply::status(1), Reply::status(1)]);

    assert_eq!(
        container(&paths, &fake).remove_volume("agentcage-certs-acme"),
        Ok(false)
    );
}

/// A volume `rm` that failed with the volume still *there* is reported,
/// naming the volume and the command that removes it by hand.
#[test]
fn a_volume_that_survived_its_rm_is_reported() {
    let dir = TestDir::new("ca-destroy-stuck");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push_all([Reply::failed(2, "Error: volume in use"), Reply::success()]);

    let warning = container(&paths, &fake)
        .remove_volume("agentcage-certs-acme")
        .expect_err("reported");

    assert!(
        warning.contains("podman volume rm agentcage-certs-acme"),
        "{warning}"
    );
    fake.assert_argv(&[
        &["podman", "volume", "rm", "agentcage-certs-acme"],
        &["podman", "volume", "exists", "agentcage-certs-acme"],
    ]);
}

/// `cage destroy` asks again after a failed `rm` — it used to read
/// every failure as "nothing to remove" and report success over a
/// certs volume that was still there — and keeps going: the other
/// volumes and the secrets are still removed.
#[test]
fn destroy_asks_after_a_failed_certs_volume_removal_and_carries_on() {
    let dir = TestDir::new("ca-destroy-sequence");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.on(
        ["podman", "volume", "rm", "agentcage-certs-acme"],
        Reply::failed(2, "Error: volume in use"),
    );
    fake.on(
        ["podman", "volume", "exists", "agentcage-certs-acme"],
        Reply::success(),
    );
    fake.on(["podman", "secret", "ls"], Reply::ok("acme.TOKEN\n"));
    fake.default_reply(Reply::success());

    let removed = container(&paths, &fake)
        .destroy_resources("acme", false)
        .expect("destroy carries on");

    assert_eq!(
        removed,
        [
            "network:acme-net",
            "volume:agentcage-public-certs-acme",
            "volume:agentcage-podman-acme",
            "secret:acme.TOKEN",
        ]
    );
    let sequence = fake.argv_sequence();
    let rm = sequence
        .iter()
        .position(|call| *call == argv(&["podman", "volume", "rm", "agentcage-certs-acme"]))
        .expect("the certs volume rm");
    assert_eq!(
        sequence[rm + 1],
        argv(&["podman", "volume", "exists", "agentcage-certs-acme"]),
        "{sequence:?}"
    );
}

// ── vm ─────────────────────────────────────────────────────────

/// A vm cage's CA is in its guest, and a guest with no deployment is a
/// leftover: it goes as a whole, so `start` provisions a fresh one.
#[test]
fn a_leftover_lima_guest_is_deleted_before_a_vm_create() {
    let dir = TestDir::new("ca-purge-vm");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.on(["limactl", "list"], Reply::ok(r#"{"status":"Stopped"}"#));
    fake.on(["limactl", "delete"], Reply::success());

    let removed = VmBackend::new(&paths, &fake, "9.9.9")
        .purge_stale_ca("acme")
        .expect("purged");

    assert_eq!(removed, ["lima-instance:agentcage-acme"]);
    fake.assert_argv(&[
        &["limactl", "list", "--json", "agentcage-acme"],
        &["limactl", "delete", "--force", "agentcage-acme"],
    ]);
}

/// No guest, nothing to delete.
#[test]
fn no_lima_guest_purges_nothing() {
    let dir = TestDir::new("ca-purge-vm-clean");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.on(
        ["limactl", "list"],
        Reply::failed(1, "instance does not exist"),
    );

    let removed = VmBackend::new(&paths, &fake, "9.9.9")
        .purge_stale_ca("acme")
        .expect("nothing to purge");

    assert!(removed.is_empty(), "{removed:?}");
    fake.assert_argv(&[&["limactl", "list", "--json", "agentcage-acme"]]);
}

/// A leftover guest that will not delete refuses the create.
#[test]
fn a_leftover_lima_guest_that_cannot_be_deleted_refuses_the_create() {
    let dir = TestDir::new("ca-purge-vm-stuck");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.on(["limactl", "list"], Reply::ok(r#"{"status":"Running"}"#));
    fake.on(["limactl", "delete"], Reply::failed(1, "permission denied"));

    let error = VmBackend::new(&paths, &fake, "9.9.9")
        .purge_stale_ca("acme")
        .expect_err("refused");

    let message = error.to_string();
    assert!(
        message.contains("limactl delete --force agentcage-acme"),
        "{message}"
    );
}

// ── apple-container ────────────────────────────────────────────

/// The two certs directories go; the rest of the state tree is the
/// deploy's to rewrite and is left alone.
#[test]
fn leftover_apple_certs_dirs_are_purged_before_an_apple_create() {
    let dir = TestDir::new("ca-purge-apple");
    let paths = Paths::under(dir.path());
    let certs = paths.apple_certs_dir("acme");
    let public_certs = paths.apple_public_certs_dir("acme");
    let logs = paths.apple_logs_dir("acme");
    for path in [&certs, &public_certs, &logs] {
        fs::create_dir_all(path).expect("dir");
    }
    fs::write(certs.join("ca-key.pem"), "not a real key\n").expect("key");
    fs::write(public_certs.join("ca-cert.pem"), "not a real cert\n").expect("cert");
    let fake = FakeRunner::new();
    fake.assume_missing();

    let removed = AppleBackend::new(&paths, &fake, "9.9.9")
        .purge_stale_ca("acme")
        .expect("purged");

    assert_eq!(
        removed,
        [
            format!("certs:{}", certs.display()),
            format!("certs:{}", public_certs.display()),
        ]
    );
    assert!(!certs.exists());
    assert!(!public_certs.exists());
    assert!(logs.is_dir(), "the rest of the state tree went too");
    assert_eq!(fake.call_count(), 0);
}

/// Every backend is reachable through the dispatch `cage create`,
/// `run` and `cage restore` call.
#[test]
fn the_dispatch_reaches_each_backends_purge() {
    let dir = TestDir::new("ca-purge-dispatch");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.on(["podman", "volume", "exists"], Reply::status(1));
    fake.on(["limactl", "list"], Reply::failed(1, "no such instance"));

    for isolation in ["container", "vm", "apple-container"] {
        let removed = AnyBackend::new(isolation, &paths, &fake, "9.9.9")
            .purge_stale_ca("acme")
            .expect("nothing to purge");
        assert!(removed.is_empty(), "{isolation}: {removed:?}");
    }
    let programs: Vec<String> = fake
        .argv_sequence()
        .into_iter()
        .map(|call| call[0].clone())
        .collect();
    assert_eq!(programs, ["podman", "podman", "limactl"]);
}
