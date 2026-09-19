//! A secret value cannot reach a debug dump, a log line or a panic
//! message.
//!
//! The other tests in this PR assert where a value *goes*. This one
//! asserts where it cannot go, which is a different and more slippery
//! property: argv can be got right and still leak the value through a
//! `{:?}` in an error path, an `unwrap()` on a failing assertion, or a
//! recorded-call dump printed by a test that failed for an unrelated
//! reason. CI logs are readable, and a credential that reaches one is
//! disclosed.
//!
//! Three surfaces, all of them exercised here with a value that is
//! [`CANARY`]:
//!
//! 1. **`Debug` and `Display`** of every type this PR defines or hands a
//!    secret to.
//! 2. **Error messages**, on every failure path a secret-carrying call
//!    has.
//! 3. **Panic payloads**, including the one from a failing
//!    [`FakeRunner::assert_argv`] -- the single most likely way for a
//!    credential to end up in a CI transcript, because it prints every
//!    recorded call.

mod common;

use std::panic::AssertUnwindSafe;
use std::path::Path;

use agentcage_cli::secrets::{
    ApplePlaintextStore, KeychainStore, MapEnv, PlaintextStore, Platform, SecretHost, SecretStore,
    SystemdCredsStore,
};
use agentcage_exec::tools::podman::Podman;
use agentcage_exec::{CommandRunner, FakeRunner, Reply};

use common::TempDir;

/// The one string that must never appear in any rendered text.
///
/// Distinctive on purpose: if it does show up in a CI log, grepping for
/// it finds this file and the leak in one step.
const CANARY: &str = "CANARY-97f3c1a2-do-not-print";

/// Fail with the rendered text when it contains [`CANARY`].
#[track_caller]
fn no_canary(what: &str, rendered: &str) {
    assert!(
        !rendered.contains(CANARY),
        "{what} leaked the value:\n{rendered}"
    );
}

/// Every place a store or the resolver can print itself.
#[test]
fn no_type_in_this_module_prints_a_value() {
    let temp = TempDir::new("redact-debug");
    let fake = FakeRunner::new();
    fake.on(["security"], Reply::success());
    // More specific first: rules are matched in registration order.
    fake.on(["podman", "secret", "inspect"], Reply::status(1));
    fake.on(["podman"], Reply::success());
    fake.on(["systemd-creds"], Reply::success());
    fake.stub_which("systemd-creds", "/usr/bin/systemd-creds");
    fake.on(["systemctl"], Reply::ok("systemd 256 (256)\n"));

    let env = MapEnv::new().with("HOST_VAR", CANARY);
    let host = SecretHost::new(&fake, &env, true);
    let podman = Podman::new(&fake);

    no_canary("MapEnv", &format!("{env:?}"));
    no_canary("SecretHost", &format!("{host:?}"));

    let resolution = host.resolve("env:HOST_VAR", "K", Path::new("/x")).unwrap();
    assert_eq!(resolution.value(), Some(CANARY), "the value did arrive");
    no_canary("Resolution", &format!("{resolution:?}"));

    let creds = SystemdCredsStore::new(&host, "user", Some(&podman));
    creds.set("acme", "K", CANARY, temp.path()).unwrap();
    no_canary("SystemdCredsStore", &format!("{creds:?}"));

    let plaintext = PlaintextStore::new(Some(&podman));
    plaintext
        .set("acme", "K", CANARY, Path::new("/unused"))
        .unwrap();
    no_canary("PlaintextStore", &format!("{plaintext:?}"));

    let keychain = KeychainStore::new(&fake, Platform::MacOs);
    keychain.set("acme", "K", CANARY, temp.path()).unwrap();
    no_canary("KeychainStore", &format!("{keychain:?}"));

    let apple = ApplePlaintextStore;
    apple.set("acme", "K", CANARY, temp.path()).unwrap();
    no_canary("ApplePlaintextStore", &format!("{apple:?}"));

    // And the recorded calls, which is what a failure would print.
    no_canary("FakeRunner", &format!("{:?}", fake.calls()));
    no_canary("argv_sequence", &format!("{:?}", fake.argv_sequence()));
    for call in fake.calls() {
        no_canary("RecordedCall", &format!("{call:?}"));
        no_canary("Command Display", &call.command.display());
        no_canary("Command Debug", &format!("{:?}", call.command));
    }

    // The value really was delivered to all four stores, so the
    // assertions above are about redaction and not about a value that
    // never existed.
    assert_eq!(
        apple.get("acme", "K", temp.path()).unwrap().as_deref(),
        Some(CANARY)
    );
    let keychain_add = fake
        .calls()
        .into_iter()
        .find(|c| c.raw_argv().contains(&"acme.K".to_string()) && c.command.program() == "security")
        .expect("the keychain add");
    assert!(keychain_add.raw_argv().contains(&CANARY.to_string()));
}

/// Every error a secret-carrying call can produce, rendered both ways.
#[test]
fn no_error_message_carries_a_value() {
    let temp = TempDir::new("redact-errors");
    let env = MapEnv::new().with("HOST_VAR", CANARY);

    // A `systemd-creds encrypt` that fails, times out, and cannot run.
    for reply in [
        Reply::failed(1, "Failed to encrypt: no key"),
        Reply::TimedOut,
        Reply::NotFound,
    ] {
        let fake = FakeRunner::new();
        fake.on(["systemd-creds"], reply);
        let host = SecretHost::new(&fake, &env, true);
        let store = SystemdCredsStore::new(&host, "system", None);
        let err = store.set("acme", "K", CANARY, temp.path()).unwrap_err();
        no_canary("encrypt error Display", &err.to_string());
        no_canary("encrypt error Debug", &format!("{err:?}"));
    }

    // A `podman secret create` that fails.
    let fake = FakeRunner::new();
    fake.on(["podman", "secret", "inspect"], Reply::status(1));
    fake.on(
        ["podman", "secret", "create"],
        Reply::failed(125, "Error: secret already exists"),
    );
    let podman = Podman::new(&fake);
    let err = PlaintextStore::new(Some(&podman))
        .set("acme", "K", CANARY, Path::new("/unused"))
        .unwrap_err();
    no_canary("podman error", &err.to_string());

    // A `security add-generic-password` that fails. This is the one
    // path where the value really is in argv, so the error `security`
    // produced is the likeliest place for it to come back out.
    let fake = FakeRunner::new();
    fake.on(["security", "delete-generic-password"], Reply::success());
    fake.on(
        [
            "security",
            "add-generic-password",
            "-s",
            "agentcage",
            "-a",
            "acme.K",
        ],
        Reply::failed(
            45,
            "SecKeychainItemCreateFromContent: write permissions error",
        ),
    );
    fake.on(["security", "add-generic-password"], Reply::success());
    let err = KeychainStore::new(&fake, Platform::MacOs)
        .set("acme", "K", CANARY, temp.path())
        .unwrap_err();
    no_canary("keychain error Display", &err.to_string());
    no_canary("keychain error Debug", &format!("{err:?}"));
    assert!(err.to_string().starts_with("keychain add failed:"));

    // A `cmd:` source that fails. Its stderr *is* interpolated -- the
    // Python does it and the port keeps it -- so the canary here is in
    // the command's output, which is not a value agentcage resolved.
    let fake = FakeRunner::new();
    fake.push(Reply::failed(2, "pass: no such entry"));
    let host = SecretHost::new(&fake, &env, true);
    let err = host
        .resolve("cmd:pass show nope", "K", Path::new("/x"))
        .unwrap_err();
    no_canary("cmd error", &err.to_string());

    // A file that cannot be written.
    let err = ApplePlaintextStore
        .set(
            "acme",
            "K",
            CANARY,
            Path::new("/proc/definitely/not/writable"),
        )
        .unwrap_err();
    no_canary("io error Display", &err.to_string());
    no_canary("io error Debug", &format!("{err:?}"));
}

/// The panic a failing argv assertion produces.
///
/// `FakeRunner::assert_argv` prints every recorded call when it fails,
/// which is the behaviour that makes it useful -- and would make it a
/// credential channel if the dump were not redacted. So: run a keychain
/// `set`, whose argv genuinely holds the cleartext, then assert a wrong
/// argv on purpose and read the panic payload.
#[test]
fn a_failing_argv_assertion_does_not_print_the_value() {
    let temp = TempDir::new("redact-panic");
    let fake = FakeRunner::new();
    fake.on(["security"], Reply::success());
    fake.on(["systemd-creds"], Reply::success());
    fake.on(["podman", "secret", "inspect"], Reply::status(1));
    fake.on(["podman"], Reply::success());

    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    KeychainStore::new(&fake, Platform::MacOs)
        .set("acme", "K", CANARY, temp.path())
        .unwrap();
    SystemdCredsStore::new(&host, "user", None)
        .set("acme", "K", CANARY, temp.path())
        .unwrap();

    // Silence the default hook for the duration: the payload is what is
    // under test, and letting it print would put the very transcript
    // noise this test exists to prevent into the test output.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let payload = std::panic::catch_unwind(AssertUnwindSafe(|| {
        fake.assert_argv(&[&["something", "else", "entirely"]]);
    }))
    .expect_err("the assertion should have failed");
    let unexpected = std::panic::catch_unwind(AssertUnwindSafe(|| {
        // An unstubbed call panics with the argv of the call it did not
        // expect -- the other dump-shaped panic in the fake.
        let bare = FakeRunner::new();
        let _ = bare.run(&agentcage_exec::Command::new("security").secret_arg(CANARY));
    }))
    .expect_err("the unstubbed call should have panicked");
    std::panic::set_hook(previous);

    for (what, payload) in [("assert_argv", payload), ("unstubbed call", unexpected)] {
        let text = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .expect("a string panic payload");
        assert!(text.contains("FakeRunner"), "{what}: {text}");
        no_canary(what, &text);
    }
}
