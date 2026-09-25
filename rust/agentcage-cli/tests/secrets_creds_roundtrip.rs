//! A real `systemd-creds` round trip, behind the availability probe
//! that e2e phase 3 already uses.
//!
//! Every other test in this PR drives [`agentcage_exec::FakeRunner`],
//! which proves the argv and nothing about whether `systemd-creds`
//! accepts it. This one runs the actual binary: encrypt a value through
//! [`SecretHost::encrypt_secret`], then decrypt the blob back with
//! `systemd-creds decrypt` and compare. If the argv were wrong in a way
//! a fake cannot see -- a missing `-`, an output path in the wrong
//! position, a `--user` that belongs after `encrypt` -- this is the test
//! that notices.
//!
//! # The probe, and why it is that shape
//!
//! `tests/e2e/phase3_secrets.sh:378` gates its systemd-creds case on
//!
//! ```sh
//! command -v systemd-creds && echo probe | systemd-creds encrypt --name _probe - -
//! ```
//!
//! and this reuses it rather than inventing a second opinion about what
//! "available" means. The Rust spelling of it is
//! [`SecretHost::default_backend`], which is that probe plus the
//! systemd-version floor -- and which is also the function production
//! uses, so a host where this test skips is a host where agentcage
//! would refuse to use the backend anyway.
//!
//! Two differences from the shell, both deliberate. The probe here runs
//! in *both* scopes and takes whichever works, because the shell's
//! system-scope probe is exactly what fails on a workstation with an
//! active graphical session -- polkit routes an interactive
//! authentication request to the desktop and the probe returns
//! `io.systemd.InteractiveAuthenticationRequired`. And a host that
//! cannot encrypt **skips**, loudly, rather than failing: CI containers
//! have no TPM, no host key and often no session bus, and a test that
//! failed there would be turned off rather than fixed.
//!
//! # What this does *not* do
//!
//! It does not touch PR A7's committed `.cred` fixture. That blob was
//! encrypted on a machine none of us has, with a key bound to it, and
//! no amount of correct argv will decrypt it here.
//! `tests/secrets_state_fixtures.rs` asserts its presence and shape and
//! stops there; this test makes its own blob so it has something it can
//! legitimately read back.

mod common;

use agentcage_cli::secrets::{Backend, MapEnv, SecretHost};
use agentcage_exec::tools::creds::Scope;
use agentcage_exec::{Command, CommandRunner, SystemRunner};

use common::TempDir;

/// The plaintext. Not a credential, and shaped like A7's fixtures so a
/// stray copy in a log is obviously a test artifact.
const PLAINTEXT: &str = "TEST-NOT-A-REAL-SECRET-0042";

/// The value `systemd-creds encrypt --name` binds the blob to. A blob
/// decrypted under a different name is refused, which is half of what
/// makes `--name` worth asserting.
const NAME: &str = "ROUNDTRIP_KEY";

#[test]
fn a_real_systemd_creds_blob_decrypts_back_to_its_plaintext() {
    let runner = SystemRunner::new();
    let env = MapEnv::new();
    let host = SecretHost::detect(&runner, &env);

    if host.default_backend() != Backend::SystemdCreds {
        eprintln!(
            "skipping: systemd-creds cannot encrypt on this host \
             (the same probe `phase3_secrets.sh:378` uses). Nothing to \
             round-trip against."
        );
        return;
    }
    let scope = host
        .default_scope()
        .expect("default_backend said systemd-creds, so a scope works");

    let temp = TempDir::new("roundtrip");
    let path = host
        .encrypt_secret(NAME, PLAINTEXT, temp.path(), scope)
        .expect("encrypt");

    // The path the Python returns, and the one the quadlet's
    // `LoadCredentialEncrypted` is generated against.
    assert_eq!(path, temp.path().join("creds").join("ROUNDTRIP_KEY.cred"));

    let blob = std::fs::read(&path).expect("the blob");
    assert!(blob.len() > 64, "{} bytes", blob.len());
    assert!(
        blob.iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\n')),
        "base64 armor, the same shape A7's fixture has"
    );
    assert!(
        !String::from_utf8_lossy(&blob).contains(PLAINTEXT),
        "the blob is not the plaintext with extra steps"
    );

    // ...and back. `--name` has to match what encryption bound it to.
    let mut decrypt = Command::new("systemd-creds");
    if let Some(flag) = scope.flag() {
        decrypt = decrypt.arg(flag);
    }
    let out = runner
        .run(
            &decrypt
                .args(["decrypt", "--name", NAME, &path.to_string_lossy(), "-"])
                .captured(),
        )
        .expect("systemd-creds decrypt ran");
    assert!(
        out.success(),
        "decrypt failed: {}",
        out.stderr_text().trim()
    );
    assert_eq!(out.stdout_text(), PLAINTEXT);

    eprintln!("round trip ran in {} scope", scope.as_str());
}

/// The scope the auto-detection picked really is one that works, and
/// the other one may or may not -- which is the whole reason
/// `secrets.scope: auto` exists.
#[test]
fn the_detected_scope_is_one_that_actually_encrypts() {
    let runner = SystemRunner::new();
    let env = MapEnv::new();
    let host = SecretHost::detect(&runner, &env);

    let Some(scope) = host.default_scope() else {
        eprintln!("skipping: neither scope encrypts on this host");
        return;
    };

    let temp = TempDir::new("scope-probe");
    host.encrypt_secret("SCOPE_PROBE", PLAINTEXT, temp.path(), scope)
        .expect("the detected scope encrypts");

    // A non-root invoker prefers `user`, because the host key routes a
    // polkit prompt to a desktop nobody is watching.
    if !nix::unistd::Uid::effective().is_root() {
        assert!(
            scope == Scope::User || !host_scope_works(runner),
            "a non-root invoker should land on `user` unless only \
             `system` works"
        );
    }
}

/// Whether the *system* scope encrypts here, asked directly.
fn host_scope_works(runner: SystemRunner) -> bool {
    runner
        .run(
            &Command::new("systemd-creds")
                .args(["encrypt", "--name", "_probe", "-", "-"])
                .stdin_text("probe")
                .captured(),
        )
        .is_ok_and(|out| out.success())
}
