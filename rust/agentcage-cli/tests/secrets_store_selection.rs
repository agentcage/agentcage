//! `resolve_store` -- which backend a given `cage.yaml` gets, and where
//! it refuses.
//!
//! The Python half is `tests/test_secret_store.py`; every case there is
//! here, plus the three that surprised the port and are asserted so the
//! next reader does not have to rediscover them:
//!
//! * an explicit `source: systemd-creds:` builds the store **without
//!   checking that it works**, so the refusal arrives from `set` rather
//!   than from resolution;
//! * the macOS-vm host-keychain rule applies to `auto` only, so an
//!   explicit `backend: systemd-creds` on a Mac vm cage still refuses;
//! * two different types answer `name() == "plaintext"`, and the only
//!   thing that tells them apart is `runtime_decrypts`.

mod common;

use agentcage_cli::secrets::{MapEnv, Platform, SecretHost, SecretStore, resolve_store};
use agentcage_core::config::types::Config;
use agentcage_exec::tools::podman::Podman;
use agentcage_exec::{FakeRunner, Reply};

/// A fake where `systemd-creds` works: installed, new enough, and the
/// per-user key encrypts.
fn creds_available() -> FakeRunner {
    let fake = FakeRunner::new();
    fake.stub_which("systemd-creds", "/usr/bin/systemd-creds");
    fake.on(
        ["systemctl", "--version"],
        Reply::ok("systemd 256 (256.11)\n"),
    );
    fake.on(["systemd-creds"], Reply::success());
    fake
}

/// A fake where it does not: the binary is not installed.
fn creds_missing() -> FakeRunner {
    let fake = FakeRunner::new();
    fake.stub_missing("systemd-creds");
    fake
}

/// `(name, runtime_decrypts)` -- enough to name any of the four stores,
/// since `PlaintextStore` and `ApplePlaintextStore` share a name.
fn identify(store: &dyn SecretStore) -> (&'static str, bool) {
    (store.name(), store.runtime_decrypts())
}

const SYSTEMD_CREDS: (&str, bool) = ("systemd-creds", true);
const PODMAN_PLAINTEXT: (&str, bool) = ("plaintext", true);
const FILE_PLAINTEXT: (&str, bool) = ("plaintext", false);
const KEYCHAIN: (&str, bool) = ("keychain", false);

/// Resolve a store and describe it, with a podman available.
fn choose(
    fake: &FakeRunner,
    cfg: &Config,
    source_scheme: &str,
    platform: Platform,
) -> Result<(&'static str, bool), String> {
    let env = MapEnv::new();
    let host = SecretHost::new(fake, &env, true);
    let podman = Podman::new(fake);
    resolve_store(cfg, &host, Some(&podman), source_scheme, platform)
        .map(|store| identify(store.as_ref()))
        .map_err(|e| e.to_string())
}

#[test]
fn an_explicit_systemd_creds_backend_needs_it_to_work() {
    let cfg = common::config("container", "systemd-creds", "auto", false);
    assert_eq!(
        choose(&creds_available(), &cfg, "", Platform::Other),
        Ok(SYSTEMD_CREDS)
    );
    assert_eq!(
        choose(&creds_missing(), &cfg, "", Platform::Other),
        Err(
            "secrets.backend is 'systemd-creds' but systemd-creds encryption \
             is not usable on this host"
                .to_string()
        )
    );
}

#[test]
fn an_explicit_plaintext_backend_is_taken_at_its_word() {
    let cfg = common::config("container", "plaintext", "auto", false);
    assert_eq!(
        choose(&creds_missing(), &cfg, "", Platform::Other),
        Ok(PODMAN_PLAINTEXT)
    );
    // ...even where an encrypting backend was available.
    assert_eq!(
        choose(&creds_available(), &cfg, "", Platform::Other),
        Ok(PODMAN_PLAINTEXT)
    );
}

#[test]
fn the_keychain_backend_is_refused_off_macos() {
    let cfg = common::config("container", "keychain", "auto", false);
    assert_eq!(
        choose(&creds_available(), &cfg, "", Platform::Other),
        Err(
            "secrets.backend 'keychain' requires macOS with an unlocked login \
             keychain or passwordless sudo for the System keychain"
                .to_string()
        )
    );
}

#[test]
fn auto_prefers_the_encrypting_backend() {
    let cfg = common::config("container", "auto", "auto", false);
    assert_eq!(
        choose(&creds_available(), &cfg, "", Platform::Other),
        Ok(SYSTEMD_CREDS)
    );
}

/// The whole point of the resolver: no encrypting backend and no
/// opt-in means a refusal, never a quiet cleartext write.
#[test]
fn auto_fails_closed_without_an_encrypting_backend() {
    let cfg = common::config("container", "auto", "auto", false);
    assert_eq!(
        choose(&creds_missing(), &cfg, "", Platform::Other),
        Err("no encrypting secret backend is available and \
             secrets.allow_plaintext is not set"
            .to_string())
    );
}

#[test]
fn auto_accepts_cleartext_only_when_the_operator_opted_in() {
    let cfg = common::config("container", "auto", "auto", true);
    assert_eq!(
        choose(&creds_missing(), &cfg, "", Platform::Other),
        Ok(PODMAN_PLAINTEXT)
    );
}

/// An empty `secrets.backend` is `auto`, which is how a config built by
/// hand rather than by the parser behaves.
#[test]
fn an_empty_backend_string_means_auto() {
    let cfg = common::config("container", "", "auto", false);
    assert_eq!(
        choose(&creds_available(), &cfg, "", Platform::Other),
        Ok(SYSTEMD_CREDS)
    );
}

#[test]
fn a_per_rule_podman_source_overrides_the_configured_backend() {
    let cfg = common::config("container", "systemd-creds", "auto", false);
    assert_eq!(
        choose(&creds_available(), &cfg, "podman", Platform::Other),
        Ok(PODMAN_PLAINTEXT)
    );
}

/// **Surprise 1.** `source: systemd-creds:` builds the store without
/// asking whether it works, unlike `backend: systemd-creds`, which
/// checks. So the same broken host refuses one and accepts the other --
/// and the second one fails later, from `set`, with the scope error
/// rather than the backend error.
#[test]
fn a_per_rule_systemd_creds_source_skips_the_availability_check() {
    let cfg = common::config("container", "plaintext", "auto", false);
    assert_eq!(
        choose(&creds_missing(), &cfg, "systemd-creds", Platform::Other),
        Ok(SYSTEMD_CREDS)
    );
}

/// apple-container's cleartext store is the file, not podman: a Mac has
/// no host podman for a `podman:` source to reach.
#[test]
fn apple_container_gets_the_file_backed_plaintext_store() {
    let cfg = common::config("apple-container", "plaintext", "auto", false);
    assert_eq!(
        choose(&creds_missing(), &cfg, "", Platform::MacOs),
        Ok(FILE_PLAINTEXT)
    );
    // ...including through an explicit `podman:` source, which on this
    // isolation backend means the file rather than podman.
    assert_eq!(
        choose(&creds_missing(), &cfg, "podman", Platform::MacOs),
        Ok(FILE_PLAINTEXT)
    );
}

/// A `vm` cage on a macOS host stores its secrets on the **host**,
/// where `secret set` runs. `systemd-creds` lives in the guest and is
/// not reachable from there, so `auto` would find no encrypting backend
/// and refuse every `secret set` -- which made `domains.auto`, whose
/// decider `api_key` is mandatory, unusable on a Mac without opting
/// into plaintext.
#[test]
fn a_vm_cage_on_a_mac_uses_the_host_keychain() {
    let cfg = common::config("vm", "auto", "auto", false);
    let fake = creds_missing();
    // The probe add is `security -i` now; only the delete still
    // carries its arguments in argv.
    fake.on(["security", "-i"], Reply::success());
    fake.on(["security", "delete-generic-password"], Reply::success());
    assert_eq!(choose(&fake, &cfg, "", Platform::MacOs), Ok(KEYCHAIN));

    // The same cage on Linux gets systemd-creds, not a keychain.
    assert_eq!(
        choose(&creds_available(), &cfg, "", Platform::Other),
        Ok(SYSTEMD_CREDS)
    );
}

/// **Surprise 2.** That host-keychain rule is `auto`-only. Name
/// `systemd-creds` explicitly on the same Mac vm cage and the store is
/// built, found unavailable, and refused -- the keychain is never
/// considered.
#[test]
fn the_host_keychain_rule_does_not_apply_to_an_explicit_backend() {
    let cfg = common::config("vm", "systemd-creds", "auto", false);
    assert_eq!(
        choose(&creds_missing(), &cfg, "", Platform::MacOs),
        Err(
            "secrets.backend is 'systemd-creds' but systemd-creds encryption \
             is not usable on this host"
                .to_string()
        )
    );
}

/// **Surprise 3.** A Mac that has neither a usable keychain nor an
/// opt-in refuses, and the message is the generic one -- it does not
/// mention the keychain, because the `auto` branch does not know which
/// encrypting backend it tried.
#[test]
fn auto_on_a_mac_with_no_keychain_gives_the_generic_refusal() {
    let cfg = common::config("apple-container", "auto", "auto", false);
    let fake = creds_missing();
    fake.on(
        ["security", "-i"],
        Reply::failed(1, "User interaction is not allowed."),
    );
    fake.on(["sudo"], Reply::failed(1, "sudo: a password is required"));
    assert_eq!(
        choose(&fake, &cfg, "", Platform::MacOs),
        Err("no encrypting secret backend is available and \
             secrets.allow_plaintext is not set"
            .to_string())
    );
}

/// The configured `secrets.scope` reaches the store it builds, which is
/// the difference between a polkit prompt nobody answers and a
/// credential encrypted with the per-user key.
#[test]
fn the_configured_scope_reaches_the_store() {
    let temp = common::TempDir::new("scope");
    let cfg = common::config("container", "systemd-creds", "user", false);
    let fake = creds_available();
    fake.on(["podman", "secret", "inspect"], Reply::status(1));
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    let podman = Podman::new(&fake);
    let store = resolve_store(&cfg, &host, Some(&podman), "", Platform::Other).unwrap();

    store
        .set("acme", "K", "TEST-NOT-A-REAL-SECRET", temp.path())
        .unwrap();

    let encrypt = fake
        .calls()
        .into_iter()
        .find(|c| c.argv().contains(&"K".to_string()))
        .expect("the encrypt call");
    assert_eq!(encrypt.argv()[..3], ["systemd-creds", "--user", "encrypt"]);
}

// ── at_rest_store (PR E9) ───────────────────────────────────────────
//
// `runtime_decrypts` existed as documentation before it decided
// anything. These pin the predicate three commands now depend on:
// `secret rm`, `cage destroy` and `cage backup --include-secrets` all
// used to assume the container backend's shape, where the runtime copy
// *is* the value, and all three were wrong on a vm cage on a Mac.

/// Which cages have a value somewhere the runtime removals do not reach.
#[test]
fn only_a_store_the_runtime_does_not_decrypt_is_an_at_rest_store() {
    let keychain_cases = [
        // The bug's cage: `auto` on a Mac vm cage is the login keychain.
        ("vm", "auto", false, Platform::MacOs),
        ("apple-container", "auto", false, Platform::MacOs),
    ];
    for (isolation, backend, allow_plaintext, platform) in keychain_cases {
        let cfg = common::config(isolation, backend, "auto", allow_plaintext);
        let fake = creds_missing();
        // Resolving the keychain store runs its write probe: an add
        // through `security -i`, then a delete.
        fake.on(["security", "-i"], Reply::success());
        fake.on(["security", "delete-generic-password"], Reply::success());
        let env = MapEnv::new();
        let host = SecretHost::new(&fake, &env, true);
        let podman = Podman::new(&fake);
        let store = agentcage_cli::secrets::at_rest_store(&cfg, &host, Some(&podman), platform)
            .unwrap_or_else(|| panic!("{isolation}/{backend} must have an at-rest store"));
        assert_eq!(identify(store.as_ref()), KEYCHAIN);
    }

    // Everything whose runtime already holds the value: the podman
    // secret store, or a `.cred` the Quadlet decrypts. Removing the
    // runtime copy removes the value, so there is nothing extra to do
    // and these must answer None -- otherwise `secret rm` would delete
    // twice and `cage backup` would resolve a store for nothing.
    let none_cases = [
        (
            "container",
            "systemd-creds",
            false,
            Platform::Other,
            "a .cred blob",
        ),
        (
            "container",
            "plaintext",
            true,
            Platform::Other,
            "the podman store",
        ),
        ("vm", "plaintext", true, Platform::MacOs, "the podman store"),
    ];
    for (isolation, backend, allow_plaintext, platform, why) in none_cases {
        let cfg = common::config(isolation, backend, "auto", allow_plaintext);
        let fake = creds_available();
        let env = MapEnv::new();
        let host = SecretHost::new(&fake, &env, true);
        let podman = Podman::new(&fake);
        let got = agentcage_cli::secrets::at_rest_store(&cfg, &host, Some(&podman), platform)
            .map(|s| identify(s.as_ref()));
        assert_eq!(
            got, None,
            "{isolation}/{backend} keeps its value in {why}, which the runtime \
             removals already cover"
        );
    }
}

/// `apple-container`/`plaintext` is the case that proves the predicate
/// is not just "is it the keychain".
///
/// `ApplePlaintextStore` answers `runtime_decrypts() == false` -- the
/// value is a file in the deployment directory, not a podman secret --
/// so it *is* an at-rest store even though it is cleartext, and the two
/// stores that share the name `plaintext` land on opposite sides of the
/// predicate. Nothing downstream depends on that today (an apple cage
/// never reaches these three call sites: `secret rm` and `cage
/// destroy` have their own apple branches, and `backup_apple` refuses
/// `--include-secrets`), which is exactly why it is worth pinning
/// here -- the flag is the rule, not the name.
#[test]
fn the_predicate_reads_the_flag_and_not_the_store_name() {
    let cfg = common::config("apple-container", "plaintext", "auto", true);
    let fake = creds_missing();
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    let podman = Podman::new(&fake);
    // Resolution gives the file-backed plaintext store...
    assert_eq!(choose(&fake, &cfg, "", Platform::MacOs), Ok(FILE_PLAINTEXT));
    // ...whose flag is false, so it is not covered by a podman removal.
    let store = resolve_store(&cfg, &host, Some(&podman), "", Platform::MacOs).unwrap();
    assert!(!store.runtime_decrypts());
    assert_ne!(identify(store.as_ref()), PODMAN_PLAINTEXT);
}

/// A store that cannot be resolved is `None`, not an error.
///
/// Callers use `at_rest_store` to do strictly *more* cleanup than they
/// used to, so a host where no store resolves has to leave them exactly
/// where they were -- a `secret rm` that fails because the keychain is
/// locked would be a regression, not a fix.
#[test]
fn an_unresolvable_store_is_none_rather_than_a_failure() {
    // `auto` with no systemd-creds and no plaintext opt-in: resolution
    // refuses, which is the fail-closed behaviour `secret set` wants.
    let cfg = common::config("container", "auto", "auto", false);
    let fake = creds_missing();
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    let podman = Podman::new(&fake);
    assert!(choose(&fake, &cfg, "", Platform::Other).is_err());
    assert!(
        agentcage_cli::secrets::at_rest_store(&cfg, &host, Some(&podman), Platform::Other)
            .is_none()
    );
}
