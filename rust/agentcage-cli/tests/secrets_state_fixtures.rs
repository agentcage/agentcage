//! Every secret-bearing file in PR A7's frozen 0.40.1 state, read back
//! through the ported readers with concrete expected values.
//!
//! There are seven, across two of the three captured cages:
//!
//! | file | cage | reader |
//! | :-- | :-- | :-- |
//! | `creds/ANTHROPIC_API_KEY.cred` | `acme-agent` | [`SecretHost::resolve`], `systemd-creds:` |
//! | `creds/IMAP_PASSWORD.cred` | `acme-agent` | same |
//! | `creds/OPENROUTER_API_KEY.cred` | `acme-agent` | same |
//! | `secret_keys.json` | `acme-agent` | [`KeychainStore::names`] |
//! | `secret_keys.json` | `mac-agent` | same |
//! | `pending_secrets.json` | `acme-agent` | [`ApplePlaintextStore`] |
//! | `pending_secrets.json` | `mac-agent` | same |
//!
//! The third cage, `plain-cage`, has none of them, and that absence is
//! captured too: a reader that treats a missing index as an error would
//! break `cage secret list` on every defaulted cage.
//!
//! # The `.cred` blobs are opaque here, on purpose
//!
//! `systemd-creds` encryption is bound to the host that did it -- the
//! host key, the TPM2, or a per-user key -- so the committed blob
//! cannot be decrypted in CI or on any other machine, and re-encrypting
//! would not reproduce it byte for byte either. A7 froze one real-shaped
//! blob into its generator and says: assert presence, filename and
//! shape, never contents. That is exactly what
//! [`the_cred_blobs_are_present_and_shaped_right`] does, and the reader
//! it exercises has the same obligation the Python's has -- find the
//! file, hand it to `systemd-creds decrypt`, never parse it.
//! `tests/secrets_creds_roundtrip.rs` is where a blob really is
//! decrypted, and it makes its own.

mod common;

use agentcage_cli::secrets::{
    ApplePlaintextStore, KeychainStore, MapEnv, Platform, Resolution, SecretHost, SecretStore,
};
use agentcage_exec::{FakeRunner, Reply};

use common::deployment_dir;

/// `acme-agent` in A7's README: many domains, several secret sources, a
/// relay, capture, grants, `creds/`.
const RICH: &str = "acme-agent";
/// `mac-agent`: the macOS shape, whose secrets live in the keychain.
const APPLE: &str = "mac-agent";
/// `plain-cage`: everything defaulted, so nothing here exists.
const MINIMAL: &str = "plain-cage";

/// A keychain store that cannot shell out.
///
/// Reading the name index must not need `security`, and the call count
/// proves it -- `cage secret list` on a Linux box looking at a restored
/// macOS cage's state directory has to work.
fn index_reader(fake: &FakeRunner) -> KeychainStore<'_> {
    KeychainStore::new(fake, Platform::Other)
}

#[test]
fn the_keychain_name_index_reads_back_as_written() {
    let fake = FakeRunner::new();
    let store = index_reader(&fake);

    assert_eq!(
        store.names(RICH, &deployment_dir(RICH)).unwrap(),
        ["ANTHROPIC_API_KEY", "GITHUB_TOKEN"]
    );
    assert_eq!(
        store.names(APPLE, &deployment_dir(APPLE)).unwrap(),
        ["ANTHROPIC_API_KEY", "OPENROUTER_API_KEY"]
    );
    assert_eq!(fake.call_count(), 0, "reading an index runs no command");
}

/// The cage argument is ignored, which is not a bug to tidy away: the
/// index is per-deployment-directory and `_index_add` calls
/// `self.names("")`.
#[test]
fn the_index_is_keyed_by_directory_and_not_by_cage_name() {
    let fake = FakeRunner::new();
    let store = index_reader(&fake);
    assert_eq!(
        store.names("", &deployment_dir(RICH)).unwrap(),
        store
            .names("some-other-cage", &deployment_dir(RICH))
            .unwrap()
    );
}

#[test]
fn a_cage_with_no_index_lists_nothing() {
    let fake = FakeRunner::new();
    assert_eq!(
        index_reader(&fake)
            .names(MINIMAL, &deployment_dir(MINIMAL))
            .unwrap(),
        Vec::<String>::new()
    );
}

/// The file is a JSON array of `[key, value]` pairs. A reader that
/// assumed a map fails on every cage that has ever used either writer --
/// `ApplePlaintextStore._save` here, and the VM hand-off in `cli.py` and
/// `run.py`.
#[test]
fn pending_secrets_is_a_list_of_pairs() {
    let store = ApplePlaintextStore;

    for cage in [RICH, APPLE] {
        let dir = deployment_dir(cage);
        let raw = std::fs::read_to_string(ApplePlaintextStore::path(&dir)).unwrap();
        assert_eq!(
            raw, r#"[["GITHUB_TOKEN", "TEST-NOT-A-REAL-SECRET-0003"]]"#,
            "{cage}: the on-disk form, separators included"
        );

        assert_eq!(
            ApplePlaintextStore::load(&dir),
            [(
                "GITHUB_TOKEN".to_string(),
                "TEST-NOT-A-REAL-SECRET-0003".to_string()
            )]
        );
        assert_eq!(store.names(cage, &dir).unwrap(), ["GITHUB_TOKEN"]);
        assert_eq!(
            store.get(cage, "GITHUB_TOKEN", &dir).unwrap().as_deref(),
            Some("TEST-NOT-A-REAL-SECRET-0003")
        );
        assert_eq!(store.get(cage, "NOPE", &dir).unwrap(), None);
    }
}

#[test]
fn a_cage_with_no_pending_secrets_file_reads_as_empty() {
    let dir = deployment_dir(MINIMAL);
    assert!(!ApplePlaintextStore::path(&dir).exists());
    assert_eq!(ApplePlaintextStore::load(&dir), []);
    assert_eq!(
        ApplePlaintextStore.names(MINIMAL, &dir).unwrap(),
        Vec::<String>::new()
    );
}

/// Presence, filename and shape. Never contents -- see the module docs.
#[test]
fn the_cred_blobs_are_present_and_shaped_right() {
    let creds = deployment_dir(RICH).join("creds");
    let mut names: Vec<String> = std::fs::read_dir(&creds)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "ANTHROPIC_API_KEY.cred",
            "IMAP_PASSWORD.cred",
            "OPENROUTER_API_KEY.cred"
        ]
    );

    for name in &names {
        let blob = std::fs::read(creds.join(name)).unwrap();
        assert!(blob.len() > 64, "{name}: {} bytes", blob.len());
        // base64 armor, as `systemd-creds encrypt … -` emits it:
        // alphanumerics, `+`, `/`, `=` and the line breaks it wraps at.
        assert!(
            blob.iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\n')),
            "{name}: not base64 armor"
        );
    }

    // A7's generator freezes *one* real-shaped blob and writes it under
    // every key, precisely because the contents are meaningless off the
    // machine that made them. Asserting they match says nothing about
    // the plaintext and everything about the fixture staying frozen.
    let first = std::fs::read(creds.join(&names[0])).unwrap();
    for name in &names[1..] {
        assert_eq!(std::fs::read(creds.join(name)).unwrap(), first);
    }
}

/// The reader's whole job for a `systemd-creds:` source: the file is
/// there, so the unit will decrypt it, and nothing here opens it.
#[test]
fn a_systemd_creds_source_resolves_to_quadlet_handled() {
    let fake = FakeRunner::new();
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    let dir = deployment_dir(RICH);

    for key in ["ANTHROPIC_API_KEY", "IMAP_PASSWORD", "OPENROUTER_API_KEY"] {
        assert_eq!(
            host.resolve("systemd-creds:", key, &dir).unwrap(),
            Resolution::QuadletHandled,
            "{key}"
        );
    }
    assert_eq!(fake.call_count(), 0, "no subprocess to notice a file");
}

/// The one `.cred` name that is in the config but not on disk is the
/// error path, and the message names the path an operator has to look
/// at.
#[test]
fn a_missing_cred_file_names_the_path() {
    let fake = FakeRunner::new();
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    let dir = deployment_dir(MINIMAL);

    let err = host
        .resolve("systemd-creds:", "GITHUB_TOKEN", &dir)
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "encrypted credential not found: {}",
            dir.join("creds/GITHUB_TOKEN.cred").display()
        )
    );
}

/// The index the keychain store *writes* is byte-identical to the one
/// A7 recorded.
///
/// `json.dumps` separates with `", "`, and a serializer that dropped
/// the space would produce a file the Python reader still accepts but a
/// byte-comparing fixture check does not -- which is why both writers
/// here go through `agentcage_core`'s `json.dumps` clone rather than
/// through `serde_json`.
///
/// The store is pointed at a fake macOS so the keychain half is
/// reachable from Linux; the keychain calls themselves are asserted in
/// `tests/secrets_argv.rs`.
#[test]
fn a_rewritten_index_matches_the_fixture_byte_for_byte() {
    let temp = common::TempDir::new("index");
    let fake = FakeRunner::new();
    // The login-keychain write probe: an add, then its delete.
    fake.push(Reply::success());
    fake.push(Reply::success());
    // Two `set`s and one `delete`, each one `security` call.
    fake.push_all([Reply::success(), Reply::success(), Reply::success()]);
    let store = KeychainStore::new(&fake, Platform::MacOs);

    // A7's `acme-agent` index is ["ANTHROPIC_API_KEY", "GITHUB_TOKEN"],
    // so write it in the other order and let the store sort it.
    store
        .set(
            "acme-agent",
            "GITHUB_TOKEN",
            "TEST-NOT-A-REAL-SECRET-0003",
            temp.path(),
        )
        .unwrap();
    store
        .set(
            "acme-agent",
            "ANTHROPIC_API_KEY",
            "TEST-NOT-A-REAL-SECRET-0001",
            temp.path(),
        )
        .unwrap();
    // A key that was never added still rewrites the index.
    store
        .delete("acme-agent", "NOT_PRESENT", temp.path())
        .unwrap();

    assert_eq!(
        std::fs::read_to_string(KeychainStore::index_path(temp.path())).unwrap(),
        std::fs::read_to_string(deployment_dir(RICH).join("secret_keys.json")).unwrap()
    );
    fake.assert_drained();
}

/// The pair file survives a read/write round trip byte for byte.
///
/// Same `", "` separator question as the index, and the same answer.
/// This is the file `cage create --set-secret` leaves behind for the VM
/// backend to pick up, so a rewrite that changed its bytes would be a
/// cross-version incompatibility rather than a cosmetic diff.
#[test]
fn a_rewritten_pending_secrets_file_matches_the_fixture_byte_for_byte() {
    let temp = common::TempDir::new("pending");
    let original = ApplePlaintextStore::path(&deployment_dir(RICH));

    let pairs = ApplePlaintextStore::load(&deployment_dir(RICH));
    ApplePlaintextStore::save(temp.path(), &pairs).unwrap();

    assert_eq!(
        std::fs::read(ApplePlaintextStore::path(temp.path())).unwrap(),
        std::fs::read(&original).unwrap()
    );
}

/// The at-rest mode A7's README says it cannot carry: git records only
/// the executable bit, so the fixture comes back 0644 and the real
/// property has to be asserted against a file this test writes.
#[test]
fn pending_secrets_is_written_0600() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = common::TempDir::new("mode");
    ApplePlaintextStore
        .set("c", "K", "TEST-NOT-A-REAL-SECRET-0009", temp.path())
        .unwrap();
    let mode = std::fs::metadata(ApplePlaintextStore::path(temp.path()))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "mode {:o}", mode & 0o777);
}
