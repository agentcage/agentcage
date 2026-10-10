//! Every command a secret store or the resolver runs, pinned by argv.
//!
//! This is the contract with `systemd-creds`, `podman` and
//! `security`. A test that only checked "a command ran" would pass
//! after a dropped `--user`, a missing `-`, or a value that moved from
//! stdin into argv -- which are exactly the three mistakes this module
//! is most able to make.
//!
//! Every test that involves a credential asserts two things about it:
//! the argv it is *not* in, and the stdin it *is* in -- including the
//! keychain, which was the one exception until PR D1 and is now
//! [`the_keychain_add_puts_the_cleartext_on_stdin`]. The shape it used
//! to have is still pinned, on purpose, by
//! [`the_argv_channel_is_reachable_and_is_what_the_fix_is_defined_against`].

mod common;

use std::collections::BTreeSet;
use std::path::Path;

use agentcage_cli::secrets::{
    ApplePlaintextStore, KeychainStore, MapEnv, PlaintextStore, Platform, SecretHost, SecretStore,
    SystemdCredsStore,
};
use agentcage_exec::tools::podman::Podman;
use agentcage_exec::tools::security::{PasswordChannel, SHIPPED_PASSWORD_CHANNEL};
use agentcage_exec::{FakeRunner, Reply};

use common::TempDir;

/// The macOS System keychain, appended last to every `security`
/// invocation that targets it.
const KC: &str = "/Library/Keychains/System.keychain";

/// The value every test uses, so a leak is greppable in a failure dump.
const VALUE: &str = "TEST-NOT-A-REAL-SECRET-hunter2";

/// Assert that nothing in `argv` contains [`VALUE`].
fn argv_is_clean(argv: &[String]) {
    assert!(
        !argv.iter().any(|a| a.contains(VALUE)),
        "the value reached argv: {argv:?}"
    );
}

// ── systemd-creds ────────────────────────────────────────────

/// `secrets.scope: auto` on a non-root invoker: probe the per-user key,
/// encrypt with it, then drop any stale podman secret of the same name.
#[test]
fn the_systemd_creds_store_probes_encrypts_and_clears_the_stale_secret() {
    let temp = TempDir::new("creds-auto");
    let fake = FakeRunner::new();
    fake.push(Reply::success()); // the `--user` probe
    fake.push(Reply::success()); // the encrypt
    fake.push(Reply::status(0)); // podman secret inspect: it exists
    fake.push(Reply::success()); // podman secret rm
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    let podman = Podman::new(&fake);
    let store = SystemdCredsStore::new(&host, "auto", Some(&podman));

    store.set("acme", "API_KEY", VALUE, temp.path()).unwrap();

    let cred = temp.path().join("creds/API_KEY.cred");
    fake.assert_argv(&[
        &[
            "systemd-creds",
            "--user",
            "encrypt",
            "--name",
            "_probe",
            "-",
            "-",
        ],
        &[
            "systemd-creds",
            "--user",
            "encrypt",
            "--name",
            "API_KEY",
            "-",
            &cred.to_string_lossy(),
        ],
        &["podman", "secret", "inspect", "acme.API_KEY"],
        &["podman", "secret", "rm", "acme.API_KEY"],
    ]);

    // The value is on stdin and nowhere else.
    let encrypt = fake.call(1);
    argv_is_clean(&encrypt.raw_argv());
    assert_eq!(encrypt.stdin_text().as_deref(), Some(VALUE));
    assert_eq!(
        encrypt.command.timeout_limit(),
        Some(std::time::Duration::from_secs(30))
    );
    fake.assert_drained();
}

/// An explicit scope runs no probe, and `system` contributes no flag.
#[test]
fn an_explicit_system_scope_encrypts_with_the_host_key() {
    let temp = TempDir::new("creds-system");
    let fake = FakeRunner::new();
    fake.push(Reply::success());
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    let store = SystemdCredsStore::new(&host, "system", None);

    store.set("acme", "API_KEY", VALUE, temp.path()).unwrap();

    let cred = temp.path().join("creds/API_KEY.cred");
    fake.assert_argv(&[&[
        "systemd-creds",
        "encrypt",
        "--name",
        "API_KEY",
        "-",
        &cred.to_string_lossy(),
    ]]);
    // `creds/` is created before the child runs, because the child
    // writes into it.
    assert!(temp.path().join("creds").is_dir());
}

/// Deleting removes the blob and the stale podman secret; a blob that
/// was never there is not an error (`unlink(missing_ok=True)`).
#[test]
fn deleting_unlinks_the_blob_and_the_podman_secret() {
    let temp = TempDir::new("creds-delete");
    std::fs::create_dir_all(temp.path().join("creds")).unwrap();
    let cred = temp.path().join("creds/API_KEY.cred");
    std::fs::write(&cred, b"not-a-real-blob").unwrap();

    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    fake.push(Reply::success());
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    let podman = Podman::new(&fake);
    let store = SystemdCredsStore::new(&host, "system", Some(&podman));

    store.delete("acme", "API_KEY", temp.path()).unwrap();
    assert!(!cred.exists());
    fake.assert_argv(&[
        &["podman", "secret", "inspect", "acme.API_KEY"],
        &["podman", "secret", "rm", "acme.API_KEY"],
    ]);

    // Again, with nothing to remove on either side.
    let fake = FakeRunner::new();
    fake.push(Reply::status(1));
    let podman = Podman::new(&fake);
    let store = SystemdCredsStore::new(&host, "system", Some(&podman));
    store.delete("acme", "API_KEY", temp.path()).unwrap();
    fake.assert_argv(&[&["podman", "secret", "inspect", "acme.API_KEY"]]);
}

/// The store whose runtime decrypts answers no retrieval question, and
/// keeps no name index -- it says so rather than panicking.
#[test]
fn the_systemd_creds_store_supports_neither_get_nor_names() {
    let fake = FakeRunner::new();
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    let store = SystemdCredsStore::new(&host, "system", None);

    assert_eq!(
        store
            .get("c", "K", Path::new("/nope"))
            .unwrap_err()
            .to_string(),
        "backend 'systemd-creds' does not support value retrieval"
    );
    assert_eq!(
        store
            .names("c", Path::new("/nope"))
            .unwrap_err()
            .to_string(),
        "backend 'systemd-creds' does not support name listing"
    );
    assert!(store.runtime_decrypts());
    assert_eq!(fake.call_count(), 0);
}

// ── plaintext (podman) ───────────────────────────────────────

/// The model every other secret path copies: `podman secret create
/// <name> -`, with the value on stdin.
#[test]
fn the_plaintext_store_puts_the_value_on_stdin() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0)); // exists
    fake.push(Reply::success()); // rm
    fake.push(Reply::success()); // create
    let podman = Podman::new(&fake);
    let store = PlaintextStore::new(Some(&podman));

    store
        .set("acme", "API_KEY", VALUE, Path::new("/unused"))
        .unwrap();

    fake.assert_argv(&[
        &["podman", "secret", "inspect", "acme.API_KEY"],
        &["podman", "secret", "rm", "acme.API_KEY"],
        &["podman", "secret", "create", "acme.API_KEY", "-"],
    ]);
    let create = fake.call(2);
    argv_is_clean(&create.raw_argv());
    assert_eq!(create.stdin_text().as_deref(), Some(VALUE));
    fake.assert_drained();
}

#[test]
fn the_plaintext_store_reads_and_deletes_by_name() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    fake.push(Reply::ok(format!("{VALUE}\n")));
    fake.push(Reply::status(1));
    let podman = Podman::new(&fake);
    let store = PlaintextStore::new(Some(&podman));
    let unused = Path::new("/unused");

    assert_eq!(
        store.get("acme", "API_KEY", unused).unwrap().as_deref(),
        Some(VALUE)
    );
    // A secret that is not there is `None`, not an error, and the
    // delete of a missing secret is a single `inspect`.
    store.delete("acme", "API_KEY", unused).unwrap();

    fake.assert_argv(&[
        &["podman", "secret", "inspect", "acme.API_KEY"],
        &[
            "podman",
            "secret",
            "inspect",
            "--showsecret",
            "--format",
            "{{.SecretData}}",
            "acme.API_KEY",
        ],
        &["podman", "secret", "inspect", "acme.API_KEY"],
    ]);
}

// ── keychain (PR E2b's behaviour, PR D1's argv) ──────────────

/// Target selection probes with a *write*, because the login keychain
/// answers reads over headless SSH and then refuses writes.
#[test]
fn the_login_keychain_is_probed_by_writing_and_deleting() {
    let fake = FakeRunner::new();
    fake.push(Reply::success()); // the probe add
    fake.push(Reply::success()); // the probe delete
    let store = KeychainStore::new(&fake, Platform::MacOs);

    assert!(store.available());
    fake.assert_argv(&[
        &["security", "-i"],
        &[
            "security",
            "delete-generic-password",
            "-s",
            "agentcage",
            "-a",
            "__agentcage_probe__",
        ],
    ]);
    assert_eq!(
        fake.call(0).stdin_text().as_deref(),
        Some("add-generic-password -s agentcage -a '__agentcage_probe__' -w 'x' -U\n"),
        "the probe writes on the channel `set` writes on"
    );

    // The answer is cached, so a second question costs nothing.
    assert!(store.available());
    assert_eq!(fake.call_count(), 2);
}

/// A locked login keychain falls through to the System keychain via
/// `sudo -n`, which never prompts -- a narrow
/// `NOPASSWD: /usr/bin/security` rule is enough.
#[test]
fn a_locked_login_keychain_falls_through_to_sudo_n() {
    let fake = FakeRunner::new();
    fake.push(Reply::failed(1, "User interaction is not allowed."));
    fake.push(Reply::success());
    fake.push(Reply::success());
    let store = KeychainStore::new(&fake, Platform::MacOs);

    assert!(store.available());
    assert_eq!(fake.argv(1), ["sudo", "-n", "security", "-i"]);
    assert_eq!(
        fake.call(1).stdin_text().as_deref(),
        Some(
            "add-generic-password -s agentcage -a '__agentcage_probe__' -w 'x' -U \
             '/Library/Keychains/System.keychain'\n"
        )
    );
}

/// Neither target works: fail closed, with the message that tells an
/// operator the three ways out.
#[test]
fn a_keychain_that_cannot_be_written_fails_closed() {
    let fake = FakeRunner::new();
    // Rules rather than a queue: a *failed* target selection is not
    // cached -- the Python raises without assigning `_target_cache`, so
    // a keychain unlocked between two calls is picked up -- and so the
    // probes run again on the second question.
    fake.on(
        ["security", "-i"],
        Reply::failed(1, "User interaction is not allowed."),
    );
    fake.on(["sudo"], Reply::failed(1, "sudo: a password is required"));
    let store = KeychainStore::new(&fake, Platform::MacOs);

    assert!(!store.available());
    assert_eq!(fake.call_count(), 2, "one probe per target");
    let err = store
        .set("acme", "API_KEY", VALUE, Path::new("/unused"))
        .unwrap_err();
    assert!(err.is_store_error());
    assert!(
        err.to_string().contains("macOS keychain unavailable"),
        "{err}"
    );
}

#[test]
fn the_keychain_is_refused_outright_off_macos() {
    let fake = FakeRunner::new();
    let store = KeychainStore::new(&fake, Platform::Other);
    assert!(!store.available());
    assert_eq!(
        store.target().unwrap_err().to_string(),
        "keychain backend is macOS-only"
    );
    assert_eq!(fake.call_count(), 0, "no probe off the platform");
}

/// **The finding, fixed, pinned through the whole store.**
///
/// `KeychainStore.set` used to pass the cleartext as `-w <value>`,
/// where it was readable from the process table by any process of the
/// same user and by root for the life of the child. It was the only
/// such path in the code being ported; every other one uses stdin. PR
/// D1 found it, PR E2b established which fix was real, and D1 shipped
/// it after a round trip against an actual keychain:
/// `security -i`, the command line on the child's stdin.
///
/// This asserts the value is on stdin and nowhere else -- not in this
/// call's argv, and not in any argv in the whole sequence, which is
/// what catches it reappearing in the *probe* rather than in `set`.
#[test]
fn the_keychain_add_puts_the_cleartext_on_stdin() {
    let temp = TempDir::new("keychain-set");
    let fake = FakeRunner::new();
    fake.push(Reply::success()); // probe add
    fake.push(Reply::success()); // probe delete
    fake.push(Reply::success()); // the real add
    let store = KeychainStore::new(&fake, Platform::MacOs);

    store.set("acme", "API_KEY", VALUE, temp.path()).unwrap();

    let add = fake.call(2);
    assert_eq!(add.raw_argv(), ["security", "-i"]);
    assert_eq!(
        add.stdin_text().as_deref(),
        Some(
            format!("add-generic-password -s agentcage -a 'acme.API_KEY' -w '{VALUE}' -U\n")
                .as_str()
        )
    );
    // Nothing that prints a command prints it.
    assert!(!format!("{add:?}").contains(VALUE));
    assert!(!add.command.display().contains(VALUE));
    assert!(
        !fake
            .argv_sequence()
            .iter()
            .flatten()
            .any(|a| a.contains(VALUE))
    );
    // The probe followed the channel, so `available()` cannot pass on a
    // shape `set` would not use.
    assert_eq!(fake.call(0).raw_argv(), ["security", "-i"]);

    // The index gained the key, and it is not a value store.
    assert_eq!(store.names("acme", temp.path()).unwrap(), ["API_KEY"]);
    assert_eq!(
        std::fs::read_to_string(KeychainStore::index_path(temp.path())).unwrap(),
        r#"["API_KEY"]"#
    );
}

/// **The System-keychain path, whole.** The store's three commands on
/// the target a headless Mac actually uses, with the keychain path
/// where `security(1)` wants it: last, after every flag and every
/// flag's value.
///
/// Every other `add` assertion in this suite and in
/// `agentcage-exec/tests/tool_argv.rs` used the *login* target, whose
/// keychain is `None` -- so nothing is appended and any ordering looks
/// correct. That blind spot hid a real bug: `add` chained the value and
/// `-U` on after the path, producing
/// `-w /Library/Keychains/System.keychain <CLEARTEXT> -U`, which stores
/// the path as the password and hands the credential to `security` as a
/// positional argument. PR E2b fixed it; this is the test that keeps it
/// fixed.
#[test]
fn the_system_keychain_carries_the_path_last_in_every_command() {
    let temp = TempDir::new("keychain-system");
    let fake = FakeRunner::new();
    fake.push(Reply::failed(1, "User interaction is not allowed.")); // login probe add
    fake.push(Reply::success()); // system probe add
    fake.push(Reply::success()); // system probe delete
    fake.push(Reply::success()); // set
    fake.push(Reply::ok(format!("{VALUE}\n"))); // get
    fake.push(Reply::success()); // delete
    let store = KeychainStore::new(&fake, Platform::MacOs);

    store.set("acme", "API_KEY", VALUE, temp.path()).unwrap();
    assert_eq!(
        store
            .get("acme", "API_KEY", temp.path())
            .unwrap()
            .as_deref(),
        Some(VALUE)
    );
    store.delete("acme", "API_KEY", temp.path()).unwrap();

    assert_eq!(fake.call(3).raw_argv(), ["sudo", "-n", "security", "-i"]);
    assert_eq!(
        fake.call(3).stdin_text().as_deref(),
        Some(
            format!("add-generic-password -s agentcage -a 'acme.API_KEY' -w '{VALUE}' -U '{KC}'\n")
                .as_str()
        ),
        "the keychain path is still last -- on stdin now, same parser"
    );
    assert_eq!(
        fake.argv(4),
        [
            "sudo",
            "-n",
            "security",
            "find-generic-password",
            "-s",
            "agentcage",
            "-a",
            "acme.API_KEY",
            "-w",
            KC,
        ]
    );
    assert_eq!(
        fake.argv(5),
        [
            "sudo",
            "-n",
            "security",
            "delete-generic-password",
            "-s",
            "agentcage",
            "-a",
            "acme.API_KEY",
            KC,
        ]
    );
    // Every invocation, including the two probes, ends at the keychain
    // -- in argv for the three that have arguments, and at the end of
    // the command line for the two adds, which now carry theirs on
    // stdin. Same requirement, two places to check it.
    for n in 1..fake.call_count() {
        let argv = fake.argv(n);
        let ends_argv = argv.last().map(String::as_str) == Some(KC);
        let ends_stdin = argv == ["sudo", "-n", "security", "-i"]
            && fake
                .call(n)
                .stdin_text()
                .is_some_and(|line| line.trim_end().ends_with(&format!("'{KC}'")));
        assert!(
            ends_argv || ends_stdin,
            "call {n} lost the keychain path: {argv:?}"
        );
    }
    // The value is still absent from everything that prints.
    assert!(!format!("{:?}", fake.calls()).contains(VALUE));
}

/// The interaction-blocked stderr, and the thing it does *not* do.
///
/// `_writable` returns `False` on any non-zero exit and `_target`
/// falls through on `False`, so the stderr text is not consulted
/// anywhere: the fall-through is identical whether the login keychain
/// is locked, `security` is missing a flag, or the item already
/// exists.
///
/// Both sides used to carry a predicate for that stderr --
/// `secret_store.py::_security_interaction_blocked` and an
/// `interaction_blocked` beside it in Rust -- defined, unit tested,
/// and called by nothing. Wiring either one in would have *narrowed*
/// the fall-through, turning a headless Mac that fails for any other
/// reason into a hard failure instead of a System-keychain attempt.
/// Both are deleted; this test is what actually holds the behaviour.
#[test]
fn the_fall_through_ignores_what_the_stderr_actually_says() {
    const STDERRS: [&str; 3] = [
        "SecKeychainItemCreateFromContent: User interaction is not allowed.",
        "SecKeychainItemCreateFromContent: The specified item already exists in the keychain.",
        "",
    ];
    for stderr in STDERRS {
        let fake = FakeRunner::new();
        fake.push(Reply::failed(1, stderr));
        fake.push(Reply::success());
        fake.push(Reply::success());
        let store = KeychainStore::new(&fake, Platform::MacOs);

        assert!(
            store.available(),
            "stderr {stderr:?} should still fall through to the System keychain"
        );
        assert_eq!(
            fake.argv(1).first().map(String::as_str),
            Some("sudo"),
            "stderr {stderr:?}"
        );
        assert_eq!(fake.call_count(), 3);
    }
}

/// **The shape PR D1 removed, driven through the whole store.**
///
/// Kept reachable, and asserted, because a test that only pins the new
/// shape cannot tell you the old one is gone. Flipping the channel
/// changes exactly one thing: the value moves from the child's stdin
/// back into argv. Target selection, the argument order, the index
/// write and the read-back path are untouched -- which is what made
/// the fix one `const`.
///
/// See `agentcage-exec/tests/keychain_stdin_probe.rs` and
/// [`agentcage_exec::tools::security::AddPassword::how_it_was_settled`].
#[test]
fn the_argv_channel_is_reachable_and_is_what_the_fix_is_defined_against() {
    let temp = TempDir::new("keychain-argv-seam");
    let fake = FakeRunner::new();
    fake.push(Reply::success()); // probe add
    fake.push(Reply::success()); // probe delete
    fake.push(Reply::success()); // the real add
    let store =
        KeychainStore::new(&fake, Platform::MacOs).with_password_channel(PasswordChannel::Argv);

    store.set("acme", "API_KEY", VALUE, temp.path()).unwrap();

    let add = fake.call(2);
    assert_eq!(
        add.raw_argv(),
        [
            "security",
            "add-generic-password",
            "-s",
            "agentcage",
            "-a",
            "acme.API_KEY",
            "-w",
            VALUE,
            "-U",
        ]
    );
    // Nothing on stdin, which was the problem...
    assert_eq!(add.stdin_bytes(), None);
    // ...and the redaction was never the gap: it always held.
    assert_eq!(add.argv()[7], "<redacted>");
    assert!(!format!("{add:?}").contains(VALUE));
    // The rest of the store does not notice either way.
    assert_eq!(store.names("acme", temp.path()).unwrap(), ["API_KEY"]);

    assert_ne!(
        SHIPPED_PASSWORD_CHANNEL,
        PasswordChannel::Argv,
        "this is the shape the fix removed -- it must not be the shipped one"
    );
}

/// A secret `security -i` cannot carry is refused, not truncated.
///
/// Its reader breaks on `\n` and its line buffer is 4096 bytes, and in
/// both cases the remainder is parsed as the next command -- storing
/// the wrong bytes *and* echoing a fragment of the secret to stderr.
/// The store turns the refusal into the same `keychain add failed:`
/// message an operator already knows, and nothing runs.
#[test]
fn the_interactive_channel_refuses_a_secret_it_would_corrupt() {
    let temp = TempDir::new("keychain-refusal");
    let fake = FakeRunner::new();
    fake.push(Reply::success()); // probe add
    fake.push(Reply::success()); // probe delete
    let store = KeychainStore::new(&fake, Platform::MacOs)
        .with_password_channel(PasswordChannel::Interactive);

    let err = store
        .set("acme", "API_KEY", "two\nlines", temp.path())
        .unwrap_err();
    assert!(err.is_store_error());
    assert!(err.to_string().starts_with("keychain add failed:"), "{err}");
    assert!(err.to_string().contains("line terminator"), "{err}");
    assert_eq!(fake.call_count(), 2, "the two probes, and no add");
    assert!(!KeychainStore::index_path(temp.path()).exists());
}

/// Retrieval is clean: the `-w` here takes no value, it asks for the
/// password to be printed.
#[test]
fn the_keychain_find_and_delete_carry_no_value() {
    let temp = TempDir::new("keychain-get");
    let fake = FakeRunner::new();
    fake.push(Reply::success());
    fake.push(Reply::success());
    fake.push(Reply::ok(format!("{VALUE}\n")));
    fake.push(Reply::success());
    let store = KeychainStore::new(&fake, Platform::MacOs);

    assert_eq!(
        store
            .get("acme", "API_KEY", temp.path())
            .unwrap()
            .as_deref(),
        Some(VALUE)
    );
    store.delete("acme", "API_KEY", temp.path()).unwrap();

    assert_eq!(
        fake.argv(2),
        [
            "security",
            "find-generic-password",
            "-s",
            "agentcage",
            "-a",
            "acme.API_KEY",
            "-w",
        ]
    );
    assert_eq!(
        fake.argv(3),
        [
            "security",
            "delete-generic-password",
            "-s",
            "agentcage",
            "-a",
            "acme.API_KEY",
        ]
    );
    for call in fake.calls() {
        argv_is_clean(&call.raw_argv());
    }
}

/// A missing item is `None`, not an error: `KeychainStore.get` treats
/// every non-zero exit as absence.
#[test]
fn a_missing_keychain_item_reads_as_none() {
    let fake = FakeRunner::new();
    fake.push(Reply::success());
    fake.push(Reply::success());
    fake.push(Reply::failed(44, "The specified item could not be found"));
    let store = KeychainStore::new(&fake, Platform::MacOs);
    assert_eq!(
        store.get("acme", "NOPE", Path::new("/unused")).unwrap(),
        None
    );
}

// ── plaintext (apple-container) ──────────────────────────────

/// The file-backed store runs no command at all -- worth asserting,
/// because it is the store a Mac without a keychain falls back to and
/// a stray `podman` call there would fail on a host that has none.
#[test]
fn the_apple_plaintext_store_shells_out_to_nothing() {
    let temp = TempDir::new("apple-plain");
    let store = ApplePlaintextStore;

    store.set("c", "A", VALUE, temp.path()).unwrap();
    store.set("c", "B", "second", temp.path()).unwrap();
    store.set("c", "A", "replaced", temp.path()).unwrap();

    // Insertion order is kept and the replaced key stays in place --
    // Python's `dict` semantics, which the file format inherits.
    assert_eq!(
        std::fs::read_to_string(ApplePlaintextStore::path(temp.path())).unwrap(),
        r#"[["A", "replaced"], ["B", "second"]]"#
    );
    assert_eq!(store.names("c", temp.path()).unwrap(), ["A", "B"]);

    store.delete("c", "A", temp.path()).unwrap();
    assert_eq!(
        std::fs::read_to_string(ApplePlaintextStore::path(temp.path())).unwrap(),
        r#"[["B", "second"]]"#
    );
}

/// A corrupt file is an empty store, not a crash: the Python's
/// `except Exception: return {}`, and the reason is that a truncated
/// write must not make the cage unusable.
#[test]
fn a_corrupt_pending_secrets_file_reads_as_empty() {
    let temp = TempDir::new("apple-corrupt");
    for bad in [
        "not json at all",
        r#"{"A": "1"}"#,
        r#"[["A"]]"#,
        r#"[["A", 1]]"#,
        "",
    ] {
        std::fs::write(ApplePlaintextStore::path(temp.path()), bad).unwrap();
        assert_eq!(
            ApplePlaintextStore::load(temp.path()),
            [],
            "{bad:?} should read as empty"
        );
    }
}

// ── the resolver ─────────────────────────────────────────────

/// `shell=True` is `/bin/sh -c <command>`, and the command is the
/// operator's -- not an argv split here.
#[test]
fn a_cmd_source_runs_bin_sh_dash_c() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok(format!("{VALUE}\n\n")));
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);

    let result = host
        .resolve(
            "cmd:pass show ops/token | head -1",
            "TOKEN",
            Path::new("/x"),
        )
        .unwrap();

    // `.rstrip("\n")` takes every trailing newline, and only newlines.
    assert_eq!(result.value(), Some(VALUE));
    fake.assert_argv(&[&["/bin/sh", "-c", "pass show ops/token | head -1"]]);
    assert_eq!(
        fake.call(0).command.timeout_limit(),
        Some(std::time::Duration::from_secs(30))
    );
}

#[test]
fn an_empty_cmd_source_is_refused_before_a_shell_starts() {
    let fake = FakeRunner::new();
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    assert_eq!(
        host.resolve("cmd:   ", "TOKEN", Path::new("/x"))
            .unwrap_err()
            .to_string(),
        "cmd: source requires a command after 'cmd:'"
    );
    assert_eq!(fake.call_count(), 0);
}

#[test]
fn a_failing_cmd_source_reports_the_exit_code_and_stderr() {
    let fake = FakeRunner::new();
    fake.push(Reply::failed(2, "pass: no such entry\n"));
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    assert_eq!(
        host.resolve("cmd:pass show nope", "TOKEN", Path::new("/x"))
            .unwrap_err()
            .to_string(),
        "command failed (exit 2): pass: no such entry"
    );
}

/// The empty scheme and `podman:` both mean "already in the store", and
/// neither runs anything.
#[test]
fn the_existing_schemes_run_nothing() {
    let fake = FakeRunner::new();
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    for source in ["", "podman:", "podman"] {
        assert_eq!(
            host.resolve(source, "TOKEN", Path::new("/x"))
                .unwrap()
                .action(),
            "existing",
            "{source:?}"
        );
    }
    assert_eq!(fake.call_count(), 0);
}

/// `resolve_and_populate` over one rule of every shape, in one
/// sequence. Both agents are enabled with keys whose names the host
/// environment and the shell could answer, and neither is touched: see
/// [`relay_and_agent_credentials_name_the_store_entry_not_the_host_env`].
#[test]
fn resolve_and_populate_materializes_every_scheme_in_order() {
    use agentcage_core::config::types::SecretInjectionRule;

    let temp = TempDir::new("populate");
    std::fs::create_dir_all(temp.path().join("creds")).unwrap();
    std::fs::write(temp.path().join("creds/CRED_KEY.cred"), b"blob").unwrap();

    let mut cfg = common::config("container", "auto", "auto", false);
    for (env, source) in [
        ("ENV_KEY", "env:HOST_VAR"),
        ("CMD_KEY", "cmd:print-it"),
        ("CRED_KEY", "systemd-creds:"),
        ("STORE_KEY", "podman:"),
        ("NO_SOURCE", ""),
        ("SKIPPED", "env:HOST_VAR"),
    ] {
        cfg.secret_injection.push(SecretInjectionRule {
            env: env.to_owned(),
            source: source.to_owned(),
            ..SecretInjectionRule::default()
        });
    }
    cfg.agents.decider.enable = true;
    cfg.agents.decider.llm.api_key = "env:HOST_VAR".to_owned();
    cfg.agents.watcher.enable = true;
    cfg.agents.watcher.llm.api_key = "cmd:print-it".to_owned();

    let fake = FakeRunner::new();
    // ENV_KEY: exists -> rm -> create.
    fake.push_all([Reply::status(0), Reply::success(), Reply::success()]);
    // CMD_KEY: the shell, then absent -> create.
    fake.push_all([Reply::ok("cmd-value\n"), Reply::status(1), Reply::success()]);

    let env = MapEnv::new().with("HOST_VAR", VALUE);
    let host = SecretHost::new(&fake, &env, true);
    let podman = Podman::new(&fake);
    let skip: BTreeSet<String> = ["SKIPPED".to_string()].into_iter().collect();

    let out = host
        .resolve_and_populate(&podman, &cfg, "acme", temp.path(), &skip, true)
        .unwrap();

    assert_eq!(
        out.resolved.iter().map(String::as_str).collect::<Vec<_>>(),
        ["CMD_KEY", "CRED_KEY", "ENV_KEY"]
    );
    assert!(out.warnings.is_empty());

    fake.assert_argv(&[
        &["podman", "secret", "inspect", "acme.ENV_KEY"],
        &["podman", "secret", "rm", "acme.ENV_KEY"],
        &["podman", "secret", "create", "acme.ENV_KEY", "-"],
        &["/bin/sh", "-c", "print-it"],
        &["podman", "secret", "inspect", "acme.CMD_KEY"],
        &["podman", "secret", "create", "acme.CMD_KEY", "-"],
    ]);
    // `STORE_KEY`, `NO_SOURCE`, `SKIPPED` and both agents produced no
    // calls at all, and `CRED_KEY` was recorded without one.
    assert_eq!(fake.call(2).stdin_text().as_deref(), Some(VALUE));
    for call in fake.calls() {
        argv_is_clean(&call.raw_argv());
    }
    fake.assert_drained();
}

/// The container backend's half of "a relay or agent credential is the
/// secret store's entry NAME, whatever its scheme, on every backend".
///
/// `env:NAME` on an injection rule's `source:` reads the host's
/// environment; on a relay's `auth.*_source` or an agent's `api_key`
/// it names a store entry, like a rule without a `source:`. The relays
/// were already left alone here. The agents were resolved from the host
/// environment: a key that existed only in the store (`secret set`,
/// `-s`) failed `cage create` / `cage start` with "env var not set",
/// and an exported value overwrote the stored one on every start. A
/// `systemd-creds:` key with no `.cred` blob failed the same way, where
/// a relay's went on to the store.
///
/// The vm half is `relay_and_agent_credentials_are_not_read_from_the_host_env_on_vm`
/// in `vm_argv.rs`, and apple-container's is
/// `relay_and_agent_credentials_are_staged_from_the_store_by_name` in
/// `apple/backend.rs`.
#[test]
fn relay_and_agent_credentials_name_the_store_entry_not_the_host_env() {
    use agentcage_core::config::types::ProtocolRelay;

    let mut cfg = common::config("container", "auto", "auto", false);
    let mut relay = ProtocolRelay::default();
    relay.auth.user_source = "env:MAIL_USER".to_owned();
    relay.auth.password_source = "systemd-creds:MAIL_PW".to_owned();
    cfg.protocol_relays.push(relay);
    cfg.agents.decider.enable = true;
    cfg.agents.decider.llm.api_key = "env:DECIDER_KEY".to_owned();
    cfg.agents.watcher.enable = true;
    cfg.agents.watcher.llm.api_key = "systemd-creds:WATCHER_KEY".to_owned();

    // Every name is also a host environment variable, holding a value
    // that must not reach the store.
    let env = MapEnv::new()
        .with("MAIL_USER", VALUE)
        .with("MAIL_PW", VALUE)
        .with("DECIDER_KEY", VALUE)
        .with("WATCHER_KEY", VALUE);
    let fake = FakeRunner::new();
    let host = SecretHost::new(&fake, &env, true);
    let podman = Podman::new(&fake);

    // No `.cred` blobs under the state dir, and strict.
    let temp = TempDir::new("populate-relay-agent");
    let out = host
        .resolve_and_populate(&podman, &cfg, "acme", temp.path(), &BTreeSet::new(), true)
        .expect("the store holds them; nothing here needs the host env");
    assert!(out.resolved.is_empty(), "{:?}", out.resolved);
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    assert_eq!(fake.call_count(), 0, "nothing written to the store");
}

/// `strict=False` collects the failure and carries on; `strict=True`
/// stops at the first one, before any unit is launched with a missing
/// secret.
#[test]
fn a_failed_resolution_is_fatal_or_a_warning_depending_on_strict() {
    use agentcage_core::config::types::SecretInjectionRule;

    let mut cfg = common::config("container", "auto", "auto", false);
    cfg.secret_injection.push(SecretInjectionRule {
        env: "ENV_KEY".to_owned(),
        source: "env:MISSING_VAR".to_owned(),
        ..SecretInjectionRule::default()
    });

    let fake = FakeRunner::new();
    let env = MapEnv::new();
    let host = SecretHost::new(&fake, &env, true);
    let podman = Podman::new(&fake);
    let skip = BTreeSet::new();

    let err = host
        .resolve_and_populate(&podman, &cfg, "acme", Path::new("/x"), &skip, true)
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "failed to resolve secret 'ENV_KEY': env var 'MISSING_VAR' not set"
    );

    let out = host
        .resolve_and_populate(&podman, &cfg, "acme", Path::new("/x"), &skip, false)
        .unwrap();
    assert_eq!(
        out.warnings,
        ["warning: failed to resolve ENV_KEY: env var 'MISSING_VAR' not set"]
    );
    assert!(out.resolved.is_empty());
    assert_eq!(fake.call_count(), 0);
}
