//! Every command a secret store or the resolver runs, pinned by argv.
//!
//! This is the contract with `systemd-creds`, `podman` and
//! `security`. A test that only checked "a command ran" would pass
//! after a dropped `--user`, a missing `-`, or a value that moved from
//! stdin into argv -- which are exactly the three mistakes this module
//! is most able to make.
//!
//! Every test that involves a credential asserts two things about it:
//! the argv it is *not* in, and the stdin it *is* in. The one exception
//! is [`the_keychain_add_puts_the_cleartext_in_argv`], which asserts the
//! opposite because that is what the code being ported does; see its
//! doc comment.

mod common;

use std::collections::BTreeSet;
use std::path::Path;

use agentcage_cli::secrets::{
    ApplePlaintextStore, KeychainStore, MapEnv, PlaintextStore, Platform, SecretHost, SecretStore,
    SystemdCredsStore,
};
use agentcage_exec::tools::podman::Podman;
use agentcage_exec::{FakeRunner, Reply};

use common::TempDir;

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
    assert_eq!(
        fake.argv(1),
        [
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
        ]
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
        ["security", "add-generic-password"],
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

/// **The finding, pinned.**
///
/// `secret_store.py:226` passes the cleartext as `-w <value>`, where it
/// is readable from the process table by any process of the same user
/// and by root for the life of the child. It is the only such path in
/// the code being ported; every other one uses stdin. PR D1 found it,
/// reproduced it, and marked the argument with `Command::secret_arg` so
/// it is redacted from every `Debug`, `Display` and recorded-call dump
/// in the workspace. **This test asserts the exposure is still exactly
/// where it was.**
///
/// It is not fixed here. The obvious fix -- a bare `-w` with the value
/// on stdin -- depends on what `security(1)` does with a non-tty stdin,
/// which is undocumented and can only be settled on a Mac. PR E2b owns
/// the keychain and the hardware; changing the argv on a Linux box
/// against no test that can run it would be a guess dressed as a fix.
/// If this test ever fails, either someone fixed it (delete the test,
/// and say so in the PR) or someone moved the value by accident.
#[test]
fn the_keychain_add_puts_the_cleartext_in_argv() {
    let temp = TempDir::new("keychain-set");
    let fake = FakeRunner::new();
    fake.push(Reply::success()); // probe add
    fake.push(Reply::success()); // probe delete
    fake.push(Reply::success()); // the real add
    let store = KeychainStore::new(&fake, Platform::MacOs);

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
    // ...and nothing that prints a command prints it.
    assert_eq!(add.argv()[7], "<redacted>");
    assert!(!format!("{add:?}").contains(VALUE));
    assert!(!add.command.display().contains(VALUE));
    assert!(
        !fake
            .argv_sequence()
            .iter()
            .flatten()
            .any(|a| a.contains(VALUE))
    );
    // The value is not on stdin either: this is the argv path, whole.
    assert_eq!(add.stdin_bytes(), None);

    // The index gained the key, and it is not a value store.
    assert_eq!(store.names("acme", temp.path()).unwrap(), ["API_KEY"]);
    assert_eq!(
        std::fs::read_to_string(KeychainStore::index_path(temp.path())).unwrap(),
        r#"["API_KEY"]"#
    );
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

/// `resolve_and_populate` over one rule of every shape, plus both
/// agents, in one sequence.
///
/// The agents are in this function for a reason worth restating: their
/// `api_key` is not a `secret_injection` rule, but the quadlet
/// generator emits a `Secret=` directive for each on the strength of
/// this function materializing it. Miss them and the egress unit
/// references a podman secret nobody created, dies at start with
/// `no such secret`, and takes the cage with it.
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
    // agents.decider's api_key names HOST_VAR, which nothing has
    // resolved yet under that name.
    fake.push_all([Reply::status(1), Reply::success()]);
    // agents.watcher's names `print-it`, likewise.
    fake.push_all([
        Reply::ok("watcher-value\n"),
        Reply::status(1),
        Reply::success(),
    ]);

    let env = MapEnv::new().with("HOST_VAR", VALUE);
    let host = SecretHost::new(&fake, &env, true);
    let podman = Podman::new(&fake);
    let skip: BTreeSet<String> = ["SKIPPED".to_string()].into_iter().collect();

    let out = host
        .resolve_and_populate(&podman, &cfg, "acme", temp.path(), &skip, true)
        .unwrap();

    assert_eq!(
        out.resolved.iter().map(String::as_str).collect::<Vec<_>>(),
        ["CMD_KEY", "CRED_KEY", "ENV_KEY", "HOST_VAR", "print-it"]
    );
    assert!(out.warnings.is_empty());

    fake.assert_argv(&[
        &["podman", "secret", "inspect", "acme.ENV_KEY"],
        &["podman", "secret", "rm", "acme.ENV_KEY"],
        &["podman", "secret", "create", "acme.ENV_KEY", "-"],
        &["/bin/sh", "-c", "print-it"],
        &["podman", "secret", "inspect", "acme.CMD_KEY"],
        &["podman", "secret", "create", "acme.CMD_KEY", "-"],
        &["podman", "secret", "inspect", "acme.HOST_VAR"],
        &["podman", "secret", "create", "acme.HOST_VAR", "-"],
        &["/bin/sh", "-c", "print-it"],
        &["podman", "secret", "inspect", "acme.print-it"],
        &["podman", "secret", "create", "acme.print-it", "-"],
    ]);
    // `STORE_KEY`, `NO_SOURCE` and `SKIPPED` produced no calls at all,
    // and `CRED_KEY` was recorded without one.
    assert_eq!(fake.call(2).stdin_text().as_deref(), Some(VALUE));
    for call in fake.calls() {
        argv_is_clean(&call.raw_argv());
    }
    fake.assert_drained();
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
