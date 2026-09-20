//! A secret value cannot reach a log line, a debug dump or a panic
//! message — on the surfaces PR D9 adds.
//!
//! `tests/secrets_redaction.rs` (PR D3) makes the same claim about the
//! four *stores*. This file makes it about the two things D9 puts on
//! top of them:
//!
//! 1. **The live staging write**, which is the one new place in the
//!    port that hands a cleartext value to a subprocess. Its only
//!    argument is a path; the value goes on stdin. Asserted through
//!    every rendering `agentcage-exec` can produce, including the
//!    recorded-call dump a failing `assert_argv` prints into a CI log.
//! 2. **`agentcage secret set`, as a process**, from stdin to the
//!    refusal. The value is read into memory, carried through
//!    `resolve_store`, and refused — the path with the most string
//!    formatting per byte of secret anywhere in the command surface.
//!    Nothing it prints, and nothing it leaves on disk, may contain it.
//!
//! The canary is distinctive on purpose: if it ever shows up in a CI
//! transcript, grepping for it finds this file and the leak together.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use agentcage_exec::tools::podman::Podman;
use agentcage_exec::{FakeRunner, Reply};

/// The value that must never appear in rendered text.
const CANARY: &str = "CANARY-d9-2f81b40c-do-not-print";

#[track_caller]
fn no_canary(what: &str, rendered: &str) {
    assert!(
        !rendered.contains(CANARY),
        "{what} leaked the value:\n{rendered}"
    );
}

// ── 1. the staging write ────────────────────────────────────────────

/// `stage_secret_value` puts the path in argv and the value on stdin.
///
/// Both halves are asserted, because only one of them is the security
/// property: proving the value is absent from argv is worth nothing if
/// it never reached the child at all.
#[test]
fn staging_puts_the_value_on_stdin_and_the_path_in_argv() {
    let dir = temp_dir("stage-argv");
    let paths = agentcage_state::Paths::under(&dir);
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push(Reply::success());
    let podman = Podman::new(&fake);

    agentcage_cli::services::stage_secret_value(&podman, &fake, &paths, "acme", "API_KEY", CANARY)
        .expect("the fake exits 0");

    let call = fake.call(0);
    let argv = call.argv();
    assert_eq!(argv[0], "podman");
    assert_eq!(argv[1], "unshare");
    // The last argument is the target path, and the key name is in it —
    // a key name is not a value.
    assert!(
        argv.last()
            .expect("a target path")
            .ends_with("/secrets/API_KEY"),
        "{argv:?}"
    );
    // The value did reach the child.
    assert_eq!(call.stdin_text().as_deref(), Some(CANARY));

    // ...and reached it through nothing that renders.
    no_canary("argv", &argv.join(" "));
    no_canary("raw argv", &call.raw_argv().join(" "));
    no_canary("the recorded call's Debug", &format!("{call:?}"));
    no_canary("the runner's Debug", &format!("{fake:?}"));
    no_canary("the argv sequence", &format!("{:?}", fake.argv_sequence()));

    // The dump a failing argv assertion prints is the likeliest route
    // from a secret to a CI log, so it is exercised deliberately.
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fake.assert_argv(&[&["podman", "deliberately", "wrong"]]);
    }))
    .expect_err("the assertion must fail");
    let message = panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default();
    no_canary("the panic payload from a failing assert_argv", &message);

    // The `Command` value itself, which is what someone reaching for a
    // `dbg!` or a tracing field would render. `Stdin`'s `Debug` is
    // hand-written for exactly this reason.
    let command = agentcage_exec::Command::new("podman").stdin_secret(CANARY.to_owned());
    no_canary("Command's Debug", &format!("{command:?}"));
    no_canary("Command::display", &command.display());
    no_canary("Command::argv_redacted", &command.argv_redacted().join(" "));

    let _ = std::fs::remove_dir_all(&dir);
}

// ── 2. `secret set`, as a process ───────────────────────────────────

/// The refusal path, end to end.
///
/// `secrets.backend: keychain` on a Linux host is a store that cannot
/// exist, so `resolve_store` refuses *after* the value has been read
/// from stdin. What is asserted is everything observable afterwards:
/// both streams, and every byte under the sandboxed home.
#[test]
fn secret_set_refusing_a_store_prints_and_writes_nothing_of_the_value() {
    let home = temp_dir("set-refusal");
    write_cage(&home, "canary", "keychain");

    let out = secret_set(&home, "canary", "API_KEY", CANARY);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("refusing to store secret 'API_KEY'"),
        "{stderr}"
    );
    // A panic would be a leak in itself: the payload is built from
    // whatever was in scope.
    assert!(!stderr.contains("panicked at"), "{stderr}");

    no_canary("stdout", &stdout);
    no_canary("stderr", &stderr);
    for (path, text) in read_tree(&home) {
        no_canary(&format!("the file {}", path.display()), &text);
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// The same for the command that reads no value at all.
///
/// `secret set` on a cage that does not exist must not echo back
/// whatever was on stdin — including when nothing ever consumed it.
#[test]
fn secret_set_on_a_missing_cage_does_not_echo_stdin() {
    let home = temp_dir("set-missing");
    let out = secret_set(&home, "nosuch", "API_KEY", CANARY);
    assert_eq!(out.status.code(), Some(1));
    no_canary("stdout", &String::from_utf8_lossy(&out.stdout));
    no_canary("stderr", &String::from_utf8_lossy(&out.stderr));
    let _ = std::fs::remove_dir_all(&home);
}

/// `secret list` reports names, statuses and placeholders — and asks
/// the store for none of the three.
///
/// A placeholder *is* printed, and must be: it is the decoy the
/// workload sees, and an operator who cannot read it back cannot tell
/// which token a rule is using. The check is that the declared value's
/// key is listed while the listing itself never grows a value column.
#[test]
fn secret_list_prints_placeholders_and_never_values() {
    let home = temp_dir("list");
    write_cage(&home, "canary", "plaintext");
    // Put the canary where a careless implementation might find it: in
    // the cage's own state directory, as the plaintext store's file.
    let creds = home
        .join(".config/agentcage/cages/canary")
        .join("pending_secrets.json");
    std::fs::write(&creds, format!("[[\"API_KEY\", \"{CANARY}\"]]")).expect("write");

    let out = agentcage(&home, &["secret", "list", "canary"]);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stdout.contains("API_KEY"), "{stdout}{stderr}");
    assert!(stdout.contains("PLACEHOLDER"), "{stdout}");
    no_canary("stdout", &stdout);
    no_canary("stderr", &stderr);
    let _ = std::fs::remove_dir_all(&home);
}

// ── plumbing ────────────────────────────────────────────────────────

fn temp_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("agentcage-d9-{label}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&path).expect("temp dir");
    path
}

/// A minimal container cage in a sandboxed home, with `backend` chosen
/// by the caller.
fn write_cage(home: &Path, name: &str, backend: &str) {
    let dir = home.join(".config/agentcage/cages").join(name);
    std::fs::create_dir_all(&dir).expect("state dir");
    std::fs::write(
        dir.join("cage.yaml"),
        format!(
            "name: {name}\n\
             container:\n  \
               image: \"docker.io/library/alpine:3\"\n  \
               command: [\"true\"]\n\
             secrets:\n  \
               backend: {backend}\n\
             secret_injection:\n  \
               - env: API_KEY\n    \
                 placeholder: \"{{{{API_KEY}}}}\"\n"
        ),
    )
    .expect("cage.yaml");
    std::fs::write(
        dir.join("metadata.json"),
        format!("{{\"agentcage_version\": \"{}\"}}", agentcage_core::VERSION),
    )
    .expect("metadata.json");
}

fn agentcage(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agentcage"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_RUNTIME_DIR", home.join("run"))
        .stdin(Stdio::null())
        .output()
        .expect("the binary is built by `cargo test`")
}

/// `printf '<value>' | agentcage secret set <cage> <key>` — the shape
/// the command is meant to be used in.
fn secret_set(home: &Path, cage: &str, key: &str, value: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentcage"))
        .args(["secret", "set", cage, key])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_RUNTIME_DIR", home.join("run"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary is built by `cargo test`");
    child
        .stdin
        .as_mut()
        .expect("piped")
        .write_all(value.as_bytes())
        .expect("write the value");
    child.wait_with_output().expect("wait")
}

/// Every readable file under `root`, as (path, text).
fn read_tree(root: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => stack.push(path),
                Ok(kind) if kind.is_file() => {
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        found.push((path, text));
                    }
                }
                _ => {}
            }
        }
    }
    found
}
