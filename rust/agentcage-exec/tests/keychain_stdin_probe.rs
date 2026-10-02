//! The test that settled the keychain argv exposure, and the Mac it
//! needs.
//!
//! It ran on 2026-10-02 and PR D1 shipped its answer. It stays here as
//! the regression check: it is the only test in the workspace that can
//! tell you the *keychain* received the exact bytes, as opposed to that
//! the command was built correctly.
//!
//! # The finding
//!
//! `KeychainStore.set` used to be the only place in agentcage where
//! secret material travelled in argv:
//!
//! ```text
//! security add-generic-password -s agentcage -a <cage>.<KEY> -w <CLEARTEXT> -U
//! ```
//!
//! For the life of that child the credential was in `ps -axww` output,
//! readable by any process of the same user and by root. Every other
//! secret path in the project uses stdin. PR D1 found it, reproduced it
//! and marked the argument so it is redacted from everything the
//! workspace prints; PR D3 preserved that; PR E2b built the fix behind
//! a seam without shipping it; PR D1 ran this probe and flipped the
//! seam.
//!
//! # What the two arms establish
//!
//! **The refuted candidate**, asserted from Apple's shipping source
//! first and then watched: a bare `-w` with the value piped to stdin
//! does not work. `keychain_add.c` routes a missing `-w` argument to
//! `getpass(3)`, which is `readpassphrase(..., RPP_ECHO_OFF)`, which
//! opens `/dev/tty` and only falls back to stdin when the process has
//! no controlling terminal at all. It prompts *twice*. And on EOF it
//! returns an empty string that passes its own confirmation check, so
//! `security` stores an empty password and exits 0. On the run that
//! settled this it did something worse than that: it exited 0 having
//! stored the literal string `-U`, read from the next flag. The module
//! docs in [`agentcage_exec::tools::security`] carry the citations.
//!
//! **The shipped channel**: `security -i` -- command lines on stdin,
//! split in process, dispatched to the same handler, with the kernel's
//! argv left as `security -i`. The argv is right by construction. What
//! a Linux box cannot check is whether the *keychain* ends up holding
//! the exact bytes: the quoting is ours, and `split_line` treats `\` as
//! an escape inside single quotes where a POSIX shell would not. Both
//! round trips were exact, including a value carrying both quote
//! characters, a backslash and a doubled backslash.
//!
//! # Running it
//!
//! ```sh
//! cargo test -p agentcage-exec --test keychain_stdin_probe -- --ignored --nocapture
//! ```
//!
//! on a Mac with an unlocked login keychain. It is `#[ignore]`d rather
//! than `#[cfg(target_os = "macos")]`d on purpose: a `cfg` would make
//! it invisible on the machines that can actually run it, whereas an
//! `#[ignore]` with a reason prints on **every** `cargo test` run in
//! this workspace, including CI's.
//!
//! It writes to throwaway accounts in the login keychain's `agentcage`
//! service and deletes them again, on every path including the failures.
//! It never touches a real cage's items and it never runs `sudo`.
//!
//! # If it ever disagrees
//!
//! That is a real finding, not a flake: it would mean the quoting and
//! the keychain have diverged on some host or OS version. Record what
//! it printed in
//! [`agentcage_exec::tools::security::AddPassword::how_it_was_settled`],
//! which is also what this probe prints, so the next person compares
//! against the last run rather than against nothing.

use std::time::Duration;

use agentcage_exec::tools::security::{
    AddPassword, KeychainTarget, PasswordChannel, SERVICE, Security,
};
use agentcage_exec::{Command, CommandRunner, ExecError, Output, SystemRunner};

/// The throwaway account the `-i` round trip uses. Not `PROBE_ACCOUNT`:
/// the availability probe owns that one, and a concurrent `cage secret
/// set` must not collide with this.
const ACCOUNT: &str = "__agentcage_i_probe__";

/// The account the refuted bare-`-w` arm uses.
const BARE_W_ACCOUNT: &str = "__agentcage_barew_probe__";

/// The plain value. Shaped so a stray copy in a log is obviously a test
/// artifact, and free of whitespace at the ends -- a value that already
/// ended in a newline would confuse the answer.
const VALUE: &str = "TEST-NOT-A-REAL-SECRET-0042";

/// The value that decides the quoting. Every character `split_line`
/// gives a meaning to: both quote characters, a backslash, a space.
const AWKWARD: &str = r#"TEST-NOT-A-REAL-SECRET a'b"c\d\\e 'f' "g""#;

/// How long a command gets before we call it a prompt.
///
/// A `security` that reads its pipe answers immediately. One that opens
/// `/dev/tty` either fails fast or blocks forever waiting for a human.
/// The timeout turns the second case into a finding instead of a hung
/// suite.
const PATIENCE: Duration = Duration::from_secs(10);

fn forget(account: &str) {
    let _ = SystemRunner.run(
        &Security::delete_command(&KeychainTarget::login(), account)
            .captured()
            .timeout(PATIENCE),
    );
}

fn cleanup() {
    forget(ACCOUNT);
    forget(BARE_W_ACCOUNT);
}

/// Read an account back, with `security`'s own line terminator taken
/// off and nothing else. `None` when there is no such item.
fn read_back(account: &str) -> Option<String> {
    let out = SystemRunner
        .run(
            &Security::find_command(&KeychainTarget::login(), account)
                .captured()
                .timeout(PATIENCE),
        )
        .expect("find-generic-password");
    if !out.success() {
        return None;
    }
    let text = out.stdout_text();
    Some(text.strip_suffix('\n').unwrap_or(&text).to_string())
}

/// One `security -i` round trip. Returns what the keychain ended up
/// holding.
fn round_trip(value: &str) -> String {
    let add = Security::add_command_via(
        PasswordChannel::Interactive,
        &KeychainTarget::login(),
        ACCOUNT,
        value,
    )
    .expect("the interactive channel accepts this value")
    .captured()
    .timeout(PATIENCE);

    // Nothing secret in the argv is the entire point; assert it before
    // running, so a probe that somehow shelled out with the value in
    // argv is a failure rather than a pass.
    assert_eq!(
        add.argv(),
        ["security", "-i"],
        "the interactive channel must put nothing but `-i` in argv"
    );

    match SystemRunner.run(&add) {
        Ok(out) if out.success() => {}
        Err(ExecError::Timeout { .. }) => {
            cleanup();
            panic!(
                "`security -i` waited {PATIENCE:?} for something that was not on \
                 the pipe.\n\
                 VERDICT: leave SHIPPED_PASSWORD_CHANNEL on Argv and record this. \
                 Next thing to try: SecItemAdd through the Security framework.\n\n{}",
                AddPassword::how_it_was_settled()
            );
        }
        Err(other) => {
            cleanup();
            panic!("could not run `security`: {other}");
        }
        Ok(out) => {
            let stderr = out.stderr_text();
            cleanup();
            assert!(
                !stderr.contains(value),
                "`security` echoed the secret to stderr -- the line was \
                 truncated and the remainder parsed as a command. VERDICT: \
                 leave SHIPPED_PASSWORD_CHANNEL on Argv."
            );
            panic!(
                "`security -i` refused the add: {stderr}\n\
                 VERDICT: if this says the login keychain is locked or that \
                 interaction is not allowed, unlock it in a GUI session and run \
                 again -- that is not an answer to the question. Anything else \
                 means the interactive channel does not work as written; leave \
                 SHIPPED_PASSWORD_CHANNEL on Argv.\n\n{}",
                AddPassword::how_it_was_settled()
            );
        }
    }

    let stored = read_back(ACCOUNT).unwrap_or_else(|| {
        cleanup();
        panic!(
            "`security -i` exited 0 and the item is not there.\n\
             VERDICT: leave SHIPPED_PASSWORD_CHANNEL on Argv."
        )
    });
    forget(ACCOUNT);
    stored
}

/// The control arm, and the refutation.
///
/// Piped to a bare `-w`. Apple's source says this reads `/dev/tty`
/// where one exists and stores an **empty password, exiting 0** where
/// one does not. Running it here turns a claim about source into an
/// observation on the machine that matters -- and if it ever comes back
/// clean, that is worth knowing too.
fn bare_w_piped() -> (Result<Output, ExecError>, Option<String>) {
    let out = SystemRunner.run(
        &Command::new("security")
            .args([
                "add-generic-password",
                "-s",
                SERVICE,
                "-a",
                BARE_W_ACCOUNT,
                "-w",
                "-U",
            ])
            .stdin_secret(format!("{VALUE}\n{VALUE}\n"))
            .captured()
            .timeout(PATIENCE),
    );
    let stored = if out.as_ref().is_ok_and(Output::success) {
        read_back(BARE_W_ACCOUNT)
    } else {
        None
    };
    forget(BARE_W_ACCOUNT);
    (out, stored)
}

#[test]
#[ignore = "REGRESSION CHECK, needs macOS and a real security(1) -- \
            re-verifies that the shipped `security -i` channel carries the \
            password on stdin exactly, quoting included; settled 2026-10-02, \
            run with --ignored on a Mac"]
fn the_interactive_channel_round_trips_through_a_real_keychain() {
    // Not a `cfg` on the function: the test has to *exist* on Linux so
    // the `#[ignore]` reason prints there. Run it with `--ignored` off
    // a Mac and it says why it cannot help.
    assert_eq!(
        std::env::consts::OS,
        "macos",
        "this probe needs a real macOS `security(1)`; there is nothing \
         useful it can learn anywhere else, and a fake runner cannot \
         answer the question it exists to ask.\n\n{}",
        AddPassword::how_it_was_settled()
    );

    cleanup();
    let plain = round_trip(VALUE);
    let awkward = round_trip(AWKWARD);
    let (bare_w, bare_w_stored) = bare_w_piped();
    cleanup();

    println!("\n-- keychain password channel probe ---------------");
    println!("  -i, plain value");
    println!("      wrote     : {VALUE:?}");
    println!("      read back : {plain:?}");
    println!("  -i, quotes and backslashes");
    println!("      wrote     : {AWKWARD:?}");
    println!("      read back : {awkward:?}");
    println!("  bare -w, two lines piped (expected to be a trap)");
    println!("      outcome   : {bare_w:?}");
    println!("      read back : {bare_w_stored:?}");
    println!("--------------------------------------------------\n");

    // The refutation, observed rather than argued. Not an assertion on
    // the outcome -- any of hang, refusal or empty-password is a "do
    // not use this", and which one you get depends on whether the
    // runner has a controlling terminal.
    if bare_w_stored.as_deref() == Some(VALUE) {
        println!(
            "NOTE: on this host a bare `-w` did read the pipe correctly. That \
             contradicts nothing -- getpass(3) falls back to stdin when \
             /dev/tty cannot be opened, so this runner has no controlling \
             terminal. It is still not a fix: on a Mac with a terminal the \
             same command reads the terminal instead, and on EOF it stores an \
             empty password and exits 0."
        );
    }

    assert_eq!(
        plain,
        VALUE,
        "the plain round trip did not come back -- the shipped channel does \
         not work on this host.\n\
         VERDICT: a real regression. Do not reach for a bare `-w`; see below.\n\n{}",
        AddPassword::how_it_was_settled()
    );
    assert_eq!(
        awkward, AWKWARD,
        "the quoting is wrong: a value with quotes and backslashes did not \
         survive `security -i`'s split_line.\n\
         VERDICT: fix AddPassword::quote and `KeychainStore._quote` in \
         secret_store.py together, and run this again -- a quoting bug here \
         stores the wrong secret silently."
    );

    println!(
        "VERDICT: `security -i` carries the password on stdin exactly, quoting \
         included -- same as the run that settled this on 2026-10-02. The \
         shipped channel (SHIPPED_PASSWORD_CHANNEL, and KeychainStore.set in \
         secret_store.py) is confirmed on this host."
    );
}
