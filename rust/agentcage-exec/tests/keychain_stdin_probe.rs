//! The one test that can settle `secret_store.py:226`, and the Mac it
//! needs.
//!
//! # The finding
//!
//! `KeychainStore.set` is the only place in agentcage where secret
//! material travels in argv:
//!
//! ```text
//! security add-generic-password -s agentcage -a <cage>.<KEY> -w <CLEARTEXT> -U
//! ```
//!
//! For the life of that child the credential is in `ps -axww` output,
//! readable by any process of the same user and by root. Every other
//! secret path in the project uses stdin. PR D1 found it, reproduced it
//! and marked the argument so it is redacted from everything the
//! workspace prints; PR D3 preserved that; PR E2b -- this one -- built
//! the fix behind a seam and did **not** ship it.
//!
//! # What is already settled, and what is not
//!
//! **Settled, from Apple's shipping source.** The obvious candidate --
//! a bare `-w` with the value piped to stdin -- does not work.
//! `keychain_add.c` routes a missing `-w` argument to `getpass(3)`,
//! which is `readpassphrase(..., RPP_ECHO_OFF)`, which opens
//! `/dev/tty` and only falls back to stdin when the process has no
//! controlling terminal at all. It prompts *twice*. And on EOF it
//! returns an empty string that passes its own confirmation check, so
//! `security` stores an empty password and exits 0. The module docs in
//! [`agentcage_exec::tools::security`] carry the citations.
//!
//! **Not settled.** `security -i` -- command lines on stdin, split in
//! process, dispatched to the same handler, with the kernel's argv left
//! as `security -i`. The argv is right by construction. What a Linux
//! box cannot check is whether the *keychain* ends up holding the exact
//! bytes: the quoting is ours, and `split_line` treats `\` as an escape
//! inside single quotes where a POSIX shell would not. One round trip
//! against a real keychain settles it. That is this file.
//!
//! # Running it
//!
//! ```sh
//! cargo test -p agentcage-exec --test keychain_stdin_probe -- --ignored --nocapture
//! ```
//!
//! on a Mac with an unlocked login keychain. It is `#[ignore]`d rather
//! than `#[cfg(target_os = "macos")]`d on purpose: a `cfg` would make
//! it invisible on the machines where the decision is pending, whereas
//! an `#[ignore]` with a reason prints on **every** `cargo test` run in
//! this workspace, including CI's. The decision announces itself.
//!
//! It writes to throwaway accounts in the login keychain's `agentcage`
//! service and deletes them again, on every path including the failures.
//! It never touches a real cage's items and it never runs `sudo`.
//!
//! # What to do with the answer
//!
//! [`agentcage_exec::tools::security::AddPassword::how_to_settle_it`]
//! spells it out. In short: if every round trip is exact, change
//! `SHIPPED_PASSWORD_CHANNEL` to `PasswordChannel::Interactive` and
//! mirror it onto `secret_store.py:226`. If it is not, leave the
//! exposure alone and write down what happened.

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
                AddPassword::how_to_settle_it()
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
                AddPassword::how_to_settle_it()
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
#[ignore = "PENDING DECISION: needs macOS and a real security(1) -- \
            settles whether `security -i` can carry the password on stdin \
            and close the one cleartext argv in the project \
            (secret_store.py:226); run with --ignored on a Mac"]
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
        AddPassword::how_to_settle_it()
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
        "the plain round trip did not come back.\n\
         VERDICT: leave SHIPPED_PASSWORD_CHANNEL on Argv.\n\n{}",
        AddPassword::how_to_settle_it()
    );
    assert_eq!(
        awkward, AWKWARD,
        "the quoting is wrong: a value with quotes and backslashes did not \
         survive `security -i`'s split_line.\n\
         VERDICT: fix AddPassword::quote and run this again. Do not flip \
         SHIPPED_PASSWORD_CHANNEL until this passes -- a quoting bug here \
         stores the wrong secret silently."
    );

    println!(
        "VERDICT: `security -i` carries the password on stdin exactly, quoting \
         included. Change SHIPPED_PASSWORD_CHANNEL in \
         rust/agentcage-exec/src/tools/security.rs to \
         PasswordChannel::Interactive, delete the \
         `the_shipped_channel_is_still_argv` and \
         `the_keychain_add_puts_the_cleartext_in_argv` pins, and mirror the \
         change onto secret_store.py:226."
    );
}
