//! The subprocess seam.
//!
//! # Why this crate exists
//!
//! agentcage is a subprocess orchestrator. Almost everything it does is
//! ultimately `podman ...`, `systemctl --user ...`, `limactl ...`,
//! `container ...`, `skopeo ...`, `security ...` or `systemd-creds ...`,
//! and the interesting part of nearly every function is *which argv it
//! builds*.
//!
//! The Python suite tests that by monkeypatching `subprocess.run` and
//! poking at the recorded call. `tests/test_apple_container.py` alone
//! has 217 `monkeypatch` calls. That technique does not port to Rust,
//! and it should not: patching a module attribute asserts that a
//! particular *function* was called, whereas argv is the actual contract
//! with podman and systemd. A test that pins argv keeps working when the
//! code around it is refactored, and stops working when the contract
//! changes -- which is the behaviour you want from a test.
//!
//! So: one trait, [`CommandRunner`], with a real implementation
//! ([`SystemRunner`]) and a recording fake ([`FakeRunner`]). Everything
//! that shells out takes a `&dyn CommandRunner`.
//!
//! # Where it lives, and why not somewhere else
//!
//! `agentcage-core` is pure by construction -- no subprocesses, no I/O
//! beyond asset extraction -- because that purity is what lets the
//! golden corpus test it by fixture diff. This cannot go there.
//!
//! `agentcage-cli` was the other candidate, and it is the wrong one for
//! a mechanical reason: it is a `[[bin]]` with no library target, so a
//! module inside it is reachable only from `#[cfg(test)]` blocks in the
//! binary itself. The deliverable here *is* a test surface -- the
//! recording fake -- and D2, D3 and every PR in Track E need it from
//! their own tests. A crate is the only shape that gives it to them
//! without a `#[path]` include or a `lib.rs` bolted onto the binary.
//!
//! The crate boundary also does real work: `agentcage-core` does not
//! depend on this crate, so "core stays pure" is a fact `cargo` checks
//! rather than a convention a reviewer has to remember.
//!
//! # What the trait can express
//!
//! The Python it replaces uses a wide slice of `subprocess`, and the
//! trait has to cover all of it or callers will reach around it:
//!
//! | Python                                        | here |
//! | :-- | :-- |
//! | `subprocess.run(cmd)`                         | [`Command`] with inherited stdio (the default) |
//! | `subprocess.run(cmd, capture_output=True)`    | [`Command::captured`] |
//! | `subprocess.run(cmd, check=True)`             | [`Output::check`] -- the runner never treats a non-zero exit as an error |
//! | `subprocess.run(cmd, input=value)`            | [`Command::stdin_secret`] / [`Command::stdin_text`] |
//! | `subprocess.run(cmd, stdin=f)`                | [`Command::stdin_file`] |
//! | `subprocess.run(cmd, stdout=f)`               | [`Command::stdout_file`] |
//! | `subprocess.run(cmd, stderr=subprocess.STDOUT)` | [`Command::merge_stderr`] |
//! | `subprocess.run(cmd, timeout=30)`             | [`Command::timeout`] |
//! | `subprocess.run(cmd, start_new_session=True)` | [`Command::new_process_group`] |
//! | `subprocess.Popen(cmd, stdout=PIPE)` + iterate | [`CommandRunner::stream`] -> [`LineStream`] |
//! | `proc.terminate()`                            | [`LineStream::terminate`] |
//! | `shutil.which("systemctl")`                   | [`CommandRunner::which`] |
//! | `FileNotFoundError` vs a non-zero exit        | [`ExecError::NotFound`] vs [`Output::status`] |
//!
//! Two of those rows are the ones worth arguing about.
//!
//! **A non-zero exit is not an error.** `podman image exists` answers by
//! exiting 1; `podman network rm` answering 1 is how a cage that was
//! already torn down looks. If the runner returned `Err` for those, every
//! caller would immediately unwrap it back into a status. So [`run`]
//! returns `Ok(Output)` for any process that ran, and `Err` only when the
//! process could not be run at all. `check=True` becomes an explicit
//! [`Output::check`], which is exactly where the Python puts it.
//!
//! [`run`]: CommandRunner::run
//!
//! **"Binary missing" is a distinct outcome.** `registry.py` catches
//! `FileNotFoundError` from `skopeo` and prints an install hint while
//! returning `None`; `apple_container/cli.py` raises its own
//! `FileNotFoundError` with a download URL; `systemd.py` turns every
//! function into a no-op when `systemctl` is not on `PATH`. Those three
//! behaviours all hinge on the same distinction, so it is a variant:
//! [`ExecError::NotFound`], with [`ExecError::is_not_found`] for the
//! callers that only care about the one bit.
//!
//! # Streaming is not an afterthought
//!
//! Most invocations are captured, but not all of them, and the ones that
//! are not would be ruined by forcing them into a captured shape:
//!
//! * `cage exec` / `cage shell` hand the terminal to the child. That is
//!   [`Command`] with all three streams inherited -- the default. The
//!   termios save/restore around it is D4's `terminal` module, not this
//!   crate's business; this crate only needs to not get in the way, which
//!   it does by making inherit the default rather than an opt-out.
//! * `podman build` (non-quiet), `podman pull`, `limactl start` and
//!   friends stream progress to the operator's terminal and are checked
//!   only on exit status. Same shape.
//! * `cage logs --level=warn` and every `cage audit` path run the child
//!   under a pipe and filter it line by line while it is still running,
//!   then `terminate()` it. That is [`CommandRunner::stream`], which
//!   hands back a [`LineStream`] rather than a finished [`Output`].
//!
//! # Environment and working directory
//!
//! [`Command`] carries `env` and `cwd` as fields, so they are part of
//! what [`FakeRunner`] records and part of what a test can assert. The
//! Python host code happens not to use either today -- it mutates
//! `os.environ` in-process or relies on the inherited cwd -- which is
//! precisely why they belong on the recorded struct now: the first
//! caller that needs one will otherwise reach for a side channel the
//! fake cannot see.
//!
//! # Secret hygiene
//!
//! The project rule is that secret material goes on stdin, never in
//! argv, because argv is world-readable through `/proc/<pid>/cmdline`
//! and `ps`. The Python honours that in every place but one --
//! `secret_store.py`'s `KeychainStore` passes the cleartext as
//! `security add-generic-password ... -w <value>`. See
//! [`tools::security`] for the detail and for what this crate does about
//! it.
//!
//! Two mechanisms here:
//!
//! * [`Command::stdin_secret`] marks a stdin payload as secret. Its
//!   `Debug` prints a byte count, never the bytes, so a payload cannot
//!   reach a panic message or a log line by accident.
//! * [`Command::secret_arg`] marks an *argument* as secret. It does not
//!   make argv safe -- nothing can -- but it keeps the value out of
//!   `Debug` output, and it puts a visible marker at the call site of
//!   every place that violates the rule, so the violations can be
//!   counted rather than discovered.
//!
//! [`FakeRunner`] inherits both: a recorded call's `Debug` is redacted,
//! and a test that genuinely wants to assert on a secret has to ask for
//! it by name ([`RecordedCall::stdin_bytes`],
//! [`RecordedCall::raw_argv`]). The default path -- an `assert_eq!` on
//! argv that fails and dumps the recorded calls -- cannot leak one.
//!
//! # Layout
//!
//! * [`command`] -- [`Command`] and its stdio/env description.
//! * [`outcome`] -- [`Output`], [`ExitStatus`], [`ExecError`].
//! * [`runner`] -- the [`CommandRunner`] and [`LineStream`] traits.
//! * [`system`] -- [`SystemRunner`], the one that really forks.
//! * [`fake`] -- [`FakeRunner`], the recording fake.
//! * [`tools`] -- one module per binary agentcage drives.

pub mod command;
pub mod fake;
pub mod outcome;
pub mod runner;
pub mod system;
pub mod tools;

pub use command::{Command, Sink, Stdin};
pub use fake::{FakeRunner, RecordedCall, Reply};
pub use outcome::{ExecError, ExitStatus, Output};
pub use runner::{CommandRunner, LineStream};
pub use system::SystemRunner;
pub use tools::Elevation;
