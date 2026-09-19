//! [`FakeRunner`]: the recording fake that replaces 217 `monkeypatch`
//! calls.
//!
//! # What it has to do
//!
//! Three things, and a test that cannot do all three is worse than no
//! test:
//!
//! 1. **Assert the full argv sequence.** Not "podman was called" but
//!    "these five commands, in this order, with these flags". That is
//!    the contract with podman; anything weaker passes when a flag is
//!    dropped. [`FakeRunner::assert_argv`].
//! 2. **Stub per-invocation results.** A `cage destroy` run is a dozen
//!    calls whose outcomes differ -- the network removes cleanly, the
//!    volume does not exist, the secret list is empty. A single canned
//!    answer cannot express that. [`FakeRunner::push`] queues one reply
//!    per call, in order; [`FakeRunner::on`] answers a repeated probe by
//!    argv prefix.
//! 3. **Fail loudly on an unexpected call.** A fake that quietly returns
//!    exit 0 for a command the test did not anticipate will pass a test
//!    for code that shells out to something new -- which is exactly the
//!    regression argv assertions exist to catch. An unstubbed call
//!    panics, and the panic names the argv.
//!
//! # Secret hygiene
//!
//! An argv assertion failure prints the recorded calls. If the fake kept
//! secrets in that dump, `cargo test` output and CI logs would be a
//! credential channel -- so [`RecordedCall`]'s `Debug`, and
//! [`FakeRunner::argv_sequence`], are redacted. A test that genuinely
//! needs the value asks for it by name: [`RecordedCall::raw_argv`],
//! [`RecordedCall::stdin_bytes`]. See [`crate::tools::security`] for the
//! one place that needs to.
//!
//! # Example
//!
//! ```
//! use agentcage_exec::{Command, CommandRunner, FakeRunner, Reply};
//!
//! let fake = FakeRunner::new();
//! fake.push(Reply::ok("running\n"));
//!
//! let out = fake
//!     .run(&Command::new("podman").args(["inspect", "c"]).captured())
//!     .unwrap();
//!
//! assert_eq!(out.stdout_trimmed(), "running");
//! fake.assert_argv(&[&["podman", "inspect", "c"]]);
//! fake.assert_drained();
//! ```

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::command::Command;
use crate::outcome::{ExecError, ExitStatus, Output};
use crate::runner::{CommandRunner, LineStream};

/// What the fake should do for one invocation.
///
/// `Clone`, which is why the error cases are variants rather than a
/// wrapped [`ExecError`]: an [`FakeRunner::on`] rule answers any number
/// of calls, and [`ExecError`] carries an `io::Error` that cannot be
/// cloned. The variants here are the ones a test has any reason to
/// simulate -- a missing binary, an unexecutable one, a timeout. A
/// `Spawn` or `Io` error is the kernel having a bad day, not a branch
/// agentcage takes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Reply {
    /// The process ran and finished like this.
    Ran(Output),
    /// The binary is not installed: [`ExecError::NotFound`].
    NotFound,
    /// The binary cannot be executed: [`ExecError::PermissionDenied`].
    PermissionDenied,
    /// The process outlived its timeout: [`ExecError::Timeout`].
    TimedOut,
}

impl Reply {
    /// Exit 0 with this stdout.
    #[must_use]
    pub fn ok(stdout: impl Into<Vec<u8>>) -> Self {
        Self::Ran(Output::ok(stdout))
    }

    /// Exit 0 with no output.
    #[must_use]
    pub fn success() -> Self {
        Self::Ran(Output::ok(""))
    }

    /// This exit code, with no output.
    ///
    /// The `podman image exists` / `podman volume exists` shape: the
    /// answer is the status and nothing else.
    #[must_use]
    pub fn status(code: i32) -> Self {
        Self::Ran(Output {
            status: ExitStatus::exited(code),
            ..Output::default()
        })
    }

    /// This exit code and this stderr.
    #[must_use]
    pub fn failed(code: i32, stderr: impl Into<Vec<u8>>) -> Self {
        Self::Ran(Output::failed(code, stderr))
    }

    /// Exit 0 with these lines on stdout, newline-terminated.
    ///
    /// For [`CommandRunner::stream`], and equally for a captured `run`
    /// of the same command -- the stub says what the process produced,
    /// and the method decides what shape the caller sees it in.
    #[must_use]
    pub fn lines<I, S>(lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = String::new();
        for line in lines {
            out.push_str(line.as_ref());
            out.push('\n');
        }
        Self::ok(out)
    }

    /// Turn this into what [`CommandRunner::run`] should return.
    fn into_result(self, program: &str) -> Result<Output, ExecError> {
        match self {
            Self::Ran(output) => Ok(output),
            Self::NotFound => Err(ExecError::not_found(program)),
            Self::PermissionDenied => Err(ExecError::PermissionDenied {
                program: program.to_string(),
            }),
            Self::TimedOut => Err(ExecError::Timeout {
                program: program.to_string(),
                after: std::time::Duration::ZERO,
            }),
        }
    }
}

/// Whether a recorded call went through `run` or `stream`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallMode {
    /// [`CommandRunner::run`].
    Run,
    /// [`CommandRunner::stream`].
    Stream,
}

/// One invocation the fake saw.
///
/// `Debug` is redacted; see the module docs.
#[derive(Clone)]
pub struct RecordedCall {
    /// The command as the caller built it.
    pub command: Command,
    /// Which trait method it arrived through.
    pub mode: CallMode,
}

impl RecordedCall {
    /// The argv with secret arguments replaced by `<redacted>`.
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        self.command.argv_redacted()
    }

    /// The argv exactly as it would be handed to `execve`.
    ///
    /// Deliberately named so it reads as a decision at the call site: if
    /// a test uses this on a command with secret arguments, whatever it
    /// asserts can end up in a failure message.
    #[must_use]
    pub fn raw_argv(&self) -> Vec<String> {
        self.command.argv()
    }

    /// The bytes that would have been written to the child's stdin.
    ///
    /// Same deal as [`RecordedCall::raw_argv`]: explicit, because this
    /// is where `podman secret create`'s payload lives.
    #[must_use]
    pub fn stdin_bytes(&self) -> Option<&[u8]> {
        self.command.stdin_bytes_ref()
    }

    /// The stdin payload as text.
    #[must_use]
    pub fn stdin_text(&self) -> Option<String> {
        self.stdin_bytes()
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }
}

impl fmt::Debug for RecordedCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} {:?}", self.mode, self.command)
    }
}

/// What [`CommandRunner::which`] answers for a program nothing stubbed.
#[derive(Debug, Clone, Default)]
enum WhichDefault {
    /// Panic, like an unstubbed call. The default.
    #[default]
    Unstubbed,
    /// Report every program as installed under this directory.
    Installed(PathBuf),
    /// Report every program as missing.
    Missing,
}

/// The fake's mutable state, shared with every [`FakeLines`] it hands out.
#[derive(Debug, Default)]
struct State {
    queue: VecDeque<Reply>,
    rules: Vec<(Vec<String>, Reply)>,
    which: BTreeMap<String, Option<PathBuf>>,
    which_default: WhichDefault,
    calls: Vec<RecordedCall>,
    which_lookups: Vec<String>,
    terminated: Vec<Vec<String>>,
}

/// A [`CommandRunner`] that records what it was asked to run and answers
/// from a script.
///
/// Every method takes `&self`, so one fake can be handed to several
/// wrappers at once -- which is what a `cage destroy` test needs, since
/// that path drives podman and systemctl in the same sequence.
#[derive(Debug, Clone, Default)]
pub struct FakeRunner {
    state: Arc<Mutex<State>>,
}

impl FakeRunner {
    /// A fake with nothing stubbed: every call panics.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic from an unstubbed call poisons this mutex, and the
        // poison must not become the error the test sees -- the argv in
        // the original panic is the useful message.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // ── stubbing ─────────────────────────────────────────────
    //
    // These return `&Self` so they can be chained, not because the
    // return value means anything: their job is the side effect, and
    // `fake.push(reply);` on its own is the normal way to call them. So
    // `must_use` is wrong for the whole group.

    /// Queue one reply, consumed by the next call the rules do not match.
    #[allow(clippy::must_use_candidate)]
    pub fn push(&self, reply: Reply) -> &Self {
        self.lock().queue.push_back(reply);
        self
    }

    /// Queue several replies, in order.
    #[allow(clippy::must_use_candidate)]
    pub fn push_all<I>(&self, replies: I) -> &Self
    where
        I: IntoIterator<Item = Reply>,
    {
        self.lock().queue.extend(replies);
        self
    }

    /// Answer every call whose argv starts with `prefix` with `reply`.
    ///
    /// For the probes a test does not want to count: `podman secret ls`
    /// called once per secret, `container system status` before every
    /// operation. Rules are checked before the queue, and the first
    /// matching rule wins, so a later `on` with a longer prefix must be
    /// registered first.
    #[allow(clippy::must_use_candidate)]
    pub fn on<I, S>(&self, prefix: I, reply: Reply) -> &Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let prefix: Vec<String> = prefix.into_iter().map(Into::into).collect();
        self.lock().rules.push((prefix, reply));
        self
    }

    /// Make [`CommandRunner::which`] answer `path` for `program`.
    #[allow(clippy::must_use_candidate)]
    pub fn stub_which(&self, program: &str, path: impl Into<PathBuf>) -> &Self {
        self.lock()
            .which
            .insert(program.to_string(), Some(path.into()));
        self
    }

    /// Make [`CommandRunner::which`] answer "not installed" for `program`.
    ///
    /// The macOS-shaped branches: `systemd.py` no-ops without
    /// `systemctl`, `registry.py` degrades without `skopeo`. CI has no
    /// macOS runner, so this is how those branches stay reachable --
    /// the same trick `test_apple_container.py` plays with
    /// `platform.system()`.
    #[allow(clippy::must_use_candidate)]
    pub fn stub_missing(&self, program: &str) -> &Self {
        self.lock().which.insert(program.to_string(), None);
        self
    }

    /// Answer any unstubbed [`CommandRunner::which`] as installed, at
    /// `/usr/bin/<program>`.
    ///
    /// Without this, an unstubbed lookup panics like an unstubbed call.
    /// Most tests are about argv rather than about availability, and
    /// would otherwise open with a line of boilerplate per binary.
    #[allow(clippy::must_use_candidate)]
    pub fn assume_installed(&self) -> &Self {
        self.lock().which_default = WhichDefault::Installed(PathBuf::from("/usr/bin"));
        self
    }

    /// Answer any unstubbed [`CommandRunner::which`] as not installed.
    #[allow(clippy::must_use_candidate)]
    pub fn assume_missing(&self) -> &Self {
        self.lock().which_default = WhichDefault::Missing;
        self
    }

    // ── inspection ───────────────────────────────────────────

    /// Every call so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.lock().calls.clone()
    }

    /// How many calls the fake has seen.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.lock().calls.len()
    }

    /// The `n`th call.
    ///
    /// # Panics
    ///
    /// When fewer than `n + 1` calls were made, printing the whole
    /// recorded sequence -- which is almost always the thing you wanted
    /// to see anyway.
    #[must_use]
    pub fn call(&self, n: usize) -> RecordedCall {
        let state = self.lock();
        state.calls.get(n).cloned().unwrap_or_else(|| {
            panic!(
                "FakeRunner: asked for call #{n}, but only {} were made:\n{}",
                state.calls.len(),
                render(&state.calls)
            )
        })
    }

    /// The `n`th call's redacted argv.
    #[must_use]
    pub fn argv(&self, n: usize) -> Vec<String> {
        self.call(n).argv()
    }

    /// Every call's redacted argv, in order.
    #[must_use]
    pub fn argv_sequence(&self) -> Vec<Vec<String>> {
        self.lock().calls.iter().map(RecordedCall::argv).collect()
    }

    /// The argv of each stream that was [`LineStream::terminate`]d.
    #[must_use]
    pub fn terminated(&self) -> Vec<Vec<String>> {
        self.lock().terminated.clone()
    }

    /// Every program [`CommandRunner::which`] was asked about, in order.
    #[must_use]
    pub fn which_lookups(&self) -> Vec<String> {
        self.lock().which_lookups.clone()
    }

    // ── assertions ───────────────────────────────────────────

    /// Assert the exact argv sequence, in order, with nothing extra.
    ///
    /// # Panics
    ///
    /// When the recorded sequence differs, with both sequences printed.
    pub fn assert_argv(&self, expected: &[&[&str]]) {
        let actual = self.argv_sequence();
        let expected: Vec<Vec<String>> = expected
            .iter()
            .map(|argv| argv.iter().map(|s| (*s).to_string()).collect())
            .collect();
        assert!(
            actual == expected,
            "FakeRunner: argv sequence differs.\n  expected ({}):\n{}\n  actual ({}):\n{}",
            expected.len(),
            indent(&expected),
            actual.len(),
            indent(&actual),
        );
    }

    /// Assert that the `n`th call's argv is exactly this.
    ///
    /// # Panics
    ///
    /// When it is not.
    pub fn assert_call(&self, n: usize, expected: &[&str]) {
        let actual = self.argv(n);
        assert!(
            actual
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied()),
            "FakeRunner: call #{n} differs.\n  expected: {expected:?}\n  actual:   {actual:?}"
        );
    }

    /// Assert that every queued [`FakeRunner::push`] reply was used.
    ///
    /// The other half of failing loudly: an unstubbed call panics, and
    /// this catches the opposite mistake -- a test that stubbed five
    /// calls, exercised code that makes three, and passed.
    ///
    /// # Panics
    ///
    /// When replies are left over.
    pub fn assert_drained(&self) {
        let state = self.lock();
        assert!(
            state.queue.is_empty(),
            "FakeRunner: {} queued replies were never used; the code under test \
             made {} calls:\n{}",
            state.queue.len(),
            state.calls.len(),
            render(&state.calls),
        );
    }

    // ── the seam ─────────────────────────────────────────────

    /// Record `command`, then pick its reply.
    fn dispatch(&self, command: &Command, mode: CallMode) -> Reply {
        let mut state = self.lock();
        state.calls.push(RecordedCall {
            command: command.clone(),
            mode,
        });
        let argv = command.argv();
        if let Some((_, reply)) = state
            .rules
            .iter()
            .find(|(prefix, _)| argv.len() >= prefix.len() && argv[..prefix.len()] == prefix[..])
        {
            return reply.clone();
        }
        state.queue.pop_front().unwrap_or_else(|| {
            panic!(
                "FakeRunner: unexpected call #{}: {:?}\nNo queued reply and no matching rule. \
                 Calls so far:\n{}",
                state.calls.len() - 1,
                command.argv_redacted(),
                render(&state.calls),
            )
        })
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, command: &Command) -> Result<Output, ExecError> {
        self.dispatch(command, CallMode::Run)
            .into_result(command.program())
    }

    fn stream(&self, command: &Command) -> Result<Box<dyn LineStream>, ExecError> {
        let output = self
            .dispatch(command, CallMode::Stream)
            .into_result(command.program())?;
        Ok(Box::new(FakeLines {
            argv: command.argv_redacted(),
            lines: output.stdout_lines().into(),
            status: output.status,
            state: Arc::clone(&self.state),
        }))
    }

    fn which(&self, program: &str) -> Option<PathBuf> {
        let mut state = self.lock();
        state.which_lookups.push(program.to_string());
        if let Some(answer) = state.which.get(program) {
            return answer.clone();
        }
        match &state.which_default {
            WhichDefault::Installed(dir) => Some(dir.join(program)),
            WhichDefault::Missing => None,
            WhichDefault::Unstubbed => panic!(
                "FakeRunner: unstubbed which({program:?}). Call stub_which / stub_missing \
                 for it, or assume_installed() / assume_missing() for a default."
            ),
        }
    }
}

/// A stubbed stream: a fixed list of lines and a fixed exit status.
#[derive(Debug)]
struct FakeLines {
    argv: Vec<String>,
    lines: VecDeque<String>,
    status: ExitStatus,
    state: Arc<Mutex<State>>,
}

impl LineStream for FakeLines {
    fn next_line(&mut self) -> Option<String> {
        self.lines.pop_front()
    }

    fn terminate(&mut self) -> Result<(), ExecError> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .terminated
            .push(self.argv.clone());
        self.lines.clear();
        Ok(())
    }

    fn wait(&mut self) -> Result<ExitStatus, ExecError> {
        Ok(self.status)
    }
}

/// Render recorded calls for a panic message, one per line.
fn render(calls: &[RecordedCall]) -> String {
    if calls.is_empty() {
        return "    (none)".to_string();
    }
    calls
        .iter()
        .enumerate()
        .map(|(i, c)| format!("    {i}: {:?}", c.argv()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render an argv sequence for a panic message, one per line.
fn indent(sequence: &[Vec<String>]) -> String {
    if sequence.is_empty() {
        return "    (none)".to_string();
    }
    sequence
        .iter()
        .enumerate()
        .map(|(i, argv)| format!("    {i}: {argv:?}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{FakeRunner, Reply};
    use crate::command::Command;
    use crate::runner::CommandRunner as _;

    #[test]
    fn replies_are_consumed_in_order() {
        let fake = FakeRunner::new();
        fake.push_all([Reply::ok("first"), Reply::status(1), Reply::ok("third")]);

        assert_eq!(
            fake.run(&Command::new("a").captured())
                .unwrap()
                .stdout_text(),
            "first"
        );
        assert_eq!(fake.run(&Command::new("b")).unwrap().status.code, Some(1));
        assert_eq!(
            fake.run(&Command::new("c").captured())
                .unwrap()
                .stdout_text(),
            "third"
        );
        fake.assert_drained();
        fake.assert_argv(&[&["a"], &["b"], &["c"]]);
    }

    #[test]
    fn rules_answer_repeatedly_and_beat_the_queue() {
        let fake = FakeRunner::new();
        fake.on(["podman", "secret", "ls"], Reply::ok("a\nb\n"));
        fake.push(Reply::ok("queued"));

        for _ in 0..3 {
            let out = fake
                .run(&Command::new("podman").args(["secret", "ls"]).captured())
                .unwrap();
            assert_eq!(out.stdout_lines(), ["a", "b"]);
        }
        // The queued reply is still there for the first non-matching call.
        assert_eq!(
            fake.run(&Command::new("podman").arg("info").captured())
                .unwrap()
                .stdout_text(),
            "queued"
        );
        fake.assert_drained();
    }

    #[test]
    #[should_panic(expected = "unexpected call")]
    fn an_unstubbed_call_panics() {
        let fake = FakeRunner::new();
        let _ = fake.run(&Command::new("podman").arg("info"));
    }

    #[test]
    #[should_panic(expected = "never used")]
    fn leftover_replies_are_an_error() {
        let fake = FakeRunner::new();
        fake.push(Reply::success());
        fake.assert_drained();
    }

    #[test]
    #[should_panic(expected = "unstubbed which")]
    fn an_unstubbed_which_panics() {
        let _ = FakeRunner::new().which("systemctl");
    }

    #[test]
    fn which_can_be_stubbed_per_program_and_by_default() {
        let fake = FakeRunner::new();
        fake.assume_installed().stub_missing("skopeo");
        assert!(fake.has("podman"));
        assert!(!fake.has("skopeo"));
        fake.stub_which("container", "/usr/local/bin/container");
        assert_eq!(
            fake.which("container").unwrap().to_str(),
            Some("/usr/local/bin/container")
        );
        assert_eq!(fake.which_lookups(), ["podman", "skopeo", "container"]);
    }

    #[test]
    fn errors_are_stubbable() {
        let fake = FakeRunner::new();
        fake.push(Reply::NotFound);
        let err = fake.run(&Command::new("skopeo")).unwrap_err();
        assert!(err.is_not_found());
    }

    #[test]
    fn streaming_serves_lines_and_records_terminate() {
        let fake = FakeRunner::new();
        fake.push(Reply::lines(["one", "two"]));

        let mut stream = fake.stream(&Command::new("journalctl").arg("-f")).unwrap();
        assert_eq!(stream.next_line().as_deref(), Some("one"));
        stream.terminate().unwrap();
        assert_eq!(stream.next_line(), None);
        assert_eq!(fake.terminated(), [["journalctl", "-f"]]);
    }

    /// The failure path must not become a credential channel.
    #[test]
    fn a_failure_message_cannot_leak_a_secret() {
        let fake = FakeRunner::new();
        fake.push(Reply::success());
        let _ = fake.run(
            &Command::new("podman")
                .args(["secret", "create", "cage.KEY", "-"])
                .stdin_secret("hunter2"),
        );

        let dump = format!("{:?}", fake.calls());
        assert!(!dump.contains("hunter2"), "{dump}");

        let caught = std::panic::catch_unwind(|| fake.assert_argv(&[&["nope"]])).unwrap_err();
        let msg = caught
            .downcast_ref::<String>()
            .map_or_else(String::new, Clone::clone);
        assert!(!msg.contains("hunter2"), "{msg}");

        // A test that wants it still gets it.
        assert_eq!(fake.call(0).stdin_text().as_deref(), Some("hunter2"));
    }
}
