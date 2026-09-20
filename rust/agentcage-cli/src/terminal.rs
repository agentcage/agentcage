//! Host terminal hygiene — the port of `src/agentcage/terminal.py`.
//!
//! `cage exec` / `cage shell` hand the operator's terminal to a program
//! running *inside* the cage. Full-screen programs in there — pi, claude,
//! vim, less — switch the host terminal into modes they promise to undo
//! on exit: raw input, bracketed paste, the Kitty keyboard protocol
//! (whose key-*release* reporting makes every later keystroke echo an
//! escape sequence), xterm `modifyOtherKeys`, focus/mouse reporting,
//! hidden cursor.
//!
//! They keep that promise when they exit on their own terms. They cannot
//! when the cage is stopped, destroyed or rebuilt underneath them: the
//! microVM / container vanishes, the program is gone before it can write
//! its restore sequence, and the exec client simply closes. The operator
//! is left with a mangled terminal and no idea why (`reset` usually does
//! not fix Kitty mode).
//!
//! The only party that can reliably clean up is the CLI on the host,
//! *after* the session ends. Hence this module.
//!
//! # Restoration is the whole point, so it is a guard
//!
//! [`RestoredTerminal`] snapshots the terminal on construction and puts
//! it back in `Drop`. Not a `restore()` the caller must remember, and
//! not a cleanup at the end of a function: a `Drop` is the only form
//! that also runs when the block exits by `?`, by an early return, or by
//! a panic.
//!
//! That last one is not free. PR B1 removed `panic = "abort"` from the
//! release profile specifically so destructors run on panic, and this is
//! exactly the case it was kept for — a panic between "the program set
//! raw mode" and "the program restored it" would otherwise leave a shell
//! with no echo. `termios_is_restored_after_a_panic` is the test that
//! holds it.
//!
//! What it does **not** cover is a signal that kills the process
//! outright: `SIGKILL`, or `SIGTERM` with no handler. There is no
//! portable, async-signal-safe way to restore a terminal from there, and
//! the Python does not try either. `SIGINT` *is* covered, because it is
//! the one a user actually sends — see [`RestoredTerminal::new`].
//!
//! # No TUI crate
//!
//! `crossterm` and friends bring their own escape sequences, their own
//! idea of which modes to reset, and their own restoration policy. This
//! module's requirement is the opposite of "sensible defaults": the
//! bytes have to be the same bytes the Python wrote, in the same order,
//! because that list was assembled against real terminals and the Kitty
//! pop in particular is not something a general-purpose crate emits.
//! `nix` is the dependency, and it only wraps the termios syscalls.

use std::ffi::{CString, NulError};
use std::io::{self, IsTerminal, Stderr, Stdin, Stdout};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use nix::sys::termios::{self, SetArg, Termios};

/// Written to the terminal after every interactive session.
///
/// Each item is a no-op on a terminal that is already in that state, so
/// it is safe to send unconditionally — including to terminals that do
/// not implement the corresponding protocol, since an unknown CSI
/// sequence is ignored.
///
/// Byte-identical to the Python's `RESTORE_SEQUENCE`, and deliberately
/// *not* including `\x1b[?1049l`: DECRST 1049 on a terminal that is not
/// in the alternate screen also performs DECRC, which on some emulators
/// homes the cursor over the prompt. Not worth it for a mode our own
/// sessions do not leak.
pub const RESTORE_SEQUENCE: &[u8] = b"\x1b[<u\
\x1b[=0;1u\
\x1b[>4;0m\
\x1b[?2004l\
\x1b[?1004l\
\x1b[?1000l\
\x1b[?1002l\
\x1b[?1003l\
\x1b[?1006l\
\x1b[?2026l\
\x1b[?25h\
\x1b[0m";

/// True when stdin is a terminal.
///
/// The same test the backends use to decide whether to allocate a pty
/// (`-it`) — and therefore whether the program inside the cage can have
/// touched the host terminal at all.
///
/// The Python deliberately asks `sys.stdin`, not fd 0, because click's
/// `CliRunner` and pytest swap `sys.stdin` for a non-tty object while
/// leaving fd 0 attached to the developer's terminal. Rust has no such
/// indirection to swap, so the same protection comes from the API
/// instead: every entry point here takes the terminal explicitly, and
/// only [`run_interactive`] consults this.
#[must_use]
pub fn is_interactive() -> bool {
    io::stdin().is_terminal()
}

/// A standard stream, held so a `BorrowedFd` can be taken from it.
///
/// `BorrowedFd::borrow_raw` would turn a bare `1` into a file
/// descriptor in one line, but it is `unsafe` and this workspace
/// forbids `unsafe_code`. Keeping the handle is the safe equivalent:
/// `Stdout`/`Stderr`/`Stdin` each implement `AsFd`, and the enum exists
/// only so the three of them have one type.
#[derive(Debug)]
pub enum Tty {
    /// File descriptor 1.
    Stdout(Stdout),
    /// File descriptor 2.
    Stderr(Stderr),
    /// File descriptor 0.
    Stdin(Stdin),
}

impl AsFd for Tty {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Stdout(h) => h.as_fd(),
            Self::Stderr(h) => h.as_fd(),
            Self::Stdin(h) => h.as_fd(),
        }
    }
}

/// A handle on the controlling terminal, or `None`.
///
/// Prefers stdout (where the session's output went), then stderr, then
/// stdin — the last covers `cage exec … | tee` style invocations where
/// only stdin is still the terminal.
#[must_use]
pub fn controlling_tty() -> Option<Tty> {
    let out = io::stdout();
    if out.is_terminal() {
        return Some(Tty::Stdout(out));
    }
    let err = io::stderr();
    if err.is_terminal() {
        return Some(Tty::Stderr(err));
    }
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Some(Tty::Stdin(stdin));
    }
    None
}

// ── SIGINT ───────────────────────────────────────────────────

/// How many sessions are currently running.
static SESSIONS: AtomicUsize = AtomicUsize::new(0);

/// The condition the installed SIGINT action reads: "no session is
/// running, so behave the way a program with no handler behaves".
static OUTSIDE_SESSION: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Divert SIGINT away from the CLI for as long as the value is alive.
///
/// # Why SIGINT needs handling at all
///
/// Ctrl-C at the keyboard is delivered to every process in the
/// terminal's foreground group — the session's child *and* this
/// process. With the default disposition the CLI dies on the spot, which
/// skips every destructor, including the one that restores the terminal.
/// So the parent has to survive the Ctrl-C that the child is supposed to
/// receive.
///
/// # Why it is not `SIG_IGN`
///
/// The Python installs a no-op Python handler and says why in a comment:
/// `SIG_IGN` survives `exec`, so the program inside the cage would
/// inherit it and Ctrl-C would be silently dead *inside* the session.
/// A handled signal is reset to its default on `exec`, so a handler is
/// the only shape that stays out of the child's way. That applies
/// unchanged here.
///
/// # What differs from the Python
///
/// The Python saves the previous handler and puts it back. Restoring a
/// disposition needs `sigaction`, which `nix` exposes as an `unsafe fn`
/// and this workspace forbids. `signal-hook` gets to the same place by a
/// different route: the action is installed once, for the life of the
/// process, and reads a flag. While a session is running it does
/// nothing; the rest of the time it runs `emulate_default_handler`,
/// which for SIGINT resets the disposition and re-raises — so the
/// process dies exactly as it would with no handler at all.
///
/// The observable difference is that a Rust CLI dies *by the signal*
/// where CPython raised `KeyboardInterrupt` and unwound. That is the
/// right analogue: each language's default is preserved, not CPython's
/// grafted onto Rust.
#[derive(Debug)]
struct SigintDiversion {
    /// `false` when the action could not be installed, so `Drop` does
    /// not decrement a count that was never incremented.
    armed: bool,
}

impl SigintDiversion {
    fn install() -> Self {
        let flag = OUTSIDE_SESSION.get_or_init(|| {
            let flag = Arc::new(AtomicBool::new(true));
            // Failure here means the process cannot install signal
            // actions at all. Nothing useful to do about it: the
            // session still has to run, and Ctrl-C keeps whatever
            // behaviour it had. The Python is no better off — it lets
            // the `ValueError` propagate out of a `cage shell`.
            let _ = signal_hook::flag::register_conditional_default(
                signal_hook::consts::SIGINT,
                Arc::clone(&flag),
            );
            flag
        });
        SESSIONS.fetch_add(1, Ordering::SeqCst);
        flag.store(false, Ordering::SeqCst);
        Self { armed: true }
    }
}

impl Drop for SigintDiversion {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // The last session out turns the default behaviour back on.
        // Counting rather than a bare flag so a nested guard — a
        // `cage shell` that shells out to another session — cannot
        // re-arm SIGINT under the outer one.
        if SESSIONS.fetch_sub(1, Ordering::SeqCst) == 1
            && let Some(flag) = OUTSIDE_SESSION.get()
        {
            flag.store(true, Ordering::SeqCst);
        }
    }
}

// ── the guard ────────────────────────────────────────────────

/// Snapshot a terminal; put it back when this value is dropped.
///
/// Restores the termios attributes (raw mode, echo, …) and writes
/// [`RESTORE_SEQUENCE`] to undo terminal-application modes, whether the
/// scope exits normally, by `?`, or by a panic. SIGINT is diverted for
/// the lifetime of the guard — see [`SigintDiversion`].
///
/// This is the `restored_terminal()` context manager, with the `yield`
/// replaced by the caller's scope.
#[derive(Debug)]
pub struct RestoredTerminal<F: AsFd> {
    fd: F,
    /// `None` when the snapshot failed — a terminal that cannot be read
    /// is one we decline to write attributes back to, rather than one we
    /// guess at. The escape sequence is still sent.
    saved: Option<Termios>,
    /// Dropped first, to match the Python's `finally` order.
    sigint: Option<SigintDiversion>,
}

impl<F: AsFd> RestoredTerminal<F> {
    /// Take the snapshot and divert SIGINT.
    ///
    /// `fd` is anything that can lend a file descriptor: a [`Tty`] from
    /// [`controlling_tty`], or a pty from a test.
    #[must_use]
    pub fn new(fd: F) -> Self {
        let saved = termios::tcgetattr(fd.as_fd()).ok();
        Self {
            fd,
            saved,
            sigint: Some(SigintDiversion::install()),
        }
    }

    /// The attributes this guard will restore, if it could read them.
    #[must_use]
    pub fn snapshot(&self) -> Option<&Termios> {
        self.saved.as_ref()
    }
}

impl<F: AsFd> Drop for RestoredTerminal<F> {
    fn drop(&mut self) {
        // Order matches the Python's `finally` block: signal handler
        // first, then the attributes, then the escape sequence. The
        // sequence goes last because it is the part that has to survive
        // a terminal still draining the session's output —
        // `TCSADRAIN` above it means the attribute change waits for
        // that drain, so the bytes land in a terminal that is already
        // back in its old mode.
        drop(self.sigint.take());

        if let Some(saved) = &self.saved {
            // A failure here is not actionable and must not mask the
            // escape sequence below, which is the half that fixes
            // Kitty mode. The Python swallows `termios.error` for the
            // same reason.
            let _ = termios::tcsetattr(self.fd.as_fd(), SetArg::TCSADRAIN, saved);
        }

        let mut written = 0;
        while written < RESTORE_SEQUENCE.len() {
            match nix::unistd::write(self.fd.as_fd(), &RESTORE_SEQUENCE[written..]) {
                Ok(0) => break,
                Ok(n) => written += n,
                Err(nix::errno::Errno::EINTR) => {}
                Err(_) => break,
            }
        }
    }
}

/// Guard the controlling terminal, if this session has one.
///
/// `None` when stdin is not a terminal or no standard stream is one —
/// the Python's two early `yield`s, which make the context manager a
/// no-op rather than an error.
#[must_use]
pub fn restored_terminal() -> Option<RestoredTerminal<Tty>> {
    session_tty().map(RestoredTerminal::new)
}

// ── running the session ──────────────────────────────────────

/// Map a `subprocess`-style return code to a shell-style exit status.
///
/// `subprocess` reports a signal death as `-signum`; shells report it as
/// `128 + signum`. Callers that scripted around the old `os.execvp`
/// hand-off saw the latter, so keep it.
///
/// Kept as a function over a plain `i32` — rather than folded into
/// [`exit_status_of`] — because it is the Python's contract, and the
/// table `tests/test_terminal.py` asserts it against transfers straight
/// over.
#[must_use]
pub fn exit_status(returncode: i32) -> i32 {
    if returncode < 0 {
        128 - returncode
    } else {
        returncode
    }
}

/// The same mapping, from a Rust [`ExitStatus`].
///
/// Rust does not use the negative-return-code convention: a signalled
/// child has `code() == None` and a `signal()`. Converting to the Python
/// convention first keeps one implementation of the arithmetic.
#[must_use]
pub fn exit_status_of(status: &ExitStatus) -> i32 {
    match status.code() {
        Some(code) => exit_status(code),
        // `signal()` is `None` only if the status is neither exited nor
        // signalled, which `wait(2)` does not produce for a child that
        // has been reaped. 0 keeps the arithmetic total.
        None => exit_status(-status.signal().unwrap_or(0)),
    }
}

/// What went wrong running an interactive session.
#[derive(Debug)]
pub enum SessionError {
    /// An argument contained a NUL byte, so it cannot become a C string.
    ///
    /// The Python raises `ValueError` from `os.execvp` for the same
    /// input.
    NulInArgument(NulError),
    /// `execvp` failed — almost always "no such program".
    Exec(nix::errno::Errno),
    /// The child could not be spawned or waited for.
    Spawn(io::Error),
    /// `run_interactive` was called with an empty argv.
    EmptyArgv,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NulInArgument(e) => write!(f, "argument contains a NUL byte: {e}"),
            Self::Exec(e) => write!(f, "exec failed: {e}"),
            Self::Spawn(e) => write!(f, "{e}"),
            Self::EmptyArgv => write!(f, "no command to run"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Run `argv` as the operator's session and return its exit status,
/// restoring the host terminal afterwards.
///
/// Without a terminal on stdin there is nothing to restore, so this
/// keeps the historical `os.execvp` semantics: the CLI is *replaced* by
/// the exec client and this call does not return. With a terminal, the
/// client runs as a child so that the CLI is still alive to clean up
/// once the session ends — however it ends.
///
/// # Where this differs from the Python
///
/// `run_interactive` returns the status instead of exiting the process
/// with it. `sys.exit` inside the Python is caught by click and turned
/// into an exit code; in Rust, `std::process::exit` **skips every
/// destructor**, which in this module is the whole point — the guard
/// above it would not have run. So the exit belongs to the caller, after
/// this has returned and the guard has done its work.
///
/// # Errors
///
/// [`SessionError`] if the argv cannot be turned into a command, if
/// `execvp` fails on the non-interactive path, or if the child cannot be
/// spawned or waited for.
pub fn run_interactive(argv: &[String]) -> Result<i32, SessionError> {
    if argv.is_empty() {
        return Err(SessionError::EmptyArgv);
    }

    if !is_interactive() {
        return Err(exec_replacing(argv));
    }

    run_guarded(session_tty(), argv)
}

/// Replace this process with `argv`.
///
/// `os.execvp`, and it only returns when the exec failed — hence a bare
/// [`SessionError`] rather than a `Result`. The Python reaches for this
/// wherever the CLI has nothing left to do after handing off: a
/// non-interactive session, and every `cage logs` stream that needs no
/// client-side filtering, where it is also what gives `journalctl -f`
/// its native Ctrl-C.
#[must_use]
pub fn exec_replacing(argv: &[String]) -> SessionError {
    let Some(program) = argv.first() else {
        return SessionError::EmptyArgv;
    };
    let path = match CString::new(program.as_str()) {
        Ok(path) => path,
        Err(error) => return SessionError::NulInArgument(error),
    };
    let c_args = match argv
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(converted) => converted,
        Err(error) => return SessionError::NulInArgument(error),
    };
    // Only returns on failure.
    SessionError::Exec(nix::unistd::execvp(&path, &c_args).unwrap_err())
}

/// The terminal a session should guard, or `None`.
///
/// The two early `yield`s of the Python's context manager, as a value:
/// no terminal on stdin means nothing inside the cage can have touched
/// the host terminal, and no standard stream being a terminal means
/// there is nothing to write the restore sequence to.
#[must_use]
pub fn session_tty() -> Option<Tty> {
    if is_interactive() {
        controlling_tty()
    } else {
        None
    }
}

/// Run `body` with `tty` snapshotted and restored afterwards.
///
/// The seam every interactive command's session goes through, and the
/// reason it takes the terminal as an argument: [`session_tty`] reads
/// the process's own streams, which a test cannot swap, while this
/// takes a pty the test owns.
///
/// Restoration is a `Drop`, so it also runs when `body` panics or when
/// the caller leaves the enclosing scope by `?` — see the module
/// documentation for why that is not incidental.
pub fn guarded<F: AsFd, R>(tty: Option<F>, body: impl FnOnce() -> R) -> R {
    let _guard = tty.map(RestoredTerminal::new);
    body()
}

/// Run `argv` as a child with `tty` guarded, and map its status.
///
/// Not the `CommandRunner` seam (PR D1): that exists to capture and
/// assert output, and this child must *inherit* the terminal rather
/// than have its streams taken away. There is nothing to record.
///
/// # Errors
///
/// [`SessionError::EmptyArgv`] for an empty argv, [`SessionError::Spawn`]
/// if the child cannot be spawned or waited for. The guard is dropped
/// before either error leaves this function.
pub fn run_guarded<F: AsFd>(tty: Option<F>, argv: &[String]) -> Result<i32, SessionError> {
    let Some(program) = argv.first() else {
        return Err(SessionError::EmptyArgv);
    };
    let status = guarded(tty, || Command::new(program).args(&argv[1..]).status())
        .map_err(SessionError::Spawn)?;
    Ok(exit_status_of(&status))
}

// ── hidden prompts ───────────────────────────────────────────

/// `click.prompt(label, hide_input=True)` — read one line with echo off.
///
/// Used by `cage create -s KEY` (and every other bare-key secret
/// prompt): the value is a credential, so it must not be echoed and it
/// must not reach the shell history.
///
/// Echo is disabled on the controlling terminal and restored whatever
/// happens, including a `?` on the read itself — that is the whole
/// reason the `Termios` is put back in a guard-shaped block rather than
/// after the read. When stdin is not a terminal there is nothing to
/// disable and the line is read plainly, which is how a piped
/// `echo value | agentcage ...` keeps working.
///
/// # Errors
///
/// [`io::Error`] if the line cannot be read, or if EOF arrives first.
pub fn prompt_hidden(label: &str) -> io::Result<String> {
    use std::io::{BufRead as _, Write as _};

    let mut err = io::stderr();
    write!(err, "{label}: ")?;
    err.flush()?;

    let stdin = io::stdin();
    let saved = if stdin.is_terminal() {
        termios::tcgetattr(&stdin).ok()
    } else {
        None
    };
    if let Some(saved) = &saved {
        let mut quiet = saved.clone();
        quiet.local_flags.remove(termios::LocalFlags::ECHO);
        let _ = termios::tcsetattr(&stdin, SetArg::TCSAFLUSH, &quiet);
    }

    let mut line = String::new();
    let read = stdin.lock().read_line(&mut line);

    if let Some(saved) = &saved {
        let _ = termios::tcsetattr(&stdin, SetArg::TCSAFLUSH, saved);
        // The newline the user typed was swallowed with the echo.
        let _ = writeln!(err);
    }

    match read? {
        0 => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no value on stdin",
        )),
        _ => Ok(line.trim_end_matches(['\n', '\r']).to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OUTSIDE_SESSION, RESTORE_SEQUENCE, RestoredTerminal, SESSIONS, SessionError, exit_status,
        exit_status_of, run_interactive,
    };
    use nix::poll::{PollFd, PollFlags, PollTimeout};
    use nix::sys::termios::{self, LocalFlags, SetArg};
    use std::os::fd::{AsFd, OwnedFd};
    use std::sync::atomic::Ordering;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes every test that constructs a [`RestoredTerminal`].
    ///
    /// `SESSIONS` and `OUTSIDE_SESSION` are process-global, and so is
    /// the SIGINT disposition they drive -- one per process, by
    /// definition. `cargo test` runs a module's tests on a thread pool
    /// in the *same* process, so two guards alive at once in two
    /// different tests make `SESSIONS` read 2 where a test expects 1,
    /// and let one test's `drop` restore the default SIGINT action
    /// while another is still relying on the diversion. Both failures
    /// are real races in the test suite rather than in the code, and
    /// both are intermittent, which is the worst way to find out.
    ///
    /// Every test below that touches a guard takes this first. Nothing
    /// in the shipped code needs it: a CLI has one terminal and one
    /// session stack.
    static ONE_SESSION_AT_A_TIME: Mutex<()> = Mutex::new(());

    /// Take [`ONE_SESSION_AT_A_TIME`], ignoring poisoning.
    ///
    /// Two of these tests panic on purpose (`termios_is_restored_after_a_panic`),
    /// which poisons the mutex. Poisoning is a signal about shared
    /// *data*, and the data here is a `()`; letting it turn every
    /// later test in the file red would hide the failure that actually
    /// matters.
    fn exclusive() -> MutexGuard<'static, ()> {
        ONE_SESSION_AT_A_TIME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A pty pair. The slave stands in for the operator's terminal.
    struct Pty {
        master: OwnedFd,
        slave: OwnedFd,
    }

    fn pty() -> Pty {
        let pair = nix::pty::openpty(None, None).expect("openpty");
        Pty {
            master: pair.master,
            slave: pair.slave,
        }
    }

    /// Read whatever the slave has written, with a deadline.
    fn drain(master: &OwnedFd, want: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < want {
            let mut fds = [PollFd::new(master.as_fd(), PollFlags::POLLIN)];
            let ready = nix::poll::poll(&mut fds, PollTimeout::from(2000u16)).expect("poll");
            if ready == 0 {
                break;
            }
            let mut buf = [0u8; 256];
            match nix::unistd::read(master.as_fd(), &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        out
    }

    /// Turn off echo and canonical input, the way a full-screen program
    /// inside the cage does and then fails to undo.
    fn make_raw(fd: &OwnedFd) {
        let mut attrs = termios::tcgetattr(fd.as_fd()).expect("tcgetattr");
        termios::cfmakeraw(&mut attrs);
        termios::tcsetattr(fd.as_fd(), SetArg::TCSANOW, &attrs).expect("tcsetattr");
        assert!(
            !termios::tcgetattr(fd.as_fd())
                .expect("tcgetattr")
                .local_flags
                .contains(LocalFlags::ECHO),
            "the test's own premise: the terminal is now dirty"
        );
    }

    fn echo_and_icanon(fd: &OwnedFd) -> (bool, bool) {
        let attrs = termios::tcgetattr(fd.as_fd()).expect("tcgetattr");
        (
            attrs.local_flags.contains(LocalFlags::ECHO),
            attrs.local_flags.contains(LocalFlags::ICANON),
        )
    }

    // ── the sequence itself ──

    #[test]
    fn pops_kitty_and_clears_flags() {
        // Pop one level *and* zero the current flags — either alone
        // leaves some terminals with key-release reporting on.
        let seq = RESTORE_SEQUENCE;
        for needle in [&b"\x1b[<u"[..], &b"\x1b[=0;1u"[..]] {
            assert!(seq.windows(needle.len()).any(|w| w == needle));
        }
    }

    #[test]
    fn undoes_paste_modifyotherkeys_and_the_cursor() {
        for needle in [&b"\x1b[?2004l"[..], &b"\x1b[>4;0m"[..], &b"\x1b[?25h"[..]] {
            assert!(RESTORE_SEQUENCE.windows(needle.len()).any(|w| w == needle));
        }
    }

    #[test]
    fn never_touches_the_alternate_screen() {
        assert!(
            !RESTORE_SEQUENCE.windows(4).any(|w| w == b"1049"),
            "DECRST 1049 also performs DECRC, which homes the cursor over \
             the prompt on some emulators"
        );
    }

    #[test]
    fn matches_the_python_byte_for_byte() {
        // The Python source is the oracle for this one constant: it is
        // a list of escapes assembled against real terminals, and a
        // transcription error in it is invisible in review.
        let python = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../src/agentcage/terminal.py"),
        )
        .expect("terminal.py");
        let body = python
            .split_once("RESTORE_SEQUENCE = (")
            .expect("the constant")
            .1
            .split_once("\n)")
            .expect("its end")
            .0;
        let mut expected = Vec::new();
        for line in body.lines() {
            let Some(start) = line.find("b\"") else {
                continue;
            };
            let rest = &line[start + 2..];
            let end = rest.find('"').expect("closing quote");
            expected.extend_from_slice(unescape(&rest[..end]).as_slice());
        }
        assert_eq!(RESTORE_SEQUENCE, expected.as_slice());
    }

    /// The only escape the Python constant uses is `\x1b`.
    fn unescape(literal: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let bytes = literal.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'x') {
                let hex = &literal[i + 2..i + 4];
                out.push(u8::from_str_radix(hex, 16).expect("hex escape"));
                i += 4;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        out
    }

    // ── restoration ──

    #[test]
    fn writes_the_restore_sequence_on_a_normal_exit() {
        let _lock = exclusive();
        let pty = pty();
        drop(RestoredTerminal::new(&pty.slave));
        assert_eq!(drain(&pty.master, RESTORE_SEQUENCE.len()), RESTORE_SEQUENCE);
    }

    #[test]
    fn restores_termios_after_the_session_left_raw_mode() {
        let _lock = exclusive();
        let pty = pty();
        assert_eq!(echo_and_icanon(&pty.slave), (true, true));
        {
            let _guard = RestoredTerminal::new(&pty.slave);
            make_raw(&pty.slave);
        }
        assert_eq!(
            echo_and_icanon(&pty.slave),
            (true, true),
            "a shell with no echo is the bug this module exists to prevent"
        );
    }

    /// The test the release profile's unwinding panics exist for.
    ///
    /// `panic = "abort"` would run no `Drop` at all, and this assertion
    /// is what would fail if someone put it back.
    #[test]
    fn termios_is_restored_after_a_panic() {
        let _lock = exclusive();
        let pty = pty();
        let before = echo_and_icanon(&pty.slave);

        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = RestoredTerminal::new(&pty.slave);
            make_raw(&pty.slave);
            panic!("cage vanished mid-session");
        }));
        std::panic::set_hook(hook);

        assert!(result.is_err(), "the panic must still propagate");
        assert_eq!(echo_and_icanon(&pty.slave), before);
        assert_eq!(
            drain(&pty.master, RESTORE_SEQUENCE.len()),
            RESTORE_SEQUENCE,
            "the escape sequence is written on the unwind path too"
        );
    }

    /// An error return is the ordinary failure shape in Rust, and it
    /// leaves the scope without a panic — so it is a second path, not
    /// the same one.
    fn failing_session(slave: &OwnedFd) -> Result<(), std::fmt::Error> {
        let _guard = RestoredTerminal::new(slave);
        make_raw(slave);
        Err(std::fmt::Error)
    }

    #[test]
    fn termios_is_restored_when_the_scope_exits_by_question_mark() {
        let _lock = exclusive();
        let pty = pty();
        let before = echo_and_icanon(&pty.slave);
        assert!(failing_session(&pty.slave).is_err());
        assert_eq!(echo_and_icanon(&pty.slave), before);
    }

    #[test]
    fn a_terminal_it_cannot_read_still_gets_the_sequence() {
        let _lock = exclusive();
        // A pipe is not a terminal: `tcgetattr` fails, so there is no
        // snapshot to put back, and the guard must still send the
        // escapes rather than give up on both halves.
        let (read, write) = nix::unistd::pipe().expect("pipe");
        let guard = RestoredTerminal::new(&write);
        assert!(guard.snapshot().is_none());
        drop(guard);
        let mut buf = [0u8; 128];
        let n = nix::unistd::read(read.as_fd(), &mut buf).expect("read");
        assert_eq!(&buf[..n], RESTORE_SEQUENCE);
    }

    #[test]
    fn nested_guards_each_restore() {
        let _lock = exclusive();
        let outer = pty();
        let inner = pty();
        {
            let _o = RestoredTerminal::new(&outer.slave);
            make_raw(&outer.slave);
            {
                let _i = RestoredTerminal::new(&inner.slave);
                make_raw(&inner.slave);
                assert_eq!(SESSIONS.load(Ordering::SeqCst), 2);
            }
            assert_eq!(echo_and_icanon(&inner.slave), (true, true));
            assert_eq!(
                SESSIONS.load(Ordering::SeqCst),
                1,
                "the inner guard must not re-arm SIGINT under the outer one"
            );
        }
        assert_eq!(echo_and_icanon(&outer.slave), (true, true));
    }

    /// Ctrl-C during a session must not take the CLI down with it.
    ///
    /// This is the claim the whole `SigintDiversion` dance exists to
    /// make, and it is only checkable by actually raising the signal:
    /// if the action were missing, or the condition flag inverted, this
    /// test would not fail — the test *process* would die, which is a
    /// loud enough answer.
    ///
    /// The other direction (SIGINT outside a session still terminates)
    /// cannot be asserted here for the same reason, and it is left to
    /// `signal-hook`'s own suite, which covers
    /// `emulate_default_handler`.
    #[test]
    fn sigint_is_swallowed_while_a_session_is_running() {
        let _lock = exclusive();
        let pty = pty();
        let guard = RestoredTerminal::new(&pty.slave);
        assert!(
            !OUTSIDE_SESSION
                .get()
                .expect("the action is installed with the first guard")
                .load(Ordering::SeqCst)
        );
        // Delivered to this thread, and the handler runs before `raise`
        // returns. Reaching the next line IS the assertion.
        signal_hook::low_level::raise(signal_hook::consts::SIGINT).expect("raise");
        drop(guard);
        assert!(
            OUTSIDE_SESSION
                .get()
                .expect("installed")
                .load(Ordering::SeqCst),
            "the last session out restores the default behaviour"
        );
    }

    // ── exit status ──

    #[test]
    fn shell_style_exit_status() {
        for (rc, expected) in [
            (0, 0),
            (1, 1),
            (129, 129),
            (137, 137),
            (-2, 130),  // SIGINT
            (-9, 137),  // SIGKILL
            (-1, 129),  // SIGHUP
            (-15, 143), // SIGTERM
        ] {
            assert_eq!(exit_status(rc), expected, "rc={rc}");
        }
    }

    #[test]
    fn exit_status_of_a_signalled_child() {
        let status = std::process::Command::new("sh")
            .args(["-c", "kill -KILL $$"])
            .status()
            .expect("sh");
        assert_eq!(exit_status_of(&status), 128 + 9);

        let status = std::process::Command::new("sh")
            .args(["-c", "exit 7"])
            .status()
            .expect("sh");
        assert_eq!(exit_status_of(&status), 7);
    }

    #[test]
    fn an_empty_argv_is_refused() {
        assert!(matches!(run_interactive(&[]), Err(SessionError::EmptyArgv)));
    }
}
