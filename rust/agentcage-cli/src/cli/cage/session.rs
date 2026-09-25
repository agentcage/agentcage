//! `cage exec` and `cage shell` — the two commands that hand the
//! operator's terminal to a program running inside a cage.
//!
//! They are one module because they are one story. Both resolve a cage,
//! refuse a stopped one, build a `podman exec` argv, and then run it as
//! the operator's session; the only real difference is that `exec` is
//! given the command and `shell` has to find one.
//!
//! # The exit path
//!
//! This is the part worth reading twice. `cli.py` ends both commands
//! with `sys.exit(terminal.exit_status(...))`, and click turns that into
//! a process exit *after* the `with terminal.restored_terminal()` block
//! has closed. The Rust analogue of `sys.exit` is
//! `std::process::exit`, and it does **not** unwind: it runs no
//! destructor, which would skip [`agentcage_cli::terminal::RestoredTerminal`]'s
//! `Drop` — the one piece of code whose entire job is to undo raw mode,
//! the Kitty keyboard protocol and bracketed paste on the host
//! terminal. A `cage shell` that exits that way leaves the operator
//! with a shell that does not echo.
//!
//! So nothing here exits. [`agentcage_cli::terminal::run_guarded`] returns the
//! status, the guard inside it is dropped on the way out — on the
//! normal path, on `?`, and on a panic — and the status becomes an
//! [`ExitCode`] that `main` returns. `ExitCode` is the shape that lets
//! the runtime unwind the stack first, and that is why every body in
//! this tree returns one instead of calling `exit`.
//!
//! The 125 podman itself exits with, and the 128+N a signalled session
//! produces, both survive that trip: [`agentcage_cli::terminal::exit_status_of`]
//! does the shell-style mapping and [`ExitCode::from`] carries the byte.

use std::process::ExitCode;

use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage};
use agentcage_cli::backend::uid_spec;
use agentcage_cli::terminal;

/// `cage exec NAME [-s SERVICE] [--as-root] COMMAND...`.
pub(crate) fn exec(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    exec_inner(ctx, matches).unwrap_or_else(|code| code)
}

fn exec_inner(ctx: &Ctx, matches: &ArgMatches) -> Result<ExitCode, ExitCode> {
    let name = string(matches, "name");
    let service = string(matches, "service");
    let as_root = matches.get_flag("as_root");
    let command: Vec<String> = matches
        .get_many::<String>("command")
        .map(|values| values.cloned().collect())
        .unwrap_or_default();

    let config = resolve(ctx, &name)?;
    if let Some(refusal) = unsupported_backend(&config.isolation, "exec") {
        return Err(refusal);
    }

    // clap makes `COMMAND...` required, so an empty argv cannot reach
    // here through the parser. The Python checks anyway and so does
    // this: `cli.py:2549` is the message an operator sees if the
    // declaration and the body ever disagree.
    if command.is_empty() {
        eprintln!("error: no command specified");
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    running_or_refuse(ctx, &name, &config.isolation)?;

    // Alias expansion, first word only. `exec_aliases: {sh: [/bin/bash,
    // -l]}` turns `cage exec app sh -c ...` into `/bin/bash -l -c ...`.
    let mut command = command;
    if let Some(expansion) = config.exec_aliases.get(command[0].as_str()) {
        let mut expanded = expansion.clone();
        expanded.extend(command.drain(1..));
        command = expanded;
    }

    let argv = ctx.backend_for(&config.isolation).exec_argv(
        &name,
        &service,
        &command,
        terminal::is_interactive(),
        as_root,
    );
    // The container backend runs the session as a *child* whether or
    // not there is a terminal — `cli.py:2604` reaches `run_interactive`
    // (and its `execvp`) only for vm and apple-container. Keeping the
    // child here is what leaves this process alive to restore the
    // terminal after a full-screen program inside the cage dies with
    // it.
    //
    // On vm the Python hands the process over: a non-interactive
    // `cage exec` becomes the `limactl shell`, so its exit status and
    // its signal disposition are the ssh client's rather than
    // agentcage's. With a terminal `run_interactive` falls back to the
    // guarded child, which is what puts the termios back.
    if config.isolation == "vm" {
        return Ok(status(terminal::run_interactive(&argv)));
    }
    Ok(status(terminal::run_guarded(
        terminal::session_tty(),
        &argv,
    )))
}

/// `cage shell NAME [-s SERVICE] [--as-root]`.
pub(crate) fn shell(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    shell_inner(ctx, matches).unwrap_or_else(|code| code)
}

fn shell_inner(ctx: &Ctx, matches: &ArgMatches) -> Result<ExitCode, ExitCode> {
    let name = string(matches, "name");
    let service = string(matches, "service");
    let as_root = matches.get_flag("as_root");

    let config = resolve(ctx, &name)?;
    if let Some(refusal) = unsupported_backend(&config.isolation, "shell") {
        return Err(refusal);
    }
    if config.isolation == "vm" {
        return Ok(shell_vm(ctx, &name, &service, as_root));
    }

    // `cage shell` has no stopped-cage pre-flight in `cli.py` — only
    // `cage exec` grew one — and adding one here would be a behaviour
    // change this port is not entitled to make. The podman error the
    // operator gets instead is the Python's.
    let container = format!("{name}-{service}");
    let spec = uid_spec(as_root);
    let shell = detect_shell(ctx, &container, spec);

    let mut argv = vec![
        "podman".to_owned(),
        "exec".to_owned(),
        "-u".to_owned(),
        spec.to_owned(),
    ];
    if terminal::is_interactive() {
        argv.push("-it".to_owned());
    }
    argv.push(container);
    argv.push(shell);
    // `cage shell` goes through `run_interactive`, which keeps the
    // historical `execvp` hand-off when there is no terminal to
    // restore. `cli.py:2726` does the same, and a non-interactive
    // `cage shell` is a scripted `podman exec` either way.
    Ok(status(terminal::run_interactive(&argv)))
}

/// `cage shell` on the vm backend — the same probe, wrapped.
///
/// `cli.py:2626`. Two things differ from the container path and both
/// are the Python's. The probe and the session are both `limactl shell
/// --workdir / <instance> -- podman exec …`, because the containers
/// live in the guest; and `--workdir /` is spelled out here rather than
/// coming from [`LimaInstance::shell_command`], since the session argv
/// is handed to `execvp` and bypasses that helper. Without it the guest
/// shell tries to `cd` into a host path it cannot see and prints a
/// spurious `No such file or directory` before the command runs.
///
/// Note the absence of `--tty=false`: this is the one path that may
/// want a PTY.
fn shell_vm(ctx: &Ctx, name: &str, service: &str, as_root: bool) -> ExitCode {
    let instance = agentcage_exec::tools::limactl::LimaInstance::new(ctx.runner.as_ref(), name);
    let container = format!("{name}-{service}");
    let spec = uid_spec(as_root);
    let prefix: Vec<String> = [
        "limactl",
        "shell",
        "--workdir",
        "/",
        instance.name(),
        "--",
        "podman",
        "exec",
        "-u",
        spec,
    ]
    .map(str::to_string)
    .to_vec();

    let mut shell = "/bin/sh";
    for candidate in ["/bin/bash", "/bin/sh"] {
        let mut argv = prefix.clone();
        argv.extend([container.clone(), "test".to_owned(), "-x".to_owned()]);
        argv.push((*candidate).to_owned());
        let (program, rest) = argv.split_first().expect("argv is never empty");
        let probe = agentcage_exec::Command::new(program.clone())
            .args(rest.iter().cloned())
            .captured();
        if ctx.runner.run(&probe).is_ok_and(|out| out.success()) {
            shell = candidate;
            break;
        }
    }

    let mut argv = prefix;
    if terminal::is_interactive() {
        argv.push("-it".to_owned());
    }
    argv.push(container);
    argv.push(shell.to_owned());
    status(terminal::run_interactive(&argv))
}

/// `/bin/bash` if the container has it, `/bin/sh` otherwise.
///
/// The probe runs under the same `-u` spec the session will, because a
/// `test -x` answered as root says nothing about whether uid 1000 can
/// execute the file.
fn detect_shell(ctx: &Ctx, container: &str, spec: &str) -> String {
    for candidate in ["/bin/bash", "/bin/sh"] {
        // A bare `podman`, not the elevation-prefixed builder: this is
        // `cli.py:2714`'s own argv, and `cage shell`'s session argv is
        // bare too. Probe and session have to agree.
        let probe = agentcage_exec::Command::new("podman")
            .args(["exec", "-u", spec, container, "test", "-x", candidate])
            .captured();
        if ctx.runner.run(&probe).is_ok_and(|out| out.success()) {
            return candidate.to_owned();
        }
    }
    "/bin/sh".to_owned()
}

/// Turn a finished session's status into this process's.
///
/// Deliberately not `std::process::exit` — see the module docs. The
/// `u8` narrowing is the same one the kernel does: a wait status
/// carries one byte, and `exit_status_of` has already folded a signal
/// death into the shell's `128 + N`, which fits.
fn status(outcome: Result<i32, agentcage_cli::terminal::SessionError>) -> ExitCode {
    match outcome {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// The checks both commands open with: the cage exists, it is not a
/// pre-v0.22 one, and its config parses.
fn resolve(ctx: &Ctx, name: &str) -> Result<agentcage_core::config::Config, ExitCode> {
    if !ctx.paths.deployment_exists(name) {
        eprintln!("error: cage '{name}' does not exist");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    ensure_v022_cage(&ctx.paths, name)?;
    ctx.paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })
}

/// Refuse to exec into a stopped cage.
///
/// Without this the operator got the raw downstream error — `no
/// container with name or ID "<name>-cage" found` from podman, exit 125
/// — which buries the actual problem.
fn running_or_refuse(ctx: &Ctx, name: &str, isolation: &str) -> Result<(), ExitCode> {
    if ctx.backend_for(isolation).is_running(name, "cage") {
        return Ok(());
    }
    eprintln!(
        "error: cage '{name}' is not running — \
         start it with 'agentcage cage start {name}' first"
    );
    Err(ExitCode::from(EXIT_FAILURE))
}

/// `BackendUnsupported`, for the one backend Track E still owns.
fn unsupported_backend(isolation: &str, verb: &str) -> Option<ExitCode> {
    agentcage_cli::backends::AnyBackend::refusal(isolation, &format!("cage {verb}")).map(
        |refusal| {
            eprintln!("{refusal}");
            ExitCode::from(EXIT_FAILURE)
        },
    )
}

fn string(matches: &ArgMatches, id: &str) -> String {
    matches.get_one::<String>(id).cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsFd, OwnedFd};
    use std::process::ExitCode;

    use agentcage_cli::backend::uid_spec;
    use agentcage_cli::terminal::{self, RESTORE_SEQUENCE, SessionError};
    use nix::poll::{PollFd, PollFlags, PollTimeout};
    use nix::sys::termios::{self, LocalFlags, SetArg};

    /// The `COMMAND...` a command line reaches the body with.
    ///
    /// Through the real tree, not a hand-built parser: what is in
    /// question is what clap does with `--` and with a flag-shaped
    /// value, and only the real `Command` can answer that.
    fn parsed_command(argv: &[&str]) -> Vec<String> {
        let matches = crate::cli::command(false)
            .try_get_matches_from(std::iter::once("agentcage").chain(argv.iter().copied()))
            .expect("the tree accepts this command line");
        let mut leaf = &matches;
        while let Some((_, next)) = leaf.subcommand() {
            leaf = next;
        }
        leaf.get_many::<String>("command")
            .expect("`COMMAND...` is required")
            .cloned()
            .collect()
    }

    /// The surprise worth a test of its own.
    ///
    /// `allow_hyphen_values` does **not** also keep the `--`: clap
    /// strips the first separator as a value terminator before the
    /// values reach the positional, which is exactly what click's
    /// `ignore_unknown_options` does. The recorded click parse in
    /// `tests/fixtures/cli-surface/parse-cases.json` says
    /// `command: ["ls", "-la"]` for both spellings, and forwarding a
    /// stray `--` into `podman exec` would make the workload see an
    /// argument the operator never typed.
    #[test]
    fn the_separator_is_stripped_and_the_two_spellings_agree() {
        assert_eq!(
            parsed_command(&["cage", "exec", "myapp", "--", "ls", "-la"]),
            ["ls", "-la"]
        );
        assert_eq!(
            parsed_command(&["cage", "exec", "myapp", "ls", "-la"]),
            ["ls", "-la"]
        );
        assert_eq!(
            parsed_command(&["exec", "myapp", "--", "ls", "-la"]),
            ["ls", "-la"]
        );
    }

    /// A second `--` is the workload's, not the parser's.
    #[test]
    fn only_the_first_separator_is_the_parsers() {
        assert_eq!(
            parsed_command(&["cage", "exec", "myapp", "--", "sh", "-c", "--", "x"]),
            ["sh", "-c", "--", "x"]
        );
    }

    /// `--as-root` before the cage name is this command's own flag;
    /// after the separator it is the workload's argument.
    #[test]
    fn a_known_flag_is_claimed_before_the_separator_and_passed_after() {
        let matches = crate::cli::command(false)
            .try_get_matches_from([
                "agentcage",
                "cage",
                "exec",
                "--as-root",
                "myapp",
                "--",
                "--as-root",
            ])
            .expect("parses");
        let mut leaf = &matches;
        while let Some((_, next)) = leaf.subcommand() {
            leaf = next;
        }
        assert!(leaf.get_flag("as_root"), "the flag before `--` is ours");
        assert_eq!(
            leaf.get_many::<String>("command")
                .expect("command")
                .cloned()
                .collect::<Vec<_>>(),
            ["--as-root"],
            "the one after it is the workload's"
        );
    }

    /// Both halves of the spec are pinned. `-u 1000` alone leaves the
    /// gid at the container default, which is gid 0 in an image with no
    /// uid 1000 in `/etc/passwd`.
    #[test]
    fn the_uid_spec_pins_the_group_too() {
        assert_eq!(uid_spec(false), "1000:1000");
        assert_eq!(uid_spec(true), "0:0");
    }

    // ── the host terminal, after the session ──
    //
    // `cage shell` is the command `terminal::RestoredTerminal` exists
    // for, and the three tests below are the three ways its session
    // can end. They drive `terminal::guarded` / `run_guarded` — the
    // functions `shell_inner` hands the session to — against a pty the
    // test owns, because the shipped path reads the process's own
    // streams and a test cannot swap those.

    /// Serializes the three guard tests.
    ///
    /// `RestoredTerminal` counts live sessions in a process-global, and
    /// drives the process-global SIGINT disposition from it. `cargo
    /// test` runs this module's tests on a thread pool in one process,
    /// so two guards alive at once would have one test's `drop` restore
    /// the default SIGINT action while another still relies on the
    /// diversion. Nothing in the shipped code needs this: a CLI has one
    /// terminal.
    static ONE_SESSION_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the lock, ignoring poisoning — one of these tests panics on
    /// purpose, and a poisoned `()` must not turn the rest red.
    fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        ONE_SESSION_AT_A_TIME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

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

    /// Leave the terminal the way a full-screen program inside the cage
    /// does when it dies before writing its own restore sequence.
    fn dirty(fd: &OwnedFd) {
        let mut attrs = termios::tcgetattr(fd.as_fd()).expect("tcgetattr");
        termios::cfmakeraw(&mut attrs);
        termios::tcsetattr(fd.as_fd(), SetArg::TCSANOW, &attrs).expect("tcsetattr");
        assert!(
            !echo(fd),
            "the test's own premise: the terminal is now dirty"
        );
    }

    fn echo(fd: &OwnedFd) -> bool {
        termios::tcgetattr(fd.as_fd())
            .expect("tcgetattr")
            .local_flags
            .contains(LocalFlags::ECHO)
    }

    /// Read what the slave side wrote, with a deadline.
    fn drain(master: &OwnedFd, want: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < want {
            let mut fds = [PollFd::new(master.as_fd(), PollFlags::POLLIN)];
            if nix::poll::poll(&mut fds, PollTimeout::from(2000u16)).expect("poll") == 0 {
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

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| (*p).to_owned()).collect()
    }

    /// The ordinary ending: the program inside the cage exits, having
    /// left the host terminal in raw mode on its way out.
    ///
    /// `exit 7` is the acceptance check's own case — the workload's
    /// status has to survive the trip rather than be flattened to 0 or
    /// 1 — and the `dirty` call is the half a live cage would supply.
    #[test]
    fn the_terminal_comes_back_after_a_normal_exit() {
        let _lock = exclusive();
        let pty = pty();
        let outcome = terminal::guarded(Some(&pty.slave), || {
            dirty(&pty.slave);
            std::process::Command::new("sh")
                .args(["-c", "exit 7"])
                .status()
        });
        assert_eq!(terminal::exit_status_of(&outcome.expect("sh ran")), 7);
        assert!(
            echo(&pty.slave),
            "a shell with no echo is the bug this module exists to prevent"
        );
        assert_eq!(drain(&pty.master, RESTORE_SEQUENCE.len()), RESTORE_SEQUENCE);
    }

    /// The error ending: the session could not be started.
    ///
    /// Reachable in production — a `podman` that is not on `PATH` fails
    /// to spawn *after* the guard has been taken — and the error leaves
    /// the scope by `?`, which is the path a cleanup written as the last
    /// statement of the function would miss. The body is
    /// `run_guarded`'s, with the dirtying added so the restoration is
    /// observable.
    fn failing_session(slave: &OwnedFd) -> Result<i32, SessionError> {
        let outcome = terminal::guarded(Some(slave), || {
            dirty(slave);
            std::process::Command::new("agentcage-no-such-program-b2f1").status()
        });
        Ok(terminal::exit_status_of(
            &outcome.map_err(SessionError::Spawn)?,
        ))
    }

    #[test]
    fn the_terminal_comes_back_when_the_session_errors() {
        let _lock = exclusive();
        let pty = pty();
        let outcome = failing_session(&pty.slave);
        assert!(
            matches!(outcome, Err(SessionError::Spawn(_))),
            "{outcome:?}"
        );
        assert!(echo(&pty.slave));
        assert_eq!(drain(&pty.master, RESTORE_SEQUENCE.len()), RESTORE_SEQUENCE);
    }

    /// The ending nothing else covers: the CLI itself panics between
    /// "the program set raw mode" and "the program restored it".
    ///
    /// This is why PR B1 took `panic = "abort"` off the release
    /// profile, and why the exit path in this module returns an
    /// `ExitCode` instead of calling `std::process::exit` — both of
    /// those skip the `Drop` this asserts.
    #[test]
    fn the_terminal_comes_back_after_a_panic() {
        let _lock = exclusive();
        let pty = pty();

        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            terminal::guarded(Some(&pty.slave), || {
                dirty(&pty.slave);
                panic!("the cage vanished mid-session");
            })
        }));
        std::panic::set_hook(hook);

        assert!(result.is_err(), "the panic must still propagate");
        assert!(echo(&pty.slave));
        assert_eq!(drain(&pty.master, RESTORE_SEQUENCE.len()), RESTORE_SEQUENCE);
    }

    /// `cage exec <cage> -- sh -c 'exit 7'` exits 7: the mapping, on
    /// the exact call `session::exec` makes, and then through the
    /// `ExitCode` the dispatch returns.
    #[test]
    fn the_workloads_status_reaches_the_process_exit() {
        assert_eq!(
            terminal::run_guarded(None::<&OwnedFd>, &argv(&["sh", "-c", "exit 7"]))
                .expect("sh ran"),
            7
        );
        // `ExitCode::from(7)` is what `status` hands back to `main`;
        // `std::process::exit(7)` would be the shape that skips the
        // guard above.
        assert_eq!(
            format!("{:?}", super::status(Ok(7))),
            format!("{:?}", ExitCode::from(7u8))
        );
    }

    /// A signalled session reports the shell's `128 + N`, which is what
    /// the `os.execvp` hand-off this replaced used to produce.
    #[test]
    fn a_signalled_session_reports_the_shells_status() {
        let status = terminal::run_guarded(None::<&OwnedFd>, &argv(&["sh", "-c", "kill -TERM $$"]));
        assert_eq!(status.expect("the child ran"), 128 + 15);
    }
}
