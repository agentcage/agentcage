//! [`SystemRunner`]: the [`CommandRunner`] that actually forks.
//!
//! Nothing in here makes policy decisions. It translates a [`Command`]
//! into a `std::process::Command`, wires the three streams, waits, and
//! reports. Every judgement call about *what* to run lives in
//! [`crate::tools`], where the fake can see it.

use std::fs::File;
use std::io::{Read, Write as _};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::command::{Command, Sink, Stdin, to_std_command, which_on_path};
use crate::outcome::{ExecError, ExitStatus, Output};
use crate::runner::{CommandRunner, LineStream};

/// Runs commands as real child processes.
///
/// Stateless and zero-sized: construct one wherever you need it.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

impl SystemRunner {
    /// A runner that forks.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl CommandRunner for SystemRunner {
    fn run(&self, command: &Command) -> Result<Output, ExecError> {
        let program = command.program();
        let mut std_cmd = to_std_command(command);
        std_cmd.stdin(stdin_stdio(command, program)?);

        // stdout, and stderr alongside it when they are merged. For a
        // file sink the handle is cloned rather than reopened, so both
        // streams share one file offset -- reopening would give them
        // independent offsets and they would overwrite each other.
        let (out_stdio, err_stdio) = output_stdio(command, program)?;
        std_cmd.stdout(out_stdio);
        std_cmd.stderr(err_stdio);

        let mut child = std_cmd
            .spawn()
            .map_err(|e| ExecError::from_spawn(program, e))?;

        let stdin_pipe = child.stdin.take();
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

        let out_buf = Mutex::new(Vec::new());
        let err_buf = Mutex::new(Vec::new());
        let merged = command.stderr_is_merged();

        let status = thread::scope(|scope| -> Result<ExitStatus, ExecError> {
            if let (Some(mut pipe), Stdin::Bytes { data, .. }) = (stdin_pipe, command.stdin_spec())
            {
                // Written from a thread, not inline: a payload larger
                // than the pipe buffer would otherwise deadlock against
                // a child that is waiting for us to drain its stdout.
                scope.spawn(move || {
                    // A child that exits without reading gives EPIPE.
                    // That is its prerogative; the exit status is what
                    // the caller judges it on.
                    let _ = pipe.write_all(data);
                });
            }
            if let Some(pipe) = stdout_pipe {
                scope.spawn(|| drain(pipe, &out_buf));
            }
            if let Some(pipe) = stderr_pipe {
                let sink = if merged { &out_buf } else { &err_buf };
                scope.spawn(move || drain(pipe, sink));
            }
            match command.timeout_limit() {
                None => child.wait().map(Into::into).map_err(|e| ExecError::Io {
                    program: program.to_string(),
                    source: e,
                }),
                Some(limit) => wait_with_timeout(&mut child, limit, program),
            }
        })?;

        Ok(Output {
            status,
            stdout: take(out_buf),
            stderr: take(err_buf),
        })
    }

    fn stream(&self, command: &Command) -> Result<Box<dyn LineStream>, ExecError> {
        let program = command.program();
        let mut std_cmd = to_std_command(command);
        std_cmd.stdin(stdin_stdio(command, program)?);
        // Streaming implies a pipe on stdout, whatever the command says.
        std_cmd.stdout(Stdio::piped());
        std_cmd.stderr(if command.stderr_is_merged() {
            Stdio::piped()
        } else {
            sink_stdio(command.stderr_spec(), program)?
        });

        let mut child = std_cmd
            .spawn()
            .map_err(|e| ExecError::from_spawn(program, e))?;

        let (tx, rx) = mpsc::channel();
        if let (Some(mut pipe), Stdin::Bytes { data, .. }) =
            (child.stdin.take(), command.stdin_spec())
        {
            let data = data.clone();
            thread::spawn(move || {
                let _ = pipe.write_all(&data);
            });
        }
        if let Some(pipe) = child.stdout.take() {
            spawn_line_reader(pipe, tx.clone());
        }
        if let Some(pipe) = child.stderr.take() {
            spawn_line_reader(pipe, tx.clone());
        }
        // The last handle here has to go, or `rx.recv()` never reports
        // end of stream.
        drop(tx);

        Ok(Box::new(ChildLines {
            program: program.to_string(),
            child: Some(child),
            rx,
            status: None,
        }))
    }

    fn which(&self, program: &str) -> Option<PathBuf> {
        which_on_path(program)
    }
}

/// A spawned child being read a line at a time.
#[derive(Debug)]
struct ChildLines {
    program: String,
    /// `None` once the child has been reaped.
    child: Option<Child>,
    rx: Receiver<String>,
    /// Remembered so a second `wait()` -- or `wait()` after `Drop` ran --
    /// gives the same answer instead of failing.
    status: Option<ExitStatus>,
}

impl ChildLines {
    /// Send `signal` to the child, if it is still ours to signal.
    fn signal(&mut self, signal: rustix::process::Signal) -> Result<(), ExecError> {
        let Some(child) = self.child.as_ref() else {
            return Ok(());
        };
        let Ok(raw) = i32::try_from(child.id()) else {
            return Ok(());
        };
        let Some(pid) = rustix::process::Pid::from_raw(raw) else {
            return Ok(());
        };
        match rustix::process::kill_process(pid, signal) {
            // ESRCH: it already exited. Nothing to do and nothing wrong.
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(e) => Err(ExecError::Io {
                program: self.program.clone(),
                source: e.into(),
            }),
        }
    }
}

impl LineStream for ChildLines {
    fn next_line(&mut self) -> Option<String> {
        self.rx.recv().ok()
    }

    fn terminate(&mut self) -> Result<(), ExecError> {
        self.signal(rustix::process::Signal::TERM)
    }

    fn wait(&mut self) -> Result<ExitStatus, ExecError> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        let Some(mut child) = self.child.take() else {
            return Ok(ExitStatus::default());
        };
        let status: ExitStatus = child
            .wait()
            .map_err(|e| ExecError::Io {
                program: self.program.clone(),
                source: e,
            })?
            .into();
        self.status = Some(status);
        Ok(status)
    }
}

impl Drop for ChildLines {
    /// Do not leave a `journalctl -f` running after the `cage audit`
    /// that started it has gone.
    ///
    /// SIGTERM first, for the reasons in [`LineStream::terminate`], then
    /// reap. A child that already exited makes both no-ops.
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.terminate();
            let _ = self.wait();
        }
    }
}

/// Read `pipe` to EOF, appending to `sink` as it goes.
///
/// Chunked rather than `read_to_end` so that two pipes draining into one
/// buffer -- [`Command::merge_stderr`] -- interleave as they arrive
/// instead of concatenating whole streams.
fn drain(mut pipe: impl Read, sink: &Mutex<Vec<u8>>) {
    let mut buf = [0u8; 8192];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => sink
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(&buf[..n]),
        }
    }
}

/// Feed `tx` one message per line of `pipe`, then drop it.
fn spawn_line_reader(pipe: impl Read + Send + 'static, tx: Sender<String>) {
    thread::spawn(move || {
        use std::io::BufRead as _;
        // Lossy so one stray byte in a log line cannot end the stream;
        // `text=True` in the Python would raise, which is worse.
        for line in std::io::BufReader::new(pipe).split(b'\n') {
            let Ok(mut bytes) = line else { return };
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            if tx
                .send(String::from_utf8_lossy(&bytes).into_owned())
                .is_err()
            {
                return; // the reader gave up
            }
        }
    });
}

/// Wait for `child`, killing it if it outlives `limit`.
///
/// Polled rather than event-driven: `std` has no timed wait, the
/// alternatives need `unsafe` or a runtime, and the three commands that
/// set a timeout are a registry round trip and two TPM operations --
/// none of them latency-sensitive at a 5ms granularity.
fn wait_with_timeout(
    child: &mut Child,
    limit: Duration,
    program: &str,
) -> Result<ExitStatus, ExecError> {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.into()),
            Ok(None) => {}
            Err(e) => {
                return Err(ExecError::Io {
                    program: program.to_string(),
                    source: e,
                });
            }
        }
        let now = Instant::now();
        if now >= deadline {
            // SIGKILL, not SIGTERM: this process already ignored its
            // deadline, and `subprocess`'s own timeout handling kills
            // too.
            let _ = child.kill();
            let _ = child.wait();
            return Err(ExecError::Timeout {
                program: program.to_string(),
                after: limit,
            });
        }
        thread::sleep(Duration::from_millis(5).min(deadline - now));
    }
}

/// The `Stdio` for a child's stdin.
fn stdin_stdio(command: &Command, program: &str) -> Result<Stdio, ExecError> {
    Ok(match command.stdin_spec() {
        Stdin::Inherit => Stdio::inherit(),
        Stdin::Null => Stdio::null(),
        Stdin::Bytes { .. } => Stdio::piped(),
        Stdin::File(path) => Stdio::from(File::open(path).map_err(|e| ExecError::Io {
            program: program.to_string(),
            source: e,
        })?),
    })
}

/// The `Stdio` for one output stream, ignoring merging.
fn sink_stdio(sink: &Sink, program: &str) -> Result<Stdio, ExecError> {
    Ok(match sink {
        Sink::Inherit => Stdio::inherit(),
        Sink::Null => Stdio::null(),
        Sink::Capture => Stdio::piped(),
        Sink::Write(path) => Stdio::from(File::create(path).map_err(|e| ExecError::Io {
            program: program.to_string(),
            source: e,
        })?),
    })
}

/// The `Stdio` pair for stdout and stderr, honouring
/// [`Command::merge_stderr`].
///
/// The file case is the only interesting one: a merged file sink clones
/// the handle so both streams share a file offset, which is what a
/// shell's `>f 2>&1` gives. Opening the path twice would give two
/// offsets and each stream would overwrite the other.
fn output_stdio(command: &Command, program: &str) -> Result<(Stdio, Stdio), ExecError> {
    if !command.stderr_is_merged() {
        return Ok((
            sink_stdio(command.stdout_spec(), program)?,
            sink_stdio(command.stderr_spec(), program)?,
        ));
    }
    if let Sink::Write(path) = command.stdout_spec() {
        let file = File::create(path).map_err(|e| ExecError::Io {
            program: program.to_string(),
            source: e,
        })?;
        let dup = file.try_clone().map_err(|e| ExecError::Io {
            program: program.to_string(),
            source: e,
        })?;
        return Ok((Stdio::from(file), Stdio::from(dup)));
    }
    Ok((
        sink_stdio(command.stdout_spec(), program)?,
        sink_stdio(command.stdout_spec(), program)?,
    ))
}

/// Unwrap a buffer that only this function still holds.
fn take(buf: Mutex<Vec<u8>>) -> Vec<u8> {
    buf.into_inner().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::SystemRunner;
    use crate::command::{Command, Sink};
    use crate::outcome::ExecError;
    use crate::runner::CommandRunner as _;
    use std::time::Duration;

    /// These exercise the runner against real processes, so they use
    /// only tools POSIX guarantees: `/bin/sh`, `cat`, `true`, `false`.

    #[test]
    fn captures_stdout_and_stderr_separately() {
        let out = SystemRunner
            .run(
                &Command::new("sh")
                    .args(["-c", "printf out; printf err >&2"])
                    .captured(),
            )
            .unwrap();
        assert!(out.success());
        assert_eq!(out.stdout_text(), "out");
        assert_eq!(out.stderr_text(), "err");
    }

    #[test]
    fn merge_stderr_puts_both_on_stdout() {
        let out = SystemRunner
            .run(
                &Command::new("sh")
                    .args(["-c", "printf err >&2"])
                    .captured()
                    .merge_stderr(),
            )
            .unwrap();
        assert_eq!(out.stdout_text(), "err");
        assert!(out.stderr.is_empty());
    }

    #[test]
    fn a_non_zero_exit_is_ok_not_err() {
        let out = SystemRunner.run(&Command::new("false")).unwrap();
        assert_eq!(out.status.code, Some(1));
        assert!(!out.success());
    }

    #[test]
    fn a_missing_binary_is_not_found() {
        let err = SystemRunner
            .run(&Command::new("agentcage-definitely-absent-4f21"))
            .unwrap_err();
        assert!(err.is_not_found(), "{err:?}");
    }

    /// The whole point of `stdin_secret`: the value reaches the child
    /// without ever appearing in argv.
    #[test]
    fn stdin_bytes_reach_the_child() {
        let out = SystemRunner
            .run(&Command::new("cat").captured().stdin_secret("hunter2"))
            .unwrap();
        assert_eq!(out.stdout_text(), "hunter2");
    }

    #[test]
    fn env_and_cwd_are_applied() {
        let out = SystemRunner
            .run(
                &Command::new("sh")
                    .args(["-c", "printf '%s %s' \"$AGENTCAGE_TEST\" \"$PWD\""])
                    .env("AGENTCAGE_TEST", "set")
                    .cwd("/tmp")
                    .captured(),
            )
            .unwrap();
        assert_eq!(out.stdout_text(), "set /tmp");
    }

    #[test]
    fn env_clear_starts_empty() {
        let out = SystemRunner
            .run(
                &Command::new("env")
                    .env_clear()
                    .env("ONLY", "one")
                    .captured(),
            )
            .unwrap();
        assert_eq!(out.stdout_text().trim(), "ONLY=one");
    }

    #[test]
    fn stdout_can_go_to_a_file_and_stdin_can_come_from_one() {
        let dir = std::env::temp_dir().join(format!("agentcage-exec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("export.tar");

        SystemRunner
            .run(
                &Command::new("sh")
                    .args(["-c", "printf payload"])
                    .stdout(Sink::Write(path.clone())),
            )
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "payload");

        let back = SystemRunner
            .run(&Command::new("cat").captured().stdin_file(&path))
            .unwrap();
        assert_eq!(back.stdout_text(), "payload");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_timeout_kills_the_child() {
        let err = SystemRunner
            .run(
                &Command::new("sh")
                    .args(["-c", "sleep 30"])
                    .captured()
                    .timeout(Duration::from_millis(80)),
            )
            .unwrap_err();
        assert!(matches!(err, ExecError::Timeout { .. }), "{err:?}");
    }

    #[test]
    fn a_signal_death_reports_the_shell_status() {
        let out = SystemRunner
            .run(&Command::new("sh").args(["-c", "kill -TERM $$"]).captured())
            .unwrap();
        assert_eq!(out.status.signal, Some(15));
        assert_eq!(out.status.shell_code(), 143);
    }

    #[test]
    fn streaming_reads_lines_while_the_child_runs() {
        let mut stream = SystemRunner
            .stream(&Command::new("sh").args(["-c", "printf 'a\\nb\\nc\\n'"]))
            .unwrap();
        assert_eq!(stream.collect_lines(), ["a", "b", "c"]);
        assert!(stream.wait().unwrap().success());
    }

    #[test]
    fn streaming_honours_merge_stderr() {
        let mut stream = SystemRunner
            .stream(
                &Command::new("sh")
                    .args(["-c", "printf 'audit\\n' >&2"])
                    .merge_stderr(),
            )
            .unwrap();
        assert_eq!(stream.collect_lines(), ["audit"]);
    }

    #[test]
    fn terminate_stops_an_endless_stream() {
        let mut stream = SystemRunner
            .stream(&Command::new("sh").args(["-c", "printf 'first\\n'; sleep 30"]))
            .unwrap();
        assert_eq!(stream.next_line().as_deref(), Some("first"));
        stream.terminate().unwrap();
        assert_eq!(stream.wait().unwrap().signal, Some(15));
    }

    #[test]
    fn which_agrees_with_running_the_thing() {
        assert!(SystemRunner.has("sh"));
        assert!(!SystemRunner.has("agentcage-definitely-absent-4f21"));
    }
}
