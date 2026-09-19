//! What to run, and how its three streams are wired.
//!
//! [`Command`] is a plain description: building one runs nothing. That
//! matters for the argv tests, which build a command and inspect it, and
//! for [`crate::FakeRunner`], which records the whole struct rather than
//! just the argv -- so `env`, `cwd`, the stdin payload and the timeout
//! are all part of the recorded contract instead of side channels a fake
//! cannot see.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where one of a child's output streams goes.
///
/// The variants line up with `subprocess`'s, because the Python being
/// ported uses all four and translating between two different vocabularies
/// at the seam would be one more thing to get wrong.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Sink {
    /// The child writes to agentcage's own stream.
    ///
    /// The default, matching `subprocess.run`'s. `cage exec`,
    /// `podman build` and `limactl start` all want this, and making it
    /// the default means the streaming cases are the ones that say
    /// nothing rather than the ones that have to opt out.
    #[default]
    Inherit,
    /// The child's output is discarded (`/dev/null`).
    Null,
    /// The child's output is collected into [`crate::Output`].
    Capture,
    /// The child's output is written to a file, truncating it.
    ///
    /// `podman volume export <name>` with `stdout=f`: the tar stream is
    /// large and there is no reason for it to pass through agentcage's
    /// address space.
    Write(PathBuf),
}

/// Where a child's stdin comes from.
#[derive(Clone, PartialEq, Eq, Default)]
pub enum Stdin {
    /// The child reads agentcage's stdin. The default.
    #[default]
    Inherit,
    /// The child reads `/dev/null`.
    ///
    /// `run.py`'s proxy monitor needs this: its `podman logs -f` runs
    /// alongside an interactive `podman exec -it`, and on the VM backend
    /// the monitor is wrapped in `limactl shell` -> ssh, which reads its
    /// stdin to forward it. Sharing the terminal makes the two children
    /// race for the operator's keystrokes.
    Null,
    /// The child is fed these bytes, and then sees EOF.
    ///
    /// `secret` is set by [`Command::stdin_secret`] and controls nothing
    /// but this type's `Debug`; see the module docs in [`crate`].
    Bytes {
        /// The payload.
        data: Vec<u8>,
        /// Whether the payload is secret material.
        secret: bool,
    },
    /// The child reads from a file.
    ///
    /// `podman volume import <name> -` with `stdin=f`.
    File(PathBuf),
}

impl fmt::Debug for Stdin {
    /// Never prints payload bytes for a secret.
    ///
    /// `Command`'s `Debug` is what lands in a panic message when an argv
    /// assertion fails, so this is the last line of defence between a
    /// `podman secret create` test and a CI log with a credential in it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inherit => f.write_str("Inherit"),
            Self::Null => f.write_str("Null"),
            Self::File(p) => write!(f, "File({})", p.display()),
            Self::Bytes { data, secret: true } => {
                write!(f, "Bytes(<{} redacted bytes>)", data.len())
            }
            Self::Bytes {
                data,
                secret: false,
            } => write!(f, "Bytes({:?})", String::from_utf8_lossy(data)),
        }
    }
}

/// A process to run: argv, environment, cwd, stdio and limits.
///
/// Construct with [`Command::new`] and chain; every builder method takes
/// and returns `self`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Command {
    program: String,
    args: Vec<String>,
    secret_args: Vec<usize>,
    env: BTreeMap<String, Option<String>>,
    env_cleared: bool,
    cwd: Option<PathBuf>,
    stdin: Stdin,
    stdout: Sink,
    stderr: Sink,
    merge_stderr: bool,
    timeout: Option<Duration>,
    new_process_group: bool,
}

impl Command {
    /// A command that runs `program` with no arguments and inherits
    /// agentcage's stdio, environment and working directory.
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            ..Self::default()
        }
    }

    /// Append one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append several arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Append an argument that carries secret material.
    ///
    /// This does **not** make it safe. Anything in argv is readable by
    /// any process on the host through `/proc/<pid>/cmdline`, for as long
    /// as the child lives, and the project's rule is that secrets go on
    /// stdin instead ([`Command::stdin_secret`]).
    ///
    /// What it buys is two things. The value is redacted from this type's
    /// `Debug`, so it cannot reach a panic message or a recorded-call
    /// dump. And the call site reads `.secret_arg(value)`, which makes
    /// every violation of the rule greppable -- there is exactly one in
    /// the tree being ported, in [`crate::tools::security`], and it
    /// should stay countable.
    #[must_use]
    pub fn secret_arg(mut self, arg: impl Into<String>) -> Self {
        self.secret_args.push(self.args.len());
        self.args.push(arg.into());
        self
    }

    /// Set an environment variable for the child.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), Some(value.into()));
        self
    }

    /// Remove an environment variable the child would otherwise inherit.
    #[must_use]
    pub fn env_remove(mut self, key: impl Into<String>) -> Self {
        self.env.insert(key.into(), None);
        self
    }

    /// Start the child's environment empty rather than inheriting.
    ///
    /// Applied before the [`Command::env`] entries, so
    /// `.env_clear().env("PATH", p)` yields exactly one variable.
    #[must_use]
    pub fn env_clear(mut self) -> Self {
        self.env_cleared = true;
        self
    }

    /// Run the child with this working directory.
    #[must_use]
    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// Capture both stdout and stderr, the way `capture_output=True` does.
    #[must_use]
    pub fn captured(mut self) -> Self {
        self.stdout = Sink::Capture;
        self.stderr = Sink::Capture;
        self
    }

    /// Set stdout's disposition.
    #[must_use]
    pub fn stdout(mut self, sink: Sink) -> Self {
        self.stdout = sink;
        self
    }

    /// Set stderr's disposition. Ignored while [`Command::merge_stderr`] is set.
    #[must_use]
    pub fn stderr(mut self, sink: Sink) -> Self {
        self.stderr = sink;
        self
    }

    /// Write the child's stdout to `path`, truncating it.
    #[must_use]
    pub fn stdout_file(self, path: impl Into<PathBuf>) -> Self {
        self.stdout(Sink::Write(path.into()))
    }

    /// Discard the child's stdout.
    #[must_use]
    pub fn stdout_null(self) -> Self {
        self.stdout(Sink::Null)
    }

    /// Send the child's stderr wherever its stdout goes (`2>&1`).
    ///
    /// Used by every audit and log-filtering path: the mitmproxy addon
    /// writes audit JSON to stderr and dnsmasq's lines arrive on the same
    /// stream, so the reader wants one interleaved pipe.
    ///
    /// The real runner approximates this with two pipes drained into one
    /// buffer rather than a genuine `dup2`, because the workspace forbids
    /// `unsafe` and `std` has no safe way to alias a child's descriptors.
    /// Relative order *within* each stream is preserved; order *between*
    /// them is arrival order at the reader. For a line-oriented log
    /// stream that is the same guarantee a shell's `2>&1` gives in
    /// practice, since both sides are block-buffered pipes.
    #[must_use]
    pub fn merge_stderr(mut self) -> Self {
        self.merge_stderr = true;
        self
    }

    /// Feed `text` to the child's stdin.
    ///
    /// For non-secret payloads only; use [`Command::stdin_secret`]
    /// otherwise, so the value stays out of `Debug` output.
    #[must_use]
    pub fn stdin_text(self, text: impl Into<String>) -> Self {
        self.stdin_bytes(text.into().into_bytes(), false)
    }

    /// Feed secret material to the child's stdin.
    ///
    /// The right channel for a credential: a pipe is visible only to the
    /// two processes on its ends, unlike argv.
    #[must_use]
    pub fn stdin_secret(self, text: impl Into<String>) -> Self {
        self.stdin_bytes(text.into().into_bytes(), true)
    }

    /// Feed raw bytes to the child's stdin.
    #[must_use]
    pub fn stdin_bytes(mut self, data: Vec<u8>, secret: bool) -> Self {
        self.stdin = Stdin::Bytes { data, secret };
        self
    }

    /// Connect the child's stdin to a file.
    #[must_use]
    pub fn stdin_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.stdin = Stdin::File(path.into());
        self
    }

    /// Connect the child's stdin to `/dev/null`.
    #[must_use]
    pub fn stdin_null(mut self) -> Self {
        self.stdin = Stdin::Null;
        self
    }

    /// Kill the child and fail with [`crate::ExecError::Timeout`] after
    /// `limit`.
    ///
    /// The Python sets this in three places, all of them calls that can
    /// block on something outside the host: `skopeo list-tags` (30s, a
    /// network round trip), `systemd-creds encrypt` (30s, a TPM that can
    /// be slow or contended) and the systemd-creds capability probe (5s).
    #[must_use]
    pub fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = Some(limit);
        self
    }

    /// Put the child in its own process group.
    ///
    /// `limactl start` forks a hostagent daemon and only then exits;
    /// `instance.py` passes `start_new_session=True` so the daemon is not
    /// tied to agentcage's process group.
    ///
    /// The difference worth writing down: Python's `start_new_session`
    /// is `setsid()`, which also detaches the controlling terminal. This
    /// is `setpgid(0, 0)` via `std`'s safe `process_group`, which is as
    /// far as the workspace's `unsafe_code = "forbid"` allows without a
    /// `pre_exec` closure. It achieves the stated purpose -- the child is
    /// out of agentcage's process group, so terminal signals and group
    /// waits do not reach it -- but the daemon keeps the controlling tty.
    /// If E4 finds Lima needs a full session, that is the PR to revisit
    /// it in, with a real Lima host to check against.
    #[must_use]
    pub fn new_process_group(mut self) -> Self {
        self.new_process_group = true;
        self
    }

    // ── accessors ────────────────────────────────────────────
    //
    // `SystemRunner` and `FakeRunner` live in other modules, and tests
    // in other crates assert on these, so the fields are read through
    // methods rather than being `pub`.

    /// The program to run: `argv[0]`.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// The arguments after `argv[0]`.
    ///
    /// Named `arguments` rather than `args` because [`Command::args`] is
    /// the builder. Secret arguments are included verbatim; prefer
    /// [`Command::argv_redacted`] anywhere the result might be printed.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.args
    }

    /// The full argv, program first, secret arguments included verbatim.
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(self.args.len() + 1);
        argv.push(self.program.clone());
        argv.extend(self.args.iter().cloned());
        argv
    }

    /// The full argv with every [`Command::secret_arg`] replaced by
    /// `<redacted>`.
    ///
    /// What every `Display`, `Debug` and error message in this crate
    /// uses.
    #[must_use]
    pub fn argv_redacted(&self) -> Vec<String> {
        let mut argv = self.argv();
        for &i in &self.secret_args {
            argv[i + 1] = "<redacted>".to_string();
        }
        argv
    }

    /// Indices into [`Command::args`] that hold secret material.
    #[must_use]
    pub fn secret_arg_indices(&self) -> &[usize] {
        &self.secret_args
    }

    /// Environment changes for the child: `None` means "unset it".
    #[must_use]
    pub fn env_changes(&self) -> &BTreeMap<String, Option<String>> {
        &self.env
    }

    /// Whether the child starts from an empty environment.
    #[must_use]
    pub fn env_is_cleared(&self) -> bool {
        self.env_cleared
    }

    /// The child's working directory, when it differs from agentcage's.
    #[must_use]
    pub fn cwd_path(&self) -> Option<&Path> {
        self.cwd.as_deref()
    }

    /// The child's stdin.
    #[must_use]
    pub fn stdin_spec(&self) -> &Stdin {
        &self.stdin
    }

    /// The child's stdout.
    #[must_use]
    pub fn stdout_spec(&self) -> &Sink {
        &self.stdout
    }

    /// The child's stderr, ignoring [`Command::merge_stderr`].
    #[must_use]
    pub fn stderr_spec(&self) -> &Sink {
        &self.stderr
    }

    /// Whether stderr follows stdout.
    #[must_use]
    pub fn stderr_is_merged(&self) -> bool {
        self.merge_stderr
    }

    /// The time limit, if any.
    #[must_use]
    pub fn timeout_limit(&self) -> Option<Duration> {
        self.timeout
    }

    /// Whether the child gets its own process group.
    #[must_use]
    pub fn is_new_process_group(&self) -> bool {
        self.new_process_group
    }

    /// The bytes destined for the child's stdin, secret or not.
    #[must_use]
    pub fn stdin_bytes_ref(&self) -> Option<&[u8]> {
        match &self.stdin {
            Stdin::Bytes { data, .. } => Some(data),
            _ => None,
        }
    }

    /// A shell-ish rendering of the redacted argv, for error messages.
    ///
    /// Not a shell-quoting implementation and not meant to be pasted --
    /// it exists so `ExecError`'s `Display` can name the command that
    /// failed.
    #[must_use]
    pub fn display(&self) -> String {
        self.argv_redacted().join(" ")
    }
}

// The omissions are the point: a `Command` has eleven fields and nine
// of them are at their default in almost every call, so a derived
// `Debug` would bury the argv -- which is the thing under test -- in
// noise. `secret_args` is omitted outright because `argv` already shows
// its effect.
#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for Command {
    /// Redacts secret arguments and secret stdin; prints only the fields
    /// that differ from the defaults, so an argv assertion failure is
    /// readable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Command");
        d.field("argv", &self.argv_redacted());
        if self.env_cleared {
            d.field("env_cleared", &true);
        }
        if !self.env.is_empty() {
            d.field("env", &self.env);
        }
        if let Some(cwd) = &self.cwd {
            d.field("cwd", &cwd.display().to_string());
        }
        if self.stdin != Stdin::Inherit {
            d.field("stdin", &self.stdin);
        }
        if self.stdout != Sink::Inherit {
            d.field("stdout", &self.stdout);
        }
        if self.merge_stderr {
            d.field("stderr", &"MergeIntoStdout");
        } else if self.stderr != Sink::Inherit {
            d.field("stderr", &self.stderr);
        }
        if let Some(t) = self.timeout {
            d.field("timeout", &t);
        }
        if self.new_process_group {
            d.field("new_process_group", &true);
        }
        d.finish()
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

/// Look `program` up on `PATH` the way `shutil.which` does.
///
/// Shared by [`crate::SystemRunner`]'s `which` and by the candidate-path
/// search in [`crate::tools::apple`]. An absolute or relative path with a
/// separator in it is tested directly rather than joined onto `PATH`,
/// which is what `shutil.which` does and what
/// `apple_container/cli.py`'s `shutil.which("/usr/local/bin/container")`
/// relies on.
#[must_use]
pub fn which_on_path(program: &str) -> Option<PathBuf> {
    let candidate = Path::new(program);
    if candidate.components().count() > 1 || candidate.is_absolute() {
        return is_executable_file(candidate).then(|| candidate.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|p| is_executable_file(p))
}

/// Whether `path` is a file the current process may execute.
///
/// `shutil.which` uses `os.access(p, os.X_OK)`; the closest portable
/// stand-in is the file's mode with any execute bit set, which is what
/// matters for the binaries agentcage looks for.
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.is_file() && meta.permissions().mode() & 0o111 != 0
}

/// Convert a [`Command`] into the `std` type that actually spawns.
///
/// Lives here rather than in [`crate::system`] so the mapping from this
/// crate's vocabulary to `std`'s is next to the vocabulary it maps.
/// Stdio is *not* set here: [`crate::system`] owns that, because a
/// [`Sink::Capture`] means different things to `run` and to `stream`.
pub(crate) fn to_std_command(cmd: &Command) -> std::process::Command {
    let mut std_cmd = std::process::Command::new(&cmd.program);
    std_cmd.args(cmd.args.iter().map(OsStr::new));
    if cmd.env_cleared {
        std_cmd.env_clear();
    }
    for (key, value) in &cmd.env {
        match value {
            Some(v) => std_cmd.env(key, v),
            None => std_cmd.env_remove(key),
        };
    }
    if let Some(dir) = &cmd.cwd {
        std_cmd.current_dir(dir);
    }
    if cmd.new_process_group {
        use std::os::unix::process::CommandExt as _;
        std_cmd.process_group(0);
    }
    std_cmd
}

#[cfg(test)]
mod tests {
    use super::{Command, Sink, Stdin};
    use std::time::Duration;

    #[test]
    fn defaults_match_subprocess_run() {
        let cmd = Command::new("podman").arg("info");
        assert_eq!(cmd.argv(), ["podman", "info"]);
        assert_eq!(cmd.stdin_spec(), &Stdin::Inherit);
        assert_eq!(cmd.stdout_spec(), &Sink::Inherit);
        assert_eq!(cmd.stderr_spec(), &Sink::Inherit);
        assert!(!cmd.stderr_is_merged());
        assert_eq!(cmd.timeout_limit(), None);
        assert!(cmd.cwd_path().is_none());
    }

    #[test]
    fn captured_sets_both_streams() {
        let cmd = Command::new("podman").captured();
        assert_eq!(cmd.stdout_spec(), &Sink::Capture);
        assert_eq!(cmd.stderr_spec(), &Sink::Capture);
    }

    /// env and cwd are recorded, not side channels.
    #[test]
    fn env_and_cwd_are_part_of_the_command() {
        let cmd = Command::new("podman")
            .env("CONTAINERS_CONF", "/etc/x.conf")
            .env_remove("XDG_RUNTIME_DIR")
            .cwd("/ctx");
        assert_eq!(
            cmd.env_changes().get("CONTAINERS_CONF"),
            Some(&Some("/etc/x.conf".to_string()))
        );
        assert_eq!(cmd.env_changes().get("XDG_RUNTIME_DIR"), Some(&None));
        assert_eq!(cmd.cwd_path().unwrap().to_str(), Some("/ctx"));
    }

    /// A secret stdin payload must not be printable.
    #[test]
    fn secret_stdin_is_redacted_in_debug() {
        let cmd = Command::new("podman")
            .args(["secret", "create", "cage.KEY", "-"])
            .stdin_secret("hunter2");
        let rendered = format!("{cmd:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
        // ...but a test that asks for it on purpose still gets it.
        assert_eq!(cmd.stdin_bytes_ref(), Some(&b"hunter2"[..]));
    }

    /// A non-secret payload prints, because hiding it would make every
    /// other argv assertion harder to debug for no benefit.
    #[test]
    fn plain_stdin_is_not_redacted() {
        let cmd = Command::new("systemd-creds").stdin_text("probe");
        assert!(format!("{cmd:?}").contains("probe"));
    }

    #[test]
    fn secret_args_are_redacted_but_still_sent() {
        let cmd = Command::new("security")
            .args(["add-generic-password", "-w"])
            .secret_arg("hunter2");
        assert_eq!(
            cmd.argv(),
            ["security", "add-generic-password", "-w", "hunter2"]
        );
        assert_eq!(
            cmd.argv_redacted(),
            ["security", "add-generic-password", "-w", "<redacted>"]
        );
        assert!(!format!("{cmd:?}").contains("hunter2"));
        assert!(!cmd.display().contains("hunter2"));
        assert_eq!(cmd.secret_arg_indices(), [2]);
    }

    #[test]
    fn debug_omits_defaults_and_shows_the_rest() {
        let plain = format!("{:?}", Command::new("podman").arg("info"));
        assert!(!plain.contains("stdin"), "{plain}");
        assert!(!plain.contains("timeout"), "{plain}");

        let rich = format!(
            "{:?}",
            Command::new("skopeo")
                .arg("list-tags")
                .captured()
                .timeout(Duration::from_secs(30))
                .merge_stderr()
                .new_process_group()
        );
        assert!(rich.contains("Capture"), "{rich}");
        assert!(rich.contains("MergeIntoStdout"), "{rich}");
        assert!(rich.contains("timeout"), "{rich}");
        assert!(rich.contains("new_process_group"), "{rich}");
    }

    #[test]
    fn which_finds_a_real_binary_and_rejects_a_directory() {
        assert!(super::which_on_path("sh").is_some());
        assert!(super::which_on_path("/tmp").is_none());
        assert!(super::which_on_path("definitely-not-a-binary-9f3a").is_none());
    }
}
