//! `podman` -- the port of `src/agentcage/podman.py`.
//!
//! Twenty-one invocation shapes, one method each, in the order the
//! Python declares them. `tests/podman_argv.rs` pins every one of them
//! against `tests/test_podman.py`'s expectations.
//!
//! Three behaviours from the Python are load-bearing and easy to lose in
//! translation, so they are called out at their methods:
//!
//! * `no_cache` and `pull` are independent flags, not one flag
//!   ([`BuildOptions`]).
//! * [`Podman::secret_list`] is lenient and [`Podman::secret_list_strict`]
//!   is not, and the difference decides whether `Secret=` directives are
//!   emitted (issue #262).
//! * [`Podman::secret_create`] puts the value on stdin. It is the model
//!   for how every secret should travel.

use serde_json::Value;

use crate::command::{Command, Sink};
use crate::outcome::{ExecError, Output};
use crate::runner::CommandRunner;
use crate::tools::Elevation;

/// A bind mount for [`Podman::run_and_remove`].
///
/// The Python takes `dict[host_path, {"bind": ..., "mode": ...}]` and
/// relies on `dict` order; this is a list because the order is part of
/// the argv and should be visible as such.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeMount {
    /// The host path.
    pub host: String,
    /// The path inside the container. Defaults to [`VolumeMount::host`].
    pub bind: Option<String>,
    /// Mount options (`ro`, `z`, ...). Omitted when empty.
    pub mode: Option<String>,
}

impl VolumeMount {
    /// A mount at the same path inside the container, with no options.
    #[must_use]
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            bind: None,
            mode: None,
        }
    }

    /// Mount at a different path inside the container.
    #[must_use]
    pub fn bind(mut self, path: impl Into<String>) -> Self {
        self.bind = Some(path.into());
        self
    }

    /// Add mount options.
    #[must_use]
    pub fn mode(mut self, mode: impl Into<String>) -> Self {
        self.mode = Some(mode.into());
        self
    }

    /// The `-v` value: `host[:bind][:mode]`.
    #[must_use]
    pub fn spec(&self) -> String {
        let bind = self.bind.as_deref().unwrap_or(&self.host);
        match self.mode.as_deref().filter(|m| !m.is_empty()) {
            Some(mode) => format!("{}:{bind}:{mode}", self.host),
            None => format!("{}:{bind}", self.host),
        }
    }
}

/// Arguments to [`Podman::build_image`].
///
/// A struct rather than eight positional parameters because the Python's
/// are keyword-only past the third, and because `no_cache` and `pull`
/// are the kind of adjacent booleans that get swapped.
#[derive(Debug, Clone, Default)]
pub struct BuildOptions {
    /// `-f <containerfile>`, omitted when `None`.
    pub containerfile: Option<String>,
    /// Capabilities for the build, one `--cap-add` each.
    pub cap_add: Vec<String>,
    /// `--no-cache`: throw away podman's per-layer build cache.
    ///
    /// Independent of [`BuildOptions::pull`], and the Python says so at
    /// length: `no_cache` alone still reuses a stale base image, because
    /// the `FROM` ref is resolved from local storage. `pull` alone still
    /// reuses cached intermediate layers built on the old base. A fully
    /// clean rebuild needs both.
    pub no_cache: bool,
    /// `--pull=always`: re-fetch the `FROM` image from the registry.
    pub pull: bool,
    /// `--build-arg K=V`, in order.
    ///
    /// A list, not a map: the Python iterates a `dict`, so insertion
    /// order is what reaches argv, and a `BTreeMap` here would silently
    /// re-sort it.
    pub build_args: Vec<(String, String)>,
    /// Capture the build output instead of streaming it to the terminal.
    ///
    /// `quiet=True` in the Python, and it changes more than the noise
    /// level: the quiet path captures and raises with the captured
    /// output attached, the loud path streams and raises with nothing.
    pub quiet: bool,
}

/// The podman CLI.
///
/// Holds a runner and an [`Elevation`]; every method builds one command
/// and interprets one result.
#[derive(Debug)]
pub struct Podman<'a> {
    runner: &'a dyn CommandRunner,
    elevation: Elevation,
}

impl<'a> Podman<'a> {
    /// A podman wrapper that detects whether it needs the `runuser`
    /// prefix from the live environment.
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Self::with_elevation(runner, Elevation::detect())
    }

    /// A podman wrapper with an explicit [`Elevation`].
    ///
    /// What tests use, so the `runuser` branch is reachable without
    /// being root.
    #[must_use]
    pub fn with_elevation(runner: &'a dyn CommandRunner, elevation: Elevation) -> Self {
        Self { runner, elevation }
    }

    /// The base command: `podman`, or `runuser -u <user> -- podman`.
    #[must_use]
    pub fn base(&self) -> Command {
        self.elevation.command("podman")
    }

    /// `podman <args>`, with the elevation prefix.
    fn cmd<I, S>(&self, args: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.base().args(args)
    }

    /// Run a command and report whether it exited 0.
    ///
    /// The `r.returncode == 0` shape that half of `podman.py` is.
    fn ran_ok(&self, command: &Command) -> Result<bool, ExecError> {
        Ok(self.runner.run(command)?.success())
    }

    /// Run a command, require exit 0, and parse stdout as JSON.
    fn json(&self, command: &Command) -> Result<Value, ExecError> {
        let out = self.runner.run(command)?.check("podman")?;
        serde_json::from_slice(&out.stdout).map_err(|e| ExecError::Parse {
            program: "podman".to_string(),
            detail: e.to_string(),
        })
    }

    /// As [`Podman::json`], then take the first element of the array.
    ///
    /// `json.loads(r.stdout)[0]`: `podman inspect` and `podman image
    /// inspect` both answer with a one-element array.
    fn json_first(&self, command: &Command) -> Result<Value, ExecError> {
        let value = self.json(command)?;
        value
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .ok_or_else(|| ExecError::Parse {
                program: "podman".to_string(),
                detail: "expected a non-empty JSON array".to_string(),
            })
    }

    // ── images ───────────────────────────────────────────────

    /// `podman image exists <name>`.
    ///
    /// Answers by exit status, which is why the runner must not treat a
    /// non-zero exit as an error.
    ///
    /// # Errors
    ///
    /// Only if podman itself could not be run.
    pub fn image_exists(&self, name: &str) -> Result<bool, ExecError> {
        self.ran_ok(&self.cmd(["image", "exists", name]))
    }

    /// `podman build -t <tag> [flags] <context_dir>`.
    ///
    /// Flag order matches the Python exactly -- `-f`, `--no-cache`,
    /// `--pull=always`, each `--cap-add`, each `--build-arg`, then the
    /// context directory last -- because that order is what the argv
    /// tests pin and what a reader comparing the two files will check.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit. With
    /// [`BuildOptions::quiet`] the error carries the captured stderr;
    /// without it the output already went to the operator's terminal and
    /// there is nothing to attach, which is exactly what
    /// `subprocess.run(check=True)` does.
    pub fn build_image(
        &self,
        tag: &str,
        context_dir: &str,
        options: &BuildOptions,
    ) -> Result<(), ExecError> {
        let mut cmd = self.cmd(["build", "-t", tag]);
        if let Some(containerfile) = &options.containerfile {
            cmd = cmd.args(["-f", containerfile]);
        }
        if options.no_cache {
            cmd = cmd.arg("--no-cache");
        }
        if options.pull {
            cmd = cmd.arg("--pull=always");
        }
        for cap in &options.cap_add {
            cmd = cmd.args(["--cap-add", cap]);
        }
        for (key, value) in &options.build_args {
            cmd = cmd.args(["--build-arg".to_string(), format!("{key}={value}")]);
        }
        cmd = cmd.arg(context_dir);
        if options.quiet {
            cmd = cmd.captured();
        }
        self.runner.run(&cmd)?.check("podman")?;
        Ok(())
    }

    /// `podman image inspect <name>`, first element.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] if the image is absent, [`ExecError::Parse`]
    /// if the answer is not a JSON array.
    pub fn image_inspect(&self, name: &str) -> Result<Value, ExecError> {
        self.json_first(&self.cmd(["image", "inspect", name]).captured())
    }

    /// `podman pull <image>`.
    ///
    /// Streams progress to the terminal and reports success as a bool --
    /// a local-only image or a missing network is a normal outcome here,
    /// not an error.
    ///
    /// # Errors
    ///
    /// Only if podman itself could not be run.
    pub fn pull(&self, image: &str) -> Result<bool, ExecError> {
        self.ran_ok(&self.cmd(["pull", image]))
    }

    // ── containers ───────────────────────────────────────────

    /// `podman run --rm [-v ...] <image> <command...>`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn run_and_remove(
        &self,
        image: &str,
        command: &[String],
        volumes: &[VolumeMount],
    ) -> Result<(), ExecError> {
        let mut cmd = self.cmd(["run", "--rm"]);
        for volume in volumes {
            cmd = cmd.args(["-v".to_string(), volume.spec()]);
        }
        cmd = cmd.arg(image).args(command.iter().cloned());
        self.runner.run(&cmd)?.check("podman")?;
        Ok(())
    }

    /// `podman inspect --format {{.State.Status}} <name>`, compared to
    /// `running`.
    ///
    /// A missing container exits non-zero and is reported as not
    /// running, which is what `cage status` wants.
    ///
    /// # Errors
    ///
    /// Only if podman itself could not be run.
    pub fn container_running(&self, name: &str) -> Result<bool, ExecError> {
        let out = self.runner.run(
            &self
                .cmd(["inspect", "--format", "{{.State.Status}}", name])
                .captured(),
        )?;
        Ok(out.success() && out.stdout_trimmed() == "running")
    }

    /// `podman inspect <name>`, first element.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] if the container is absent.
    pub fn container_inspect(&self, name: &str) -> Result<Value, ExecError> {
        self.json_first(&self.cmd(["inspect", name]).captured())
    }

    /// `podman exec <name> <cmd...>`, returning the exit code and stdout.
    ///
    /// Not checked: `cage verify` runs probes inside the cage whose
    /// failure is the answer, not an error.
    ///
    /// # Errors
    ///
    /// Only if podman itself could not be run.
    pub fn container_exec(
        &self,
        name: &str,
        command: &[String],
    ) -> Result<(i32, String), ExecError> {
        let out = self.runner.run(
            &self
                .cmd(["exec", name])
                .args(command.iter().cloned())
                .captured(),
        )?;
        Ok((out.status.code_or(-1), out.stdout_text()))
    }

    // ── networks and volumes ─────────────────────────────────

    /// `podman network rm <name>`, reporting success as a bool.
    ///
    /// # Errors
    ///
    /// Only if podman itself could not be run.
    pub fn network_remove(&self, name: &str) -> Result<bool, ExecError> {
        self.ran_ok(&self.cmd(["network", "rm", name]).captured())
    }

    /// `podman volume rm <name>`, reporting success as a bool.
    ///
    /// # Errors
    ///
    /// Only if podman itself could not be run.
    pub fn volume_remove(&self, name: &str) -> Result<bool, ExecError> {
        self.ran_ok(&self.cmd(["volume", "rm", name]).captured())
    }

    /// `podman volume exists <name>`.
    ///
    /// # Errors
    ///
    /// Only if podman itself could not be run.
    pub fn volume_exists(&self, name: &str) -> Result<bool, ExecError> {
        self.ran_ok(&self.cmd(["volume", "exists", name]))
    }

    /// `podman volume create <name>`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn volume_create(&self, name: &str) -> Result<(), ExecError> {
        self.runner
            .run(&self.cmd(["volume", "create", name]).captured())?
            .check("podman")?;
        Ok(())
    }

    /// `podman volume export <name> > <output_path>`.
    ///
    /// The tar stream goes straight to the file. `cage backup` on a
    /// workspace volume can be gigabytes, and there is no reason for any
    /// of it to pass through agentcage's address space.
    ///
    /// # Errors
    ///
    /// [`ExecError::Io`] if the file cannot be created,
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn volume_export(&self, name: &str, output_path: &str) -> Result<(), ExecError> {
        self.runner
            .run(
                &self
                    .cmd(["volume", "export", name])
                    .stdout(Sink::Write(output_path.into())),
            )?
            .check("podman")?;
        Ok(())
    }

    /// `podman volume import <name> - < <tar_path>`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Io`] if the archive cannot be opened,
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn volume_import(&self, name: &str, tar_path: &str) -> Result<(), ExecError> {
        self.runner
            .run(
                &self
                    .cmd(["volume", "import", name, "-"])
                    .stdin_file(tar_path),
            )?
            .check("podman")?;
        Ok(())
    }

    // ── host ─────────────────────────────────────────────────

    /// `podman info --format json`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit, [`ExecError::Parse`] if
    /// the answer is not JSON.
    pub fn info(&self) -> Result<Value, ExecError> {
        self.json(&self.cmd(["info", "--format", "json"]).captured())
    }

    // ── secrets ──────────────────────────────────────────────

    /// The `podman secret ls --noheading --format {{.Name}}` command.
    fn secret_ls_cmd(&self) -> Command {
        self.cmd(["secret", "ls", "--noheading", "--format", "{{.Name}}"])
            .captured()
    }

    /// List secret names, optionally filtered by prefix. Lenient.
    ///
    /// A non-zero exit yields an empty list. `cage show`, `secret list`
    /// and `destroy_resources` all rely on that: a podman hiccup should
    /// not crash a read-only command.
    ///
    /// This is the wrong function for the store-aware `Secret=` gate;
    /// see [`Podman::secret_list_strict`].
    ///
    /// # Errors
    ///
    /// Only if podman itself could not be run -- which is the same thing
    /// the Python does, since a `FileNotFoundError` from `subprocess`
    /// escapes its `try`.
    pub fn secret_list(&self, prefix: &str) -> Result<Vec<String>, ExecError> {
        let out = self.runner.run(&self.secret_ls_cmd())?;
        Ok(parse_secret_list(&out, prefix))
    }

    /// List secret names, failing on a `podman secret ls` failure.
    ///
    /// The distinction matters and is not stylistic (issue #262). The
    /// quadlet generator emits a `Secret=` directive per secret that
    /// exists in the store. If a transient failure were reported as an
    /// empty store, it would emit *no* directives and the cage would
    /// start with none of its credentials. So this raises instead, and
    /// the caller's fallback is the legacy emit-everything behaviour --
    /// a cage with too many directives, not one with none.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn secret_list_strict(&self, prefix: &str) -> Result<Vec<String>, ExecError> {
        let out = self.runner.run(&self.secret_ls_cmd())?;
        if !out.success() {
            let detail = {
                let stderr = out.stderr_text();
                let text = if stderr.trim().is_empty() {
                    out.stdout_text()
                } else {
                    stderr
                };
                text.trim().to_string()
            };
            return Err(ExecError::Failed {
                program: "podman secret ls".to_string(),
                status: out.status,
                stderr: detail,
            });
        }
        Ok(parse_secret_list(&out, prefix))
    }

    /// `podman secret inspect <name>`, as a bool.
    ///
    /// # Errors
    ///
    /// Only if podman itself could not be run.
    pub fn secret_exists(&self, name: &str) -> Result<bool, ExecError> {
        self.ran_ok(&self.cmd(["secret", "inspect", name]).captured())
    }

    /// `podman secret create <name> - ` with the value **on stdin**.
    ///
    /// The trailing `-` is what makes this safe, and it is the pattern
    /// every secret-bearing call in this crate should copy. An argv
    /// carrying the value would be readable by every process on the host
    /// through `/proc/<pid>/cmdline` for as long as podman ran; a pipe
    /// is visible only to its two ends.
    ///
    /// stdout is discarded because podman echoes the new secret's ID and
    /// nothing reads it.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    pub fn secret_create(&self, name: &str, value: &str) -> Result<(), ExecError> {
        self.runner
            .run(
                &self
                    .cmd(["secret", "create", name, "-"])
                    .stdin_secret(value)
                    .stdout_null(),
            )?
            .check("podman")?;
        Ok(())
    }

    /// `podman secret inspect --showsecret --format {{.SecretData}} <name>`.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] if the secret does not exist.
    pub fn secret_read(&self, name: &str) -> Result<String, ExecError> {
        let out = self
            .runner
            .run(
                &self
                    .cmd([
                        "secret",
                        "inspect",
                        "--showsecret",
                        "--format",
                        "{{.SecretData}}",
                        name,
                    ])
                    .captured(),
            )?
            .check("podman")?;
        Ok(out.stdout_trimmed())
    }

    /// `podman secret rm <name>`, reporting success as a bool.
    ///
    /// # Errors
    ///
    /// Only if podman itself could not be run.
    pub fn secret_remove(&self, name: &str) -> Result<bool, ExecError> {
        self.ran_ok(&self.cmd(["secret", "rm", name]).captured())
    }
}

/// Keep the names that start with `prefix`; keep all of them when it is
/// empty.
///
/// `podman.py::filter_secrets_by_prefix`, shared by the host and VM
/// implementations. The Python returns `[{"Name": n}]`; the dict was
/// only ever there because `podman secret ls --format json` used to be
/// parsed, and every caller immediately reads `["Name"]`.
#[must_use]
pub fn filter_secrets_by_prefix(names: &[String], prefix: &str) -> Vec<String> {
    if prefix.is_empty() {
        return names.to_vec();
    }
    names
        .iter()
        .filter(|n| n.starts_with(prefix))
        .cloned()
        .collect()
}

/// Lenient parse of a `podman secret ls` result: empty on failure or
/// empty output.
///
/// `podman.py::_parse_secret_list`, shared by the host and VM lenient
/// listers.
#[must_use]
pub fn parse_secret_list(output: &Output, prefix: &str) -> Vec<String> {
    if !output.success() {
        return Vec::new();
    }
    filter_secrets_by_prefix(&output.stdout_lines(), prefix)
}

/// Anything that can pull and inspect an image.
///
/// `cli._update_image_digests` picks its `inspector` at run time: host
/// podman for a container cage, the Lima-routed `VmPodman` for a vm
/// cage whose guest is up — because a vm cage's images live in the
/// guest's store and inspecting the host's would report every one of
/// them `unavailable`, and a fingerprint over `unavailable` never
/// matches twice. This is that choice written down.
pub trait ImageInspector {
    /// `podman pull <reference>`, reporting whether it worked.
    ///
    /// # Errors
    ///
    /// Only if the underlying command could not be run.
    fn pull(&self, reference: &str) -> Result<bool, ExecError>;

    /// `podman image inspect <reference>`, first element.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] when the image is unknown.
    fn image_inspect(&self, reference: &str) -> Result<serde_json::Value, ExecError>;

    /// Whether a refresh is possible at all.
    ///
    /// `can_refresh` in the Python: false for a vm cage whose guest is
    /// not running, where there is nothing to pull *into*.
    fn can_refresh(&self) -> bool {
        true
    }
}

impl ImageInspector for Podman<'_> {
    fn pull(&self, reference: &str) -> Result<bool, ExecError> {
        Self::pull(self, reference)
    }

    fn image_inspect(&self, reference: &str) -> Result<serde_json::Value, ExecError> {
        Self::image_inspect(self, reference)
    }
}

/// Anything that can list a cage's podman secrets.
///
/// The host [`Podman`] here, and the Lima-routed `VmPodman` that E1
/// adds. `podman.py::secret_env_names` takes "any object with the
/// `secret_list(prefix=...)` interface" and then does
/// `getattr(podman_like, "secret_list_strict", None) or ...`; this is
/// that duck type written down.
pub trait SecretLister {
    /// List secret names with this prefix, leniently.
    ///
    /// # Errors
    ///
    /// Only if the underlying command could not be run.
    fn secret_list(&self, prefix: &str) -> Result<Vec<String>, ExecError>;

    /// List secret names with this prefix, failing on a listing failure.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] when the listing itself failed.
    fn secret_list_strict(&self, prefix: &str) -> Result<Vec<String>, ExecError>;
}

impl SecretLister for Podman<'_> {
    fn secret_list(&self, prefix: &str) -> Result<Vec<String>, ExecError> {
        Self::secret_list(self, prefix)
    }

    fn secret_list_strict(&self, prefix: &str) -> Result<Vec<String>, ExecError> {
        Self::secret_list_strict(self, prefix)
    }
}

/// Env-name set, deploy prefix stripped, of the store entries for a cage.
///
/// `podman.py::secret_env_names`. Secrets are stored as
/// `{deploy_name}.{ENV}` when a deploy name is set and as bare `ENV`
/// otherwise; the quadlet generator wants the env names.
///
/// Uses the strict lister on purpose, so a transient failure propagates
/// to the caller's fallback rather than arriving as an empty set -- see
/// [`Podman::secret_list_strict`].
///
/// # Errors
///
/// [`ExecError::Failed`] when the listing failed.
pub fn secret_env_names<L: SecretLister + ?Sized>(
    lister: &L,
    deploy_name: &str,
) -> Result<Vec<String>, ExecError> {
    let prefix = if deploy_name.is_empty() {
        String::new()
    } else {
        format!("{deploy_name}.")
    };
    let names = lister.secret_list_strict(&prefix)?;
    if prefix.is_empty() {
        return Ok(names);
    }
    Ok(names
        .iter()
        .map(|n| n[prefix.len()..].to_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{VolumeMount, filter_secrets_by_prefix, parse_secret_list};
    use crate::outcome::Output;

    #[test]
    fn mount_specs_match_the_python() {
        assert_eq!(VolumeMount::new("/h").spec(), "/h:/h");
        assert_eq!(VolumeMount::new("/h").bind("/c").spec(), "/h:/c");
        assert_eq!(
            VolumeMount::new("/h").bind("/c").mode("ro").spec(),
            "/h:/c:ro"
        );
        // An empty mode is dropped, as `if mode:` does.
        assert_eq!(VolumeMount::new("/h").mode("").spec(), "/h:/h");
    }

    #[test]
    fn prefix_filtering_keeps_everything_when_the_prefix_is_empty() {
        let names = vec!["a.K".to_string(), "b.K".to_string()];
        assert_eq!(filter_secrets_by_prefix(&names, ""), names);
        assert_eq!(filter_secrets_by_prefix(&names, "a."), ["a.K"]);
    }

    #[test]
    fn the_lenient_parse_swallows_a_failure() {
        assert!(parse_secret_list(&Output::failed(1, "daemon unavailable"), "").is_empty());
        assert!(parse_secret_list(&Output::ok(""), "").is_empty());
        assert_eq!(parse_secret_list(&Output::ok("a\nb\n"), ""), ["a", "b"]);
    }
}
