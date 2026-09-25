//! Apple's `container`(1) -- the port of
//! `src/agentcage/apple_container/cli.py`.
//!
//! The binary is installed by the Apple `container` .pkg at
//! `/usr/local/bin/container`, which is not on `PATH` for every
//! non-login shell -- including the one agentcage is often started from
//! -- so the path is resolved explicitly against a candidate list.
//!
//! This module is reachable from Linux CI. `test_apple_container.py`
//! already exercises the Mac backend on Linux by patching
//! `platform.system()`; the equivalent here is
//! [`crate::FakeRunner::stub_which`], which is why binary resolution
//! goes through the runner rather than calling `which` directly.

use serde_json::Value;

use crate::command::Command;
use crate::outcome::{ExecError, Output};
use crate::runner::CommandRunner;

/// Where the `container` .pkg and Homebrew put the binary.
///
/// Searched in order, after `PATH`.
pub const CANDIDATE_PATHS: [&str; 2] = ["/usr/local/bin/container", "/opt/homebrew/bin/container"];

/// Apple's `container` CLI.
#[derive(Debug)]
pub struct AppleContainer<'a> {
    runner: &'a dyn CommandRunner,
}

impl<'a> AppleContainer<'a> {
    /// A wrapper over `container`(1).
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Self { runner }
    }

    /// The resolved path to the binary, or `None` when it is not
    /// installed.
    ///
    /// `PATH` first, then [`CANDIDATE_PATHS`], which is what
    /// `container_binary()` does -- and note that the Python probes the
    /// candidates with `shutil.which(absolute_path)`, i.e. it still
    /// checks executability rather than mere existence.
    #[must_use]
    pub fn binary(&self) -> Option<String> {
        if let Some(path) = self.runner.which("container") {
            return Some(path.to_string_lossy().into_owned());
        }
        CANDIDATE_PATHS.iter().find_map(|p| {
            self.runner
                .which(p)
                .map(|p| p.to_string_lossy().into_owned())
        })
    }

    /// The command for `container <args>`.
    ///
    /// # Errors
    ///
    /// [`ExecError::NotFound`] when the binary is not installed. The
    /// Python raises `FileNotFoundError` with an install URL here; the
    /// URL belongs in the CLI's error presentation, not in the seam, so
    /// this returns the variant and lets D5 phrase it.
    pub fn command<I, S>(&self, args: I) -> Result<Command, ExecError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let binary = self
            .binary()
            .ok_or_else(|| ExecError::not_found("container"))?;
        Ok(Command::new(binary).args(args))
    }

    /// Run `container <args>` and capture its output.
    ///
    /// # Errors
    ///
    /// [`ExecError::NotFound`] when the binary is missing,
    /// [`ExecError::Failed`] on a non-zero exit when `check` is set.
    pub fn run<I, S>(&self, args: I, check: bool) -> Result<Output, ExecError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let out = self.runner.run(&self.command(args)?.captured())?;
        if check {
            out.check("container")
        } else {
            Ok(out)
        }
    }

    /// Run `container <args>` with its output attached to the terminal.
    ///
    /// The streaming half of the Python's `run(capture_output=False)`.
    /// That branch also wraps the call in `output.pause_active_spinner()`
    /// because Apple's CLI writes its own progress -- `[1/2] Fetching
    /// image [13s]` -- to stderr and would fight an agentcage spinner for
    /// the line. The spinner lives in D4's `output` module, so the pause
    /// belongs at the call site there, not here; this crate has no
    /// terminal state to coordinate with.
    ///
    /// # Errors
    ///
    /// [`ExecError::NotFound`] when the binary is missing,
    /// [`ExecError::Failed`] on a non-zero exit when `check` is set.
    pub fn run_streaming<I, S>(&self, args: I, check: bool) -> Result<Output, ExecError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let out = self.runner.run(&self.command(args)?)?;
        if check {
            out.check("container")
        } else {
            Ok(out)
        }
    }

    /// Whether the `container` apiserver is running.
    ///
    /// `container system status`, with the Python's substring test on
    /// stdout rather than the exit code. A missing binary answers
    /// `false` rather than erroring, the way its `except
    /// FileNotFoundError` does.
    ///
    /// # Errors
    ///
    /// Only if the binary exists but could not be run at all.
    pub fn system_running(&self) -> Result<bool, ExecError> {
        match self.run(["system", "status"], false) {
            Ok(out) => {
                let stdout = out.stdout_text();
                Ok(stdout.contains("status") && stdout.contains("running"))
            }
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `container inspect <name>`, or `None` when the container is absent.
    ///
    /// # Errors
    ///
    /// Only if the binary exists but could not be run at all. A missing
    /// binary, a non-zero exit and unparseable JSON all answer `None`,
    /// matching `except (FileNotFoundError, JSONDecodeError)`.
    pub fn inspect(&self, name: &str) -> Result<Option<Value>, ExecError> {
        self.inspect_args(&["inspect".to_string(), name.to_string()])
    }

    /// `container image inspect <image>`, or `None` when it is absent.
    ///
    /// # Errors
    ///
    /// As [`AppleContainer::inspect`].
    pub fn image_inspect(&self, image: &str) -> Result<Option<Value>, ExecError> {
        self.inspect_args(&[
            "image".to_string(),
            "inspect".to_string(),
            image.to_string(),
        ])
    }

    /// The shared body of the two inspect calls.
    fn inspect_args(&self, args: &[String]) -> Result<Option<Value>, ExecError> {
        let out = match self.run(args.iter().cloned(), false) {
            Ok(out) => out,
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => return Err(e),
        };
        if !out.success() {
            return Ok(None);
        }
        let Ok(value) = serde_json::from_slice::<Value>(&out.stdout) else {
            return Ok(None);
        };
        // `data[0] if isinstance(data, list) and data else data`
        Ok(Some(match value.as_array() {
            Some(items) if !items.is_empty() => items[0].clone(),
            _ => value,
        }))
    }
}

/// The run state from an [`AppleContainer::inspect`] result, tolerating
/// both schemas.
///
/// Apple's CLI changed the shape in v1.0.0: the state used to be a
/// top-level string (`status == "running"`) and is now nested
/// (`status.state == "running"`, next to `networks` and `startedDate`).
/// Comparing `data["status"]` to `"running"` therefore broke silently
/// against 1.0 -- a dict never equals a string, so every cage looked
/// stopped and the egress readiness wait raised a spurious "exited
/// before becoming ready".
#[must_use]
pub fn container_state(data: Option<&Value>) -> Option<String> {
    let data = data?;
    let status = data.get("status").or_else(|| data.get("Status"))?;
    if status.is_object() {
        return status
            .get("state")
            .or_else(|| status.get("State"))
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    status.as_str().map(str::to_string)
}

/// The network entries from an [`AppleContainer::inspect`] result,
/// tolerating both schemas.
///
/// The same v1.0.0 reshuffle as [`container_state`]: `networks` moved
/// under the nested `status` object. Reading the top level returned `[]`
/// against 1.0 and the cage could never learn the egress sibling's
/// gateway IP. The nested location wins.
#[must_use]
pub fn container_networks(data: Option<&Value>) -> Vec<Value> {
    let Some(data) = data else {
        return Vec::new();
    };
    if let Some(status) = data.get("status").filter(|s| s.is_object()) {
        let nested = status
            .get("networks")
            .or_else(|| status.get("Networks"))
            .and_then(Value::as_array);
        if let Some(nets) = nested.filter(|n| !n.is_empty()) {
            return nets.clone();
        }
    }
    data.get("networks")
        .or_else(|| data.get("Networks"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{container_networks, container_state};
    use serde_json::json;

    /// Both `container inspect` schemas, which is the bug these two
    /// helpers exist for.
    #[test]
    fn state_reads_the_pre_1_0_and_1_0_shapes() {
        let old = json!({"status": "running"});
        let new = json!({"status": {"state": "running", "networks": []}});
        assert_eq!(container_state(Some(&old)).as_deref(), Some("running"));
        assert_eq!(container_state(Some(&new)).as_deref(), Some("running"));
        assert_eq!(container_state(None), None);
        assert_eq!(container_state(Some(&json!({}))), None);
    }

    #[test]
    fn networks_prefer_the_nested_location() {
        let old = json!({"networks": [{"gateway": "10.0.0.1"}]});
        let new = json!({"status": {"state": "running", "networks": [{"gateway": "10.0.0.2"}]}});
        assert_eq!(container_networks(Some(&old)).len(), 1);
        assert_eq!(
            container_networks(Some(&new))[0]["gateway"],
            json!("10.0.0.2")
        );
        assert!(container_networks(None).is_empty());
        // Nested-but-empty falls back to the top level.
        let mixed = json!({"status": {"networks": []}, "networks": [{"gateway": "10.0.0.3"}]});
        assert_eq!(container_networks(Some(&mixed)).len(), 1);
    }
}
