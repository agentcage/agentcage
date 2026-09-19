//! `skopeo` -- the seam half of `src/agentcage/registry.py`.
//!
//! One command, and it is the clearest case in the tree for why
//! [`ExecError::NotFound`] is its own variant. `registry.py` catches
//! `FileNotFoundError` specifically, prints "skopeo is not installed --
//! install it for automatic image version pinning", and returns `None`
//! so the build proceeds with whatever tag is already pinned. A non-zero
//! exit (no such repository, no network) also returns `None`, but
//! silently. Same result, different message, and the difference is
//! visible to the user.
//!
//! Only the subprocess half is here. `_version_key`, the version-tag
//! regex and the arch-suffix filter are pure functions over the tag list
//! and belong wherever `registry.py`'s logic lands; this crate hands
//! them the list.

use serde_json::Value;
use std::time::Duration;

use crate::command::Command;
use crate::outcome::ExecError;
use crate::runner::CommandRunner;

/// The registry round trip's time limit.
///
/// 30 seconds, as `registry.py` sets. A `TimeoutExpired` there returns
/// `None` -- the same degradation as a missing binary -- because a slow
/// registry must not wedge `cage update`.
pub const LIST_TAGS_TIMEOUT: Duration = Duration::from_secs(30);

/// The skopeo CLI.
#[derive(Debug)]
pub struct Skopeo<'a> {
    runner: &'a dyn CommandRunner,
}

impl<'a> Skopeo<'a> {
    /// A skopeo wrapper.
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Self { runner }
    }

    /// The command for `skopeo list-tags docker://<image>`.
    #[must_use]
    pub fn list_tags_command(image: &str) -> Command {
        Command::new("skopeo")
            .args(["list-tags".to_string(), format!("docker://{image}")])
            .captured()
            .timeout(LIST_TAGS_TIMEOUT)
    }

    /// Every tag the registry reports for `image`.
    ///
    /// # Errors
    ///
    /// [`ExecError::NotFound`] when skopeo is not installed -- the case
    /// `registry.py` gives its own message to -- [`ExecError::Timeout`]
    /// after [`LIST_TAGS_TIMEOUT`], [`ExecError::Failed`] on a non-zero
    /// exit, and [`ExecError::Parse`] when the answer is not the
    /// expected JSON. All four mean "no tag", and only the first two are
    /// worth saying out loud.
    pub fn list_tags(&self, image: &str) -> Result<Vec<String>, ExecError> {
        let out = self
            .runner
            .run(&Self::list_tags_command(image))?
            .check("skopeo")?;
        let doc: Value = serde_json::from_slice(&out.stdout).map_err(|e| ExecError::Parse {
            program: "skopeo".to_string(),
            detail: e.to_string(),
        })?;
        Ok(doc
            .get("Tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default())
    }
}
