//! What can go wrong reading or writing state.
//!
//! The Python raises `OSError`, `ValueError`, `FileNotFoundError`,
//! `yaml.YAMLError` and `json.JSONDecodeError` from these paths, and
//! `cli.py` turns most of them into a click error with the message
//! attached. So the variants here are grouped by *what the CLI has to
//! say about it*, not by which syscall failed:
//!
//! * [`StateError::Io`] carries the path, because "No such file or
//!   directory" on its own is useless in a message.
//! * [`StateError::Config`] is `agentcage-core`'s own error passed
//!   through unchanged — `config.py`'s wording is asserted verbatim by
//!   the golden corpus and must not be re-wrapped.
//! * [`StateError::TempCollision`] is its own variant rather than an
//!   `Io` because it is the one failure that is *correct behaviour*:
//!   see [`crate::atomic`].
//! * [`StateError::Value`] is the `ValueError` a caller raises about
//!   content rather than about I/O — `resolve_relay_ca_files`'s two
//!   messages, which are reproduced byte for byte, and the
//!   "this file is not the shape it has to be" complaints from the
//!   JSON readers. There is no `Json` variant: the crate's JSON goes
//!   through `agentcage_core::har::json`, whose parse error is not a
//!   `std::error::Error`, and a malformed state file is a sentence a
//!   user reads rather than an error a caller matches on.

use std::fmt;
use std::path::{Path, PathBuf};

use agentcage_core::config::ConfigError;

/// The result type every fallible function in this crate returns.
pub type Result<T> = std::result::Result<T, StateError>;

/// A failure reading or writing agentcage's on-disk state.
#[derive(Debug)]
#[non_exhaustive]
pub enum StateError {
    /// A filesystem operation failed.
    Io {
        /// What was being touched.
        path: PathBuf,
        /// What was being attempted, as a verb phrase: `"read"`,
        /// `"create temp file"`, `"rename into place"`.
        doing: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A stored file that has to exist does not.
    ///
    /// Separate from [`StateError::Io`] because the Python raises
    /// `FileNotFoundError` with its *own* message here rather than
    /// letting the OS one through — `"No stored config for deployment
    /// '<name>'"` — and `cage show` on a typo'd name is a common
    /// enough path that the wording matters.
    Missing {
        /// The message, exactly as the Python composes it.
        message: String,
        /// The file that was looked for.
        path: PathBuf,
    },
    /// The file parsed as YAML but not as a config.
    Config(ConfigError),
    /// A stored file is not valid YAML.
    Yaml {
        /// The file.
        path: PathBuf,
        /// The parser's complaint.
        source: agentcage_core::yaml::Error,
    },
    /// Both atomic-temp candidate names were already taken.
    ///
    /// The write did not happen and **nothing was deleted**. See
    /// [`crate::atomic`] for why aborting is the right answer.
    TempCollision {
        /// The file that was to be written.
        target: PathBuf,
        /// `<name>.<pid>.tmp`.
        first: String,
        /// `<name>.<pid>.1.tmp`.
        second: String,
    },
    /// A `systemctl` invocation failed, or could not be made.
    ///
    /// Passed through from `agentcage-exec` rather than flattened to a
    /// string: [`agentcage_exec::ExecError::is_not_found`] is the one
    /// bit `backends/container.py` branches on, and re-wrapping would
    /// take it away.
    Systemd(agentcage_exec::ExecError),
    /// A `ValueError` about the content of a file.
    Value(String),
}

impl StateError {
    /// Build an [`StateError::Io`].
    pub(crate) fn io(path: impl AsRef<Path>, doing: &'static str, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_path_buf(),
            doing,
            source,
        }
    }

    /// Build a [`StateError::Missing`].
    pub(crate) fn missing(message: impl Into<String>, path: impl AsRef<Path>) -> Self {
        Self::Missing {
            message: message.into(),
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Build a [`StateError::Value`].
    pub(crate) fn value(message: impl Into<String>) -> Self {
        Self::Value(message.into())
    }

    /// Whether this is a "the file is not there" failure.
    ///
    /// The Python distinguishes these constantly — `load_metadata`
    /// returns `{}`, `load_fingerprint` returns `None`, `load_grants`
    /// returns `[]` — and the readers here do the same, so this is for
    /// the callers that have to decide it themselves.
    #[must_use]
    pub fn is_missing(&self) -> bool {
        match self {
            Self::Missing { .. } => true,
            Self::Io { source, .. } => source.kind() == std::io::ErrorKind::NotFound,
            _ => false,
        }
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                path,
                doing,
                source,
            } => {
                write!(f, "cannot {doing} {}: {source}", path.display())
            }
            // `Missing` and `Value` render the same way and mean
            // different things: one is a `FileNotFoundError` with the
            // Python's own wording, the other a `ValueError` about a
            // file's content. Merging the arms would tie them together.
            Self::Missing { message, .. } | Self::Value(message) => f.write_str(message),
            Self::Config(error) => f.write_str(error.message()),
            Self::Yaml { path, source } => {
                write!(f, "{} is not valid YAML: {source}", path.display())
            }
            Self::TempCollision {
                target,
                first,
                second,
            } => write!(
                f,
                "cannot create atomic temp for {}: both {first} and {second} exist",
                target.display()
            ),
            Self::Systemd(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Yaml { source, .. } => Some(source),
            Self::Systemd(source) => Some(source),
            _ => None,
        }
    }
}

impl From<agentcage_exec::ExecError> for StateError {
    fn from(error: agentcage_exec::ExecError) -> Self {
        Self::Systemd(error)
    }
}

impl From<ConfigError> for StateError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

#[cfg(test)]
mod tests {
    use super::StateError;
    use std::path::PathBuf;

    #[test]
    fn the_collision_message_is_the_pythons() {
        let error = StateError::TempCollision {
            target: PathBuf::from("/s/cage.yaml"),
            first: "cage.yaml.9.tmp".to_owned(),
            second: "cage.yaml.9.1.tmp".to_owned(),
        };
        assert_eq!(
            error.to_string(),
            "cannot create atomic temp for /s/cage.yaml: \
             both cage.yaml.9.tmp and cage.yaml.9.1.tmp exist"
        );
    }

    #[test]
    fn a_missing_file_says_so_in_the_pythons_words() {
        let error = StateError::missing(
            "No stored config for deployment 'nope'",
            "/s/cages/nope/cage.yaml",
        );
        assert_eq!(error.to_string(), "No stored config for deployment 'nope'");
        assert!(error.is_missing());
    }
}
