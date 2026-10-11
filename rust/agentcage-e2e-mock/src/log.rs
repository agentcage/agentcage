//! The phase 9 services' append-only logs, read back by the phase with
//! `podman exec <cage>-svc cat /tmp/mock-log/<file>`.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Where the services log by default.
pub const DEFAULT_DIR: &str = "/tmp/mock-log";

/// A directory of line-oriented log files shared by every service thread.
#[derive(Debug)]
pub struct LogDir {
    dir: PathBuf,
    // One lock for all files: appends are tiny, and serializing them keeps
    // a line from two threads from interleaving.
    lock: Mutex<()>,
}

impl LogDir {
    /// Create `dir` (and its parents) and log into it.
    ///
    /// # Errors
    /// When the directory cannot be created.
    pub fn create(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            lock: Mutex::new(()),
        })
    }

    /// Append `line` to `name`, with any trailing CR/LF replaced by one LF.
    ///
    /// Best effort: a full disk must not turn into a protocol error the
    /// relay under test would then be blamed for.
    pub fn append(&self, name: &str, line: &str) {
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let line = line.trim_end_matches(['\r', '\n']);
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(name))
        {
            let _ = writeln!(file, "{line}");
        }
    }
}
