//! `state.py::_atomic_write_text`, ported branch for branch.
//!
//! This is a 30-line function with a 25-line docstring, and the
//! docstring is load-bearing. It is reproduced below because every
//! sentence in it corresponds to a branch here, and because the one
//! thing a reader will want to "clean up" — the refusal to unlink a
//! colliding temp file — is the whole point.
//!
//! ## The Python, verbatim
//!
//! > Atomically write *text* to *p* via a PID-suffixed temp + rename.
//! >
//! > The temp lives in the same directory (so `os.replace` is atomic on
//! > a single filesystem) and is opened with `O_CREAT | O_EXCL` so a
//! > planted symlink at the temp path cannot be written through. The
//! > base temp name is PID-suffixed (`<p>.<pid>.tmp`); the grants
//! > reconcile and any `cage update` / `domain add` run on the host,
//! > and the in-container addon runs in a different PID namespace (or
//! > on a different host), so the two sides normally never collide on
//! > the same numeric PID.
//! >
//! > On `FileExistsError` (a leftover temp from a crashed writer, OR —
//! > because PID namespaces share a numeric space — a *different*
//! > writer's in-flight temp at the same numeric PID) the writer does
//! > NOT unlink the colliding temp: unlinking a concurrent writer's
//! > in-flight file would make its later rename fail (a lost write).
//! > Instead it retries ONCE with a counter-suffixed name
//! > (`<p>.<pid>.1.tmp`); a concurrent writer using the same base
//! > cannot be using the counter-suffixed name unless it too collided,
//! > in which case its own counter differs (or both abort — neither
//! > loses its write). If the retry also hits `FileExistsError` the
//! > write is aborted (never write through / delete an existing file).
//! > This never deletes anything. The final `tmp.replace(p)` is the
//! > atomic publish.
//! >
//! > Used by `save_raw_config`, `save_metadata`, and `save_grants` so
//! > the grants reconcile (`cage grants sync` / `domain list`) and any
//! > concurrent `cage update` / `domain add` never observe a
//! > half-written file: they see either the old contents or the new
//! > contents, never a truncated prefix that would raise YAMLError /
//! > JSONDecodeError and abort the reconcile.
//!
//! ## What that means for the port
//!
//! Four invariants, each of which a plausible Rust rewrite breaks:
//!
//! 1. **`O_EXCL`, not truncate.** `File::create` would happily write
//!    through a symlink an attacker planted at the predictable temp
//!    path. [`std::fs::OpenOptions::create_new`] is `O_CREAT|O_EXCL`.
//! 2. **Two candidate names, then give up.** Not a loop until success:
//!    a loop would spin against a hostile or stuck writer, and the
//!    second name's whole safety argument is that it is reached only
//!    by a writer that already collided.
//! 3. **Nothing is ever unlinked except this call's own temp, and only
//!    when the write itself failed.** A collision leaves the other
//!    file alone.
//! 4. **The mode of an existing file is preserved** across the
//!    replace, under whatever umask the process happens to have. The
//!    Python opens with `mode` *and then* `fchmod`s, because the open
//!    mode is masked by the umask and `fchmod` is not. Both steps are
//!    here.
//!
//! ## Why the tests race for real
//!
//! A single-threaded test of an atomicity primitive proves nothing.
//! `tests/atomic_race.rs` runs concurrent writers — threads sharing
//! one PID, which is the *worst* case since they all pick the same
//! base name, and separate child processes, which is the realistic
//! one — against concurrent readers that assert every read is one
//! complete document.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::{Result, StateError};

/// The mode a brand-new file is opened with.
///
/// `os.open(tmp, ..., mode if mode is not None else 0o644)`. Masked by
/// the umask, like any `open(2)`, so a `umask 077` process still gets
/// 0600 — and *is not* followed by an `fchmod`, so the umask keeps its
/// say. Only a file that already existed has its exact mode restored.
const DEFAULT_MODE: u32 = 0o644;

/// Atomically write `text` to `path`.
///
/// See the module docs. In one line: same-directory temp opened
/// `O_CREAT|O_EXCL` under a PID-suffixed name, one counter-suffixed
/// retry, then `rename(2)`.
///
/// # Errors
///
/// * [`StateError::TempCollision`] when both candidate names exist —
///   the Python's final `raise FileExistsError`, and a *successful*
///   refusal rather than a failure to be retried blindly.
/// * [`StateError::Io`] for anything else: the parent directory could
///   not be created, the temp could not be written, the rename failed.
///
/// A failed write removes its own temp file and leaves `path`
/// untouched.
pub fn atomic_write_text(path: &Path, text: &str) -> Result<()> {
    atomic_write_text_as(path, text, std::process::id())
}

/// [`atomic_write_text`] with the PID chosen by the caller.
///
/// Exists for the tests, and it is not a convenience: the failure this
/// function is built for is *two different processes picking the same
/// numeric PID*, which happens when one of them is in a container's PID
/// namespace. There is no way to reproduce that from a test suite by
/// forking, and mocking `getpid` reaches inside the thing under test.
/// Passing the number in makes the collision a parameter, so the retry
/// and the give-up branch can both be driven deterministically.
///
/// # Errors
///
/// As [`atomic_write_text`].
pub fn atomic_write_text_as(path: &Path, text: &str, pid: u32) -> Result<()> {
    // `p.parent.mkdir(parents=True, exist_ok=True)`.
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|source| StateError::io(parent, "create directory", source))?;
    }

    // `try: mode = p.stat().st_mode & 0o777 / except FileNotFoundError:
    // mode = None`. A *different* stat error is not swallowed.
    let mode = match fs::metadata(path) {
        Ok(meta) => Some(meta.permissions().mode() & 0o777),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(StateError::io(path, "stat", error)),
    };

    let candidates = temp_candidates(path, pid);

    // The loop is over exactly two names, and only `AlreadyExists`
    // advances it. Anything else is a real error and propagates, as the
    // Python's bare `except FileExistsError` lets it.
    let mut opened: Option<(PathBuf, File)> = None;
    for candidate in &candidates {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode.unwrap_or(DEFAULT_MODE))
            .open(candidate)
        {
            Ok(file) => {
                opened = Some((candidate.clone(), file));
                break;
            }
            // `except FileExistsError: continue` -- try the next
            // candidate name, and only that one.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(StateError::io(candidate, "create temp file", error)),
        }
    }

    let Some((tmp, mut file)) = opened else {
        // Both names exist. Abort rather than unlink a possible
        // concurrent writer's in-flight temp. The Python raises
        // FileExistsError with this exact sentence.
        return Err(StateError::TempCollision {
            target: path.to_path_buf(),
            first: file_name(&candidates[0]),
            second: file_name(&candidates[1]),
        });
    };

    // `except BaseException: unlink(tmp); raise` — a guard rather than
    // a `match`, so a panic between here and `disarm()` cleans up too.
    // The release profile keeps unwinding panics precisely so this
    // runs (see the root `Cargo.toml`).
    let mut guard = TempGuard::new(&tmp);

    // Preserve existing permissions even under a different current
    // umask; brand-new files without a source keep what the umask made
    // of DEFAULT_MODE. `os.fchmod(f.fileno(), mode)` -- on the open
    // descriptor, not on the path, so a swapped file cannot be
    // chmodded by mistake.
    if let Some(mode) = mode {
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|source| StateError::io(&tmp, "set permissions", source))?;
    }
    file.write_all(text.as_bytes())
        .map_err(|source| StateError::io(&tmp, "write", source))?;
    // `os.fdopen(...)` closing is where Python would surface a write
    // error; close explicitly so the same is true here.
    drop(file);

    // The atomic publish. `Path.replace` is `os.replace`, which is
    // `rename(2)`: atomic within one filesystem, and the temp is a
    // sibling of the target precisely so it always is one.
    fs::rename(&tmp, path).map_err(|source| StateError::io(&tmp, "rename into place", source))?;
    guard.disarm();
    Ok(())
}

/// `<p>.<pid>.tmp`, then `<p>.<pid>.1.tmp`.
///
/// Both are siblings of the target, which is what makes the final
/// rename atomic, and both are derived from `p.name` rather than the
/// full path so a long directory name cannot push them over `NAME_MAX`
/// any more than the target already does.
fn temp_candidates(path: &Path, pid: u32) -> [PathBuf; 2] {
    let name = file_name(path);
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    [
        parent.join(format!("{name}.{pid}.tmp")),
        parent.join(format!("{name}.{pid}.1.tmp")),
    ]
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Removes the temp file unless the write got all the way to a rename.
///
/// `except BaseException: try: os.unlink(tmp) except OSError: pass`.
/// The `except OSError: pass` is why this ignores its own errors: by
/// the time cleanup runs, something has already gone wrong, and the
/// original error is the one worth reporting.
#[derive(Debug)]
struct TempGuard {
    path: Option<PathBuf>,
}

impl TempGuard {
    fn new(path: &Path) -> Self {
        Self {
            path: Some(path.to_path_buf()),
        }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{atomic_write_text, atomic_write_text_as, temp_candidates};
    use crate::error::StateError;
    use crate::testdir::TestDir;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    #[test]
    fn the_temp_names_are_the_pythons() {
        let names = temp_candidates(Path::new("/x/cage.yaml"), 4242);
        assert_eq!(names[0], Path::new("/x/cage.yaml.4242.tmp"));
        assert_eq!(names[1], Path::new("/x/cage.yaml.4242.1.tmp"));
    }

    #[test]
    fn it_creates_the_parent_directory() {
        let dir = TestDir::new("atomic-mkdir");
        let target = dir.path().join("deep/deeper/cage.yaml");
        atomic_write_text(&target, "name: x\n").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "name: x\n");
    }

    #[test]
    fn a_collision_on_the_base_name_falls_through_to_the_counter() {
        let dir = TestDir::new("atomic-retry");
        let target = dir.path().join("cage.yaml");
        // Stand in for a crashed writer's leftover, or a same-numbered
        // PID in another namespace holding its temp open.
        fs::write(dir.path().join("cage.yaml.777.tmp"), "IN FLIGHT").unwrap();

        atomic_write_text_as(&target, "second\n", 777).unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "second\n");
        // The colliding temp is STILL THERE. Unlinking it would make
        // the other writer's rename fail, which is a lost write.
        assert_eq!(
            fs::read_to_string(dir.path().join("cage.yaml.777.tmp")).unwrap(),
            "IN FLIGHT"
        );
        // And the counter-suffixed one was renamed away, not left.
        assert!(!dir.path().join("cage.yaml.777.1.tmp").exists());
    }

    #[test]
    fn both_names_taken_aborts_and_deletes_nothing() {
        let dir = TestDir::new("atomic-abort");
        let target = dir.path().join("cage.yaml");
        fs::write(&target, "original\n").unwrap();
        fs::write(dir.path().join("cage.yaml.777.tmp"), "A").unwrap();
        fs::write(dir.path().join("cage.yaml.777.1.tmp"), "B").unwrap();

        let error = atomic_write_text_as(&target, "new\n", 777).unwrap_err();
        let StateError::TempCollision { first, second, .. } = &error else {
            panic!("expected a collision, got {error:?}");
        };
        assert_eq!(first, "cage.yaml.777.tmp");
        assert_eq!(second, "cage.yaml.777.1.tmp");
        // The Python's sentence, which a user may well see.
        assert!(
            error.to_string().contains("cannot create atomic temp for"),
            "{error}"
        );

        // Never write through, never delete.
        assert_eq!(fs::read_to_string(&target).unwrap(), "original\n");
        assert_eq!(
            fs::read_to_string(dir.path().join("cage.yaml.777.tmp")).unwrap(),
            "A"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("cage.yaml.777.1.tmp")).unwrap(),
            "B"
        );
    }

    #[test]
    fn an_existing_files_mode_survives_the_replace() {
        let dir = TestDir::new("atomic-mode");
        let target = dir.path().join("pending_secrets.json");
        fs::write(&target, "[]").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

        atomic_write_text(&target, r#"[["K","V"]]"#).unwrap();

        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "0600 state file came back as {mode:o}");
    }

    #[test]
    fn a_symlink_at_the_temp_path_is_not_written_through() {
        // The reason for O_EXCL. A predictable temp name in a
        // world-writable-ish directory is a classic symlink target.
        let dir = TestDir::new("atomic-symlink");
        let target = dir.path().join("cage.yaml");
        let victim = dir.path().join("victim");
        fs::write(&victim, "PRECIOUS").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("cage.yaml.777.tmp")).unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("cage.yaml.777.1.tmp")).unwrap();

        let error = atomic_write_text_as(&target, "attacker\n", 777).unwrap_err();
        assert!(
            matches!(error, StateError::TempCollision { .. }),
            "{error:?}"
        );
        assert_eq!(fs::read_to_string(&victim).unwrap(), "PRECIOUS");
    }
}
