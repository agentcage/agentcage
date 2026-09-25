//! Materializing the embedded trees as a podman build context.
//!
//! `backends/container.py:70` hands podman the installed package's own
//! `data/` directory:
//!
//! ```text
//! data_dir = Path(__file__).resolve().parent.parent / "data"
//! build_context = str(data_dir)
//! ```
//!
//! and `vm.py:593` pushes that same tree into the Lima guest, and the
//! apple-container backend builds from it too. A Rust binary has no
//! package directory, so [`ensure_extracted`] writes one.
//!
//! # Where
//!
//! `$XDG_DATA_HOME/agentcage/assets/<version>-<digest>`, falling back to
//! `~/.local/share`. That is the same root `state.py:215` and
//! `services.patches_work_dir` already use, and `patches` is the
//! precedent: extracted package data, refreshed from the binary,
//! overwritten rather than edited.
//!
//! # Invalidation
//!
//! The directory name carries the binary version *and*
//! [`crate::assets_digest`], so a new binary never reuses an old tree
//! and a rebuilt binary with changed assets never reuses the previous
//! one. The version alone would not be enough during development, where
//! the assets change constantly and the version does not.
//!
//! Note this is deliberately *not* [`crate::egress::content_hash`]. That
//! digest covers only the egress image's `COPY` sources; a change to
//! `templates/lima/provision.sh.j2` or `scaffolds/codex/Containerfile`
//! leaves it untouched, and keying the cache on it would serve a stale
//! `templates/` tree from a correct-looking directory.
//!
//! # Concurrency
//!
//! Two `agentcage` processes can race here — `cage create` in one
//! terminal while `init` runs in another is ordinary usage. The approach
//! is **atomic rename, no lock file**: each process extracts into a
//! private staging directory beside the target and then `rename(2)`s it
//! into place. A directory either exists complete or does not exist at
//! all; no reader can observe a half-written tree, which is the failure
//! a lock is usually reached for.
//!
//! `rename` onto an existing non-empty directory fails with `ENOTEMPTY`,
//! so the loser of a race does not clobber the winner: it sees the
//! target present, drops its staging copy and uses the winner's. Both
//! trees were byte-identical anyway — the directory name is a content
//! digest — so which one wins does not matter.
//!
//! A lock file would have been worse here: it needs a stale-lock policy,
//! it serializes work that is idempotent, and a process killed between
//! `mkdir` and `write` leaves a plausible-looking empty tree behind. The
//! only thing a lock buys is not extracting twice, and extraction is
//! 79 files and half a megabyte.
//!
//! # Durability
//!
//! Not `fsync`ed. This is a cache keyed by content digest, and the cost
//! of a power loss between the writes and the rename is a tree that
//! looks complete but is not. `egress::content_hash_from_dir` recomputes
//! the digest from an extracted tree, so `agentcage doctor` (Track D)
//! can detect exactly that without this path paying for 79 `fsync`s on
//! every cold start.

use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{EMBEDDED_TREES, VERSION, assets_digest, embedded_files};

/// Mode for every directory the extraction creates.
///
/// Set explicitly rather than left to the umask, for the same reason the
/// file modes are: the tree has to be reproducible, and a contributor
/// with `umask 077` should get the same build context as everyone else.
const DIR_MODE: u32 = 0o755;

/// The directory holding every extracted tree, one per `<version>-<digest>`.
///
/// Honours `XDG_DATA_HOME`, matching `state._DATA_DIR` and
/// `services.patches_work_dir` on the Python side.
#[must_use]
pub fn cache_root() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map_or_else(
            || {
                std::env::var_os("HOME").map_or_else(
                    || PathBuf::from("/tmp"),
                    |home| PathBuf::from(home).join(".local").join("share"),
                )
            },
            PathBuf::from,
        );
    base.join("agentcage").join("assets")
}

/// The cache key: this binary's version and a digest of everything it carries.
///
/// See the module docs for why the digest is [`crate::assets_digest`]
/// and not the egress content hash.
#[must_use]
pub fn tag() -> String {
    format!("{VERSION}-{}", assets_digest())
}

/// Extract the embedded trees if they are not already on disk.
///
/// Returns the directory containing `data/`, `templates/` and
/// `scaffolds/`. Idempotent and safe to call concurrently from several
/// processes; see the module docs.
///
/// # Errors
///
/// Any I/O error that is not "someone else won the race".
pub fn ensure_extracted() -> io::Result<PathBuf> {
    ensure_extracted_in(&cache_root())
}

/// [`ensure_extracted`], into a caller-chosen cache root.
///
/// Exists so tests do not write to the developer's real
/// `~/.local/share`, and so `AGENTCAGE_ASSETS_DIR`-style overrides have
/// somewhere to land when Track D needs one.
///
/// # Errors
///
/// Any I/O error that is not "someone else won the race".
pub fn ensure_extracted_in(cache_root: &Path) -> io::Result<PathBuf> {
    let target = cache_root.join(tag());
    if target.is_dir() {
        return Ok(target);
    }

    fs::create_dir_all(cache_root)?;
    fs::set_permissions(cache_root, fs::Permissions::from_mode(DIR_MODE)).ok();

    let staging = cache_root.join(staging_name());
    // A previous run killed mid-extraction cannot collide (the name
    // carries the pid and a timestamp), but be defensive: a stale
    // directory here would silently merge into the new one.
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }

    if let Err(err) = write_tree(&staging) {
        let _ = fs::remove_dir_all(&staging);
        return Err(err);
    }

    match fs::rename(&staging, &target) {
        Ok(()) => Ok(target),
        Err(err) => {
            // ENOTEMPTY/EEXIST: another process finished first. Its tree
            // is byte-identical to ours -- the name is a content digest
            // -- so take theirs and drop ours.
            let _ = fs::remove_dir_all(&staging);
            if target.is_dir() {
                Ok(target)
            } else {
                Err(err)
            }
        }
    }
}

/// The extracted `data/` directory: the podman build context.
///
/// This is the path that replaces `Path(__file__).parent.parent / "data"`
/// at `backends/container.py:70`.
///
/// # Errors
///
/// Any I/O error from [`ensure_extracted`].
pub fn build_context() -> io::Result<PathBuf> {
    build_context_in(&cache_root())
}

/// [`build_context`], from a caller-chosen cache root.
///
/// # Errors
///
/// Any I/O error from [`ensure_extracted_in`].
pub fn build_context_in(cache_root: &Path) -> io::Result<PathBuf> {
    Ok(ensure_extracted_in(cache_root)?.join("data"))
}

/// A staging directory name no concurrent extraction can collide with.
///
/// The leading dot keeps it out of the way of anything listing the cache
/// root for `<version>-<digest>` directories.
fn staging_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(".staging-{}-{}-{nanos}", tag(), std::process::id())
}

/// Write every embedded file under `root`, creating parents as needed.
fn write_tree(root: &Path) -> io::Result<()> {
    create_dir(root)?;
    for tree in EMBEDDED_TREES {
        create_dir(&root.join(tree))?;
    }

    for file in embedded_files() {
        let dest = root.join(file.path);
        if let Some(parent) = dest.parent() {
            create_dir_all(parent)?;
        }
        // `create_new` so a name collision is an error rather than a
        // silent overwrite, and `mode` so the file is never briefly
        // more permissive than it should be.
        let mut handle = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(file.mode)
            .open(&dest)?;
        handle.write_all(file.bytes)?;
        drop(handle);
        // `OpenOptions::mode` is masked by the umask, so a contributor
        // with `umask 077` would otherwise get 0600 where the source
        // tree has 0644. Force the exact mode. Nothing in these three
        // trees is a secret -- they are the proxy's own source, shipped
        // in a public package -- so widening past the umask is the right
        // call here and would not be for anything under `cage-env/`.
        fs::set_permissions(&dest, fs::Permissions::from_mode(file.mode))?;
    }
    Ok(())
}

/// `mkdir` with an explicit mode, tolerating an existing directory.
fn create_dir(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(DIR_MODE))
}

/// [`create_dir`], for a whole path.
fn create_dir_all(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    create_dir(path)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use super::{DIR_MODE, build_context_in, cache_root, ensure_extracted_in, tag};
    use crate::{EMBEDDED_TREES, VERSION, egress, embedded_files};

    /// A scratch directory that removes itself.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "agentcage-b3-{label}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("scratch directory is creatable");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Walk a directory into `relpath -> (bytes, mode)`.
    fn snapshot(root: &Path) -> BTreeMap<String, (Vec<u8>, u32)> {
        fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, (Vec<u8>, u32)>) {
            for entry in std::fs::read_dir(dir).expect("directory is readable") {
                let entry = entry.expect("entry is readable");
                let name = entry.file_name().into_string().expect("UTF-8 name");
                let rel = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                let path = entry.path();
                if path.is_dir() {
                    if name == "__pycache__" {
                        continue;
                    }
                    walk(&path, &rel, out);
                } else if !crate::egress::is_excluded(&name) {
                    let bytes = std::fs::read(&path).expect("file is readable");
                    let mode = std::fs::metadata(&path)
                        .expect("file is stat-able")
                        .permissions()
                        .mode()
                        & 0o777;
                    out.insert(rel, (bytes, mode));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(root, "", &mut out);
        out
    }

    /// The acceptance criterion: the extracted tree *is* the source tree.
    ///
    /// Walks both, compares the path sets, then every file's bytes, then
    /// every file's mode. Not a digest comparison -- a digest would say
    /// "different" and leave you guessing, and the point of this test is
    /// to name what moved.
    #[test]
    fn the_extracted_tree_is_byte_and_mode_identical_to_the_source() {
        let scratch = Scratch::new("identical");
        let extracted = ensure_extracted_in(&scratch.0).expect("extraction succeeds");

        let source_root = crate::tests::repo_root().join(crate::PACKAGE_ROOT);
        let mut expected = BTreeMap::new();
        for tree in EMBEDDED_TREES {
            for (rel, entry) in snapshot(&source_root.join(tree)) {
                expected.insert(format!("{tree}/{rel}"), entry);
            }
        }
        let actual = snapshot(&extracted);

        let expected_paths: Vec<&String> = expected.keys().collect();
        let actual_paths: Vec<&String> = actual.keys().collect();
        assert_eq!(expected_paths, actual_paths, "file sets differ");

        for (rel, (bytes, mode)) in &expected {
            let (got_bytes, got_mode) = &actual[rel];
            assert_eq!(
                got_bytes.len(),
                bytes.len(),
                "{rel}: extracted {} bytes, source {}",
                got_bytes.len(),
                bytes.len()
            );
            assert!(got_bytes == bytes, "{rel}: contents differ");
            // The source mode is whatever the checkout's umask produced;
            // the embed normalizes to git's two values, so compare the
            // bit that git actually records.
            assert_eq!(
                got_mode & 0o100,
                mode & 0o100,
                "{rel}: extracted 0o{got_mode:o}, source 0o{mode:o}"
            );
            assert!(
                *got_mode == 0o644 || *got_mode == 0o755,
                "{rel}: unexpected extracted mode 0o{got_mode:o}"
            );
        }
    }

    /// The extracted build context hashes to the contract value.
    ///
    /// The strongest single statement this crate can make: what podman
    /// will be handed produces the digest the Python CLI computes.
    #[test]
    fn the_extracted_build_context_hashes_to_the_contract_value() {
        let scratch = Scratch::new("hash");
        let extracted = ensure_extracted_in(&scratch.0).expect("extraction succeeds");
        assert_eq!(
            egress::content_hash_from_dir(&extracted.join("data")),
            egress::content_hash()
        );
    }

    /// Every embedded file landed, and nothing else did.
    #[test]
    fn extraction_writes_exactly_the_embedded_files() {
        let scratch = Scratch::new("count");
        let extracted = ensure_extracted_in(&scratch.0).expect("extraction succeeds");
        let on_disk = snapshot(&extracted);
        assert_eq!(on_disk.len(), embedded_files().len());
        for file in embedded_files() {
            let (bytes, mode) = &on_disk[file.path];
            assert!(bytes == file.bytes, "{}", file.path);
            assert_eq!(*mode, file.mode, "{}", file.path);
        }
    }

    /// Directories get an explicit mode, not the umask's.
    #[test]
    fn directories_are_created_with_an_explicit_mode() {
        let scratch = Scratch::new("dirmode");
        let extracted = ensure_extracted_in(&scratch.0).expect("extraction succeeds");
        for dir in [
            extracted.clone(),
            extracted.join("data"),
            extracted.join("data").join("proxy"),
            extracted.join("data").join("proxy").join("inspectors"),
        ] {
            let mode = std::fs::metadata(&dir)
                .expect("directory is stat-able")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, DIR_MODE, "{}", dir.display());
        }
    }

    /// A second call is a cache hit, and leaves no staging behind.
    #[test]
    fn extraction_is_idempotent_and_leaves_no_staging_directories() {
        let scratch = Scratch::new("idempotent");
        let first = ensure_extracted_in(&scratch.0).expect("first extraction");
        let marker = first.join("data").join(".cache-hit-marker");
        std::fs::write(&marker, b"x").expect("marker is writable");

        let second = ensure_extracted_in(&scratch.0).expect("second extraction");
        assert_eq!(first, second);
        assert!(
            marker.is_file(),
            "the second call re-extracted instead of reusing the tree"
        );
        std::fs::remove_file(&marker).expect("marker is removable");

        let leftovers: Vec<String> = std::fs::read_dir(&scratch.0)
            .expect("cache root is readable")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".staging-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// Concurrent extraction into one cache root converges.
    ///
    /// Threads rather than processes, which is the same race as far as
    /// the filesystem is concerned: every caller builds a private
    /// staging tree and then `rename`s, and exactly one rename wins.
    /// What this asserts is that the losers do not error, do not clobber
    /// the winner and do not leave staging directories behind.
    #[test]
    fn concurrent_extraction_converges_on_one_tree() {
        let scratch = Scratch::new("concurrent");
        let root = scratch.0.clone();

        let results: Vec<PathBuf> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| ensure_extracted_in(&root).expect("extraction succeeds")))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("thread did not panic"))
                .collect()
        });

        let target = root.join(tag());
        assert!(results.iter().all(|p| *p == target), "{results:?}");

        let entries: Vec<String> = std::fs::read_dir(&root)
            .expect("cache root is readable")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec![tag()], "staging left behind: {entries:?}");
        assert_eq!(snapshot(&target).len(), embedded_files().len());
    }

    /// The cache key carries both halves of the invalidation rule.
    #[test]
    fn the_tag_is_version_and_digest() {
        let tag = tag();
        let digest = crate::assets_digest();
        assert_eq!(tag, format!("{VERSION}-{digest}"));
        assert!(tag.starts_with(&format!("{VERSION}-")), "{tag}");
        assert_ne!(
            digest,
            egress::content_hash(),
            "the cache key must not be the egress contract hash -- it has to \
             see templates/ and scaffolds/ too"
        );
    }

    /// The cache lands where the Python data root already is.
    #[test]
    fn the_cache_root_follows_xdg_data_home() {
        let root = cache_root();
        assert!(root.ends_with("agentcage/assets"), "{}", root.display());
        assert!(root.is_absolute(), "{}", root.display());
    }

    /// `build_context()` points at `data/`, which is what podman is given.
    ///
    /// Through `build_context_in` so the test does not write to the
    /// developer's real `~/.local/share`; the two differ only in where
    /// the cache root comes from.
    #[test]
    fn the_build_context_is_the_data_directory() {
        let scratch = Scratch::new("context");
        let context = build_context_in(&scratch.0).expect("extraction succeeds");
        assert_eq!(context.file_name().and_then(|n| n.to_str()), Some("data"));
        assert!(
            context
                .join("containers")
                .join("Containerfile.egress")
                .is_file(),
            "{} is not a build context",
            context.display()
        );
        assert_eq!(context.parent(), Some(scratch.0.join(tag()).as_path()));
    }
}
