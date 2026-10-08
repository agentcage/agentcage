//! `_record_mask_mountpoints` / `_cleanup_mask_mountpoints` — issue #320
//! on this backend.
//!
//! A `container.tmpfs:` target nested under a host bind makes the
//! in-guest OCI runtime create the mount point, and a bind shares
//! inodes with its source, so the `mkdir -p` lands in the operator's
//! project directory **on the host**. Masking
//! `/workspace/.git/hooks/` on a project that is not a git checkout
//! leaves a stray `.git/hooks/` behind, and the ubiquitous `test -d
//! .git` then reads that directory as a repository.
//!
//! The quadlet backend solves this with an `ExecStartPre` /
//! `ExecStopPost` pair in the unit. Apple's runtime has no such hook,
//! so the Python does the same bookkeeping itself, host-side, around
//! `container run`. This is that bookkeeping.
//!
//! # What makes removal safe
//!
//! Three things, and all three matter:
//!
//! * only paths that **do not exist at start** are recorded, so a
//!   directory the operator already had is never a removal candidate.
//!   `lexists` — a dangling symlink counts as existing, mirroring the
//!   quadlet hook's `[ -e ] || [ -L ]` skip;
//! * removal is `rmdir`, so a directory with anything in it survives,
//!   with a warning;
//! * the recorded path must still resolve under the recorded bind
//!   source, re-checked at teardown, so a symlink swapped in after
//!   start cannot redirect a removal out of the project directory.
//!
//! The mask itself stays unconditional. Dropping it when `.git` is
//! absent would reopen the #170 pivot for a `.git` created later.

use std::collections::BTreeMap;
use std::path::Path;

use agentcage_core::volume_mounts::{MountTarget, mask_mountpoint_dirs};

/// `_record_mask_mountpoints` — note which mask mount points are absent
/// from the host right now.
///
/// Writes the bookkeeping file, or removes a stale one when there is
/// nothing to record: teardown must never act on an earlier start's
/// answer.
///
/// Best-effort, like the Python: a state directory that cannot be
/// created or written is not a reason to fail a start that would
/// otherwise work, and the consequence is a mask mount point left
/// behind rather than anything lost.
pub fn record(state_path: &Path, tmpfs_specs: &[String], mount_targets: &[MountTarget]) {
    let mut absent: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in mask_mountpoint_dirs(tmpfs_specs, mount_targets) {
        // `dirs` is deepest-first; keep that order for teardown.
        let missing: Vec<String> = entry
            .dirs
            .into_iter()
            .filter(|dir| !lexists(Path::new(dir)))
            .collect();
        if !missing.is_empty() {
            absent.insert(entry.host_source, missing);
        }
    }
    if absent.is_empty() {
        let _ = std::fs::remove_file(state_path);
        return;
    }
    let Some(parent) = state_path.parent() else {
        return;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    // `json.dumps(absent, indent=2)`.
    if let Ok(text) = serde_json::to_string_pretty(&absent) {
        let _ = std::fs::write(state_path, text);
    }
}

/// `_cleanup_mask_mountpoints` — retire the still-empty mount points
/// [`record`] noted.
///
/// Idempotent and silent about a missing, unreadable or
/// wrong-shaped state file: start may never have run, the cage may
/// predate the bookkeeping, or someone may have deleted it by hand.
/// None of those may fail a stop or a destroy.
pub fn cleanup(state_path: &Path) {
    let Ok(text) = std::fs::read_to_string(state_path) else {
        return;
    };
    let Ok(recorded) = serde_json::from_str::<BTreeMap<String, Vec<String>>>(&text) else {
        // `not isinstance(recorded, dict)` — and, here, also a mapping
        // whose values are not lists of strings. Either way the record
        // is unusable and keeping it would mean re-reading it forever.
        let _ = std::fs::remove_file(state_path);
        return;
    };
    // The Python iterates `sorted(recorded.items())`; a `BTreeMap` is
    // already in that order.
    for (root, dirs) in &recorded {
        // `realpath` on a non-existent path resolves lexically, which
        // is what the quadlet hook's `realpath -m` does.
        let real_root = crate::hostenv::realpath(root);
        let prefix = format!("{real_root}/");
        for dir in dirs {
            if !crate::hostenv::realpath(dir).starts_with(&prefix) {
                continue;
            }
            let path = Path::new(dir);
            if is_symlink(path) || !path.is_dir() {
                continue;
            }
            if std::fs::remove_dir(path).is_err() {
                crate::output::echo_err(&format!(
                    "warning: keeping {dir} (created as a tmpfs mask \
                     mount point, but not empty)"
                ));
            }
        }
    }
    let _ = std::fs::remove_file(state_path);
}

/// `os.path.lexists` — exists, without following a final symlink, so a
/// dangling one still counts.
fn lexists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// `os.path.islink`.
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use agentcage_core::volume_mounts::MountTarget;

    use super::{cleanup, record};

    /// A throwaway directory, named after the test that asked for it.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "agentcage-apple-masks-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp dir");
        dir
    }

    fn workspace_mask(project: &str) -> (Vec<String>, Vec<MountTarget>) {
        (
            vec!["/workspace/.git/hooks:rw,noexec".to_owned()],
            vec![MountTarget {
                target: "/workspace".to_owned(),
                source: project.to_owned(),
            }],
        )
    }

    /// The #320 shape end to end: record what is absent, then retire it.
    #[test]
    fn an_absent_mount_point_is_recorded_and_then_removed() {
        let root = scratch("roundtrip");
        let project = root.join("project");
        std::fs::create_dir_all(&project).expect("project");
        let state = root.join("mask-mountpoints.json");
        let (tmpfs, mounts) = workspace_mask(&project.display().to_string());

        record(&state, &tmpfs, &mounts);
        assert!(state.is_file(), "nothing was recorded");

        // What the in-guest runtime would have created through the bind.
        let hooks = project.join(".git/hooks");
        std::fs::create_dir_all(&hooks).expect("hooks");

        cleanup(&state);
        assert!(!hooks.exists(), "the mask mount point survived");
        assert!(!project.join(".git").exists(), "its parent survived");
        assert!(!state.exists(), "the bookkeeping survived");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A directory the operator already had is not a removal candidate,
    /// and the stale record from an earlier start is dropped.
    #[test]
    fn a_pre_existing_directory_is_never_recorded() {
        let root = scratch("pre-existing");
        let project = root.join("project");
        std::fs::create_dir_all(project.join(".git/hooks")).expect("hooks");
        let state = root.join("mask-mountpoints.json");
        std::fs::write(&state, "{\"/stale\": [\"/stale/dir\"]}").expect("stale");
        let (tmpfs, mounts) = workspace_mask(&project.display().to_string());

        record(&state, &tmpfs, &mounts);
        assert!(
            !state.exists(),
            "a start with nothing to record must drop the stale file"
        );
        assert!(project.join(".git/hooks").is_dir(), "the operator's dir");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `rmdir` is the whole safety story, so a non-empty mount point
    /// has to survive.
    #[test]
    fn a_mount_point_with_content_is_kept() {
        let root = scratch("not-empty");
        let project = root.join("project");
        std::fs::create_dir_all(&project).expect("project");
        let state = root.join("mask-mountpoints.json");
        let (tmpfs, mounts) = workspace_mask(&project.display().to_string());

        record(&state, &tmpfs, &mounts);
        let hooks = project.join(".git/hooks");
        std::fs::create_dir_all(&hooks).expect("hooks");
        std::fs::write(hooks.join("pre-commit"), "#!/bin/sh\n").expect("hook");

        cleanup(&state);
        assert!(hooks.is_dir(), "a non-empty mount point was removed");
        assert!(!state.exists(), "the bookkeeping survived");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A record pointing outside its own bind source is refused, which
    /// is what stops a symlink swapped in after start from redirecting
    /// a removal.
    #[test]
    fn a_path_that_escapes_its_recorded_root_is_refused() {
        let root = scratch("escape");
        let project = root.join("project");
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&project).expect("project");
        std::fs::create_dir_all(elsewhere.join("victim")).expect("victim");
        let state = root.join("mask-mountpoints.json");
        std::fs::write(
            &state,
            serde_json::to_string(&serde_json::json!({
                project.display().to_string(): [
                    elsewhere.join("victim").display().to_string(),
                ],
            }))
            .expect("json"),
        )
        .expect("write");

        cleanup(&state);
        assert!(
            elsewhere.join("victim").is_dir(),
            "a removal escaped the recorded bind source"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An unparseable record is dropped rather than re-read forever.
    #[test]
    fn a_malformed_record_is_dropped() {
        let root = scratch("malformed");
        let state = root.join("mask-mountpoints.json");
        std::fs::write(&state, "[\"not a mapping\"]").expect("write");
        cleanup(&state);
        assert!(!state.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// No state file at all is a silent no-op.
    #[test]
    fn a_missing_record_is_a_no_op() {
        let root = scratch("missing");
        cleanup(&root.join("mask-mountpoints.json"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
