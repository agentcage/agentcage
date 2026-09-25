//! Staging a Containerfile's build context into a cage's state dir.
//!
//! `cli._stage_build_context` plus `scaffold_brief.stage_scaffold_assets`.
//! Both run at `cage create` and at `cage update -c`, and both exist for
//! the same reason: a cage owns a frozen copy of everything its image is
//! built from, so a later `cage update` (with no `-c`) can rebuild
//! without the operator's original tree being present or unchanged.

use std::fs;
use std::io;
use std::path::Path;

/// Entries beside a Containerfile that are agentcage config rather than
/// build input.
const SKIP_SUFFIXES: [&str; 3] = ["yaml", "yml", "j2"];

/// Build noise that must never reach a cage's staged context.
///
/// `shutil.ignore_patterns("__pycache__", "*.pyc", ".git", "node_modules",
/// "*.deleted.*")`, as five predicates rather than five globs.
fn is_ignored(name: &str) -> bool {
    name == "__pycache__"
        || name == ".git"
        || name == "node_modules"
        // `*.pyc`, case-sensitively: `shutil.ignore_patterns` uses
        // `fnmatch.filter`, which on POSIX does not fold case, and a
        // file literally named `X.PYC` is not a Python bytecode cache.
        // Spelled as a suffix on the whole name rather than through
        // `Path::extension`, because the pattern is a glob over the
        // *name* -- `.pyc` with no stem matches it and has no extension.
        || ends_with_pyc(name)
        || is_deleted_marker(name)
}

/// `*.pyc`. See [`is_ignored`] for why this is not `Path::extension`.
fn ends_with_pyc(name: &str) -> bool {
    name.len() >= 4 && name.as_bytes()[name.len() - 4..] == *b".pyc"
}

/// `*.deleted.*` — a `.deleted.` infix with something on both sides.
fn is_deleted_marker(name: &str) -> bool {
    name.match_indices(".deleted.")
        .any(|(index, _)| index > 0 && index + ".deleted.".len() < name.len())
}

/// `cli._stage_build_context` — copy a Containerfile's siblings.
///
/// Directories as well as files, because a Containerfile that `COPY`s a
/// tree (skill bundles, vendored packages) would otherwise fail the
/// rebuild with only its sibling *files* staged.
///
/// With `clobber` false, entries already present in `dest` are left
/// alone. Nothing in this PR passes false — `cage restore` does — but
/// the flag is part of the function's contract and dropping it would
/// mean a second, subtly different copier later.
///
/// # Errors
///
/// [`io::Error`] on a failed read or copy.
pub fn stage_build_context(source: &Path, dest: &Path, clobber: bool) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    let mut entries: Vec<_> = fs::read_dir(source)?.collect::<Result<_, _>>()?;
    // `Path.iterdir()` is directory order, which is arbitrary; sorting
    // makes a staged tree reproducible, which the fingerprint's context
    // digest depends on for its *contents* but not its order. Sorting
    // costs nothing and removes the only nondeterminism here.
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let path = entry.path();
        if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| SKIP_SUFFIXES.contains(&e))
        {
            continue;
        }
        let target = dest.join(name.as_ref());
        if !clobber && target.exists() {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_tree_filtered(&path, &target)?;
        } else if file_type.is_file() {
            copy_file(&path, &target)?;
        }
    }
    Ok(())
}

/// `shutil.copytree(..., ignore=_BUILD_CONTEXT_IGNORE, dirs_exist_ok=True)`.
fn copy_tree_filtered(source: &Path, dest: &Path) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if is_ignored(&name.to_string_lossy()) {
            continue;
        }
        let from = entry.path();
        let to = dest.join(&name);
        if entry.file_type()?.is_dir() {
            copy_tree_filtered(&from, &to)?;
        } else {
            copy_file(&from, &to)?;
        }
    }
    Ok(())
}

/// `shutil.copy2` minus the mtime — nothing reads it, and preserving it
/// would need `utimensat`. The mode is carried, because an executable
/// build script that arrives non-executable fails the build.
fn copy_file(from: &Path, to: &Path) -> io::Result<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    // A staged file left over from a previous deploy may be read-only,
    // and `fs::copy` opens the destination for writing.
    if to.exists() {
        fs::remove_file(to)?;
    }
    fs::copy(from, to)?;
    Ok(())
}

// ── the canonical brief and skill ────────────────────────────

/// `scaffold_brief.SKILL_CONTEXT_PATH`.
const SKILL_CONTEXT_PATH: &str = "skills/agentcage";

/// `scaffold_brief.stage_scaffold_assets` — drop the canonical brief
/// and skill into a scaffold cage's staged context.
///
/// Scaffolds do not each ship a copy: one editable `AGENTS.md` and one
/// editable `skills/agentcage/` live in the repo (embedded here), and
/// this puts them where the scaffold's `COPY` lines will find them.
///
/// Three conditions, all of which have to hold: the cage is
/// scaffold-backed, the Containerfile actually `COPY`s the asset, and
/// the source context does not ship its own next to the Containerfile.
///
/// Returns whether anything was written.
#[must_use]
pub fn stage_scaffold_assets(containerfile: &Path, dest: &Path, scaffold: &str) -> bool {
    let brief = stage_brief(containerfile, dest, scaffold).unwrap_or(false);
    let skill = stage_skill(containerfile, dest, scaffold).unwrap_or(false);
    brief || skill
}

/// The embedded `scaffolds/<relative>` file, if there is one.
fn canonical(relative: &str) -> Option<&'static [u8]> {
    let wanted = format!("scaffolds/{relative}");
    agentcage_assets::embedded_files()
        .iter()
        .find(|file| file.path == wanted)
        .map(|file| file.bytes)
}

/// Every embedded file under `scaffolds/skills/agentcage/`, as
/// `(path-below-that-dir, bytes)`.
fn canonical_skill() -> Vec<(String, &'static [u8])> {
    let prefix = format!("scaffolds/{SKILL_CONTEXT_PATH}/");
    let mut files: Vec<(String, &'static [u8])> = agentcage_assets::embedded_files()
        .iter()
        .filter_map(|file| {
            file.path
                .strip_prefix(&prefix)
                .map(|rest| (rest.to_owned(), file.bytes))
        })
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

/// `scaffold_brief._copy_references` — does this Containerfile `COPY`
/// that build-context path?
///
/// A comment mentioning the path is not a reference, and neither is a
/// longer name: `COPY skills/agentcage-x` does not reference
/// `skills/agentcage`. The match must begin at the instruction's first
/// source token and end at a path boundary.
fn copy_references(containerfile: &Path, path: &str) -> bool {
    let Ok(text) = fs::read_to_string(containerfile) else {
        return false;
    };
    text.lines().any(|line| line_copies(line, path))
}

fn line_copies(line: &str, path: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.len() < 4 || !trimmed[..4].eq_ignore_ascii_case("COPY") {
        return false;
    }
    let rest = &trimmed[4..];
    if !rest.starts_with(char::is_whitespace) {
        return false;
    }
    let mut tokens = rest.split_whitespace().peekable();
    // `(?:--\S+\s+)*` — any number of flags.
    while tokens.peek().is_some_and(|t| t.starts_with("--")) {
        tokens.next();
    }
    let Some(source) = tokens.next() else {
        return false;
    };
    // `\S*<path>(?=[\s/,"']|$)` — a prefix is allowed, a suffix is not
    // unless it starts a new path component.
    source.match_indices(path).any(|(index, _)| {
        let after = &source[index + path.len()..];
        after.is_empty() || after.starts_with(['/', ',', '"', '\''])
    })
}

/// `_context_ships` — the Containerfile's own directory already has it.
fn context_ships(containerfile: &Path, relative: &str) -> bool {
    containerfile
        .parent()
        .is_some_and(|dir| dir.join(relative).exists())
}

fn stage_brief(containerfile: &Path, dest: &Path, scaffold: &str) -> io::Result<bool> {
    let Some(bytes) = canonical("AGENTS.md").filter(|_| !scaffold.is_empty()) else {
        return Ok(false);
    };
    if !copy_references(containerfile, "AGENTS.md") || context_ships(containerfile, "AGENTS.md") {
        return Ok(false);
    }
    let target = dest.join("AGENTS.md");
    let metadata = fs::symlink_metadata(&target).ok();
    match metadata {
        Some(meta) if meta.is_file() => {
            if fs::read(&target).is_ok_and(|current| current == bytes) {
                return Ok(false); // current — nothing to refresh
            }
            fs::remove_file(&target)?;
        }
        Some(_) => remove_path(&target)?,
        None => {}
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&target, bytes)?;
    Ok(true)
}

fn stage_skill(containerfile: &Path, dest: &Path, scaffold: &str) -> io::Result<bool> {
    if scaffold.is_empty() {
        return Ok(false);
    }
    let files = canonical_skill();
    if !files.iter().any(|(path, _)| path == "SKILL.md") {
        return Ok(false);
    }
    if !copy_references(containerfile, SKILL_CONTEXT_PATH)
        || context_ships(containerfile, SKILL_CONTEXT_PATH)
    {
        return Ok(false);
    }
    let target = dest.join(SKILL_CONTEXT_PATH);
    match fs::symlink_metadata(&target) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => remove_path(&target)?,
        Ok(_) => {
            if !tree_differs(&files, &target) {
                return Ok(false); // current — nothing to refresh
            }
            remove_path(&target)?;
        }
        Err(_) => {}
    }
    if let Some(parent) = target.parent() {
        match fs::symlink_metadata(parent) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => remove_path(parent)?,
            _ => {}
        }
        fs::create_dir_all(parent)?;
    }
    for (relative, bytes) in &files {
        let path = target.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, bytes)?;
    }
    Ok(true)
}

/// `_trees_differ`, against the embedded tree: same set of relative
/// paths, same bytes for each.
fn tree_differs(canonical: &[(String, &'static [u8])], staged: &Path) -> bool {
    let mut present: Vec<String> = Vec::new();
    collect_relative(staged, staged, &mut present);
    present.sort();
    let expected: Vec<String> = canonical.iter().map(|(path, _)| path.clone()).collect();
    if present != expected {
        return true;
    }
    canonical.iter().any(|(relative, bytes)| {
        fs::read(staged.join(relative)).is_ok_and(|b| b != *bytes)
            || fs::read(staged.join(relative)).is_err()
    })
}

fn collect_relative(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_relative(root, &path, out);
        } else if let Ok(relative) = path.strip_prefix(root) {
            out.push(relative.to_string_lossy().into_owned());
        }
    }
}

/// `_remove_path` — a file, a symlink, or a whole tree.
fn remove_path(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || meta.is_file() {
        fs::remove_file(path)
    } else {
        fs::remove_dir_all(path)
    }
}

#[cfg(test)]
mod tests {
    use super::{is_ignored, line_copies, stage_build_context};

    #[test]
    fn the_ignore_patterns_are_the_pythons_five() {
        assert!(is_ignored("__pycache__"));
        assert!(is_ignored(".git"));
        assert!(is_ignored("node_modules"));
        assert!(is_ignored("module.pyc"));
        assert!(is_ignored("cage.deleted.1"));
        assert!(!is_ignored("deleted.txt"));
        assert!(!is_ignored("agent.js"));
        assert!(!is_ignored("gitignore"));
    }

    #[test]
    fn a_copy_reference_stops_at_a_path_boundary() {
        assert!(line_copies("COPY AGENTS.md /home/agent/", "AGENTS.md"));
        assert!(line_copies(
            "  copy --chown=1000:1000 skills/agentcage /skills/agentcage",
            "skills/agentcage"
        ));
        assert!(line_copies(
            "COPY ./skills/agentcage/ /x",
            "skills/agentcage"
        ));
        // A longer name is not a reference.
        assert!(!line_copies(
            "COPY skills/agentcage-x /x",
            "skills/agentcage"
        ));
        // A comment is not an instruction.
        assert!(!line_copies("# COPY AGENTS.md /x", "AGENTS.md"));
        // A mention in the destination is not a reference.
        assert!(!line_copies("COPY brief.md /agent/AGENTS.md", "AGENTS.md"));
        assert!(!line_copies("COPYRIGHT AGENTS.md", "AGENTS.md"));
    }

    #[test]
    fn staging_skips_configs_and_build_noise_and_keeps_trees() {
        let source = agentcage_state::TestDir::new("stage-src");
        let dest = agentcage_state::TestDir::new("stage-dst");
        let src = source.path();
        std::fs::write(src.join("Containerfile"), b"FROM x\n").unwrap();
        std::fs::write(src.join("cage.yaml"), b"name: x\n").unwrap();
        std::fs::write(src.join("unit.j2"), b"{}\n").unwrap();
        std::fs::write(src.join("entry.sh"), b"#!/bin/sh\n").unwrap();
        std::fs::create_dir_all(src.join("skills/__pycache__")).unwrap();
        std::fs::write(src.join("skills/SKILL.md"), b"skill\n").unwrap();
        std::fs::write(src.join("skills/__pycache__/x.pyc"), b"junk").unwrap();

        stage_build_context(src, dest.path(), true).unwrap();

        assert!(dest.path().join("Containerfile").is_file());
        assert!(dest.path().join("entry.sh").is_file());
        assert!(dest.path().join("skills/SKILL.md").is_file());
        assert!(!dest.path().join("cage.yaml").exists());
        assert!(!dest.path().join("unit.j2").exists());
        assert!(!dest.path().join("skills/__pycache__").exists());
    }

    #[test]
    fn clobber_false_leaves_what_is_already_there() {
        let source = agentcage_state::TestDir::new("stage-src2");
        let dest = agentcage_state::TestDir::new("stage-dst2");
        std::fs::write(source.path().join("f.txt"), b"new").unwrap();
        std::fs::write(dest.path().join("f.txt"), b"old").unwrap();
        stage_build_context(source.path(), dest.path(), false).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.path().join("f.txt")).unwrap(),
            "old"
        );
        stage_build_context(source.path(), dest.path(), true).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.path().join("f.txt")).unwrap(),
            "new"
        );
    }
}
