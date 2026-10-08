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
/// alone — except any named in `clobber_names`, which are overwritten
/// either way.
///
/// That exemption is `init --force`. `init` stages into the operator's
/// own directory, so it cannot clobber wholesale (a project's
/// `README.md` is not ours to replace), but the entries the image is
/// built from have to be the scaffold's or the config written beside
/// them is a lie. `init` refuses on those unless forced, and a force
/// that then kept the stale file would be the bug with a prompt. See
/// [`stage_conflicts`].
///
/// # Errors
///
/// [`io::Error`] on a failed read or copy.
pub fn stage_build_context(
    source: &Path,
    dest: &Path,
    clobber: bool,
    clobber_names: &[String],
) -> io::Result<()> {
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
        if !clobber && target.exists() && !clobber_names.iter().any(|n| *n == *name) {
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

/// A canonical asset's source: embedded bytes, or an embedded tree.
enum Canonical {
    File(&'static [u8]),
    Tree(Vec<(String, &'static [u8])>),
}

/// `scaffold_brief.staged_asset_sources` — `(build-context-relative
/// path, source)` for each canonical asset [`stage_scaffold_assets`]
/// would write beside `containerfile`.
///
/// The three conditions that gate *every* canonical asset — a scaffold
/// build, an asset agentcage actually ships, and a `COPY` of it in a
/// context that does not ship its own — live here once. [`stage_brief`],
/// [`stage_skill`] and [`stage_conflicts`] all consult it rather than
/// re-deriving them.
///
/// Says nothing about whether the destination is already current: that
/// is per-asset, and belongs to the caller.
fn staged_asset_sources(containerfile: &Path, scaffold: &str) -> Vec<(String, Canonical)> {
    let mut out = Vec::new();
    if scaffold.is_empty() {
        return out;
    }
    if let Some(bytes) = canonical("AGENTS.md") {
        if copy_references(containerfile, "AGENTS.md") && !context_ships(containerfile, "AGENTS.md")
        {
            out.push(("AGENTS.md".to_owned(), Canonical::File(bytes)));
        }
    }
    let files = canonical_skill();
    if files.iter().any(|(path, _)| path == "SKILL.md")
        && copy_references(containerfile, SKILL_CONTEXT_PATH)
        && !context_ships(containerfile, SKILL_CONTEXT_PATH)
    {
        out.push((SKILL_CONTEXT_PATH.to_owned(), Canonical::Tree(files)));
    }
    out
}

/// `scaffold_brief._would_stage` — whether [`staged_asset_sources`]
/// names `relative`.
fn would_stage(containerfile: &Path, relative: &str, scaffold: &str) -> bool {
    staged_asset_sources(containerfile, scaffold)
        .iter()
        .any(|(path, _)| path == relative)
}

/// `cli._scaffold_build_inputs` — entries beside `containerfile` whose
/// bytes decide what the image *is*.
///
/// The Containerfile itself, plus every sibling [`stage_build_context`]
/// would stage that the Containerfile actually `COPY`s, through the one
/// definition of a build-context reference in [`copy_references`].
///
/// Everything else a scaffold dir holds is deliberately absent: a
/// scaffold's `README.md` is staged for the operator to read and the
/// build never opens it, so an operator's own README stays theirs.
///
/// Regular files only, for the reason on `_scaffold_build_inputs`: a
/// `COPY`ed sibling *directory* is staged through [`is_ignored`], so a
/// staged copy legitimately lacks the `node_modules` its source has and
/// would compare as different forever. No scaffold ships one.
#[must_use]
pub fn build_inputs(containerfile: &Path) -> Vec<String> {
    let Some(name) = containerfile
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
    else {
        return Vec::new();
    };
    let mut names = vec![name.clone()];
    let Some(dir) = containerfile.parent() else {
        return names;
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return names;
    };
    let mut siblings: Vec<_> = entries.flatten().collect();
    siblings.sort_by_key(std::fs::DirEntry::file_name);
    for entry in siblings {
        let sibling = entry.file_name().to_string_lossy().into_owned();
        if sibling == name || !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        if entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| SKIP_SUFFIXES.contains(&e))
        {
            continue;
        }
        if copy_references(containerfile, &sibling) {
            names.push(sibling);
        }
    }
    names
}

/// `cli._scaffold_stage_conflicts` — paths in `dest` that `init` must
/// not quietly stage over.
///
/// `init` stages a scaffold's build context into the operator's working
/// directory, not into a cage's private state dir, and both of the
/// policies that are right for a state dir are wrong there:
///
/// * [`stage_build_context`] is called with `clobber` false, which
///   silently *keeps* what is already present. For the Containerfile
///   that is a trap: the config `init` writes names
///   `localhost/agentcage-scaffold-<name>` and
///   `containerfile: Containerfile`, so `cage create` builds the
///   operator's unrelated Containerfile and tags the result with the
///   scaffold's name. The wrapper's `FROM` picks that up and the first
///   symptom is a failure deep inside the wrapper build (`useradd: not
///   found` for a scaffold that has `useradd`) with nothing pointing at
///   the cause — or no symptom at all, and a cage running an image its
///   own name denies.
/// * [`stage_scaffold_assets`] always refreshes a stale copy, which
///   silently *overwrites* a project's own `AGENTS.md`.
///
/// Both get the same answer: name the conflict and refuse, exactly as
/// `init` already treats an existing `cage.yaml`, with the documented
/// `--force` as the single override.
///
/// Returns the conflicting build-context-relative paths, sorted and
/// deduplicated.
#[must_use]
pub fn stage_conflicts(containerfile: &Path, dest: &Path, scaffold: &str) -> Vec<String> {
    let mut conflicts = std::collections::BTreeSet::new();
    let dir = containerfile.parent().unwrap_or(Path::new("."));
    for name in build_inputs(containerfile) {
        let target = dest.join(&name);
        if target.exists() && paths_differ(&dir.join(&name), &target) {
            conflicts.insert(name);
        }
    }
    for (relative, source) in staged_asset_sources(containerfile, scaffold) {
        let target = dest.join(&relative);
        if target.exists() && canonical_differs(&source, &target) {
            conflicts.insert(relative);
        }
    }
    conflicts.into_iter().collect()
}

/// `scaffold_brief.staged_asset_differs`, for an embedded source.
fn canonical_differs(source: &Canonical, dest: &Path) -> bool {
    if fs::symlink_metadata(dest).is_ok_and(|m| m.file_type().is_symlink()) {
        return true;
    }
    match source {
        Canonical::File(bytes) => !fs::read(dest).is_ok_and(|current| current == *bytes),
        Canonical::Tree(files) => !dest.is_dir() || tree_differs(files, dest),
    }
}

/// `scaffold_brief.staged_asset_differs`, for a source on disk.
///
/// True when `dest` is anything other than a current copy of `source`,
/// including absent, so callers testing "exists and disagrees" check
/// existence themselves. Byte-deep, and recursive for a directory.
fn paths_differ(source: &Path, dest: &Path) -> bool {
    let Ok(dest_meta) = fs::symlink_metadata(dest) else {
        return true;
    };
    if dest_meta.file_type().is_symlink() {
        return true;
    }
    let Ok(source_meta) = fs::symlink_metadata(source) else {
        return true;
    };
    if source_meta.is_dir() != dest_meta.is_dir() {
        return true;
    }
    if !source_meta.is_dir() {
        return match (fs::read(source), fs::read(dest)) {
            (Ok(a), Ok(b)) => a != b,
            _ => true,
        };
    }
    let mut here = Vec::new();
    collect_relative(source, source, &mut here);
    here.sort();
    let mut there = Vec::new();
    collect_relative(dest, dest, &mut there);
    there.sort();
    if here != there {
        return true;
    }
    here.iter().any(|relative| {
        match (
            fs::read(source.join(relative)),
            fs::read(dest.join(relative)),
        ) {
            (Ok(a), Ok(b)) => a != b,
            _ => true,
        }
    })
}

fn stage_brief(containerfile: &Path, dest: &Path, scaffold: &str) -> io::Result<bool> {
    if !would_stage(containerfile, "AGENTS.md", scaffold) {
        return Ok(false);
    }
    let Some(bytes) = canonical("AGENTS.md") else {
        return Ok(false);
    };
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
    if !would_stage(containerfile, SKILL_CONTEXT_PATH, scaffold) {
        return Ok(false);
    }
    let files = canonical_skill();
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
    use super::{
        build_inputs, canonical, is_ignored, line_copies, stage_build_context, stage_conflicts,
    };

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

        stage_build_context(src, dest.path(), true, &[]).unwrap();

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
        stage_build_context(source.path(), dest.path(), false, &[]).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.path().join("f.txt")).unwrap(),
            "old"
        );
        // ...unless it is named: `init --force`'s exemption.
        stage_build_context(source.path(), dest.path(), false, &["f.txt".to_owned()]).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.path().join("f.txt")).unwrap(),
            "new"
        );
        std::fs::write(dest.path().join("f.txt"), b"old").unwrap();
        stage_build_context(source.path(), dest.path(), true, &[]).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.path().join("f.txt")).unwrap(),
            "new"
        );
    }

    /// A scaffold dir whose Containerfile `COPY`s one sibling and the
    /// canonical brief, next to a README and a config that are not build
    /// input.
    fn scaffold_dir(name: &str) -> agentcage_state::TestDir {
        let dir = agentcage_state::TestDir::new(name);
        let src = dir.path();
        std::fs::write(
            src.join("Containerfile"),
            b"FROM scaffold\nCOPY AGENTS.md /x\nCOPY entry.sh /usr/bin/entry\n",
        )
        .unwrap();
        std::fs::write(src.join("entry.sh"), b"#!/bin/sh\nscaffold\n").unwrap();
        std::fs::write(src.join("README.md"), b"scaffold docs\n").unwrap();
        std::fs::write(src.join("cage.yaml"), b"name: x\n").unwrap();
        dir
    }

    #[test]
    fn the_build_inputs_are_the_containerfile_and_what_it_copies() {
        let source = scaffold_dir("inputs-src");
        let inputs = build_inputs(&source.path().join("Containerfile"));
        // The README is staged for the operator but never built from,
        // and cage.yaml is not staged at all.
        assert_eq!(
            inputs,
            vec!["Containerfile".to_owned(), "entry.sh".to_owned()]
        );
    }

    /// The bug `init` had: a foreign Containerfile survived `clobber`
    /// false and `cage create` built it under the scaffold's tag, while
    /// a project's own `AGENTS.md` was overwritten without a word.
    #[test]
    fn a_foreign_build_input_is_a_conflict_and_a_current_one_is_not() {
        let source = scaffold_dir("conflict-src");
        let dest = agentcage_state::TestDir::new("conflict-dst");
        let containerfile = source.path().join("Containerfile");

        // An empty destination has nothing to disagree with.
        assert!(stage_conflicts(&containerfile, dest.path(), "demo").is_empty());

        std::fs::write(dest.path().join("Containerfile"), b"FROM busybox\n").unwrap();
        std::fs::write(dest.path().join("entry.sh"), b"#!/bin/sh\npwned\n").unwrap();
        std::fs::write(dest.path().join("AGENTS.md"), b"my brief\n").unwrap();
        std::fs::write(dest.path().join("README.md"), b"my readme\n").unwrap();
        assert_eq!(
            stage_conflicts(&containerfile, dest.path(), "demo"),
            vec![
                "AGENTS.md".to_owned(),
                "Containerfile".to_owned(),
                "entry.sh".to_owned(),
            ],
            "the README must not be here: the build never reads it"
        );

        // Make every one of them current, as a second `init` in the
        // directory the first one staged would find them. Idempotence:
        // the check must not make `init` a one-shot.
        std::fs::copy(&containerfile, dest.path().join("Containerfile")).unwrap();
        std::fs::copy(source.path().join("entry.sh"), dest.path().join("entry.sh")).unwrap();
        std::fs::write(
            dest.path().join("AGENTS.md"),
            canonical("AGENTS.md").expect("the embedded brief"),
        )
        .unwrap();
        assert!(stage_conflicts(&containerfile, dest.path(), "demo").is_empty());
    }

    /// `scaffold` empty means "not a scaffold build", so the canonical
    /// assets are not staged and cannot conflict — but the Containerfile
    /// still can.
    #[test]
    fn without_a_scaffold_only_the_context_can_conflict() {
        let source = scaffold_dir("noscaffold-src");
        let dest = agentcage_state::TestDir::new("noscaffold-dst");
        std::fs::write(dest.path().join("AGENTS.md"), b"my brief\n").unwrap();
        std::fs::write(dest.path().join("Containerfile"), b"FROM busybox\n").unwrap();
        assert_eq!(
            stage_conflicts(&source.path().join("Containerfile"), dest.path(), ""),
            vec!["Containerfile".to_owned()]
        );
    }
}
