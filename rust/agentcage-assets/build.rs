//! Turns three source trees into one sorted, mode-carrying table of
//! `include_bytes!`.
//!
//! # Why a build script and not `include_dir!` / `rust-embed`
//!
//! Both were considered. Neither can do the job on its own, and the
//! reasons are measurable rather than aesthetic:
//!
//! 1. **The embed set has to be deterministic, and the source tree is
//!    not.** `pyproject.toml` sets `pythonpath = ["src",
//!    "src/agentcage/data/proxy"]`, so one `uv run pytest` plants
//!    `__pycache__/` directories *inside* the egress build context --
//!    `data/proxy/__pycache__`, `data/proxy/inspectors/__pycache__`,
//!    `relays/`, `transforms/`. `include_dir!` takes a directory whole,
//!    with no exclusion mechanism, so whether the shipped binary
//!    contains interpreter-version-specific `.pyc` files would depend on
//!    whether the machine that built it had ever run the test suite.
//!    That is not a hypothetical: it is the state of a checkout after
//!    `make test`. `egress_hash.py` excludes those same paths from the
//!    content hash for exactly this reason ("bytecode caches are
//!    interpreter-dependent"), and the embed has to make the same
//!    exclusion or the hash and the build context disagree.
//! 2. **File modes have to survive.** Neither crate carries them:
//!    `include_dir` exposes `contents()` and metadata behind a feature
//!    flag that covers timestamps, not permissions, and `rust-embed`
//!    hands back bytes. So a side channel for the executable bit is
//!    needed either way -- which means a build script either way.
//! 3. **`rust-embed` changes behaviour between profiles.** Without
//!    `debug-embed` it reads from the filesystem in debug builds and
//!    embeds only in release, so `cargo test` would be testing a
//!    different code path from the one that ships. The feature exists to
//!    turn that off, but a dependency whose default is "be a different
//!    program in tests" is a poor fit for a crate whose entire job is
//!    byte-exactness.
//!
//! Once a build script is required for (2), it costs about eighty lines
//! to also do (1) and (3), and the dependency count stays at zero --
//! which the workspace has held since PR B1 and which section 2.5 of the
//! plan cares about, since it sells the port partly on a single small
//! binary.
//!
//! # What it emits
//!
//! `$OUT_DIR/embedded_files.rs`, a single `EMBEDDED_FILES` slice sorted
//! by relative path, each entry pairing a POSIX-relative path with
//! `include_bytes!` of the absolute source path and a normalized mode.
//! Sorted here so the runtime never has to sort, and so a reviewer can
//! diff the generated file across commits and see exactly what moved.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

/// The Python package root, relative to the repository root.
///
/// Kept equal to `agentcage_assets::PACKAGE_ROOT` by a test; a build
/// script cannot import the crate it builds.
const PACKAGE_ROOT: &str = "src/agentcage";

/// The trees to embed, relative to [`PACKAGE_ROOT`].
///
/// Kept equal to `agentcage_assets::EMBEDDED_TREES` by a test.
const TREES: [&str; 3] = ["data", "templates", "scaffolds"];

/// Directory names that never enter the embed.
///
/// Mirrors `egress_hash.HASH_EXCLUDE_DIRS`. See the module docs for how
/// these come to exist inside the build context in the first place.
const EXCLUDE_DIRS: [&str; 1] = ["__pycache__"];

/// File suffixes that never enter the embed.
///
/// Mirrors `egress_hash.HASH_EXCLUDE_SUFFIXES`.
const EXCLUDE_SUFFIXES: [&str; 2] = [".pyc", ".pyo"];

/// One embedded file, as the build script sees it.
struct Found {
    /// Absolute path on the build machine.
    source: PathBuf,
    /// `0o755` or `0o644`; see [`normalized_mode`].
    mode: u32,
}

fn main() {
    let manifest = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"),
    );
    // rust/agentcage-assets -> rust -> repository root.
    let repo_root = manifest
        .ancestors()
        .nth(2)
        .expect("the crate is nested at rust/<crate> inside the repository")
        .to_path_buf();
    let package_root = repo_root.join(PACKAGE_ROOT);

    // The build script itself, so editing the walk rules rebuilds.
    println!("cargo::rerun-if-changed=build.rs");

    let mut found: BTreeMap<String, Found> = BTreeMap::new();
    for tree in TREES {
        let dir = package_root.join(tree);
        assert!(
            dir.is_dir(),
            "missing embedded tree {} -- did the Python package move?",
            dir.display()
        );
        walk(&dir, tree, &mut found);
    }
    assert!(
        !found.is_empty(),
        "embedded nothing from {}",
        package_root.display()
    );

    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"))
        .join("embedded_files.rs");
    fs::write(&out, render(&found)).unwrap_or_else(|err| {
        panic!("could not write {}: {err}", out.display());
    });
}

/// Recursively collect the files under `dir`, keyed by POSIX relpath.
///
/// `prefix` is the relative path of `dir` from [`PACKAGE_ROOT`].
///
/// Panics rather than skipping on anything it was not built to carry --
/// a symlink, a fifo, a non-UTF-8 name. A silent skip here would ship a
/// binary missing a build input, and the failure would surface as an
/// opaque `podman build` error on a user's machine.
fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Found>) {
    // Watching the directory catches files added or removed; watching
    // each file catches edits. A pure `chmod` changes ctime, not mtime,
    // so it does *not* retrigger -- `touch` the file if you flip an
    // executable bit. Modes are asserted by a test, so a stale one is
    // caught there rather than shipped.
    println!("cargo::rerun-if-changed={}", dir.display());

    let entries = fs::read_dir(dir).unwrap_or_else(|err| {
        panic!("could not read {}: {err}", dir.display());
    });

    for entry in entries {
        let entry = entry.unwrap_or_else(|err| {
            panic!("could not read an entry of {}: {err}", dir.display());
        });
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .unwrap_or_else(|raw| panic!("non-UTF-8 name in {}: {raw:?}", dir.display()));
        let rel = format!("{prefix}/{name}");

        // `file_type` on Unix does not follow symlinks, so this is an
        // lstat and a symlink is reported as one.
        let file_type = entry.file_type().unwrap_or_else(|err| {
            panic!("could not stat {}: {err}", path.display());
        });
        assert!(
            !file_type.is_symlink(),
            "{} is a symlink; the embed has no way to represent one, and \
             `podman build` would not follow it out of the context either. \
             Replace it with the file it points at, or teach this script \
             about it.",
            path.display()
        );

        if file_type.is_dir() {
            if EXCLUDE_DIRS.contains(&name.as_str()) {
                continue;
            }
            walk(&path, &rel, out);
            continue;
        }

        assert!(
            file_type.is_file(),
            "{} is neither a file nor a directory",
            path.display()
        );
        if EXCLUDE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix)) {
            continue;
        }

        println!("cargo::rerun-if-changed={}", path.display());
        let metadata = fs::metadata(&path).unwrap_or_else(|err| {
            panic!("could not stat {}: {err}", path.display());
        });
        let mode = normalized_mode(metadata.permissions().mode());
        out.insert(rel, Found { source: path, mode });
    }
}

/// Collapse a filesystem mode to the two values git can store.
///
/// git records exactly `100644` and `100755`, so those are the only two
/// modes the source tree can *mean*. What a checkout ends up with on
/// disk depends on the umask -- a contributor with `umask 077` gets
/// `0600`/`0700` -- and embedding that would make the binary's contents
/// depend on the build machine's environment. Normalizing on the owner
/// execute bit reproduces git's model exactly and makes the embed
/// deterministic.
fn normalized_mode(mode: u32) -> u32 {
    if mode & 0o100 == 0 { 0o644 } else { 0o755 }
}

/// Render the table as Rust source.
fn render(found: &BTreeMap<String, Found>) -> String {
    let mut src = String::with_capacity(found.len() * 160);
    src.push_str(
        "// @generated by rust/agentcage-assets/build.rs -- do not edit.\n\
         //\n\
         // One entry per embedded file, sorted by `path`, which the crate\n\
         // relies on: the egress content hash is defined over sorted inputs\n\
         // and must never depend on directory iteration order.\n\n",
    );
    let _ = writeln!(
        src,
        "pub(crate) static EMBEDDED_FILES: [EmbeddedFile; {}] = [",
        found.len()
    );
    for (rel, file) in found {
        let source = file
            .source
            .to_str()
            .unwrap_or_else(|| panic!("non-UTF-8 source path {}", file.source.display()));
        let _ = writeln!(
            src,
            "    EmbeddedFile {{ path: {rel:?}, bytes: include_bytes!({source:?}), mode: 0o{:o} }},",
            file.mode
        );
    }
    src.push_str("];\n");
    src
}
