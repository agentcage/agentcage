//! The Python trees that ship *inside* the Rust binary.
//!
//! # Why this crate exists
//!
//! The port does not replace the egress proxy — mitmproxy, the addon,
//! the inspectors and the relays stay Python, unchanged, inside the
//! egress container (RUST-PORT-PLAN.md, scope decision). But today those
//! files are simply *there* on disk, because agentcage is installed as a
//! Python package and `backends/container.py` hands the package's own
//! `data/` directory to podman as the build context:
//!
//! ```text
//! data_dir = Path(__file__).resolve().parent.parent / "data"
//! build_context = str(data_dir)
//! ```
//!
//! A single static binary has no package directory. So it has to carry
//! those trees and materialize them on disk before any image build, and
//! that is work with no Python counterpart at all — which is why it gets
//! its own crate instead of being a module of [`agentcage_core`], and
//! why PR B3 is scheduled early: it is the highest-risk piece of *new*
//! code in the port, and it fails loudly and cheaply.
//!
//! # The three jobs
//!
//! - **Embedding.** [`EMBEDDED_TREES`] are compiled into the binary by
//!   `build.rs`, which also records each file's mode. Its module docs
//!   explain why neither `include_dir!` nor `rust-embed` could do it
//!   alone; the short version is that `uv run pytest` plants
//!   `__pycache__` inside the egress build context, so an
//!   embed-the-whole-directory macro makes the binary's contents depend
//!   on whether the build machine ever ran the tests.
//! - **Extraction.** [`extract`] materializes the trees under
//!   `$XDG_DATA_HOME/agentcage/assets/<version>-<digest>` and hands back
//!   the build-context path. Byte-exact and mode-exact, because the
//!   Containerfile only `chmod`s the files it knows about.
//! - **Hashing.** [`egress`] reproduces `egress_hash.py` byte-exactly.
//!   That digest is the suffix of the egress image tag, so a Rust
//!   implementation that disagrees means every Mac rebuilds its image
//!   once on upgrade and then keeps a second, permanently divergent tag
//!   lineage for identical content.
//!
//! This crate is where the extraction and hashing live because both are
//! I/O, and [`agentcage_core`] is not allowed any. `agentcage-core` is
//! handed the *results*.
//!
//! # Dependencies
//!
//! One: `sha2`, for the SHA-256 the egress hash is defined in terms of.
//! Hand-rolling it to keep the count at zero would be the wrong trade —
//! use the audited implementation. The embedding itself adds nothing;
//! see `build.rs`.
//!
//! # Platform
//!
//! Unix only. Modes are Unix modes and the extraction uses `rename(2)`
//! semantics; the port targets Linux and macOS (plan, scope decision).

pub mod egress;
pub mod extract;
/// Just enough of Python's `shlex.split` for a `COPY` line and for
/// `$EDITOR` (PR D14).
pub mod shlex;

use std::fmt;

use sha2::{Digest as _, Sha256};

/// Where the embedded trees live in the source repository.
///
/// The Python package root. Paths in [`EMBEDDED_TREES`] are relative to
/// this, and this is relative to the repository root.
pub const PACKAGE_ROOT: &str = "src/agentcage";

/// The trees the binary embeds, relative to [`PACKAGE_ROOT`].
///
/// - `data/` — the podman build context: `Containerfile.egress`, the
///   mitmproxy addon, inspectors, relays, transforms, the supervisor
///   scripts and the apple-container assets.
/// - `templates/` — the Jinja2 sources for quadlets, the Lima config and
///   the provisioning script, rendered by minijinja rather than
///   rewritten (Track C, PR C8).
/// - `scaffolds/` — the `claude-code`, `codex` and `pi` scaffolds that
///   `agentcage init` and `agentcage run` render (Track D, PR D14).
pub const EMBEDDED_TREES: [&str; 3] = ["data", "templates", "scaffolds"];

/// The version this binary was built as, and half of the cache key.
///
/// Read from the crate's own metadata, which inherits the workspace
/// version, which `scripts/check-version.sh` holds equal to the root
/// `VERSION` file. Deliberately not taken from `agentcage_core` — this
/// crate has no reason to depend on it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One file carried inside the binary.
#[derive(Clone, Copy)]
pub struct EmbeddedFile {
    /// POSIX-relative path from [`PACKAGE_ROOT`], e.g.
    /// `data/proxy/addon.py`. Always contains a `/`, since every file
    /// lives under one of [`EMBEDDED_TREES`].
    pub path: &'static str,
    /// The file's contents, verbatim.
    pub bytes: &'static [u8],
    /// Unix permission bits, normalized to `0o644` or `0o755` — the two
    /// values git can record. See `build.rs`.
    pub mode: u32,
}

impl EmbeddedFile {
    /// Whether the file is executable in the source tree.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.mode & 0o100 != 0
    }
}

impl fmt::Debug for EmbeddedFile {
    /// Prints the size rather than the contents.
    ///
    /// The derived impl would dump 92 KB of `watcher.py` into a failing
    /// test's output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbeddedFile")
            .field("path", &self.path)
            .field("len", &self.bytes.len())
            .field("mode", &format_args!("0o{:o}", self.mode))
            .finish()
    }
}

mod generated {
    //! The build script's output, and nothing else.
    use super::EmbeddedFile;

    include!(concat!(env!("OUT_DIR"), "/embedded_files.rs"));
}

/// Every embedded file, sorted by [`EmbeddedFile::path`].
///
/// The sort is the build script's, and it is load-bearing: the egress
/// content hash is defined over sorted inputs precisely so it never
/// depends on directory iteration order.
#[must_use]
pub fn embedded_files() -> &'static [EmbeddedFile] {
    &generated::EMBEDDED_FILES
}

/// The embedded files under one of [`EMBEDDED_TREES`], still sorted.
///
/// Paths are relative to the tree, so `tree("data")` yields
/// `proxy/addon.py`, not `data/proxy/addon.py` — the build context's
/// root is `data/` itself, which is what `Containerfile.egress` `COPY`s
/// are written against.
pub fn tree(name: &str) -> impl Iterator<Item = (&'static str, &'static EmbeddedFile)> + '_ {
    let prefix = format!("{name}/");
    embedded_files()
        .iter()
        .filter_map(move |file| Some((file.path.strip_prefix(&prefix)?, file)))
}

/// A digest over the entire embed, for cache keying only.
///
/// **This is not [`egress::content_hash`].** That one is a frozen
/// cross-language contract covering only the egress image's `COPY`
/// sources, and it is what goes in the image tag. This one covers every
/// embedded byte, path and mode across all three trees, because the
/// extraction cache has to be invalidated by a change to
/// `templates/lima/provision.sh.j2` or `scaffolds/codex/Containerfile`
/// too — neither of which the egress hash can see. Using the egress hash
/// as the cache key would let a new binary reuse a stale scaffolds tree.
///
/// Format is this crate's business and may change freely; the only
/// requirement is that different embeds give different strings.
#[must_use]
pub fn assets_digest() -> String {
    let mut digest = Sha256::new();
    for file in embedded_files() {
        digest.update(file.path.as_bytes());
        digest.update([0]);
        digest.update(file.mode.to_be_bytes());
        digest.update(
            u64::try_from(file.bytes.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        digest.update(file.bytes);
    }
    let hex = format!("{:x}", digest.finalize());
    hex[..16].to_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use super::{
        EMBEDDED_TREES, PACKAGE_ROOT, VERSION, assets_digest, egress, embedded_files, tree,
    };

    /// The repository root, two levels up from `rust/agentcage-assets`.
    pub(super) fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate is nested at rust/<crate> inside the repo")
            .to_path_buf()
    }

    /// Every file the embed *should* contain, walked from the source
    /// tree with the build script's exclusion rules applied.
    ///
    /// Written independently of `build.rs` on purpose: if both used the
    /// same walk, a bug in it would agree with itself.
    fn source_files() -> Vec<(String, PathBuf)> {
        let root = repo_root().join(PACKAGE_ROOT);
        let mut out = Vec::new();
        for tree in EMBEDDED_TREES {
            collect(&root.join(tree), tree, &mut out);
        }
        out.sort();
        out
    }

    fn collect(dir: &Path, prefix: &str, out: &mut Vec<(String, PathBuf)>) {
        for entry in std::fs::read_dir(dir).expect("source tree is readable") {
            let entry = entry.expect("source tree entry is readable");
            let name = entry.file_name().into_string().expect("UTF-8 name");
            let rel = format!("{prefix}/{name}");
            let path = entry.path();
            if path.is_dir() {
                if name != "__pycache__" {
                    collect(&path, &rel, out);
                }
            } else if !egress::is_excluded(&name) {
                out.push((rel, path));
            }
        }
    }

    /// Every tree this crate promises to embed is actually there.
    ///
    /// Trivial until B3 wired up the embedding, and now load-bearing:
    /// the build script points at these paths, so a rename or a move of
    /// the Python package fails the *build* with a panic from a build
    /// script, which is a long way from the source. This fails a test
    /// instead, and names the path.
    #[test]
    fn every_embedded_tree_exists_and_is_populated() {
        let root = repo_root();
        assert!(
            root.join("VERSION").is_file(),
            "{} is not the repository root",
            root.display()
        );

        for tree in EMBEDDED_TREES {
            let path = root.join(PACKAGE_ROOT).join(tree);
            assert!(path.is_dir(), "missing embedded tree {}", path.display());

            let populated = std::fs::read_dir(&path)
                .expect("embedded tree is readable")
                .next()
                .is_some();
            assert!(populated, "embedded tree {} is empty", path.display());
        }
    }

    /// The egress build context is the one whose loss is silent.
    ///
    /// If `data/` were embedded without `Containerfile.egress` the
    /// failure would surface as an opaque podman build error a long way
    /// from the cause (RUST-PORT-PLAN.md section 6).
    #[test]
    fn the_egress_build_context_has_its_containerfile() {
        let containerfile = repo_root()
            .join(PACKAGE_ROOT)
            .join("data")
            .join("containers")
            .join("Containerfile.egress");
        assert!(
            containerfile.is_file(),
            "missing {}",
            containerfile.display()
        );
        assert!(
            super::tree("data").any(|(rel, _)| rel == "containers/Containerfile.egress"),
            "the Containerfile is on disk but not in the embed"
        );
    }

    /// The build script embedded exactly the source tree, byte for byte.
    ///
    /// This is the claim the whole crate rests on, so it is checked
    /// against a second, independent walk rather than against itself.
    #[test]
    fn the_embed_matches_the_source_tree_byte_for_byte() {
        let source = source_files();
        let embedded = embedded_files();

        let source_paths: BTreeSet<&str> = source.iter().map(|(rel, _)| rel.as_str()).collect();
        let embedded_paths: BTreeSet<&str> = embedded.iter().map(|f| f.path).collect();
        assert_eq!(
            source_paths, embedded_paths,
            "embed and source tree disagree about which files exist"
        );

        for (rel, path) in &source {
            let file = embedded
                .iter()
                .find(|f| f.path == rel)
                .expect("path sets already compared equal");
            let bytes = std::fs::read(path).expect("source file is readable");
            assert_eq!(
                file.bytes.len(),
                bytes.len(),
                "{rel}: embedded {} bytes, source has {}",
                file.bytes.len(),
                bytes.len()
            );
            assert!(file.bytes == bytes.as_slice(), "{rel}: contents differ");
        }
    }

    /// The executable bit survives the embed.
    ///
    /// Three files in the source tree are `0755`, and each one is
    /// `chmod`ed again by whatever consumes it —
    /// `Containerfile.egress:83` for `dns-audit.sh`,
    /// `services.py:177` for the `docker` shim,
    /// `scaffolds/openclaw/Containerfile:66` for `entrypoint.sh`. So
    /// nothing breaks *today* if a mode is lost. This test exists so
    /// that a future `COPY` written without a `chmod` cannot quietly
    /// ship a non-executable script.
    #[test]
    fn modes_match_the_source_tree() {
        use std::os::unix::fs::PermissionsExt as _;

        for (rel, path) in source_files() {
            let file = embedded_files()
                .iter()
                .find(|f| f.path == rel)
                .unwrap_or_else(|| panic!("{rel} is not embedded"));
            let on_disk = std::fs::metadata(&path)
                .expect("source file is stat-able")
                .permissions()
                .mode();
            let expected = if on_disk & 0o100 == 0 { 0o644 } else { 0o755 };
            assert_eq!(
                file.mode, expected,
                "{rel}: embedded mode 0o{:o}, source 0o{:o}",
                file.mode, on_disk
            );
        }
    }

    /// The set of embedded files is small, known, and reviewable.
    ///
    /// A count that moves without a deliberate change to the Python
    /// trees means something leaked into the embed — a build artifact, a
    /// `.pyc`, an editor backup. Update the number in the same commit
    /// that adds or removes the file.
    #[test]
    fn the_embedded_file_count_is_pinned() {
        assert_eq!(
            embedded_files().len(),
            78,
            "embedded file set changed: {:#?}",
            embedded_files().iter().map(|f| f.path).collect::<Vec<_>>()
        );
    }

    /// Bytecode caches never reach the binary.
    ///
    /// `pythonpath` in `pyproject.toml` includes
    /// `src/agentcage/data/proxy`, so `uv run pytest` leaves
    /// `__pycache__` directories inside the egress build context. This
    /// asserts they stayed out — the single reason this crate has a
    /// build script instead of an `include_dir!`.
    #[test]
    fn no_bytecode_caches_are_embedded() {
        for file in embedded_files() {
            assert!(
                !file.path.split('/').any(|part| part == "__pycache__"),
                "{} came from a bytecode cache",
                file.path
            );
            assert!(
                !egress::is_excluded(file.path),
                "{} is excluded from the egress hash but present in the embed",
                file.path
            );
        }
    }

    /// Paths are sorted and unique, which the hash depends on.
    #[test]
    fn embedded_paths_are_sorted_and_unique() {
        let paths: Vec<&str> = embedded_files().iter().map(|f| f.path).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(paths, sorted, "the build script emitted an unsorted table");
    }

    /// Every file belongs to a declared tree.
    #[test]
    fn every_embedded_path_is_under_a_declared_tree() {
        for file in embedded_files() {
            assert!(
                EMBEDDED_TREES
                    .iter()
                    .any(|t| file.path.starts_with(&format!("{t}/"))),
                "{} is outside {EMBEDDED_TREES:?}",
                file.path
            );
        }
    }

    /// `tree()` strips the tree name and finds every file.
    #[test]
    fn tree_strips_its_own_prefix() {
        let data: Vec<&str> = tree("data").map(|(rel, _)| rel).collect();
        assert!(data.contains(&"proxy/addon.py"), "{data:?}");
        assert!(data.iter().all(|rel| !rel.starts_with("data/")), "{data:?}");
        assert_eq!(
            data.len(),
            embedded_files()
                .iter()
                .filter(|f| f.path.starts_with("data/"))
                .count()
        );
        assert_eq!(tree("nope").count(), 0);
    }

    /// The cache-key digest is stable across calls and looks like a hash.
    #[test]
    fn assets_digest_is_stable_hex() {
        let digest = assets_digest();
        assert_eq!(digest.len(), 16, "{digest}");
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()), "{digest}");
        assert_eq!(digest, assets_digest());
    }

    /// The crate version is the workspace one, which is the VERSION file.
    #[test]
    fn version_is_the_version_file() {
        let expected =
            std::fs::read_to_string(repo_root().join("VERSION")).expect("VERSION is readable");
        assert_eq!(VERSION, expected.trim());
    }

    /// `build.rs` cannot import this crate, so its copies are checked here.
    #[test]
    fn the_build_script_agrees_about_the_trees_it_walks() {
        let build_rs =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs"))
                .expect("build.rs is readable");
        assert!(
            build_rs.contains(&format!("const PACKAGE_ROOT: &str = {PACKAGE_ROOT:?};")),
            "build.rs disagrees with PACKAGE_ROOT"
        );
        let trees = EMBEDDED_TREES
            .iter()
            .map(|t| format!("{t:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            build_rs.contains(&format!("const TREES: [&str; 3] = [{trees}];")),
            "build.rs disagrees with EMBEDDED_TREES"
        );
    }
}
