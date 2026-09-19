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
//! # What will live here
//!
//! PR B3, per RUST-PORT-PLAN.md section 2.1:
//!
//! - **embedding** the three trees named in [`EMBEDDED_TREES`],
//! - **extraction** to a cache directory, byte-exact and mode-exact.
//!   File modes matter: the Containerfile `chmod 0755`s the supervisor
//!   itself, but every other executable's bit has to survive the round
//!   trip,
//! - **cache invalidation** keyed on binary version plus content hash,
//! - **`_egress_content_hash`** — `apple_container.py` hashes sorted
//!   `(relpath, len, content)` triples over the transitive `COPY`
//!   sources to build the image tag
//!   `localhost/agentcage-egress:<version>-<hash>`. Rust must reproduce
//!   it bit for bit or every Mac rebuilds its egress image once and then
//!   drifts from the Python build forever after. That means porting
//!   `_egress_copy_sources` verbatim, continuation handling and all, and
//!   asserting against the fixture PR A5 pinned.
//!
//! This crate is where the extraction and hashing live because both are
//! I/O, and [`agentcage_core`] is not allowed any. `agentcage-core` is
//! handed the *results*.
//!
//! # Dependencies
//!
//! None today. B3 adds an embedding crate — `include_dir` or
//! `rust-embed` — and that choice belongs in B3's body, where the mode
//! and byte-exactness requirements above can actually be argued about.

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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{EMBEDDED_TREES, PACKAGE_ROOT};

    /// The repository root, two levels up from `rust/agentcage-assets`.
    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate is nested at rust/<crate> inside the repo")
            .to_path_buf()
    }

    /// Every tree this crate promises to embed is actually there.
    ///
    /// Trivial until B3 wires up the embedding, and then load-bearing:
    /// once `include_dir!` points at these paths, a rename or a move of
    /// the Python package fails the *build* with a macro error that says
    /// nothing useful. This fails a test instead, and names the path.
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
    }
}
