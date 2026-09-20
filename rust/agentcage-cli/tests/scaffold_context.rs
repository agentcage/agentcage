//! `fingerprint.scaffold_context_version`'s directory walk, against the
//! Python.
//!
//! PR C4 ported the digest; the walk that feeds it is I/O and belongs to
//! Track D. The ephemeral `run` flow is what makes it reachable in
//! anger: a scaffold cage's build context is staged into the cage's
//! state directory, and `cage update`'s no-op decision then hashes that
//! directory — so if the walk prunes the wrong thing, either every
//! `cage update` rebuilds or none of them notice an edit.
//!
//! # Why a recorded digest rather than a fixture tree
//!
//! A7's state fixtures do **not** include a cage with a staged scaffold
//! context, so there is no golden input to read. The tree below is built
//! here and its expected hash was produced by running the Python
//! directly over the identical tree:
//!
//! ```text
//! $ uv run python -c "from agentcage.fingerprint import \
//!     scaffold_context_version; print(scaffold_context_version(root, 'Containerfile'))"
//! 0069d3bdd2beef2b5c3c29922b6ad70de01e4b039582d5a85bcf3dc489248dc2
//! ```
//!
//! The tree is chosen to exercise every branch the walk has: nested
//! directories, each of the seven state artifacts at the top level, and
//! — the case that is easy to get wrong — a `creds/` and a
//! `metadata.json` that are *not* at the top level and therefore must be
//! hashed. `relative.parts[0] in _STATE_ARTIFACTS` prunes the root's own
//! entries, not every occurrence of those names at any depth.

use std::fs;
use std::path::Path;

use agentcage_cli::deploy::scaffold_context_version;

/// What the Python prints for the tree [`build`] creates.
const PYTHON_DIGEST: &str = "0069d3bdd2beef2b5c3c29922b6ad70de01e4b039582d5a85bcf3dc489248dc2";

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
    fs::write(path, text).expect("write");
}

fn build(root: &Path) {
    write(root, "Containerfile", "FROM scratch\n");
    write(root, "entrypoint.sh", "#!/bin/sh\necho hi\n");
    write(root, "sub/nested.txt", "nested\n");
    write(root, "skills/agentcage/SKILL.md", "skill\n");
    // The seven `_STATE_ARTIFACTS`, all excluded — writing a
    // fingerprint must not be able to invalidate itself.
    write(root, "cage.yaml", "name: x\n");
    write(root, "metadata.json", "{}\n");
    write(root, "fingerprint.json", "{}\n");
    write(root, "proxy-config.yaml", "{}\n");
    write(root, "dns-allowlist.conf", "server=1.1.1.1\n");
    write(root, "pending_secrets.json", "[]\n");
    write(root, "cage-env/placeholders.env", "K=v\n");
    write(root, "creds/K.cred", "blob\n");
    // Same names, one level down: build inputs, and hashed.
    write(root, "deep/creds/inner.txt", "inner\n");
    write(root, "deep/metadata.json", "{}\n");
}

#[test]
fn the_walk_hashes_what_the_python_hashes() {
    let dir = agentcage_state::TestDir::new("scaffold-context");
    let root = dir.path().join("root");
    build(&root);
    assert_eq!(
        scaffold_context_version(&root, "Containerfile"),
        PYTHON_DIGEST
    );
}

/// Both sentinels, and the absolute-`containerfile:` branch.
///
/// A cage with no `containerfile:` has no context to hash and answers
/// `""`; a root that is not a directory answers `"missing"`. An absolute
/// `containerfile:` re-roots the walk at that file's own directory,
/// which is why pointing a throwaway state dir at the tree's
/// Containerfile produces the same digest as walking the tree.
#[test]
fn the_three_special_answers_are_the_pythons() {
    let dir = agentcage_state::TestDir::new("scaffold-context-sentinels");
    let root = dir.path().join("root");
    build(&root);

    assert_eq!(scaffold_context_version(&root, ""), "");
    assert_eq!(
        scaffold_context_version(&dir.path().join("absent"), "Containerfile"),
        "missing"
    );
    assert_eq!(
        scaffold_context_version(
            Path::new("/does/not/matter"),
            &root.join("Containerfile").display().to_string()
        ),
        PYTHON_DIGEST
    );
}

/// An edit anywhere under the context moves the digest, and an edit to a
/// state artifact does not. That is the whole contract `cage update`
/// depends on.
#[test]
fn only_build_inputs_move_the_digest() {
    let dir = agentcage_state::TestDir::new("scaffold-context-edits");
    let root = dir.path().join("root");
    build(&root);
    let before = scaffold_context_version(&root, "Containerfile");

    write(&root, "metadata.json", "{\"network_octet\": 7}\n");
    write(&root, "fingerprint.json", "{\"x\": 1}\n");
    assert_eq!(scaffold_context_version(&root, "Containerfile"), before);

    write(&root, "skills/agentcage/SKILL.md", "skill, revised\n");
    assert_ne!(scaffold_context_version(&root, "Containerfile"), before);
}
