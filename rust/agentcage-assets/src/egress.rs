//! The egress image's content hash — a cross-language contract.
//!
//! A line-for-line port of `src/agentcage/egress_hash.py`. Read that
//! module's docstring first; it is the specification, and it explains
//! why the wire format is frozen. The short version, from #312: the
//! egress image used to be tagged `localhost/agentcage-egress:<version>`
//! and the build was skipped whenever that tag was already present, so a
//! security fix in `supervisor-egress.sh` between releases never reached
//! a host that already held the tag. The tag now carries a digest of the
//! build inputs, so changed content yields a tag the host cannot already
//! have.
//!
//! What makes it a *contract* rather than an implementation detail is
//! this port. The Python CLI and the Rust CLI will both compute this
//! digest during the transition, for the same tree, and they must agree
//! exactly. If they do not, every Mac rebuilds its egress image once on
//! upgrade and then maintains a second, permanently divergent tag
//! lineage for byte-identical content — and the "already present?" probe
//! stops meaning anything across the boundary.
//!
//! The format, from the Python docstring, is therefore not up for
//! tidying. SHA-256 over the inputs sorted by relative path, each
//! contributing:
//!
//! ```text
//! relpath (utf-8) || 0x00 || len(body) as 8-byte big-endian || body
//! ```
//!
//! truncated to the first [`TAG_HASH_LEN`] hex characters.
//!
//! `tests/fixtures/egress_hash.json` pins the digest of the tree as it
//! stands, together with the full relative-path → size list of inputs
//! that produced it. The test below reads that file rather than
//! hardcoding the digest, so a deliberate change to the build inputs is
//! one `scripts/bless-egress-hash.py` away and an accidental one names
//! the file that moved.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::shlex;

/// Truncated SHA-256 length for the tag suffix, in hex characters.
///
/// 12 hex chars = 48 bits. Mirrors `egress_hash.TAG_HASH_LEN`.
pub const TAG_HASH_LEN: usize = 12;

/// The Containerfile, relative to the build context (`data/`).
///
/// Mirrors `egress_hash.CONTAINERFILE_REL`.
pub const CONTAINERFILE_REL: &str = "containers/Containerfile.egress";

/// What an empty or absent build context hashes to.
///
/// Mirrors `egress_hash.UNKNOWN_HASH`. Callers embed this in the image
/// tag rather than failing, so the build path can report the missing
/// Containerfile with its own actionable error.
pub const UNKNOWN_HASH: &str = "unknown";

/// Directory names excluded from the hash.
///
/// Mirrors `egress_hash.HASH_EXCLUDE_DIRS`. `build.rs` already keeps
/// these out of the embed, but the exclusion is part of the contract and
/// has to apply to a directory too: an *extracted* build context sitting
/// on disk can acquire a `__pycache__` of its own if anything ever runs
/// Python in it.
pub const HASH_EXCLUDE_DIRS: [&str; 1] = ["__pycache__"];

/// File suffixes excluded from the hash.
///
/// Mirrors `egress_hash.HASH_EXCLUDE_SUFFIXES`.
pub const HASH_EXCLUDE_SUFFIXES: [&str; 2] = [".pyc", ".pyo"];

/// Containerfile instructions, with backslash continuations joined.
///
/// A port of `egress_hash.containerfile_logical_lines`, including its
/// quirks: comment-only lines are dropped, but a comment *inside* a
/// continuation is not, and a line whose continuation is never closed is
/// still yielded at EOF. Deliberately not a general Containerfile
/// parser — it only has to find `COPY` sources, and it has to find
/// exactly the ones Python finds.
#[must_use]
pub fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    // Python's `str.splitlines()` also breaks on \r, \v, \f and friends;
    // splitting on \n and trimming covers \n and \r\n, which is every
    // line ending a Containerfile in this repository has ever had.
    for raw in text.split('\n') {
        let stripped = raw.trim();
        if buf.is_empty() && (stripped.is_empty() || stripped.starts_with('#')) {
            continue;
        }
        if let Some(head) = stripped.strip_suffix('\\') {
            buf.push_str(head);
            buf.push(' ');
            continue;
        }
        buf.push_str(stripped);
        if !buf.is_empty() {
            out.push(std::mem::take(&mut buf));
        }
        buf.clear();
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

/// Source paths named by the `COPY` directives of a Containerfile.
///
/// A port of `egress_hash.egress_copy_sources`. Deriving the list from
/// the Containerfile rather than hardcoding it means a new
/// `COPY proxy/<something-new>` joins the content hash automatically,
/// instead of falling out of the rebuild decision the way a
/// hand-maintained list eventually would.
///
/// Only the shell form of `COPY` is matched; a JSON-array `COPY` simply
/// contributes no sources, and the Containerfile's own bytes are always
/// hashed, so the tag still changes whenever it is edited.
#[must_use]
pub fn copy_sources(containerfile_text: &str) -> Vec<String> {
    let mut sources = Vec::new();
    for line in logical_lines(containerfile_text) {
        let Some(rest) = copy_rest(&line) else {
            continue;
        };
        // Python skips the line on ValueError; so do we.
        let Ok(parts) = shlex::split(rest) else {
            continue;
        };
        // Drop `--chown=`/`--from=`-style flags; the final token is the
        // destination inside the image, everything before it is a source.
        let parts: Vec<String> = parts.into_iter().filter(|p| !p.starts_with("--")).collect();
        if parts.len() < 2 {
            continue;
        }
        sources.extend(parts.into_iter().rev().skip(1).rev());
    }
    sources
}

/// `^COPY\s+(?P<rest>.+)$`, case-insensitive, without a regex crate.
fn copy_rest(line: &str) -> Option<&str> {
    let (head, tail) = line.split_at_checked(4)?;
    if !head.eq_ignore_ascii_case("COPY") {
        return None;
    }
    // Python's `\s` is [ \t\n\r\f\v]; the logical line has no newlines.
    let rest = tail.trim_start_matches([' ', '\t', '\r', '\x0c', '\x0b']);
    if std::ptr::eq(rest, tail) || rest.is_empty() {
        // No separating whitespace, or nothing after it.
        return None;
    }
    Some(rest)
}

/// Somewhere the egress build context can be read from.
///
/// Two implementations: the bytes embedded in this binary, and a
/// directory on disk. The `COPY`-resolution logic above them is written
/// once, so the hash of the extracted tree is computed by the same code
/// as the hash of the embed — which is how the extraction proves itself.
trait Context {
    /// Contents of the file at POSIX-relative `rel`, or `None` when
    /// `rel` does not name a regular file.
    fn read(&self, rel: &str) -> Option<Vec<u8>>;

    /// Relative paths under directory `rel`, or `None` when `rel` does
    /// not name a directory. Entries may include directories; [`add`]
    /// filters them out, matching Python's `rglob("*")` plus `_add`.
    fn list_dir(&self, rel: &str) -> Option<Vec<String>>;
}

/// The trees compiled into this binary, rooted at `data/`.
struct Embedded;

impl Context for Embedded {
    fn read(&self, rel: &str) -> Option<Vec<u8>> {
        crate::tree("data")
            .find(|(path, _)| *path == rel)
            .map(|(_, file)| file.bytes.to_vec())
    }

    fn list_dir(&self, rel: &str) -> Option<Vec<String>> {
        let prefix = format!("{rel}/");
        let entries: Vec<String> = crate::tree("data")
            .filter(|(path, _)| path.starts_with(&prefix))
            .map(|(path, _)| path.to_owned())
            .collect();
        (!entries.is_empty()).then_some(entries)
    }
}

/// A build context on disk — an extracted tree, or the source `data/`.
struct Dir {
    /// Absolute path to the build-context root.
    root: PathBuf,
}

impl Context for Dir {
    fn read(&self, rel: &str) -> Option<Vec<u8>> {
        let path = self.root.join(rel);
        if !path.is_file() {
            return None;
        }
        // Python catches OSError at hash time and contributes b"".
        Some(std::fs::read(&path).unwrap_or_default())
    }

    fn list_dir(&self, rel: &str) -> Option<Vec<String>> {
        let path = self.root.join(rel);
        if !path.is_dir() {
            return None;
        }
        let mut out = Vec::new();
        walk(&path, rel, &mut out);
        Some(out)
    }
}

/// Collect every path under `dir` as `prefix`-relative POSIX paths.
fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let rel = format!("{prefix}/{name}");
        let path = entry.path();
        if path.is_dir() {
            walk(&path, &rel, out);
        } else {
            out.push(rel);
        }
    }
}

/// Every file baked into the egress image, sorted by relative path.
///
/// A port of `egress_hash.egress_build_inputs`: the Containerfile itself
/// plus the transitive contents of each `COPY` source. Returns an empty
/// vector when the Containerfile is missing — the build path reports
/// that with its own error rather than hashing nothing silently.
fn build_inputs_from(ctx: &dyn Context) -> Vec<(String, Vec<u8>)> {
    let Some(containerfile) = ctx.read(CONTAINERFILE_REL) else {
        return Vec::new();
    };

    let mut inputs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    // Added directly, not through `add`: Python does the same, so the
    // Containerfile is in the hash even if it somehow matched an
    // exclusion rule.
    inputs.insert(CONTAINERFILE_REL.to_owned(), containerfile.clone());

    // `read_text(errors="replace")` — lossy decoding, same replacement
    // character, so a Containerfile with a stray byte hashes the same on
    // both sides.
    let text = String::from_utf8_lossy(&containerfile);

    for src in copy_sources(&text) {
        let Some(target) = normalize_source(&src) else {
            continue;
        };
        if let Some(children) = ctx.list_dir(&target) {
            for child in children {
                add(ctx, &child, &mut inputs);
            }
        } else {
            // A missing source contributes nothing on purpose: the build
            // itself fails loudly on it and there are no bytes to hash.
            add(ctx, &target, &mut inputs);
        }
    }

    inputs.into_iter().collect()
}

/// `PurePosixPath(src.strip("/")).parts`, rejecting `..` and empties.
fn normalize_source(src: &str) -> Option<String> {
    let parts: Vec<&str> = src
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    if parts.is_empty() || parts.contains(&"..") {
        return None;
    }
    Some(parts.join("/"))
}

/// `egress_hash._add`: record `rel` unless excluded or not a file.
fn add(ctx: &dyn Context, rel: &str, inputs: &mut BTreeMap<String, Vec<u8>>) {
    if is_excluded(rel) {
        return;
    }
    if let Some(bytes) = ctx.read(rel) {
        inputs.insert(rel.to_owned(), bytes);
    }
}

/// Whether [`HASH_EXCLUDE_DIRS`] or [`HASH_EXCLUDE_SUFFIXES`] keeps `rel`
/// out of the build inputs.
///
/// Case-sensitive, because `pathlib`'s `suffix` comparison in
/// `egress_hash._add` is: a file named `X.PYC` is hashed by Python and
/// must therefore be hashed here too, however odd that is on a
/// case-insensitive filesystem.
pub(crate) fn is_excluded(rel: &str) -> bool {
    HASH_EXCLUDE_SUFFIXES.contains(&suffix_of(rel))
        || rel.split('/').any(|part| HASH_EXCLUDE_DIRS.contains(&part))
}

/// `pathlib.PurePath.suffix`: the last `.xxx` of the file name, or `""`.
///
/// A leading dot does not count, so `.pyc` as a whole file name has no
/// suffix — which is what Python does, and why this is not `rsplit`.
fn suffix_of(rel: &str) -> &str {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    match name.rfind('.') {
        Some(0) | None => "",
        Some(idx) => &name[idx..],
    }
}

/// The hash itself, over already-sorted inputs.
///
/// This function *is* the contract. Do not "clean it up".
fn hash_inputs(inputs: &[(String, Vec<u8>)]) -> String {
    if inputs.is_empty() {
        return UNKNOWN_HASH.to_owned();
    }
    let mut digest = Sha256::new();
    for (rel, body) in inputs {
        digest.update(rel.as_bytes());
        digest.update([0]);
        // Length-prefix the body so no path+content concatenation can be
        // re-partitioned into a different input set with the same hash.
        digest.update(u64::try_from(body.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(body);
    }
    let mut hex = format!("{:x}", digest.finalize());
    hex.truncate(TAG_HASH_LEN);
    hex
}

/// Build inputs of the egress image, from the embedded trees.
///
/// Sorted `(relative path, contents)` pairs, relative to the build
/// context root — which is `data/`, the directory `backends/container.py`
/// hands to podman.
#[must_use]
pub fn build_inputs() -> Vec<(String, Vec<u8>)> {
    build_inputs_from(&Embedded)
}

/// Build inputs of the egress image, from a build context on disk.
///
/// `root` is the build-context root, i.e. an extracted `data/`.
#[must_use]
pub fn build_inputs_from_dir(root: &Path) -> Vec<(String, Vec<u8>)> {
    build_inputs_from(&Dir {
        root: root.to_path_buf(),
    })
}

/// The egress image tag's content-hash suffix, from the embedded trees.
///
/// [`UNKNOWN_HASH`] when the Containerfile is missing.
#[must_use]
pub fn content_hash() -> String {
    hash_inputs(&build_inputs())
}

/// The egress image tag's content-hash suffix, from a directory.
///
/// Same digest as [`content_hash`] when `root` is an extraction of the
/// embedded `data/` tree — which is how [`crate::extract`] proves it
/// materialized the bytes it was carrying.
#[must_use]
pub fn content_hash_from_dir(root: &Path) -> String {
    hash_inputs(&build_inputs_from_dir(root))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        CONTAINERFILE_REL, TAG_HASH_LEN, UNKNOWN_HASH, build_inputs, build_inputs_from_dir,
        content_hash, content_hash_from_dir, copy_sources, logical_lines, suffix_of,
    };

    /// `tests/fixtures/egress_hash.json`, as PR A5 committed it.
    struct Fixture {
        hash: String,
        input_count: usize,
        inputs: BTreeMap<String, usize>,
    }

    fn fixture() -> Fixture {
        let path = crate::tests::repo_root()
            .join("tests")
            .join("fixtures")
            .join("egress_hash.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("{} is unreadable: {err}", path.display()));
        let json: serde_json::Value =
            serde_json::from_str(&text).expect("the fixture is valid JSON");
        Fixture {
            hash: json["hash"].as_str().expect("hash is a string").to_owned(),
            input_count: usize::try_from(
                json["input_count"]
                    .as_u64()
                    .expect("input_count is a number"),
            )
            .expect("input_count fits"),
            inputs: json["inputs"]
                .as_object()
                .expect("inputs is an object")
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        usize::try_from(v.as_u64().expect("a size is a number"))
                            .expect("a size fits"),
                    )
                })
                .collect(),
        }
    }

    /// The whole reason PR B3 exists.
    ///
    /// Reads the digest from A5's fixture rather than hardcoding it, so
    /// the Python reference and this port cannot drift apart without one
    /// of them failing. A deliberate change to the build inputs is
    /// `python3 scripts/bless-egress-hash.py` plus this test passing
    /// again; an accidental one fails here and in
    /// `tests/test_egress_hash.py` together.
    #[test]
    fn the_embedded_hash_matches_the_python_fixture() {
        let fixture = fixture();
        assert_eq!(
            content_hash(),
            fixture.hash,
            "the Rust egress content hash diverged from the Python one; \
             compare the input lists below"
        );
    }

    /// Which files went into the hash, not just what it came to.
    ///
    /// A5 committed the full relpath → size list rather than only the
    /// digest precisely so that a mismatch can name the file that moved.
    /// A bare hash comparison would say "different" and stop there.
    #[test]
    fn the_embedded_build_inputs_match_the_python_fixture() {
        let fixture = fixture();
        let actual: BTreeMap<String, usize> = build_inputs()
            .into_iter()
            .map(|(rel, body)| (rel, body.len()))
            .collect();

        let missing: Vec<&String> = fixture
            .inputs
            .keys()
            .filter(|k| !actual.contains_key(*k))
            .collect();
        let extra: Vec<&String> = actual
            .keys()
            .filter(|k| !fixture.inputs.contains_key(*k))
            .collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "build inputs differ from the fixture.\n  missing from Rust: {missing:?}\n  \
             extra in Rust:     {extra:?}"
        );

        let resized: Vec<String> = fixture
            .inputs
            .iter()
            .filter(|(rel, size)| actual[*rel] != **size)
            .map(|(rel, size)| format!("{rel}: fixture {size} bytes, embedded {}", actual[rel]))
            .collect();
        assert!(
            resized.is_empty(),
            "sizes differ:\n  {}",
            resized.join("\n  ")
        );

        assert_eq!(actual.len(), fixture.input_count);
        assert_eq!(fixture.input_count, fixture.inputs.len());
    }

    /// The hash of the source tree on disk equals the hash of the embed.
    ///
    /// Closes the loop the fixture leaves open: the fixture was blessed
    /// from `src/agentcage/data`, and this shows the binary is carrying
    /// that same tree rather than a coincidentally equal one.
    #[test]
    fn the_source_tree_on_disk_hashes_the_same() {
        let data = crate::tests::repo_root()
            .join(crate::PACKAGE_ROOT)
            .join("data");
        assert_eq!(content_hash_from_dir(&data), content_hash());
    }

    /// `__pycache__` in a real build context is excluded, not hashed.
    ///
    /// Not hypothetical: `pyproject.toml` puts
    /// `src/agentcage/data/proxy` on `pythonpath`, so the source tree
    /// this test reads has `__pycache__` directories in it after any
    /// `uv run pytest`. If the exclusion were broken, the test above
    /// would fail on whichever machine had run the suite — which is a
    /// worse way to find out than this.
    #[test]
    fn bytecode_caches_never_enter_the_hash() {
        let data = crate::tests::repo_root()
            .join(crate::PACKAGE_ROOT)
            .join("data");
        for (rel, _) in build_inputs_from_dir(&data) {
            assert!(!rel.contains("__pycache__"), "{rel}");
            assert!(!super::is_excluded(&rel), "{rel}");
        }
    }

    /// The Containerfile is always an input, and the shape is sane.
    #[test]
    fn the_containerfile_is_the_first_input() {
        let inputs = build_inputs();
        assert_eq!(inputs[0].0, CONTAINERFILE_REL, "inputs are sorted");
        assert_eq!(content_hash().len(), TAG_HASH_LEN);
        assert!(content_hash().chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// An empty context hashes to the sentinel, not to SHA-256 of "".
    #[test]
    fn a_missing_containerfile_is_unknown() {
        let empty = std::env::temp_dir().join("agentcage-b3-no-such-context");
        assert_eq!(content_hash_from_dir(&empty), UNKNOWN_HASH);
        assert!(build_inputs_from_dir(&empty).is_empty());
    }

    /// Continuation joining, as `containerfile_logical_lines` does it.
    #[test]
    fn logical_lines_join_continuations_and_drop_comments() {
        let text = "# a comment\n\nRUN a \\\n    b \\\n    c\nCOPY x y\n";
        assert_eq!(logical_lines(text), ["RUN a  b  c", "COPY x y"]);

        // A comment inside a continuation is *not* dropped -- Python
        // only skips comment lines when the buffer is empty.
        assert_eq!(
            logical_lines("RUN a \\\n# not a comment\n"),
            ["RUN a  # not a comment"]
        );

        // An unterminated continuation is still yielded at EOF.
        assert_eq!(logical_lines("RUN a \\\n"), ["RUN a  "]);
        assert_eq!(logical_lines(""), Vec::<String>::new());
    }

    /// The `COPY` forms the parser has to get right.
    #[test]
    fn copy_sources_handles_flags_multiple_sources_and_case() {
        assert_eq!(copy_sources("COPY a b\n"), ["a"]);
        assert_eq!(copy_sources("copy a b c\n"), ["a", "b"]);
        assert_eq!(copy_sources("COPY --chown=1:1 a b\n"), ["a"]);
        assert_eq!(copy_sources("COPY --from=x --chown=1:1 a b\n"), ["a"]);
        assert_eq!(copy_sources("COPY \"a b\" c\n"), ["a b"]);
        assert_eq!(
            copy_sources("COPY a \\\n    b \\\n    c\n"),
            ["a", "b"],
            "a continued COPY is one logical line"
        );
        // Not a COPY, or not enough tokens, or unlexable.
        assert_eq!(copy_sources("RUN copy a b\n"), Vec::<String>::new());
        assert_eq!(copy_sources("COPYa b\n"), Vec::<String>::new());
        assert_eq!(copy_sources("COPY a\n"), Vec::<String>::new());
        assert_eq!(copy_sources("COPY \"a b\n"), Vec::<String>::new());
        assert_eq!(copy_sources("# COPY a b\n"), Vec::<String>::new());
    }

    /// The real Containerfile names the sources the fixture lists.
    #[test]
    fn the_real_containerfile_copies_the_expected_trees() {
        let text = String::from_utf8(
            crate::tree("data")
                .find(|(rel, _)| *rel == CONTAINERFILE_REL)
                .expect("the Containerfile is embedded")
                .1
                .bytes
                .to_vec(),
        )
        .expect("the Containerfile is UTF-8");
        let sources = copy_sources(&text);
        for expected in [
            "proxy/addon.py",
            "proxy/inspectors/",
            "proxy/relays/",
            "proxy/transforms/",
            "containers/supervisor-egress.sh",
        ] {
            assert!(sources.contains(&expected.to_owned()), "{sources:?}");
        }
    }

    /// `pathlib`'s suffix rules, which decide the `.pyc` exclusion.
    #[test]
    fn suffix_matches_pathlib() {
        assert_eq!(suffix_of("a/b.pyc"), ".pyc");
        assert_eq!(suffix_of("a/b.tar.gz"), ".gz");
        assert_eq!(suffix_of("a/b"), "");
        assert_eq!(suffix_of(".pyc"), "", "a dotfile has no suffix");
        assert_eq!(suffix_of("a.b/c"), "");
    }
}
