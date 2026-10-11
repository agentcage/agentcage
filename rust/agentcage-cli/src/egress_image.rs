//! The egress image's build inputs beyond the embedded `data/` tree.
//!
//! `Containerfile.egress` copies the `agentcage-egress` binary from
//! [`egress::BINARY_REL`] inside the build context. That binary is built
//! for a linux-musl target, not the host's, so it reaches the host
//! binary through its own crate (`agentcage-egress-embed`) rather than
//! the `data/` embed, and it is laid over the extracted tree here, just
//! before a build.
//!
//! The image tag is `<version>-<hash>` on every backend, and the hash
//! covers the binary: rebuilding the egress yields a reference no store
//! already holds, so the "already present" short-circuits stay sound
//! when only the binary changed.

use std::fmt;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::{Mutex, OnceLock, PoisonError};

use agentcage_assets::egress;

/// Why the egress binary could not be put into a build context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageError {
    /// This host binary was built without the egress binary.
    MissingBinary,
    /// The binary could not be written into the build context.
    Write(String),
}

impl fmt::Display for StageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBinary => f.write_str(&agentcage_egress_embed::missing_hint()),
            Self::Write(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for StageError {}

/// A stand-in binary, for a host built without one: see
/// [`provide_binary_for_tests`].
static PROVIDED: OnceLock<&'static [u8]> = OnceLock::new();

/// Give a host built without an embedded egress a binary to stage.
///
/// For tests that drive a whole deploy against stubbed runtimes on a
/// development build, which carries no egress: without a binary the
/// build step refuses, as it must for a real deploy. The first call
/// wins, and an embedded binary always takes precedence, so this
/// changes nothing on a release build.
#[doc(hidden)]
pub fn provide_binary_for_tests(bytes: &'static [u8]) {
    let _ = PROVIDED.set(bytes);
}

/// The binary this host stages: the embedded one, else a provided one.
fn binary() -> Option<&'static [u8]> {
    agentcage_egress_embed::binary().or_else(|| PROVIDED.get().copied())
}

/// The egress image's content hash: the embedded tree plus the egress
/// binary.
///
/// Without a binary the hash is the tree's alone. Nothing can be built
/// under that tag ([`stage`] refuses first), so a lookup by it simply
/// misses and the build reports why.
#[must_use]
pub fn content_hash() -> String {
    // Hashing a multi-megabyte binary is the one non-trivial cost here,
    // and the tag is asked for by the unit render, the build and the
    // image-digest probe of one deploy. Keyed by which binary, since a
    // test may provide one after the first call.
    static HASH: Mutex<Option<(usize, String)>> = Mutex::new(None);
    let bytes = binary();
    let key = bytes.map_or(0, |b| b.as_ptr() as usize);
    let mut cached = HASH.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((cached_key, hash)) = cached.as_ref()
        && *cached_key == key
    {
        return hash.clone();
    }
    let hash = match bytes {
        Some(binary) => egress::content_hash_with(&[(egress::BINARY_REL, binary)]),
        None => egress::content_hash(),
    };
    *cached = Some((key, hash.clone()));
    hash
}

/// The egress image tag, `<version>-<hash>`.
#[must_use]
pub fn tag(version: &str) -> String {
    format!("{version}-{}", content_hash())
}

/// Put the embedded egress binary into an extracted build context.
///
/// Written at [`egress::BINARY_REL`], mode 0755, to a temporary name and
/// renamed into place: the extracted context is shared by every
/// concurrent `agentcage` process, and a reader must see the whole
/// binary or the previous one, never a partial write. Skipped when the
/// bytes on disk already match, so a context another process staged is
/// not rewritten.
///
/// # Errors
///
/// [`StageError::MissingBinary`] on a host built without one (and given
/// none by [`provide_binary_for_tests`]), [`StageError::Write`] when the
/// write fails.
pub fn stage(context: &Path) -> Result<(), StageError> {
    let binary = binary().ok_or(StageError::MissingBinary)?;
    stage_file(&context.join(egress::BINARY_REL), binary)
}

/// Write `bytes` to `path` atomically, executable, unless already there.
fn stage_file(path: &Path, bytes: &[u8]) -> Result<(), StageError> {
    let fail = |what: &str, error: std::io::Error| {
        StageError::Write(format!(
            "could not stage the egress binary at {} ({what}): {error}",
            path.display()
        ))
    };
    if fs::read(path).is_ok_and(|existing| existing == bytes) {
        return Ok(());
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir).map_err(|e| fail("mkdir", e))?;
    let tmp = dir.join(format!(".agentcage-egress.{}.tmp", std::process::id()));
    let written = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o755)
            .open(&tmp)?;
        file.write_all(bytes)?;
        // `mode()` is filtered by the umask; the image `chmod`s the
        // binary anyway, but the context should not depend on either.
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
        fs::rename(&tmp, path)
    })();
    written.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        fail("write", e)
    })
}

#[cfg(test)]
mod tests {
    use agentcage_assets::egress;

    use super::{StageError, content_hash, stage, tag};

    #[test]
    fn the_tag_is_version_dash_hash() {
        assert_eq!(tag("1.2.3"), format!("1.2.3-{}", content_hash()));
        assert_eq!(content_hash().len(), egress::TAG_HASH_LEN);
    }

    /// With a binary embedded, the tag carries its hash and staging
    /// reproduces it on disk; without one, staging says how to get one.
    #[test]
    fn the_embedded_binary_is_hashed_and_staged() {
        let Some(binary) = agentcage_egress_embed::binary() else {
            assert_eq!(content_hash(), egress::content_hash());
            let error = stage(&std::env::temp_dir()).expect_err("nothing to stage");
            assert_eq!(error, StageError::MissingBinary);
            assert!(error.to_string().contains("cargo build --release --target"));
            return;
        };
        assert_ne!(
            content_hash(),
            egress::content_hash(),
            "the binary must be a hash input"
        );

        let cache = std::env::temp_dir().join(format!("agentcage-stage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache);
        let context = agentcage_assets::extract::build_context_in(&cache).expect("extracts");
        stage(&context).expect("stages");
        // Twice: the second finds the bytes in place.
        stage(&context).expect("restages");
        let staged = context.join(egress::BINARY_REL);
        assert_eq!(std::fs::read(&staged).expect("staged"), binary);
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&staged)
                .expect("stat")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o755);
        }
        assert_eq!(
            egress::content_hash_from_dir(&context),
            content_hash(),
            "the staged context must hash to the tag it is built under"
        );
        std::fs::remove_dir_all(&cache).expect("cleanup");
    }
}
