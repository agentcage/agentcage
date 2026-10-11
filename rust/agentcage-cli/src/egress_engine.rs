//! Which egress implementation a deploy builds, during the transition.
//!
//! `AGENTCAGE_EGRESS_ENGINE` selects it: `python` (the default, the
//! image every cage runs today) or `rust` (the `agentcage-egress`
//! binary, `EGRESS-PORT-PLAN.md` Phase 5). The choice picks the
//! Containerfile, stages the binary into the build context, and is part
//! of the image tag, so both images coexist in one store and a cage
//! switches engines with an ordinary `cage update`.
//!
//! Transition-only, and kept to this one module for that reason: at the
//! cutover the Rust engine becomes the only one, the variable goes, and
//! the call sites collapse back to a single Containerfile and tag.

use std::fmt;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::OnceLock;

use agentcage_assets::egress;

/// The environment variable that selects the engine.
pub const ENGINE_ENV: &str = "AGENTCAGE_EGRESS_ENGINE";

/// The two egress implementations a host can build.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EgressEngine {
    /// The Python egress in `data/proxy/`, built from
    /// `Containerfile.egress`.
    #[default]
    Python,
    /// The `agentcage-egress` binary, built from
    /// `Containerfile.egress-rust`.
    Rust,
}

/// Why an engine could not be selected or prepared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// `AGENTCAGE_EGRESS_ENGINE` names no engine.
    Unknown(String),
    /// The Rust engine is selected but this host carries no binary.
    MissingBinary,
    /// The binary could not be staged into the build context.
    Stage(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(value) => write!(
                f,
                "{ENGINE_ENV}={value:?} is not an egress engine (expected `python` or `rust`)"
            ),
            Self::MissingBinary => write!(
                f,
                "{ENGINE_ENV}=rust: {}",
                agentcage_egress_embed::missing_hint()
            ),
            Self::Stage(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for EngineError {}

impl EgressEngine {
    /// The engine a value of [`ENGINE_ENV`] names.
    ///
    /// Unset or empty is the default; anything else must be one of the
    /// two names, case-insensitively, so a typo fails the deploy instead
    /// of silently building the engine the operator was not testing.
    ///
    /// # Errors
    ///
    /// [`EngineError::Unknown`] for any other value.
    pub fn parse(value: Option<&str>) -> Result<Self, EngineError> {
        let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
            return Ok(Self::default());
        };
        if value.eq_ignore_ascii_case(Self::Python.name()) {
            Ok(Self::Python)
        } else if value.eq_ignore_ascii_case(Self::Rust.name()) {
            Ok(Self::Rust)
        } else {
            Err(EngineError::Unknown(value.to_owned()))
        }
    }

    /// The engine this process's environment selects.
    ///
    /// # Errors
    ///
    /// [`EngineError::Unknown`] when the variable names no engine.
    pub fn from_env() -> Result<Self, EngineError> {
        Self::parse(std::env::var(ENGINE_ENV).ok().as_deref())
    }

    /// The engine's name, as [`ENGINE_ENV`] spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Rust => "rust",
        }
    }

    /// The Containerfile, relative to the build context.
    #[must_use]
    pub const fn containerfile_rel(self) -> &'static str {
        match self {
            Self::Python => egress::CONTAINERFILE_REL,
            Self::Rust => egress::RUST_CONTAINERFILE_REL,
        }
    }

    /// The image's content hash, over the embed (and, for Rust, the
    /// embedded binary).
    ///
    /// # Errors
    ///
    /// [`EngineError::MissingBinary`] for Rust on a host without one.
    pub fn content_hash(self) -> Result<String, EngineError> {
        match self {
            Self::Python => Ok(egress::content_hash()),
            Self::Rust => {
                // Hashing a multi-megabyte binary is the one non-trivial
                // cost here, and the tag is asked for by the unit render,
                // the build and the image-digest probe of one deploy.
                // The bytes are `'static`, so the answer never changes.
                static RUST_HASH: OnceLock<String> = OnceLock::new();
                let binary = agentcage_egress_embed::binary().ok_or(EngineError::MissingBinary)?;
                Ok(RUST_HASH
                    .get_or_init(|| {
                        egress::content_hash_with(
                            egress::RUST_CONTAINERFILE_REL,
                            &[(egress::RUST_BINARY_REL, binary)],
                        )
                    })
                    .clone())
            }
        }
    }

    /// The tag of the egress image for the container and vm backends.
    ///
    /// `<version>` for Python, unchanged, so every existing cage keeps
    /// its image reference. `<version>-rust-<hash>` for Rust: the hash
    /// covers the binary, so rebuilding the egress yields a reference no
    /// store already holds and a unit that names it.
    ///
    /// # Errors
    ///
    /// [`EngineError::MissingBinary`] for Rust on a host without one.
    pub fn tag(self, version: &str) -> Result<String, EngineError> {
        match self {
            Self::Python => Ok(version.to_owned()),
            Self::Rust => Ok(format!("{version}-rust-{}", self.content_hash()?)),
        }
    }

    /// The apple-container image tag: `<version>-<hash>` for Python, as
    /// before, and `<version>-rust-<hash>` for Rust.
    ///
    /// # Errors
    ///
    /// [`EngineError::MissingBinary`] for Rust on a host without one.
    pub fn apple_tag(self, version: &str) -> Result<String, EngineError> {
        match self {
            Self::Python => Ok(format!("{version}-{}", self.content_hash()?)),
            Self::Rust => self.tag(version),
        }
    }

    /// Put what this engine's Containerfile copies, beyond the embed,
    /// into an extracted build context.
    ///
    /// Nothing for Python. For Rust, the binary at
    /// [`egress::RUST_BINARY_REL`], mode 0755, written to a temporary
    /// name and renamed into place: the extracted context is shared by
    /// every concurrent `agentcage` process, and a reader must see the
    /// whole binary or the previous one, never a partial write. Skipped
    /// when the bytes on disk already match, so a context another
    /// process staged is not rewritten.
    ///
    /// # Errors
    ///
    /// [`EngineError::MissingBinary`] for Rust on a host without one,
    /// [`EngineError::Stage`] when the write fails.
    pub fn stage(self, context: &Path) -> Result<(), EngineError> {
        match self {
            Self::Python => Ok(()),
            Self::Rust => {
                let binary = agentcage_egress_embed::binary().ok_or(EngineError::MissingBinary)?;
                stage_file(&context.join(egress::RUST_BINARY_REL), binary)
            }
        }
    }
}

/// Write `bytes` to `path` atomically, executable, unless already there.
fn stage_file(path: &Path, bytes: &[u8]) -> Result<(), EngineError> {
    let fail = |what: &str, error: std::io::Error| {
        EngineError::Stage(format!(
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

    use super::{EgressEngine, EngineError};

    #[test]
    fn unset_and_empty_select_the_default_python_engine() {
        assert_eq!(EgressEngine::parse(None), Ok(EgressEngine::Python));
        assert_eq!(EgressEngine::parse(Some("")), Ok(EgressEngine::Python));
        assert_eq!(EgressEngine::parse(Some("  ")), Ok(EgressEngine::Python));
        assert_eq!(EgressEngine::default(), EgressEngine::Python);
    }

    #[test]
    fn both_names_parse_case_insensitively() {
        assert_eq!(
            EgressEngine::parse(Some("python")),
            Ok(EgressEngine::Python)
        );
        assert_eq!(EgressEngine::parse(Some("rust")), Ok(EgressEngine::Rust));
        assert_eq!(EgressEngine::parse(Some(" Rust\n")), Ok(EgressEngine::Rust));
        for engine in [EgressEngine::Python, EgressEngine::Rust] {
            assert_eq!(EgressEngine::parse(Some(engine.name())), Ok(engine));
        }
    }

    #[test]
    fn an_unknown_engine_is_refused_by_name() {
        let error = EgressEngine::parse(Some("rsut")).expect_err("a typo must not build");
        assert_eq!(error, EngineError::Unknown("rsut".to_owned()));
        assert!(
            error
                .to_string()
                .contains("AGENTCAGE_EGRESS_ENGINE=\"rsut\"")
        );
    }

    #[test]
    fn each_engine_builds_its_own_containerfile() {
        assert_eq!(
            EgressEngine::Python.containerfile_rel(),
            "containers/Containerfile.egress"
        );
        assert_eq!(
            EgressEngine::Rust.containerfile_rel(),
            "containers/Containerfile.egress-rust"
        );
    }

    /// The default engine's tags are exactly the pre-transition ones,
    /// so a host that never sets the variable sees no change at all.
    #[test]
    fn the_python_tags_are_unchanged() {
        assert_eq!(EgressEngine::Python.tag("1.2.3"), Ok("1.2.3".to_owned()));
        assert_eq!(
            EgressEngine::Python.apple_tag("1.2.3"),
            Ok(format!("1.2.3-{}", egress::content_hash()))
        );
        let context = std::env::temp_dir().join("agentcage-engine-python-stage");
        assert_eq!(EgressEngine::Python.stage(&context), Ok(()));
        assert!(!context.exists(), "the Python engine stages nothing");
    }

    /// With a binary embedded, the Rust tag carries its hash and staging
    /// reproduces it on disk; without one, every Rust operation says how
    /// to get one.
    #[test]
    fn the_rust_engine_tags_and_stages_the_embedded_binary() {
        let Some(binary) = agentcage_egress_embed::binary() else {
            assert_eq!(
                EgressEngine::Rust.tag("1.2.3"),
                Err(EngineError::MissingBinary)
            );
            let error = EgressEngine::Rust
                .stage(&std::env::temp_dir())
                .expect_err("nothing to stage");
            assert!(error.to_string().contains("cargo build --release --target"));
            return;
        };
        let hash = EgressEngine::Rust.content_hash().expect("embedded");
        assert_eq!(
            EgressEngine::Rust.tag("1.2.3"),
            Ok(format!("1.2.3-rust-{hash}"))
        );
        assert_eq!(
            EgressEngine::Rust.apple_tag("1.2.3"),
            EgressEngine::Rust.tag("1.2.3")
        );
        assert_ne!(hash, egress::content_hash());

        let cache = std::env::temp_dir().join(format!("agentcage-engine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache);
        let context = agentcage_assets::extract::build_context_in(&cache).expect("extracts");
        EgressEngine::Rust.stage(&context).expect("stages");
        // Twice: the second finds the bytes in place.
        EgressEngine::Rust.stage(&context).expect("restages");
        let staged = context.join(egress::RUST_BINARY_REL);
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
            egress::content_hash_from_dir_with(&context, egress::RUST_CONTAINERFILE_REL),
            hash,
            "the staged context must hash to the tag it is built under"
        );
        assert_eq!(
            egress::content_hash_from_dir(&context),
            egress::content_hash()
        );
        std::fs::remove_dir_all(&cache).expect("cleanup");
    }
}
