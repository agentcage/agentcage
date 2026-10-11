//! The shared egress image: what it is called, and when it is rebuilt.
//!
//! One `agentcage-egress` image is built per host per distinct set of
//! build inputs, and every cage on that host shares it — a per-cage
//! build would burn ~30s and ~120 MB on every `cage create`.
//!
//! # Why the tag carries a hash
//!
//! [`egress_build_argv`] is only ever reached when the tag is *not*
//! already present locally: the build probes with
//! `container image inspect` and skips the build when it hits. Nothing
//! about the image's contents took part in that decision while the tag
//! was `agentcage-egress:<version>` alone, so a security fix landing in
//! `supervisor-egress.sh` between releases never reached a host that
//! already held the tag. Measured on a real Mac (#312): a `0.32.0` image
//! built before the #186 proxy-log hardening still had the pre-fix
//! supervisor and a world-readable `audit.jsonl`, while `cage create`
//! printed "already present; skipping rebuild".
//!
//! So the tag is `<version>-<12 hex of the build inputs>`, the same
//! scheme as the container and vm backends. The inputs include the
//! `agentcage-egress` binary ([`crate::egress_image`]), so a changed
//! input yields a tag the host cannot already have, the probe misses,
//! and the rebuild happens with no flag.
//!
//! # The build context
//!
//! A single binary has no package directory, so the context comes from
//! [`agentcage_assets::extract`], which materializes the embedded tree
//! into a cache dir, with the egress binary staged into it. Which is why
//! the context is a parameter here rather than a constant: the argv
//! *shape* is the contract, the path is not.

use std::path::Path;

use agentcage_assets::egress;

/// `_EGRESS_IMAGE_REPO` — the repository half of the tag.
///
/// `localhost/` is load-bearing: the image is built locally and can
/// never resolve in a registry, which `build_artifacts` relies on when
/// it refuses to `image pull` a `localhost/` reference.
pub const EGRESS_IMAGE_REPO: &str = "localhost/agentcage-egress";

/// `_egress_image_name` — the full tagged reference.
///
/// The version keeps the tag human-readable and greppable; the hash is
/// what actually drives the rebuild decision.
#[must_use]
pub fn egress_image_name(version: &str, content_hash: &str) -> String {
    format!("{EGRESS_IMAGE_REPO}:{version}-{content_hash}")
}

/// [`egress_image_name`] over a build context on disk.
///
/// The seam that points the whole rebuild decision at a throwaway
/// context; `tests/fixtures/apple-container/image.json` records one.
#[must_use]
pub fn egress_image_name_from_context(version: &str, context: &Path) -> String {
    egress_image_name(version, &egress::content_hash_from_dir(context))
}

/// [`egress_image_name`] over the tree and the egress binary embedded
/// in this binary.
///
/// The version is this crate's, which the workspace holds equal to the
/// root `VERSION` file (`scripts/check-version.sh`).
#[must_use]
pub fn egress_image_name_embedded() -> String {
    egress_image_name(
        agentcage_assets::VERSION,
        &crate::egress_image::content_hash(),
    )
}

/// What `cage create --no-cache` / `--pull` mean for the egress build.
///
/// Either one forces a rebuild even when the tag *is* present: the
/// operator asked for a clean rebuild or a fresh base, so the shared
/// image is rebuilt too rather than served from the cached tag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BuildFlags {
    /// `container build --no-cache`.
    pub no_cache: bool,
    /// `container build --pull`.
    pub pull: bool,
}

impl BuildFlags {
    /// Whether the "already present; skipping rebuild" short-circuit is
    /// bypassed.
    #[must_use]
    pub const fn forces_rebuild(self) -> bool {
        self.no_cache || self.pull
    }
}

/// `_build_egress_image_if_missing`'s argv, minus the `container` binary.
///
/// The fixture pins the order: the flags land
/// *between* `-f <containerfile>` and the context, not at the end.
#[must_use]
pub fn egress_build_argv(image: &str, context: &Path, flags: BuildFlags) -> Vec<String> {
    let context = context.display().to_string();
    let mut argv = vec![
        "build".to_owned(),
        "-t".to_owned(),
        image.to_owned(),
        "-f".to_owned(),
        format!("{context}/{}", egress::CONTAINERFILE_REL),
    ];
    if flags.no_cache {
        argv.push("--no-cache".to_owned());
    }
    if flags.pull {
        argv.push("--pull".to_owned());
    }
    argv.push(context);
    argv
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        BuildFlags, EGRESS_IMAGE_REPO, egress_build_argv, egress_image_name,
        egress_image_name_embedded,
    };

    #[test]
    fn tag_is_repo_version_hash() {
        assert_eq!(
            egress_image_name("1.2.3", "abcdef012345"),
            "localhost/agentcage-egress:1.2.3-abcdef012345"
        );
    }

    /// The embedded tag is the one a user of this release would get.
    ///
    /// The digest itself is checked against the committed fixture by
    /// `agentcage-assets`; what this adds is that the wiring puts the
    /// crate's version and that digest together in the right order.
    #[test]
    fn embedded_tag_carries_this_crate_version() {
        let name = egress_image_name_embedded();
        let suffix = name
            .strip_prefix(&format!("{EGRESS_IMAGE_REPO}:"))
            .expect("the repo half is a literal");
        let (version, hash) = suffix
            .rsplit_once('-')
            .expect("the tag is <version>-<hash>");
        assert_eq!(version, agentcage_assets::VERSION);
        assert_eq!(hash, crate::egress_image::content_hash());
    }

    /// The flags go before the context, which is not a free choice:
    /// `container build` takes the context positionally and a flag
    /// after it would be parsed as a second positional.
    #[test]
    fn flags_precede_the_context() {
        let argv = egress_build_argv(
            "img",
            Path::new("/ctx"),
            BuildFlags {
                no_cache: true,
                pull: true,
            },
        );
        assert_eq!(
            argv,
            [
                "build",
                "-t",
                "img",
                "-f",
                "/ctx/containers/Containerfile.egress",
                "--no-cache",
                "--pull",
                "/ctx",
            ]
        );
    }

    #[test]
    fn either_flag_forces_a_rebuild() {
        assert!(!BuildFlags::default().forces_rebuild());
        assert!(
            BuildFlags {
                no_cache: true,
                pull: false
            }
            .forces_rebuild()
        );
        assert!(
            BuildFlags {
                no_cache: false,
                pull: true
            }
            .forces_rebuild()
        );
    }
}
