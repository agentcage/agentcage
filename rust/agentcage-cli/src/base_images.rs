//! `cage update`'s cheap "has a base image moved?" check, and the
//! "did the rebuild change anything?" restart decision that follows it.
//!
//! Every shipped image builds from a floating tag (`alpine:3`,
//! `debian:stable-slim`), and every build runs with `--pull=newer`, so a
//! rebuild picks up a moved base on its own. What was missing is a
//! reason to rebuild at all: an update whose inputs are unchanged used
//! to stop there. This module supplies that reason without pulling
//! anything:
//!
//! 1. Resolve the `FROM` references of each image the cage builds — the
//!    embedded egress Containerfile and the cage's own staged one (or
//!    the cage's image itself when it is pulled rather than built).
//!    `localhost/` builds, digest-pinned references and `scratch` cannot
//!    move and are skipped; earlier build stages and `ARG` substitution
//!    are handled by [`crate::deploy::containerfile_text_image_refs`].
//! 2. For each, ask the registry for its manifest with
//!    `podman manifest inspect <ref>` (one HTTPS round trip, no layers)
//!    and compare it with `podman image inspect <ref>`:
//!    * a manifest **list / index** is matched by the entry for the
//!      local image's platform: its digest is the per-arch manifest
//!      digest, which podman records in the local image's `Digest` and
//!      `RepoDigests` when it pulled by tag;
//!    * a **single-image** manifest is refused by `podman manifest
//!      inspect`, so it is read into a throwaway local list
//!      (`podman manifest create <tmp> docker://<ref>`, manifest and
//!      config only, then `podman manifest rm`), whose one entry is the
//!      image's manifest digest, compared the same way. Should podman
//!      ever print a single manifest itself, its `config.digest` (the
//!      image ID) is compared with the local image's ID.
//! 3. If the check cannot run (offline, registry error, rate limit), the
//!    base is treated as unchanged and the caller warns once.
//!
//! After a rebuild, [`image_changed`] compares the image a running
//! container was started from with the image its tag names now. Units
//! name images by tag, and the egress tag (`<version>-<hash>`) does not
//! change when its base does, so the tag alone says nothing; the IDs
//! do.

use std::collections::BTreeSet;
use std::path::Path;

use agentcage_core::config::Config;
use agentcage_exec::ExecError;
use agentcage_exec::tools::limactl::VmPodman;
use agentcage_exec::tools::podman::Podman;
use serde_json::Value;

use self::BaseStatus::{Current, Moved, NotLocal};

/// The podman store a cage's images live in: host podman for a
/// container cage, the guest's for a vm cage.
pub trait ImageStore {
    /// `podman image inspect <reference>`, first element.
    ///
    /// # Errors
    ///
    /// When the image is not in the store.
    fn image_inspect(&self, reference: &str) -> Result<Value, ExecError>;

    /// `podman manifest inspect <reference>`: the registry's manifest.
    ///
    /// # Errors
    ///
    /// When the registry cannot be asked or does not answer.
    fn manifest_inspect(&self, reference: &str) -> Result<Value, ExecError>;

    /// `podman manifest create <list> <image>`: a local list holding
    /// `image`'s manifest, which may be a remote (`docker://`) one.
    ///
    /// # Errors
    ///
    /// When the image cannot be read.
    fn manifest_create(&self, list: &str, image: &str) -> Result<(), ExecError>;

    /// `podman manifest rm <list>`, best-effort.
    fn manifest_remove(&self, list: &str);

    /// `podman container inspect <name>`, first element.
    ///
    /// # Errors
    ///
    /// When there is no such container.
    fn container_inspect(&self, name: &str) -> Result<Value, ExecError>;
}

impl ImageStore for Podman<'_> {
    fn image_inspect(&self, reference: &str) -> Result<Value, ExecError> {
        Podman::image_inspect(self, reference)
    }

    fn manifest_inspect(&self, reference: &str) -> Result<Value, ExecError> {
        Podman::manifest_inspect(self, reference)
    }

    fn manifest_create(&self, list: &str, image: &str) -> Result<(), ExecError> {
        Podman::manifest_create(self, list, image)
    }

    fn manifest_remove(&self, list: &str) {
        let _ = Podman::manifest_remove(self, list);
    }

    fn container_inspect(&self, name: &str) -> Result<Value, ExecError> {
        Podman::container_inspect(self, name)
    }
}

impl ImageStore for VmPodman<'_> {
    fn image_inspect(&self, reference: &str) -> Result<Value, ExecError> {
        VmPodman::image_inspect(self, reference)
    }

    fn manifest_inspect(&self, reference: &str) -> Result<Value, ExecError> {
        VmPodman::manifest_inspect(self, reference)
    }

    fn manifest_create(&self, list: &str, image: &str) -> Result<(), ExecError> {
        VmPodman::manifest_create(self, list, image)
    }

    fn manifest_remove(&self, list: &str) {
        let _ = VmPodman::manifest_remove(self, list);
    }

    fn container_inspect(&self, name: &str) -> Result<Value, ExecError> {
        VmPodman::container_inspect(self, name)
    }
}

// ── which references ─────────────────────────────────────────

/// Whether a `FROM` reference is one a registry could move.
///
/// Not `localhost/…` (a local build), not `…@sha256:…` (pinned), not
/// `scratch`, and not one with an unresolved `$VAR`.
#[must_use]
pub fn is_checkable(reference: &str) -> bool {
    !reference.is_empty()
        && !reference.starts_with("localhost/")
        && !reference.contains('@')
        && !reference.contains('$')
        && !reference.eq_ignore_ascii_case("scratch")
}

/// The checkable `FROM` references of the embedded egress Containerfile.
#[must_use]
pub fn egress_base_refs() -> BTreeSet<String> {
    let text = agentcage_assets::tree("data")
        .find(|(path, _)| *path == agentcage_assets::egress::CONTAINERFILE_REL)
        .map(|(_, file)| String::from_utf8_lossy(file.bytes).into_owned())
        .unwrap_or_default();
    crate::deploy::containerfile_text_image_refs(&text, &[])
        .into_iter()
        .filter(|reference| is_checkable(reference))
        .collect()
}

/// The checkable references the cage's own image depends on.
///
/// The staged Containerfile's `FROM` references, with the config's build
/// args; or, for a cage that runs a registry image directly (no
/// Containerfile), that image itself.
#[must_use]
pub fn cage_base_refs(config: &Config, state_dir: &Path) -> BTreeSet<String> {
    let refs = if config.container.build.containerfile.is_empty() {
        BTreeSet::from([config.container.image.clone()])
    } else {
        let args: Vec<(String, String)> = config
            .container
            .build
            .args
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        crate::deploy::containerfile_image_refs(config, state_dir, &args)
    };
    refs.into_iter()
        .filter(|reference| is_checkable(reference))
        .collect()
}

// ── the comparison ───────────────────────────────────────────

/// What the registry says about one base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseStatus {
    /// The local image is what the registry serves.
    Current,
    /// The registry serves a different image under this reference.
    Moved,
    /// The reference is not in the local store; a build would pull it.
    NotLocal,
}

/// Compare a local `podman image inspect` with a registry manifest.
///
/// # Errors
///
/// A description, when the manifest has neither shape this knows or
/// names no image for the local platform and none the local image has.
pub fn compare(local: &Value, remote: &Value) -> Result<BaseStatus, String> {
    if let Some(entries) = remote.get("manifests").and_then(Value::as_array) {
        let digests = local_digests(local);
        let os = str_field(local, &["Os", "os"]);
        let arch = str_field(local, &["Architecture", "architecture"]);
        let variant = str_field(local, &["Variant", "variant"]);
        let for_platform: Vec<&str> = entries
            .iter()
            .filter(|entry| {
                let platform = entry.get("platform");
                let field = |key: &str| {
                    platform
                        .and_then(|p| p.get(key))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                };
                field("os") == os
                    && field("architecture") == arch
                    && (variant.is_empty()
                        || field("variant").is_empty()
                        || field("variant") == variant)
            })
            .filter_map(|entry| entry.get("digest").and_then(Value::as_str))
            .collect();
        if !for_platform.is_empty() {
            return Ok(if for_platform.iter().any(|d| digests.contains(*d)) {
                Current
            } else {
                Moved
            });
        }
        // No entry for this platform (or a local image without platform
        // fields): any entry the local image has is still a match.
        let any = entries
            .iter()
            .filter_map(|entry| entry.get("digest").and_then(Value::as_str))
            .any(|digest| digests.contains(digest));
        return if any {
            Ok(Current)
        } else {
            Err(format!(
                "no manifest for {os}/{arch} in the registry's index"
            ))
        };
    }
    if let Some(config) = remote
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(Value::as_str)
    {
        let id = str_field(local, &["Id", "ID", "id"]);
        return Ok(if !id.is_empty() && same_image(config, id) {
            Current
        } else {
            Moved
        });
    }
    Err("the registry's manifest has an unrecognised shape".to_owned())
}

/// Every manifest digest the local image is known by: `Digest` and the
/// digest half of each `RepoDigests` entry.
fn local_digests(local: &Value) -> BTreeSet<String> {
    let mut digests = BTreeSet::new();
    let digest = str_field(local, &["Digest", "digest"]);
    if !digest.is_empty() {
        digests.insert(digest.to_owned());
    }
    for key in ["RepoDigests", "repoDigests"] {
        for entry in local
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if let Some((_, digest)) = entry.rsplit_once('@') {
                digests.insert(digest.to_owned());
            }
        }
    }
    digests
}

fn str_field<'v>(value: &'v Value, keys: &[&str]) -> &'v str {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .unwrap_or_default()
}

/// The name to ask the registry for: the local image's own qualified
/// name when it has one that spells this reference (so a short name
/// like `debian:stable-slim` is looked up where it was pulled from),
/// else the reference as written, for podman to resolve.
fn lookup_name(reference: &str, local: Option<&Value>) -> String {
    let tagged = if reference
        .rsplit('/')
        .next()
        .is_some_and(|last| last.contains(':'))
    {
        reference.to_owned()
    } else {
        format!("{reference}:latest")
    };
    local
        .and_then(|local| local.get("RepoTags").and_then(Value::as_array))
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .find(|tag| *tag == tagged || tag.ends_with(&format!("/{tagged}")))
        .map_or_else(|| reference.to_owned(), str::to_owned)
}

/// The outcome of checking a set of references.
#[derive(Debug, Default)]
pub struct Checked {
    /// The references that moved or are missing locally, with which.
    pub changed: Vec<(String, BaseStatus)>,
    /// The first reason a reference could not be checked, if any.
    pub failure: Option<String>,
}

/// Check each reference against the registry.
///
/// A reference whose check fails is left out of `changed` — treated as
/// unchanged — and the first failure is kept for the caller's single
/// warning. A reference missing from the local store still asks the
/// registry first: offline, a rebuild would have nothing to build from,
/// and an update that fails because of this check is worse than one
/// that skips it.
pub fn check(store: &dyn ImageStore, refs: &BTreeSet<String>) -> Checked {
    let mut checked = Checked::default();
    for reference in refs {
        let local = store.image_inspect(reference).ok();
        let name = lookup_name(reference, local.as_ref());
        let remote = match remote_manifest(store, &name) {
            Ok(remote) => remote,
            Err(error) => {
                checked
                    .failure
                    .get_or_insert_with(|| format!("{reference}: {}", one_line(&error)));
                continue;
            }
        };
        let Some(local) = local else {
            checked.changed.push((reference.clone(), NotLocal));
            continue;
        };
        match compare(&local, &remote) {
            Ok(Current) => {}
            Ok(status) => checked.changed.push((reference.clone(), status)),
            Err(why) => {
                checked
                    .failure
                    .get_or_insert_with(|| format!("{reference}: {why}"));
            }
        }
    }
    checked
}

/// The registry's manifest for `name`, as an index.
///
/// `podman manifest inspect` answers for a manifest list directly. For a
/// single-image manifest it refuses ("Treating single images as manifest
/// lists is not implemented"), so that one is read into a throwaway
/// local list instead (`podman manifest create <tmp> docker://<name>`,
/// manifests and config only), whose one entry carries the image's
/// manifest digest and platform; the list is removed again.
fn remote_manifest(store: &dyn ImageStore, name: &str) -> Result<Value, ExecError> {
    match store.manifest_inspect(name) {
        Err(ExecError::Failed { ref stderr, .. }) if stderr.contains(SINGLE_IMAGE) => {
            let list = format!("localhost/agentcage-base-probe-{}", std::process::id());
            store.manifest_remove(&list);
            let created = store.manifest_create(&list, &format!("docker://{name}"));
            let inspected = created.and_then(|()| store.manifest_inspect(&list));
            store.manifest_remove(&list);
            inspected
        }
        other => other,
    }
}

/// The tail of podman's refusal to inspect a single-image manifest.
const SINGLE_IMAGE: &str = "Treating single images as manifest lists is not implemented";

/// An exec error's message, cut to its last non-empty line: podman's
/// registry errors end with the useful part.
fn one_line(error: &ExecError) -> String {
    let text = match error {
        ExecError::Failed { stderr, .. } if !stderr.trim().is_empty() => stderr.clone(),
        other => other.to_string(),
    };
    text.lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default()
        .trim_start_matches("Error: ")
        .to_owned()
}

// ── the restart decision ─────────────────────────────────────

/// Whether two image IDs name the same image, with or without the
/// `sha256:` prefix.
#[must_use]
pub fn same_image(a: &str, b: &str) -> bool {
    let strip = |id: &str| id.trim().trim_start_matches("sha256:").to_owned();
    strip(a) == strip(b)
}

/// The image ID a container was started from (`.Image`), if it exists.
#[must_use]
pub fn running_image(store: &dyn ImageStore, container: &str) -> Option<String> {
    let inspect = store.container_inspect(container).ok()?;
    let id = str_field(&inspect, &["Image", "ImageID"]);
    (!id.is_empty()).then(|| id.to_owned())
}

/// The image ID a reference names now, if it is in the store.
#[must_use]
pub fn current_image(store: &dyn ImageStore, reference: &str) -> Option<String> {
    let inspect = store.image_inspect(reference).ok()?;
    let id = str_field(&inspect, &["Id", "ID", "id"]);
    (!id.is_empty()).then(|| id.to_owned())
}

/// Whether a running container has to restart to pick up its image.
///
/// Only when both IDs are known and equal is the answer "no": a
/// container or image that cannot be inspected restarts, because
/// leaving a cage on a stale image is the failure this exists to stop.
#[must_use]
pub fn image_changed(running: Option<&str>, current: Option<&str>) -> bool {
    match (running, current) {
        (Some(running), Some(current)) => !same_image(running, current),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};

    use agentcage_exec::tools::podman::Podman;
    use agentcage_exec::{Elevation, ExecError, FakeRunner, Reply};
    use serde_json::{Value, json};

    use super::{
        BaseStatus, ImageStore, check, compare, egress_base_refs, image_changed, is_checkable,
        lookup_name, same_image,
    };

    const LIST: &str = "sha256:1111";
    const AMD64: &str = "sha256:aaaa";
    const ARM64: &str = "sha256:bbbb";

    fn local_amd64(digest: &str) -> Value {
        json!({
            "Id": "c0ffee",
            "Digest": digest,
            "RepoDigests": [
                format!("docker.io/library/alpine@{LIST}"),
                format!("docker.io/library/alpine@{digest}"),
            ],
            "RepoTags": ["docker.io/library/alpine:3"],
            "Os": "linux",
            "Architecture": "amd64",
        })
    }

    fn index(amd64: &str) -> Value {
        json!({
            "schemaVersion": 2,
            "manifests": [
                {"digest": amd64, "platform": {"architecture": "amd64", "os": "linux"}},
                {"digest": "sha256:attest", "platform": {"architecture": "unknown", "os": "unknown"}},
                {"digest": ARM64, "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"}},
            ],
        })
    }

    #[test]
    fn checkable_references_skip_local_pinned_and_scratch() {
        assert!(is_checkable("docker.io/library/alpine:3"));
        assert!(is_checkable("debian:stable-slim"));
        assert!(!is_checkable("localhost/agentcage-egress:1"));
        assert!(!is_checkable("alpine@sha256:abcd"));
        assert!(!is_checkable("scratch"));
        assert!(!is_checkable("${BASE}"));
        assert!(!is_checkable(""));
    }

    #[test]
    fn the_egress_base_is_found_in_the_embedded_containerfile() {
        let refs = egress_base_refs();
        assert!(!refs.is_empty(), "the egress builds FROM something");
        assert!(refs.iter().all(|r| is_checkable(r)), "{refs:?}");
    }

    #[test]
    fn an_index_is_matched_by_the_local_platforms_entry() {
        assert_eq!(
            compare(&local_amd64(AMD64), &index(AMD64)),
            Ok(BaseStatus::Current)
        );
        assert_eq!(
            compare(&local_amd64(AMD64), &index("sha256:new")),
            Ok(BaseStatus::Moved)
        );
    }

    /// The index's own digest is in `RepoDigests` too, but the
    /// pretty-printed manifest cannot be hashed back to it; only the
    /// per-arch entry decides. A local image another arch's entry
    /// happens to match is not "current" for this platform.
    #[test]
    fn another_platforms_entry_does_not_count() {
        let mut local = local_amd64("sha256:old");
        local["RepoDigests"] = json!([format!("x@{ARM64}")]);
        assert_eq!(compare(&local, &index(AMD64)), Ok(BaseStatus::Moved));
    }

    #[test]
    fn a_variant_must_agree_when_both_sides_have_one() {
        let local =
            json!({"Digest": ARM64, "Os": "linux", "Architecture": "arm64", "Variant": "v8"});
        assert_eq!(compare(&local, &index(AMD64)), Ok(BaseStatus::Current));
        let local =
            json!({"Digest": "sha256:v7", "Os": "linux", "Architecture": "arm64", "Variant": "v7"});
        assert!(compare(&local, &index(AMD64)).is_err());
    }

    #[test]
    fn a_single_manifest_is_matched_by_its_config_digest() {
        let remote = json!({"schemaVersion": 2, "config": {"digest": "sha256:c0ffee"}});
        assert_eq!(
            compare(&local_amd64(AMD64), &remote),
            Ok(BaseStatus::Current)
        );
        let remote = json!({"schemaVersion": 2, "config": {"digest": "sha256:beef"}});
        assert_eq!(compare(&local_amd64(AMD64), &remote), Ok(BaseStatus::Moved));
    }

    #[test]
    fn an_unknown_shape_or_platform_cannot_be_compared() {
        assert!(compare(&local_amd64(AMD64), &json!({"schemaVersion": 1})).is_err());
        let local = json!({"Digest": "sha256:x", "Os": "plan9", "Architecture": "mips"});
        assert!(compare(&local, &index(AMD64)).is_err());
    }

    #[test]
    fn a_short_name_is_looked_up_under_the_local_images_qualified_name() {
        let local = json!({"RepoTags": ["docker.io/library/debian:stable-slim"]});
        assert_eq!(
            lookup_name("debian:stable-slim", Some(&local)),
            "docker.io/library/debian:stable-slim"
        );
        let local = json!({"RepoTags": ["docker.io/library/node:latest"]});
        assert_eq!(
            lookup_name("node", Some(&local)),
            "docker.io/library/node:latest"
        );
        assert_eq!(
            lookup_name("debian:stable-slim", None),
            "debian:stable-slim"
        );
        let other = json!({"RepoTags": ["quay.io/x/debian:other"]});
        assert_eq!(
            lookup_name("debian:stable-slim", Some(&other)),
            "debian:stable-slim"
        );
    }

    /// A store from maps; a missing key is an error.
    #[derive(Default)]
    struct Store {
        local: BTreeMap<String, Value>,
        remote: BTreeMap<String, Value>,
        asked: RefCell<Vec<String>>,
    }

    fn missing() -> ExecError {
        ExecError::Failed {
            program: "podman".to_owned(),
            status: agentcage_exec::ExitStatus::exited(125),
            stderr: "Error: reading image: pinging container registry: connection refused\n"
                .to_owned(),
        }
    }

    impl ImageStore for Store {
        fn image_inspect(&self, reference: &str) -> Result<Value, ExecError> {
            self.local.get(reference).cloned().ok_or_else(missing)
        }
        fn manifest_inspect(&self, reference: &str) -> Result<Value, ExecError> {
            self.asked.borrow_mut().push(reference.to_owned());
            self.remote.get(reference).cloned().ok_or_else(missing)
        }
        fn manifest_create(&self, _: &str, _: &str) -> Result<(), ExecError> {
            Err(missing())
        }
        fn manifest_remove(&self, _: &str) {}
        fn container_inspect(&self, _: &str) -> Result<Value, ExecError> {
            Err(missing())
        }
    }

    #[test]
    fn check_reports_moved_and_missing_and_keeps_the_first_failure() {
        let mut store = Store::default();
        store.local.insert("alpine:3".into(), local_amd64(AMD64));
        store
            .remote
            .insert("docker.io/library/alpine:3".into(), index("sha256:new"));
        store.remote.insert("debian:13".into(), index(AMD64));
        let refs: BTreeSet<String> = ["alpine:3", "debian:13", "node:1", "zzz:1"]
            .map(String::from)
            .into();
        let checked = check(&store, &refs);
        assert_eq!(
            checked.changed,
            vec![
                ("alpine:3".to_owned(), BaseStatus::Moved),
                ("debian:13".to_owned(), BaseStatus::NotLocal),
            ]
        );
        assert_eq!(
            checked.failure.as_deref(),
            Some("node:1: reading image: pinging container registry: connection refused")
        );
        assert_eq!(
            store.asked.borrow().as_slice(),
            ["docker.io/library/alpine:3", "debian:13", "node:1", "zzz:1"]
        );
    }

    #[test]
    fn an_unchanged_base_is_not_reported() {
        let mut store = Store::default();
        store.local.insert("alpine:3".into(), local_amd64(AMD64));
        store
            .remote
            .insert("docker.io/library/alpine:3".into(), index(AMD64));
        let checked = check(&store, &BTreeSet::from(["alpine:3".to_owned()]));
        assert!(checked.changed.is_empty());
        assert!(checked.failure.is_none());
    }

    /// Through real podman argv: an offline registry is a failure, not
    /// a moved base, and the lookup carries a time limit.
    #[test]
    fn the_podman_store_asks_manifest_inspect_with_a_timeout() {
        let fake = FakeRunner::new();
        fake.push(Reply::ok(
            serde_json::to_string(&json!([local_amd64(AMD64)])).unwrap(),
        ));
        fake.push(Reply::failed(
            125,
            "Error: pinging container registry: dial tcp: i/o timeout",
        ));
        let podman = Podman::with_elevation(&fake, Elevation::none());
        let checked = check(&podman, &BTreeSet::from(["alpine:3".to_owned()]));
        assert!(checked.changed.is_empty());
        assert_eq!(
            checked.failure.as_deref(),
            Some("alpine:3: pinging container registry: dial tcp: i/o timeout")
        );
        fake.assert_argv(&[
            &["podman", "image", "inspect", "alpine:3"],
            &[
                "podman",
                "manifest",
                "inspect",
                "docker.io/library/alpine:3",
            ],
        ]);
        assert_eq!(
            fake.call(1).command.timeout_limit(),
            Some(agentcage_exec::tools::podman::MANIFEST_INSPECT_TIMEOUT)
        );
    }

    /// A single-image manifest is read through a throwaway list, which
    /// is removed again, and matched by the digest it records.
    #[test]
    fn a_single_image_manifest_is_read_through_a_throwaway_list() {
        let fake = FakeRunner::new();
        let local = json!([{
            "Id": "c0ffee",
            "RepoDigests": ["localhost:5000/base@sha256:one"],
            "RepoTags": ["localhost:5000/base:1"],
            "Os": "linux",
            "Architecture": "amd64",
        }]);
        fake.push(Reply::ok(local.to_string()));
        fake.push(Reply::failed(
            125,
            "Error: parsing manifest blob \"{}\" as a \"application/vnd.oci.image.manifest.v1+json\": \
             Treating single images as manifest lists is not implemented",
        ));
        fake.push(Reply::status(1)); // stale list from a crashed run: none
        fake.push(Reply::success());
        fake.push(Reply::ok(index("sha256:two").to_string()));
        fake.push(Reply::success());
        let podman = Podman::with_elevation(&fake, Elevation::none());
        let checked = check(
            &podman,
            &BTreeSet::from(["localhost:5000/base:1".to_owned()]),
        );
        assert_eq!(
            checked.changed,
            vec![("localhost:5000/base:1".to_owned(), BaseStatus::Moved)]
        );
        assert!(checked.failure.is_none());
        let list = format!("localhost/agentcage-base-probe-{}", std::process::id());
        fake.assert_argv(&[
            &["podman", "image", "inspect", "localhost:5000/base:1"],
            &["podman", "manifest", "inspect", "localhost:5000/base:1"],
            &["podman", "manifest", "rm", &list],
            &[
                "podman",
                "manifest",
                "create",
                &list,
                "docker://localhost:5000/base:1",
            ],
            &["podman", "manifest", "inspect", &list],
            &["podman", "manifest", "rm", &list],
        ]);
    }

    #[test]
    fn restart_only_when_the_running_image_differs_from_the_tag() {
        assert!(!image_changed(Some("abc"), Some("sha256:abc")));
        assert!(image_changed(Some("abc"), Some("def")));
        assert!(image_changed(None, Some("def")));
        assert!(image_changed(Some("abc"), None));
        assert!(same_image("sha256:abc", "abc"));
    }
}
