//! `container.volumes` and `container.tmpfs`, as this backend means them.
//!
//! Four pure functions, and the order they are called in is part of the
//! contract. `start()` does:
//!
//! ```text
//! volume_entries = _user_volume_argv(meta["volumes"])      # expanded
//! targets        = _tmpfs_targets(meta["tmpfs"])
//! seeds          = _tmpfs_copyup_seeds(meta["tmpfs"], volume_entries, np)
//! ```
//!
//! — so the mask logic sees the **expanded** entries, not the raw ones
//! (`apple_container.py:1805`). That matters twice over: `~` and `$VAR`
//! are already gone, so a host path can be stat'd; and an entry
//! [`user_volume_argv`] refused is not a mount at all, so nothing nests
//! under it. Feeding it the raw list would silently re-expose a volume
//! the containment check had just rejected.
//!
//! The topology itself — which mask sits under which mount, what the
//! host directory underneath it is, the deepest-first mount-point
//! ordering — is [`agentcage_core::volume_mounts`] (PR C7), shared with
//! the quadlet backend. Nothing here reimplements any of it; what lives
//! here is the part that is genuinely this backend's: Apple's
//! `--tmpfs` taking a bare path, the home-directory containment rule,
//! and the emulated copy-up.
//!
//! # Why copy-up is emulated
//!
//! Apple's `container run --tmpfs` takes a bare path — at container
//! 1.0.0 the *whole* argument is the destination, so Docker's
//! `path:opts` form would mount a tmpfs at a directory literally named
//! `path:opts`. (1.3.0 learned to split it, but the older contract is
//! still targeted, so options are dropped on every version;
//! `validate_config` warns per cage about exactly which ones.) A mask's
//! `tmpcopyup` therefore can never reach the runtime, and copy-up is
//! emulated the way `np` binds already are: the host directory the mask
//! covers is mounted read-only at a *lower* under
//! `/run/agentcage/masks/`, and cage-init's stage C'' replays it into
//! the fresh tmpfs. The tmpfs is what the workload writes to, so the
//! mask's whole point (#170/#173) survives — only what the cage can
//! *read* changes (#328).

use std::collections::BTreeSet;

use agentcage_core::quadlets::{QuadletHost, expanduser, expandvars};
use agentcage_core::volume_mounts::{
    MountTarget, NonPersistentVolumeError, is_non_persistent_volume, mask_copyup_entries,
    split_volume_spec, validate_non_persistent_volume,
};

/// Where an emulated copy-up mask's read-only lower is mounted.
///
/// `/run/agentcage/masks/mask-<n>/lower`. The index is the mask's
/// position in [`mask_copyup_entries`], *not* its position among the
/// seeds — an entry that yields no seed still consumes its number.
const MASK_LOWER_ROOT: &str = "/run/agentcage/masks";

/// The `--volume` arguments, plus the warnings that explain what is
/// missing from them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeArgv {
    /// `host:cage[:mode]` strings, ready to splice into `container run
    /// --volume <entry>`.
    pub argv: Vec<String>,
    /// One line per skipped entry, in emission order.
    ///
    /// These are the only signal an operator gets that a mount was
    /// dropped, so they are as much a part of the contract as the argv:
    /// a cage that comes up without its workspace and says nothing is
    /// how #318's `${PROJECT_DIR}` regression stayed invisible.
    pub warnings: Vec<String>,
}

/// `_user_volume_argv` — expand and validate `container.volumes`.
///
/// Mirrors the quadlet backend's safety rules so behaviour is identical
/// across backends:
///
/// * `~` and `$VAR` are expanded in the host portion;
/// * an entry whose host path still contains a `$` is skipped — the
///   variable was unset, and `posixpath.expandvars` leaves such a
///   reference in place, which is what makes the check reliable;
/// * an entry whose host path **resolves** outside the operator's home
///   is skipped, so a symlink cannot smuggle `/etc` in;
/// * an entry with no `:` has no cage-side path and is skipped.
///
/// Note that only the host half is touched: `parts[1]` — the cage path
/// and any options, `np` included — is passed through verbatim, which
/// is what keeps this function idempotent. `start()` re-runs it over
/// the metadata a previous `create` baked, and a second pass over its
/// own output has to be a no-op.
///
/// # Errors
///
/// [`NonPersistentVolumeError`] when an `np` option is combined with
/// something it cannot compose with. The Python raises here rather than
/// warning, and it raises *before* anything else in the loop, so a bad
/// `np` spec fails the deploy instead of being quietly dropped.
pub fn user_volume_argv(
    raw_entries: &[String],
    host: &dyn QuadletHost,
) -> Result<VolumeArgv, NonPersistentVolumeError> {
    let mut out = VolumeArgv::default();
    let home = host.realpath(&expanduser("~", host));
    for entry in raw_entries {
        validate_non_persistent_volume(entry)?;
        let Some((raw_host, rest)) = entry.split_once(':') else {
            out.warnings.push(format!(
                "warning: skipping volume '{entry}' on apple-container \
                 (missing ':<cage-path>')"
            ));
            continue;
        };
        let host_part = expandvars(&expanduser(raw_host, host), host);
        if host_part.contains('$') {
            out.warnings.push(format!(
                "warning: skipping volume '{host_part}' on apple-container \
                 (unresolved variable in host path)"
            ));
            continue;
        }
        let real = host.realpath(&host_part);
        if real != home && !real.starts_with(&format!("{home}/")) {
            out.warnings.push(format!(
                "warning: skipping volume '{host_part}' on apple-container \
                 (host path resolves outside '{home}')"
            ));
            continue;
        }
        out.argv.push(format!("{real}:{rest}"));
    }
    Ok(out)
}

/// The `--tmpfs` arguments, plus the warnings for the refused ones.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TmpfsTargets {
    /// Absolute, de-duplicated, trailing-slash-stripped cage paths.
    pub targets: Vec<String>,
    /// One line per refused entry, in emission order.
    pub warnings: Vec<String>,
}

/// `_tmpfs_targets` — normalize `container.tmpfs` into bare cage paths.
///
/// The option list is dropped, because Apple's `--tmpfs` is the
/// destination and nothing else. So the scaffolds'
/// `rw,noexec,nosuid,size=64M` does **not** reach the mount: it lands
/// with kernel-default tmpfs options — writable, exec/suid/dev
/// permitted, bounded only by the cage VM's memory. That is a real
/// weakening relative to the quadlet backend and it is not silent;
/// `validate_config` warns per cage about exactly which options were
/// dropped.
///
/// Entries that are not absolute, or that ask for `/` (a tmpfs over
/// the rootfs would hide the whole image), are skipped with a warning
/// rather than handed to the runtime. Duplicates are dropped *after*
/// normalization, because Apple lexically normalizes destinations too
/// and a dedupe that did not would be dishonest.
#[must_use]
pub fn tmpfs_targets(raw_entries: &[String]) -> TmpfsTargets {
    let mut out = TmpfsTargets::default();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for entry in raw_entries {
        let target = entry.split(':').next().unwrap_or(entry).trim();
        let normalized = target.trim_end_matches('/');
        if !target.starts_with('/') {
            out.warnings.push(format!(
                "warning: skipping tmpfs '{entry}' on apple-container \
                 (target must be an absolute path)"
            ));
            continue;
        }
        if normalized.is_empty() {
            out.warnings.push(format!(
                "warning: skipping tmpfs '{entry}' on apple-container \
                 (a tmpfs over `/` would hide the cage image's rootfs)"
            ));
            continue;
        }
        if !seen.insert(normalized.to_owned()) {
            continue;
        }
        out.targets.push(normalized.to_owned());
    }
    out
}

/// `_mask_mount_targets` — the mount table the mask helpers consume.
///
/// `(container_target, host_source)` per bind. An `np` bind reports an
/// **empty** source: its target is a tmpfs seeded from a read-only
/// lowerdir, so writes there never reach the host, and a mask nested
/// under it must not be attributed to a host path.
///
/// Call it with the output of [`user_volume_argv`], not with the raw
/// `container.volumes` — see the module docs.
#[must_use]
pub fn mask_mount_targets(volume_entries: &[String]) -> Vec<MountTarget> {
    let mut mounts = Vec::new();
    for entry in volume_entries {
        let (host_src, target, _options) = split_volume_spec(entry);
        if target.is_empty() {
            continue;
        }
        let source = if is_non_persistent_volume(entry) {
            ""
        } else {
            host_src
        };
        mounts.push(MountTarget::new(target, source));
    }
    mounts
}

/// One emulated copy-up: a read-only lower and the tmpfs it seeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyupSeed {
    /// The host directory the mask covers, after `realpath`.
    pub host_source: String,
    /// Where it is mounted read-only inside the cage.
    pub lower: String,
    /// The mask's own container path — the tmpfs being seeded.
    pub target: String,
}

/// The emulated copy-ups, plus the warnings for the refused ones.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopyupSeeds {
    /// One per seedable copy-up mask, in declaration order.
    pub seeds: Vec<CopyupSeed>,
    /// One line per mask refused for escaping its bind.
    pub warnings: Vec<String>,
}

/// `_tmpfs_copyup_seeds` — the emulated copy-up masks.
///
/// Skipped, silently, when the mask does not name `tmpcopyup`, when the
/// enclosing mount does not reach the host (a named volume or an `np`
/// bind — nothing host-side to seed from), when the target is already
/// an `np` tmpfs (*`skip_targets`*, #325's double-tmpfs avoidance;
/// cage-init seeds that one from the np lowerdir instead), or when the
/// host source is not an existing directory.
///
/// That last case must **not** create the directory. The mask
/// mount-point bookkeeping (#320) removes host directories agentcage
/// materialized, and inventing one here would leave a stray `.claude/`
/// in a project that has none — the same class of bug as the stray
/// `.git/hooks/` that `test -d .git` misreads as a repository.
///
/// A source that resolves outside the bind it came from is refused with
/// a warning, and this is the security-relevant branch: without it a
/// repository containing `.claude -> ../../.ssh` would turn the mask
/// into a fresh read-only window onto a host path the operator never
/// shared. The bind alone does not expose it, because an in-guest
/// symlink resolves in the guest; a host-side mount of the resolved
/// path would.
///
/// Equality with the bind root is legitimate and deliberately allowed:
/// a mask covering the whole bind seeds from the bind source itself.
#[must_use]
pub fn tmpfs_copyup_seeds(
    raw_entries: &[String],
    volume_entries: &[String],
    skip_targets: &BTreeSet<String>,
    host: &dyn QuadletHost,
) -> CopyupSeeds {
    let mut out = CopyupSeeds::default();
    let mounts = mask_mount_targets(volume_entries);
    for (index, entry) in mask_copyup_entries(raw_entries, &mounts).iter().enumerate() {
        if entry.host_source.is_empty() || skip_targets.contains(&entry.container_target) {
            continue;
        }
        let real_source = host.realpath(&entry.host_source);
        let real_root = host.realpath(&entry.host_root);
        if real_source != real_root && !real_source.starts_with(&format!("{real_root}/")) {
            out.warnings.push(format!(
                "warning: not seeding tmpfs mask '{}' on apple-container \
                 ('{}' resolves to '{real_source}', outside the '{}' mount); \
                 the mask comes up empty",
                entry.container_target, entry.host_source, entry.host_root,
            ));
            continue;
        }
        if !host.is_dir(&real_source) {
            continue;
        }
        out.seeds.push(CopyupSeed {
            host_source: real_source,
            lower: format!("{MASK_LOWER_ROOT}/mask-{index}/lower"),
            target: entry.container_target.clone(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{mask_mount_targets, tmpfs_targets};

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The behaviour a fixture cannot show, because it is about what a
    /// *second* pass does: `start()` re-runs `_user_volume_argv` over
    /// metadata a previous `create` already expanded.
    #[test]
    fn tmpfs_targets_is_idempotent() {
        let once = tmpfs_targets(&strings(&["/tmp/:rw,size=64M", "/var/log"]));
        let twice = tmpfs_targets(&once.targets);
        assert_eq!(once.targets, twice.targets);
        assert!(twice.warnings.is_empty());
    }

    /// An `np` bind contributes a target with no source, which is what
    /// keeps a mask under it from being attributed to the host.
    #[test]
    fn np_bind_has_no_host_source() {
        let mounts = mask_mount_targets(&strings(&[
            "/home/u/work:/workspace:rw,np",
            "/home/u/data:/data:rw",
        ]));
        assert_eq!(mounts[0].target, "/workspace");
        assert_eq!(mounts[0].source, "");
        assert_eq!(mounts[1].source, "/home/u/data");
    }

    /// An entry with no cage-side path is not a mount.
    #[test]
    fn entry_without_target_is_dropped() {
        assert!(mask_mount_targets(&strings(&["/home/u/work"])).is_empty());
    }
}
