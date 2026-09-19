//! Shared parsing and validation for user-declared host bind mounts.
//!
//! Port of `src/agentcage/volume_mounts.py`. Everything here turns a
//! user-authored string from `cage.yaml` into something that ends up in a
//! container runtime's mount arguments, so a parsing mistake here is a
//! containment mistake, not a cosmetic one. Two rules follow from that and
//! are worth stating before the code:
//!
//! **Parse exactly as Python does, colon for colon.** `split_volume_spec`
//! splits on at most two colons, so the *third* field swallows every
//! remaining colon. A host path containing a colon therefore does not mean
//! what its author expects — `/a:b:/dst` parses as source `/a`, target `b`,
//! options `/dst` — and that is also how Podman's own `--volume` parser
//! behaves. Reproducing it is the point; "fixing" it here would make the
//! Rust host disagree with the runtime it drives.
//!
//! **Do not expand anything.** No `~`, no `$VAR`, no `realpath`, no
//! `Path::canonicalize`. The Python module is equally inert: expansion
//! happens later and elsewhere, at the three sites that actually build
//! runtime arguments (`quadlets.py:639`, `run.py:200`,
//! `backends/apple_container.py:438`), each of which pairs it with a
//! containment check against `$HOME`. Expanding earlier would change what a
//! config *means*: the stored `cage.yaml` and the fingerprint would capture a
//! resolved path instead of the operator's `${HOME}/project`, so the same
//! config would stop meaning the same thing for a different user, and a
//! `${VAR}` that is unset at parse time would silently collapse to a
//! different path than the one the runtime would have seen. The golden corpus
//! pins this: every `source` it records is the literal `${HOME}/…` text.
//!
//! This crate is also forbidden to touch the filesystem (see the crate docs),
//! which lines up: none of these functions ask the disk anything, exactly as
//! the Python does not.
//!
//! # The tmpfs mask logic
//!
//! The second half of the module is the mount-topology lookup behind three
//! CHANGELOG entries, and the comments below are written assuming you have
//! not read them:
//!
//! * **#320** — a `tmpfs:` mask whose target sits under a host bind-mount
//!   makes the OCI runtime create the mount point, and a bind shares inodes
//!   with its source, so that `mkdir -p` lands in the operator's project
//!   directory on the *host*. [`mask_mountpoint_dirs`] is the bookkeeping that
//!   lets the caller remove exactly what it created, and only while empty.
//! * **#321** — an option-less tmpfs inherits the *host* directory's mode,
//!   which has no relationship to the cage's uid space, so the masks came up
//!   unwritable by the workload. The fix pins `mode=1777` on exactly the
//!   entries [`enclosing_mount`] says are inside another mount; that lookup
//!   was lifted here so the #320 cleanup and the #321 mode pin cannot drift.
//! * **#328** — Podman appends `tmpcopyup` to any tmpfs declaring neither
//!   copy-up option while Apple's `container run --tmpfs` has no option
//!   channel at all, so "unspecified" meant two different things.
//!   [`tmpfs_wants_copyup`] and [`mask_copyup_entries`] make it an explicit
//!   per-entry decision with one meaning on every backend.

use std::cmp::Reverse;
use std::fmt;
use std::fmt::Write as _;

/// Options that may accompany agentcage's inline `np` option.
///
/// Kept deliberately portable across Podman and apple-container. In
/// particular, Podman's overlay `O` cannot compose with `z`/`Z`, `U` mutates
/// the host source, and Apple container's bare `--tmpfs` has no option
/// channel.
const NP_ALLOWED_OPTIONS: [&str; 2] = ["np", "rw"];

/// Copy-up options, as podman's `pkg/util/mountOpts.go` spells them.
///
/// Podman appends `tmpcopyup` to every tmpfs that declares neither, which is
/// why the scaffold masks came up on podman holding the host's hooks and
/// project `.claude/` while apple-container (whose `--tmpfs` has no option
/// channel at all) came up empty — issue #328.
pub const TMPFS_COPYUP_OPTIONS: [&str; 2] = ["tmpcopyup", "notmpcopyup"];

/// Split `host:target[:options]` into its three fields.
///
/// Mirrors Python's `spec.split(":", 2)`: at most two splits, so any further
/// colon stays inside the options field. A spec with no colon at all is all
/// source and no target, and a trailing colon yields an empty options field
/// rather than being trimmed away.
#[must_use]
pub fn split_volume_spec(spec: &str) -> (&str, &str, &str) {
    let mut parts = spec.splitn(3, ':');
    // `splitn` always yields at least one item, so the first `unwrap_or` is
    // only there to keep the expression total.
    let source = parts.next().unwrap_or(spec);
    let Some(target) = parts.next() else {
        // `len(parts) < 2` in the Python: no colon, so nothing is a target.
        return (spec, "", "");
    };
    (source, target, parts.next().unwrap_or(""))
}

/// Return non-empty comma-separated options from a volume spec.
///
/// Empty fields are dropped, so `rw,,ro` is two options and a bare `:` tail
/// is none. Unknown options are *kept*: this module does not hold an
/// allowlist, because the option vocabulary belongs to the runtime the spec
/// is handed to (Podman's `z`, `Z`, `U`, `O`, `idmap`, the propagation flags)
/// and agentcage only reasons about the ones it adds itself.
#[must_use]
pub fn volume_options(spec: &str) -> Vec<&str> {
    let (_source, _target, raw_options) = split_volume_spec(spec);
    raw_options.split(',').filter(|o| !o.is_empty()).collect()
}

/// Return whether `spec` carries agentcage's inline `np` option.
#[must_use]
pub fn is_non_persistent_volume(spec: &str) -> bool {
    volume_options(spec).contains(&"np")
}

/// A volume spec whose `np` option cannot compose with its other options.
///
/// Carries the parts rather than a formatted string so a caller can render
/// it differently; [`fmt::Display`] reproduces the Python `ValueError`
/// message byte-for-byte, because `cage create` puts it in front of a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonPersistentVolumeError {
    /// The offending spec, verbatim.
    pub spec: String,
    /// The options that cannot combine with `np`, in the order declared.
    pub unsupported: Vec<String>,
}

impl fmt::Display for NonPersistentVolumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "volume {}: the np option cannot be combined with {}; only rw,np \
             is supported",
            py_repr(&self.spec),
            self.unsupported.join(", ")
        )
    }
}

impl std::error::Error for NonPersistentVolumeError {}

/// Reject options that cannot safely compose with `np`.
///
/// `np` creates a writable overlay whose host source is read-only. In
/// particular, Podman's `O` overlay cannot combine with `z`/`Z`; `U` would
/// recursively chown the host source; and caller-provided overlay directories
/// would escape agentcage's cleanup lifecycle.
///
/// # Errors
///
/// Returns [`NonPersistentVolumeError`] when the spec declares `np` alongside
/// anything outside `{np, rw}`. A spec without `np` is always accepted here —
/// its options are the runtime's business.
pub fn validate_non_persistent_volume(spec: &str) -> Result<(), NonPersistentVolumeError> {
    let options = volume_options(spec);
    if !options.contains(&"np") {
        return Ok(());
    }

    let unsupported: Vec<String> = options
        .iter()
        .filter(|o| !NP_ALLOWED_OPTIONS.contains(*o))
        .map(|o| (*o).to_string())
        .collect();
    if unsupported.is_empty() {
        return Ok(());
    }
    Err(NonPersistentVolumeError {
        spec: spec.to_string(),
        unsupported,
    })
}

/// Return the container path of a `container.tmpfs` spec.
///
/// An entry is `target[:options]`; only the target is meaningful to the
/// mount-topology helpers below. Note this is *not* normalized: a trailing
/// slash survives, because [`enclosing_mount`] is specified against the raw
/// target and the callers that need it normalized do their own trimming.
#[must_use]
pub fn tmpfs_spec_target(spec: &str) -> &str {
    spec.split_once(':').map_or(spec, |(target, _)| target)
}

/// Return the non-empty options of a `container.tmpfs` spec.
///
/// Unlike a volume spec there is only one separator colon, so everything
/// after the first one is options — including any further colons, which is
/// how `size=64M` and friends would survive a value containing one.
#[must_use]
pub fn tmpfs_spec_options(spec: &str) -> Vec<&str> {
    let raw_options = spec.split_once(':').map_or("", |(_, rest)| rest);
    raw_options.split(',').filter(|o| !o.is_empty()).collect()
}

/// Return whether `spec` explicitly asks for `tmpcopyup`.
///
/// Only an explicit request counts, and a spec naming *both* options asks for
/// neither — the same conservative reading Podman's own parser would not give
/// it. agentcage pins `notmpcopyup` on mask entries that declare neither
/// option (see `agentcage.quadlets._apply_tmpfs_mask_options`), so
/// "unspecified" means *empty* on every backend rather than whatever the
/// runtime happens to default to (issue #328).
#[must_use]
pub fn tmpfs_wants_copyup(spec: &str) -> bool {
    let options = tmpfs_spec_options(spec);
    options.contains(&"tmpcopyup") && !options.contains(&"notmpcopyup")
}

/// One mount the backend emits, as the topology helpers see it.
///
/// `source` is empty for mounts that do not write through to the host: named
/// volumes, and `np` mounts whose writes land in an overlay upperdir or a
/// tmpfs. That emptiness is load-bearing — it is what makes a mask over such
/// a mount correctly invisible to the #320 cleanup and unseedable for #328.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountTarget {
    /// The container-side path the mount lands on.
    pub target: String,
    /// The host-side path it writes through to, or empty if it does not.
    pub source: String,
}

impl MountTarget {
    /// Build a mount target from anything string-shaped.
    #[must_use]
    pub fn new(target: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            source: source.into(),
        }
    }
}

/// The deepest mount containing a target, as [`enclosing_mount`] found it.
///
/// `target` is the enclosing mount's own container path with any trailing
/// slash removed; `source` is its host source, empty when the mount does not
/// reach the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnclosingMount<'a> {
    /// The enclosing mount's container path, trailing slash removed.
    pub target: &'a str,
    /// Its host source, or `""` when the mount does not reach the host.
    pub source: &'a str,
}

/// Return the deepest mount in `mount_targets` that contains `target`.
///
/// `target` is an absolute container path. `mount_targets` describes every
/// mount the backend emits.
///
/// Returns the longest matching mount, or [`None`] when no mount encloses
/// `target` (the Python returns `("", "")` here; `None` says the same thing
/// without an in-band empty string, since a matched mount's target is never
/// empty). A mount at `/` never matches: it would make every path in the cage
/// look nested.
///
/// Ties go to the *last* candidate, matching the Python's `>=`. That only
/// bites when two mounts declare the same container target, which the runtime
/// itself resolves last-wins, so this agrees with what would actually be
/// mounted.
#[must_use]
pub fn enclosing_mount<'a>(
    target: &str,
    mount_targets: &'a [MountTarget],
) -> Option<EnclosingMount<'a>> {
    let mut best: Option<EnclosingMount<'a>> = None;
    for mount in mount_targets {
        if !mount.target.starts_with('/') {
            continue;
        }
        // `rstrip("/") or "/"`: an all-slashes target collapses to root.
        let trimmed = mount.target.trim_end_matches('/');
        let mount_target = if trimmed.is_empty() { "/" } else { trimmed };
        // Containment is by path *component*, never by raw string prefix:
        // `/workspace-backup` must not count as being inside `/workspace`.
        // Getting this wrong would attribute a mask to the wrong bind and
        // point the #320 cleanup at a host directory nobody shared, so it is
        // pinned by a unit test — the golden corpus has no adjacent-prefix
        // mounts and would not catch it.
        //
        // Collapsing a mount at `/` to `"/"` above is what makes the
        // documented "root never matches" fall out: the second arm then asks
        // whether `target` starts with `//`, which no normalized container
        // path does.
        let encloses = target == mount_target
            || (target.len() > mount_target.len()
                && target.starts_with(mount_target)
                && target.as_bytes()[mount_target.len()] == b'/');
        if !encloses {
            continue;
        }
        if mount_target.len() >= best.map_or(0, |b| b.target.len()) {
            best = Some(EnclosingMount {
                target: mount_target,
                source: &mount.source,
            });
        }
    }
    best
}

/// Host directories a `tmpfs:` mask will materialize under one bind source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskMountpointDirs {
    /// The enclosing bind mount's host source.
    pub host_source: String,
    /// Host paths the mask forces into existence, deepest first.
    pub dirs: Vec<String>,
}

/// Map bind-mount host source -> host dirs a `tmpfs:` mask materializes.
///
/// A `tmpfs:` entry whose target sits *under* a host bind-mount forces the
/// OCI runtime to create the mount point, and because a bind shares inodes
/// with its source, that `mkdir -p` lands in the operator's project directory
/// on the host. The scaffold masks are the common case: masking
/// `/workspace/.git/hooks/` on a project that is not a git repo leaves a stray
/// host `.git/hooks/`, which makes the ubiquitous `test -d .git` idiom
/// misreport the directory as a repository (issue #320).
///
/// The mask itself stays unconditional — dropping it when `.git` is absent
/// would reopen the #170 cage->host git-hook pivot for any `.git` created
/// later. Instead the caller records which of these paths were absent
/// immediately before container start and removes exactly those, and only
/// while still empty, on teardown.
///
/// `tmpfs` takes raw `container.tmpfs` specs (`target[:options]`).
/// Longest-prefix matching runs over the whole of `mount_targets` so that a
/// mask under, say, a named volume nested inside a bind is correctly
/// attributed to the named volume and therefore skipped.
///
/// The result is ordered by first appearance of each host source — the
/// insertion order of the Python `dict`, which the golden corpus records —
/// and each `dirs` list is ordered deepest first, so removing
/// `<project>/.git/hooks` is attempted before the `<project>/.git` parent that
/// the same mask also created.
#[must_use]
pub fn mask_mountpoint_dirs(
    tmpfs: &[String],
    mount_targets: &[MountTarget],
) -> Vec<MaskMountpointDirs> {
    let mut result: Vec<MaskMountpointDirs> = Vec::new();
    for spec in tmpfs {
        let target = tmpfs_spec_target(spec).trim_end_matches('/');
        if !target.starts_with('/') {
            continue;
        }
        let Some(enclosing) = enclosing_mount(target, mount_targets) else {
            // No enclosing mount: the mount point is created in the
            // container's own writable layer and never reaches the host.
            continue;
        };
        // The enclosing mount does not reach the host (named volume, `np`
        // bind), or the mask covers the whole mount so there is nothing to
        // create.
        if enclosing.source.is_empty() || target == enclosing.target {
            continue;
        }
        let parts: Vec<&str> = target[enclosing.target.len()..]
            .split('/')
            .filter(|p| !p.is_empty())
            .collect();
        // A `..` in the relative tail would let the derived host path climb
        // out of the bind source it was built from, and a `.` means the
        // operator wrote something this code has no normalization for. Skip
        // the entry rather than guess at a host path: the caller's runtime
        // `realpath` containment check is the second line of defence, not the
        // first.
        if parts.is_empty() || parts.iter().any(|p| *p == "." || *p == "..") {
            continue;
        }
        let index = if let Some(i) = result
            .iter()
            .position(|e| e.host_source == enclosing.source)
        {
            i
        } else {
            result.push(MaskMountpointDirs {
                host_source: enclosing.source.to_string(),
                dirs: Vec::new(),
            });
            result.len() - 1
        };
        let slot = &mut result[index];
        // Deepest first, then every parent the same `mkdir -p` implies, so
        // cleaning `<project>/.git/hooks` also retires `<project>/.git`.
        for depth in (1..=parts.len()).rev() {
            let path = join_host_path(enclosing.source, &parts[..depth]);
            if !slot.dirs.contains(&path) {
                slot.dirs.push(path);
            }
        }
    }
    // A stable sort by component count, descending — Python's
    // `sort(key=..., reverse=True)` keeps equal keys in insertion order, and
    // `slice::sort_by_key` is stable too, so equal-depth siblings from
    // different masks stay in declaration order.
    for entry in &mut result {
        entry.dirs.sort_by_key(|path| Reverse(count_slashes(path)));
    }
    result
}

/// A `tmpfs:` mask that asked for copy-up, resolved against the mount table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskCopyupEntry {
    /// The mask's container path, normalized (no trailing slash).
    pub container_target: String,
    /// The host directory the mask covers, or `""` when unseedable.
    pub host_source: String,
    /// The enclosing bind's own source, or `""` when unseedable.
    pub host_root: String,
}

/// Return the copy-up masks among `tmpfs`, resolved to host paths.
///
/// A *mask* is a `tmpfs:` entry whose target sits at or below another emitted
/// mount — the same relation [`mask_mountpoint_dirs`] and
/// `agentcage.quadlets._apply_tmpfs_mask_options` use. A tmpfs over a plain
/// image directory (`/tmp`, `/var/cache`) has no enclosing mount and is never
/// returned: its contents are the image author's intent and the runtime's own
/// copy-up already expresses them.
///
/// `tmpfs` takes raw `container.tmpfs` specs (`target[:options]`);
/// `mount_targets` is the same table [`mask_mountpoint_dirs`] consumes.
///
/// One entry per copy-up mask, ordered as declared.
/// [`container_target`](MaskCopyupEntry::container_target) is normalized (no
/// trailing slash). [`host_source`](MaskCopyupEntry::host_source) is the host
/// directory the mask covers — `<bind source>/<relative path>` — and
/// [`host_root`](MaskCopyupEntry::host_root) the enclosing bind's own source,
/// so a caller that turns `host_source` into a mount can require it to
/// resolve inside the directory the operator already agreed to share (a
/// project-supplied `.claude -> ../../.ssh` symlink must not become a new
/// host exposure). Both are `""` when the enclosing mount does not reach the
/// host (a named volume, an `np` bind), in which case only a runtime-side
/// copy-up can populate the tmpfs.
#[must_use]
pub fn mask_copyup_entries(
    tmpfs: &[String],
    mount_targets: &[MountTarget],
) -> Vec<MaskCopyupEntry> {
    let mut entries: Vec<MaskCopyupEntry> = Vec::new();
    for spec in tmpfs {
        let target = tmpfs_spec_target(spec).trim_end_matches('/');
        if !target.starts_with('/') || !tmpfs_wants_copyup(spec) {
            continue;
        }
        let normalized = normpath(target);
        let Some(enclosing) = enclosing_mount(&normalized, mount_targets) else {
            continue;
        };
        let mut source = String::new();
        if !enclosing.source.is_empty() {
            let parts: Vec<&str> = normalized[enclosing.target.len()..]
                .split('/')
                .filter(|p| !p.is_empty())
                .collect();
            // Same refusal as in `mask_mountpoint_dirs`, and here it is the
            // load-bearing one: this path becomes a read-only bind on
            // apple-container, so a `..` that escaped would open a window
            // onto a host directory the operator never shared. Leaving
            // `source` empty downgrades the mask to "unseedable", which the
            // caller warns about rather than acting on.
            if !parts.iter().any(|p| *p == "." || *p == "..") {
                source = join_host_path(enclosing.source, &parts);
            }
        }
        let host_root = if source.is_empty() {
            String::new()
        } else {
            enclosing.source.to_string()
        };
        entries.push(MaskCopyupEntry {
            container_target: normalized,
            host_source: source,
            host_root,
        });
    }
    entries
}

// ── helpers ──────────────────────────────────────────────────

/// Count `/` characters in a path, for the deepest-first ordering.
fn count_slashes(path: &str) -> usize {
    path.bytes().filter(|b| *b == b'/').count()
}

/// Join relative components onto a host path, as `os.path.join` would.
///
/// The components come from splitting an already-validated container path on
/// `/` and dropping empties, so none of them can be absolute or contain a
/// separator — which is the only case where `os.path.join`'s "an absolute
/// component discards everything before it" rule could bite. What is left to
/// reproduce is that `os.path.join` does not double a separator the base
/// already ends with, and that an empty base contributes no leading slash.
fn join_host_path(base: &str, parts: &[&str]) -> String {
    let mut out = base.to_string();
    for part in parts {
        if !out.is_empty() && !out.ends_with('/') {
            out.push('/');
        }
        out.push_str(part);
    }
    out
}

/// `os.path.normpath` for the POSIX paths this module sees.
///
/// Collapses repeated separators, drops `.` components, and resolves `..`
/// lexically — *without* consulting the filesystem, exactly as the Python
/// does, so a `..` through a symlink is not silently followed. Two POSIX
/// quirks are deliberate rather than accidental: a path beginning with
/// exactly two slashes keeps them (POSIX reserves `//` for the
/// implementation), and `..` at the root of an absolute path is discarded
/// rather than climbing above `/`.
#[must_use]
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let absolute = path.starts_with('/');
    // `//foo` is implementation-defined and preserved; `///foo` is not.
    let leading = usize::from(absolute && path.starts_with("//") && !path.starts_with("///"));

    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|last| *last != "..") {
                    out.pop();
                } else if !absolute {
                    out.push("..");
                }
                // An absolute path's leading `..` components vanish: there is
                // nothing above `/`.
            }
            other => out.push(other),
        }
    }

    let joined = out.join("/");
    if absolute {
        let mut prefix = "/".repeat(1 + leading);
        prefix.push_str(&joined);
        prefix
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Render a string the way Python's `repr()` would.
///
/// [`NonPersistentVolumeError`]'s message interpolates the spec with `{!r}`,
/// and that message is UX: `cage create` prints it verbatim, and
/// `tests/fixtures/golden` pins the bytes. So the quoting rules have to
/// match, not merely look similar — Python prefers `'`, switches to `"` when
/// the string contains a `'` but no `"`, and escapes the quote character only
/// when it could not switch away from it.
///
/// Scope: exact over the whole of Latin-1, verified character by character
/// against `CPython`. Beyond it Python decides printability from the Unicode
/// category table — `U+200B` renders `\u200b`, not as itself — and carrying
/// that table to render one error message about a path nobody can type by
/// accident is not a trade worth making, so such a character is emitted
/// literally here. It is a divergence in an error string only; no parsing
/// decision depends on this function. If it ever matters, the fix is a shared
/// `py_repr` alongside the rest of `config.py`'s message formatting rather
/// than a second copy here.
fn py_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(value.len() + 2);
    out.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            // Every character Latin-1 has that Python calls non-printable:
            // the C0 controls, DEL, the C1 controls, NBSP and the soft
            // hyphen. All render `\xNN`.
            c if (c as u32) < 0x20 || ('\u{7f}'..='\u{a0}').contains(&c) || c == '\u{ad}' => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(pairs: &[(&str, &str)]) -> Vec<MountTarget> {
        pairs
            .iter()
            .map(|(t, s)| MountTarget::new(*t, *s))
            .collect()
    }

    fn specs(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn split_is_at_most_two_colons() {
        assert_eq!(split_volume_spec("/src:/dst"), ("/src", "/dst", ""));
        assert_eq!(split_volume_spec("/src:/dst:ro"), ("/src", "/dst", "ro"));
        assert_eq!(split_volume_spec("/src:/dst:"), ("/src", "/dst", ""));
        assert_eq!(split_volume_spec("/src"), ("/src", "", ""));
        assert_eq!(split_volume_spec(""), ("", "", ""));
    }

    /// The colon-in-path case, pinned because it is the one a reader will
    /// assume is handled and it is not: the third field swallows the rest.
    #[test]
    fn a_colon_in_a_path_is_a_separator_not_a_path_character() {
        assert_eq!(split_volume_spec("/a:b:/dst"), ("/a", "b", "/dst"));
        assert_eq!(
            split_volume_spec("/a:/dst:ro:extra"),
            ("/a", "/dst", "ro:extra")
        );
        // …and the options split is plain `,`, so the swallowed tail shows up
        // as an option nobody wrote.
        assert_eq!(volume_options("/a:/dst:ro:extra"), vec!["ro:extra"]);
    }

    #[test]
    fn spaces_and_trailing_slashes_survive_verbatim() {
        assert_eq!(
            split_volume_spec("/home/u/My Project/:/workspace/:ro"),
            ("/home/u/My Project/", "/workspace/", "ro")
        );
    }

    #[test]
    fn nothing_is_expanded() {
        let (source, ..) = split_volume_spec("~/p:/workspace");
        assert_eq!(source, "~/p");
        let (source, ..) = split_volume_spec("${HOME}/p:/workspace");
        assert_eq!(source, "${HOME}/p");
        let (source, ..) = split_volume_spec("../p:/workspace");
        assert_eq!(source, "../p");
    }

    #[test]
    fn empty_options_are_dropped_and_unknown_ones_kept() {
        assert_eq!(volume_options("/a:/b:rw,,ro"), vec!["rw", "ro"]);
        assert_eq!(volume_options("/a:/b:,"), Vec::<&str>::new());
        assert_eq!(
            volume_options("/a:/b:rw,rslave,idmap"),
            vec!["rw", "rslave", "idmap"]
        );
    }

    #[test]
    fn np_rejects_only_what_it_cannot_compose_with() {
        assert!(validate_non_persistent_volume("/a:/b:rw,np").is_ok());
        assert!(validate_non_persistent_volume("/a:/b:np").is_ok());
        // No `np` at all: not this function's business.
        assert!(validate_non_persistent_volume("/a:/b:z,U,O").is_ok());

        let err = validate_non_persistent_volume("/a:/b:np,z,U").unwrap_err();
        assert_eq!(err.unsupported, vec!["z", "U"]);
        assert_eq!(
            err.to_string(),
            "volume '/a:/b:np,z,U': the np option cannot be combined with \
             z, U; only rw,np is supported"
        );
    }

    #[test]
    fn repr_switches_quotes_like_python() {
        assert_eq!(py_repr("/a:/b"), "'/a:/b'");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("say \"hi\""), "'say \"hi\"'");
        assert_eq!(py_repr("both ' and \""), "'both \\' and \"'");
        assert_eq!(py_repr("tab\there"), "'tab\\there'");
        assert_eq!(py_repr("a\u{7f}b"), "'a\\x7fb'");
        // The far end of Latin-1's non-printables: NBSP and the soft hyphen.
        assert_eq!(py_repr("a\u{a0}b"), "'a\\xa0b'");
        assert_eq!(py_repr("a\u{ad}b"), "'a\\xadb'");
        // …and the first printable past them stays literal.
        assert_eq!(py_repr("a\u{a1}b"), "'a\u{a1}b'");
    }

    #[test]
    fn tmpfs_target_and_options_split_once() {
        assert_eq!(tmpfs_spec_target("/tmp:rw,size=64M"), "/tmp");
        assert_eq!(tmpfs_spec_target("/tmp"), "/tmp");
        assert_eq!(tmpfs_spec_target("/a:"), "/a");
        // The target keeps its trailing slash; callers normalize.
        assert_eq!(
            tmpfs_spec_target("/workspace/.claude/"),
            "/workspace/.claude/"
        );
        assert_eq!(
            tmpfs_spec_options("/tmp:rw,size=64M"),
            vec!["rw", "size=64M"]
        );
        assert_eq!(tmpfs_spec_options("/tmp"), Vec::<&str>::new());
    }

    #[test]
    fn copyup_needs_an_explicit_and_unambiguous_request() {
        assert!(tmpfs_wants_copyup("/a:rw,tmpcopyup"));
        assert!(!tmpfs_wants_copyup("/a:rw"));
        assert!(!tmpfs_wants_copyup("/a:rw,notmpcopyup"));
        // Both named: the mask comes up empty rather than guessing.
        assert!(!tmpfs_wants_copyup("/a:rw,tmpcopyup,notmpcopyup"));
        assert_eq!(TMPFS_COPYUP_OPTIONS, ["tmpcopyup", "notmpcopyup"]);
    }

    #[test]
    fn enclosing_mount_is_by_component_and_deepest_wins() {
        let mounts = targets(&[
            ("/workspace", "/host/project"),
            ("/workspace/vendor", "/host/vendor"),
            ("/workspace-backup", "/host/backup"),
            ("/", "/host/root"),
        ]);
        let found = enclosing_mount("/workspace/vendor/x", &mounts).unwrap();
        assert_eq!(found.target, "/workspace/vendor");
        assert_eq!(found.source, "/host/vendor");

        // Prefix-but-not-component must not match.
        let found = enclosing_mount("/workspace-backup/x", &mounts).unwrap();
        assert_eq!(found.source, "/host/backup");

        // A mount at `/` never encloses anything.
        assert!(enclosing_mount("/elsewhere", &mounts).is_none());

        // Trailing slashes on the mount target are trimmed…
        let slashed = targets(&[("/workspace/", "/host/project")]);
        assert_eq!(
            enclosing_mount("/workspace/.git", &slashed).unwrap().target,
            "/workspace"
        );
        // …and on the queried target they are tolerated.
        assert_eq!(
            enclosing_mount("/workspace/.git/", &slashed)
                .unwrap()
                .target,
            "/workspace"
        );
    }

    #[test]
    fn duplicate_mount_targets_resolve_last_wins() {
        let mounts = targets(&[("/w", "/host/a"), ("/w", "/host/b")]);
        assert_eq!(enclosing_mount("/w/x", &mounts).unwrap().source, "/host/b");
    }

    #[test]
    fn mask_dirs_are_deepest_first_and_deduplicated() {
        let mounts = targets(&[("/workspace", "/host/project")]);
        let dirs = mask_mountpoint_dirs(
            &specs(&[
                "/workspace/.git/hooks:rw,noexec",
                "/workspace/.claude/:rw",
                "/workspace/.git/info:rw",
            ]),
            &mounts,
        );
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].host_source, "/host/project");
        assert_eq!(
            dirs[0].dirs,
            vec![
                "/host/project/.git/hooks",
                "/host/project/.git/info",
                "/host/project/.git",
                "/host/project/.claude",
            ]
        );
    }

    #[test]
    fn a_mask_that_cannot_reach_the_host_is_not_tracked() {
        // Named volume and `np` bind both carry an empty source.
        let mounts = targets(&[("/state", ""), ("/workspace", "")]);
        assert!(
            mask_mountpoint_dirs(&specs(&["/state/x:rw", "/workspace/.git:rw"]), &mounts)
                .is_empty()
        );
        // No enclosing mount at all: the container's own writable layer.
        assert!(mask_mountpoint_dirs(&specs(&["/tmp:rw"]), &[]).is_empty());
        // A mask covering the whole mount creates nothing.
        let bind = targets(&[("/workspace", "/host/project")]);
        assert!(mask_mountpoint_dirs(&specs(&["/workspace/:rw"]), &bind).is_empty());
    }

    /// A named volume nested inside a bind must win the longest-prefix match,
    /// so the mask under it is attributed to the volume and skipped.
    #[test]
    fn a_nested_named_volume_shadows_the_bind_it_sits_in() {
        let mounts = targets(&[
            ("/workspace", "/host/project"),
            ("/workspace/node_modules", ""),
        ]);
        assert!(
            mask_mountpoint_dirs(&specs(&["/workspace/node_modules/.bin:rw"]), &mounts).is_empty()
        );
    }

    #[test]
    fn copyup_entries_resolve_to_host_paths_only_when_seedable() {
        let mounts = targets(&[("/workspace", "/host/project"), ("/state", "")]);
        let entries = mask_copyup_entries(
            &specs(&[
                "/workspace/.claude/:rw,tmpcopyup",
                "/state/x:rw,tmpcopyup",
                "/tmp:rw,tmpcopyup",
                "/workspace/.git/hooks:rw,notmpcopyup",
            ]),
            &mounts,
        );
        assert_eq!(
            entries,
            vec![
                MaskCopyupEntry {
                    container_target: "/workspace/.claude".into(),
                    host_source: "/host/project/.claude".into(),
                    host_root: "/host/project".into(),
                },
                // Enclosed but unseedable: the runtime must do the copy-up.
                MaskCopyupEntry {
                    container_target: "/state/x".into(),
                    host_source: String::new(),
                    host_root: String::new(),
                },
            ]
        );
    }

    #[test]
    fn a_dotdot_tail_never_becomes_a_host_path() {
        let mounts = targets(&[("/workspace", "/host/project")]);
        // Copy-up normalizes first, so this lands *outside* the bind and
        // finds no enclosing mount at all.
        assert!(
            mask_copyup_entries(&specs(&["/workspace/../etc:rw,tmpcopyup"]), &mounts).is_empty()
        );
        // The mountpoint bookkeeping does not normalize — it matches
        // `/workspace` on the raw text and then refuses the `..` tail, which
        // reaches the same answer by the other route.
        assert!(mask_mountpoint_dirs(&specs(&["/workspace/../etc:rw"]), &mounts).is_empty());
    }

    #[test]
    fn normpath_matches_posixpath() {
        assert_eq!(normpath("/a/b/../c"), "/a/c");
        assert_eq!(normpath("/a//b"), "/a/b");
        assert_eq!(normpath("/a/./b"), "/a/b");
        assert_eq!(normpath("//a/b"), "//a/b");
        assert_eq!(normpath("///a/b"), "/a/b");
        assert_eq!(normpath("/.."), "/");
        assert_eq!(normpath("/../a"), "/a");
        assert_eq!(normpath("a/../.."), "..");
        assert_eq!(normpath(""), ".");
    }

    #[test]
    fn join_does_not_double_a_separator() {
        assert_eq!(join_host_path("/host/", &["a", "b"]), "/host/a/b");
        assert_eq!(join_host_path("/host", &["a", "b"]), "/host/a/b");
        assert_eq!(join_host_path("", &["a"]), "a");
    }

    /// A bind source with a trailing slash reaches the derived host paths
    /// unchanged apart from the separator — the corpus has no such case, so
    /// this is where that behaviour is pinned.
    #[test]
    fn a_trailing_slash_on_the_bind_source_does_not_double() {
        let mounts = targets(&[("/workspace", "/host/project/")]);
        let dirs = mask_mountpoint_dirs(&specs(&["/workspace/.git/hooks:rw"]), &mounts);
        assert_eq!(
            dirs[0].dirs,
            vec!["/host/project/.git/hooks", "/host/project/.git"]
        );
    }
}
