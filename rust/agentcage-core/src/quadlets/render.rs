//! `quadlets.generate_quadlets` — the five unit files a cage deploys.
//!
//! The Python function is one 600-line body that interleaves filesystem
//! probing with context building. This keeps the same order of
//! operations, because the order is observable: warnings are emitted as
//! the volume loop walks, and the corpus records them in that order.

use std::collections::BTreeSet;

use indexmap::IndexMap;
use serde::Serialize;

use crate::config::{Config, ConfigError};
use crate::python::repr_str;
use crate::quadlets::{
    CageNetworkAddrs, b64, cage_network_addrs, effective_port_policy, passthrough_regex, templates,
    vm_local_cage_env_dir, vm_local_dns_allowlist_path, vm_local_grants_dir,
    vm_local_placeholders_env_path, vm_local_proxy_config_path,
};
use crate::volume_mounts::{
    self, MountTarget, TMPFS_COPYUP_OPTIONS, enclosing_mount, is_non_persistent_volume,
    mask_copyup_entries, mask_mountpoint_dirs, split_volume_spec, tmpfs_spec_options,
    tmpfs_spec_target, validate_non_persistent_volume, volume_options,
};

/// `/tmp` semantics: writable by every uid in the cage, sticky so one
/// uid cannot delete another's entries. Applied only to tmpfs entries
/// that mask a path inside another mount — see [`apply_tmpfs_mask_options`].
const TMPFS_MASK_MODE: &str = "mode=1777";

/// Copy-up default for a mask that declares neither `tmpcopyup` nor
/// `notmpcopyup` (#328).
///
/// Podman appends `tmpcopyup` to every tmpfs in that position
/// (`pkg/util/mountOpts.go`), so a mask silently came up holding the
/// very host content it was added to hide, while apple-container — whose
/// `--tmpfs` has no option channel — came up empty. Pinning the default
/// here makes "unspecified" mean the same thing on both backends and
/// matches what a mask is for: an operator who overlays a bind wants
/// that path hidden, and copy-up under the masks' `noexec` only delivers
/// files the cage can look at but never run. Opt in per entry with
/// `tmpcopyup` (the `.claude/` mask does).
const TMPFS_MASK_NO_COPYUP: &str = "notmpcopyup";

/// uid:gid the copied-up mask content is handed to when `container.user`
/// does not name a numeric one.
///
/// Matches the uid every first-party scaffold image gives its workload
/// user, the uid apple-container's cage-init hands its seeded copies
/// (`data/apple-container/cage-init.sh` stage C'), and the uid
/// interactive `cage exec` / `cage shell` sessions are pinned to
/// regardless of `container.user`.
const MASK_COPYUP_DEFAULT_OWNER: &str = "1000:1000";

/// The capability set inner rootless podman needs.
///
/// `SYS_ADMIN` for namespaces, `SYS_CHROOT` for the tar applier,
/// `CHOWN`/`FOWNER`/`DAC_OVERRIDE` for file ops, `SETUID`/`SETGID` for
/// user mapping, `MKNOD` for device nodes, and so on.
const NESTED_CAPABILITIES: [&str; 16] = [
    "SYS_ADMIN",
    "SYS_CHROOT",
    "MKNOD",
    "SETUID",
    "SETGID",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "NET_ADMIN",
    "NET_BIND_SERVICE",
    "NET_RAW",
    "SETFCAP",
    "SETPCAP",
    "AUDIT_WRITE",
];

/// The questions the renderer has to ask the machine it runs on.
///
/// `agentcage-core` performs no I/O (see the crate docs), but
/// `generate_quadlets` genuinely depends on the filesystem: it expands
/// `~` and `$VAR` in volume sources, refuses one that resolves outside
/// the home directory, skips one that does not exist, and — on the VM
/// backend — *copies* a single-file source into a shared directory. Each
/// of those is a method here, implemented against the real filesystem by
/// `agentcage-cli` and against a temporary tree by the golden-corpus
/// test.
///
/// Every method is named after the Python call it replaces, so the two
/// can be read side by side.
pub trait QuadletHost {
    /// `os.environ.get(name)` — used by `expandvars`, and for `HOME`.
    fn env_var(&self, name: &str) -> Option<String>;

    /// `os.path.realpath(path)`.
    ///
    /// Non-strict, like Python's: components that do not exist are kept
    /// rather than erroring, and a relative path resolves against the
    /// process's working directory.
    fn realpath(&self, path: &str) -> String;

    /// `os.path.exists(path)`, following symlinks.
    fn exists(&self, path: &str) -> bool;

    /// `os.path.isdir(path)`, following symlinks.
    fn is_dir(&self, path: &str) -> bool;

    /// `quadlets._stage_vm_file_volume` — copy a single-file volume
    /// source somewhere the VM can see it, and return the staged path.
    ///
    /// Lima's virtiofs shares directories, not single files, so a volume
    /// whose host source is a regular file (a scaffold mounting one
    /// dotfile from the host) cannot be handed to the VM directly. The
    /// implementation copies it into
    /// `~/.local/share/agentcage/<cage>/seed/` — already virtiofs-mounted
    /// — and returns that path for the cage quadlet to bind-mount.
    ///
    /// The copy is one-way: the cage reads and may write the staged
    /// file, but changes are not propagated back to the host original.
    /// Staging runs on every deploy, so the seed tracks the host file
    /// over time.
    ///
    /// Note that the Python spells this directory with a literal
    /// `~/.local/share`, ignoring `XDG_DATA_HOME`, unlike every other
    /// state path. The behaviour belongs to the implementation rather
    /// than to this trait, but a port of it should keep the quirk: a
    /// cage deployed by the Python has its seed there.
    ///
    /// # Errors
    ///
    /// The message to surface when the copy fails.
    fn stage_vm_file_volume(&self, source: &str, deploy_name: &str) -> Result<String, String>;

    /// `secret_resolver.detect_default_scope()` — whether user-scoped
    /// systemd-creds encryption works on this host.
    ///
    /// `Some("user")`, `Some("system")`, or `None` when neither is
    /// usable. Only consulted when `secrets.scope` is `auto` *and* the
    /// cage has at least one `.cred`-backed secret, so a host without
    /// systemd-creds never pays for it.
    fn detect_default_creds_scope(&self) -> Option<String>;

    /// `os.path.expanduser("~")`, before `realpath`.
    ///
    /// The default is `$HOME`; an implementation with access to the
    /// password database can override it, which is what Python falls
    /// back to when `HOME` is unset.
    fn home(&self) -> String {
        self.env_var("HOME").unwrap_or_default()
    }

    /// The home directory of another user, for the `~user` form.
    ///
    /// `None` — the default — leaves `~user/...` unexpanded, which is
    /// what `posixpath.expanduser` does when `getpwnam` raises
    /// `KeyError`. An implementation that can read the password database
    /// should.
    fn user_home(&self, _user: &str) -> Option<String> {
        None
    }
}

/// Where a deployment's files live on disk.
///
/// `state.py` composes these from `XDG_CONFIG_HOME` / `XDG_DATA_HOME`
/// once at import time and the renderer calls the resulting helpers.
/// Porting `state.py` is Track D's; this is the slice of it
/// `generate_quadlets` reads, passed in rather than recomputed so there
/// is one definition of the layout when that PR lands.
#[derive(Clone, Debug)]
pub struct StatePaths {
    /// `$XDG_CONFIG_HOME/agentcage`, absolute.
    pub config_root: String,
    /// `$XDG_DATA_HOME/agentcage`, absolute.
    pub data_root: String,
}

impl StatePaths {
    /// `state.deployment_dir(name)`.
    #[must_use]
    pub fn deployment_dir(&self, name: &str) -> String {
        format!("{}/cages/{name}", self.config_root)
    }

    /// Where `agentcage secret set` leaves systemd-creds blobs.
    #[must_use]
    pub fn creds_dir(&self, name: &str) -> String {
        format!("{}/creds", self.deployment_dir(name))
    }

    /// `state.cage_env_dir(name)`.
    #[must_use]
    pub fn cage_env_dir(&self, name: &str) -> String {
        format!("{}/cage-env", self.deployment_dir(name))
    }

    /// `state.placeholders_env_path(name)`.
    #[must_use]
    pub fn placeholders_env_path(&self, name: &str) -> String {
        format!("{}/placeholders.env", self.cage_env_dir(name))
    }

    /// `state.dns_allowlist_path(name)`.
    #[must_use]
    pub fn dns_allowlist_path(&self, name: &str) -> String {
        format!("{}/dns-allowlist.conf", self.deployment_dir(name))
    }

    /// `state.capture_dir(name)`. Path only — the Python helper also
    /// creates it, and the deploy path still has to.
    #[must_use]
    pub fn capture_dir(&self, name: &str) -> String {
        format!("{}/{name}/capture", self.data_root)
    }

    /// `state.grants_dir(name)`. Path only, as above.
    #[must_use]
    pub fn grants_dir(&self, name: &str) -> String {
        format!("{}/{name}/grants", self.data_root)
    }
}

/// Everything `generate_quadlets` takes besides the config itself.
#[derive(Clone, Copy, Debug)]
pub struct GenerateOptions<'a> {
    /// Absolute host path to the stored `cage.yaml`, for the egress
    /// `Volume=`.
    pub config_host_path: &'a str,
    /// Absolute host path to the shared `patches/` dir, for the cage
    /// `Volume=`.
    pub patches_host_dir: &'a str,
    /// Deployment name for secret prefixing. When set, podman secret
    /// references become `{deploy_name}.{key}` with `target={key}` so
    /// the container still sees the original env name.
    pub deploy_name: &'a str,
    /// Whether the units run under a rootless podman.
    pub rootless: bool,
    /// Third octets already taken by other deployed cages, or `None` to
    /// skip collision resolution. `collect_used_octets` builds it; it
    /// reads deployment metadata, so it is Track D's, not this module's.
    pub used_octets: Option<&'a BTreeSet<u32>>,
    /// Pins the cage to a specific `10.89.<octet>.0/24` subnet,
    /// bypassing hash-based allocation. Used by `cage update` to
    /// preserve the already-allocated subnet of an existing cage — the
    /// podman network is created once at cage-create time and
    /// re-deriving a different octet on update would generate quadlets
    /// whose static IPs don't fall in the existing `<name>-net` subnet.
    pub network_octet: Option<u32>,
    /// Env-name set (deploy prefix stripped) of secrets currently
    /// present in the podman secret store, or `None` when the store
    /// cannot be queried (e.g. VM backend with the guest stopped).
    ///
    /// When a set is given, `Secret=` emission becomes *store-aware*
    /// (issue #262): a store-backed reference whose entry is absent —
    /// and that will not be materialized before container start by a
    /// decrypt `ExecStartPre` (present `.cred` blob, including
    /// `systemd-creds:` sources) or by the start path's
    /// `resolve_and_populate` (`env:` / `cmd:` source) — is skipped
    /// instead of rendered as an unresolvable directive that fails the
    /// next boot with `start-limit-hit`. `None` keeps the legacy
    /// emit-everything behaviour.
    pub store_secrets: Option<&'a BTreeSet<String>>,
    /// The state directory layout.
    pub state: &'a StatePaths,
    /// The version to stamp into the units, and the egress image tag.
    ///
    /// `importlib.metadata.version("agentcage")` in Python; the binary's
    /// own [`VERSION`](crate::VERSION) in the port, except in the golden
    /// corpus, which pins it so a release does not churn the fixtures.
    pub version: &'a str,
}

/// What a render produced.
#[derive(Clone, Debug, Default)]
pub struct Quadlets {
    /// `{filename: content}`, in the order the Python dict built them:
    /// network, the two cert volumes, the egress container, the
    /// nested-podman volume when there is one, and the cage container.
    pub files: IndexMap<String, String>,
    /// What the Python wrote to stderr with `click.echo(..., err=True)`.
    ///
    /// Returned rather than printed: `agentcage-core` has no stdout.
    /// The corpus records these in `render-warnings.txt`, one per line
    /// including the trailing newline, so a caller that prints them
    /// verbatim reproduces the Python's stderr.
    pub warnings: Vec<String>,
}

/// One inbound port forward, as the egress template consumes it.
#[derive(Debug, Serialize)]
struct InboundForward {
    host_bind: String,
    host_port: String,
    container_port: String,
    publish_spec: String,
}

/// One `np` single-file bind's runtime copy.
#[derive(Debug, Serialize)]
struct FileCopy {
    src: String,
    dst: String,
    dir: String,
}

/// One bind root's tmpfs-mask mount-point bookkeeping (#320).
#[derive(Debug, Serialize)]
struct MaskMountpoint {
    root_b64: String,
    state_dir: String,
    state_file: String,
    dirs_b64: String,
}

/// One copy-up mask to hand to the cage user after start (#328).
#[derive(Debug, Serialize)]
struct CopyupMask {
    target_b64: String,
}

/// The context `network.j2` and `volume.j2` take.
#[derive(Debug, Serialize)]
struct VolumeContext<'a> {
    volume_name: &'a str,
}

/// The context `network.j2` takes: the cage name plus its addresses.
#[derive(Debug, Serialize)]
struct NetworkContext<'a> {
    name: &'a str,
    #[serde(flatten)]
    addrs: &'a CageNetworkAddrs,
}

/// The context `egress.container.j2` takes.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the fields are the template's variables, one per `{% if %}` \
              it tests; collapsing them into enums would move the naming \
              away from the thing being rendered"
)]
#[derive(Debug, Serialize)]
struct EgressContext<'a> {
    name: &'a str,
    #[serde(flatten)]
    addrs: &'a CageNetworkAddrs,
    agentcage_version: &'a str,
    patches_host_dir: &'a str,
    config_host_path: &'a str,
    dns_allowlist_enabled: bool,
    dns_allowlist_host_path: &'a str,
    proxy_secrets: &'a [String],
    deploy_name: &'a str,
    creds_secrets: &'a [String],
    creds_dir: &'a str,
    creds_scope_flag: &'a str,
    log_dns_queries: bool,
    log_proxy_connections: bool,
    dns_servers: &'a [String],
    inbound_forwards: &'a [InboundForward],
    capture_enabled: bool,
    capture_host_dir: &'a str,
    agents_volume_enabled: bool,
    grants_host_dir: &'a str,
    passthrough_regex: &'a str,
    rootless: bool,
    inspected_tcp_ports: &'a [i64],
    passthrough_tcp_ports: &'a [i64],
    allow_udp_ports: &'a [i64],
    allow_icmp: bool,
}

/// The context `cage.container.j2` takes.
#[expect(
    clippy::struct_excessive_bools,
    reason = "see `EgressContext`: these are template variables, not state"
)]
#[derive(Debug, Serialize)]
struct CageContext<'a> {
    name: &'a str,
    #[serde(flatten)]
    addrs: &'a CageNetworkAddrs,
    image: &'a str,
    agentcage_version: &'a str,
    patches_host_dir: &'a str,
    volumes: &'a [String],
    named_volumes: &'a IndexMap<String, String>,
    tmpfs: &'a [String],
    copyup_masks: &'a [CopyupMask],
    copyup_owner: &'a str,
    non_persistent_runtime_root: &'a str,
    non_persistent_precreate_dirs: &'a [String],
    non_persistent_file_copies: &'a [FileCopy],
    mask_mountpoints: &'a [MaskMountpoint],
    podman_secrets: &'a [String],
    placeholders_env_path: &'a str,
    cage_env_dir: &'a str,
    env: &'a IndexMap<String, String>,
    userns: &'a str,
    user: &'a str,
    read_only: bool,
    security_label_disable: bool,
    no_new_privileges: bool,
    drop_capabilities: &'a [String],
    add_capabilities: &'a [String],
    memory: &'a str,
    cpus: &'a str,
    command: &'a [String],
    restart: &'a str,
    restart_sec: i64,
    timeout_start_sec: i64,
    timeout_stop_sec: i64,
    deploy_name: &'a str,
    nested_containers: bool,
    lifecycle: &'a str,
}

/// Return `{filename: content}` for all five quadlet files.
///
/// # Errors
///
/// [`ConfigError::Value`] for the operator-facing refusals the Python
/// raises as `ValueError`: a volume host path that resolves outside the
/// home directory, an `np` option that cannot compose, and a published
/// port that collides with mitmproxy's own 8080/8443.
/// [`ConfigError::Runtime`] when every cage subnet is taken, when the VM
/// file staging fails, or when a template fails to render — the last of
/// which is a bug in this crate rather than in the operator's config.
#[expect(
    clippy::too_many_lines,
    reason = "one body, because the order of its steps is observable: the \
              volume loop's warnings are recorded in emission order and \
              later steps read the mount table it builds. Splitting it \
              would mean threading a dozen intermediate values through \
              helpers that have no meaning apart from this sequence."
)]
pub fn generate_quadlets(
    config: &Config,
    options: &GenerateOptions<'_>,
    host: &dyn QuadletHost,
) -> Result<Quadlets, ConfigError> {
    let name = config.name.as_str();
    let cc = &config.container;
    // `deploy_name or name` — the Python's fallback, spelled once.
    let deploy = if options.deploy_name.is_empty() {
        name
    } else {
        options.deploy_name
    };
    let mut out = Quadlets::default();

    // Expand ~ and env vars in volume paths and env values. The inline
    // `np` option marks one bind non-persistent: it uses Podman's
    // overlay bind with explicit %t-backed upper/work dirs, so cage
    // writes never reach the host.
    let mut expanded_volumes: Vec<String> = Vec::new();
    let mut non_persistent_precreate_dirs: Vec<String> = Vec::new();
    let mut non_persistent_file_copies: Vec<FileCopy> = Vec::new();
    // (container_target, host_source) for every mount emitted below,
    // with an empty source for mounts that do not write through to the
    // host. Feeds the tmpfs-mask mount-point bookkeeping (#320) after
    // the loop.
    let mut mount_targets: Vec<MountTarget> = cc
        .named_volumes
        .values()
        .map(|mount| MountTarget::new(mount.split_once(':').map_or(&**mount, |(t, _)| t), ""))
        .collect();
    let home = host.realpath(&expanduser("~", host));

    for volume in &cc.volumes {
        // Split inline options first: `np` is agentcage-only and must
        // not reach podman. All other mount options are preserved.
        validate_non_persistent_volume(volume).map_err(ConfigError::value)?;
        let (source, target, _raw_options) = split_volume_spec(volume);
        let is_np = is_non_persistent_volume(volume);
        let kept_options: Vec<&str> = volume_options(volume)
            .into_iter()
            .filter(|o| *o != "np")
            .collect();
        let source = expandvars(&expanduser(source, host), host);
        let mut expanded = format!("{source}:{target}");
        if !kept_options.is_empty() {
            expanded.push(':');
            expanded.push_str(&kept_options.join(","));
        }
        let host_path = source;

        // Skip a volume whose ${VAR} did not expand — it cannot be
        // mounted.
        if host_path.contains('$') {
            out.warnings.push(format!(
                "warning: skipping volume {} (unresolved variable)",
                repr_str(&host_path)
            ));
            continue;
        }

        // Validate host path portion (before first ':') resolves safely
        let real = host.realpath(&host_path);
        if !(real.starts_with(&format!("{home}/")) || real == home) {
            return Err(ConfigError::value(format!(
                "volume host path {} resolves to {} which is outside the home directory ({})",
                repr_str(&host_path),
                repr_str(&real),
                repr_str(&home)
            )));
        }

        // Skip optional mounts whose host source does not exist. podman
        // cannot bind-mount a missing path — the container fails to
        // start with `statfs ...: no such file or directory` — and on
        // the VM backend the path is not mounted into the VM either.
        if !host.exists(&real) {
            // Name np explicitly: for an np bind the consequence is not
            // just a missing mount but a silently unmet isolation
            // expectation, which a generic warning makes easy to
            // overlook (e.g. a typo'd source).
            let detail = if is_np {
                "host path does not exist; the np bind is not mounted at all"
            } else {
                "host path does not exist"
            };
            out.warnings.push(format!(
                "warning: skipping volume {} ({detail})",
                repr_str(&host_path)
            ));
            continue;
        }

        // VM backend: Lima's virtiofs shares directories, not single
        // files, so a file-source volume (a scaffold mounting a single
        // host dotfile) cannot be mounted into the VM directly. Stage a
        // copy into the cage's data dir — which is virtiofs-mounted —
        // and bind-mount the staged path instead. Container mode
        // bind-mounts files directly.
        let real_for_mount = if config.isolation == "vm" && !host.is_dir(&real) {
            let staged = host
                .stage_vm_file_volume(&real, deploy)
                .map_err(ConfigError::runtime)?;
            let container_part = expanded.split_once(':').map_or("", |(_, rest)| rest);
            expanded = format!("{staged}:{container_part}");
            staged
        } else {
            real.clone()
        };

        if is_np && !host.is_dir(&real) {
            let (_source, target, _options) = split_volume_spec(&expanded);
            if target.is_empty() {
                out.warnings.push(format!(
                    "warning: skipping volume {} with the np flag (invalid volume spec)",
                    repr_str(&expanded)
                ));
                continue;
            }
            let target = target.to_owned();
            let copy_id = format!("file-{}", non_persistent_file_copies.len());
            let runtime_file = format!(
                "%t/agentcage/{deploy}/mounts/{copy_id}/{}",
                basename(&real_for_mount)
            );
            expanded_volumes.push(format!("{runtime_file}:{target}:rw"));
            mount_targets.push(MountTarget::new(target, ""));
            non_persistent_file_copies.push(FileCopy {
                src: shlex_quote(&real_for_mount),
                dst: shlex_quote(&runtime_file),
                dir: shlex_quote(dirname(&runtime_file)),
            });
            continue;
        }

        if is_np {
            let index = non_persistent_precreate_dirs.len() / 2;
            let Some(overlay) = non_persistent_overlay_mount(&expanded, deploy, index) else {
                out.warnings.push(format!(
                    "warning: skipping volume {} with the np flag (invalid volume spec)",
                    repr_str(&expanded)
                ));
                continue;
            };
            mount_targets.push(MountTarget::new(split_volume_spec(&overlay.volume).1, ""));
            expanded_volumes.push(overlay.volume);
            non_persistent_precreate_dirs.push(shlex_quote(&overlay.upperdir));
            non_persistent_precreate_dirs.push(shlex_quote(&overlay.workdir));
            continue;
        }

        let (bind_source, bind_target, _bind_options) = split_volume_spec(&expanded);
        mount_targets.push(MountTarget::new(bind_target, bind_source));
        expanded_volumes.push(expanded);
    }

    let non_persistent_runtime_root =
        if non_persistent_precreate_dirs.is_empty() && non_persistent_file_copies.is_empty() {
            String::new()
        } else {
            shlex_quote(&format!("%t/agentcage/{deploy}/mounts"))
        };

    // tmpfs masks whose target sits under a host bind-mount make the OCI
    // runtime create the mount point on the HOST side of the bind,
    // littering the operator's project dir with e.g. an empty
    // `.git/hooks/` (#320). One ExecStartPre/ExecStopPost pair per bind
    // root records which of those paths were absent right before start
    // and removes exactly those, still only while empty, on teardown.
    // Grouping by root lets the teardown line bake its own containment
    // root, so a removal can never step outside the bind-mounted project
    // directory.
    let mask_state_dir = format!("%t/agentcage/{deploy}/masks");
    let mut mask_groups = mask_mountpoint_dirs(&cc.tmpfs, &mount_targets);
    // `sorted(dict.items())` — by host source, the dict's key.
    mask_groups.sort_by(|a, b| a.host_source.cmp(&b.host_source));
    let mut mask_mountpoints: Vec<MaskMountpoint> = Vec::new();
    for (index, group) in mask_groups.iter().enumerate() {
        // Host paths reach the unit base64-encoded. A systemd Exec line
        // is word-split with its own quoting rules *before* /bin/bash
        // ever sees it, so there is no single escaping that survives
        // both layers for an arbitrary project path (a plain `~/My
        // Project` already needs a quote that would terminate the
        // systemd-level quoting early). Base64's alphabet is inert to
        // systemd (no `%`, `$`, quote or backslash) and to the shell, so
        // the decode happens inside bash where normal newline-delimited
        // `read -r` handles spaces and quotes correctly.
        let has_newline = std::iter::once(&group.host_source)
            .chain(group.dirs.iter())
            .any(|path| path.contains('\n') || path.contains('\r'));
        if has_newline {
            out.warnings.push(format!(
                "warning: skipping tmpfs mask cleanup for {} (path contains a newline)",
                repr_str(&group.host_source)
            ));
            continue;
        }
        let mut dirs_text = String::new();
        for dir in &group.dirs {
            // Trailing newline: `read` returns non-zero at EOF, so an
            // unterminated last line would be dropped by the while loop.
            dirs_text.push_str(dir);
            dirs_text.push('\n');
        }
        mask_mountpoints.push(MaskMountpoint {
            root_b64: b64(&group.host_source),
            state_dir: shlex_quote(&mask_state_dir),
            state_file: shlex_quote(&format!("{mask_state_dir}/root-{index}")),
            dirs_b64: b64(&dirs_text),
        });
    }

    let expanded_env: IndexMap<String, String> = cc
        .env
        .iter()
        .map(|(key, value)| (key.clone(), expandvars(value, host)))
        .collect();

    // Cage placeholders are delivered via an EnvironmentFile (read by
    // podman at every container creation) instead of baked Environment=
    // lines, so a plain `cage restart` — not just `cage update` — picks
    // up placeholder changes. The file is a cage.yaml-derived sibling of
    // proxy-config.yaml, regenerated by state.save_proxy_config on every
    // deploy/restart path. Rules whose placeholder hasn't been generated
    // yet (config.fill_raw_placeholders runs at declare time) don't
    // count.
    let has_placeholders = config
        .secret_injection
        .iter()
        .any(|rule| !rule.placeholder.is_empty());
    let (placeholders_env_path, cage_env_dir) = if has_placeholders {
        if config.isolation == "vm" {
            // Lima's reverse-sshfs caches host writes; mount the
            // VM-local copy pushed by backends.vm.push_config_files
            // instead.
            (
                vm_local_placeholders_env_path(deploy),
                vm_local_cage_env_dir(deploy),
            )
        } else {
            (
                options.state.placeholders_env_path(deploy),
                options.state.cage_env_dir(deploy),
            )
        }
    } else {
        (String::new(), String::new())
    };

    // Proxy secrets: split by backend for quadlet generation.
    // A rule gets a decrypt ExecStartPre if:
    //   (a) its source scheme is "systemd-creds:" (explicit opt-in), OR
    //   (b) a .cred file exists in the state dir (auto-encrypted via
    //       `agentcage secret set` on a systemd-creds default host).
    // Either way the rule still needs the podman Secret= directive — the
    // ExecStartPre decrypts the blob and populates the podman store
    // before the proxy container starts.
    let creds_dir = options.state.creds_dir(deploy);
    let has_cred_file = |env_name: &str| host.exists(&format!("{creds_dir}/{env_name}.cred"));
    // True when a `Secret=` reference to `env_name` will resolve at
    // container start (issue #262 store-aware gate). Always true when
    // `store_secrets` is None (store state unknown — keep the legacy
    // behaviour). Otherwise true when the entry is in the store now, or
    // a pre-start channel materializes it: the decrypt ExecStartPre
    // (present `.cred` blob, including `systemd-creds:` sources) or the
    // start path's resolve_and_populate (`env:` / `cmd:` source).
    let boot_resolvable = |env_name: &str, scheme: &str, cred_file: bool| -> bool {
        let Some(store) = options.store_secrets else {
            return true;
        };
        cred_file || scheme == "env" || scheme == "cmd" || store.contains(env_name)
    };

    let mut proxy_secrets: Vec<String> = Vec::new();
    let mut creds_secrets: Vec<String> = Vec::new();
    for rule in &config.secret_injection {
        let scheme = partition(&rule.source).0;
        let cred_file = has_cred_file(&rule.env);
        if !boot_resolvable(&rule.env, scheme, cred_file) {
            // `secret rm` removed the store entry but the declared rule
            // stays in cage.yaml — rendering the directive anyway would
            // make the next egress boot fail with an unresolvable
            // `Secret=`. Skip it; the next `secret set` re-converges the
            // units and the line comes back.
            continue;
        }
        if scheme == "systemd-creds" || cred_file {
            creds_secrets.push(rule.env.clone());
        }
        proxy_secrets.push(rule.env.clone());
    }

    // Protocol-relay credentials live in the same podman secret store
    // and need a Secret= directive on the proxy container so the relay
    // can resolve them via env at startup. The CLI parser strips them
    // from the cage's podman_secrets/env so the cage container never
    // sees them; they only land in the proxy. Auto-decrypt the .cred
    // file if systemd-creds is the default backend, mirroring
    // secret_injection above.
    for relay in &config.protocol_relays {
        for source in [&relay.auth.user_source, &relay.auth.password_source] {
            let (scheme, argument) = partition(source);
            if argument.is_empty() || proxy_secrets.iter().any(|s| s == argument) {
                continue;
            }
            let cred_file = has_cred_file(argument);
            if !boot_resolvable(argument, scheme, cred_file) {
                continue;
            }
            if scheme == "systemd-creds" || cred_file {
                creds_secrets.push(argument.to_owned());
            }
            proxy_secrets.push(argument.to_owned());
        }
    }

    // agents.decider's api_key — same shape and same egress-only
    // invariant as a relay credential: it uses a `*_source` scheme
    // (env:/cmd:/systemd-creds:) and must NEVER reach the cage. An
    // egress-only credential (the CLI parser already stripped it from
    // cage env/podman_secrets in config.load_config). Stage it into the
    // proxy's tmpfs secret files so the addon can read the real value
    // when calling the decider. Same relay-auth staging path.
    //
    // The traffic watcher agent's own api_key has an identical
    // egress-only invariant and an identical staging path, and reusing
    // the decider's env var (same NAME) is fine — the dedup check
    // handles it.
    for (enable, api_key) in [
        (
            config.agents.decider.enable,
            &config.agents.decider.llm.api_key,
        ),
        (
            config.agents.watcher.enable,
            &config.agents.watcher.llm.api_key,
        ),
    ] {
        if !enable {
            continue;
        }
        let (scheme, argument) = partition(api_key);
        if argument.is_empty() || proxy_secrets.iter().any(|s| s == argument) {
            continue;
        }
        let cred_file = has_cred_file(argument);
        if !boot_resolvable(argument, scheme, cred_file) {
            continue;
        }
        if scheme == "systemd-creds" || cred_file {
            creds_secrets.push(argument.to_owned());
        }
        proxy_secrets.push(argument.to_owned());
    }

    // Direct podman_secrets on the cage container hit the same boot
    // failure when their store entry was `secret rm`'d — gate them with
    // the same store-aware rule (no source: concept here; a .cred blob
    // is materialized by the egress decrypt ExecStartPre, which runs
    // before the cage starts).
    let cage_podman_secrets: Vec<String> = cc
        .podman_secrets
        .iter()
        .filter(|secret| boot_resolvable(secret, "", has_cred_file(secret)))
        .cloned()
        .collect();

    // Parse ports into structured forwards for proxy reverse mode
    let mut inbound_forwards: Vec<InboundForward> = Vec::new();
    for port_spec in &cc.ports {
        let parts: Vec<&str> = port_spec.split(':').collect();
        let (host_bind, host_port, container_port) = match parts.len() {
            3 => (parts[0], parts[1], parts[2]),
            2 => ("127.0.0.1", parts[0], parts[1]),
            _ => continue,
        };
        if container_port == "8080" {
            return Err(ConfigError::value(format!(
                "container port 8080 conflicts with the mitmproxy forward proxy (port spec: {}). \
                 Use a different container port.",
                repr_str(port_spec)
            )));
        }
        if container_port == "8443" {
            return Err(ConfigError::value(format!(
                "container port 8443 conflicts with the mitmproxy transparent proxy (port spec: \
                 {}). Use a different container port.",
                repr_str(port_spec)
            )));
        }
        inbound_forwards.push(InboundForward {
            host_bind: host_bind.to_owned(),
            host_port: host_port.to_owned(),
            container_port: container_port.to_owned(),
            publish_spec: format!("{host_bind}:{host_port}:{container_port}"),
        });
    }

    let addrs = cage_network_addrs(name, options.used_octets, options.network_octet)?;

    // Network
    out.files.insert(
        format!("{name}-net.network"),
        render(
            "network.j2",
            &NetworkContext {
                name,
                addrs: &addrs,
            },
        )?,
    );

    // Volumes
    //
    // Two cert volumes, not one:
    //   * agentcage-certs-<name>        — mitmproxy state dir (private
    //     key, .p12 bundles, public cert). Mounted RW into the egress
    //     only.
    //   * agentcage-public-certs-<name> — published public cert only.
    //     Mounted RW into the egress (so supervisor-egress.sh Step E can
    //     install the cert there) and RO into the cage at /certs.
    //
    // The cage MUST NOT see the private-key volume. CTF findings F6
    // (container) and F9 (vm) on agentcage 0.22.0 flagged the prior
    // single-volume layout as a defense-in-depth violation: a uid/perm
    // regression would let the cage mint trusted certs for any
    // allowlisted host.
    out.files.insert(
        format!("{name}-certs.volume"),
        render(
            "volume.j2",
            &VolumeContext {
                volume_name: &format!("agentcage-certs-{name}"),
            },
        )?,
    );
    out.files.insert(
        format!("{name}-public-certs.volume"),
        render(
            "volume.j2",
            &VolumeContext {
                volume_name: &format!("agentcage-public-certs-{name}"),
            },
        )?,
    );

    // DNS allowlist sidecar file path — bind-mounted into the egress
    // container at /etc/agentcage/dns-allowlist.conf. The quadlet only
    // encodes whether allowlist mode is on; the contents change without
    // touching the systemd unit.
    //
    // VM backend: the bind mount source is a VM-local path, NOT the host
    // path under ~/.config/agentcage. Lima's reverse-sshfs mount caches
    // host writes, so a host-side rewrite of dns-allowlist.conf would
    // not propagate into the egress container; the VM-local copy is
    // rewritten by `_update_dns_quadlet` via `inst.exec` and dnsmasq
    // SIGHUPs to pick it up.
    let dns_allowlist_path = if config.isolation == "vm" {
        vm_local_dns_allowlist_path(deploy)
    } else {
        options.state.dns_allowlist_path(deploy)
    };

    // Capture volume — host path for capture JSONL
    let capture_enabled = config.capture.enable_har;
    let capture_host_dir = if capture_enabled {
        options.state.capture_dir(deploy)
    } else {
        String::new()
    };

    // Resolve secrets.scope (auto/user/system) into the concrete flag
    // passed to systemd-creds decrypt in the egress quadlet's
    // ExecStartPre. The quadlet runs under `systemctl --user`, so --user
    // picks the per-user decryption key — no polkit prompt at start
    // time.
    let mut creds_scope_flag = "";
    if !creds_secrets.is_empty() {
        // `resolve_scope` raises on an unusable host and the Python
        // swallows that into "system".
        let scope = resolve_scope(&config.secrets.scope, host).unwrap_or_else(|| "system".into());
        if scope == "user" {
            creds_scope_flag = "--user ";
        }
    }

    // VM backend: rewrite proxy-config.yaml mount source to a VM-local
    // path for the same reason as dns-allowlist.conf above — Lima's
    // reverse-sshfs caching would otherwise hide host-side rewrites from
    // mitmproxy's mtime-poll hot-reload.
    let (proxy_config_path, grants_dir) = if config.isolation == "vm" {
        // Grants overlay: VM-local too. The addon writes it in-guest
        // (atomic rename, no sshfs cache) and the reconcile round-trips
        // it via limactl (backends.vm.pull_grants/push_grants).
        (
            vm_local_proxy_config_path(deploy),
            vm_local_grants_dir(deploy),
        )
    } else {
        (
            options.config_host_path.to_owned(),
            // Note `name`, not `deploy`: the Python reads
            // `state.grants_dir(name)` here while every sibling path in
            // this function uses `deploy_name or name`. The two differ
            // only when a cage is deployed under another name, and the
            // host-side grants watcher resolves the same way, so the
            // inconsistency is harmless — but it is load-bearing for
            // byte-equality and must not be "fixed" in isolation.
            options.state.grants_dir(name),
        )
    };

    let port_policy = effective_port_policy(config);
    out.files.insert(
        format!("{name}-egress.container"),
        render(
            "egress.container.j2",
            &EgressContext {
                name,
                addrs: &addrs,
                agentcage_version: options.version,
                patches_host_dir: options.patches_host_dir,
                config_host_path: &proxy_config_path,
                dns_allowlist_enabled: config.domains.mode == "allowlist",
                dns_allowlist_host_path: &dns_allowlist_path,
                proxy_secrets: &proxy_secrets,
                deploy_name: options.deploy_name,
                creds_secrets: &creds_secrets,
                creds_dir: &creds_dir,
                creds_scope_flag,
                log_dns_queries: config.logging.dns_queries,
                log_proxy_connections: config.logging.proxy_connections,
                dns_servers: &config.dns_servers,
                inbound_forwards: &inbound_forwards,
                capture_enabled,
                capture_host_dir: &capture_host_dir,
                // Grants-overlay volume gate: mounted when an agent is
                // on (the decider writes decided grants, the watcher
                // writes findings/state and revokes through it) OR an
                // allow entry has an expiry (the addon sweeps those and
                // re-publishes the DNS zone list).
                agents_volume_enabled: config.agents.decider.enable
                    || config.agents.watcher.enable
                    || !config.domains.expires.is_empty(),
                grants_host_dir: &grants_dir,
                passthrough_regex: &passthrough_regex(&config.domains.passthrough),
                rootless: options.rootless,
                inspected_tcp_ports: &port_policy.inspected_tcp,
                passthrough_tcp_ports: &port_policy.passthrough_tcp,
                allow_udp_ports: &port_policy.allow_udp,
                allow_icmp: config.ports.icmp.allow,
            },
        )?,
    );

    // Nested containers support
    let nested_containers = cc.nested_containers;
    let mut cage_drop_caps = cc.drop_capabilities.clone();
    let mut cage_add_caps = cc.add_capabilities.clone();
    let mut cage_no_new_privs = cc.no_new_privileges;
    let mut cage_user = cc.user.clone();
    if nested_containers {
        cage_drop_caps = Vec::new();
        for capability in NESTED_CAPABILITIES {
            if !cage_add_caps.iter().any(|c| c == capability) {
                cage_add_caps.push(capability.to_owned());
            }
        }
        cage_no_new_privs = false;
        // Run as root inside the user namespace so setuid helpers
        // (newuidmap/newgidmap) work for inner rootless podman.
        "0".clone_into(&mut cage_user);
        // Storage volume for inner podman state
        out.files.insert(
            format!("{name}-podman-storage.volume"),
            render(
                "volume.j2",
                &VolumeContext {
                    volume_name: &format!("agentcage-podman-{name}"),
                },
            )?,
        );
    }

    // Map lifecycle to systemd restart policy
    let lifecycle = config.lifecycle.as_str();
    let restart = if lifecycle == "interactive" || lifecycle == "ephemeral" {
        "no"
    } else {
        cc.restart.as_str()
    };

    // tmpfs masks that opted into copy-up (#328). Podman hands the
    // option to the OCI runtime verbatim, so the content is already in
    // place when the workload starts — but it is owned by the userns
    // root the runtime copied it as, which the cage's non-root uid can
    // neither modify nor delete. A post-start chown inside the
    // container's namespaces repairs exactly that; see the ExecStartPost
    // in cage.container.j2 for why it cannot run earlier (ExecStartPre
    // precedes the container, so the tmpfs does not exist yet).
    let cage_tmpfs = apply_tmpfs_mask_options(&cc.tmpfs, &mount_targets);
    let copyup_owner = mask_copyup_owner(&cage_user);
    let mut copyup_masks: Vec<CopyupMask> = Vec::new();
    if !copyup_owner.is_empty() {
        for entry in mask_copyup_entries(&cage_tmpfs, &mount_targets) {
            // Same escaping story as the mask mount-point hooks above: a
            // systemd Exec line applies its own quoting before bash sees
            // it, so the cage path travels base64-encoded and is decoded
            // inside bash where it can be quoted normally.
            copyup_masks.push(CopyupMask {
                target_b64: b64(&entry.container_target),
            });
        }
    }

    // Cage container — no published ports (traffic arrives via proxy
    // reverse mode)
    out.files.insert(
        format!("{name}-cage.container"),
        render(
            "cage.container.j2",
            &CageContext {
                name,
                addrs: &addrs,
                image: &cc.image,
                agentcage_version: options.version,
                patches_host_dir: options.patches_host_dir,
                volumes: &expanded_volumes,
                named_volumes: &cc.named_volumes,
                tmpfs: &cage_tmpfs,
                copyup_masks: &copyup_masks,
                copyup_owner: &copyup_owner,
                non_persistent_runtime_root: &non_persistent_runtime_root,
                non_persistent_precreate_dirs: &non_persistent_precreate_dirs,
                non_persistent_file_copies: &non_persistent_file_copies,
                mask_mountpoints: &mask_mountpoints,
                podman_secrets: &cage_podman_secrets,
                placeholders_env_path: &placeholders_env_path,
                cage_env_dir: &cage_env_dir,
                env: &expanded_env,
                userns: &cc.userns,
                user: &cage_user,
                read_only: cc.read_only,
                security_label_disable: cc.security_label_disable,
                no_new_privileges: cage_no_new_privs,
                drop_capabilities: &cage_drop_caps,
                add_capabilities: &cage_add_caps,
                memory: &cc.memory,
                cpus: &cc.cpus,
                command: &cc.command,
                restart,
                restart_sec: cc.restart_sec,
                timeout_start_sec: cc.timeout_start_sec,
                timeout_stop_sec: cc.timeout_stop_sec,
                deploy_name: options.deploy_name,
                nested_containers,
                lifecycle,
            },
        )?,
    );

    Ok(out)
}

/// Render one template, turning a minijinja failure into an error the
/// CLI can print.
///
/// A failure here is a bug in this crate or in a `.j2` file, not
/// something an operator did, but it must not be a panic: the CLI is the
/// only process the user has.
fn render(template: &str, context: &impl Serialize) -> Result<String, ConfigError> {
    templates::render(template, minijinja::Value::from_serialize(context))
        .map_err(|error| ConfigError::runtime(format!("rendering {template}: {error}")))
}

/// An ephemeral overlay bind, as `_non_persistent_overlay_mount` returns
/// it.
struct OverlayMount {
    /// The `source:target:options` spec for `Volume=`.
    volume: String,
    /// The `%t`-backed overlay upper dir.
    upperdir: String,
    /// The `%t`-backed overlay work dir.
    workdir: String,
}

/// Return the overlay bind for an ephemeral (`np`) volume.
///
/// Podman's `:O` bind option mounts the host source as an overlay
/// lowerdir. Supplying explicit upper/work dirs under `%t` keeps all
/// writes in the user's runtime tmpfs instead of in container storage.
/// The host source is never mounted writable, while the cage still sees
/// a writable target.
///
/// `None` when the spec has no source or no target, which the caller
/// reports as an invalid spec.
fn non_persistent_overlay_mount(spec: &str, name: &str, index: usize) -> Option<OverlayMount> {
    let (source, target, options) = split_volume_spec(spec);
    if source.is_empty() || target.is_empty() {
        return None;
    }
    let mount_id = format!("vol-{index}");
    let upperdir = format!("%t/agentcage/{name}/mounts/{mount_id}/upper");
    let workdir = format!("%t/agentcage/{name}/mounts/{mount_id}/work");
    let mut parts = vec![
        "O".to_owned(),
        format!("upperdir={upperdir}"),
        format!("workdir={workdir}"),
    ];
    parts.extend(
        options
            .split(',')
            .filter(|o| {
                !o.is_empty()
                    && !matches!(*o, "ro" | "rw" | "O" | "np")
                    && !o.starts_with("upperdir=")
                    && !o.starts_with("workdir=")
            })
            .map(str::to_owned),
    );
    Some(OverlayMount {
        volume: format!("{source}:{target}:{}", parts.join(",")),
        upperdir,
        workdir,
    })
}

/// Pin agentcage's mask defaults on tmpfs entries nested inside a mount.
///
/// Neither OCI runtime gives a tmpfs the kernel's default `1777` root
/// mode when the mount spec carries no explicit `mode=`: both copy the
/// mode of the directory the tmpfs is mounted *over* instead — runc in
/// `mountEntry.createOpenMountpoint`, crun in
/// `append_tmpfs_mode_if_missing`. The tmpfs root is then owned by the
/// userns root the runtime mounts as, not by the cage workload's
/// `user:`.
///
/// For a tmpfs that masks a path inside a host bind-mount — the #170
/// `/workspace/.git/hooks/` and #173 `/workspace/.claude/` masks the
/// scaffolds ship — the inherited mode is the **host** directory's,
/// typically `0755`. The mask therefore comes up root-owned and
/// read-only for the uid the cage actually runs as, so a legitimate
/// in-cage write (`git` installing a hook, an agent writing project
/// `.claude` state) fails with EACCES and only `--as-root` can write
/// (#321). Ownership cannot be expressed here — tmpfs `uid=`/`gid=`
/// would have to hardcode the workload uid — but the mode can, and a
/// sticky world-writable root makes the mask usable by any `user:`.
///
/// This does not weaken the mask. The tmpfs stays private to the cage's
/// mount namespace and mounted `rprivate`, so cage writes still never
/// reach the host; the declared `noexec,nosuid,nodev` options are
/// untouched, so nothing planted there is executable; and the sticky bit
/// keeps one in-cage uid from clobbering another's entries.
///
/// The second pin is `notmpcopyup` (#328) — see [`TMPFS_MASK_NO_COPYUP`].
///
/// Only masking entries are rewritten, and each pin only when the
/// operator did not name that option themselves. A tmpfs over an image
/// directory (`/tmp`, `/var/cache`, …) is left entirely alone: its mode
/// and its contents are the image author's intent and are already
/// expressed in the cage's own uid space, so there is nothing to fix.
///
/// `mount_targets` carries `(container_target, host_source)` for every
/// mount the cage quadlet emits. Only the *topology* matters here — a
/// mask inherits the mode and the contents of whatever it covers whether
/// or not that mount reaches the host — so unlike the mount-point
/// bookkeeping this ignores the source.
fn apply_tmpfs_mask_options(tmpfs: &[String], mount_targets: &[MountTarget]) -> Vec<String> {
    let mut rewritten: Vec<String> = Vec::with_capacity(tmpfs.len());
    for spec in tmpfs {
        let target = tmpfs_spec_target(spec);
        let options = tmpfs_spec_options(spec);
        if !target.starts_with('/') {
            rewritten.push(spec.clone());
            continue;
        }
        if enclosing_mount(&volume_mounts::normpath(target), mount_targets).is_none() {
            rewritten.push(spec.clone());
            continue;
        }
        let mut pinned: Vec<String> = options.iter().map(|o| (*o).to_owned()).collect();
        if !options.iter().any(|o| TMPFS_COPYUP_OPTIONS.contains(o)) {
            pinned.push(TMPFS_MASK_NO_COPYUP.to_owned());
        }
        // `mode=` stays LAST: both runtimes prepend the mount point's
        // inherited mode to the mount data and the kernel takes the last
        // `mode=` it parses.
        if !options.iter().any(|o| o.starts_with("mode=")) {
            pinned.push(TMPFS_MASK_MODE.to_owned());
        }
        if pinned.len() == options.len() {
            rewritten.push(spec.clone());
            continue;
        }
        // The operator's literal target is emitted back unchanged; only
        // the comparison above is normalized.
        rewritten.push(format!("{target}:{}", pinned.join(",")));
    }
    rewritten
}

/// Return the `uid:gid` a copy-up mask's contents must be handed to.
///
/// Both OCI runtimes perform `tmpcopyup` as the user-namespace root they
/// mount as, and neither replays the source's ownership onto the copy,
/// so the content lands `0:0` — unwritable and undeletable for the
/// non-root uid the cage actually runs as, even with
/// [`TMPFS_MASK_MODE`]'s sticky world-writable tmpfs root (the sticky
/// bit lets the workload *create* siblings but never modify or remove a
/// root-owned entry). #328 measured exactly that: an agent could read
/// the seeded project `.claude/settings.json` but got `Permission
/// denied` editing its own throwaway copy.
///
/// Returns `""` when no chown is needed or possible: a cage that already
/// runs as uid 0 owns the copy outright (`nested_containers` forces
/// `User=0`), and a `container.user` naming a *name* rather than a uid
/// cannot be resolved host-side — the cage image's `/etc/passwd` is not
/// readable from here.
fn mask_copyup_owner(user: &str) -> String {
    let spec = user.trim();
    if spec.is_empty() {
        // Image default. Every first-party scaffold image puts its
        // workload user at uid 1000 and interactive sessions are pinned
        // there anyway.
        return MASK_COPYUP_DEFAULT_OWNER.to_owned();
    }
    let (uid, gid) = spec.split_once(':').unwrap_or((spec, ""));
    if !is_digits(uid) {
        return String::new();
    }
    if uid.parse::<u64>().is_ok_and(|value| value == 0) {
        return String::new();
    }
    if is_digits(gid) {
        format!("{uid}:{gid}")
    } else {
        format!("{uid}:{uid}")
    }
}

/// Python's `str.isdigit()` for the ASCII case, which is the only one a
/// uid can be — `int()` accepts other Unicode digits, but a uid spelled
/// in Devanagari is not a uid systemd would take either.
fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|c| c.is_ascii_digit())
}

/// `secret_resolver.resolve_scope`, minus the error message.
///
/// The one caller wraps it in `except ValueError: _scope = "system"`, so
/// the distinction between "invalid scope" and "no usable scope" is not
/// observable here; `None` covers both.
fn resolve_scope(configured: &str, host: &dyn QuadletHost) -> Option<String> {
    match configured {
        "user" | "system" => Some(configured.to_owned()),
        "auto" => host.detect_default_creds_scope(),
        _ => None,
    }
}

/// `"scheme:rest".partition(":")` — the head and the tail.
///
/// Python's `partition` returns `(s, "", "")` when the separator is
/// absent, so a bare `NAME` keeps the whole string as the scheme and
/// has an *empty* argument. That emptiness is what the call sites test:
/// a source with no `:` is not a store reference.
fn partition(source: &str) -> (&str, &str) {
    source.split_once(':').unwrap_or((source, ""))
}

/// `os.path.basename` for the POSIX paths this module builds.
fn basename(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |(_, base)| base)
}

/// `os.path.dirname` for the POSIX paths this module builds.
fn dirname(path: &str) -> &str {
    match path.rsplit_once('/') {
        // `posixpath.dirname` keeps a lone root slash.
        Some(("", _)) => "/",
        Some((head, _)) => head,
        None => "",
    }
}

/// `shlex.quote`.
///
/// Returns the text unchanged when every character is in Python's
/// `_find_unsafe` safe set, and otherwise wraps it in single quotes with
/// any embedded `'` spliced out as `'"'"'`.
fn shlex_quote(text: &str) -> String {
    if text.is_empty() {
        return "''".to_owned();
    }
    let safe = text.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-' | '_')
    });
    if safe {
        return text.to_owned();
    }
    format!("'{}'", text.replace('\'', "'\"'\"'"))
}

/// `posixpath.expanduser`.
///
/// `~` and `~/...` use the host's home directory; `~user/...` needs the
/// password database, which [`QuadletHost::user_home`] may or may not
/// provide — when it does not, the path is returned unchanged, exactly
/// as Python does on `KeyError`.
pub fn expanduser(path: &str, host: &dyn QuadletHost) -> String {
    if !path.starts_with('~') {
        return path.to_owned();
    }
    let split = path[1..].find('/').map_or(path.len(), |index| index + 1);
    let user_home = if split == 1 {
        host.home()
    } else {
        match host.user_home(&path[1..split]) {
            Some(home) => home,
            None => return path.to_owned(),
        }
    };
    let joined = format!("{}{}", user_home.trim_end_matches('/'), &path[split..]);
    if joined.is_empty() {
        "/".to_owned()
    } else {
        joined
    }
}

/// `posixpath.expandvars`.
///
/// `$name` and `${name}`, where `name` is `[A-Za-z0-9_]+` (the `\w` in
/// `_varprog` is ASCII-only). An undefined variable is left in place,
/// braces and all — which is exactly what makes the caller's `"$" in
/// host_path` check a reliable "did not expand" test. A substituted
/// value is never rescanned.
pub fn expandvars(path: &str, host: &dyn QuadletHost) -> String {
    if !path.contains('$') {
        return path.to_owned();
    }
    let bytes = path.as_bytes();
    let mut out = String::with_capacity(path.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'$' {
            // Advance one whole character: a multi-byte character can
            // never contain an ASCII `$`, so every `$` this loop stops
            // on is a char boundary, but walking byte by byte would
            // split the ones in between.
            let character = path[index..].chars().next().unwrap_or('\0');
            out.push(character);
            index += character.len_utf8();
            continue;
        }
        let rest = &path[index + 1..];
        let (name, consumed) = if let Some(braced) = rest.strip_prefix('{') {
            // `\{[^}]*\}` — a run without a closing brace is not a match
            // at all, so the `$` is literal.
            let Some(end) = braced.find('}') else {
                out.push('$');
                index += 1;
                continue;
            };
            (&braced[..end], end + 3)
        } else {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            if end == 0 {
                // `$` not followed by a name: `_varprog` does not match,
                // so it stays.
                out.push('$');
                index += 1;
                continue;
            }
            (&rest[..end], end + 1)
        };
        match host.env_var(name) {
            Some(value) => out.push_str(&value),
            // KeyError: the reference is left exactly as written.
            None => out.push_str(&path[index..index + consumed]),
        }
        index += consumed;
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        GenerateOptions, QuadletHost, StatePaths, apply_tmpfs_mask_options, basename, dirname,
        expanduser, expandvars, generate_quadlets, mask_copyup_owner, non_persistent_overlay_mount,
        partition, shlex_quote,
    };
    use crate::volume_mounts::MountTarget;

    struct TestHost;

    impl QuadletHost for TestHost {
        fn env_var(&self, name: &str) -> Option<String> {
            match name {
                "HOME" => Some("/home/tester".to_owned()),
                "SET" => Some("value".to_owned()),
                "EMPTY" => Some(String::new()),
                _ => None,
            }
        }
        fn realpath(&self, path: &str) -> String {
            path.to_owned()
        }
        fn exists(&self, path: &str) -> bool {
            // Everything exists except a systemd-creds blob: the
            // store-aware gate below turns on `.cred` presence, and a
            // host that answered "yes" to every path would open the
            // gate for every secret.
            std::path::Path::new(path)
                .extension()
                .is_none_or(|extension| extension != "cred")
        }
        fn is_dir(&self, _path: &str) -> bool {
            true
        }
        fn stage_vm_file_volume(&self, source: &str, _deploy: &str) -> Result<String, String> {
            Ok(source.to_owned())
        }
        fn detect_default_creds_scope(&self) -> Option<String> {
            Some("user".to_owned())
        }
    }

    /// The two behaviours the golden corpus cannot reach: it renders
    /// every case with `store_secrets=None` and with `deploy_name ==
    /// config.name`, so the issue-#262 gate and the `Secret=` prefixing
    /// have no fixture. Both are load-bearing — the gate is what stops
    /// a `secret rm`'d entry failing the next boot with
    /// `start-limit-hit`, and the prefix is what lets two cages hold a
    /// secret of the same name.
    #[test]
    fn the_store_gate_and_the_deploy_prefix_shape_the_secret_lines() {
        let yaml = r"
name: c
container:
  image: busybox
  podman_secrets: [DIRECT]
domains:
  allow: [api.example.com]
dns_servers: [192.0.2.53]
secret_injection:
- env: PRESENT
  inject_to: [api.example.com]
  source: podman:PRESENT
- env: ABSENT
  inject_to: [api.example.com]
  source: podman:ABSENT
- env: FROM_ENV
  inject_to: [api.example.com]
  source: env:SET
";
        let config = crate::config::load(
            "cage.yaml",
            yaml,
            &crate::config::FixedHost::linux(&["192.0.2.53"]),
        )
        .expect("valid config");
        let state = StatePaths {
            config_root: "/cfg/agentcage".to_owned(),
            data_root: "/data/agentcage".to_owned(),
        };
        let store: BTreeSet<String> = ["PRESENT".to_owned()].into_iter().collect();
        let units = generate_quadlets(
            &config,
            &GenerateOptions {
                config_host_path: "/cfg/agentcage/cages/deployed/cage.yaml",
                patches_host_dir: "/data/patches",
                deploy_name: "deployed",
                rootless: true,
                used_octets: None,
                network_octet: None,
                store_secrets: Some(&store),
                state: &state,
                version: "9.9.9",
            },
            &TestHost,
        )
        .expect("renders");

        let egress = &units.files["c-egress.container"];
        // In the store: emitted, prefixed with the deploy name, and
        // targeted at the env name the container expects.
        assert!(egress.contains("Secret=deployed.PRESENT,type=env,target=PRESENT\n"));
        // An `env:` source is materialized by the start path before the
        // container runs, so the gate lets it through even though the
        // store does not hold it yet.
        assert!(egress.contains("Secret=deployed.FROM_ENV,type=env,target=FROM_ENV\n"));
        // Not in the store, no `.cred` blob, and no pre-start channel:
        // rendering it would make the next boot fail.
        assert!(!egress.contains("ABSENT"), "{egress}");

        // The cage's own `podman_secrets` go through the same gate.
        let cage = &units.files["c-cage.container"];
        assert!(!cage.contains("DIRECT"), "{cage}");

        // The version reaches both units, and the file set is the five
        // the Python builds, in its order.
        assert!(egress.contains("Image=localhost/agentcage-egress:9.9.9\n"));
        assert_eq!(
            units.files.keys().cloned().collect::<Vec<_>>(),
            vec![
                "c-net.network",
                "c-certs.volume",
                "c-public-certs.volume",
                "c-egress.container",
                "c-cage.container",
            ]
        );
        assert!(units.warnings.is_empty());
    }

    #[test]
    fn expanduser_matches_posixpath() {
        let host = TestHost;
        assert_eq!(expanduser("~", &host), "/home/tester");
        assert_eq!(expanduser("~/x", &host), "/home/tester/x");
        assert_eq!(expanduser("/abs/x", &host), "/abs/x");
        assert_eq!(expanduser("rel/x", &host), "rel/x");
        // No password database: `~other` is left alone, as Python's
        // `KeyError` branch does.
        assert_eq!(expanduser("~other/x", &host), "~other/x");
    }

    #[test]
    fn expandvars_matches_posixpath() {
        let host = TestHost;
        assert_eq!(expandvars("$SET/x", &host), "value/x");
        assert_eq!(expandvars("${SET}/x", &host), "value/x");
        assert_eq!(expandvars("a${EMPTY}b", &host), "ab");
        assert_eq!(expandvars("plain", &host), "plain");
        // Undefined: left verbatim, which is what the caller's `$` check
        // relies on.
        assert_eq!(expandvars("${MISSING}/x", &host), "${MISSING}/x");
        assert_eq!(expandvars("$MISSING/x", &host), "$MISSING/x");
        // A `$` that starts no name stays put.
        assert_eq!(expandvars("a$/b", &host), "a$/b");
        assert_eq!(expandvars("cost: 5$", &host), "cost: 5$");
        // An unclosed brace never matches `\{[^}]*\}`.
        assert_eq!(expandvars("${SET/x", &host), "${SET/x");
        // A substituted value is not rescanned.
        assert_eq!(expandvars("$SET", &host), "value");
        // Non-ASCII around a reference survives byte-slicing.
        assert_eq!(expandvars("é$SET é", &host), "évalue é");
    }

    #[test]
    fn shlex_quote_matches_python() {
        assert_eq!(shlex_quote("/home/luca/project"), "/home/luca/project");
        assert_eq!(shlex_quote(""), "''");
        assert_eq!(shlex_quote("a b"), "'a b'");
        assert_eq!(
            shlex_quote("%t/agentcage/x/mounts"),
            "%t/agentcage/x/mounts"
        );
        assert_eq!(shlex_quote("it's"), "'it'\"'\"'s'");
        // A brace is unsafe to Python's `_find_unsafe`, which matters
        // for the golden corpus: its scrubbed `{{HOME}}` paths would be
        // quoted, so the test renders real paths and scrubs afterwards.
        assert_eq!(shlex_quote("{{HOME}}/x"), "'{{HOME}}/x'");
    }

    #[test]
    fn path_helpers_match_posixpath() {
        assert_eq!(basename("/a/b/c.txt"), "c.txt");
        assert_eq!(basename("c.txt"), "c.txt");
        assert_eq!(dirname("/a/b/c.txt"), "/a/b");
        assert_eq!(dirname("/c.txt"), "/");
        assert_eq!(dirname("c.txt"), "");
    }

    #[test]
    fn partition_leaves_a_bare_name_with_an_empty_argument() {
        assert_eq!(partition("env:API_KEY"), ("env", "API_KEY"));
        assert_eq!(partition("systemd-creds:K"), ("systemd-creds", "K"));
        // No separator: Python's `partition` keeps the whole string as
        // the head, and the empty tail is what the call sites test.
        assert_eq!(partition("API_KEY"), ("API_KEY", ""));
        assert_eq!(partition(""), ("", ""));
    }

    #[test]
    fn copyup_owner_follows_the_user_field() {
        assert_eq!(mask_copyup_owner(""), "1000:1000");
        assert_eq!(mask_copyup_owner("  "), "1000:1000");
        assert_eq!(mask_copyup_owner("1001"), "1001:1001");
        assert_eq!(mask_copyup_owner("1001:2002"), "1001:2002");
        // A named user cannot be resolved host-side, and root needs no
        // chown.
        assert_eq!(mask_copyup_owner("node"), "");
        assert_eq!(mask_copyup_owner("0"), "");
        assert_eq!(mask_copyup_owner("0:0"), "");
        // A numeric uid with a named group falls back to uid:uid.
        assert_eq!(mask_copyup_owner("1001:staff"), "1001:1001");
    }

    #[test]
    fn overlay_mount_keeps_unrelated_options() {
        let overlay = non_persistent_overlay_mount("/src:/dst:rw,np,z", "cage", 0)
            .expect("a source and a target");
        assert_eq!(
            overlay.volume,
            "/src:/dst:O,upperdir=%t/agentcage/cage/mounts/vol-0/upper,\
             workdir=%t/agentcage/cage/mounts/vol-0/work,z"
        );
        assert_eq!(overlay.upperdir, "%t/agentcage/cage/mounts/vol-0/upper");
        assert!(non_persistent_overlay_mount("/src", "cage", 0).is_none());
    }

    #[test]
    fn mask_options_are_pinned_only_on_nested_tmpfs() {
        let mounts = vec![MountTarget::new("/workspace", "/home/tester/project")];
        let tmpfs = vec![
            "/workspace/.git/hooks:rw,noexec".to_owned(),
            "/tmp:rw,size=64M".to_owned(),
            "/workspace/.claude:rw,tmpcopyup".to_owned(),
            "/workspace/x:rw,mode=0700".to_owned(),
        ];
        assert_eq!(
            apply_tmpfs_mask_options(&tmpfs, &mounts),
            vec![
                // Nested and unopinionated: both pins, mode last.
                "/workspace/.git/hooks:rw,noexec,notmpcopyup,mode=1777".to_owned(),
                // Not nested: untouched.
                "/tmp:rw,size=64M".to_owned(),
                // Copy-up named by the operator: only the mode pin.
                "/workspace/.claude:rw,tmpcopyup,mode=1777".to_owned(),
                // Mode named by the operator: only the copy-up pin.
                "/workspace/x:rw,mode=0700,notmpcopyup".to_owned(),
            ]
        );
    }
}
