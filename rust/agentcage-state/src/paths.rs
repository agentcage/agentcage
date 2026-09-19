//! Where agentcage keeps things, and the four roots that are not one
//! root.
//!
//! RUST-PORT-PLAN.md section 2.7 is the table this module implements.
//! It has been corrected once already, and the corrections are the
//! interesting part — a Rust reader that assumed the obvious layout
//! would miss a file on a real user's disk at cutover. In full:
//!
//! | root | resolved from | what lives there |
//! | :-- | :-- | :-- |
//! | [`Paths::config_root`] | `$XDG_CONFIG_HOME` or `~/.config`, + `agentcage` | `cages/<name>/` — `cage.yaml`, `metadata.json`, `fingerprint.json`, `proxy-config.yaml`, `dns-allowlist.conf`, `cage-env/`, `creds/`, `secret_keys.json`, `pending_secrets.json` |
//! | [`Paths::apple_root`] | **`~` directly** + `.config/agentcage/apple-container` | `<name>/logs/{audit,capture}.jsonl`, `dnsmasq.log`, `ready`, `mask-mountpoints.json` |
//! | [`Paths::data_root`] | `$XDG_DATA_HOME` or `~/.local/share`, + `agentcage` | `<name>/grants/grants.yaml`, `<name>/capture/`, `<name>/policy-audit.jsonl`, and the **shared** `patches/` |
//! | [`Paths::quadlet_dir`] | **`~` directly** + `.config/containers/systemd` | the quadlets Python rendered, which systemd is still running |
//! | [`Paths::user_unit_dir`] | **`~` directly** + `.config/systemd/user` | *native* `.service` units — the legacy grants watcher D16 has to clean up |
//! | [`Paths::runtime_root`] | `$XDG_RUNTIME_DIR` or `/run/user/<uid>` | `agentcage/<name>/secrets`, tmpfs, the egress's staged credentials |
//! | [`Paths::apple_launchd_plist`] | **`~` directly** + `Library/LaunchAgents` | the opt-in autostart job, outside every agentcage root |
//!
//! Three things in that table are easy to get wrong:
//!
//! * **The per-cage config dir is `cages/<name>/`**, not
//!   `deployments/<name>/` and not `<name>/` — `state.py:29`.
//! * **The apple-container root ignores `XDG_CONFIG_HOME`.**
//!   `backends/apple_container.py:206` is
//!   `Path(os.path.expanduser("~/.config/agentcage/apple-container"))`,
//!   an `expanduser` with no XDG lookup anywhere near it. So it is a
//!   genuinely separate root, *and* an XDG sandbox does not redirect
//!   it — which makes it a testing hazard as much as a portability
//!   wart. [`Paths`] carries `home` separately for exactly this, so a
//!   test can move it without pretending XDG covers it.
//! * **`patches/` is shared, not per-cage.** It sits at
//!   `<data_root>/patches/` and holds `resolv-<name>.conf`,
//!   `resolv-egress-<name>.conf` and the `nested/` podman shim for
//!   *every* cage.
//! * **The quadlet directory ignores `XDG_CONFIG_HOME` too.**
//!   `backends/container.py::unit_dir` is another bare `expanduser`,
//!   so it has the same wart as the apple root and for the same
//!   reason: it is not agentcage's directory, it is podman's.
//!
//! And one absence: **there is no host-side `audit.jsonl` for a
//! `container` or `vm` cage.** The egress addon writes its audit trail
//! to stderr and the host reads it back out of `journalctl`. Only
//! apple-container has a file, which is why [`Paths::apple_audit_file`]
//! exists and no `audit_file` does.
//!
//! # Why a struct and not module constants
//!
//! `state.py` resolves `_CONFIG_DIR` and `_DATA_DIR` at *import* time,
//! into module-level constants, and its own test suite then has to
//! `monkeypatch.setattr(_state, "_CONFIG_DIR", ...)` to point them
//! anywhere else (`tests/test_state_compat.py:80`). A Rust equivalent
//! would be a `OnceLock`, with the same problem and no monkeypatch to
//! escape it. So the roots are a value that callers pass down.
//!
//! [`Paths::from_env`] reads the environment once, at the top of the
//! program, exactly where Python's import did.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The resolved state roots.
///
/// Build one with [`Paths::from_env`] in a real run, or
/// [`Paths::under`] in a test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    home: PathBuf,
    config_root: PathBuf,
    data_root: PathBuf,
    apple_root: PathBuf,
    quadlet_dir: PathBuf,
    user_unit_dir: PathBuf,
    runtime_root: PathBuf,
}

impl Paths {
    /// Resolve every root from the environment.
    ///
    /// The lookups match `state.py`'s exactly, including the two places
    /// where they differ from each other:
    ///
    /// * `os.environ.get("XDG_CONFIG_HOME", expanduser("~/.config"))`
    ///   — a `get` with a default, so `XDG_CONFIG_HOME=""` yields the
    ///   empty string and the config root becomes the *relative* path
    ///   `agentcage`. Surprising, but it is what the Python does, and a
    ///   port that quietly "fixed" it would write state somewhere the
    ///   Python would not look.
    /// * `os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{getuid()}"`
    ///   — an `or`, so there an empty value *does* fall through to the
    ///   default (`state.py:389`).
    ///
    /// `~` is `$HOME`. Python's `expanduser` would fall back to a
    /// `pwd` lookup when `HOME` is unset, and then to leaving the `~`
    /// in place; there is no `pwd` without `libc`, so this skips the
    /// middle step and leaves the literal `~`, which is Python's own
    /// last resort. A host with no `HOME` is not a configuration
    /// agentcage supports either way.
    #[must_use]
    pub fn from_env() -> Self {
        let home = home_dir();
        let config_home = env_path("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
        let data_home = env_path("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share"));
        // `or`, not `get(..., default)`: an empty value falls through.
        let runtime_root = env_path("XDG_RUNTIME_DIR")
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or_else(|| {
                PathBuf::from(format!("/run/user/{}", rustix::process::getuid().as_raw()))
            });
        Self::new(&home, &config_home, &data_home, &runtime_root)
    }

    /// Every root under one directory, as a sandbox.
    ///
    /// `home/.config`, `home/.local/share` and `home/run` — so the
    /// apple-container root and the quadlet directory, which follow
    /// `~` rather than XDG, land inside the sandbox too. That is the
    /// whole point: pointing `XDG_CONFIG_HOME` at a temp dir leaves
    /// those two writing to the developer's real home.
    #[must_use]
    pub fn under(home: impl AsRef<Path>) -> Self {
        let home = home.as_ref();
        Self::new(
            home,
            &home.join(".config"),
            &home.join(".local/share"),
            &home.join("run"),
        )
    }

    /// Each root named independently.
    ///
    /// What the state-compat fixture needs: its `xdg-config/` and
    /// `xdg-data/` trees are siblings rather than a `.config` and a
    /// `.local/share` under a shared home, and the apple-container root
    /// lives inside `xdg-config/` because the generator ran with `HOME`
    /// pointed at the sandbox.
    #[must_use]
    pub fn from_roots(
        home: impl AsRef<Path>,
        config_home: impl AsRef<Path>,
        data_home: impl AsRef<Path>,
        runtime_root: impl AsRef<Path>,
    ) -> Self {
        Self::new(
            home.as_ref(),
            config_home.as_ref(),
            data_home.as_ref(),
            runtime_root.as_ref(),
        )
    }

    fn new(home: &Path, config_home: &Path, data_home: &Path, runtime_root: &Path) -> Self {
        Self {
            home: home.to_path_buf(),
            config_root: config_home.join("agentcage"),
            data_root: data_home.join("agentcage"),
            // NOT `config_home`. See the module docs.
            apple_root: home.join(".config/agentcage/apple-container"),
            quadlet_dir: home.join(".config/containers/systemd"),
            user_unit_dir: home.join(".config/systemd/user"),
            runtime_root: runtime_root.to_path_buf(),
        }
    }

    // ── the roots themselves ────────────────────────────

    /// `~`, as every `expanduser` in the codebase resolves it.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// `$XDG_CONFIG_HOME/agentcage` — `state.py::_CONFIG_DIR`.
    #[must_use]
    pub fn config_root(&self) -> &Path {
        &self.config_root
    }

    /// `$XDG_DATA_HOME/agentcage` — `state.py::_DATA_DIR`.
    #[must_use]
    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    /// `~/.config/agentcage/apple-container` — the third root.
    ///
    /// `backends/apple_container.py:1344`. It does **not** honour
    /// `XDG_CONFIG_HOME`.
    #[must_use]
    pub fn apple_root(&self) -> &Path {
        &self.apple_root
    }

    /// `~/.config/containers/systemd` — where quadlets are installed.
    ///
    /// `backends/container.py::unit_dir`, also an `expanduser` with no
    /// XDG lookup.
    #[must_use]
    pub fn quadlet_dir(&self) -> &Path {
        &self.quadlet_dir
    }

    /// `~/.config/systemd/user` — where *native* `.service` units go.
    ///
    /// `backends/container.py::user_unit_dir`. A quadlet is transpiled
    /// by the systemd generator; a hand-written `.service` is not, and
    /// has to be installed where systemd-user looks directly.
    #[must_use]
    pub fn user_unit_dir(&self) -> &Path {
        &self.user_unit_dir
    }

    /// `$XDG_RUNTIME_DIR`, or `/run/user/<uid>`.
    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    // ── the config root ─────────────────────────────────

    /// `<config_root>/cages` — `state.py::_DEPLOYMENTS_DIR`.
    #[must_use]
    pub fn deployments_dir(&self) -> PathBuf {
        self.config_root.join("cages")
    }

    /// `<config_root>/cages/<name>` — `state.deployment_dir`.
    #[must_use]
    pub fn deployment_dir(&self, name: &str) -> PathBuf {
        self.deployments_dir().join(name)
    }

    /// `<deployment_dir>/cage.yaml` — `state.stored_config_path`.
    #[must_use]
    pub fn stored_config_path(&self, name: &str) -> PathBuf {
        self.deployment_dir(name).join("cage.yaml")
    }

    /// `<deployment_dir>/metadata.json`.
    #[must_use]
    pub fn metadata_path(&self, name: &str) -> PathBuf {
        self.deployment_dir(name).join("metadata.json")
    }

    /// `<deployment_dir>/fingerprint.json`.
    #[must_use]
    pub fn fingerprint_path(&self, name: &str) -> PathBuf {
        self.deployment_dir(name).join("fingerprint.json")
    }

    /// `<deployment_dir>/proxy-config.yaml`.
    #[must_use]
    pub fn proxy_config_path(&self, name: &str) -> PathBuf {
        self.deployment_dir(name).join("proxy-config.yaml")
    }

    /// `<deployment_dir>/dns-allowlist.conf` —
    /// `state.dns_allowlist_path`.
    ///
    /// The dnsmasq sidecar mounts this read-only and reads it with
    /// `--servers-file`, so a domain change is a file rewrite rather
    /// than unit churn and a daemon-reload.
    #[must_use]
    pub fn dns_allowlist_path(&self, name: &str) -> PathBuf {
        self.deployment_dir(name).join("dns-allowlist.conf")
    }

    /// `<deployment_dir>/cage-env` — `state.cage_env_dir`.
    ///
    /// Bind-mounted read-only into the cage at `/run/agentcage/env`. A
    /// directory rather than a single-file mount so an in-place rewrite
    /// propagates regardless of inode churn. Path only: the Python
    /// helper does not `mkdir` either, because quadlet rendering
    /// composes this path and must have no side effects.
    #[must_use]
    pub fn cage_env_dir(&self, name: &str) -> PathBuf {
        self.deployment_dir(name).join("cage-env")
    }

    /// `<cage_env_dir>/placeholders.env`.
    #[must_use]
    pub fn placeholders_env_path(&self, name: &str) -> PathBuf {
        self.cage_env_dir(name).join("placeholders.env")
    }

    /// `<deployment_dir>/creds` — the systemd-creds blob directory.
    ///
    /// Read by D3's `SystemdCredsStore`; named here because the
    /// directory is state layout, not store policy.
    #[must_use]
    pub fn creds_dir(&self, name: &str) -> PathBuf {
        self.deployment_dir(name).join("creds")
    }

    /// `<creds_dir>/<key>.cred`.
    #[must_use]
    pub fn cred_path(&self, name: &str, key: &str) -> PathBuf {
        self.creds_dir(name).join(format!("{key}.cred"))
    }

    /// `<deployment_dir>/secret_keys.json` — the non-secret name index.
    #[must_use]
    pub fn secret_keys_path(&self, name: &str) -> PathBuf {
        self.deployment_dir(name).join("secret_keys.json")
    }

    /// `<deployment_dir>/pending_secrets.json`.
    ///
    /// A JSON array of `[key, value]` **pairs**, not an object — see
    /// [`crate::pending_secrets`].
    #[must_use]
    pub fn pending_secrets_path(&self, name: &str) -> PathBuf {
        self.deployment_dir(name).join("pending_secrets.json")
    }

    // ── the data root ───────────────────────────────────

    /// `<data_root>/<name>` — `state.cage_data_dir`.
    #[must_use]
    pub fn cage_data_dir(&self, name: &str) -> PathBuf {
        self.data_root.join(name)
    }

    /// `<data_root>/<name>/capture` — `state.capture_dir`.
    #[must_use]
    pub fn capture_dir(&self, name: &str) -> PathBuf {
        self.cage_data_dir(name).join("capture")
    }

    /// `<capture_dir>/capture.jsonl` — `state.capture_file`.
    #[must_use]
    pub fn capture_file(&self, name: &str) -> PathBuf {
        self.capture_dir(name).join("capture.jsonl")
    }

    /// `<data_root>/<name>/grants` — `state.grants_dir`.
    ///
    /// Bind-mounted read-write into the egress container, so the addon
    /// can write decided grants. That is why
    /// [`Paths::policy_audit_file`] is deliberately *not* in here.
    #[must_use]
    pub fn grants_dir(&self, name: &str) -> PathBuf {
        self.cage_data_dir(name).join("grants")
    }

    /// `<grants_dir>/grants.yaml` — `state.grants_file`.
    ///
    /// **`.yaml`, and a top-level YAML list.** An earlier draft of the
    /// plan said `grants.json`; it is neither JSON nor an object.
    #[must_use]
    pub fn grants_file(&self, name: &str) -> PathBuf {
        self.grants_dir(name).join("grants.yaml")
    }

    /// `<data_root>/<name>/policy-audit.jsonl` —
    /// `state.policy_audit_file`.
    ///
    /// A **sibling** of `grants/`, not a file inside it, and the
    /// Python carries a long comment explaining why: `grants/` is
    /// group-writable by the egress container and bind-mounted
    /// read-write into it, so a forensic trail placed inside would be
    /// forgeable and truncatable by the thing it audits.
    #[must_use]
    pub fn policy_audit_file(&self, name: &str) -> PathBuf {
        self.cage_data_dir(name).join("policy-audit.jsonl")
    }

    /// `<data_root>/patches` — **shared across cages.**
    ///
    /// Holds `resolv-<name>.conf`, `resolv-egress-<name>.conf` and the
    /// nested-podman shim for every cage at once.
    #[must_use]
    pub fn patches_dir(&self) -> PathBuf {
        self.data_root.join("patches")
    }

    /// `<patches_dir>/resolv-<name>.conf` — the cage's resolver patch.
    #[must_use]
    pub fn cage_resolv_patch(&self, name: &str) -> PathBuf {
        self.patches_dir().join(format!("resolv-{name}.conf"))
    }

    /// `<patches_dir>/resolv-egress-<name>.conf`.
    #[must_use]
    pub fn egress_resolv_patch(&self, name: &str) -> PathBuf {
        self.patches_dir()
            .join(format!("resolv-egress-{name}.conf"))
    }

    /// `<patches_dir>/nested` — the nested-podman shim.
    ///
    /// `services.ensure_patches` copies `data/nested/` here on every
    /// deploy, replacing whatever was there, so that tampering inside
    /// a cage cannot persist into the next one. Shared across cages
    /// like the rest of `patches/`, and not captured by the A7
    /// fixture, which has no nested-container cage.
    #[must_use]
    pub fn nested_shim_dir(&self) -> PathBuf {
        self.patches_dir().join("nested")
    }

    // ── the apple-container root ────────────────────────

    /// `<apple_root>/<name>` —
    /// `backends/apple_container.py::_state_dir`.
    #[must_use]
    pub fn apple_state_dir(&self, name: &str) -> PathBuf {
        self.apple_root.join(name)
    }

    /// `<apple_state_dir>/logs`.
    #[must_use]
    pub fn apple_logs_dir(&self, name: &str) -> PathBuf {
        self.apple_state_dir(name).join("logs")
    }

    /// `<apple_logs_dir>/audit.jsonl` — **the only host-side
    /// `audit.jsonl` that exists.**
    ///
    /// On `container` and `vm` cages the addon writes its audit trail
    /// to stderr and `cage audit` reads it back out of `journalctl`.
    /// A reader that looks for a file on Linux finds nothing, and that
    /// is not a bug to fix.
    #[must_use]
    pub fn apple_audit_file(&self, name: &str) -> PathBuf {
        self.apple_logs_dir(name).join("audit.jsonl")
    }

    /// `<apple_logs_dir>/capture.jsonl`.
    ///
    /// Note that this is a *different file* from
    /// [`Paths::capture_file`], which is the container backend's and
    /// lives under the data root.
    #[must_use]
    pub fn apple_capture_file(&self, name: &str) -> PathBuf {
        self.apple_logs_dir(name).join("capture.jsonl")
    }

    /// `<apple_logs_dir>/dnsmasq.log`.
    #[must_use]
    pub fn apple_dnsmasq_log(&self, name: &str) -> PathBuf {
        self.apple_logs_dir(name).join("dnsmasq.log")
    }

    /// `<apple_logs_dir>/ready` — the supervisor's readiness marker.
    #[must_use]
    pub fn apple_ready_marker(&self, name: &str) -> PathBuf {
        self.apple_logs_dir(name).join("ready")
    }

    /// `<apple_state_dir>/mask-mountpoints.json`.
    #[must_use]
    pub fn apple_mask_mountpoints(&self, name: &str) -> PathBuf {
        self.apple_state_dir(name).join("mask-mountpoints.json")
    }

    /// `<apple_state_dir>/egress-config` — the rendered egress config
    /// the apple backend bind-mounts, in place of the container
    /// backend's `proxy-config.yaml` volume.
    #[must_use]
    pub fn apple_egress_config_dir(&self, name: &str) -> PathBuf {
        self.apple_state_dir(name).join("egress-config")
    }

    /// `<apple_state_dir>/certs` — the apple backend's stand-in for
    /// the container backend's `agentcage-certs-<name>` podman volume.
    #[must_use]
    pub fn apple_certs_dir(&self, name: &str) -> PathBuf {
        self.apple_state_dir(name).join("certs")
    }

    /// `<apple_state_dir>/public-certs`.
    #[must_use]
    pub fn apple_public_certs_dir(&self, name: &str) -> PathBuf {
        self.apple_state_dir(name).join("public-certs")
    }

    /// `<apple_state_dir>/secrets` — where `_stage_secrets` writes.
    ///
    /// Note that this is *persistent disk*, not the tmpfs
    /// [`Paths::runtime_secrets_dir`] the container backend uses:
    /// macOS has no `XDG_RUNTIME_DIR` and no tmpfs to stage into. A
    /// real difference between the backends, and one worth knowing
    /// about before writing a secret here.
    #[must_use]
    pub fn apple_secrets_dir(&self, name: &str) -> PathBuf {
        self.apple_state_dir(name).join("secrets")
    }

    /// `<apple_state_dir>/launchd.{out,err}.log`.
    ///
    /// The launchd job's stdout and stderr, named by the plist
    /// `_launchd_plist` renders.
    #[must_use]
    pub fn apple_launchd_logs(&self, name: &str) -> [PathBuf; 2] {
        let dir = self.apple_state_dir(name);
        [dir.join("launchd.out.log"), dir.join("launchd.err.log")]
    }

    /// `~/Library/LaunchAgents/io.agentcage.<name>.plist`.
    ///
    /// A **sixth** location, and the only one outside the four roots:
    /// macOS decides where a per-user launch agent lives, so opt-in
    /// autostart writes here. RUST-PORT-PLAN.md section 2.7 does not
    /// list it.
    #[must_use]
    pub fn apple_launchd_plist(&self, name: &str) -> PathBuf {
        self.home
            .join("Library/LaunchAgents")
            .join(format!("io.agentcage.{name}.plist"))
    }

    // ── the runtime root ────────────────────────────────

    /// `<runtime_root>/agentcage/<name>/secrets` —
    /// `state.runtime_secrets_dir`, path only.
    ///
    /// The same location the egress quadlet names as
    /// `%t/agentcage/<name>/secrets` (systemd expands `%t` to
    /// `$XDG_RUNTIME_DIR`). tmpfs only: real secret values never touch
    /// persistent disk unencrypted. Use
    /// [`crate::Paths::ensure_runtime_secrets_dir`] to create it with
    /// the modes the Python sets.
    #[must_use]
    pub fn runtime_secrets_dir(&self, name: &str) -> PathBuf {
        self.runtime_root
            .join("agentcage")
            .join(name)
            .join("secrets")
    }

    // ── bridges ─────────────────────────────────────────

    /// The view `agentcage-core`'s quadlet renderer wants.
    ///
    /// `quadlets::StatePaths` holds the same two roots as `String`s
    /// because the templates interpolate them into unit files. Lossy
    /// on a non-UTF-8 path, which a unit file could not carry anyway.
    #[must_use]
    pub fn quadlet_state_paths(&self) -> agentcage_core::quadlets::StatePaths {
        agentcage_core::quadlets::StatePaths {
            config_root: self.config_root.to_string_lossy().into_owned(),
            data_root: self.data_root.to_string_lossy().into_owned(),
        }
    }
}

/// `$HOME`, or a literal `~` when it is unset.
fn home_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => PathBuf::from(home),
        _ => PathBuf::from("~"),
    }
}

/// `os.environ.get(key)` as a path, preserving an empty value.
fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(OsString::into)
}

#[cfg(test)]
mod tests {
    use super::Paths;
    use std::path::Path;

    fn sandbox() -> Paths {
        Paths::under("/sand")
    }

    #[test]
    fn the_per_cage_config_dir_is_cages_not_deployments() {
        assert_eq!(
            sandbox().deployment_dir("acme"),
            Path::new("/sand/.config/agentcage/cages/acme")
        );
    }

    #[test]
    fn the_apple_root_and_the_quadlet_dir_follow_home_not_xdg() {
        // The corrected plan row: `XDG_CONFIG_HOME` pointed somewhere
        // else leaves both of these under `~`.
        let paths = Paths::from_roots(
            "/home/luca",
            "/elsewhere/config",
            "/elsewhere/data",
            "/run/user/1000",
        );
        assert_eq!(
            paths.config_root(),
            Path::new("/elsewhere/config/agentcage")
        );
        assert_eq!(
            paths.apple_root(),
            Path::new("/home/luca/.config/agentcage/apple-container")
        );
        assert_eq!(
            paths.quadlet_dir(),
            Path::new("/home/luca/.config/containers/systemd")
        );
        assert_eq!(
            paths.user_unit_dir(),
            Path::new("/home/luca/.config/systemd/user")
        );
    }

    #[test]
    fn the_grants_overlay_is_yaml_and_the_audit_trail_is_its_sibling() {
        let paths = sandbox();
        assert_eq!(
            paths.grants_file("acme"),
            Path::new("/sand/.local/share/agentcage/acme/grants/grants.yaml")
        );
        assert_eq!(
            paths.policy_audit_file("acme").parent(),
            paths.grants_dir("acme").parent(),
        );
        assert_ne!(
            paths.policy_audit_file("acme").parent(),
            Some(paths.grants_dir("acme").as_path()),
        );
    }

    #[test]
    fn patches_are_shared_across_cages() {
        let paths = sandbox();
        assert_eq!(
            paths.nested_shim_dir(),
            Path::new("/sand/.local/share/agentcage/patches/nested")
        );
        assert_eq!(
            paths.cage_resolv_patch("acme").parent(),
            paths.egress_resolv_patch("other").parent(),
        );
        assert_eq!(
            paths.patches_dir(),
            Path::new("/sand/.local/share/agentcage/patches")
        );
    }

    #[test]
    fn the_apple_state_root_holds_more_than_the_plan_lists() {
        // RUST-PORT-PLAN.md section 2.7's apple row names only
        // `logs/{audit,capture}.jsonl`, `dnsmasq.log`, `ready` and
        // `mask-mountpoints.json`. `backends/apple_container.py` puts
        // four more directories under the same root, and the launch
        // agent outside every root entirely.
        let paths = sandbox();
        let root = paths.apple_state_dir("acme");
        for under in [
            paths.apple_logs_dir("acme"),
            paths.apple_egress_config_dir("acme"),
            paths.apple_certs_dir("acme"),
            paths.apple_public_certs_dir("acme"),
            paths.apple_secrets_dir("acme"),
            paths.apple_mask_mountpoints("acme"),
        ] {
            assert!(under.starts_with(&root), "{}", under.display());
        }
        assert_eq!(
            paths.apple_launchd_logs("acme"),
            [root.join("launchd.out.log"), root.join("launchd.err.log")]
        );
        // The plist is not under any agentcage root -- macOS decides.
        let plist = paths.apple_launchd_plist("acme");
        assert_eq!(
            plist,
            Path::new("/sand/Library/LaunchAgents/io.agentcage.acme.plist")
        );
        assert!(!plist.starts_with(paths.apple_root()));
        assert!(!plist.starts_with(paths.config_root()));
        assert!(!plist.starts_with(paths.data_root()));

        // And the apple backend stages secrets on persistent disk,
        // not on the container backend's tmpfs.
        assert!(
            !paths
                .apple_secrets_dir("acme")
                .starts_with(paths.runtime_root())
        );
    }

    #[test]
    fn the_runtime_secrets_dir_matches_the_quadlets_percent_t() {
        assert_eq!(
            Paths::from_roots("/h", "/h/.config", "/h/.local/share", "/run/user/1000")
                .runtime_secrets_dir("acme"),
            Path::new("/run/user/1000/agentcage/acme/secrets")
        );
    }

    #[test]
    fn the_quadlet_bridge_carries_both_roots() {
        let bridge = sandbox().quadlet_state_paths();
        assert_eq!(bridge.config_root, "/sand/.config/agentcage");
        assert_eq!(bridge.data_root, "/sand/.local/share/agentcage");
        // And agrees with this module on what it derives from them.
        assert_eq!(
            bridge.deployment_dir("acme"),
            sandbox().deployment_dir("acme").to_string_lossy()
        );
        assert_eq!(
            bridge.dns_allowlist_path("acme"),
            sandbox().dns_allowlist_path("acme").to_string_lossy()
        );
        assert_eq!(
            bridge.placeholders_env_path("acme"),
            sandbox().placeholders_env_path("acme").to_string_lossy()
        );
        assert_eq!(
            bridge.creds_dir("acme"),
            sandbox().creds_dir("acme").to_string_lossy()
        );
        assert_eq!(
            bridge.capture_dir("acme"),
            sandbox().capture_dir("acme").to_string_lossy()
        );
        assert_eq!(
            bridge.grants_dir("acme"),
            sandbox().grants_dir("acme").to_string_lossy()
        );
    }
}
