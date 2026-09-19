//! `services.py` — the orchestration between the CLI and the backend.
//!
//! The Python module exists so `cli.py` can be reduced to argument
//! handling, and the split survives here: nothing in this file prints
//! anything a command did not ask it to, and nothing in it decides
//! whether to exit.
//!
//! The one function the whole PR is about is [`build_and_deploy`].

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

use agentcage_core::config::Config;
use agentcage_core::quadlets::{Quadlets, cage_network_addrs};
use agentcage_state::Paths;

use crate::backend::{BackendError, ContainerBackend, patches_work_dir};

/// `services._BUILD_CAPS` — the capabilities a *cage* image build gets.
///
/// Distinct from the egress build's set in [`crate::backend`], and in a
/// different order. Both orders reach argv, so neither is normalized.
pub const BUILD_CAPS: [&str; 6] = [
    "CAP_SETFCAP",
    "CAP_SETUID",
    "CAP_SETGID",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FOWNER",
];

/// `services.expected_secrets` — every secret name a cage expects.
///
/// Four sources, in this order: injection rules, `container.podman_secrets`,
/// each protocol relay's two credential sources, and the two in-egress LLM
/// agents' API keys. The last two groups are deduplicated against what is
/// already in the list; the first two are not, because the Python does not
/// deduplicate them either and `check_secrets` is indifferent to a repeat.
#[must_use]
pub fn expected_secrets(config: &Config) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for rule in &config.secret_injection {
        names.push(rule.env.clone());
    }
    for secret in &config.container.podman_secrets {
        names.push(secret.clone());
    }
    // Relay credentials are stripped from the cage's own
    // podman_secrets/env — the cage must not see them — but the proxy
    // container still needs them from the same store.
    for relay in &config.protocol_relays {
        for source in [&relay.auth.user_source, &relay.auth.password_source] {
            let arg = after_colon(source);
            if !arg.is_empty() && !names.iter().any(|n| n == arg) {
                names.push(arg.to_owned());
            }
        }
    }
    // `agents.decider` / `agents.watcher`: real consumers of stored
    // secrets that are not injection rules, so without them `secret set`
    // calls the key an orphan and `check_secrets` gives no warning when
    // an agent-enabled cage deploys without it.
    for (enabled, key) in [
        (
            config.agents.decider.enable,
            &config.agents.decider.llm.api_key,
        ),
        (
            config.agents.watcher.enable,
            &config.agents.watcher.llm.api_key,
        ),
    ] {
        if !enabled {
            continue;
        }
        let arg = after_colon(key);
        if !arg.is_empty() && !names.iter().any(|n| n == arg) {
            names.push(arg.to_owned());
        }
    }
    names
}

/// `src.partition(":")[2]` — everything after the first colon, or the
/// empty string when there is none.
fn after_colon(source: &str) -> &str {
    source.split_once(':').map_or("", |(_, rest)| rest)
}

/// `services.check_secrets` — the names a cage expects but cannot get.
///
/// A rule with an explicit `source:` is checked against that scheme and
/// nothing else:
///
/// * `env:VAR` — the host variable must be set (the rule's `env` name is
///   the fallback when no `VAR` is given).
/// * `cmd:COMMAND` — the first token must resolve on `PATH`. A blank
///   command is missing; a token with a `/` or an `=` in it is a path or
///   an inline assignment and is not probed.
/// * `systemd-creds:` — the `.cred` blob must already exist.
///
/// Everything else falls through to the legacy pair: a present `.cred`
/// counts (the auto-default case, where `secret set` encrypted without
/// an explicit source), otherwise the podman store must hold
/// `<deploy>.<key>`.
#[must_use]
pub fn check_secrets(
    podman: &agentcage_exec::tools::podman::Podman<'_>,
    paths: &Paths,
    deploy_name: &str,
    config: &Config,
    env: &dyn crate::secrets::Environment,
) -> Vec<String> {
    let creds_dir = paths.creds_dir(deploy_name);
    let mut missing = Vec::new();
    for key in expected_secrets(config) {
        let rule = config.secret_injection.iter().find(|r| r.env == key);
        if let Some(source) = rule.map(|r| r.source.as_str()).filter(|s| !s.is_empty()) {
            let (scheme, arg) = source.split_once(':').unwrap_or((source, ""));
            match scheme {
                "env" => {
                    let var = if arg.is_empty() { key.as_str() } else { arg };
                    if env.get(var).is_none() {
                        missing.push(key);
                    }
                    continue;
                }
                "cmd" => {
                    if arg.trim().is_empty() {
                        missing.push(key);
                        continue;
                    }
                    let first = arg.split_whitespace().next().unwrap_or("");
                    if !first.is_empty()
                        && !first.contains('/')
                        && !first.contains('=')
                        && agentcage_exec::command::which_on_path(first).is_none()
                    {
                        missing.push(key);
                    }
                    continue;
                }
                "systemd-creds" => {
                    if !creds_dir.join(format!("{key}.cred")).exists() {
                        missing.push(key);
                    }
                    continue;
                }
                _ => {}
            }
        }
        if creds_dir.join(format!("{key}.cred")).exists() {
            continue;
        }
        if !podman
            .secret_exists(&format!("{deploy_name}.{key}"))
            .unwrap_or(false)
        {
            missing.push(key);
        }
    }
    missing
}

/// `services.suggest_alt_port` — the port the error message suggests.
#[must_use]
pub const fn suggest_alt_port(port: u16) -> u16 {
    // The Python clamps at 65535 by stepping *down* instead; `u16`
    // makes the overflow unrepresentable, so the clamp is the same
    // decision spelled without the arithmetic.
    if port == u16::MAX { port - 1 } else { port + 1 }
}

/// One published port that something else already holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortConflict {
    /// The `ports:` entry, verbatim, for the error's example block.
    pub spec: String,
    /// The host address the spec binds.
    pub host_bind: String,
    /// The host port, as written.
    pub host_port: String,
}

/// `services.check_port_availability`.
///
/// Binds each published host port with `SO_REUSEADDR`, exactly as the
/// Python's socket does — a port in `TIME_WAIT` must read as free, or
/// every `cage update` inside two minutes of a stop would refuse.
///
/// A two-part spec (`3000:3000`) binds `0.0.0.0`; a one- or
/// four-part spec is skipped, as is a host port that is not a number.
#[must_use]
pub fn check_port_availability(config: &Config) -> Vec<PortConflict> {
    let mut unavailable = Vec::new();
    for spec in &config.container.ports {
        let parts: Vec<&str> = spec.split(':').collect();
        let (host_bind, host_port) = match parts.len() {
            3 => (parts[0], parts[1]),
            2 => ("0.0.0.0", parts[0]),
            _ => continue,
        };
        let Ok(port) = host_port.parse::<u16>() else {
            continue;
        };
        let Ok(address) = host_bind.parse::<Ipv4Addr>() else {
            // `socket.bind(("localhost", …))` resolves a name; a spec
            // that is not an address at all would raise there. Skipping
            // is the conservative answer: a false "in use" would block
            // a deploy that works.
            continue;
        };
        if !bind_probe(address, port) {
            unavailable.push(PortConflict {
                spec: spec.clone(),
                host_bind: host_bind.to_owned(),
                host_port: host_port.to_owned(),
            });
        }
    }
    unavailable
}

/// One `SO_REUSEADDR` bind, immediately dropped. `true` means free.
///
/// `SO_REUSEADDR` because the Python sets it, and it is not cosmetic:
/// without it a port the cage's own container released seconds ago is
/// still in `TIME_WAIT`, and `cage update` would refuse to redeploy the
/// cage it just stopped.
fn bind_probe(address: Ipv4Addr, port: u16) -> bool {
    use nix::sys::socket::{
        AddressFamily, SockFlag, SockType, SockaddrIn, bind, setsockopt, socket, sockopt,
    };
    use std::os::fd::AsRawFd as _;

    let Ok(fd) = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    ) else {
        // The Python's `except OSError` wraps the whole block, and a
        // socket it could not create is a port it reports as in use.
        return false;
    };
    if setsockopt(&fd, sockopt::ReuseAddr, &true).is_err() {
        return false;
    }
    bind(
        fd.as_raw_fd(),
        &SockaddrIn::from(SocketAddrV4::new(address, port)),
    )
    .is_ok()
}

/// `services.ensure_patches` — refresh the nested-podman shim.
///
/// Copies the embedded `data/nested` tree into the shared patches
/// directory, replacing whatever is there so tampering in the work
/// directory is overwritten. Returns the patches directory.
///
/// # Errors
///
/// [`io::Error`] if the assets cannot be extracted or the copy fails.
pub fn ensure_patches(paths: &Paths) -> io::Result<PathBuf> {
    let patches = patches_work_dir(paths)?;
    let context = agentcage_assets::extract::build_context()?;
    let source = context.join("nested");
    if source.is_dir() {
        let dest = patches.join("nested");
        if dest.is_dir() {
            fs::remove_dir_all(&dest)?;
        }
        copy_tree(&source, &dest)?;
        let shim = dest.join("docker");
        if shim.is_file() {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&shim, fs::Permissions::from_mode(0o755))?;
        }
    }
    Ok(patches)
}

/// `shutil.copytree` — files, subdirectories and modes.
fn copy_tree(source: &Path, dest: &Path) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// `services.write_resolv_files` — the cage's and the egress's
/// `resolv.conf`, into the patches directory.
///
/// The cage's (`resolv-<name>.conf`) points at its own egress sidecar,
/// so its DNS goes through the egress's allowlist-scoped dnsmasq.
///
/// The egress's (`resolv-egress-<name>.conf`) is seeded with the
/// configured upstreams and nothing else. It exists because the egress
/// joins two aardvark-enabled podman networks and podman would otherwise
/// generate its `/etc/resolv.conf` for it — which is where mitmproxy
/// resolves every allowlisted upstream hostname from, so a resolver that
/// intermittently fails to forward turns every allowlisted host into a
/// 502. The quadlet bind-mounts this file **rw**, not ro: the supervisor
/// prepends the default-route gateway at start so the egress tracks host
/// network changes without a restart, and what is written here is the
/// deterministic fallback under it. `egress.container.j2` carries the
/// full history of that decision.
///
/// Returns `(cage_resolv, egress_resolv)`.
///
/// # Errors
///
/// [`io::Error`] on a failed write.
pub fn write_resolv_files(
    patches: &Path,
    name: &str,
    ip_egress: &str,
    dns_servers: &[String],
) -> io::Result<(PathBuf, PathBuf)> {
    let cage_path = patches.join(format!("resolv-{name}.conf"));
    fs::write(&cage_path, format!("nameserver {ip_egress}\n"))?;

    let egress_path = patches.join(format!("resolv-egress-{name}.conf"));
    let mut body = String::new();
    for server in dns_servers {
        body.push_str("nameserver ");
        body.push_str(server);
        body.push('\n');
    }
    fs::write(&egress_path, body)?;
    Ok((cage_path, egress_path))
}

/// What [`build_and_deploy`] produced, for the fingerprint the caller
/// records afterwards.
#[derive(Debug)]
pub struct Deployed {
    /// The units that were installed.
    pub units: Quadlets,
    /// The third octet actually assigned, as persisted to metadata.
    pub octet: u32,
}

/// Everything [`build_and_deploy`] needs besides the backend and the
/// state roots.
///
/// A struct because the tail is four `bool`s and two `Option`s; the
/// Python spells them as keyword-only arguments for the same reason.
#[derive(Debug)]
pub struct DeployPlan<'a> {
    /// The cage's configuration.
    pub config: &'a Config,
    /// Absolute host path to the stored `cage.yaml`, for the egress
    /// `Volume=`.
    pub config_host_path: &'a str,
    /// The deployment name, which the podman secret prefix is built
    /// from.
    pub deploy_name: &'a str,
    /// Third octets other cages already hold.
    pub used_octets: Option<&'a BTreeSet<u32>>,
    /// Pin the subnet instead of deriving it — the `cage update` path.
    pub network_octet: Option<u32>,
    /// Suppress the progress lines.
    pub quiet: bool,
    /// `podman build --no-cache`.
    pub no_cache: bool,
    /// `podman build --pull=always`.
    pub pull: bool,
}

/// `services.build_and_deploy` — build, render, install, record, start.
///
/// The order matters and is the Python's:
///
/// 1. Refresh the shared patches directory.
/// 2. Allocate (or reuse) the cage's `/24` and write the two
///    `resolv.conf` files the quadlets bind-mount.
/// 3. Build the egress image.
/// 4. Render and install the units.
/// 5. Persist the assigned octet into `metadata.json`, **before**
///    starting — so `collect_used_octets` reads the real value rather
///    than recomputing the hash, which would be wrong if collision
///    resolution shifted it.
/// 6. Start.
///
/// `network_octet` pins the subnet instead of re-deriving it from the
/// cage-name hash. That is the path `cage update` takes: the podman
/// network was created once at create time, and a re-derived octet
/// would render static IPs that fall outside the existing `<name>-net`,
/// which the egress refuses to start into.
///
/// # Errors
///
/// [`BackendError`] from any step. Nothing is rolled back — the caller
/// prints the Python's "state preserved for debugging" hint.
pub fn build_and_deploy(
    backend: &ContainerBackend<'_>,
    paths: &Paths,
    plan: &DeployPlan<'_>,
) -> Result<Deployed, BackendError> {
    let &DeployPlan {
        config,
        config_host_path,
        deploy_name,
        used_octets,
        network_octet,
        quiet,
        no_cache,
        pull,
    } = plan;
    let patches = ensure_patches(paths).map_err(BackendError::Assets)?;

    let addrs = cage_network_addrs(&config.name, used_octets, network_octet)?;
    write_resolv_files(
        &patches,
        &config.name,
        &addrs.ip_egress,
        &config.dns_servers,
    )
    .map_err(BackendError::Assets)?;

    backend.build_artifacts(no_cache, pull, quiet)?;

    let units = backend.generate_units(
        config,
        config_host_path,
        &patches.display().to_string(),
        deploy_name,
        used_octets,
        network_octet,
    )?;
    for warning in &units.warnings {
        eprint!("{warning}");
    }
    backend.install_units(&units, quiet)?;

    let octet = addrs.octet();
    let mut metadata = paths.load_metadata(deploy_name)?;
    metadata.set(
        "network_octet",
        agentcage_core::har::json::Json::Int(i64::from(octet)),
    );
    paths.save_metadata(deploy_name, &metadata)?;

    backend.start(&config.name, quiet)?;
    Ok(Deployed { units, octet })
}

/// `quadlets.collect_used_octets` — the third octets other cages hold.
///
/// Reads each deployment's persisted `network_octet` and falls back to
/// the hash-derived value only for a legacy deployment whose metadata
/// predates the field. A deployment that cannot be read at all is
/// skipped, as the Python's bare `except` skips it: a broken cage must
/// not block a new one.
#[must_use]
pub fn collect_used_octets(paths: &Paths, exclude: &str) -> BTreeSet<u32> {
    let mut used = BTreeSet::new();
    for name in paths.list_deployments().unwrap_or_default() {
        if name == exclude {
            continue;
        }
        let metadata = paths
            .load_metadata(&name)
            .unwrap_or_else(|_| agentcage_core::har::json::Json::Object(Vec::new()));
        if let Some(octet) = metadata.get("network_octet").and_then(as_u32) {
            used.insert(octet);
            continue;
        }
        let Ok(config) = paths.load_deployment_config(&name, &crate::hostenv::RealHost) else {
            continue;
        };
        if let Ok(addrs) = cage_network_addrs(&config.name, None, None) {
            used.insert(addrs.octet());
        }
    }
    used
}

/// A JSON number that is a plausible third octet.
fn as_u32(value: &agentcage_core::har::json::Json) -> Option<u32> {
    match value {
        agentcage_core::har::json::Json::Int(n) => u32::try_from(*n).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BUILD_CAPS, check_port_availability, expected_secrets, suggest_alt_port, write_resolv_files,
    };
    use agentcage_core::config::Config;
    use agentcage_core::config::types::{ProtocolRelay, SecretInjectionRule};

    #[test]
    fn build_caps_keep_the_pythons_order() {
        assert_eq!(BUILD_CAPS[0], "CAP_SETFCAP");
        assert_eq!(BUILD_CAPS[5], "CAP_FOWNER");
    }

    #[test]
    fn expected_secrets_walks_all_four_sources_in_order() {
        let mut config = Config::default();
        config.secret_injection.push(SecretInjectionRule {
            env: "API_KEY".to_owned(),
            ..SecretInjectionRule::default()
        });
        config.container.podman_secrets.push("EXTRA".to_owned());
        let mut relay = ProtocolRelay::default();
        relay.auth.user_source = "env:MAIL_USER".to_owned();
        relay.auth.password_source = "env:MAIL_PASS".to_owned();
        config.protocol_relays.push(relay);
        config.agents.decider.enable = true;
        config.agents.decider.llm.api_key = "env:DECIDER_KEY".to_owned();

        assert_eq!(
            expected_secrets(&config),
            ["API_KEY", "EXTRA", "MAIL_USER", "MAIL_PASS", "DECIDER_KEY"]
        );
    }

    #[test]
    fn a_disabled_agents_api_key_is_not_expected() {
        let mut config = Config::default();
        config.agents.watcher.enable = false;
        config.agents.watcher.llm.api_key = "env:WATCHER_KEY".to_owned();
        assert!(expected_secrets(&config).is_empty());
    }

    #[test]
    fn suggest_alt_port_steps_up_except_at_the_ceiling() {
        assert_eq!(suggest_alt_port(3000), 3001);
        assert_eq!(suggest_alt_port(65535), 65534);
    }

    #[test]
    fn a_held_port_is_reported_and_a_free_one_is_not() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();

        let mut config = Config::default();
        config.container.ports = vec![
            format!("127.0.0.1:{port}:3000"),
            // Two-part spec: binds 0.0.0.0, and port 0 is always free.
            "0:3000".to_owned(),
            // Not a number, and a one-part spec: both skipped.
            "127.0.0.1:nope:3000".to_owned(),
            "3000".to_owned(),
        ];
        let conflicts = check_port_availability(&config);
        assert_eq!(conflicts.len(), 1, "{conflicts:?}");
        assert_eq!(conflicts[0].host_port, port.to_string());
        assert_eq!(conflicts[0].host_bind, "127.0.0.1");
    }

    #[test]
    fn resolv_files_are_the_two_the_quadlets_mount() {
        let dir = agentcage_state::TestDir::new("resolv");
        let (cage, egress) = write_resolv_files(
            dir.path(),
            "acme",
            "10.89.7.2",
            &["1.1.1.1".to_owned(), "9.9.9.9".to_owned()],
        )
        .unwrap();
        assert!(cage.ends_with("resolv-acme.conf"));
        assert!(egress.ends_with("resolv-egress-acme.conf"));
        assert_eq!(
            std::fs::read_to_string(cage).unwrap(),
            "nameserver 10.89.7.2\n"
        );
        assert_eq!(
            std::fs::read_to_string(egress).unwrap(),
            "nameserver 1.1.1.1\nnameserver 9.9.9.9\n"
        );
    }
}
