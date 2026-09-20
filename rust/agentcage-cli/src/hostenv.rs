//! The three host probes `agentcage-core` declares and does not
//! implement.
//!
//! `agentcage-core` performs no I/O, so every question the config
//! loader, the validator and the quadlet renderer have to ask the
//! machine arrives as a trait method. The golden corpus answers them
//! from a hermetic tree; this answers them from the real host, and it
//! is the only place in the port where those answers come from.
//!
//! Each function is named after the `config.py` / `quadlets.py` call it
//! replaces so the two can be read side by side.

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use agentcage_core::config::{ConfigError, HostProbe};
use agentcage_core::quadlets::QuadletHost;

/// `config._RESOLVED_CONF` — where systemd-resolved keeps the real
/// upstreams while `/etc/resolv.conf` points at the 127.0.0.53 stub.
const RESOLVED_CONF: &str = "/run/systemd/resolve/resolv.conf";

/// `config._read_nameservers` — the `nameserver <addr>` lines of a
/// resolv.conf-shaped file, in order. An unreadable file is an empty
/// list, not an error.
fn read_nameservers(path: &str) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("nameserver"), Some(addr)) => Some(addr.to_owned()),
                _ => None,
            }
        })
        .collect()
}

/// `config._is_loopback` — 127.0.0.0/8 or `::1`. A string that is not
/// an IP address at all is not loopback, matching the Python's
/// `except ValueError: return False`.
fn is_loopback(addr: &str) -> bool {
    addr.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// `config._host_dns_servers`.
///
/// # Errors
///
/// [`ConfigError::Runtime`] with the Python's Linux message when every
/// nameserver on offer is a loopback address. The macOS `scutil` branch
/// is not reachable here — the container backend is Linux-only, and the
/// vm / apple-container backends are Track E.
fn host_dns_servers() -> Result<Vec<String>, ConfigError> {
    let servers: Vec<String> = read_nameservers("/etc/resolv.conf")
        .into_iter()
        .filter(|s| !is_loopback(s))
        .collect();
    if !servers.is_empty() {
        return Ok(servers);
    }
    let resolved: Vec<String> = read_nameservers(RESOLVED_CONF)
        .into_iter()
        .filter(|s| !is_loopback(s))
        .collect();
    if !resolved.is_empty() {
        return Ok(resolved);
    }
    Err(ConfigError::runtime(format!(
        "Could not detect usable DNS servers: /etc/resolv.conf contains only \
         loopback addresses (e.g. 127.0.0.53 from systemd-resolved) and \
         {RESOLVED_CONF} is missing or empty. Set dns_servers explicitly in \
         your agentcage config."
    )))
}

/// Variables this process publishes to the config layer without
/// putting them in its own environment.
///
/// `run.py` does `os.environ["PROJECT_DIR"] = project_dir` so that a
/// scaffold's `${PROJECT_DIR}:/workspace:rw` expands when the quadlets
/// are rendered. `std::env::set_var` is `unsafe` in Rust 2024 — it races
/// every other thread's `getenv`, and this crate forbids `unsafe` — and
/// the value is only ever read back by this process, through
/// [`RealQuadletHost::env_var`] and [`RealHost::env_var_is_set`]. So it
/// is published here instead, the same trade
/// [`crate::timing::enable_echo`] makes for `AGENTCAGE_TIMING`.
///
/// An overlay entry wins over the real environment: `agentcage run
/// --project X` has to mean `X` even on a shell that exports
/// `PROJECT_DIR`.
static OVERLAY: std::sync::OnceLock<std::sync::Mutex<BTreeMap<String, String>>> =
    std::sync::OnceLock::new();

fn overlay() -> &'static std::sync::Mutex<BTreeMap<String, String>> {
    OVERLAY.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// Publish `name=value` to every host probe in this process.
///
/// See [`OVERLAY`]. Called once, by the `run` flow, before the config is
/// loaded.
pub fn publish_env(name: &str, value: &str) {
    if let Ok(mut map) = overlay().lock() {
        map.insert(name.to_owned(), value.to_owned());
    }
}

/// `os.environ.get(name)`, overlay first.
#[must_use]
pub fn env_var(name: &str) -> Option<String> {
    if let Ok(map) = overlay().lock() {
        if let Some(value) = map.get(name) {
            return Some(value.clone());
        }
    }
    std::env::var(name).ok()
}

/// `platform.system()` for this build.
///
/// A compile-time constant rather than a runtime probe: a binary built
/// for Linux is not going to find itself on Darwin.
#[must_use]
pub fn system() -> &'static str {
    if cfg!(target_os = "macos") {
        "Darwin"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        std::env::consts::OS
    }
}

/// `pwd.getpwuid(os.getuid()).pw_name` — the invoking user's login name.
///
/// Lima names the guest user after the host user, deriving it from the
/// invoking uid's passwd entry, and `lima/provisioning.py` resolves it
/// the same way so the provisioning script targets the right account.
/// The comment there is explicit about why it is not
/// `getpass.getuser()`: that one trusts `$USER` / `$LOGNAME` and can
/// disagree with the uid under `sudo` or an overridden environment,
/// which would produce a script that chowns and lingers the wrong user.
///
/// The environment is only the *fallback*, for a uid with no passwd
/// entry. Python raises `KeyError` there; a container-ish host with no
/// passwd database is not something to crash a cage create over, and
/// the resulting script is wrong in the same way either way.
#[must_use]
pub fn login_name() -> String {
    if let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::Uid::current()) {
        return user.name;
    }
    env_var("USER").unwrap_or_default()
}

/// `platform.machine()`.
#[must_use]
pub fn machine() -> &'static str {
    match std::env::consts::ARCH {
        // Python reports `arm64` on Apple Silicon and `aarch64` on
        // Linux for the same instruction set, and `default_isolation`
        // compares against `arm64`.
        "aarch64" if cfg!(target_os = "macos") => "arm64",
        other => other,
    }
}

/// The real [`HostProbe`] and [`agentcage_core::config::ValidationHost`].
///
/// One type for both because they are the same host, and because
/// `cage create` loads and validates in the same breath.
#[derive(Clone, Copy, Debug, Default)]
pub struct RealHost;

impl HostProbe for RealHost {
    fn default_isolation(&self) -> String {
        // `config.default_isolation()`, minus its apple-container
        // branch. That branch needs `platform.mac_ver()` and a probe
        // for the `container` binary, both of which belong to the PR
        // that ports the backend it selects (Track E, E2/E3/E5).
        // Until then a Mac gets `vm`, which is what the Python answers
        // on every Mac without the CLI installed.
        if system() == "Darwin" {
            "vm".to_owned()
        } else {
            "container".to_owned()
        }
    }

    fn dns_servers(&self) -> Result<Vec<String>, ConfigError> {
        host_dns_servers()
    }
}

impl agentcage_core::config::ValidationHost for RealHost {
    fn system(&self) -> &str {
        system()
    }

    fn machine(&self) -> &str {
        machine()
    }

    fn env_var_is_set(&self, name: &str) -> bool {
        env_var(name).is_some()
    }
}

/// The real [`QuadletHost`].
///
/// Holds the data root so `stage_vm_file_volume` can compose the seed
/// directory without re-reading the environment — the Python composes
/// it from a literal `~/.local/share`, which is a wart the vm backend
/// (Track E) inherits; here it comes from the same [`Paths`] every
/// other writer uses.
///
/// [`Paths`]: agentcage_state::Paths
#[derive(Clone, Debug)]
pub struct RealQuadletHost {
    data_root: PathBuf,
}

impl RealQuadletHost {
    /// A host that stages vm file volumes under `data_root`.
    #[must_use]
    pub fn new(data_root: impl Into<PathBuf>) -> Self {
        Self {
            data_root: data_root.into(),
        }
    }
}

/// `os.path.realpath` — non-strict, so the components that do not exist
/// are kept verbatim rather than erroring.
///
/// Shared with the golden-corpus harness in spirit but not in code: the
/// harness resolves inside a sandbox root, this resolves the real path.
#[must_use]
pub fn realpath(path: &str) -> String {
    let absolute = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    let mut trailing: Vec<std::ffi::OsString> = Vec::new();
    let mut probe = absolute.clone();
    loop {
        if let Ok(resolved) = fs::canonicalize(&probe) {
            let mut out = resolved;
            for part in trailing.iter().rev() {
                out.push(part);
            }
            return out.display().to_string();
        }
        match probe.file_name() {
            Some(name) => {
                trailing.push(name.to_owned());
                if !probe.pop() {
                    return absolute.display().to_string();
                }
            }
            None => return absolute.display().to_string(),
        }
    }
}

impl QuadletHost for RealQuadletHost {
    fn env_var(&self, name: &str) -> Option<String> {
        env_var(name)
    }

    fn realpath(&self, path: &str) -> String {
        realpath(path)
    }

    fn exists(&self, path: &str) -> bool {
        fs::metadata(path).is_ok()
    }

    fn is_dir(&self, path: &str) -> bool {
        fs::metadata(path).is_ok_and(|meta| meta.is_dir())
    }

    fn stage_vm_file_volume(&self, source: &str, deploy_name: &str) -> Result<String, String> {
        let seed = self.data_root.join(deploy_name).join("seed");
        fs::create_dir_all(&seed).map_err(|error| error.to_string())?;
        let name = Path::new(source)
            .file_name()
            .ok_or_else(|| format!("no basename in {source}"))?;
        let staged = seed.join(name);
        fs::copy(source, &staged).map_err(|error| error.to_string())?;
        Ok(staged.display().to_string())
    }

    fn detect_default_creds_scope(&self) -> Option<String> {
        use crate::secrets::SecretHost;
        use agentcage_exec::SystemRunner;

        let runner = SystemRunner::new();
        let env = crate::secrets::SystemEnv;
        SecretHost::detect(&runner, &env)
            .default_scope()
            .map(|scope| scope.as_str().to_owned())
    }
}

/// Every environment variable, for the renderer's `${VAR}` expansion
/// in a context that wants them all at once.
#[must_use]
pub fn environment() -> BTreeMap<String, String> {
    std::env::vars().collect()
}

#[cfg(test)]
mod tests {
    use super::{is_loopback, read_nameservers, realpath};

    #[test]
    fn loopback_matches_pythons_ip_address_is_loopback() {
        assert!(is_loopback("127.0.0.53"));
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("::1"));
        assert!(!is_loopback("8.8.8.8"));
        // `ipaddress.ip_address("nonsense")` raises; the Python catches
        // it and answers False.
        assert!(!is_loopback("nonsense"));
        assert!(!is_loopback(""));
    }

    #[test]
    fn nameservers_come_back_in_file_order_and_ignore_everything_else() {
        let dir = std::env::temp_dir().join(format!("acns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("resolv.conf");
        std::fs::write(
            &path,
            "# comment\nsearch example.com\nnameserver 9.9.9.9\noptions edns0\n\
             nameserver 1.1.1.1\nnameserver\n",
        )
        .unwrap();
        assert_eq!(
            read_nameservers(path.to_str().unwrap()),
            ["9.9.9.9", "1.1.1.1"]
        );
        assert!(read_nameservers("/nonexistent/resolv.conf").is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn realpath_keeps_the_components_that_do_not_exist() {
        let resolved = realpath("/tmp/definitely-not-here/and/neither/is/this");
        assert!(resolved.ends_with("/definitely-not-here/and/neither/is/this"));
    }
}
