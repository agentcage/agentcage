//! `_render_egress_config` — the three files the egress microVM mounts.
//!
//! The egress sibling reads its whole configuration off a bind mount at
//! startup, so the host renders these before `container run`:
//!
//! | File | In the egress | Produced from |
//! | :-- | :-- | :-- |
//! | `proxy-config.yaml` | `/etc/agentcage/config.yaml`, via `$AGENTCAGE_CONFIG` | [`Paths::save_proxy_config`] |
//! | `dnsmasq.conf` | `/etc/agentcage/dnsmasq.conf` | [`render_dnsmasq_conf`] |
//! | `dns-allowlist.conf` | `/etc/agentcage/dns-allowlist.conf` | [`Paths::save_dns_allowlist`] |
//!
//! Rendering host-side rather than baking into the image is what makes
//! `domain add` a file rewrite plus a SIGHUP instead of a rebuild and a
//! restart — parity with the container and vm backends, which get the
//! same effect through quadlet bind mounts.
//!
//! Two of the three are *copied* from the same `state.py` helpers the
//! container backend uses, deliberately: the on-disk shape has to stay
//! identical across backends, and a second renderer here would be a
//! second thing to keep in sync. What is genuinely this backend's is
//! `dnsmasq.conf`, which no other backend writes to disk.
//!
//! # The pre-create fallback
//!
//! Both copies need a stored `cage.yaml`, which `cage create` writes
//! before `build_artifacts` runs — so on the happy path it is there.
//! When it is not, the Python catches `FileNotFoundError` and writes a
//! minimal config inline instead. That branch is reproduced rather than
//! tidied away, because it is reachable (a test, a partial create) and
//! because what it *omits* matters: no `agentcage_version` stamp, no
//! passthrough list, no inspectors, no secret-injection rules. An egress
//! started against it enforces `domains.allow` and nothing else.
//! `tests/fixtures/apple-container/egress-config/pre-create-fallback/`
//! is what it produces.

use std::path::{Path, PathBuf};

use agentcage_core::config::{Config, ConfigError, HostProbe};
use agentcage_core::quadlets::effective_dns_allowlist;
use agentcage_core::yaml::{self, Mapping, Sequence, Value};
use agentcage_state::{Paths, StateError};

/// `wrapper._DEFAULT_DNS_SERVERS` — the template's own fallback.
///
/// Reached when a `Config` carries no `dns_servers` at all, which
/// `load_config` never produces (`raw.get("dns_servers") or
/// _host_dns_servers()` means an explicit `[]` loses to auto-detection)
/// but a hand-built one can.
const DEFAULT_DNS_SERVERS: [&str; 2] = ["1.1.1.1", "8.8.8.8"];

/// The embedded template, under the name its `FileSystemLoader` gives it.
const DNSMASQ_TEMPLATE: &str = "apple-container/dnsmasq.conf.j2";

/// What went wrong rendering the egress config.
#[derive(Debug)]
pub enum EgressConfigError {
    /// A read or write failed, or a stored file could not be parsed.
    State(StateError),
    /// The dnsmasq template failed to render.
    ///
    /// `ConfigError::Runtime`, as `generate_quadlets` classifies the
    /// same failure: the template is embedded in the binary, so a
    /// render error is a bug here rather than something the operator
    /// wrote.
    Render(ConfigError),
    /// The fallback proxy-config could not be serialized.
    Yaml(yaml::Error),
    /// A filesystem operation outside `agentcage-state` failed.
    Io {
        /// What was being touched.
        path: PathBuf,
        /// What was being attempted.
        doing: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
}

impl std::fmt::Display for EgressConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::State(e) => write!(f, "{e}"),
            Self::Render(e) => write!(f, "could not render dnsmasq.conf: {e}"),
            Self::Yaml(e) => write!(f, "could not write the fallback proxy-config: {e}"),
            Self::Io {
                path,
                doing,
                source,
            } => {
                write!(f, "could not {doing} {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for EgressConfigError {}

impl From<StateError> for EgressConfigError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

/// `wrapper.render_dnsmasq_conf` — the per-cage dnsmasq configuration.
///
/// Recursion is permitted **only** for hostnames within an explicitly
/// allowlisted apex domain: one `server=/<zone>/<upstream>` line per
/// (zone × upstream) pair, and no blanket `server=<upstream>` at all.
/// Every other zone returns REFUSED regardless of record type.
///
/// That scoping is not a tidiness choice. dnsmasq's `address=/#/<ip>`
/// sinkhole only covers A and AAAA, so a blanket forwarder would send
/// TXT/MX/NS/SRV/CNAME queries for *any* hostname upstream — a fully
/// out-of-band DNS-tunnel exfiltration channel that mitmproxy never
/// sees, because mitmproxy never sees DNS. The sinkhole line stays as
/// defence in depth for A/AAAA inside non-allowed zones.
///
/// Empty (or whitespace-only) entries are dropped, and an empty
/// allowlist takes the template's no-upstreams branch: the cage can
/// resolve nothing.
///
/// # Errors
///
/// [`ConfigError::Runtime`] if the embedded template is missing or
/// fails to render, which would be a build problem rather than a config
/// one.
pub fn render_dnsmasq_conf(
    allowlist: &[String],
    dns_servers: &[String],
) -> Result<String, ConfigError> {
    let allowlist: Vec<&str> = allowlist
        .iter()
        .map(|host| host.trim())
        .filter(|host| !host.is_empty())
        .collect();
    let servers: Vec<String> = if dns_servers.is_empty() {
        DEFAULT_DNS_SERVERS
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    } else {
        dns_servers.to_vec()
    };
    let source = agentcage_assets::tree("data")
        .find(|(path, _)| *path == DNSMASQ_TEMPLATE)
        .and_then(|(_, file)| std::str::from_utf8(file.bytes).ok())
        .ok_or_else(|| {
            ConfigError::runtime(format!(
                "{DNSMASQ_TEMPLATE} is not in the embedded asset tree"
            ))
        })?;
    agentcage_core::quadlets::templates::render_source(
        DNSMASQ_TEMPLATE,
        source,
        &serde_json::json!({ "allowlist": allowlist, "dns_servers": servers }),
        // `placeholder()` is never called by this template; installing a
        // generator that panicked would be a worse failure than the
        // environment's own "no generator installed" error.
        |_name| String::new(),
    )
    .map_err(|error| ConfigError::runtime(format!("could not render {DNSMASQ_TEMPLATE}: {error}")))
}

/// What [`render_egress_config`] wrote, and how.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedEgressConfig {
    /// The directory the three files landed in.
    pub directory: PathBuf,
    /// Whether `proxy-config.yaml` came from a stored `cage.yaml`.
    ///
    /// `false` means the pre-create fallback fired and the file carries
    /// only `name` and `domains.allow`.
    pub proxy_config_stored: bool,
    /// Whether `dns-allowlist.conf` came from a stored `cage.yaml`.
    pub dns_allowlist_stored: bool,
}

/// `_render_egress_config` — write the three files.
///
/// `version` is stamped into `proxy-config.yaml` by
/// [`Paths::save_proxy_config`]; pass [`agentcage_core::VERSION`].
/// `host` supplies the DNS auto-detection [`Paths::save_dns_allowlist`]
/// may need.
///
/// # Errors
///
/// [`EgressConfigError`] when the directory cannot be created, a stored
/// config is unreadable or malformed, or the template fails to render.
/// A *missing* stored config is not an error: it takes the fallback.
pub fn render_egress_config(
    paths: &Paths,
    config: &Config,
    deploy_name: &str,
    version: &str,
    host: &dyn HostProbe,
) -> Result<RenderedEgressConfig, EgressConfigError> {
    let dest = paths.apple_egress_config_dir(deploy_name);
    std::fs::create_dir_all(&dest).map_err(|source| EgressConfigError::Io {
        path: dest.clone(),
        doing: "create",
        source,
    })?;

    // 1. proxy-config.yaml — the same subset `save_proxy_config` writes
    //    for container/vm, copied rather than re-derived so the on-disk
    //    shape stays identical across backends.
    let proxy_config_stored = match paths.save_proxy_config(deploy_name, version) {
        Ok(source) => {
            copy(&source, &dest.join("proxy-config.yaml"))?;
            true
        }
        Err(StateError::Missing { .. }) => {
            write(
                &dest.join("proxy-config.yaml"),
                &minimal_proxy_config(deploy_name, config)?,
            )?;
            false
        }
        Err(other) => return Err(other.into()),
    };

    // 2. dnsmasq.conf — the EFFECTIVE DNS allowlist, not `domains.allow`.
    //    `effective_dns_allowlist` is the single source of truth the
    //    container backend uses too, so the egress-internal hosts that
    //    must resolve there (passthrough domains, relay upstreams, the
    //    agents decider's provider) resolve here as well.
    let effective = effective_dns_allowlist(config);
    let rendered =
        render_dnsmasq_conf(&effective, &config.dns_servers).map_err(EgressConfigError::Render)?;
    write(&dest.join("dnsmasq.conf"), &rendered)?;

    // 3. dns-allowlist.conf — what dnsmasq reads through
    //    `--servers-file`. Same helper as the container backend, which
    //    also goes through `effective_dns_allowlist`, so the two files
    //    cannot drift apart.
    let dns_allowlist_stored = match paths.save_dns_allowlist(deploy_name, host) {
        Ok(source) => {
            copy(&source, &dest.join("dns-allowlist.conf"))?;
            true
        }
        Err(StateError::Missing { .. }) => {
            write(
                &dest.join("dns-allowlist.conf"),
                &inline_dns_allowlist(&effective, &config.dns_servers),
            )?;
            false
        }
        Err(other) => return Err(other.into()),
    };

    Ok(RenderedEgressConfig {
        directory: dest,
        proxy_config_stored,
        dns_allowlist_stored,
    })
}

/// The pre-create `proxy-config.yaml`: a name and an allowlist.
///
/// `yaml.safe_dump({...}, default_flow_style=False, sort_keys=False)`,
/// which is what [`yaml::dump`] reproduces.
///
/// The name is the **deploy** name, not `config.name`. The two differ
/// whenever a cage is deployed under another name, and this file is
/// what the egress addon identifies itself as — so using `config.name`
/// here would label the running egress after the config it was built
/// from rather than after the cage it belongs to. The
/// `pre-create-fallback` fixture case is deliberately one where they
/// disagree.
fn minimal_proxy_config(deploy_name: &str, config: &Config) -> Result<String, EgressConfigError> {
    let mut domains = Mapping::new();
    domains.insert(
        Value::String("allow".to_owned()),
        Value::Sequence(
            config
                .domains
                .allow
                .iter()
                .map(|domain| Value::String(domain.clone()))
                .collect::<Sequence>(),
        ),
    );
    let mut document = Mapping::new();
    document.insert(
        Value::String("name".to_owned()),
        Value::String(deploy_name.to_owned()),
    );
    document.insert(Value::String("domains".to_owned()), Value::Mapping(domains));
    yaml::dump(&Value::Mapping(document)).map_err(EgressConfigError::Yaml)
}

/// The pre-create `dns-allowlist.conf`.
///
/// One line per (zone × upstream), and a trailing newline only when
/// there is something to terminate — `"\n".join(lines) + ("\n" if lines
/// else "")`, which is the same shape `save_dns_allowlist` writes.
fn inline_dns_allowlist(effective: &[String], dns_servers: &[String]) -> String {
    let servers: Vec<&str> = if dns_servers.is_empty() {
        DEFAULT_DNS_SERVERS.to_vec()
    } else {
        dns_servers.iter().map(String::as_str).collect()
    };
    let mut lines: Vec<String> = Vec::new();
    for domain in effective {
        for server in &servers {
            lines.push(format!("server=/{domain}/{server}"));
        }
    }
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

/// `shutil.copy2` — contents and mode; the egress mounts these
/// read-only, so nothing else about the metadata matters.
fn copy(source: &Path, dest: &Path) -> Result<(), EgressConfigError> {
    std::fs::copy(source, dest).map_err(|error| EgressConfigError::Io {
        path: dest.to_path_buf(),
        doing: "copy into",
        source: error,
    })?;
    Ok(())
}

fn write(path: &Path, text: &str) -> Result<(), EgressConfigError> {
    std::fs::write(path, text).map_err(|source| EgressConfigError::Io {
        path: path.to_path_buf(),
        doing: "write",
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_DNS_SERVERS, inline_dns_allowlist, render_dnsmasq_conf};

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The property the whole file exists for: no blanket forwarder.
    ///
    /// A `server=` line with no `/zone/` prefix is a default upstream,
    /// and a default upstream is the DNS-tunnel channel #CTF found.
    #[test]
    fn no_blanket_upstream() {
        let text = render_dnsmasq_conf(&strings(&["api.example.com"]), &strings(&["192.0.2.53"]))
            .expect("renders");
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("server=") {
                assert!(
                    rest.starts_with('/'),
                    "unscoped forwarder in dnsmasq.conf: {line}"
                );
            }
        }
        assert!(text.contains("server=/api.example.com/192.0.2.53"));
        assert!(text.contains("address=/#/198.51.100.1"));
    }

    /// An empty allowlist still sinkholes; it does not fall open.
    #[test]
    fn empty_allowlist_has_no_forwarder() {
        let text = render_dnsmasq_conf(&[], &strings(&["192.0.2.53"])).expect("renders");
        // A `server=` also appears in the template's own commentary, so
        // the assertion is about directives — lines, not substrings.
        assert!(!text.lines().any(|line| line.starts_with("server=")));
        assert!(text.contains("address=/#/198.51.100.1"));
    }

    /// Blank entries are dropped rather than emitted as `server=//<ip>`.
    #[test]
    fn blank_entries_are_dropped() {
        let text = render_dnsmasq_conf(
            &strings(&["  ", "", " api.example.com "]),
            &strings(&["192.0.2.53"]),
        )
        .expect("renders");
        assert!(text.contains("server=/api.example.com/192.0.2.53"));
        assert!(!text.lines().any(|line| line.starts_with("server=//")));
    }

    /// No `dns_servers` reaches the template's own default pair.
    #[test]
    fn missing_servers_take_the_default_pair() {
        let text = render_dnsmasq_conf(&strings(&["api.example.com"]), &[]).expect("renders");
        for server in DEFAULT_DNS_SERVERS {
            assert!(text.contains(&format!("server=/api.example.com/{server}")));
        }
    }

    /// An empty file, not a bare newline: dnsmasq is fine with either,
    /// but the container backend writes the former and these two files
    /// are compared against each other by hand often enough to matter.
    #[test]
    fn empty_inline_allowlist_has_no_newline() {
        assert_eq!(inline_dns_allowlist(&[], &strings(&["1.1.1.1"])), "");
    }
}
