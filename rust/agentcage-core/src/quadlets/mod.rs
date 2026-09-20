//! Quadlet unit files, rendered from the same `.j2` templates Python uses.
//!
//! This is PR C8 of RUST-PORT-PLAN.md's Track C: the port of
//! `src/agentcage/quadlets.py` and the four templates under
//! `src/agentcage/templates/` it renders.
//!
//! # The templates are not rewritten
//!
//! `network.j2`, `volume.j2`, `cage.container.j2` and
//! `egress.container.j2` are used **unmodified**. They have to be: the
//! Python renders the same files until cutover, so any edit would have
//! to keep working for both implementations, and a systemd unit file is
//! line-oriented — a stray blank line or a lost one is a behaviour
//! change, not a formatting one. minijinja is Jinja2-compatible enough
//! to render them as they stand; [`templates`] is where the environment
//! is configured to match `quadlets._make_env()` setting for setting.
//!
//! The bytes come from [`agentcage_assets`], which already embeds
//! `templates/` for this purpose, rather than from a second
//! `include_str!` copy.
//!
//! # What "faithful" means here
//!
//! The golden corpus (`tests/fixtures/golden/`) records every unit file
//! `quadlets.generate_quadlets` produced for 120 of its 125 valid cases,
//! and the corpus README puts quadlets on the **byte-exact** side of its
//! comparison line — systemd is a byte-sensitive consumer. So the
//! acceptance check is a diff, not a judgement: `tests/golden_quadlets.rs`
//! re-renders each case and compares the bytes, and the same test
//! reproduces each case's `render-warnings.txt`.
//!
//! The five cases with no units are the `apple-container` ones, which
//! carry a `NOT-APPLICABLE.txt`: that backend builds `container run`
//! argv and a launchd plist in `backends/apple_container.py` and never
//! reaches this module. They are Track E's, not this PR's.
//!
//! # I/O
//!
//! `generate_quadlets` is the one place in `agentcage-core` that has to
//! ask the outside world questions — it resolves `~` and `$VAR` in
//! volume sources, refuses a source that resolves outside the home
//! directory, skips one that does not exist, and stages a single-file
//! source for the VM backend by *copying* it. The crate still performs
//! no I/O itself: every one of those goes through [`QuadletHost`], which
//! `agentcage-cli` implements against the real filesystem (Track D) and
//! the golden-corpus test implements against a temporary tree.
//!
//! # What stayed behind
//!
//! `quadlets.collect_used_octets` is not here. It walks
//! `~/.config/agentcage/cages/*/metadata.json`, which is `state.py`'s
//! territory (Track D); this module takes the resulting set as
//! [`GenerateOptions::used_octets`], exactly as the Python function
//! takes it as an argument.

pub mod render;
pub mod templates;

pub use render::{
    GenerateOptions, QuadletHost, Quadlets, StatePaths, expanduser, expandvars, generate_quadlets,
};

use crate::config::Config;

/// The network addresses a cage's units are pinned to.
///
/// The Python returns a `dict` with these three keys and splats it into
/// every template as part of `common`; the field names are the template
/// variable names and must not drift.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct CageNetworkAddrs {
    /// The cage's `/24`, e.g. `10.89.42.0/24`.
    pub subnet: String,
    /// The cage container's static address, `.2` in that subnet.
    pub ip_cage: String,
    /// The egress container's static address, `.10` in that subnet.
    pub ip_egress: String,
}

impl CageNetworkAddrs {
    /// Build the three addresses from a third octet.
    fn from_octet(octet: u32) -> Self {
        Self {
            subnet: format!("10.89.{octet}.0/24"),
            ip_cage: format!("10.89.{octet}.2"),
            ip_egress: format!("10.89.{octet}.10"),
        }
    }

    /// The third octet these addresses were built from.
    ///
    /// `collect_used_octets`'s legacy path recovers it from the subnet
    /// text; having it here saves the caller a `split('.')`.
    #[must_use]
    pub fn octet(&self) -> u32 {
        self.subnet
            .split('.')
            .nth(2)
            .and_then(|part| part.parse().ok())
            .unwrap_or(0)
    }
}

/// Derive deterministic, unique network addresses for a cage.
///
/// Each cage gets a `/24` subnet under `10.89.x.0` where *x* is derived
/// from the cage name via a hash (range 1–254). This avoids subnet
/// collisions when multiple cages run simultaneously.
///
/// If `used_octets` is provided, the function checks for collisions and
/// increments the third octet until a free slot is found.
///
/// If `network_octet` is provided, the addresses are derived directly
/// from that octet, bypassing the hash and any collision resolution.
/// This is the correct path for updates to an already-deployed cage
/// whose podman network is pinned to the previously-allocated subnet —
/// re-allocating would produce IPs that fall outside the existing
/// `<name>-net` subnet and the egress container would refuse to start
/// with `requested static ip not in any subnet on network`.
/// `used_octets` is ignored when `network_octet` is set.
///
/// The hash is MD5, and it stays MD5 because it is a compatibility
/// constraint rather than a security one: every cage Python deployed has
/// its podman network pinned to the octet MD5 chose, and a "better" hash
/// would move every one of them.
///
/// # Errors
///
/// [`ConfigError::Runtime`](crate::config::ConfigError::Runtime) when
/// all 254 slots in `used_octets` are taken.
pub fn cage_network_addrs(
    name: &str,
    used_octets: Option<&std::collections::BTreeSet<u32>>,
    network_octet: Option<u32>,
) -> Result<CageNetworkAddrs, crate::config::ConfigError> {
    use md5::{Digest as _, Md5};

    if let Some(octet) = network_octet {
        return Ok(CageNetworkAddrs::from_octet(octet));
    }
    let digest = Md5::digest(name.as_bytes());
    // `int(h[:8], 16)` over the hex digest — the first four bytes, big
    // endian.
    let leading = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let mut octet = (leading % 254) + 1;
    if let Some(used) = used_octets {
        let mut attempts = 0;
        while used.contains(&octet) && attempts < 254 {
            octet = (octet % 254) + 1;
            attempts += 1;
        }
        if used.contains(&octet) {
            return Err(crate::config::ConfigError::runtime(
                "All 254 subnet slots are in use — cannot allocate a new cage network",
            ));
        }
    }
    Ok(CageNetworkAddrs::from_octet(octet))
}

/// VM-local path where the cage's egress config files live.
///
/// The host's `~/.config/agentcage/cages/<name>/` is exposed inside the
/// Lima VM as a reverse-sshfs mount that caches file contents
/// aggressively — so a host-side rewrite of `proxy-config.yaml` or
/// `dns-allowlist.conf` is invisible to processes running inside the VM
/// until the mount itself is reset. We sidestep that by writing a
/// VM-local copy of those two files into a parallel directory tree under
/// the user's home that is *not* a Lima mount, and bind-mounting the
/// VM-local copy into the egress container.
///
/// Returned with the systemd `%h` home-directory specifier instead of
/// `~`: systemd-quadlet expands `%h` to the user's absolute home before
/// podman parses the unit, so `Volume=%h/...` works as a bind mount.
/// Using `~` would NOT work — podman-quadlet treats unprefixed paths as
/// named volumes, and the resulting "name" fails podman's
/// `[a-zA-Z0-9_.-]*` validator. Shell-context callers (`mkdir` /
/// `base64` in the VM backend's `push_config_files`) must substitute
/// `%h` with the actual `$HOME` before invocation; bash does not expand
/// systemd specifiers.
#[must_use]
pub fn vm_local_config_dir(name: &str) -> String {
    format!("%h/.config/agentcage-vm/cages/{name}")
}

/// VM-local path of the dnsmasq allowlist file. See [`vm_local_config_dir`].
#[must_use]
pub fn vm_local_dns_allowlist_path(name: &str) -> String {
    format!("{}/dns-allowlist.conf", vm_local_config_dir(name))
}

/// VM-local path of the proxy config file. See [`vm_local_config_dir`].
#[must_use]
pub fn vm_local_proxy_config_path(name: &str) -> String {
    format!("{}/proxy-config.yaml", vm_local_config_dir(name))
}

/// VM-local copy of the cage-env dir. See [`vm_local_config_dir`].
#[must_use]
pub fn vm_local_cage_env_dir(name: &str) -> String {
    format!("{}/cage-env", vm_local_config_dir(name))
}

/// VM-local path of `placeholders.env`. See [`vm_local_config_dir`].
#[must_use]
pub fn vm_local_placeholders_env_path(name: &str) -> String {
    format!("{}/placeholders.env", vm_local_cage_env_dir(name))
}

/// VM-local dir of the Policy-API grants overlay.
///
/// Like the other `vm_local_*` paths, this lives OUTSIDE any Lima mount:
/// the in-guest egress addon writes `grants.yaml` here (atomic
/// temp+rename), and the reconcile (`cage grants sync` / `domain list`)
/// pulls it back over `limactl shell` and pushes removals back via
/// base64. Keeping the overlay guest-local avoids Lima's reverse-sshfs
/// host→guest write caching (host-side rewrites of a mounted file would
/// be invisible to the addon's mtime-poll) and keeps the host-side
/// `~/.local/share/agentcage/<name>/grants/` dir operator-owned (never
/// world-writable) — the guest container writes only inside the VM's own
/// filesystem. Returned with the systemd `%h` specifier; see
/// [`vm_local_config_dir`] for why.
#[must_use]
pub fn vm_local_grants_dir(name: &str) -> String {
    format!("{}/grants", vm_local_config_dir(name))
}

/// VM-local path of the grants overlay file. See [`vm_local_grants_dir`].
#[must_use]
pub fn vm_local_grants_file(name: &str) -> String {
    format!("{}/grants.yaml", vm_local_grants_dir(name))
}

/// VM-local dir of the traffic watcher's output (findings + scan state).
///
/// Sibling of the grants overlay INSIDE the guest: the in-egress watcher
/// (`data/proxy/watcher.py`) writes `watcher/findings.jsonl` and
/// `watcher/state.json` next to the overlay on the same guest-local
/// volume, and the host-side `agentcage watcher` CLI pulls them back
/// over `limactl shell` exactly like `pull_grants` does (same
/// guest-local rationale — see [`vm_local_grants_dir`]).
#[must_use]
pub fn vm_local_watcher_dir(name: &str) -> String {
    format!("{}/watcher", vm_local_grants_dir(name))
}

// Note: a `render_dns_quadlet()` helper used to live here for the
// 3-service shape so `domain add` / `domain rm` could regenerate just
// the dns sidecar's quadlet when its `--servers-file` shape changed. In
// the 2-service (cage + egress) shape the dnsmasq allowlist is mounted
// into the egress container at `/etc/agentcage/dns-allowlist.conf` and
// re-read on SIGHUP — the quadlet itself is stable across allowlist
// edits, so the fast path is a uniform `<runtime> exec <name>-egress
// kill -HUP $(cat /home/acdns/dnsmasq.pid)`.

/// Characters that require quoting in systemd `Exec=` lines.
///
/// The Python is `re.compile(r'[\s"\\$%]')`, matched against a `str`, so
/// `\s` is Python's *Unicode* whitespace class. That is Rust's
/// [`char::is_whitespace`] plus the four ASCII information separators
/// `\x1c`–`\x1f`, which Python counts as whitespace and the Unicode
/// `White_Space` property does not.
fn systemd_needs_quote(arg: &str) -> bool {
    arg.chars().any(|c| {
        c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}') || matches!(c, '"' | '\\' | '$' | '%')
    })
}

/// Join a command list into a systemd `Exec=` value.
///
/// Arguments containing spaces or special characters are wrapped in
/// double-quotes with inner `"` and `\` escaped per the systemd exec
/// parsing rules.
///
/// Registered as the `systemd_exec` filter; see [`templates`].
#[must_use]
pub fn systemd_exec_join(args: &[String]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(args.len());
    for arg in args {
        if systemd_needs_quote(arg) {
            let escaped = arg.replace('\\', "\\\\").replace('"', "\\\"");
            parts.push(format!("\"{escaped}\""));
        } else {
            parts.push(arg.clone());
        }
    }
    parts.join(" ")
}

/// The characters Python's `re.escape` backslashes.
///
/// Python 3.7 narrowed `re.escape` to this exact set
/// (`re._special_chars_map`), so escaping "every non-alphanumeric" — the
/// pre-3.7 behaviour and the obvious Rust shortcut — would produce a
/// *different regex string* for a domain containing, say, `_`. The
/// string is what reaches mitmproxy's `--ignore-hosts`, so it is the
/// contract.
const PYTHON_RE_SPECIAL: [char; 24] = [
    '(', ')', '[', ']', '{', '}', '?', '*', '+', '-', '|', '^', '$', '\\', '.', '&', '~', '#', ' ',
    '\t', '\n', '\r', '\u{0b}', '\u{0c}',
];

/// `re.escape`, for the subset of inputs a domain can be.
fn re_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if PYTHON_RE_SPECIAL.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Build a mitmproxy `--ignore-hosts` regex from a list of domains.
///
/// Each domain becomes `^(.+\.)?example\.com(:\d+)?$` so both the bare
/// domain and any subdomain match (with optional port). Multiple domains
/// are OR-joined. mitmproxy matches against `host:port`, so the port
/// suffix is required.
#[must_use]
pub fn passthrough_regex(domains: &[String]) -> String {
    domains
        .iter()
        .map(|domain| format!("^(.+\\.)?{}(:\\d+)?$", re_escape(domain)))
        .collect::<Vec<_>>()
        .join("|")
}

/// DNS host per LLM provider for the egress's own agent calls (the
/// decider and the traffic watcher).
///
/// Kept in sync with the base URLs in `data/proxy/policy_api.py`
/// `_LLM_BASE_URLS` — this is the hostnames-only half, because DNS
/// resolution needs a host while the urllib call needs the full base
/// URL.
const LLM_PROVIDER_DNS_HOSTS: [(&str, &str); 3] = [
    ("anthropic", "api.anthropic.com"),
    ("openai", "api.openai.com"),
    ("openrouter", "openrouter.ai"),
];

/// Merge passthrough + egress-internal hosts into the DNS allowlist.
///
/// These hosts must resolve via upstream DNS (not the sinkhole) because
/// a component *inside the egress* connects to them directly — not
/// through mitmproxy, so the L7 allowlist never sees them and the
/// sinkhole would just break the connection:
///
/// * `passthrough` domains (cage traffic that bypasses TLS interception).
/// * protocol-relay upstream hosts — the relay opens its own socket to
///   the upstream, so it resolves via the egress's dnsmasq. The operator
///   drops these from `domains.allow` so the *cage* can't reach them
///   (only the relay can); but they must still resolve, so they're
///   auto-added here.
/// * the `agents.decider` agent's LLM provider host — the decider calls
///   the model via `urllib` from the addon process, again outside
///   mitmproxy. Without DNS resolution the decider 502s on every
///   request. Same for the traffic watcher.
///
/// Being in the DNS allowlist only makes a host *resolvable*; it does
/// NOT add it to the cage's HTTP allowlist (`DomainInspector`), so the
/// cage still can't reach these hosts over HTTP — only the
/// egress-internal component that needs them can.
///
/// This lives here because it does in Python: `state.save_dns_allowlist`
/// imports it from `quadlets` to build `dns-allowlist.conf`.
#[must_use]
pub fn effective_dns_allowlist(config: &Config) -> Vec<String> {
    if config.domains.mode != "allowlist" {
        return Vec::new();
    }
    let mut merged: Vec<String> = config.domains.allow.clone();
    let push = |host: &str, merged: &mut Vec<String>| {
        if !host.is_empty() && !merged.iter().any(|d| d == host) {
            merged.push(host.to_owned());
        }
    };
    for domain in &config.domains.passthrough {
        push(domain, &mut merged);
    }
    // Protocol-relay upstream hosts.
    for relay in &config.protocol_relays {
        push(&relay.upstream.host, &mut merged);
    }
    // agents.decider's LLM provider host — and the traffic watcher
    // agent's. Both LLMs call their model via urllib from the addon
    // process, outside mitmproxy, so without DNS resolution here every
    // decider adjudication / watcher scan fails. One shared map for both
    // agents (kept in sync with `policy_api._LLM_BASE_URLS` — the
    // DNS-relevant HOST half of it; the full base URLs live there): a
    // provider addition means one edit here, not N inline copies. If the
    // operator set a custom base_url, parse ITS host instead (a
    // self-hosted/proxy endpoint won't be in the provider map).
    for (enable, llm) in [
        (config.agents.decider.enable, &config.agents.decider.llm),
        (config.agents.watcher.enable, &config.agents.watcher.llm),
    ] {
        if !enable {
            continue;
        }
        let base_url = llm.base_url.trim_end_matches('/');
        let host = if base_url.is_empty() {
            let provider = llm.provider.to_lowercase();
            LLM_PROVIDER_DNS_HOSTS
                .iter()
                .find(|(key, _)| *key == provider)
                .map_or(String::new(), |(_, host)| (*host).to_owned())
        } else {
            url_hostname(base_url)
        };
        push(&host, &mut merged);
    }
    merged
}

/// `urllib.parse.urlsplit(url).hostname or ""`, for the http(s) URLs a
/// `base_url` can be.
///
/// Lowercased and with any `user:password@`, port and IPv6 brackets
/// stripped, which is what `.hostname` does. A `base_url` that parses to
/// nothing (no `//`) yields `""`, as it does in Python.
fn url_hostname(url: &str) -> String {
    let after_scheme = match url.split_once("://") {
        Some((_scheme, rest)) => rest,
        // `urlsplit` only finds a netloc after `//`. Without one the
        // whole thing is a path and `.hostname` is None.
        None => match url.strip_prefix("//") {
            Some(rest) => rest,
            None => return String::new(),
        },
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(host, _)| host)
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    host.to_lowercase()
}

/// The three port lists the egress quadlet renders.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortPolicy {
    /// `tcp.allow` minus `tcp.passthrough`, deduped. Becomes one
    /// `nat:PREROUTING` REDIRECT rule per port.
    pub inspected_tcp: Vec<i64>,
    /// `tcp.passthrough`, deduped. Becomes one `filter:FORWARD -p tcp
    /// ACCEPT` per port. Auto-merges into the effective allow set if the
    /// operator didn't list it in `tcp.allow`.
    pub passthrough_tcp: Vec<i64>,
    /// `udp.allow`, deduped. Becomes one `filter:FORWARD -p udp ACCEPT`
    /// per port. UDP is never inspected.
    pub allow_udp: Vec<i64>,
}

/// Resolve the nested ports config into the three lists rendered into
/// the proxy quadlet, preserving operator-supplied order.
#[must_use]
pub fn effective_port_policy(config: &Config) -> PortPolicy {
    let passthrough: std::collections::BTreeSet<i64> =
        config.ports.tcp.passthrough.iter().copied().collect();
    PortPolicy {
        inspected_tcp: dedup(&config.ports.tcp.allow, |port| !passthrough.contains(port)),
        passthrough_tcp: dedup(&config.ports.tcp.passthrough, |_| true),
        allow_udp: dedup(&config.ports.udp.allow, |_| true),
    }
}

/// Order-preserving dedup with a per-item filter.
fn dedup(ports: &[i64], keep: impl Fn(&i64) -> bool) -> Vec<i64> {
    let mut seen = std::collections::BTreeSet::new();
    ports
        .iter()
        .filter(|port| keep(port) && seen.insert(**port))
        .copied()
        .collect()
}

/// Base64-encode `value` for safe embedding in a systemd `Exec` line.
///
/// Standard alphabet with padding — `base64.b64encode`. Hand-rolled
/// rather than pulled in as a dependency: it is a 30-line transcription
/// of a fixed table with no security role here (the encoding exists so
/// a path survives systemd's quoting *and* bash's, not to hide
/// anything), and the golden corpus checks every byte it produces.
#[must_use]
pub fn b64(value: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).map_or(0, |b| u32::from(*b));
        let b2 = chunk.get(2).map_or(0, |b| u32::from(*b));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        b64, cage_network_addrs, effective_port_policy, passthrough_regex, systemd_exec_join,
        url_hostname,
    };
    use crate::config::{Config, FixedHost, load};

    fn config_from(yaml: &str) -> Config {
        load("cage.yaml", yaml, &FixedHost::linux(&["192.0.2.53"])).expect("valid config")
    }

    /// `tests/test_quadlets.py::test_systemd_exec_join*`.
    #[test]
    fn systemd_exec_quotes_only_what_needs_it() {
        let args =
            |items: &[&str]| -> Vec<String> { items.iter().map(|s| (*s).to_owned()).collect() };
        assert_eq!(
            systemd_exec_join(&args(&["sleep", "infinity"])),
            "sleep infinity"
        );
        assert_eq!(
            systemd_exec_join(&args(&["bash", "-c", "echo hello world"])),
            "bash -c \"echo hello world\""
        );
        assert_eq!(
            systemd_exec_join(&args(&["echo", "say \"hi\""])),
            "echo \"say \\\"hi\\\"\""
        );
        assert_eq!(
            systemd_exec_join(&args(&["echo", "a\\b"])),
            "echo \"a\\\\b\""
        );
        // `%` is a systemd specifier introducer, `$` an environment
        // reference: both are quoted even without whitespace.
        assert_eq!(systemd_exec_join(&args(&["echo", "100%"])), "echo \"100%\"");
        assert_eq!(
            systemd_exec_join(&args(&["echo", "$HOME"])),
            "echo \"$HOME\""
        );
        assert_eq!(systemd_exec_join(&[]), "");
    }

    /// `tests/test_quadlets.py::TestPassthroughRegex`.
    #[test]
    fn passthrough_regex_matches_the_python() {
        let domains =
            |items: &[&str]| -> Vec<String> { items.iter().map(|s| (*s).to_owned()).collect() };
        assert_eq!(
            passthrough_regex(&domains(&["whatsapp.com"])),
            r"^(.+\.)?whatsapp\.com(:\d+)?$"
        );
        assert_eq!(
            passthrough_regex(&domains(&["whatsapp.com", "signal.org"])),
            r"^(.+\.)?whatsapp\.com(:\d+)?$|^(.+\.)?signal\.org(:\d+)?$"
        );
        assert_eq!(passthrough_regex(&[]), "");
        // A hyphen is in `re._special_chars_map`, so Python escapes it
        // even outside a character class.
        assert_eq!(
            passthrough_regex(&domains(&["my-host.example.com"])),
            r"^(.+\.)?my\-host\.example\.com(:\d+)?$"
        );
        // An underscore is not, which is where "escape everything
        // non-alphanumeric" would diverge.
        assert_eq!(
            passthrough_regex(&domains(&["a_b.example"])),
            r"^(.+\.)?a_b\.example(:\d+)?$"
        );
    }

    /// The octet is MD5-derived and must not move: a deployed cage's
    /// podman network is pinned to the one Python computed.
    #[test]
    fn network_addrs_reproduce_the_python_hash() {
        let addrs = cage_network_addrs("test", None, None).expect("allocates");
        // md5("test") = 098f6bcd…, and 0x098f6bcd % 254 + 1 = 48.
        assert_eq!(addrs.subnet, "10.89.48.0/24");
        assert_eq!(addrs.ip_cage, "10.89.48.2");
        assert_eq!(addrs.ip_egress, "10.89.48.10");
        assert_eq!(addrs.octet(), 48);
    }

    #[test]
    fn a_pinned_octet_bypasses_the_hash_and_the_collision_walk() {
        let used = (1..=254).collect::<std::collections::BTreeSet<u32>>();
        let addrs = cage_network_addrs("test", Some(&used), Some(7)).expect("pinned");
        assert_eq!(addrs.subnet, "10.89.7.0/24");
    }

    #[test]
    fn a_full_subnet_table_is_a_runtime_error() {
        let used = (1..=254).collect::<std::collections::BTreeSet<u32>>();
        let error = cage_network_addrs("test", Some(&used), None).expect_err("no slots");
        assert_eq!(
            error.as_python_traceback_line(),
            "RuntimeError: All 254 subnet slots are in use — cannot allocate a new cage network"
        );
    }

    #[test]
    fn a_collision_walks_to_the_next_free_slot() {
        let used = [48u32]
            .into_iter()
            .collect::<std::collections::BTreeSet<u32>>();
        let addrs = cage_network_addrs("test", Some(&used), None).expect("allocates");
        assert_eq!(addrs.subnet, "10.89.49.0/24");
    }

    #[test]
    fn base64_matches_python() {
        assert_eq!(b64(""), "");
        assert_eq!(b64("a"), "YQ==");
        assert_eq!(b64("ab"), "YWI=");
        assert_eq!(b64("abc"), "YWJj");
        assert_eq!(b64("/home/luca/project\n"), "L2hvbWUvbHVjYS9wcm9qZWN0Cg==");
        // Non-ASCII goes through as UTF-8, as `value.encode()` does.
        assert_eq!(b64("é"), "w6k=");
    }

    #[test]
    fn hostname_parsing_follows_urlsplit() {
        assert_eq!(
            url_hostname("https://api.example.com/v1"),
            "api.example.com"
        );
        assert_eq!(url_hostname("https://API.Example.COM"), "api.example.com");
        assert_eq!(
            url_hostname("http://user:pw@host.example:8080/x"),
            "host.example"
        );
        assert_eq!(url_hostname("https://[2001:db8::1]:443/v1"), "2001:db8::1");
        assert_eq!(url_hostname("not-a-url"), "");
    }

    /// `inspected = allow − passthrough`, each list deduped, all three
    /// in operator order.
    #[test]
    fn port_policy_subtracts_and_dedupes_in_order() {
        let config = config_from(
            "name: p\ncontainer:\n  image: busybox\nports:\n  tcp:\n    allow: [443, 80, 443, 1143]\n    passthrough: [1143, 1143]\n  udp:\n    allow: [53, 53, 123]\n",
        );
        let policy = effective_port_policy(&config);
        assert_eq!(policy.inspected_tcp, vec![443, 80]);
        assert_eq!(policy.passthrough_tcp, vec![1143]);
        assert_eq!(policy.allow_udp, vec![53, 123]);
    }
}
