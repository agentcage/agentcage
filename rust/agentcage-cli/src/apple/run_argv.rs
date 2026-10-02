//! The two `container run` argvs `start()` builds.
//!
//! Pulled out of the lifecycle so they can be asserted without a Mac.
//! Everything host-shaped — the resolved state directories, the egress
//! sibling's address, whether a bind source is a directory — arrives as
//! an argument, so both functions are values in and a `Vec<String>`
//! out. That is the same split the generation half of this backend got
//! (RUST-PORT-PLAN.md Track E), applied to the half that needs
//! hardware: the hardware is needed to *run* the argv, not to decide
//! what it should be.
//!
//! # Why the order is asserted and not just the contents
//!
//! Two reasons. Apple's `container run --tmpfs` takes a bare path and
//! nothing else, so the only way a mask and the bind it overlays can be
//! told apart is their position; and the cage's `--volume` for an `np`
//! bind must precede the `--tmpfs` that covers it or the seeded copy is
//! shadowed. The runtime happens to sort mounts by destination depth
//! before applying them — `cleanAndSortMounts` in containerization's
//! `LinuxContainer.swift` — so argv order is not what decides the
//! mount order, but it is what makes the argv readable *in* mount
//! order, and a reordering here is a change worth seeing in a diff.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use agentcage_core::apple::{normalize_cpus, normalize_memory};
use agentcage_core::volume_mounts::{is_non_persistent_volume, split_volume_spec};

use super::meta::Meta;
use super::volumes::CopyupSeed;

/// The capability set the egress microVM runs with.
///
/// Mirrors `templates/egress.container.j2`:
///
/// | Capability | Why |
/// | :-- | :-- |
/// | `NET_ADMIN` | the supervisor's iptables `PREROUTING` REDIRECT and `FORWARD` chain |
/// | `NET_BIND_SERVICE` | dnsmasq on `:53`; the image `setcap`s the binary, and a file capability still needs the bounding set to permit it |
/// | `SETUID` + `SETGID` | the supervisor's `setpriv --reuid/--regid` drop to `acdns` (201) and `acproxy` (200) |
/// | `SETPCAP` | `setpriv --bounding-set`, which strips the children's `CapBnd` |
/// | `KILL` | the supervisor is root and polls its own cross-uid children with `kill -0` |
///
/// The earlier list of just the first two relied on the runtime's
/// default set carrying the rest. Rootless podman on a host with
/// `default_capabilities = []` drops them all and the supervisor died
/// at its first `setpriv`; Apple's runtime has not reproduced that, and
/// being explicit costs nothing and survives a future tightening.
const EGRESS_CAPS: [&str; 6] = [
    "CAP_NET_ADMIN",
    "CAP_NET_BIND_SERVICE",
    "CAP_SETUID",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_KILL",
];

/// The egress microVM's memory cap.
///
/// Not normalized, unlike the cage's: the value is internal, not
/// operator-supplied.
const EGRESS_MEMORY: &str = "512M";

/// What [`egress_argv`] needs from the host.
#[derive(Clone, Debug)]
pub struct EgressPaths<'a> {
    /// `logs_dir(name)` → `/var/log/agentcage`.
    pub logs: &'a Path,
    /// `certs_dir(name)` → `/home/acproxy/.mitmproxy`. Holds the CA
    /// **private** key, so it is mounted into this VM and no other.
    pub certs: &'a Path,
    /// `public_certs_dir(name)` → `/home/acproxy/public-certs`.
    pub public_certs: &'a Path,
    /// `egress_config_dir(name)`; three files under it are mounted
    /// individually, read-only.
    pub egress_config: &'a Path,
    /// `secrets_dir(name)`, when it exists and has at least one file.
    ///
    /// `None` when it is empty: an empty bind would shadow the egress
    /// image's own empty `/home/acproxy/secrets` with a host directory
    /// for no gain.
    pub secrets: Option<&'a Path>,
    /// `state.grants_dir(name)`, when the grants overlay is on.
    ///
    /// The canonical agentcage data path, **not** this backend's state
    /// root: the egress addon writes decided grants there and a shared
    /// legacy-cleanup helper still reads it, so the source has to be
    /// that exact location.
    pub grants: Option<&'a Path>,
}

/// `start()` step 2 — the egress sibling's `container run` argv.
///
/// `--kernel-arg sysctl.net.ipv4.ip_forward=1` is the first flag after
/// the name and it is load-bearing (origin: #407). The egress routes
/// between the cage and the host bridge, so `supervisor-egress.sh` step
/// A hard-fails without `ip_forward` — and neither route that works on
/// the other backends is available here. Apple's runtime mounts
/// `/proc/sys` read-only, so the supervisor's `sysctl -w` fails even as
/// uid 0 with `CAP_SYS_ADMIN`; and `container run` has no `--sysctl`,
/// so there is no create-time equivalent of the Quadlet `Sysctl=`.
/// Linux 5.8+ accepts `sysctl.<name>=<value>` on the kernel command
/// line, which `--kernel-arg` can set. Without it the symptom is total
/// loss of connectivity inside the cage — the egress IP is both the
/// cage's default gateway and its dnsmasq upstream — rather than a
/// proxy error, which is what made it expensive to diagnose.
///
/// The other sysctl `egress.container.j2` sets,
/// `net.ipv4.ip_unprivileged_port_start=80`, is deliberately **not**
/// carried: on the Quadlet path it exists only for the reverse-mode
/// inbound forwards this backend never stages, and here mitmproxy binds
/// `:8080` and `:8443`, both already unprivileged, while dnsmasq gets
/// `:53` from its file capability plus the bounding-set entry above.
#[must_use]
pub fn egress_argv(
    name: &str,
    network: &str,
    image: &str,
    version: &str,
    meta: &Meta,
    paths: &EgressPaths<'_>,
) -> Vec<String> {
    let mut argv = argv![
        "run",
        "-d",
        "--name",
        &format!("{name}-egress"),
        "--kernel-arg",
        "sysctl.net.ipv4.ip_forward=1",
    ];
    for capability in EGRESS_CAPS {
        argv.push("--cap-add".to_owned());
        argv.push(capability.to_owned());
    }
    argv.push("--network".to_owned());
    argv.push(network.to_owned());
    for (source, target) in [
        (paths.logs, "/var/log/agentcage"),
        (paths.certs, "/home/acproxy/.mitmproxy"),
        (paths.public_certs, "/home/acproxy/public-certs"),
    ] {
        argv.push("--volume".to_owned());
        argv.push(format!("{}:{target}", source.display()));
    }
    argv.push("-e".to_owned());
    argv.push(format!("AGENTCAGE_VERSION={version}"));
    // The upstreams for policy-api granted zones. Same env as
    // `egress.container.j2`; the baseline is empty under default-deny,
    // so the supervisor cannot scrape them out of it.
    argv.push("-e".to_owned());
    argv.push(format!(
        "AGENTCAGE_DNS_UPSTREAMS={}",
        meta.strings("dns_servers").join(" ")
    ));
    for file in ["proxy-config.yaml", "dnsmasq.conf", "dns-allowlist.conf"] {
        let target = if file == "proxy-config.yaml" {
            "/etc/agentcage/config.yaml"
        } else {
            // dnsmasq.conf and dns-allowlist.conf keep their names.
            &format!("/etc/agentcage/{file}")
        };
        argv.push("--volume".to_owned());
        argv.push(format!(
            "{}/{file}:{target}:ro",
            paths.egress_config.display()
        ));
    }
    if let Some(secrets) = paths.secrets {
        argv.push("--volume".to_owned());
        argv.push(format!("{}:/home/acproxy/secrets:ro", secrets.display()));
    }
    if let Some(grants) = paths.grants {
        argv.push("--volume".to_owned());
        argv.push(format!("{}:/var/lib/agentcage", grants.display()));
        argv.push("-e".to_owned());
        argv.push("AGENTCAGE_GRANTS_DIR=/var/lib/agentcage".to_owned());
    }
    argv.extend(argv![
        "-e",
        "AGENTCAGE_CONFIG=/etc/agentcage/config.yaml",
        "-e",
        "AGENTCAGE_AUDIT_LOG=/var/log/agentcage/audit.jsonl",
        "-e",
        "AGENTCAGE_CAPTURE=/var/log/agentcage/capture.jsonl",
    ]);
    // The port policy `generate_units` persisted. `supervisor-egress.sh`
    // step A turns these into iptables rules: inspected TCP into a
    // `nat:PREROUTING` REDIRECT to mitmproxy, passthrough TCP into a
    // `FORWARD` ACCEPT that skips inspection, allowed UDP into a UDP
    // `FORWARD` ACCEPT.
    //
    // `INSPECTED_TCP_PORTS` must be set **explicitly**, empty included:
    // the supervisor falls back to `80 443` only when the variable is
    // unset, so a cage that narrows its inspected set is only honoured
    // if the narrowing arrives as an empty value rather than as an
    // absent one.
    argv.push("-e".to_owned());
    argv.push(format!(
        "INSPECTED_TCP_PORTS={}",
        joined(&meta.ports("inspected_tcp_ports"))
    ));
    argv.push("-e".to_owned());
    argv.push(format!(
        "PASSTHROUGH_TCP_PORTS={}",
        joined(&meta.ports("passthrough_tcp_ports"))
    ));
    // CTF F2 (0.22.6): the cage's own dnsmasq queries its upstreams over
    // UDP :53, and those packets route through the egress — the cage's
    // default gateway. `supervisor-egress.sh` sets the `FORWARD` policy
    // to DROP and only ACCEPTs the UDP ports named here, so without 53
    // the cage's dnsmasq sees every forwarder time out and answers
    // SERVFAIL, allowlisted apexes included. It is unioned in rather
    // than required of the operator, and appended rather than sorted so
    // their own order survives.
    let mut udp = meta.ports("allow_udp_ports");
    if !udp.contains(&53) {
        udp.push(53);
    }
    argv.push("-e".to_owned());
    argv.push(format!("ALLOW_UDP_PORTS={}", joined(&udp)));
    // Outbound ICMP echo-request, off unless `ports.icmp.allow` opted
    // in. Metadata written before this knob existed has no key, which
    // reads as 0 — the supervisor's own locked-down default.
    argv.push("-e".to_owned());
    argv.push(format!(
        "ALLOW_ICMP={}",
        u8::from(meta.truthy("allow_icmp"))
    ));
    argv.push("--memory".to_owned());
    argv.push(EGRESS_MEMORY.to_owned());
    argv.push(image.to_owned());
    argv
}

/// What [`cage_argv`] needs from the host and from the staging that ran
/// before it.
#[derive(Clone, Debug)]
pub struct CageInputs<'a> {
    /// `public_certs_dir(name)` → `/certs:ro`. The public cert and
    /// nothing else; see [`EgressPaths::certs`] for the other half.
    pub public_certs: &'a Path,
    /// `egress_config_dir(name)`; two files under it are mounted.
    pub egress_config: &'a Path,
    /// The egress sibling's address, for `cage-init.sh`'s default route.
    pub egress_ip: &'a str,
    /// The secret envs `_stage_secrets` actually wrote a value for.
    pub staged_envs: &'a BTreeSet<String>,
    /// env → placeholder, the live config's merged over the metadata's.
    pub placeholders: &'a BTreeMap<String, String>,
    /// `_user_volume_argv(meta["volumes"])` — absolute, revalidated.
    pub volume_entries: &'a [String],
    /// `_tmpfs_copyup_seeds(...)`.
    pub copyup_seeds: &'a [CopyupSeed],
}

/// `start()` step 5 — the cage microVM's `container run` argv.
///
/// `CAP_NET_ADMIN` is added because `cage-init.sh` needs `ip route
/// replace default via <egress ip>`. It does not survive to the
/// workload: capsh drops it before the user's CMD runs, and an exec
/// session does not re-acquire it either, because Apple's runtime hands
/// exec sessions only the default OCI set. The cage VM gets **no**
/// secrets bind and **no** proxy config bind.
///
/// `is_dir` answers `os.path.isdir(host_src)` for an `np` bind's
/// source. It decides whether the `--tmpfs` that covers the target is
/// emitted at all, so a caller that answers it wrongly produces a cage
/// whose non-persistent mount is persistent.
//
// Long for the same reason [`egress_argv`] is: it is one argv, built in
// mount order, and the order is part of the contract (see the module
// docs). Splitting it would scatter the comments that say *why* each
// flag is where it is.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn cage_argv(
    name: &str,
    network: &str,
    image: &str,
    version: &str,
    meta: &Meta,
    inputs: &CageInputs<'_>,
    is_dir: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    let mut argv = argv![
        "run",
        "-d",
        "--name",
        name,
        "--cap-add",
        "CAP_NET_ADMIN",
        "--network",
        network,
    ];
    // CTF F1 (0.22.5): this used to bind `certs_dir`, which holds
    // `mitmproxy-ca.pem` — the CA *private* key. A uid-1000 workload
    // that can read it can mint a trusted certificate for any
    // allowlisted host. It binds `public_certs_dir` now, where the
    // egress supervisor's step E copies only the public cert.
    //
    // CTF #275 (0.25.4): `:ro`, so the workload can read the CA it is
    // told to trust and cannot replace it or persist anything under
    // `/certs`. The quadlet backend's `cage.container.j2` says
    // `:/certs:ro,Z` for the same reason.
    argv.push("--volume".to_owned());
    argv.push(format!("{}:/certs:ro", inputs.public_certs.display()));
    // CTF F2 (0.22.6): the cage resolves through a dnsmasq of its own,
    // started by `cage-init.sh` stage A' against the same
    // allowlist-scoped config the egress uses. macOS vmnet drops
    // inter-microVM UDP — `NonisolatedInterfaceStrategy.swift` runs the
    // interface in `VMNET_SHARED_MODE`, i.e. NAT — so the cage cannot
    // reach the egress's dnsmasq on `.2:53`, and a local resolver
    // scoped to the same config is the only fix.
    for file in ["dnsmasq.conf", "dns-allowlist.conf"] {
        argv.push("--volume".to_owned());
        argv.push(format!(
            "{}/{file}:/etc/agentcage/{file}:ro",
            inputs.egress_config.display()
        ));
    }
    argv.extend(argv![
        "-e",
        &format!("AGENTCAGE_EGRESS_IP={}", inputs.egress_ip),
        "-e",
        "AGENTCAGE_DNS_SERVERS_FILE=/etc/agentcage/dns-allowlist.conf",
        // Point HTTPS clients at the proxy CA immediately, without
        // waiting for `cage-init.sh` stage C to copy it into
        // /usr/local/share/ca-certificates and run
        // update-ca-certificates. curl reads SSL_CERT_FILE and Node
        // reads NODE_EXTRA_CA_CERTS; together they cover the agents
        // agentcage actually ships. `cage.container.j2` does the same.
        // Without it, claude-code 2.1.x exits 0 from `-p` when its
        // HTTPS call fails verification, which looks like success.
        "-e",
        "SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem",
        "-e",
        "NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem",
        // So an agent can tell it is sandboxed, and which version by.
        "-e",
        &format!("AGENTCAGE_VERSION={version}"),
    ]);
    for (key, value) in meta.map("env") {
        argv.push("-e".to_owned());
        argv.push(format!("{key}={value}"));
    }
    // The PLACEHOLDER, never the value. The workload sees `{{API_KEY}}`
    // in its environment and the egress addon substitutes the real
    // value on the wire. An env with no staged value gets no `-e` at
    // all, so the placeholder cannot reach upstream as a literal.
    for env_name in inputs.staged_envs {
        let Some(placeholder) = inputs.placeholders.get(env_name) else {
            continue;
        };
        if placeholder.is_empty() {
            continue;
        }
        argv.push("-e".to_owned());
        argv.push(format!("{env_name}={placeholder}"));
    }
    // User binds. A bind carrying the inline `np` flag is read from a
    // read-only lowerdir and copied to a tmpfs at the target it asked
    // for; everything else passes through unchanged.
    let mut copies: Vec<String> = Vec::new();
    let mut np_tmpfs_targets: BTreeSet<String> = BTreeSet::new();
    for (index, entry) in inputs.volume_entries.iter().enumerate() {
        let (host_source, target, _options) = split_volume_spec(entry);
        if target.is_empty() {
            continue;
        }
        if !is_non_persistent_volume(entry) {
            argv.push("--volume".to_owned());
            argv.push(entry.clone());
            continue;
        }
        let lower = format!("/run/agentcage/mounts/vol-{index}/lower");
        argv.push("--volume".to_owned());
        argv.push(format!("{host_source}:{lower}:ro"));
        if is_dir(host_source) {
            // Apple's `--tmpfs` takes a bare path; Docker's
            // `path:opts` spelling is read literally.
            argv.push("--tmpfs".to_owned());
            argv.push(target.to_owned());
            let normalized = target.trim_end_matches('/');
            np_tmpfs_targets.insert(if normalized.is_empty() {
                "/".to_owned()
            } else {
                normalized.to_owned()
            });
        }
        copies.push(format!("{lower}\t{target}"));
    }
    if !copies.is_empty() {
        argv.push("-e".to_owned());
        argv.push(format!(
            "AGENTCAGE_NONPERSISTENT_COPIES={}",
            copies.join("\n")
        ));
    }
    // The operator's own `container.tmpfs:` masks (#318, the tmpfs half
    // of the #120 parity gap). Before 0.32 they were dropped on this
    // backend, which silently disabled the claude-code scaffold's #170
    // `/workspace/.git/hooks/` and #173 `/workspace/.claude/` masks —
    // on the one backend macOS picks by default.
    for target in super::volumes::tmpfs_targets(&meta.strings("tmpfs")).targets {
        // An `np` bind already owns this target with a tmpfs seeded
        // from its lowerdir. A second `--tmpfs` would be a duplicate
        // destination that Apple dedupes anyway; skipping it keeps the
        // seeded copy from being masked by an empty mount on a runtime
        // that decided to keep both.
        if np_tmpfs_targets.contains(&target) {
            continue;
        }
        argv.push("--tmpfs".to_owned());
        argv.push(target);
    }
    // Emulated `tmpcopyup` (#328). Apple's `--tmpfs` has no option
    // channel, so a mask that asked for copy-up gets the directory it
    // covers mounted read-only alongside it, and `cage-init.sh` stage
    // C'' replays that into the tmpfs as the cage user. The read-only
    // lower is the only new host-facing mount and is never written to,
    // so the mask still blocks every cage→host write.
    for seed in inputs.copyup_seeds {
        argv.push("--volume".to_owned());
        argv.push(format!("{}:{}:ro", seed.host_source, seed.lower));
    }
    if !inputs.copyup_seeds.is_empty() {
        argv.push("-e".to_owned());
        argv.push(format!(
            "AGENTCAGE_TMPFS_COPYUP={}",
            inputs
                .copyup_seeds
                .iter()
                .map(|seed| format!("{}\t{}", seed.lower, seed.target))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    // Resources. `container.cpus` / `container.memory` win over
    // `vm.vcpus` / `vm.mem_mb`, which `generate_units` already resolved
    // into `cpus` / `memory`; `mem_mb` is the pre-0.20.6 metadata
    // fallback and is still read because a cage last deployed by that
    // version has it and nothing else.
    let cpus = meta.get("cpus").map(scalar_text).unwrap_or_default();
    if !cpus.is_empty() && cpus != "0" {
        argv.push("--cpus".to_owned());
        argv.push(normalize_cpus(&cpus));
    }
    let memory = meta.get("memory").map(scalar_text).unwrap_or_default();
    if memory.is_empty() {
        let legacy = meta.get("mem_mb").map(scalar_text).unwrap_or_default();
        if !legacy.is_empty() && legacy != "0" {
            argv.push("--memory".to_owned());
            argv.push(format!("{legacy}M"));
        }
    } else {
        argv.push("--memory".to_owned());
        argv.push(normalize_memory(&memory));
    }
    argv.push(image.to_owned());
    argv
}

/// `str(value)` for the scalar metadata fields, which have been written
/// as both numbers and strings across versions.
fn scalar_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// `" ".join(str(p) for p in ports)`.
fn joined(ports: &[u32]) -> String {
    ports
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

/// `vec!` for argv, without the `.to_owned()` at every element.
macro_rules! argv {
    ($($item:expr),* $(,)?) => {
        vec![$(::std::string::ToString::to_string($item)),*]
    };
}
use argv;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use super::super::meta::Meta;
    use super::{CageInputs, EgressPaths, cage_argv, egress_argv};

    /// The flag and its value, as a pair, for every `-e`/`--volume`
    /// style argument. Asserting on pairs rather than on a flat list is
    /// what makes a failure say *which* mount moved.
    fn pairs(argv: &[String], flag: &str) -> Vec<String> {
        argv.windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].clone())
            .collect()
    }

    fn meta(text: &str) -> Meta {
        Meta::parse(text).expect("valid JSON")
    }

    fn egress_paths() -> EgressPaths<'static> {
        EgressPaths {
            logs: Path::new("/s/logs"),
            certs: Path::new("/s/certs"),
            public_certs: Path::new("/s/public-certs"),
            egress_config: Path::new("/s/egress-config"),
            secrets: None,
            grants: None,
        }
    }

    /// #407, which is the whole reason this backend works at all: the
    /// egress is a router, `supervisor-egress.sh` step A hard-fails
    /// without `ip_forward`, and Apple's runtime offers no other way to
    /// set it. Its absence costs total connectivity inside the cage.
    #[test]
    fn the_egress_carries_the_ip_forward_kernel_arg() {
        let argv = egress_argv(
            "demo",
            "demo-net",
            "img",
            "9.9.9",
            &meta("{}"),
            &egress_paths(),
        );
        assert_eq!(
            pairs(&argv, "--kernel-arg"),
            vec!["sysctl.net.ipv4.ip_forward=1".to_owned()]
        );
    }

    /// Six capabilities, in order. The list is mirrored from
    /// `egress.container.j2` and a quiet loss of `SETPCAP` or `KILL`
    /// breaks the supervisor's drop chain rather than the proxy, so the
    /// symptom would not point here.
    #[test]
    fn the_egress_cap_set_is_the_quadlets() {
        let argv = egress_argv(
            "demo",
            "demo-net",
            "img",
            "9.9.9",
            &meta("{}"),
            &egress_paths(),
        );
        assert_eq!(
            pairs(&argv, "--cap-add"),
            vec![
                "CAP_NET_ADMIN",
                "CAP_NET_BIND_SERVICE",
                "CAP_SETUID",
                "CAP_SETGID",
                "CAP_SETPCAP",
                "CAP_KILL",
            ]
        );
    }

    /// `INSPECTED_TCP_PORTS` has to be *present and empty* rather than
    /// absent: the supervisor falls back to `80 443` only when the
    /// variable is unset, so an absent one silently widens a cage that
    /// asked to inspect nothing.
    #[test]
    fn an_empty_inspected_set_is_still_passed_explicitly() {
        let argv = egress_argv(
            "demo",
            "demo-net",
            "img",
            "9.9.9",
            &meta(r#"{"inspected_tcp_ports": []}"#),
            &egress_paths(),
        );
        assert!(
            pairs(&argv, "-e").contains(&"INSPECTED_TCP_PORTS=".to_owned()),
            "{argv:?}"
        );
    }

    /// CTF F2: 53 is unioned in whatever the operator said, because the
    /// cage's own dnsmasq forwards over UDP :53 *through* the egress and
    /// the FORWARD policy is DROP. Appended, not sorted — the
    /// operator's order survives.
    #[test]
    fn udp_53_is_unioned_in_without_reordering() {
        let argv = egress_argv(
            "demo",
            "demo-net",
            "img",
            "9.9.9",
            &meta(r#"{"allow_udp_ports": [443, 123]}"#),
            &egress_paths(),
        );
        assert!(
            pairs(&argv, "-e").contains(&"ALLOW_UDP_PORTS=443 123 53".to_owned()),
            "{argv:?}"
        );

        // Already present: not duplicated, and not moved.
        let argv = egress_argv(
            "demo",
            "demo-net",
            "img",
            "9.9.9",
            &meta(r#"{"allow_udp_ports": [53, 443]}"#),
            &egress_paths(),
        );
        assert!(
            pairs(&argv, "-e").contains(&"ALLOW_UDP_PORTS=53 443".to_owned()),
            "{argv:?}"
        );
    }

    /// The CA *private* key goes to the egress and nowhere else. The
    /// cage gets the public-only directory, read-only. This is CTF F1
    /// and #275, and it is the one assertion in this file that is a
    /// security boundary rather than a compatibility one.
    #[test]
    fn the_private_ca_reaches_the_egress_and_never_the_cage() {
        let egress = egress_argv(
            "demo",
            "demo-net",
            "img",
            "9.9.9",
            &meta("{}"),
            &egress_paths(),
        );
        assert!(
            pairs(&egress, "--volume").contains(&"/s/certs:/home/acproxy/.mitmproxy".to_owned()),
            "{egress:?}"
        );

        let staged = BTreeSet::new();
        let placeholders = BTreeMap::new();
        let cage = cage_argv(
            "demo",
            "demo-net",
            "img",
            "9.9.9",
            &meta("{}"),
            &CageInputs {
                public_certs: Path::new("/s/public-certs"),
                egress_config: Path::new("/s/egress-config"),
                egress_ip: "10.0.0.2",
                staged_envs: &staged,
                placeholders: &placeholders,
                volume_entries: &[],
                copyup_seeds: &[],
            },
            &|_| true,
        );
        let mounts = pairs(&cage, "--volume");
        assert!(
            mounts.contains(&"/s/public-certs:/certs:ro".to_owned()),
            "{mounts:?}"
        );
        assert!(
            !mounts.iter().any(|m| m.contains("/s/certs:")),
            "the cage was handed the private CA directory: {mounts:?}"
        );
        assert!(
            !mounts.iter().any(|m| m.contains("secrets")),
            "the cage was handed a secrets mount: {mounts:?}"
        );
    }

    /// A staged secret reaches the cage as its **placeholder**. One
    /// without a placeholder gets no `-e` at all, so a bare token
    /// cannot leak upstream as a literal string.
    #[test]
    fn only_placeholders_reach_the_cage_and_only_with_one() {
        let staged: BTreeSet<String> = ["API_KEY", "NO_PLACEHOLDER"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let placeholders: BTreeMap<String, String> =
            [("API_KEY".to_owned(), "{{API_KEY}}".to_owned())]
                .into_iter()
                .collect();
        let argv = cage_argv(
            "demo",
            "demo-net",
            "img",
            "9.9.9",
            &meta("{}"),
            &CageInputs {
                public_certs: Path::new("/s/public-certs"),
                egress_config: Path::new("/s/egress-config"),
                egress_ip: "10.0.0.2",
                staged_envs: &staged,
                placeholders: &placeholders,
                volume_entries: &[],
                copyup_seeds: &[],
            },
            &|_| true,
        );
        let envs = pairs(&argv, "-e");
        assert!(envs.contains(&"API_KEY={{API_KEY}}".to_owned()), "{envs:?}");
        assert!(
            !envs.iter().any(|e| e.starts_with("NO_PLACEHOLDER=")),
            "an env with no placeholder was passed: {envs:?}"
        );
    }

    /// An `np` bind becomes a read-only lowerdir plus a tmpfs at the
    /// requested target, and the user's `container.tmpfs` entry for the
    /// *same* target is dropped rather than emitted twice — a second
    /// `--tmpfs` would mask the seeded copy on a runtime that kept
    /// both.
    #[test]
    fn a_non_persistent_bind_is_not_masked_twice() {
        let staged = BTreeSet::new();
        let placeholders = BTreeMap::new();
        let volumes = vec!["/home/luca/proj:/workspace:np".to_owned()];
        let argv = cage_argv(
            "demo",
            "demo-net",
            "img",
            "9.9.9",
            &meta(r#"{"tmpfs": ["/workspace", "/tmp/scratch"]}"#),
            &CageInputs {
                public_certs: Path::new("/s/public-certs"),
                egress_config: Path::new("/s/egress-config"),
                egress_ip: "10.0.0.2",
                staged_envs: &staged,
                placeholders: &placeholders,
                volume_entries: &volumes,
                copyup_seeds: &[],
            },
            &|_| true,
        );
        assert!(
            pairs(&argv, "--volume")
                .contains(&"/home/luca/proj:/run/agentcage/mounts/vol-0/lower:ro".to_owned()),
            "{argv:?}"
        );
        let masks = pairs(&argv, "--tmpfs");
        assert_eq!(
            masks.iter().filter(|m| *m == "/workspace").count(),
            1,
            "the np target was masked twice: {masks:?}"
        );
        assert!(masks.contains(&"/tmp/scratch".to_owned()), "{masks:?}");
        assert!(
            pairs(&argv, "-e").iter().any(|e| e
                == "AGENTCAGE_NONPERSISTENT_COPIES=/run/agentcage/mounts/vol-0/lower\t/workspace"),
            "{argv:?}"
        );
    }

    /// A source that is not a directory gets the lowerdir but no
    /// tmpfs — the copy has nothing to land in, and Apple's `--tmpfs`
    /// over a file target would be a different mount than asked for.
    #[test]
    fn a_non_directory_np_source_gets_no_tmpfs() {
        let staged = BTreeSet::new();
        let placeholders = BTreeMap::new();
        let volumes = vec!["/home/luca/file.txt:/workspace/file.txt:np".to_owned()];
        let argv = cage_argv(
            "demo",
            "demo-net",
            "img",
            "9.9.9",
            &meta("{}"),
            &CageInputs {
                public_certs: Path::new("/s/public-certs"),
                egress_config: Path::new("/s/egress-config"),
                egress_ip: "10.0.0.2",
                staged_envs: &staged,
                placeholders: &placeholders,
                volume_entries: &volumes,
                copyup_seeds: &[],
            },
            &|_| false,
        );
        assert!(pairs(&argv, "--tmpfs").is_empty(), "{argv:?}");
    }

    /// `container.memory`/`cpus` win, `mem_mb` is the pre-0.20.6
    /// fallback, and both go through Apple's stricter normalization.
    #[test]
    fn resources_are_normalized_and_the_legacy_key_is_a_fallback() {
        let run = |json: &str| {
            let staged = BTreeSet::new();
            let placeholders = BTreeMap::new();
            cage_argv(
                "demo",
                "demo-net",
                "img",
                "9.9.9",
                &meta(json),
                &CageInputs {
                    public_certs: Path::new("/s/public-certs"),
                    egress_config: Path::new("/s/egress-config"),
                    egress_ip: "10.0.0.2",
                    staged_envs: &staged,
                    placeholders: &placeholders,
                    volume_entries: &[],
                    copyup_seeds: &[],
                },
                &|_| true,
            )
        };

        let argv = run(r#"{"cpus": "1.5", "memory": "2g"}"#);
        assert_eq!(pairs(&argv, "--cpus"), vec!["2".to_owned()]);
        assert_eq!(pairs(&argv, "--memory"), vec!["2G".to_owned()]);

        // `memory` absent, `mem_mb` present: the legacy shape.
        let argv = run(r#"{"mem_mb": 4096}"#);
        assert_eq!(pairs(&argv, "--memory"), vec!["4096M".to_owned()]);

        // Both absent: no flag at all, so Apple's defaults apply.
        let argv = run("{}");
        assert!(pairs(&argv, "--memory").is_empty(), "{argv:?}");
        assert!(pairs(&argv, "--cpus").is_empty(), "{argv:?}");

        // A zero `cpus` is falsy in the Python's `not in (None, "", 0)`.
        let argv = run(r#"{"cpus": 0}"#);
        assert!(pairs(&argv, "--cpus").is_empty(), "{argv:?}");
    }

    /// The secrets bind appears only when there is something in it, and
    /// the grants bind only when the overlay is on. An empty secrets
    /// bind would shadow the egress image's own directory.
    #[test]
    fn the_optional_egress_mounts_are_conditional() {
        let bare = egress_argv(
            "demo",
            "demo-net",
            "img",
            "9.9.9",
            &meta("{}"),
            &egress_paths(),
        );
        let mounts = pairs(&bare, "--volume");
        assert!(!mounts.iter().any(|m| m.contains("secrets")), "{mounts:?}");
        assert!(
            !pairs(&bare, "-e")
                .iter()
                .any(|e| e.starts_with("AGENTCAGE_GRANTS_DIR")),
            "{bare:?}"
        );

        let mut paths = egress_paths();
        paths.secrets = Some(Path::new("/s/secrets"));
        paths.grants = Some(Path::new("/d/grants"));
        let full = egress_argv("demo", "demo-net", "img", "9.9.9", &meta("{}"), &paths);
        let mounts = pairs(&full, "--volume");
        assert!(
            mounts.contains(&"/s/secrets:/home/acproxy/secrets:ro".to_owned()),
            "{mounts:?}"
        );
        // Read-write, deliberately: the addon rewrites grants.yaml.
        assert!(
            mounts.contains(&"/d/grants:/var/lib/agentcage".to_owned()),
            "{mounts:?}"
        );
        assert!(
            pairs(&full, "-e").contains(&"AGENTCAGE_GRANTS_DIR=/var/lib/agentcage".to_owned()),
            "{full:?}"
        );
    }

    /// The image is the last element on both, because `container run`
    /// takes it positionally after the flags.
    #[test]
    fn the_image_is_last() {
        let argv = egress_argv(
            "demo",
            "demo-net",
            "egress:tag",
            "9.9.9",
            &meta("{}"),
            &egress_paths(),
        );
        assert_eq!(argv.last().map(String::as_str), Some("egress:tag"));

        let staged = BTreeSet::new();
        let placeholders = BTreeMap::new();
        let argv = cage_argv(
            "demo",
            "demo-net",
            "wrapper:tag",
            "9.9.9",
            &meta("{}"),
            &CageInputs {
                public_certs: Path::new("/s/public-certs"),
                egress_config: Path::new("/s/egress-config"),
                egress_ip: "10.0.0.2",
                staged_envs: &staged,
                placeholders: &placeholders,
                volume_entries: &[],
                copyup_seeds: &[],
            },
            &|_| true,
        );
        assert_eq!(argv.last().map(String::as_str), Some("wrapper:tag"));
    }
}
