//! Static and behavioural checks on files agentcage ships in its images.
//!
//! Everything here reads a file the binary embeds and a container runs:
//! the egress image's `supervisor-egress.sh` and `Containerfile.egress`,
//! the apple-container `cage-init.sh`, and `templates/egress.container.j2`.
//! Most checks assert on the text, because the bugs they guard were
//! one-line regressions in a shell script that no other test executes;
//! `cage-init.sh`'s seeding stages are pure filesystem work, so those are
//! run for real under `sh` against a temporary directory.
//!
//! The scaffold checks (`scaffolds/`, the rendered `cage.yaml` fixtures)
//! live in `agentcage-core/tests/shipped_scaffolds.rs`, next to the YAML
//! parser they need.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The repository root: `rust/agentcage-assets` -> `rust` -> root.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate is nested at rust/<crate>")
        .to_path_buf()
}

/// A file under `src/agentcage/`, as text.
fn read_src(rel: &str) -> String {
    let path = repo_root().join("src/agentcage").join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn supervisor() -> String {
    read_src("data/containers/supervisor-egress.sh")
}

fn containerfile() -> String {
    read_src("data/containers/Containerfile.egress")
}

fn cage_init() -> String {
    read_src("data/apple-container/cage-init.sh")
}

/// Byte offset of `needle` in `haystack` at or after `from`, or a panic
/// naming what was missing.
fn index_from(haystack: &str, needle: &str, from: usize) -> usize {
    haystack[from..].find(needle).map_or_else(
        || panic!("{needle:?} not found after byte {from}"),
        |i| i + from,
    )
}

fn index_of(haystack: &str, needle: &str) -> usize {
    index_from(haystack, needle, 0)
}

/// First line index whose text satisfies `pred`.
fn line_index(text: &str, what: &str, pred: impl Fn(&str) -> bool) -> usize {
    text.lines()
        .position(pred)
        .unwrap_or_else(|| panic!("no line matching {what}"))
}

// ── supervisor-egress.sh: applying policy-api grants ─────────────────────

/// The whole point: no new process, no new service. The check rides the
/// loop that already polls both children for liveness.
#[test]
fn monitor_loop_watches_the_published_list() {
    let s = supervisor();
    assert!(s.contains(r#"while kill -0 "$DNSMASQ_PID""#));
    assert!(s.contains(r#"if [ -f "$GRANTS_RELOAD" ]; then"#));
}

/// `-nt` is a bash/dash extension, not POSIX (shellcheck SC3013). The
/// script is `#!/bin/sh` and CI lints it as POSIX sh; a `stat` comparison
/// would fork a process every second in a loop whose appeal is that it
/// costs nothing.
#[test]
fn reload_signal_is_posix() {
    assert!(!supervisor().replace("`-nt`", "").contains("-nt"));
}

/// A grant decided mid-render must not be swallowed, and a failed render
/// puts the flag back so the next tick retries.
#[test]
fn flag_is_cleared_before_rendering() {
    let s = supervisor();
    let i = index_of(&s, r#"if [ -f "$GRANTS_RELOAD" ]; then"#);
    let clear = index_from(&s, r#"rm -f "$GRANTS_RELOAD""#, i);
    let render = index_from(&s, "_render_servers_file", i);
    assert!(clear < render);
    assert!(s.contains(r#": > "$GRANTS_RELOAD""#));
}

/// Regression: sending SIGHUP to `$DNSMASQ_PID` kills the whole egress. dnsmasq
/// runs under `dns-audit.sh`, so that pid is the WRAPPER's, and SIGHUP is
/// fatal to a plain shell: the liveness poll sees a dead child and the
/// container exits.
#[test]
fn sighup_targets_the_pidfile_not_the_wrapper() {
    let s = supervisor();
    assert!(s.contains(r#"_hup_pid=$(cat "$DNSMASQ_PID_FILE""#));
    assert!(s.contains(r#"kill -HUP "$_hup_pid""#));
    assert!(!s.contains(r#"kill -HUP "$DNSMASQ_PID""#));
}

/// dnsmasq must never read a half-written servers-file.
#[test]
fn render_is_atomic() {
    let s = supervisor();
    assert!(s.contains(r#"_sf_tmp="${SERVERS_OUT}.tmp""#));
    assert!(s.contains(r#"mv -f "$_sf_tmp" "$SERVERS_OUT""#));
}

/// A grant is strictly additive: the rendered file is always
/// baseline-then-grants, regenerated from the read-only bind mount, so a
/// grant can never delete or repoint an operator zone.
#[test]
fn baseline_is_read_only_and_rebuilt_each_render() {
    let s = supervisor();
    assert!(s.contains("SERVERS_BASE=/etc/agentcage/dns-allowlist.conf"));
    assert!(s.contains("SERVERS_OUT=/run/agentcage/dns-allowlist.egress.conf"));
    let base = index_of(&s, r#"cat "$SERVERS_BASE" >> "$_sf_tmp""#);
    let grants = index_of(&s, r#"if [ -s "$GRANTED_DOMAINS" ]"#);
    assert!(base < grants, "baseline must be emitted before grants");
}

/// The egress names a zone; the supervisor routes it. If the egress could
/// emit `server=` directives it could point a zone at a resolver it
/// controls, which is more authority than deciding grants. The shell also
/// re-validates the name as a second gate.
#[test]
fn supervisor_chooses_the_upstream_not_the_egress() {
    let s = supervisor();
    assert!(s.contains(r#"printf 'server=/%s/%s\n' "$_sf_dom" "$_sf_up""#));
    assert!(s.contains("grep -E '^[a-z0-9]"));
}

/// Under full default-deny the baseline is EMPTY, so granted upstreams
/// cannot be scraped out of it.
#[test]
fn granted_upstreams_do_not_come_from_the_baseline() {
    assert!(supervisor().contains("AGENTCAGE_DNS_UPSTREAMS"));
}

/// Every dnsmasq branch ends up on the writable /run path; pointing
/// dnsmasq at the read-only bind mount would make a grant unappliable
/// without a restart.
#[test]
fn runtime_servers_file_is_always_rendered() {
    let s = supervisor();
    assert!(s.matches("_render_servers_file").count() >= 4);
    assert!(s.contains(r#"--servers-file="$SERVERS_OUT""#));
}

// ── supervisor-egress.sh: DNS forwarding and the egress's resolver ───────

/// The container/vm egress dnsmasq forwards allowlisted zones to the
/// runtime DEFAULT-ROUTE gateway (host-tracking) in addition to the baked
/// `dns_servers`, with `--all-servers` so a degraded gateway falls back
/// instantly. Derived from the default route, not eth0's subnet: the
/// egress is dual-homed and `<name>-net` is internal.
#[test]
fn container_path_forwards_to_default_route_gateway() {
    let s = supervisor();
    assert!(s.contains("ip route 2>/dev/null | awk '/^default/{print $3; exit}'"));
    assert!(s.contains(r#"sed "s#/[^/]*\$#/$_SF_GW#" "$SERVERS_BASE""#));
    assert!(s.contains("SERVERS_BASE=/etc/agentcage/dns-allowlist.conf"));
    assert!(s.contains("_SF_STYLE=prepend"));
    assert!(s.contains("/run/agentcage/dns-allowlist.egress.conf"));
    assert!(s.contains(r#"_all_servers="--all-servers""#));
    assert!(s.contains("$_all_servers"));
    // Unconditional: dnsmasq must prefer a positive answer over a public
    // resolver's NXDOMAIN so a split-horizon apex resolves, and the egress
    // proxy resolves through this dnsmasq even when no gateway is derived.
    assert!(!s.contains(r#"_all_servers="""#));
}

/// The egress proxy re-resolves the upstream SNI/Host, so its own
/// resolver (/etc/resolv.conf) must track the host and resolve
/// split-horizon names: a single nameserver, the local dnsmasq. A flat
/// list of upstreams cannot (glibc stops at the first NXDOMAIN), and the
/// old `sort -u` of `dns_servers` broke MagicDNS-homed cages. Requires the
/// rw resolv bind in the egress unit.
#[test]
fn egress_resolver_points_at_local_dnsmasq() {
    let s = supervisor();
    assert!(s.contains(r#"_resolver_ip="$DNS_LISTEN_IP""#));
    assert!(s.contains(r#"echo "nameserver $_resolver_ip""#));
    assert!(s.contains("> /etc/resolv.conf"));
    assert!(!s.contains(r#"echo "nameserver $_gw""#));
    assert!(!s.contains("dns-allowlist.conf | sort"));

    let unit = read_src("templates/egress.container.j2");
    assert!(unit.contains("resolv-egress-{{ name }}.conf:/etc/resolv.conf:rw,Z"));
    assert!(!unit.contains(":/etc/resolv.conf:ro,Z"));
}

/// apple-container: the egress dnsmasq binds an explicit listen address
/// (a wildcard listener in the microVM opens :53 but does not answer the
/// cage sibling) and forwards allowlisted zones to the host-tracking vmnet
/// gateway (`<subnet>.1`) instead of the resolver baked at `cage update`.
#[test]
fn apple_egress_dnsmasq_listens_explicitly_and_forwards_to_gateway() {
    let s = supervisor();
    assert!(s.contains(r#"--listen-address="${_eth0_ip}""#));
    assert!(s.contains("grep -vE '^(server=/|listen-address=)'"));
    assert!(s.contains(r#"print $1"."$2"."$3".1""#));
    assert!(s.contains("/run/agentcage/dns-allowlist.egress.conf"));
}

// ── supervisor-egress.sh: log files (#186) ───────────────────────────────

/// On apple-container the host per-cage logs dir is bind-mounted into the
/// egress microVM and virtiofs identity-maps owners, so a log file created
/// at the daemon's default 0644 is readable (dnsmasq.log even writable) by
/// the cage workload, which could then forge the audit trail. The
/// supervisor pre-creates all four at 0640, as the service user, before
/// the daemon that writes each one starts, and says so loudly on failure.
#[test]
fn supervisor_precreates_logs_at_0640() {
    let s = supervisor();
    assert!(
        s.contains("install -m 0640"),
        "log files must be created with `install -m 0640` (no race)"
    );
    assert!(
        s.contains("setpriv --reuid=") && s.contains("--clear-groups"),
        "logs must be created/tightened under setpriv as the service user"
    );
    for (path, user) in [
        ("/var/log/agentcage/dnsmasq.log", "acdns"),
        ("/var/log/agentcage/audit.jsonl", "acproxy"),
        ("/var/log/agentcage/capture.jsonl", "acproxy"),
        ("/var/log/agentcage/proxy.log", "acproxy"),
    ] {
        let call = format!("_ensure_log {path} {user}");
        assert!(s.contains(&call), "supervisor missing `{call}` (#186)");
    }

    let dns_ensure = line_index(&s, "the dnsmasq.log ensure", |l| {
        l.contains("_ensure_log /var/log/agentcage/dnsmasq.log acdns")
    });
    let dns_launch = line_index(&s, "a dnsmasq launch", |l| {
        l.contains("/usr/sbin/dnsmasq") || l.contains("/opt/agentcage/dns-audit.sh")
    });
    assert!(
        dns_ensure < dns_launch,
        "_ensure_log dnsmasq.log must run BEFORE the dnsmasq launch line (#186)"
    );
    let proxy_ensure = line_index(&s, "the proxy.log ensure", |l| {
        l.contains("_ensure_log /var/log/agentcage/proxy.log acproxy")
    });
    let proxy_launch = line_index(&s, "the egress launch", |l| {
        l.contains(r#""$EGRESS_BIN" run"#)
    });
    assert!(
        proxy_ensure < proxy_launch,
        "_ensure_log acproxy logs must run BEFORE the egress launch line (#186)"
    );

    assert!(
        s.contains(r#"|| log "warn: _ensure_log"#),
        "_ensure_log must warn loudly on failure, not `|| true` (#186)"
    );
    for line in s.lines() {
        if !["audit.jsonl", "capture.jsonl", "proxy.log", "dnsmasq.log"]
            .iter()
            .any(|b| line.contains(b))
        {
            continue;
        }
        for mode in ["0644", "0664", "0666"] {
            assert!(
                !line.contains(mode),
                "a log file is created with mode {mode} (#186): {line:?}"
            );
        }
    }
}

// ── supervisor-egress.sh + Containerfile.egress: the egress itself ───────

/// Every `/opt/agentcage/<file>` the supervisor runs is put there by a
/// `COPY` in the image. A file referenced but never copied fails only at
/// runtime, inside a container, with the image building cleanly.
#[test]
fn everything_the_supervisor_runs_is_copied_into_the_image() {
    let s = supervisor();
    let cf = containerfile();
    let copied: Vec<&str> = cf
        .lines()
        .filter_map(|l| l.trim().strip_prefix("COPY "))
        .filter_map(|rest| rest.split_whitespace().last())
        .collect();
    for target in [
        "/opt/agentcage/agentcage-egress",
        "/opt/agentcage/dns-audit.sh",
        "/opt/agentcage/supervisor",
    ] {
        assert!(
            copied.contains(&target),
            "{target} is never COPYed: {copied:?}"
        );
    }
    for word in s.split(|c: char| c.is_whitespace() || c == '"' || c == '=') {
        if let Some(name) = word.strip_prefix("/opt/agentcage/") {
            let name = name.trim_end_matches([';', ')']);
            if name.is_empty() {
                continue;
            }
            let full = format!("/opt/agentcage/{name}");
            assert!(
                copied.contains(&full.as_str()),
                "the supervisor runs {full}, which the image never COPYs"
            );
        }
    }
    assert!(
        s.contains("EGRESS_BIN=/opt/agentcage/agentcage-egress"),
        "the supervisor launches the binary the image ships"
    );
    assert!(cf.contains(r#"ENTRYPOINT ["/usr/bin/tini", "--", "/opt/agentcage/supervisor"]"#));
}

/// The egress process runs as acproxy with an empty bounding set and
/// no-new-privs; dnsmasq keeps only `net_bind_service` (its file cap needs
/// it, and `NoNewPrivs` would block file caps).
#[test]
fn both_daemons_drop_their_bounding_set() {
    let s = supervisor();
    let launch = index_of(&s, r#""$EGRESS_BIN" run"#);
    let prelude = &s[s[..launch].rfind("prlimit").expect("egress prlimit")..launch];
    assert!(prelude.contains("--reuid=acproxy --regid=acproxy --clear-groups"));
    assert!(prelude.contains("--no-new-privs --bounding-set=-all --inh-caps=-all"));
    assert!(s.contains("--bounding-set=-all,+net_bind_service --inh-caps=-all"));
    assert!(!s.contains("--bounding-set=-all,+net_bind_service --no-new-privs"));
}

/// The egress's address-space limit follows `egress.body_budget_bytes`:
/// the binary computes it (as acproxy, from the config it then runs),
/// and anything but a plain number falls back to the old fixed 2 GiB.
#[test]
fn the_egress_address_space_limit_comes_from_its_config() {
    let s = supervisor();
    let launch = index_of(&s, r#""$EGRESS_BIN" run"#);
    let ask = index_of(&s, r#""$EGRESS_BIN" address-space"#);
    assert!(ask < launch);
    let asking = &s[s[..ask].rfind("EGRESS_AS_BYTES=$(").expect("the probe")..ask];
    assert!(asking.contains("setpriv --reuid=acproxy --regid=acproxy --clear-groups"));
    assert!(asking.contains("AGENTCAGE_CONFIG=/etc/agentcage/config.yaml"));
    assert!(s.contains("''|*[!0-9]*) EGRESS_AS_BYTES=$((2 * 1024 * 1024 * 1024)) ;;"));
    let prelude = &s[s[..launch].rfind("prlimit").expect("egress prlimit")..launch];
    assert!(prelude.starts_with(r#"prlimit --as="$EGRESS_AS_BYTES" --"#));
}

/// Only the public half of the CA reaches the cage. The cage mounts
/// `/home/acproxy/public-certs` at `/certs`; the private store holds the
/// key (exposed to uid 1000 in 0.22.0-0.22.5). One file is published,
/// under the one contract name.
#[test]
fn supervisor_publishes_only_the_public_cert() {
    let s = supervisor();
    assert!(s.contains("CA_DIR=/home/acproxy/ca"));
    assert!(s.contains(r#"CA_PATH="$CA_DIR/agentcage-ca.pem""#));
    let installs: Vec<&str> = s
        .lines()
        .filter(|l| l.contains("public-certs/") && l.trim_start().starts_with("install "))
        .collect();
    assert_eq!(
        installs,
        [r#"  install -m 0644 "$CA_PATH" /home/acproxy/public-certs/agentcage-ca.pem"#]
    );
}

/// No runtime chown: hardened rootless podman drops `CAP_CHOWN`, so the
/// egress-local DNS publish dir is chowned in an image layer, the same way
/// /home/acdns is.
#[test]
fn image_creates_an_acproxy_owned_dns_dir() {
    let cf = containerfile();
    assert!(cf.contains("mkdir -p /home/acproxy/dns"));
    assert!(cf.contains("chown acproxy:acproxy /home/acproxy/dns"));
}

/// The egress image carries no interpreter.
#[test]
fn the_egress_image_installs_no_python() {
    for line in containerfile().lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        assert!(!line.contains("pip "), "{line}");
        assert!(!line.contains("python"), "{line}");
    }
}

/// The egress reports its version in Policy API payloads; the unit is
/// where that reaches the container/vm egress.
#[test]
fn egress_gets_the_agentcage_version() {
    assert!(read_src("templates/egress.container.j2").contains("AGENTCAGE_VERSION"));
}

// ── apple-container/cage-init.sh ─────────────────────────────────────────

/// capsh's `--user=` takes a name, and the uid-1000 user's name varies by
/// base image, so it is looked up at runtime.
#[test]
fn cage_init_resolves_cage_user_dynamically() {
    let text = cage_init();
    assert!(text.contains("getent passwd 1000"));
    assert!(text.contains("--user="));
    assert!(text.contains("${CAGE_USER}"));
}

/// PID 1 of the cage microVM: route via the egress, environment for the
/// dropped user, the OUTPUT-chain DROPs and the local dnsmasq.
#[test]
fn cage_init_boot_sequence() {
    let text = cage_init();
    assert!(text.contains("AGENTCAGE_EGRESS_IP"));
    assert!(text.contains("ip route replace default via"));
    assert!(text.contains("capsh"));
    // capsh switches uid but not env; without these the workload inherits
    // HOME=/root and tools touching ~/.config fail EACCES (0.22.4).
    assert!(text.contains(r#"export HOME="${CAGE_HOME}""#));
    assert!(text.contains(r#"export USER="${CAGE_USER}""#));
    assert!(text.contains(r#"export LOGNAME="${CAGE_USER}""#));
    assert!(text.contains("CAGE_HOME=$(getent passwd 1000 | cut -d: -f6)"));
    // Stage B': no TCP or UDP to the macOS host gateway, and only acdns
    // may emit UDP :53 (otherwise the in-cage dnsmasq scoping is
    // decorative).
    assert!(text.contains("_apple_host_gw="));
    assert!(text.contains(r#"iptables -A OUTPUT -d "${_apple_host_gw}" -p tcp -j DROP"#));
    assert!(text.contains(r#"iptables -A OUTPUT -d "${_apple_host_gw}" -p udp -j DROP"#));
    let accept_lo = "iptables -A OUTPUT -o lo -p udp --dport 53 -j ACCEPT";
    let drop_non_acdns = "iptables -A OUTPUT -p udp --dport 53 -m owner ! --uid-owner 201 -j DROP";
    assert!(
        index_of(&text, accept_lo) < index_of(&text, drop_non_acdns),
        "loopback :53 ACCEPT must come BEFORE the uid-owner DROP (first match wins)"
    );
    assert!(
        !text.contains(r#"iptables -A OUTPUT -d "${_apple_host_gw}" -p udp ! --dport 53 -j DROP"#)
    );
    // Stage A': local dnsmasq scoped to the allowlist, forwarding to the
    // egress sibling so the egress stays the single chokepoint.
    assert!(text.contains("stage A': starting local dnsmasq"));
    assert!(text.contains("/etc/agentcage/dnsmasq.conf"));
    assert!(text.contains("grep -v '^server=/'"));
    assert!(text.contains("/run/agentcage/dns-allowlist.cage.conf"));
    assert!(text.contains(r#"up="${AGENTCAGE_EGRESS_IP}""#));
    assert!(text.contains("--bind-interfaces"));
    assert!(text.contains("--except-interface=eth0"));
    assert!(text.contains("--user=acdns"));
    assert!(text.contains("nameserver 127.0.0.1"));
}

/// The cage-init half of single-file `np` routing: the file is copied to
/// its exact target, the parent created first. (The argv half is
/// `run_argv.rs::a_non_directory_np_source_gets_no_tmpfs`.)
#[test]
fn cage_init_routes_np_file_to_exact_target() {
    let text = cage_init();
    assert!(text.contains(r#"np_parent=$(dirname "${target}")"#));
    assert!(text.contains(r#"mkdir -p "${np_parent}""#));
    assert!(text.contains(r#"cp -f "${lower}" "${target}""#));
}

/// cage-init.sh's seeding stages (the helper plus C' and C'') as a
/// standalone POSIX-sh script. They are pure filesystem work driven by
/// two env vars, so they can run off-VM against a temp dir; each stage is
/// inert when its variable is unset.
fn seeding_script() -> String {
    let text = cage_init();
    let start = index_of(&text, "#-- Seeding helper (stages C' and C'')");
    let end = index_from(&text, "#-- Stage D.", start);
    format!(
        "set -eu\nlog() {{ printf '%s\\n' \"$*\" >&2; }}\n{}",
        &text[start..end]
    )
}

/// A fresh scratch directory for one test.
fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "agentcage-shipped-{}-{}-{name}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// Run stages C'/C'' with a recording `chown` stub and return the
/// argument lines it saw, or `None` when `sh`/`tar` are unavailable.
///
/// chown to uid 1000 needs root, which the test suite is not; the stub
/// keeps the assertions about which paths are handed to the cage user
/// honest without privileges, while the seeding itself is real.
fn run_seeding(
    dir: &Path,
    copies: &[(&Path, &Path)],
    copyup: &[(&Path, &Path)],
) -> Option<Vec<String>> {
    for tool in ["sh", "tar"] {
        // Only a spawn failure means "absent"; dash exits non-zero on
        // `--version` and is still a perfectly good `sh`.
        if Command::new(tool).arg("--version").output().is_err() {
            eprintln!("skipping: {tool} is not available");
            return None;
        }
    }
    // The stub is a shell function, not a file on PATH: exec'ing a file
    // this process just wrote races other test threads' forks (ETXTBSY).
    let log = dir.join("chown.log");
    let script = dir.join("seed.sh");
    fs::write(
        &script,
        format!(
            "chown() {{ printf '%s\\n' \"$*\" >> '{}'; }}\n{}",
            log.display(),
            seeding_script()
        ),
    )
    .expect("script");

    let pairs = |list: &[(&Path, &Path)]| {
        list.iter()
            .map(|(l, t)| format!("{}\t{}", l.display(), t.display()))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let out = Command::new("sh")
        .arg(&script)
        .env("AGENTCAGE_NONPERSISTENT_COPIES", pairs(copies))
        .env("AGENTCAGE_TMPFS_COPYUP", pairs(copyup))
        .output()
        .expect("sh runs");
    assert!(
        out.status.success(),
        "seeding failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(
        fs::read_to_string(&log)
            .map(|t| t.lines().map(str::to_owned).collect())
            .unwrap_or_default(),
    )
}

/// REGRESSION (#311): `tar xp` replays the host source's root-owned 0755
/// modes into the tmpfs, so the uid-1000 workload could not write to an
/// `np` mount at all. The seeded tree is chowned to uid 1000, and the
/// read-only host bind is never chowned through.
#[test]
fn cage_init_hands_np_directory_seed_to_the_cage_user() {
    let dir = scratch("np-dir");
    let lower = dir.join("lower");
    fs::create_dir_all(lower.join("sub")).expect("mkdir");
    fs::write(lower.join("sub/f.txt"), "hi").expect("write");
    let target = dir.join("target");

    let Some(chowns) = run_seeding(&dir, &[(&lower, &target)], &[]) else {
        return;
    };
    assert_eq!(
        fs::read_to_string(target.join("sub/f.txt")).expect("seeded"),
        "hi"
    );
    assert_eq!(chowns, [format!("-Rh 1000:1000 {}", target.display())]);
    assert!(
        !chowns
            .iter()
            .any(|l| l.contains(&lower.display().to_string()))
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The seeded tree is a verbatim copy of a host directory, so it can hold
/// a symlink to /etc/shadow; chown must carry `-h`.
#[test]
fn cage_init_np_directory_chown_does_not_follow_symlinks() {
    assert!(seeding_script().contains("chown -Rh 1000:1000"));
}

/// A single-file `np` source is copied to its exact target, owned by uid
/// 1000 — and so is a parent directory this stage invents, or the
/// root-owned parent blocks the write-temp-then-rename save path.
#[test]
fn cage_init_hands_np_file_seed_and_invented_parent_to_the_cage_user() {
    let dir = scratch("np-file");
    let lower = dir.join("settings.json");
    fs::write(&lower, "{}").expect("write");
    let target = dir.join("cage/config/settings.json");

    let Some(chowns) = run_seeding(&dir, &[(&lower, &target)], &[]) else {
        return;
    };
    assert_eq!(fs::read_to_string(&target).expect("seeded"), "{}");
    assert_eq!(
        chowns,
        [
            format!("1000:1000 {}", target.parent().expect("parent").display()),
            format!("-h 1000:1000 {}", target.display()),
        ]
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A parent that already exists belongs to the image; seeding one file
/// into it must not rewrite that directory's ownership.
#[test]
fn cage_init_np_file_seed_leaves_a_preexisting_parent_alone() {
    let dir = scratch("np-parent");
    let lower = dir.join("settings.json");
    fs::write(&lower, "{}").expect("write");
    let target = dir.join("existing/settings.json");
    fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");

    let Some(chowns) = run_seeding(&dir, &[(&lower, &target)], &[]) else {
        return;
    };
    assert_eq!(chowns, [format!("-h 1000:1000 {}", target.display())]);
    let _ = fs::remove_dir_all(&dir);
}

/// Stage C'' replays the read-only lower into the tmpfs and chowns it to
/// uid 1000, so the agent can edit its throwaway copy (#328).
#[test]
fn stage_c_double_prime_seeds_and_hands_the_copy_to_the_cage_user() {
    let dir = scratch("copyup");
    let lower = dir.join("lower");
    fs::create_dir_all(lower.join("commands")).expect("mkdir");
    fs::write(lower.join("settings.json"), r#"{"host":"settings"}"#).expect("write");
    let target = dir.join("target");

    let Some(chowns) = run_seeding(&dir, &[], &[(&lower, &target)]) else {
        return;
    };
    assert_eq!(
        fs::read_to_string(target.join("settings.json")).expect("seeded"),
        r#"{"host":"settings"}"#
    );
    assert!(target.join("commands").is_dir());
    assert_eq!(chowns, [format!("-Rh 1000:1000 {}", target.display())]);
    assert!(
        !chowns
            .iter()
            .any(|l| l.contains(&lower.display().to_string()))
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn seeding_stages_are_inert_without_the_env() {
    let dir = scratch("inert");
    if let Some(chowns) = run_seeding(&dir, &[], &[]) {
        assert!(chowns.is_empty(), "{chowns:?}");
    }
    let _ = fs::remove_dir_all(&dir);
}
