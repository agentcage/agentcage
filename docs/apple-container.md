# Apple Container Isolation

`apple-container` isolation uses Apple's [`container`](https://github.com/apple/container) CLI on macOS 26+ Apple Silicon. Each cage runs in a single Apple `container` microVM (one kernel per cage, hypervisor boundary via Apple's Virtualization.framework). A small POSIX-sh supervisor takes PID 1 inside the microVM, stands up an in-microVM egress filter (mitmproxy + dnsmasq + iptables), then drops privileges before exec'ing the cage workload.

Introduced in **0.20**. On macOS 26+ Apple Silicon hosts where the `container` CLI is installed, this is the **default** when `isolation:` is omitted from `cage.yaml`. Lima remains the default everywhere else.

## Why apple-container

Versus Lima on the same host:

- **~10–20× faster cage create** warm (~5s vs ~60s+ Lima warm). Apple microVMs boot in well under a second; Lima has to bring up a full Ubuntu cloud image.
- **~3× less RAM per cage.** A single microVM with one kernel vs Lima's full guest OS.
- **Same hypervisor boundary** — both use Virtualization.framework. The host-side trust boundary is identical.

Trade-offs:

- **macOS 26+ Apple Silicon only.** Older macOS, Intel Macs, and Linux all stay on Lima/container.
- **User cage image must be glibc-based** (debian, ubuntu, slim variants of those, distroless w/ apt). The bundled mitmproxy is a PyInstaller binary built against glibc; alpine/musl bases fail at wrapper-build time with exit 78.
- **One defense layer instead of two** for egress (see Security below).
- **`{{SECRET:...}}` server-side injection not yet shipped** — cage env vars carry secrets as written; the proxy doesn't substitute them on the wire. Egress allowlist + MITM are functional. Keychain-backed secrets are a follow-up.

## Architecture

Per cage, one Apple `container` microVM runs:

```
microVM (one kernel, isolated from host via Apple Virtualization.framework)
│
├── PID 1: /opt/agentcage/supervisor (POSIX sh, runs as root inside the µVM)
│   │
│   ├── stage 10  remount /proc with hidepid=2
│   ├── stage 20  parse cage CMD from /etc/agentcage/cage-cmd.json (jq @sh)
│   ├── stage 30  start dnsmasq (uid 201) → :53 forwarding to 1.1.1.1/8.8.8.8
│   ├── stage 40  start mitmproxy (uid 200) → transparent on :8080 with
│   │             /opt/agentcage/allowlist_addon.py
│   ├── stage 50  poll mitmproxy CA file AND listening socket (fail loud)
│   ├── stage 60  install proxy CA via update-ca-certificates
│   ├── stage 70  point /etc/resolv.conf at 127.0.0.1
│   ├── stage 80  iptables: DROP OUTPUT, REDIRECT cage 80/443 → :8080,
│   │             allow lo:{8080,53}, allow uid 200/201, kill IPv6
│   └── stage 90  capsh --no-new-privs --drop=all --user=1000
│                 → exec the cage workload
│
├── dnsmasq      (uid 201) — only DNS path the cage has
├── mitmproxy    (uid 200) — egress filter + addon allowlist enforcement
└── cage workload (uid 1000) — exactly zero capabilities, NoNewPrivs set,
                                hidepid hides other UIDs' PIDs
```

The per-cage wrapper image (built by `AppleContainerBackend.build_artifacts` via `container build`) layers the supervisor + addons + dnsmasq + mitmproxy bundle (SHA256-pinned, fetched from `downloads.mitmproxy.org`) onto the user's cage image with an explicit `USER root` so the apt install step works even when the user image sets a non-root USER.

## Prerequisites

- macOS 26 or later
- Apple Silicon (arm64) — Intel Macs are not supported
- Apple's `container` CLI installed and apiserver started:

```bash
# Install the latest .pkg from apple/container releases
PKG=$(curl -fsSL https://api.github.com/repos/apple/container/releases/latest \
      | grep -oE 'https://github.com/apple/container/releases/download/[^"]+\.pkg' | head -1)
curl -fsSLO "$PKG" && sudo installer -pkg "$(basename "$PKG")" -target /

# Start the apiserver and let it install the recommended kernel
container system start --enable-kernel-install
```

`agentcage doctor` will tell you which prerequisite is missing if any of these aren't met.

## Usage

Once `container` is installed and the apiserver is running, agentcage uses it by default:

```bash
# isolation: defaults to apple-container on macOS 26+ ASi
agentcage run claude-code

# Or be explicit
agentcage init my-cage --isolation apple-container
```

To opt back into Lima on a macOS 26+ host, set `isolation: vm` explicitly in `cage.yaml`.

`agentcage cage logs <name>` and `agentcage cage exec <name>` work through the supervisor's component layout (the `cage`, `proxy`, and `dns` "service" names). The CLI's component-aware dispatch for these commands lives in the Backend protocol lift — see the deferred work below.

## Security model

The cage workload runs with:

| Property | Value | Verifiable in `/proc/1/status` |
|---|---|---|
| UID | 1000 | `Uid: 1000 1000 1000 1000` |
| Capability sets | all empty | `CapInh/Prm/Eff/Bnd: 0000000000000000` |
| `NoNewPrivs` | set | `NoNewPrivs: 1` |
| `/proc` visibility | only own UID's PIDs | `hidepid=2` mount option |

Cage-side escape attempts that are blocked end-to-end (verified on macOS 26.3.2 + ASi):

- `iptables -F` → "Permission denied (you must be root)" (no `CAP_NET_ADMIN`)
- `mount` syscall → denied (no `CAP_SYS_ADMIN`)
- TCP to non-80/443 port → DROPped by iptables
- UDP DNS to upstream (8.8.8.8) → DROPped by iptables
- Connect to arbitrary loopback port (not 53 or 8080) → DROPped by iptables
- IPv6 fallback → killed at ip6tables + sysctl `disable_ipv6=1`
- TLS with `Host: evil.com` spoofed on connection to allowlisted host → 403 from proxy (addon uses SNI/dst, not Host header)
- Bypass via raw IP literal → 403 from proxy (allowlist applies to all hosts)

The single defense-in-depth layer that's missing vs Lima: if iptables in the cage netns is somehow flushed (would require a supervisor bug or kernel CVE — the cage itself cannot do this), Lima's `<cage>-net` is a non-routed podman network so the cage still can't reach the internet. Apple custom networks always have NAT, so apple-container has no equivalent backstop. We compensate with a comprehensive supervisor test suite and the `/codex review` gate on supervisor changes.

## Deferred to follow-ups

Tracked in [#120](https://github.com/agentcage/agentcage/issues/120):

- **Server-side `{{SECRET:...}}` placeholder injection.** Cage env vars carry secrets as written today; the existing `SecretInjector` from the Lima proxy needs porting into `allowlist_addon.py`.
- **`agentcage cage audit` integration.** mitmproxy writes audit lines to `/var/log/agentcage/proxy.log` inside the cage; the CLI doesn't yet read them out.
- **Backend protocol lift for `exec` / `logs` / `audit`.** Today the CLI has special-cases per isolation; lifting these methods onto the Backend protocol would clean this up.
- **Phase-level `--time` instrumentation for apple-container.** The `_timing.Phase` calls live in the Lima/container backends; apple-container doesn't emit them yet (the `--time` summary just says "no timing data for this run").
- **Linux CI for the supervisor.** The supervisor's hardening logic is standard Linux; a Linux CI suite (running the supervisor in a privileged container) would catch regressions before the manual macOS rerun. Today the security-critical code is only verified by the maintainer's manual e2e on a single Mac.
- **Alpine/musl user image support.** mitmproxy bundle is glibc-only; would need a musl build of mitmproxy or a portable Python.
- **Autostart after host reboot.** systemd quadlets auto-start; Apple `container` does not. Run `agentcage cage start <name>` manually after reboot until a launchd plist lands.

## Troubleshooting

**`agentcage doctor` reports "Apple container unavailable"** — check `container system status`. If "not running", `container system start --enable-kernel-install`. If "not installed", install the `.pkg` from apple/container releases.

**Cage create fails with `exit 78`** — your cage image is not glibc-based (alpine or similar). Use a debian/ubuntu base for now.

**Cage create fails with `exit 79`** — your cage image has a system user at uid 200 or 201 that collides with the apple-container `acproxy`/`acdns` users. File an issue.

**Cage runs but every outbound HTTP times out** — check `container logs <cage>` for the supervisor's stages. If stage 50 says "mitmproxy listener never came up", check `container exec <cage> tail /var/log/agentcage/proxy.log` for mitmproxy errors.

**`agentcage cage destroy <cage>` leaves an image behind** — `container image delete localhost/agentcage-apple-<cage>:latest` to clean it up. This is logged as a destroy error; not destructive.
