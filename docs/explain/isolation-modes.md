<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Isolation modes

agentcage runs each cage inside one of three isolation backends: rootless `container`, Lima `vm`, or Apple `apple-container`. The choice shapes the trust boundary — namespaces vs a guest kernel vs sibling microVMs — but the inspector chain, secret injection, DNS filtering, and audit pipeline are identical across all three.

When `isolation:` is omitted from `cage.yaml`, agentcage picks the best available: `apple-container` on macOS 26+ Apple Silicon with the `container` CLI installed, `vm` on other macOS hosts (including Intel), and `container` on Linux.

## How container isolation works

Two rootless Podman containers on a `--internal` Podman network with no internet gateway. The agent sits on the internal network only; the egress container is dual-homed and runs mitmproxy plus dnsmasq side by side. *Since v0.22* — earlier versions used a three-service shape (separate `<name>-proxy` and `<name>-dns` containers); the CLI refuses to operate on legacy cages.

```text
host (rootless podman)
└── <name>-net (--internal, no gateway)
    ├── <name>-cage       agent, internal-only, default route → egress
    └── <name>-egress     mitmproxy + dnsmasq + inspector chain, dual-homed
```

The agent's default route points at the egress. iptables REDIRECT rules intercept outbound TCP on the allowed ports regardless of whether the application honours `HTTP_PROXY`. A default-deny `filter:FORWARD` policy drops any port not explicitly allowed.

The isolation boundary is Linux namespaces plus rootless Podman hardening (read-only root, all caps dropped, NoNewPrivs). The host kernel is shared — a kernel or runtime escape lands on the host.

## How VM isolation works

The same two-container topology runs inside a Lima-managed Linux VM, one VM per cage. The boundary is the CPU's virtualization extensions (VT-x / AMD-V on Linux, Hypervisor.framework on macOS). A container escape inside the VM lands in the VM's userspace, not on the host.

```text
host
└── <name>-cage  (Lima VM, dedicated kernel)
    └── podman (inside VM)
        ├── <name>-egress  mitmproxy + dnsmasq
        └── <name>-cage    user workload
```

Lima handles VM networking transparently. Host volumes from `container.volumes` are forwarded into the VM via Lima virtiofs (read-only by default; `:rw` opts in to writable) and then bind-mounted into the workload container — except paths under `~/.ssh`, `~/.aws`, etc., which are blocked outright. Secrets set on the host (systemd-creds or Podman) are bridged into the VM's Podman secret store at deploy.

## How apple-container isolation works

Each cage runs as **two sibling Apple `container` microVMs** on a per-cage Apple network. One microVM holds the egress filter (mitmproxy + dnsmasq + iptables); the other holds the workload. The cage VM's default route points at the egress sibling, so all cage egress flows through the proxy.

```text
host (apple `container` apiserver)
└── <cage>-net (per-cage Apple network)
    ├── <cage>-egress    mitmproxy + dnsmasq + iptables (uid 200/201)
    │                    iptables REDIRECT 80/443 → :8443, FORWARD default DROP
    │
    └── <cage>           wrapper on user image
                         cage-init.sh: set default route, install proxy CA,
                         capsh --drop=all, exec workload as uid 1000
```

The boundary is Apple's `Virtualization.framework` (same as Lima on macOS). The two-microVM split means secrets in cleartext live only in the egress sibling's `/home/acproxy/secrets` bind mount; the cage VM has no iptables binary to flush and no dnsmasq config to read.

A shared `agentcage-egress` image is built once per host so sibling cages reuse the ~120 MB mitmproxy bundle.

## Comparing the three

| | container | vm | apple-container |
|---|---|---|---|
| Boundary | Linux namespaces + rootless Podman | KVM / HVF guest kernel (Lima) | Two sibling Apple microVMs |
| Kernel | Shared with host | Dedicated guest kernel | Dedicated microVM kernel |
| Container-escape risk | Mitigated by hardening, not eliminated | Escape lands in VM | Escape lands in microVM |
| macOS support | No | Yes (Intel + Apple Silicon) | macOS 26+ Apple Silicon only |
| User image constraint | Any Linux base | Any (built inside the VM) | Any Linux base (apt or apk; distroless skips the install) |
| Boot overhead | ~1s | ~15–30s | ~3–5s warm, ~25–30s cold |
| Host bind mounts into cage | Yes (`container.volumes`) | Yes, via Lima virtiofs (host path must exist; `~/.ssh` etc. blocked) | Yes (`container.volumes`; host path must resolve under `$HOME`) |
| Secrets at rest | systemd-creds blob (default if available) or host Podman secret store | Bridged into the VM's Podman secret store (from host systemd-creds or Podman) | `pending_secrets.json` (mode 0600) under the per-cage state dir; staged at `start` into a per-cage secrets dir bind-mounted read-only into the egress sibling |

For the threat-by-threat matrix, see [Security model](security-model.md).

## Known limitations

**container — shared kernel.** A kernel CVE or container-runtime escape bypasses all in-cage hardening. Use `vm` or `apple-container` when this risk is unacceptable.

**vm — host bind mounts go through Lima virtiofs.** `container.volumes` entries are forwarded via Lima mounts (read-only by default; opt in with `:rw`). The host path must exist before `cage create`, must resolve under `$HOME`, and must not fall under blocked dirs like `~/.ssh` / `~/.aws`. File-source entries (single dotfile) are staged into `~/.local/share/agentcage` first because Lima virtiofs only shares directories.

**apple-container — wrapper image installs via apt or apk.** The wrapper Containerfile adds `iproute2`, `libcap2-bin`, `ca-certificates`, `iptables`, and `dnsmasq-base` via apt on debian/ubuntu bases or `apk` on Alpine. Distroless bases without a package manager fall through silently; cage-init will then surface "command not found" at boot. The mitmproxy bundle lives in a separate glibc-based egress sibling and never enters the user image.

**apple-container — `--as-root` can bypass egress for that exec session.** The cage microVM keeps `CAP_NET_ADMIN` so `cage-init.sh` can set the default route at startup. Apple's runtime reconstructs `CapBnd` from `configuration.capAdd` on every exec, so `cage exec --user 0` re-acquires it. An `--as-root` operator can `ip route replace default` to route around the egress sibling. They cannot read cleartext secrets (different microVM). For hardened `--as-root` sessions, use `vm`.

**apple-container — `cage update` needed for most `cage.yaml` edits.** Allowlist, command, env, secret-injection rules, capture, and autostart are baked into the wrapper image at build time. `domain add / rm` auto-rebuilds; other field edits need an explicit `cage update`.

**apple-container — `cage backup --include-secrets` is rejected.** The backend has no host Podman secret store to serialize; secrets are provided once via `cage create --set-secret` (stored at the per-cage state dir as `pending_secrets.json`, mode 0600) and never reconciled back into a cross-host portable form. The backup manifest records the expected env names so they can be re-set on the restore host with `--set-secret`.

## Related

- [Security model](security-model.md) — defended threats per mode
- [Architecture](architecture.md) — inspector chain and shared topology
- [Configuration reference](../reference/configuration.md) — `isolation:` and `vm:` settings
- [Install](../get-started/install.md) — backend-specific setup steps
