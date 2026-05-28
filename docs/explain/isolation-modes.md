<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Isolation modes

agentcage runs each cage inside one of three isolation backends: rootless `container`, Lima `vm`, or Apple `apple-container`. The choice shapes the trust boundary around the agent — namespaces vs a guest kernel vs a sibling-microVM split — but the inspector chain, secret injection, DNS filtering, and audit pipeline are identical across all three.

## When to use which

| Situation | Pick |
|---|---|
| Linux host, development or CI | `container` |
| Linux host, untrusted agent or production | `vm` |
| macOS Intel or pre-26 | `vm` |
| macOS 26+ Apple Silicon, default fast path | `apple-container` |
| Cage needs `apt install` at runtime | `container` or `vm` (apple-container bakes the image at build time) |
| Cage uses an Alpine / musl base image | `container` or `vm` (apple-container is glibc-only) |
| Need to bind-mount host directories into the agent | `container` only |
| `--as-root` operator sessions must not bypass egress | `vm` |

When `isolation:` is omitted from `cage.yaml`, agentcage picks the best available: `apple-container` on macOS 26+ Apple Silicon with the `container` CLI installed, `vm` on other macOS hosts (including Intel), and `container` on Linux.

## How container isolation works

Three rootless Podman containers run directly on the host on a `--internal` Podman network with no internet gateway. The agent sits on the internal network only; the DNS sidecar and proxy are dual-homed so they can reach upstream.

```text
host (rootless podman)
└── <name>-net (--internal, no gateway)
    ├── <name>-cage       agent, internal-only, default route → proxy
    ├── <name>-dns        dnsmasq, dual-homed
    └── <name>-proxy      mitmproxy + inspector chain, dual-homed
```

The agent's default route points at the proxy. iptables REDIRECT rules on the proxy intercept outbound TCP on the allowed ports (default `[80, 443]`) regardless of whether the application honours `HTTP_PROXY`. A default-deny `filter:FORWARD` policy on the proxy drops any port not explicitly allowed by the cage's `ports` config.

The isolation boundary is Linux namespaces plus rootless Podman hardening: read-only root filesystem, all capabilities dropped on the workload, `no-new-privileges`. The host kernel is shared — a kernel or runtime escape lands on the host.

## How VM isolation works

The same three-container topology runs inside a Lima-managed Linux VM. Lima creates one VM per cage and runs Podman inside it with the same quadlet unit files.

```text
host
└── <name>-cage  (Lima VM, dedicated kernel, KVM/HVF)
    └── podman (inside VM)
        ├── <name>-dns
        ├── <name>-proxy
        └── <name>-cage   user workload
```

The VM boundary is enforced by the CPU's virtualization extensions (VT-x / AMD-V on Linux, Hypervisor.framework on macOS). A container escape inside the VM lands in the VM's userspace, not on the host. A kernel exploit affects only the guest kernel.

Lima handles VM networking transparently — no TAP devices, no bridges, no root. Secret storage on the host still uses Podman's secret store; all other operations happen inside the VM.

## How apple-container isolation works

On macOS 26+ Apple Silicon, each cage runs as **two sibling Apple `container` microVMs** on a per-cage Apple network. One microVM holds the egress filter (mitmproxy + dnsmasq + iptables); the other holds the workload. The cage VM's default route points at the egress sibling, so all cage egress flows through the proxy.

```text
host (apple `container` apiserver)
└── <cage>-net (per-cage Apple network)
    ├── <cage>-egress    shared agentcage-egress image
    │   ├── tini → supervisor (POSIX sh, PID 1)
    │   ├── iptables: PREROUTING REDIRECT 80/443 → :8443,
    │   │             FORWARD default DROP
    │   ├── dnsmasq (uid 201): scoped recursion, sinks unlisted zones
    │   ├── mitmproxy (uid 200): allowlist, secret injection, audit, capture
    │   └── binds: secrets, certs, logs, config
    │
    └── <cage>           per-cage wrapper on top of user image
        ├── cage-init.sh: ping egress sibling → set default route →
        │                 install proxy CA → capsh --drop=all → exec workload
        ├── workload runs as uid 1000, empty caps, NoNewPrivs
        └── no mitmproxy, no dnsmasq, no iptables, no jq
```

The hypervisor boundary is Apple's `Virtualization.framework`, the same one Lima uses on macOS. The two-microVM split means workload-threat invariants match the `container` and `vm` backends: secrets cleartext lives only in the egress sibling's filesystem; the cage VM has no iptables binary to flush and no dnsmasq config to read.

A shared `agentcage-egress` image is built once per host so sibling cages reuse the ~120 MB mitmproxy bundle. Per-cage builds layer a small wrapper on top of the user's image.

## Comparing the three

| | container | vm | apple-container |
|---|---|---|---|
| Boundary | Linux namespaces + rootless Podman | KVM / HVF guest kernel (Lima) | Two sibling Apple microVMs (Virtualization.framework) |
| Kernel | Shared with host | Dedicated guest kernel | Dedicated microVM kernel |
| Container-escape risk | Mitigated by hardening, not eliminated | Escape lands in VM | Escape lands in microVM |
| Egress defense layers | iptables-in-cage + non-routed internal net | iptables-in-cage + non-routed internal net | iptables in egress sibling (cage VM has no iptables) |
| Root required | No | No (Lima manages networking) | No (Apple `container` is rootless) |
| macOS support | No | Yes (Intel + Apple Silicon) | macOS 26+ Apple Silicon only |
| User image constraint | Any Linux base | Any (built inside the VM) | glibc-based (debian/ubuntu/...) |
| Boot overhead | ~1s | ~15–30s | ~3–5s warm, ~25–30s cold |
| Host bind mounts into cage | Yes | No | No |
| Secrets at rest | Host Podman secret store | Host Podman secret store | Host environment at `cage start`, bind-mounted as files into the egress sibling |

For the threat-by-threat matrix and what each mode defends against, see [Security model](security-model.md).

## Known limitations

**container — shared kernel.** All containers share the host kernel. A kernel CVE or container-runtime escape bypasses all in-cage hardening. Use `vm` or `apple-container` when this risk is unacceptable.

**vm — no host volume mounts.** The agent runs inside a VM with its own filesystem; there is no mechanism to bind-mount host directories into the workload. Code must be baked into the image or fetched at runtime.

**vm — boot overhead.** A few seconds of VM boot per `cage create` or cold start, compared to sub-second for `container`.

**apple-container — glibc-only user images.** The supervisor includes mitmproxy as a glibc-linked PyInstaller bundle, and the `pip install` fallback fails on Alpine because `mitmproxy-rs` requires a Rust toolchain Alpine doesn't ship stably. `cage create` against an Alpine base exits with a clear message. Use a debian/ubuntu base, or switch to `isolation: vm`.

**apple-container — `cage exec --service proxy|dns` not addressable.** On `container` and `vm`, the proxy and DNS sidecar are separate containers with their own names. On `apple-container`, they run as supervised processes (uid 200 and 201) inside the egress sibling; there is no separate exec target. Use `cage logs` for combined output and `cage exec -- ps aux` to inspect individual processes.

**apple-container — `--as-root` can bypass egress for that exec session.** The cage microVM is created with `CAP_NET_ADMIN` so `cage-init.sh` can set the default route at startup. Apple's runtime reconstructs `CapBnd` from `configuration.capAdd` on every exec, so `cage exec --user 0` re-acquires `CAP_NET_ADMIN` even after the supervisor's `capsh --drop=all`. An operator with `--as-root` can `ip route replace default` to route around the egress sibling. They cannot read cleartext secrets (different microVM) or flush iptables (no binary in the wrapper). Workload threat is unaffected. If your threat model needs hardened `--as-root` sessions, use `isolation: vm`.

**apple-container — `cage update` is needed for most `cage.yaml` edits.** Allowlist, command, env, secret-injection rules, capture config, and autostart are baked into the wrapper image at build time. `domain add / rm` auto-rebuilds; other field edits require an explicit `cage update`.

**apple-container — `cage backup --include-secrets` is rejected.** Secrets are env-passed at `cage start` from `os.environ`; by the time backup runs, the values are not anywhere agentcage can re-read them. The backup manifest records the expected env names so they can be re-set on the restore host.

**apple-container — `cage audit --since` filters in Python.** The audit data is a plain JSONL file with no time index, so `--since` is a post-parse filter rather than a journal cursor. Correct results, slightly slower for very large audit files.

**apple-container — `cage exec` defaults to uid 1000.** Matches the workload's uid and capability set: no `CAP_NET_ADMIN`, no `CAP_DAC_OVERRIDE`. Pass `--as-root` for operator-debug paths that genuinely need root (`apt-get install`, inspecting iptables in the egress sibling, reading dnsmasq logs). This is intentional — a malicious workload that tricks the operator into running `cage exec <cage> -- malicious-binary` no longer gets root automatically.

**apple-container — virtiofs locks file ownership to the host user.** Files written by uid 200 or uid 201 inside the cage show up as the host user on the macOS side. Apple's virtiofs bind mount maps all guest uids to the host file's owner. The supervisor uses sticky-bit world-writable directories so any in-cage uid can still write logs.

**apple-container — dnsmasq strips AAAA records.** `getent ahosts` returns IPv4 only. Without `filter-AAAA`, the cage would try IPv6 first, fail instantly (IPv6 killed at netfilter and sysctl), and fall back to v4. Correct behavior, just visible in client logs.

**apple-container — `apt-get update` emits cosmetic HTTP→HTTPS warnings.** apt tries HTTP first, the upstream redirects to HTTPS, mitmproxy handles the TLS interception correctly, the fetches succeed. The `Failed to fetch http://...` lines are cosmetic; `apt-get update` returns 0.

## Related

- [Security model](security-model.md) — defended threats per mode
- [Architecture](architecture.md) — inspector chain and shared topology
- [Configuration reference](../reference/configuration.md) — `isolation:` and `vm:` settings
- [Install](../get-started/install.md) — backend-specific setup steps
