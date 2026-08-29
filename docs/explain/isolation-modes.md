<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Isolation modes

agentcage runs each cage inside one of three isolation backends. They share the same inspector chain, secret injection, DNS filtering, and audit pipeline — what differs is the trust boundary between the cage and the host.

| Backend | Boundary | Platforms |
|---|---|---|
| `container` | Linux namespaces + rootless Podman hardening | Linux (default) |
| `vm` | Dedicated guest kernel inside a Lima VM | macOS Intel + Apple Silicon (default), Linux |
| `apple-container` | Two sibling Apple microVMs per cage | macOS 26+ Apple Silicon (default when available) |

When `isolation:` is omitted from `cage.yaml`, agentcage picks the best available for the host.

## Topology

Every backend uses the same two-role shape: a workload container with no internet gateway, and an egress sibling that runs the proxy and DNS filter. The workload's default route points at the egress, so all traffic flows through the inspector chain.

```text
<name>-cage  (workload, no gateway)
     │
     └──▶  <name>-egress  (mitmproxy + DNS filter)  ──▶  internet
```

In `container` mode both sit on a single rootless Podman `--internal` network. In `vm` mode the pair lives inside a Lima VM, one VM per cage. In `apple-container` mode they're two Apple microVMs on a per-cage Apple network.

See [Architecture](architecture.md) for the inspector chain and how requests flow through it.

## Comparing the three

| | container | vm | apple-container |
|---|---|---|---|
| Trust boundary | Shared kernel + namespace isolation | Hypervisor (KVM / HVF) | Apple `Virtualization.framework` per microVM |
| Kernel | Shared with host | Dedicated guest kernel | Dedicated microVM kernel |
| Container-escape risk | Mitigated, not eliminated | Lands in VM, not on host | Lands in microVM, not on host |
| macOS support | No | Yes (Intel + Apple Silicon) | macOS 26+ Apple Silicon only |
| Boot overhead | ~1 s | ~15–30 s | ~3–5 s warm, ~25–30 s cold |
| Host bind mounts | Yes | Yes (paths under `$HOME`, `~/.ssh` etc. blocked) | Yes (paths under `$HOME`) |
| Secrets at rest | Encrypted on host (systemd-creds when available, else Podman secret store) | Same as host, bridged into the VM at deploy | Per-cage encrypted file on host, mounted read-only into the egress sibling |

For the threat-by-threat matrix, see [Security model](security-model.md).

## Known limitations

**container — shared kernel.** A kernel CVE or container-runtime escape bypasses all in-cage hardening. Use `vm` or `apple-container` when this risk is unacceptable.

**vm — host bind mounts are restricted.** Paths under blocked directories like `~/.ssh` or `~/.aws` are rejected, and the path must exist on the host before `cage create`. Mounts are read-only by default.

**apple-container — most edits need `cage update`.** Allowlist, command, env, secret-injection rules, capture, and autostart are baked into the wrapper image at build time. `domain add / rm` auto-rebuilds; other edits need an explicit `cage update`.

**apple-container — tmpfs options are not applied.** `container.tmpfs` mounts are created, including the scaffold masks over `/workspace/.git/hooks/` and `/workspace/.claude/`, but Apple's runtime takes a bare path so `noexec`, `nosuid`, `nodev` and `size=` are dropped. Set `container.memory` to bound an unlimited tmpfs. See [tmpfs mounts](../reference/configuration.md#tmpfs-mounts).

**apple-container — `cage backup --include-secrets` is unsupported.** Secrets are provided once at `cage create` and never reconciled into a portable backup. The backup manifest records the env-var names; re-set them on the restore host with `--set-secret`.

## Related

- [Security model](security-model.md) — defended threats per mode
- [Architecture](architecture.md) — inspector chain and shared topology
- [Configuration reference](../reference/configuration.md) — `isolation:` and `vm:` settings
- [Install](../get-started/install.md) — backend-specific setup steps
