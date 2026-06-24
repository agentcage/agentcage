<!-- owner: @luca  last-reviewed: 2026-06-24 -->
# Configuration

The top-level settings, container block, hardening, and restart policy for `cage.yaml`. Pair with the per-feature pages under `docs/reference/` for everything else.

Example configs: [`basic/cage.yaml`](../../examples/basic/) and [`openclaw/cage.yaml`](../../src/agentcage/scaffolds/openclaw/).

## Top-level settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `name` | `string` | *(required)* | Project name — used as the prefix for container names, network name, and quadlet filenames (e.g. `myapp` produces `myapp-cage`, `myapp-proxy`). |
| `isolation` | `string` | platform-dependent | Isolation backend: `"container"` (rootless Podman, Linux), `"vm"` (Lima VM), or `"apple-container"` (Apple `container` microVM, macOS 26+ Apple Silicon — see [Isolation modes](../explain/isolation-modes.md)). When omitted, `agentcage.config.default_isolation()` picks the best available: `apple-container` on macOS 26+ ASi with the `container` CLI installed, `vm` on other macOS / Intel hosts, `container` on Linux. Old `"firecracker"` configs are silently upgraded to `"vm"`. |
| `lifecycle` | `string` | `"service"` | Cage lifecycle mode: `"service"` (always running, auto-restart), `"interactive"` (on-demand, stops on exit, state preserved), or `"ephemeral"` (stops on exit, destroyed by `cage prune`). |
| `scaffold` | `string` | `""` | Scaffold name used to generate this config (shown in `cage list` output). |
| `log_allowed` | `bool` | `false` | Log allowed requests to the proxy journal. |
| `max_request_body` | `int` | `10485760` (10 MB) | Max request body size in bytes. Set to `0` to disable the body-size limit. |
| `dns_servers` | `list[string]` | *(from host `/etc/resolv.conf`)* | Upstream DNS servers used by both the dnsmasq sidecar and the proxy container. |

### VM settings

VM-specific settings under `vm:`. Only used when `isolation: vm`.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `vcpus` | `int` | `4` | Number of virtual CPUs to allocate to the VM. |
| `mem_mb` | `int` | `4096` | VM memory in megabytes. |

See [Isolation modes](../explain/isolation-modes.md) for how VM isolation works and [Install](../get-started/install.md) for setup.

### DNS servers example

```yaml
dns_servers:
  - 100.100.100.100   # Tailscale MagicDNS (for *.ts.net)
  - 1.1.1.1
  - 8.8.8.8
```

### DNS upstream mode (apple-container)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `dns_upstream` | `string` | `gateway` | `gateway` or `direct`. apple-container only. |

*Since 0.26.0.* `dns_upstream` controls how the apple-container egress reaches upstream DNS. `gateway` (default) forwards to the vmnet gateway, which tracks host network changes (Wi-Fi/VPN) without a rebuild. Set `direct` when the host runs a resolver the microVM can't reach — Cloudflare WARP and other loopback/NetworkExtension resolvers, or locked-down corporate DNS — which shows up as cages failing to resolve, or allowlisted hosts returning `502`. `direct` forwards to `dns_servers` and resolves the proxy through the in-egress dnsmasq, bypassing the gateway. See [Architecture](../explain/architecture.md) for how egress DNS flows.

```yaml
dns_servers:
  - 1.1.1.1
  - 8.8.8.8
dns_upstream: direct
```

Set `dns_servers` explicitly with `direct` — auto-detection can't read the host's real upstreams behind a loopback resolver. The trade-off is losing live host-tracking: after the host's DNS changes, run `agentcage cage update <name>`. Other backends ignore this setting (their egress already queries `dns_servers` as a parallel `--all-servers` upstream).

## Container settings

Settings under `container:`.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `image` | `string` | *(required)* | Container image for the agent. |
| `command` | `list[string]` | *(none)* | Command to run in the agent container (e.g. `["node", "app.js"]`). |
| `volumes` | `list[string]` | `[]` | Bind mount specs (`host:container`). Host paths are resolved to absolute paths at generation time. If you move files after generating, regenerate the quadlets. |
| `env` | `map[string, string]` | `{}` | Environment variables. `${VAR}` references are expanded from your current shell environment at generation time — the values are baked into the generated quadlet files, not resolved at container start. |
| `named_volumes` | `map[string, string]` | `{}` | Podman named volume to mount spec (e.g. `mydata: "/data:rw"`). Not resolved with realpath. |
| `tmpfs` | `list[string]` | `[]` | tmpfs mount specs (useful for writable areas on read-only containers). |
| `ports` | `list[string]` | `[]` | Published port specs — see [Ports](#ports). |
| `podman_secrets` | `list[string]` | `[]` | [Podman secret](https://docs.podman.io/en/latest/markdown/podman-secret.1.html) names (injected as env vars). |
| `user` | `string` | `"1000:1000"` | UID:GID for the cage workload (Quadlet `User=`). Set to `""` to use the image default. Interactive `agentcage run` / `cage exec` / `cage shell` sessions are pinned to uid 1000 (or `0` with `--as-root`) regardless of this field — matching the apple-container backend's behavior. See [Podman `--user`](https://docs.podman.io/en/latest/markdown/podman-run.1.html). |
| `userns` | `string` | `""` | User namespace mode (e.g. `"keep-id"`). See [Podman `--userns`](https://docs.podman.io/en/latest/markdown/podman-run.1.html). |
| `memory` | `string` | *(none)* | Memory limit (e.g. `"4g"`). See [Podman `--memory`](https://docs.podman.io/en/latest/markdown/podman-run.1.html). |
| `cpus` | `string` | *(none)* | CPU limit (e.g. `"2.0"`). See [Podman `--cpus`](https://docs.podman.io/en/latest/markdown/podman-run.1.html). |
| `nested_containers` | `bool` | `false` | Enable podman-in-podman support. See [Nested containers](#nested-containers). |

### Ports

Publish container ports to the host. Each entry is a string in one of two formats:

| Format | Example | Description |
|--------|---------|-------------|
| `"BIND:HOST_PORT:CONTAINER_PORT"` | `"127.0.0.1:8080:80"` | Bind to a specific interface. |
| `"HOST_PORT:CONTAINER_PORT"` | `"8080:80"` | Bind to localhost (`127.0.0.1`). |

Ports must be integers between 1 and 65535. The three-part form with an explicit bind address is recommended — binding to `127.0.0.1` ensures the port is only accessible from the host, not from the network.

```yaml
container:
  ports:
    - "127.0.0.1:8080:8080"    # bind to localhost only (recommended)
    - "0.0.0.0:3000:3000"      # bind to all interfaces (accessible from LAN)
    - "9090:9090"              # short form (binds to 127.0.0.1)
```

Port conflicts are detected at `cage create` / `cage update` time — if a host port is already in use, the command fails with a suggestion to pick a different port.

### Nested containers

When `nested_containers: true`, the cage container can run podman (and docker via a shim) to spawn inner containers. This is required for AI agent frameworks that create Docker containers as part of their workflow.

Enabling this option automatically:

- Adds 16 Linux capabilities (`SYS_ADMIN`, `SYS_CHROOT`, `MKNOD`, etc.) instead of the default `DropCapability=ALL`.
- Forces `User=0` and `NoNewPrivileges=false`.
- Adds `/dev/fuse` device and `seccomp=unconfined`.
- Creates a persistent storage volume for inner podman state.
- Bind-mounts a Docker CLI shim and podman config files.

The nested-containers base image must be built first with a custom scaffold's `build.sh` (or equivalent) before `cage create`.

```yaml
container:
  image: "localhost/agentcage-nested"
  nested_containers: true
```

> **Security note:** Nested containers require elevated capabilities that weaken container hardening. All network-level protections (proxy inspection, domain filtering, secret detection) remain active. Only supported with `isolation: container`. See [Security model](../explain/security-model.md).

## Container hardening

Nested under `container:`. All hardening options are enabled by default.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `read_only` | `bool` | `true` | Read-only root filesystem. See [Podman `ReadOnly=`](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html). |
| `drop_capabilities` | `string \| list` | `"ALL"` | Linux capabilities to drop. `"ALL"` drops everything; use a list for specific caps (e.g. `[NET_RAW]`). Set to `[]` to keep all caps. |
| `add_capabilities` | `list[string]` | `[]` | Capabilities to add back (e.g. `[NET_BIND_SERVICE]`). |
| `no_new_privileges` | `bool` | `true` | Prevent privilege escalation. |
| `security_label_disable` | `bool` | `true` | Disable SELinux/AppArmor labeling. |

## Restart policy

Nested under `container:`.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `restart` | `string` | `"on-failure"` | Systemd restart policy: `"no"`, `"on-failure"`, `"always"`. |
| `restart_sec` | `int` | `10` | Seconds to wait before restart. |
| `timeout_start_sec` | `int` | `120` | Systemd `TimeoutStartSec`. |
| `timeout_stop_sec` | `int` | `30` | Systemd `TimeoutStopSec`. |

## Related

- [Domains](domains.md) — allow/block/passthrough host filtering.
- [Ports](ports.md) — TCP/UDP egress policy and the default-deny FORWARD chain.
- [Secret injection](secret-injection.md) — keep real secrets out of the cage container.
- [Protocol relays](protocol-relays.md) — IMAP and SMTP credential brokers.
- [Inspectors](inspectors.md) — the inspector chain, secret detection, and writing custom inspectors.
- [Traffic capture](capture.md) — opt-in HAR recording.
