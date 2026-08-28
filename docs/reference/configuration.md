<!-- owner: @luca  last-reviewed: 2026-05-28 -->
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

## Container settings

Settings under `container:`.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `image` | `string` | *(required)* | Container image for the agent. |
| `command` | `list[string]` | *(none)* | Command to run in the agent container (e.g. `["node", "app.js"]`). |
| `volumes` | `list[string]` | `[]` | Host bind specs in `host:container[:options]` form. Host paths are resolved to absolute paths at generation time; regenerate the deployment if a source moves. Add the agentcage-only `np` option to make one bind non-persistent; see [Non-persistent bind mounts](#non-persistent-bind-mounts). |
| `env` | `map[string, string]` | `{}` | Environment variables. `${VAR}` references are expanded from your current shell environment at generation time — the values are baked into the generated quadlet files, not resolved at container start. |
| `named_volumes` | `map[string, string]` | `{}` | Podman named volume to mount spec (e.g. `mydata: "/data:rw"`). Not resolved with realpath. |
| `tmpfs` | `list[string]` | `[]` | tmpfs mount specs in `path[:options]` form — useful for writable areas on read-only containers, and for masking a path inside a bind mount. See [tmpfs mounts](#tmpfs-mounts). |
| `ports` | `list[string]` | `[]` | Published port specs — see [Ports](#ports). |
| `podman_secrets` | `list[string]` | `[]` | [Podman secret](https://docs.podman.io/en/latest/markdown/podman-secret.1.html) names (injected as env vars). |
| `user` | `string` | `"1000:1000"` | UID:GID for the cage workload (Quadlet `User=`). Set to `""` to use the image default. Interactive `agentcage run` / `cage exec` / `cage shell` sessions are pinned to uid 1000 (or `0` with `--as-root`) regardless of this field — matching the apple-container backend's behavior. See [Podman `--user`](https://docs.podman.io/en/latest/markdown/podman-run.1.html). |
| `userns` | `string` | `""` | User namespace mode (e.g. `"keep-id"`). See [Podman `--userns`](https://docs.podman.io/en/latest/markdown/podman-run.1.html). |
| `memory` | `string` | *(none)* | Memory limit (e.g. `"4g"`). See [Podman `--memory`](https://docs.podman.io/en/latest/markdown/podman-run.1.html). |
| `cpus` | `string` | *(none)* | CPU limit (e.g. `"2.0"`). See [Podman `--cpus`](https://docs.podman.io/en/latest/markdown/podman-run.1.html). |
| `nested_containers` | `bool` | `false` | Enable podman-in-podman support. See [Nested containers](#nested-containers). |

### Non-persistent bind mounts

Add the inline `np` option to an individual `container.volumes` entry when the
cage must be able to edit that mount without writing changes back to the host:

```yaml
container:
  volumes:
    - "~/project:/workspace:rw,np"  # writable in the cage; changes discarded
    - "~/.cache/tool:/cache:rw"     # ordinary persistent host bind
```

`np` affects only the entry carrying it. Unflagged host binds and
`container.named_volumes` retain their normal persistence. On the next start,
the ephemeral target is seeded again from the host source, so changes from a
previous cage session do not reappear.

The host source must already exist. In particular, `agentcage run` does not
create a missing source for an `np` bind; the normal missing-volume warning and
skip behavior applies.

For consistent behavior across all isolation backends, use `np` by itself or
as `rw,np`. Other options are rejected when combined with `np`: `ro`
contradicts the writable ephemeral target; Podman's `z`/`Z` and `O` conflict
with the generated overlay; `U` could mutate host ownership; and Apple
container cannot apply additional options to its bare tmpfs mount.

Implementation differs by source and backend but preserves the same external
semantics:

- **Container and VM, directory source:** the host directory is a read-only
  lower layer beneath a Podman overlay. Upper/work state is kept under the
  user's runtime directory and removed on stop and before every start.
- **Container and VM, file source:** the host file is copied to an ephemeral
  runtime file and mounted at the requested target.
- **Apple container, directory source:** the directory is copied into a tmpfs
  at startup. Large directory mounts therefore consume VM memory and increase
  startup time.
- **Apple container, file source:** the file is copied to its exact target in
  the fresh cage filesystem.

On Apple container the seeded copy is handed to the cage workload user (uid
1000) so the mount is writable regardless of who owns the host source; file
modes are otherwise preserved from the host. The copy runs during cage
startup, so a `cage exec` issued in the first seconds after `cage start` can
observe the target still empty.

Use an ordinary `ro` bind instead if the cage does not need to edit the data.
Use `container.tmpfs` for empty scratch space that does not need initial
contents from the host.

### tmpfs mounts

Each `container.tmpfs` entry is `path[:options]`. The cage sees an empty,
writable directory at `path`; everything written there is discarded when the
cage stops.

A tmpfs entry can also target a path *inside* a bind mount, which masks the
host content underneath it. The built-in scaffolds use this to close two
cage-to-host paths:

```yaml
container:
  tmpfs:
    - "/workspace/.git/hooks/:rw,noexec,nosuid,nodev,size=64M"
    - "/workspace/.claude/:rw,noexec,nosuid,nodev,size=64M"
```

The cage can write to both paths, but nothing reaches the host, so a caged
agent cannot plant a git hook that a later host-side `git commit` executes,
nor a project `.claude/settings.json` `hooks` block that another cage honors
on launch.

**Apple container applies the mounts but not their options.** Apple's
`container run --tmpfs` takes a bare path, so `noexec`, `nosuid`, `nodev` and
`size=` are dropped and each mount lands with kernel-default tmpfs semantics.
The masks above still work — the protection comes from the overlay hiding the
bind, not from `noexec`. What is lost is the size cap: a tmpfs the cage fills
is bounded only by the cage VM's memory, so set `container.memory` on this
backend. `agentcage cage create` warns and names the affected paths.

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
