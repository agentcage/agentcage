<!-- owner: @luca  last-reviewed: 2026-09-04 -->
# Configuration

The top-level settings, container block, hardening, and restart policy for `cage.yaml`. Pair with the per-feature pages under `docs/reference/` for everything else.

Example configs: [`basic/cage.yaml`](../../examples/basic/) and [`openclaw/cage.yaml`](../../src/agentcage/scaffolds/openclaw/).

## Top-level settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `name` | `string` | *(required)* | Project name — used as the prefix for container names, network name, and quadlet filenames (e.g. `myapp` produces `myapp-cage`, `myapp-proxy`). |
| `isolation` | `string` | platform-dependent | Isolation backend: `"container"` (rootless Podman, Linux), `"vm"` (Lima VM), or `"apple-container"` (Apple `container` microVM, macOS 26+ Apple Silicon — see [Isolation modes](../explain/isolation-modes.md)). When omitted, `agentcage.config.default_isolation()` picks the best available: `apple-container` on macOS 26+ ASi with the `container` CLI installed, `vm` on other macOS / Intel hosts, `container` on Linux. Old `"firecracker"` configs are silently upgraded to `"vm"`. |
| `lifecycle` | `string` | `"service"` | Cage lifecycle mode: `"service"` (always running, auto-restart), `"interactive"` (on-demand, stops on exit, state preserved), or `"ephemeral"` (stops on exit, destroyed by `cage prune`). |
| `scaffold` | `string` | `""` | Scaffold name used to generate this config (shown in `cage list` output). Also gates staging of the `AGENTS.md` brief and the `agentcage` skill into the build context; see [How the agent learns about the API](policy-api.md#how-the-agent-learns-about-the-api). |
| `log_allowed` | `bool` | `false` | Log allowed requests to the proxy journal. |
| `max_request_body` | `int` | `10485760` (10 MB) | Max request body size in bytes. Set to `0` to disable the body-size limit. |
| `dns_servers` | `list[string]` | *(from host `/etc/resolv.conf`)* | Upstream DNS servers used by both the dnsmasq sidecar and the proxy container. |
| `watcher` | `block` | *(off)* | Opt-in traffic watcher: an in-egress LLM agent that re-analyzes the cage's recent traffic (audit + HAR capture) after the fact and flags suspicious patterns, revoking runtime grants its analysis damns. See [the traffic watcher](../explain/traffic-watcher.md). |

### watcher settings

The `watcher:` block enables the traffic watcher — see [the traffic-watcher explain page](../explain/traffic-watcher.md) for the trust model (it can only narrow: revoke runtime grants, never grant, never edit the static baseline). For the setup workflow, see [Run the traffic watcher](../how-to/run-the-traffic-watcher.md).

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enable` | `bool` | `false` | Master switch. Absent block = zero surface. Requires allowlist mode — rejected in blocklist mode, where the static baseline is the block list and the analysis would invert. |
| `interval_seconds` | `int` | `900` | Scan cadence (minimum 60). One model call per interval at most, and only when the window had traffic. The default is chosen for cost, not latency — see the cost note. |
| `window_seconds` | `int` | `3600` | After-the-fact lookback on the first scan after an egress (re)start (max 86400). |
| `max_flows` | `int` | `200` | Flows per analysis window (digest prompt cap, range 10–2000). |
| `auto_revoke` | `bool` | `true` | Apply runtime-grant revocations autonomously. `false` applies nothing but still records each revocation as a "revocation recommended" finding. Must be a real boolean — a quoted `"false"` is rejected at validation (it would silently enable revocations). |
| `context` | `string` | `""` | Trusted operator free-text describing the cage's purpose (max 4096 chars) — the same channel as `domains.auto.context`. |
| `max_digest_tokens` | `int` | `8000` | Hard ceiling on the digest sent to the model, in estimated tokens. The only setting that bounds spend regardless of traffic: `max_flows` bounds sample *count*, not size. When it bites, allowed flows are dropped oldest-first and blocked/flagged ones are kept. `0` removes the ceiling. *Since 0.37.0* |
| `dedup_samples` | `bool` | `true` | Collapse repeated flow shapes in the digest into one sample carrying a `repeated` count, keeping up to 3 distinct request bodies per group. Measured at 18.4% of the prompt payload on real traffic. Set `false` to send every sample. *Since 0.37.0* |
| `agent.provider` | `string` | *(required)* | `anthropic` \| `openai` \| `openrouter`. |
| `agent.model` | `string` | *(required)* | Model id. |
| `agent.api_key` | `string` | *(required)* | The watcher's own API key — an egress-only `source:` credential (`env:NAME` \| `systemd-creds:NAME`; `cmd:` is rejected — the egress has no shell). Reusing the decider's env var name is fine. |
| `agent.timeout_seconds` | `int` | `30` | LLM call timeout. |
| `agent.base_url` | `string` | *(provider default)* | `https://`-only override. |

```yaml
watcher:
  enable: true
  context: "runs the payments-reconciliation suite against staging"
  agent:
    provider: openrouter
    model: anthropic/claude-sonnet-4-5
    api_key: env:WATCHER_LLM_KEY
```

### What the watcher costs

Cost is driven by the model you choose and the scan cadence, not by how much traffic the cage makes: the digest is bounded, so a busy cage and a quiet one send similar prompts. A quiet window is free, because the watcher skips the call entirely.

The defaults (`interval_seconds: 900`, `max_digest_tokens: 8000`) cap a cage at roughly 885,000 input tokens per day. Against measured OpenRouter prices in September 2026, that is about $47 a month on a frontier-priced model and about $2.50 on a fast one. Dropping the cadence to 300 seconds triples both figures.

`agentcage watcher status` reports the actual digest size against the budget, so you can see real usage rather than only the ceiling. Configurations that could send more than 5 million tokens a day produce a warning at `cage create` and `cage update`.

Findings surface in `cage audit --inspector watcher` and via `agentcage watcher findings <name>`.

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
    - "/workspace/.git/hooks/:rw,noexec,nosuid,nodev,size=64M,notmpcopyup"
    - "/workspace/.claude/:rw,noexec,nosuid,nodev,size=64M,tmpcopyup"
```

The cage can write to both paths, but nothing reaches the host, so a caged
agent cannot plant a git hook that a later host-side `git commit` executes,
nor a project `.claude/settings.json` `hooks` block that another cage honors
on launch.

#### Copy-up: what a mask starts out holding

`tmpcopyup` seeds the tmpfs with a copy of the directory it covers;
`notmpcopyup` leaves it empty. Both are declared per entry, and the choice is
independent of the masking itself — the cage writes to the tmpfs either way,
so nothing it does reaches the host.

A mask that names neither option gets `notmpcopyup`. Empty is what a mask is
usually for, and pinning it keeps the two backends identical: Podman appends
`tmpcopyup` to every tmpfs that does not say otherwise, while Apple container's
bare `--tmpfs` has no option channel at all, so leaving it unspecified used to
mean "full" on one backend and "empty" on the other. Entries that are not
inside a mount (`/tmp`, `/var/cache`, …) are untouched and keep whatever the
runtime does by default — their contents are the image author's business.

The scaffolds split the two masks by intent. `.git/hooks/` is empty: the mask
is `noexec`, so a copied-up hook could never run in the cage, and a copy would
only add confusion. `.claude/` is seeded, so a caged agent still reads the
project's `settings.json`, commands and subagents — as its own throwaway copy.

The seeded copy is handed to the cage workload user (uid 1000 unless
`container.user` names another numeric uid), so the agent can edit it. The
mechanism differs by backend:

- **Container and VM:** the option reaches Podman verbatim and the OCI runtime
  performs the copy before the workload starts, so the content is there from
  the first instant. The runtime copies as the user-namespace root and does not
  replay the source's ownership, so a post-start hook on the cage unit chowns
  the copy to the cage user; for a moment after `cage start` the content is
  readable but not yet writable.
- **Apple container:** the option cannot reach Apple's runtime, so agentcage
  emulates it. The host directory the mask covers is mounted **read-only**
  under `/run/agentcage/masks/`, and the cage's init replays it into the tmpfs
  — chowned to the cage user — before the workload starts. Copy-up is only
  emulated where there is a host directory to seed from: a mask over a named
  volume, over an `np` bind, or a tmpfs over a plain image directory comes up
  empty here, and `agentcage cage create` warns when you ask for one.

A copy-up source that resolves outside the bind it came from — a project
containing `.claude -> ../../.ssh` — is refused with a warning rather than
mounted.

Making the cage able to write there takes one extra option. Both OCI runtimes
give a tmpfs the mode of the directory it is mounted over whenever the entry
declares no `mode=` of its own, and the tmpfs root is owned by the
user-namespace root — for a mask that is the *host* directory's mode (usually
`0755`) and an owner the workload is not, so a non-root `container.user` could
not write to its own mask. agentcage therefore appends `mode=1777` (`/tmp`
semantics: writable by any uid in the cage, sticky) to any entry whose target
sits at or below a mount target. Declare your own `mode=` to opt out. Entries
that are not inside a mount (`/tmp`, `/var/cache`, …) keep inheriting the image
directory's mode.

A mask over a path that does not exist on the host creates it there — a bind
shares inodes with its source, so the runtime's mount-point `mkdir` writes
through. agentcage records which of those directories were absent when the
cage started and removes them again, while still empty, on `cage stop` and
`cage destroy`. Directories you already had, and any that gained content, are
left alone.

**Apple container applies the mounts but not their options.** Apple's
`container run --tmpfs` takes a bare path, so `noexec`, `nosuid`, `nodev` and
`size=` are dropped — as is the `mode=` above — and each mount lands with
kernel-default tmpfs semantics. The exception is `tmpcopyup`/`notmpcopyup`,
which agentcage honors by emulation as described above.
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
