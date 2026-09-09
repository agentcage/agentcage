# Isolation Backends

agentcage supports three distinct isolation backends:
1. **`container`** (Linux rootless Podman + systemd quadlets)
2. **`apple-container`** (macOS 26+ native Apple Container microVMs)
3. **`vm`** (Lima virtual machine with QEMU / Apple Virtualization)

Every backend enforces identical egress network isolation, TLS inspection, and placeholder secret injection. However, their isolation boundaries, operating system requirements, and filesystem behaviors differ.

---

## Backend Comparison Matrix

| Feature | `container` | `apple-container` | `vm` |
| :--- | :--- | :--- | :--- |
| **Host Operating System** | Linux | macOS 26+ (Apple Silicon) | macOS (Intel / all), Linux |
| **Virtualization Boundary** | Linux user namespaces + cgroups v2 | Lightweight Apple microVMs (VZ) | Full Linux VM (QEMU / VZ) |
| **Default On** | Linux | macOS 26+ ASi with Apple `container` | Older macOS, Intel Macs |
| **Startup Latency** | **Fastest** (< 1 second) | **Fast** (~1–2 seconds) | **Moderate** (~10–15s VM boot) |
| **Host Bind Mounts** | Arbitrary paths (`rw`/`ro`) | Any path under `$HOME` | Staged copies / sshfs |
| **Read-Only Rootfs** | Supported (`read_only: true`) | Always RW (warned at create) | Supported |
| **Pivot Masks (`.git/hooks`)**| Native tmpfs overlays | Emulated via tmpcopyup | Native tmpfs overlays |
| **Named Podman Volumes** | Supported | Not supported | Supported |
| **Published Host Ports** | Supported (via reverse proxy) | Reached via direct vmnet IP | Supported |
| **Nested Containers** | Supported (`nested_containers: true`)| Not supported | Not supported |
| **Secret Storage** | `systemd-creds` (encrypted) | macOS Keychain | macOS Keychain (macOS) / `systemd-creds` (Linux) |
| **Custom Inspector Files** | Supported (`path: ...`) | Built-ins only | Supported (`path: ...`) |
| **Resource Overhead** | Zero idle background overhead | Minimal (~2 microVMs per cage) | Dedicated VM memory/CPU allocation |

---

## 1. `container` — Rootless Podman on Linux

The `container` backend is the default and recommended engine for Linux hosts.

### How It Works
- Runs directly on the host Linux kernel using **rootless Podman**.
- Both `<name>-cage` and `<name>-egress` containers run in unprivileged user namespaces with UID/GID mapping (`100000+`).
- Both containers attach to a private Podman bridge network generated with `Internal=true`.
- Service lifecycles are declared as **systemd user quadlets** placed in `~/.config/containers/systemd/`. Systemd automatically handles service restarts, dependency ordering, and logging.

### Strengths
- **Near-Zero Latency**: Containers launch in milliseconds without hypervisor boot times.
- **Resource Efficiency**: Shares kernel page caches and memory; consumes zero resources when idle.
- **Full Linux Hardening**: Supports complete capability dropping (`drop_capabilities: [ALL]`), `no_new_privileges`, read-only root filesystems, and fine-grained tmpfs options (`noexec`, `nosuid`, `size=`).
- **Advanced Features**: Supports named volumes, host port forwards, and nested rootless containers for builds (`podman build` inside the cage).

### Limitations
- **Shared Kernel**: The agent workload shares the host Linux kernel. A zero-day Linux kernel privilege escalation exploit could theoretically break out to the host user (mitigated by user namespaces and capability drops).
- **systemd Dependency**: Requires a systemd user session with lingering enabled (`loginctl enable-linger $USER`).

---

## 2. `apple-container` — Native macOS MicroVMs

The `apple-container` backend is designed specifically for Apple Silicon Macs running macOS 26+ equipped with Apple's `container` command-line runtime (`brew install container`).

### How It Works
- Instead of running a heavy virtual machine, it leverages Apple's native container virtualization framework to spin up **two lightweight Linux microVMs per cage** (`<name>-cage` and `<name>-egress`).
- The egress microVM acts as the network router and supervisor, running `dnsmasq` and `mitmdump`.
- Managed on macOS by a unified agentcage supervisor and launchd daemon.

### Strengths
- **Native Hardware Isolation**: Each container runs inside its own isolated microVM with a dedicated Linux kernel boundary. Even a kernel exploit inside the cage cannot reach the macOS host kernel.
- **High Performance**: Apple's native virtualization framework provides fast I/O and low memory overhead compared to traditional VMs.
- **Integrated Storage**: Secrets are secured in the macOS Keychain.

### Limitations
- **macOS 26+ & Apple Silicon Only**: Requires modern Apple Silicon hardware running macOS 26 or newer.
- **Mount Path Restrictions**: Host volume mounts must reside under `$HOME`.
- **Writable Rootfs**: The Apple container runtime does not currently enforce read-only container root filesystems (`read_only: true` is warned).
- **Port Publishing**: Inbound host ports cannot be published to `127.0.0.1`; local services inside the cage must be accessed via their virtual network IP.

---

## 3. `vm` — Lima Virtual Machine

The `vm` backend is the universal cross-platform fallback, using **Lima** to manage an isolated Linux virtual machine running QEMU or Apple Virtualization.

### How It Works
- Creates a dedicated Lima instance (`agentcage-<name>`) running Alpine or Debian Linux.
- Inside the Lima VM, agentcage provisions rootless Podman and systemd quadlets identical to the Linux `container` backend.
- Network traffic passes from the inner cage container through the inner egress proxy before exiting the Lima VM.

### Strengths
- **Universal Compatibility**: Runs on Intel Macs, older macOS versions, and Linux machines where hardware virtualization is required.
- **Hard Hypervisor Boundary**: Provides strict hardware virtualization; the agent executes within an isolated guest OS kernel.
- **Full Feature Parity**: Inside the VM, all Podman features (read-only rootfs, named volumes, custom inspector paths, quadlet restarts) work identically to native Linux.

### Limitations
- **Startup Latency**: Launching a VM requires 10–15 seconds to boot the guest operating system.
- **Resource Footprint**: Consumes dedicated RAM and CPU allocations specified in `cage.yaml` (`vm.vcpus`, `vm.mem_mb`, default 4 CPUs / 4 GB RAM).
- **Host Mount Speed**: Volume mounts pass through sshfs/virtiofs, which can be slower for large directory trees like `node_modules`.

---

## Selecting an Isolation Backend

### Automatic Selection
When you run `agentcage init` or `agentcage run`, agentcage automatically detects your platform:
1. **Linux**: Automatically chooses `container`.
2. **macOS 26+ (Apple Silicon)** with Apple `container` installed: Automatically chooses `apple-container`.
3. **Other macOS / Fallback**: Automatically chooses `vm`.

### Explicit Selection
You can override automatic detection in `cage.yaml`:

```yaml
name: my-agent
isolation: vm # container | apple-container | vm
```

Or via the CLI when running an ephemeral session:

```bash
agentcage run claude-code --isolation vm -s ANTHROPIC_API_KEY
```

---

## Moving a Cage Between Backends

To migrate an existing cage from one backend to another (e.g. moving from `vm` to `apple-container` on macOS):

1. **Create a Backup**:
   ```bash
   agentcage cage backup my-agent -o my-agent-backup.tar.gz --include-secrets
   ```
2. **Destroy the Old Cage**:
   ```bash
   agentcage cage destroy my-agent -y
   ```
3. **Edit the Isolation Setting**:
   Extract `cage.yaml` from the archive or update your local file to change `isolation: apple-container`.
4. **Restore or Recreate**:
   ```bash
   agentcage cage create -c cage.yaml
   ```

---

## Next Steps

- **[System Architecture](architecture.md)** — Learn how the network and proxy services interact.
- **[Security Model](security-model.md)** — Understand capabilities, attack vectors, and trust boundaries.
- **[Configuration Reference](../reference/configuration.md)** — Specify backend options in `cage.yaml`.
