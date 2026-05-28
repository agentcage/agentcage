# Lima VM Isolation

Lima VM isolation is an optional alternative to the default container-based isolation. When `isolation: vm` is set in the cage configuration, each cage runs inside a dedicated Linux VM managed by [Lima](https://lima-vm.io), providing hardware-level isolation via KVM rather than Linux namespace separation.

For configuration options, see the [Configuration Reference](reference/configuration.md).

## Why VM isolation

Container mode is a strong default: rootless, no KVM required, works on macOS, sub-second startup. But containers share the host kernel. A kernel vulnerability or container runtime escape (runc/crun CVE) could let a compromised agent break out of the container and access the host.

VM mode eliminates this risk by wrapping the entire container topology in a dedicated VM:

- **Dedicated guest kernel per cage.** Each cage boots its own Linux kernel. A kernel exploit inside the VM cannot affect the host kernel.
- **Hardware-level isolation via KVM.** The VM boundary is enforced by the CPU's virtualization extensions (VT-x/AMD-V), not by kernel namespaces.
- **Container escape is contained.** If an agent escapes its container, it lands inside the VM — not on the host. The VM has no host filesystem access and no shared kernel.
- **Same inspection architecture.** The inspector chain, secret injection, DNS filtering, and audit logging work identically inside the VM. VM mode adds an outer boundary; it does not replace the inner defenses.

The tradeoff is additional VM startup time and a requirement for Linux or macOS with Lima installed.

**Use container mode** for development, CI, and workloads where the host kernel is trusted. **Use VM mode** for production, untrusted agents, and environments where container escape is an unacceptable risk.

## How it works

Lima creates and manages a Linux VM for each cage. Inside the VM, Podman runs with quadlet unit files (the same as container mode) orchestrating the three-container topology: DNS sidecar, proxy, and agent container.

From the host, the cage is managed as a Lima instance. agentcage uses the Lima CLI (`limactl`) to create, start, stop, and delete instances, and to run commands inside them.

No root or sudo is required. Lima handles VM networking transparently without TAP devices or bridge setup.

```
Host (Lima)
└── <name>-cage (Lima instance, Linux VM)
    └── Podman (rootful inside VM, quadlets)
        ├── <name>-dns       # dnsmasq container
        ├── <name>-proxy     # mitmproxy container
        └── <name>-cage      # user's agent container
```

For details on Lima's architecture and supported platforms, see [lima-vm.io](https://lima-vm.io).

## Configuration Reference

VM-specific settings live under the `vm:` key in `cage.yaml`.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `vcpus` | int | `4` | Number of virtual CPUs to allocate to the VM. |
| `mem_mb` | int | `4096` | VM memory in megabytes. |

### Example Configuration

```yaml
name: basic
isolation: vm

vm:
  vcpus: 4
  mem_mb: 4096

container:
  image: "node:22-slim"
  command: ["node", "/app/agent.js"]

domains:
  allow:
    - api.anthropic.com
    - api.github.com

secrets:
  enabled: true
```

## Setup

### Prerequisites

| Requirement | Notes |
|-------------|-------|
| Lima | Install via `brew install lima` on macOS, or your Linux package manager. See [lima-vm.io](https://lima-vm.io) for details. |
| QEMU (Linux only) | Required for VM acceleration. Install via your package manager. |
| Podman (optional) | Only needed on the host for `agentcage secret set` (secret storage). All container operations happen inside the VM. |

### Install Lima

**macOS:**
```bash
brew install lima
```

**Linux (Arch):**
```bash
sudo pacman -S lima
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install lima
```

**Linux (Fedora):**
```bash
sudo dnf install lima
```

### Create and Run a Cage

```bash
# Create the cage
agentcage cage create --config cage-vm.yaml

# Tail logs
agentcage cage logs basic
```

No sudo required.

## Known Limitations

- **Host volume mounts are not supported.** The agent container runs inside a VM with its own filesystem. There is no mechanism to bind-mount directories from the host into the agent container. Agent code must be baked into the container image or fetched at runtime.

- **VM boot overhead.** VM startup adds a few seconds compared to container mode.
