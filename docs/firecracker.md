# Firecracker MicroVM Isolation

Firecracker microVM isolation is an optional alternative to the default container-based isolation. When `isolation: firecracker` is set in the cage configuration, each cage runs inside a dedicated Firecracker microVM with its own Linux kernel, providing hardware-level isolation via KVM rather than Linux namespace separation.

For configuration options, see the [Configuration Reference](configuration.md).

## Architecture

Each cage maps to a single Firecracker process managed as a systemd user service. Inside the VM, Podman runs as root (see [design decisions](#key-design-decisions) below) and orchestrates the same three-container topology as container mode — DNS sidecar, proxy, and agent — over an internal network.

```
Host (systemd --user)
├── basic-cage.service          # Firecracker process
│   └── Firecracker VM (kernel 6.1+, 2 vCPUs, 2GB RAM)
│       ├── vm-init.sh (PID 1)
│       ├── Podman 5.7.1 (rootful, overlay storage)
│       │   ├── basic-dns       # dnsmasq container
│       │   ├── basic-proxy     # mitmproxy container
│       │   └── basic-cage      # user's agent container
│       └── Internal network (10.89.0.0/24, netavark/nftables)
└── TAP device (tap-basic) ──── Bridge (agentcage-br0) ──── Host network
```

Host-to-VM connectivity is provided by a TAP device (`tap-<name>`) bridged into `agentcage-br0`. VM traffic is NATed through the host via an iptables MASQUERADE rule. The VM receives a static IP derived deterministically from the cage name (see [Networking](#networking--the-nethelper)).

### Key Design Decisions

**Podman runs as root inside the VM.** The VM itself is the isolation boundary. Rootless Podman inside a VM would add operational complexity without meaningful security benefit — the guest kernel already enforces the isolation.

**Container images are baked into the rootfs at cage creation time.** At `cage create` time, agentcage runs `podman save` on each required image and embeds the resulting tarballs into the VM rootfs. On first boot, `vm-init.sh` loads them with `podman load` and deletes the tarballs. This avoids any requirement for the VM to pull images at runtime.

**No mount or root privileges are needed to build the rootfs.** The rootfs is built using `podman export` (to produce a staging directory) followed by `mkfs.ext4 -d` (to create the image from the directory). Both commands run unprivileged.

**Auto-generated startup script.** `start-cage.sh` is generated at cage creation time and baked into the rootfs at `/start-cage.sh`. It encodes the specific container names, image references, and configuration for that cage, and orchestrates the DNS → proxy → cage startup sequence inside the VM.

**Fedora Minimal 43 as the VM base.** Fedora Minimal provides the best upstream Podman compatibility with a minimal footprint suitable for a VM rootfs.

## Networking & the Nethelper

### Why a Nethelper is Needed

Firecracker VMs connect to the host via TAP devices rather than the virtual Ethernet pairs used in container networking. Creating TAP devices, attaching them to bridges, and installing iptables rules all require root privileges. agentcage runs as a regular user (systemd --user), so these operations cannot be performed directly.

The nethelper binary (`agentcage-nethelper`) is the minimal privilege escalation boundary. It is installed setuid or invoked via a `sudoers` rule, performs strict input validation, and exposes only the specific operations required to manage Firecracker networking. It does nothing else.

### What it Does

**Bridge management** (`agentcage-br0`, `10.88.0.1/24`):

The bridge is a shared Linux bridge that acts as a virtual switch connecting all Firecracker VMs on the host to each other and to the host's network stack. It is created once and persists across cage lifetimes. The nethelper also enables `net.ipv4.ip_forward` and installs a single iptables `MASQUERADE` rule on the bridge's subnet, so VM traffic is NATed through the host to the internet.

**TAP device management** (one `tap-<name>` per cage):

Each cage gets a dedicated TAP device. The TAP device is the virtual NIC that Firecracker attaches to the VM's `eth0`. The nethelper creates it, sets ownership to the calling user's UID (read from `SUDO_UID`) so that the Firecracker process can open it without root, and attaches it to `agentcage-br0`.

### The Flow

```
cage create → systemd ExecStartPre:
    sudo agentcage-nethelper create-tap basic
        → creates tap-basic
        → attaches tap-basic to agentcage-br0
        → chowns tap-basic to SUDO_UID

→ Firecracker starts, attaches tap-basic to VM's eth0
→ VM kernel receives ip= parameter, configures eth0 with 10.88.0.209/24
→ VM traffic → tap-basic → agentcage-br0 → MASQUERADE → internet

cage destroy → systemd ExecStopPost:
    sudo agentcage-nethelper destroy-tap basic
        → deletes tap-basic
```

### Security Design

The nethelper applies several restrictions to limit the scope of the privilege it holds:

**Strict input validation.** Cage names must match `^[a-z0-9][a-z0-9-]{0,62}$` before any operation proceeds. Invalid input is rejected immediately.

**Fixed operations only.** The nethelper can only manage `agentcage-br0` and devices named `tap-*`. It cannot operate on arbitrary network interfaces.

**No user-controlled paths.** TAP device names are derived from the validated cage name by prepending `tap-`. The user never supplies a raw device name.

**Deterministic IP assignment.** The `cage_ip()` function hashes the cage name to select a stable IP in the range `10.88.0.2–10.88.0.254`. The same cage name always gets the same IP, making routing predictable without requiring a DHCP server.

**Minimal sudoers scope.** The sudoers rule grants `NOPASSWD` only for this specific binary. No other commands are covered.

### Nethelper Commands

| Command | Arguments | Description |
|---------|-----------|-------------|
| `create-bridge` | _(none)_ | Creates `agentcage-br0` at `10.88.0.1/24`, enables IP forwarding, installs MASQUERADE rule |
| `destroy-bridge` | _(none)_ | Removes `agentcage-br0` and its associated iptables rule |
| `create-tap` | `<cage-name>` | Creates `tap-<cage-name>`, sets owner to `SUDO_UID`, attaches to `agentcage-br0` |
| `destroy-tap` | `<cage-name>` | Deletes `tap-<cage-name>` |

## VM Rootfs Build Pipeline

The rootfs for a Firecracker VM is a self-contained ext4 image built at `cage create` time. The build process requires no root privileges and no loop-device mounts.

1. **Build the base VM image.** `Containerfile.vmbase` installs Fedora Minimal 43 with Podman 5.7.1 and the supporting utilities (`nftables`, `iptables-nft`, `netavark`, etc.) into a container image tagged `agentcage-vmbase`.

2. **Export to a staging directory.** `podman export` flattens the container filesystem into a staging directory. This produces a plain directory tree, not a container layer, and requires no elevated privileges.

3. **Export container images.** The DNS, proxy, and agent container images are each exported as Docker-archive tarballs via `podman save --format docker-archive` and placed into the staging directory at `/var/lib/agentcage/images/`. These will be loaded by the VM on first boot.

4. **Generate `start-cage.sh`.** A startup script is generated that encodes the exact `podman run` commands for this cage's DNS, proxy, and agent containers, including all environment variables, mounts, and network settings. The script is written into the staging directory at `/var/lib/agentcage/start-cage.sh`.

5. **Copy cage configuration.** The rendered `config.yaml` for this cage is copied into the staging directory at `/etc/agentcage/config.yaml`, where the proxy container will mount it at runtime.

6. **Build the ext4 image.** `mkfs.ext4 -d <staging-dir>` creates a 4GB sparse ext4 image directly from the staging directory. No loop device, no mount, no root required.

## VM Init (vm-init.sh)

`vm-init.sh` runs as PID 1 inside every Firecracker VM. As PID 1, it is responsible for both system initialisation and zombie reaping.

On boot it performs the following steps in order:

1. **Mount essential filesystems.** Mounts `proc`, `sys`, `dev`, `cgroup2`, and a `tmpfs` at `/tmp`. These are required before any network or container operations.

2. **Configure the network.** Reads the `ip=` kernel parameter passed by Firecracker to configure `eth0` with the cage's static IP, netmask, and gateway. Sets the hostname to the cage name.

3. **Load secrets from the virtio block device.** If a second block device (`/dev/vdb`) is present, it is mounted and the secrets file is read. This device is populated at cage start time from the host's secret store. After loading, the device is unmounted and the mount point is removed.

4. **Load container images.** Iterates over the tarballs in `/var/lib/agentcage/images/` and loads each one with `podman load`. After loading, the tarballs are deleted to reclaim rootfs space.

5. **Execute `start-cage.sh`.** Hands off to the generated startup script, which starts the DNS sidecar, waits for it to be ready, starts the proxy, waits for the mitmproxy CA certificate, and finally starts the agent container.

6. **Reap zombies.** As PID 1, `vm-init.sh` runs a background wait loop to reap any zombie processes that are reparented to it by the kernel.

## Configuration Reference

Firecracker-specific settings live under the `firecracker:` key in `config.yaml`.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `kernel` | string | _(auto-downloaded)_ | Path to the `vmlinux` kernel binary. If omitted, a pre-built kernel is automatically downloaded to `~/.local/share/agentcage/firecracker/`. |
| `vcpus` | int | `2` | Number of virtual CPUs to allocate to the VM. |
| `mem_mb` | int | `2048` | VM memory in megabytes. |
| `firecracker_bin` | string | `"firecracker"` | Path to the Firecracker binary. If omitted, auto-downloaded to `~/.local/share/agentcage/firecracker/` when not found in `$PATH`. |

### Example Configuration

```yaml
name: basic
isolation: firecracker

firecracker:
  # kernel is optional — auto-downloaded to ~/.local/share/agentcage/firecracker/
  vcpus: 2
  mem_mb: 2048

container:
  image: "node:22-slim"
  command: ["node", "/app/agent.js"]

domains:
  mode: allowlist
  list:
    - api.anthropic.com
    - api.github.com

secrets:
  enabled: true
```

## Setup

### Prerequisites

| Requirement | Notes |
|-------------|-------|
| `/dev/kvm` | KVM must be accessible to your user. Check with `ls -la /dev/kvm`. |
| Firecracker binary | Auto-downloaded on first use to `~/.local/share/agentcage/firecracker/`, or specify a custom path via `firecracker.firecracker_bin` in config. |
| Linux kernel 6.1+ | Auto-downloaded on first use, or specify a custom path via `firecracker.kernel` in config. |
| Podman | Required on the host to build and export container images. |
| `mkfs.ext4` | Part of `e2fsprogs`. Used to create the VM rootfs image. |
| `debugfs` | Also part of `e2fsprogs`. Used to inspect rootfs images. |

### One-Time Host Setup

Run the setup command to download the kernel, check prerequisites, and create the network bridge:

```bash
agentcage firecracker setup
```

This will:
1. Download a pre-built vmlinux kernel to `~/.local/share/agentcage/firecracker/` (if not already present)
2. Download the Firecracker binary to `~/.local/share/agentcage/firecracker/` (if not already present)
3. Check all prerequisites and report any issues
4. Create the `agentcage-br0` network bridge (requires the nethelper)

**Install the nethelper and configure sudoers** (before running setup):

```bash
# Install the nethelper binary
sudo install -m 755 agentcage-nethelper /usr/local/bin/agentcage-nethelper

# Grant your user passwordless access to the nethelper
echo "$USER ALL=(root) NOPASSWD: /usr/local/bin/agentcage-nethelper" \
  | sudo tee /etc/sudoers.d/agentcage-nethelper
```

### Create and Run a Cage

```bash
# Create the cage (builds rootfs, exports images — takes 1–2 minutes on first run)
agentcage cage create --config config-firecracker.yaml

# Tail logs
journalctl --user -u basic-cage -f
```

## Known Limitations

- **Host volume mounts are not supported.** The agent container runs inside a VM with its own rootfs. There is no mechanism to bind-mount directories from the host into the agent container. Agent code must be baked into the container image.

- **4GB rootfs per cage.** The ext4 rootfs image is sparse, so it does not consume 4GB of disk immediately, but the full 4GB is reserved in the filesystem. Cages with large container images may require a larger rootfs — this is not currently configurable.

- **VM boot overhead.** Firecracker boots quickly relative to traditional VMs, but there is still approximately 7 seconds of startup overhead compared to container mode. This includes kernel boot, `vm-init.sh` initialisation, and container image loading inside the VM.
