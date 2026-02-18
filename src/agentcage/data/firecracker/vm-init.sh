#!/bin/bash
# vm-init.sh — Firecracker guest init script
#
# This runs as PID 1 inside the Firecracker VM.
# It sets up networking, mounts filesystems, loads container images,
# and starts the cage containers via Podman.
#
# Podman runs as root inside the VM — the VM itself is the isolation
# boundary, so rootless Podman adds no security benefit here.

set -euo pipefail

echo "agentcage-vm: starting init"

# ── Mount essential filesystems ──────────────────────────
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs tmpfs /dev/shm 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
mkdir -p /run/lock

# ── Mount cgroups (required for Podman) ──────────────────
if ! mountpoint -q /sys/fs/cgroup 2>/dev/null; then
    if mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null; then
        echo "agentcage-vm: mounted cgroup v2"
    else
        echo "agentcage-vm: cgroup v2 not available, trying v1"
        mount -t tmpfs cgroup /sys/fs/cgroup
        for ctrl in cpu cpuacct blkio memory devices freezer net_cls pids; do
            mkdir -p "/sys/fs/cgroup/$ctrl"
            mount -t cgroup -o "$ctrl" cgroup "/sys/fs/cgroup/$ctrl" 2>/dev/null || true
        done
    fi
fi

# ── Parse kernel command line ────────────────────────────
CAGE_NAME=""
for param in $(cat /proc/cmdline); do
    case "$param" in
        agentcage.name=*)
            CAGE_NAME="${param#agentcage.name=}"
            ;;
    esac
done

if [[ -z "$CAGE_NAME" ]]; then
    echo "agentcage-vm: error: agentcage.name not set in kernel cmdline" >&2
    exec /bin/sh
fi

echo "agentcage-vm: cage name: $CAGE_NAME"

# ── Network setup ────────────────────────────────────────
if ! ip addr show eth0 2>/dev/null | grep -q "inet "; then
    echo "agentcage-vm: configuring network manually"
    for param in $(cat /proc/cmdline); do
        case "$param" in
            ip=*)
                IFS=':' read -r IP _ GW MASK _ _ _ <<< "${param#ip=}"
                ip addr add "$IP/$MASK" dev eth0 2>/dev/null || true
                ip link set eth0 up
                ip route add default via "$GW" 2>/dev/null || true
                ;;
        esac
    done
fi

echo "nameserver 10.88.0.1" > /etc/resolv.conf

# ── Mount secrets drive if present ───────────────────────
if [[ -b /dev/vdb ]]; then
    echo "agentcage-vm: mounting secrets drive"
    mkdir -p /mnt/secrets
    mount -o ro /dev/vdb /mnt/secrets

    for f in /mnt/secrets/*; do
        [[ -f "$f" ]] || continue
        local_name="$(basename "$f")"
        podman secret create "$local_name" "$f" || true
        echo "agentcage-vm: loaded secret $local_name"
    done
fi

# ── Quick diagnostic ─────────────────────────────────────
echo "agentcage-vm: kernel $(uname -r)"

# ── Prepare Podman runtime dirs (tmpfs loses them) ───────
mkdir -p /run/containers/storage /var/lib/containers/storage

# ── Load pre-built container images ──────────────────────
IMAGE_DIR="/var/lib/agentcage/images"
if [[ -d "$IMAGE_DIR" ]]; then
    echo "agentcage-vm: images dir contents: $(ls -la $IMAGE_DIR)"
    for archive in "$IMAGE_DIR"/*.tar; do
        [[ -f "$archive" ]] || continue
        echo "agentcage-vm: loading image $(basename "$archive") ($(du -h "$archive" | cut -f1))"
        if timeout 120 podman load -i "$archive" 2>&1; then
            echo "agentcage-vm: loaded $(basename "$archive") ok"
        else
            echo "agentcage-vm: warning: failed to load $(basename "$archive")"
        fi
        # Free space — tarballs are no longer needed after loading
        rm -f "$archive"
    done
fi

# ── Start the cage ───────────────────────────────────────
echo "agentcage-vm: starting cage services"

STARTUP_SCRIPT="/var/lib/agentcage/start-cage.sh"

if [[ -x "$STARTUP_SCRIPT" ]]; then
    echo "agentcage-vm: running startup script"
    bash "$STARTUP_SCRIPT" 2>&1 || {
        echo "agentcage-vm: startup script failed (exit $?)" >&2
    }
else
    echo "agentcage-vm: error: startup script not found: $STARTUP_SCRIPT" >&2
fi

echo "agentcage-vm: init complete, cage $CAGE_NAME is running"

# Keep PID 1 alive — reap zombies
while true; do
    wait -n 2>/dev/null || sleep 60
done
