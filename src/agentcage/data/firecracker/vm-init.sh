#!/bin/bash
# vm-init.sh — Firecracker guest init script
#
# This runs as PID 1 (or called by init) inside the Firecracker VM.
# It sets up networking, mounts filesystems, starts Podman, and
# deploys the cage containers using pre-baked quadlet files.

set -euo pipefail

echo "agentcage-vm: starting init"

# ── Mount essential filesystems ──────────────────────────
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
mkdir -p /run/lock

# ── Parse kernel command line ────────────────────────────
# Expected params: agentcage.name=<name> ip=<ip>::<gw>:<mask>::<iface>:off
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
    exec /bin/sh  # drop to shell for debugging
fi

echo "agentcage-vm: cage name: $CAGE_NAME"

# ── Network setup ────────────────────────────────────────
# The ip= kernel param configures eth0 automatically via the kernel's
# IP autoconfiguration. If it didn't work, we configure it manually.
if ! ip addr show eth0 2>/dev/null | grep -q "inet "; then
    echo "agentcage-vm: configuring network manually"
    # Read from kernel cmdline ip= param
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

# Set up DNS (use the bridge gateway as a forwarder to host DNS)
echo "nameserver 10.88.0.1" > /etc/resolv.conf

# ── Mount secrets drive if present ───────────────────────
if [[ -b /dev/vdb ]]; then
    echo "agentcage-vm: mounting secrets drive"
    mkdir -p /mnt/secrets
    mount -o ro /dev/vdb /mnt/secrets

    # Create Podman secrets from files
    for f in /mnt/secrets/*; do
        [[ -f "$f" ]] || continue
        local_name="$(basename "$f")"
        su - agentcage -c "podman secret create '$local_name' '$f'" 2>/dev/null || true
        echo "agentcage-vm: loaded secret $local_name"
    done
fi

# ── Load pre-built container images ──────────────────────
IMAGE_DIR="/var/lib/agentcage/images"
if [[ -d "$IMAGE_DIR" ]]; then
    for archive in "$IMAGE_DIR"/*.tar; do
        [[ -f "$archive" ]] || continue
        echo "agentcage-vm: loading image $(basename "$archive")"
        su - agentcage -c "podman load -i '$archive'" 2>/dev/null || true
    done
fi

# ── Install and start quadlet services ───────────────────
QUADLET_SRC="/var/lib/agentcage/quadlets"
QUADLET_DST="/home/agentcage/.config/containers/systemd"

if [[ -d "$QUADLET_SRC" ]]; then
    mkdir -p "$QUADLET_DST"
    cp "$QUADLET_SRC"/* "$QUADLET_DST"/ 2>/dev/null || true
    chown -R agentcage:agentcage "$QUADLET_DST"
fi

# ── Start the cage via Podman (as agentcage user) ────────
echo "agentcage-vm: starting cage services"

# Use loginctl or direct systemd --user if available
if command -v loginctl &>/dev/null; then
    loginctl enable-linger agentcage 2>/dev/null || true
fi

# Start systemd user instance and reload quadlets
su - agentcage -c "systemctl --user daemon-reload" 2>/dev/null || true
su - agentcage -c "systemctl --user start ${CAGE_NAME}-cage.service" 2>/dev/null || {
    # Fallback: start containers directly if systemd --user isn't available
    echo "agentcage-vm: systemd --user not available, starting containers directly"
    su - agentcage -c "podman network create --internal --subnet=10.89.0.0/24 ${CAGE_NAME}-net" 2>/dev/null || true
    su - agentcage -c "podman start ${CAGE_NAME}-dns ${CAGE_NAME}-proxy ${CAGE_NAME}-cage" 2>/dev/null || true
}

echo "agentcage-vm: init complete, cage $CAGE_NAME is running"

# Keep PID 1 alive — reap zombies
while true; do
    wait -n 2>/dev/null || sleep 60
done
