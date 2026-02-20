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

# ── Ctrl+Alt+Del → SIGINT to PID 1 (not hard reboot) ────
# Firecracker's SendCtrlAltDel triggers this; mode 0 sends
# SIGINT to init so our trap can do a graceful shutdown.
echo 0 > /proc/sys/kernel/ctrl-alt-del 2>/dev/null || true

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

# ── Mount data drive if present (persistent named volumes) ─
DATA_DEV=$(blkid -L cage-data 2>/dev/null || true)
if [[ -n "$DATA_DEV" ]]; then
    echo "agentcage-vm: mounting data drive ($DATA_DEV)"
    mkdir -p /mnt/data
    mount "$DATA_DEV" /mnt/data
fi

# ── Quick diagnostic ─────────────────────────────────────
echo "agentcage-vm: kernel $(uname -r)"

# ── Prepare Podman runtime dirs (tmpfs loses them) ───────
mkdir -p /run/containers/storage /var/lib/containers/storage

# ── Handle restart: reset corrupted storage ───────────────
# Firecracker VMs are killed abruptly, leaving Podman's overlay storage in
# a corrupted state (broken symlinks, stale lock files).  On restart we
# detect this, wipe the storage, and reload images from preserved tarballs.
if [ -d /var/lib/containers/storage/overlay ]; then
    echo "agentcage-vm: restart detected — resetting podman storage"
    podman system reset --force 2>&1 || true
    mkdir -p /run/containers/storage
fi

# ── Mount secrets drive and create Podman secrets ─────────
# Must happen AFTER podman system reset (restart) to avoid secrets being
# wiped.  The drive is an ext4 image attached by Firecracker as a
# virtio-block device with label "cage-secrets".
SECRETS_DEV=$(blkid -L cage-secrets 2>/dev/null || true)
if [[ -n "$SECRETS_DEV" ]]; then
    echo "agentcage-vm: mounting secrets drive ($SECRETS_DEV)"
    mkdir -p /mnt/secrets
    mount -o ro "$SECRETS_DEV" /mnt/secrets

    for f in /mnt/secrets/*; do
        [[ -f "$f" ]] || continue
        local_name="$(basename "$f")"
        podman secret create "$local_name" "$f" || true
        echo "agentcage-vm: loaded secret $local_name"
    done
else
    echo "agentcage-vm: no secrets drive found"
fi

# ── Load pre-built container images ──────────────────────
# Images are exported as gzipped, split chunks to work around mkfs.ext4 -d's
# 2GB per-file limit.  Chunks are named <image>.tar.gz.00, .01, etc.
# We reassemble then load with -i (not stdin) to avoid podman creating
# a temp copy of the entire decompressed archive.
#
# On first boot, chunks are reassembled into .tar files and loaded.
# The .tar files are kept (not deleted) so restarts can reload them.
IMAGE_DIR="/var/lib/agentcage/images"
NEED_LOAD=false
if [[ -d "$IMAGE_DIR" ]]; then
    echo "agentcage-vm: images dir contents: $(ls -la $IMAGE_DIR)"

    # Phase 1: reassemble split chunks into .tar files (first boot only)
    for chunk in "$IMAGE_DIR"/*.tar.gz.00; do
        [[ -f "$chunk" ]] || continue
        prefix="${chunk%00}"
        reassembled="${prefix%.}"
        echo "agentcage-vm: reassembling $(basename "$reassembled") ($(du -ch "${prefix}"* | tail -1 | cut -f1) total)"
        mv "$chunk" "$reassembled"
        for c in "${prefix}"*; do
            [[ -f "$c" ]] || continue
            cat "$c" >> "$reassembled"
            rm -f "$c"
        done
        echo "agentcage-vm: decompressing $(basename "$reassembled") ($(du -h "$reassembled" | cut -f1))"
        gunzip "$reassembled"
        NEED_LOAD=true
    done

    # Phase 2: load all .tar files (first boot and restarts)
    # Check if images are already loaded (skip on first boot after phase 1
    # only if storage is clean — but always reload after a reset)
    if ! podman image ls -q 2>/dev/null | grep -q . || [[ "$NEED_LOAD" == true ]]; then
        for archive in "$IMAGE_DIR"/*.tar; do
            [[ -f "$archive" ]] || continue
            echo "agentcage-vm: loading image $(basename "$archive") ($(du -h "$archive" | cut -f1))"
            if timeout 300 podman load -i "$archive" 2>&1; then
                echo "agentcage-vm: loaded $(basename "$archive") ok"
            else
                echo "agentcage-vm: warning: failed to load $(basename "$archive")"
            fi
        done
    else
        echo "agentcage-vm: images already loaded, skipping"
    fi
fi

# ── Start the cage ───────────────────────────────────────
echo "agentcage-vm: starting cage services"

STARTUP_SCRIPT="/var/lib/agentcage/start-cage.sh"

STARTUP_OK=false
if [[ -x "$STARTUP_SCRIPT" ]]; then
    echo "agentcage-vm: running startup script"
    if bash "$STARTUP_SCRIPT" 2>&1; then
        STARTUP_OK=true
    else
        echo "agentcage-vm: startup script FAILED (exit $?)"
    fi
else
    echo "agentcage-vm: error: startup script not found: $STARTUP_SCRIPT"
fi

if [[ "$STARTUP_OK" == true ]]; then
    echo "agentcage-vm: init complete, cage $CAGE_NAME is running"
else
    echo "agentcage-vm: init complete, cage $CAGE_NAME FAILED TO START"
fi

# ── Graceful shutdown on SIGINT (SendCtrlAltDel) / SIGTERM ──
# Disable errexit — bash's SIGINT handling with set -e can cause
# immediate exit before the trap handler fires.
set +e

shutdown_vm() {
    echo "agentcage-vm: graceful shutdown requested"
    for c in "${CAGE_NAME}-cage" "${CAGE_NAME}-proxy" "${CAGE_NAME}-dns"; do
        echo "agentcage-vm: stopping $c"
        podman stop --time 10 "$c" 2>/dev/null || true
    done
    echo "agentcage-vm: all containers stopped"
    sync
    echo o > /proc/sysrq-trigger   # SysRq poweroff
    sleep 5                         # fallback if SysRq unsupported
    exit 0                          # kernel panic → Firecracker exits
}
trap shutdown_vm SIGINT SIGTERM

# Keep PID 1 alive — reap zombies.
# sleep runs in the background so that `wait` (a bash builtin) is the
# foreground operation.  This lets signals (SIGINT from SendCtrlAltDel)
# interrupt wait immediately and trigger the trap handler.
while true; do
    sleep 60 &
    wait -n 2>/dev/null || true
done
