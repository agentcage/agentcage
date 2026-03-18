#!/usr/bin/env bash
# End-to-end test for the Lima VM backend.
# Requires: limactl, podman (for secrets)
#
# Usage: bash tests/e2e_lima.sh
set -euo pipefail

CAGE_NAME="e2e-lima-test"

cleanup() {
    echo "=== Cleanup ==="
    limactl stop "agentcage-${CAGE_NAME}" 2>/dev/null || true
    limactl delete --force "agentcage-${CAGE_NAME}" 2>/dev/null || true
    echo y | agentcage cage destroy "$CAGE_NAME" 2>/dev/null || true
    rm -rf ~/.config/agentcage/lima
}
trap cleanup EXIT

cleanup  # start clean

echo "=== Creating test config ==="
TMPCONFIG=$(mktemp /tmp/e2e-lima-XXXXXX.yaml)
cat > "$TMPCONFIG" <<EOF
name: $CAGE_NAME
isolation: vm
container:
  image: docker.io/library/nginx:latest
  read_only: false
  ports:
    - "0.0.0.0:19080:80"
  tmpfs:
    - /var/cache/nginx:rw,size=64M,mode=1777
domains:
  allow:
    - "*.docker.io"
    - "*.docker.com"
    - "production.cloudflare.docker.com"
EOF

echo "=== Creating cage ==="
agentcage cage create -c "$TMPCONFIG"

echo "=== Checking cage list ==="
agentcage cage list
agentcage cage list | grep "$CAGE_NAME" | grep -q "vm"

echo "=== Waiting for services to stabilize ==="
sleep 30

echo "=== Checking status ==="
STATUS=$(agentcage cage list | grep "$CAGE_NAME" | awk '{print $4}')
echo "Status: $STATUS"

echo "=== Checking containers inside VM ==="
limactl shell "agentcage-${CAGE_NAME}" -- podman ps

echo "=== Checking logs ==="
agentcage cage logs "$CAGE_NAME" -n 3 || true

echo "=== Stopping cage ==="
agentcage cage stop "$CAGE_NAME"
agentcage cage list | grep "$CAGE_NAME" | grep -q "stopped"

echo "=== Starting cage ==="
agentcage cage start "$CAGE_NAME"
sleep 15

echo "=== Verifying cage is running again ==="
agentcage cage list | grep "$CAGE_NAME"
limactl shell "agentcage-${CAGE_NAME}" -- podman ps

echo "=== Destroying cage ==="
echo y | agentcage cage destroy "$CAGE_NAME"
! agentcage cage list 2>&1 | grep -q "$CAGE_NAME"

echo ""
echo "=== ALL E2E TESTS PASSED ==="
