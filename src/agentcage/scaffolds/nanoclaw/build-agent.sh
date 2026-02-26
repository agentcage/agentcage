#!/usr/bin/env bash
set -euo pipefail
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
echo "Cloning nanoclaw repository..."
git clone --depth 1 https://github.com/qwibitai/nanoclaw.git "$TMPDIR"
podman build -t nanoclaw-agent -f "$TMPDIR/container/Dockerfile" \
  --cap-add CAP_SETFCAP,CAP_SETUID,CAP_SETGID,CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER \
  "$TMPDIR/container"
echo "Built localhost/nanoclaw-agent"
