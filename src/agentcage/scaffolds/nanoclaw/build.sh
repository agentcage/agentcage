#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Prerequisite check
if ! podman image exists localhost/agentcage-nested; then
  echo "error: localhost/agentcage-nested not found" >&2
  echo "  Run: agentcage build nested-base" >&2
  exit 1
fi
podman build -t agentcage-nanoclaw \
  -f "$SCRIPT_DIR/Containerfile" \
  --cap-add CAP_SETFCAP,CAP_SETUID,CAP_SETGID,CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER \
  "$SCRIPT_DIR"
echo "Built localhost/agentcage-nanoclaw"
