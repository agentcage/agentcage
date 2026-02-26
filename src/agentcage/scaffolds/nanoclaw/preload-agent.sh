#!/usr/bin/env bash
set -euo pipefail
CAGE="${1:?Usage: preload-agent.sh <cage-name>}"
IMAGE="${2:-nanoclaw-agent}"
if ! podman image exists "localhost/$IMAGE"; then
  echo "error: localhost/$IMAGE not found — build it first" >&2
  exit 1
fi
echo "Preloading $IMAGE into $CAGE..."
podman save "localhost/$IMAGE" | podman exec -i "${CAGE}-cage" podman load
echo "Preloaded $IMAGE into $CAGE"
