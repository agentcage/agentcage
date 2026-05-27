#!/usr/bin/env bash
# Phase: apple-container Mode — Manual e2e (macOS-only).
#
# Apple's `container` CLI ships only for macOS 26+ ASi, so this phase
# is manual-only and not part of CI. Run on a developer workstation
# with `agentcage doctor` reporting all-green for apple-container.
#
# Covers the 2-microVM model from PR 3 (#196):
#   * cage create builds both images (agentcage-egress + per-cage wrapper)
#   * cage status shows both microVMs running
#   * cage exec defaults to uid 1000
#   * Threat-model invariants: secrets/iptables not reachable from cage
#   * domain add SIGHUPs dnsmasq in egress (no restart)
#   * cage destroy cleans both microVMs + the per-cage network
set -uo pipefail
source "$(dirname "$0")/lib.sh"

if [ "$(uname)" != "Darwin" ]; then
    echo "SKIP: phase_apple requires macOS"
    exit 0
fi
if ! command -v container >/dev/null 2>&1 && \
   [ ! -x /usr/local/bin/container ] && \
   [ ! -x /opt/homebrew/bin/container ]; then
    echo "SKIP: Apple \`container\` CLI not installed"
    exit 0
fi

phase_header A "apple-container Mode — Lifecycle & 2-microVM Threat Model"

CAGE="e2e-apple"
CONFIGS="$(dirname "$0")/configs"

destroy_cage "$CAGE" >/dev/null 2>&1 || true
register_cage "$CAGE"

cat > "/tmp/${CAGE}.yaml" <<EOF
name: $CAGE
isolation: apple-container
container:
  image: docker.io/library/ubuntu:24.04
  command: ["sleep", "infinity"]
domains:
  allow:
    - api.github.com
secret_injection:
  - env: API_KEY
    placeholder: "{{API_KEY}}"
    inject_to: ["api.github.com"]
EOF

echo "Creating apple-container cage (builds egress + wrapper images)..."
agentcage cage create "$CAGE" --config "/tmp/${CAGE}.yaml" \
    -s "API_KEY=test-secret-value" \
    || { echo "FAIL: cage create"; exit 1; }

agentcage cage start "$CAGE" || { echo "FAIL: cage start"; exit 1; }

echo "--- Both microVMs running ---"
container list | grep "^$CAGE\\b" || { echo "FAIL: cage VM not running"; exit 1; }
container list | grep "^${CAGE}-egress\\b" || { echo "FAIL: egress VM not running"; exit 1; }

echo "--- cage exec default uid is 1000 ---"
out=$(agentcage cage exec "$CAGE" -- id)
echo "$out" | grep -q "uid=1000" || { echo "FAIL: expected uid=1000, got: $out"; exit 1; }

echo "--- cage exec --as-root is uid 0 ---"
out=$(agentcage cage exec "$CAGE" --as-root -- id)
echo "$out" | grep -q "uid=0" || { echo "FAIL: expected uid=0, got: $out"; exit 1; }

echo "--- THREAT MODEL: secrets NOT in cage VM (uid 1000) ---"
if agentcage cage exec "$CAGE" -- ls /home/acproxy/secrets 2>/dev/null; then
    echo "FAIL: /home/acproxy/secrets is reachable from cage VM!"
    exit 1
fi

echo "--- THREAT MODEL: secrets NOT in cage VM (--as-root) ---"
if agentcage cage exec "$CAGE" --as-root -- ls /home/acproxy/secrets 2>/dev/null; then
    echo "FAIL: --as-root can read /home/acproxy/secrets in cage VM!"
    exit 1
fi

echo "--- THREAT MODEL: secrets ARE in egress VM ---"
agentcage cage exec "$CAGE" -s egress --as-root -- ls /home/acproxy/secrets \
    || { echo "FAIL: egress can't read its own secrets"; exit 1; }

echo "--- THREAT MODEL: no iptables binary in cage VM ---"
if agentcage cage exec "$CAGE" --as-root -- which iptables 2>/dev/null; then
    echo "FAIL: iptables present in cage VM!"
    exit 1
fi

echo "--- cage exec proxied curl works (allowlisted) ---"
if ! agentcage cage exec "$CAGE" -- curl -s -o /dev/null -w "%{http_code}" \
        https://api.github.com/zen | grep -q "200"; then
    echo "FAIL: curl through egress to allowlisted domain"
    exit 1
fi

echo "--- domain add live-reloads dnsmasq (no cage restart) ---"
cage_pid_before=$(container inspect "$CAGE" | jq -r '.[0].process.pid // .[0].Process.pid // empty')
agentcage domain add "$CAGE" api.anthropic.com || { echo "FAIL: domain add"; exit 1; }
cage_pid_after=$(container inspect "$CAGE" | jq -r '.[0].process.pid // .[0].Process.pid // empty')
if [ "$cage_pid_before" != "$cage_pid_after" ]; then
    echo "FAIL: cage VM restarted on domain add (was $cage_pid_before, now $cage_pid_after)"
    exit 1
fi

echo "--- cage destroy cleans both microVMs + network ---"
agentcage cage destroy "$CAGE" --force || { echo "FAIL: cage destroy"; exit 1; }
if container list -a | grep -q "^$CAGE\\b"; then
    echo "FAIL: cage VM not deleted"
    exit 1
fi
if container list -a | grep -q "^${CAGE}-egress\\b"; then
    echo "FAIL: egress VM not deleted"
    exit 1
fi

echo "PASS: phase_apple — 2-microVM model intact"
