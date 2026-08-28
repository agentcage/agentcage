#!/usr/bin/env bash
# Phase: apple-container Mode — Manual e2e (macOS-only).
#
# Apple's `container` CLI ships only for macOS 26+ ASi, so this phase
# is manual-only and not part of CI. Run on a developer workstation
# with `agentcage doctor` reporting all-green for apple-container.
#
# CI status (issue #215): this phase CANNOT run on GitHub's hosted
# `macos-26` runner — that runner is itself a VM, so Apple's
# Virtualization.framework refuses to boot nested VMs with
# `VZErrorDomain Code=2 "Virtualization is not available on this
# hardware."` The script therefore probes for nested virt and SKIPS
# (exit 0, clear reason) on a no-nested-virt host instead of erroring,
# while still running the real e2e when nested virt IS available.
# Getting the real e2e into CI needs one of (none are in-repo fixes):
#   1. a paid `macos-26-large` / `-xlarge` runner with nested virt
#   2. a self-hosted Apple Silicon runner (bare metal)
#   3. keep it manual-only on developer workstations (status quo)
# See https://github.com/agentcage/agentcage/issues/215.
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

# ── nested-virtualization probe (issue #215) ────────────────────────────────────────
# GitHub's hosted macos-26 runners are themselves VMs, so Apple's
# Virtualization.framework refuses to boot nested VMs (VZErrorDomain
# Code=2). Rather than error out mid-run, detect the no-nested-virt
# condition here and SKIP with a clear reason. On a capable bare-metal
# (or nested-virt-enabled) host the probe passes and the real e2e runs.
#
# Set AGENTCAGE_APPLE_E2E_FORCE=1 to bypass the probe entirely (escape
# hatch for self-hosted runners known to support nested virt even when
# the heuristics below can't confirm it).
#
# Probe order (first hit ⇒ SKIP):
#   1. ImageOS env — set ONLY on GitHub-hosted image runners (e.g.
#      "macos26"), never on self-hosted runners. macos* ⇒ hosted VM
#      ⇒ no nested virt.
#   2. kern.hv_vcpus sysctl — 0 means the hypervisor framework exposes
#      no vCPUs, i.e. no nested-virt support. Covers non-GitHub VMs.
if [ "${AGENTCAGE_APPLE_E2E_FORCE:-0}" != "1" ]; then
    if [ -n "${ImageOS:-}" ]; then
        case "$ImageOS" in
            macos*)
                echo "SKIP: nested virtualization unavailable on this GitHub-hosted runner (ImageOS=$ImageOS) — apple-container e2e needs bare-metal Apple Silicon or a self-hosted/paid runner with nested virt (see issue #215)"
                exit 0
                ;;
        esac
    fi
    _hv_vcpus="$(sysctl -n kern.hv_vcpus 2>/dev/null || true)"
    if [ -n "$_hv_vcpus" ] && [ "$_hv_vcpus" -eq 0 ] 2>/dev/null; then
        echo "SKIP: nested virtualization unavailable on this runner (kern.hv_vcpus=$_hv_vcpus) — apple-container e2e needs bare-metal Apple Silicon or a self-hosted/paid runner with nested virt (see issue #215)"
        exit 0
    fi
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
    # apt-get update/install for the curl bootstrap below — pre-allowlist
    # the ubuntu apt mirrors so the cage workload can fetch curl through
    # the egress sibling. This is *only* needed because the slimmed
    # wrapper Containerfile no longer pre-installs HTTP clients in the
    # base image; production cages don't need apt at runtime.
    - archive.ubuntu.com
    - ports.ubuntu.com
    - security.ubuntu.com
secret_injection:
  - env: API_KEY
    placeholder: "{{API_KEY}}"
    inject_to: ["api.github.com"]
EOF

echo "Creating apple-container cage (builds egress + wrapper images)..."
# `cage create` takes the cage name from cage.yaml — no positional arg.
agentcage cage create --config "/tmp/${CAGE}.yaml" \
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
# The cage's ubuntu:24.04 base ships without curl/wget. apt-install it
# inside the cage VM (as root, before we test as uid 1000) so the
# subsequent egress-proxied request has a client to make. The HTTPS
# fetch goes through mitmproxy in the egress sibling thanks to
# cage-init.sh's default-route handoff + trust-store install.
agentcage cage exec "$CAGE" --as-root -- bash -c \
    'command -v curl >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq curl) >/dev/null 2>&1' \
    || { echo "FAIL: could not install curl in cage VM"; exit 1; }
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
# `cage destroy` flag is `-y / --yes`, not `--force`.
agentcage cage destroy "$CAGE" -y || { echo "FAIL: cage destroy"; exit 1; }
if container list -a | grep -q "^$CAGE\\b"; then
    echo "FAIL: cage VM not deleted"
    exit 1
fi
if container list -a | grep -q "^${CAGE}-egress\\b"; then
    echo "FAIL: egress VM not deleted"
    exit 1
fi

echo "PASS: phase_apple — 2-microVM model intact"
