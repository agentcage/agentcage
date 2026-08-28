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
#      (requires AGENTCAGE_APPLE_E2E_FORCE=1 in the workflow env — these
#      are GitHub-hosted image runners that ALSO set ImageOS=macos26, so
#      the auto-skip in probe 1 below would otherwise suppress them; the
#      FORCE escape hatch is the documented way to run the real e2e on a
#      known-capable paid nested-virt runner instead of being skipped)
#   2. a self-hosted Apple Silicon runner (bare metal)
#   3. keep it manual-only on developer workstations (status quo)
# See https://github.com/agentcage/agentcage/issues/215.
#
# Covers the 2-microVM model from PR 3 (#196):
#   * cage create builds both images (agentcage-egress + per-cage wrapper)
#   * cage status shows both microVMs running
#   * cage exec defaults to uid 1000
#   * Threat-model invariants: secrets not reachable from the cage VM;
#     root in the cage VM cannot modify the cage's firewall
#   * domain add SIGHUPs dnsmasq in BOTH the egress sibling and the cage
#     (the cage-local one is load-bearing since #210) — no cage restart
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
#   2. kern.hv.supported sysctl — the documented Hypervisor.framework
#      availability sysctl: 1 ⟹ hypervisor available (proceed); 0 ⟹
#      no VM/nested-virt support on this host (e.g. a non-GitHub VM
#      without nested virt). We deliberately use `kern.hv.supported`
#      and NOT `kern.hv_vcpus`: where the latter exists it reports the
#      vCPUs *currently in use by running VMs*, so it is 0 on every
#      IDLE capable bare-metal Apple Silicon workstation — i.e. it
#      would FALSE-SKIP the real e2e on the very workstations this
#      phase targets. `kern.hv.supported` reflects capability, not
#      current utilization, which is the property we actually want.
#      Empty/non-numeric ⟹ sysctl absent or unreadable ⟹ treat as
#      capable and proceed (fall through to the real e2e, which is no
#      worse than the pre-fix behavior on an incapable host).
if [ "${AGENTCAGE_APPLE_E2E_FORCE:-0}" != "1" ]; then
    if [ -n "${ImageOS:-}" ]; then
        case "$ImageOS" in
            macos*)
                echo "SKIP: nested virtualization unavailable on this GitHub-hosted runner (ImageOS=$ImageOS) — apple-container e2e needs bare-metal Apple Silicon or a self-hosted/paid runner with nested virt (see issue #215)"
                exit 0
                ;;
        esac
    fi
    # kern.hv.supported: 1 ⟹ hypervisor available (proceed); 0 ⟹ no
    # nested virt (skip). Empty/non-numeric ⟹ sysctl absent/unreadable
    # ⟹ treat as capable and proceed (intentional fallthrough: the
    # `-eq 0` test is false for non-numeric, so we DON'T skip — the real
    # e2e then runs and, on a genuinely incapable host, fails for the
    # same reason it did before this probe existed).
    _hv_supported="$(sysctl -n kern.hv.supported 2>/dev/null || true)"
    if [ -n "$_hv_supported" ] && [ "$_hv_supported" -eq 0 ] 2>/dev/null; then
        echo "SKIP: nested virtualization unavailable on this runner (kern.hv.supported=$_hv_supported) — apple-container e2e needs bare-metal Apple Silicon or a self-hosted/paid runner with nested virt (see issue #215)"
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

echo "--- THREAT MODEL: root in cage VM cannot modify the firewall ---"
# This assertion used to be "no iptables binary in the cage VM" — that
# invariant died in #210 ("block cage->host-gateway TCP + non-DNS UDP",
# CTF F1), which re-added iptables to Containerfile.wrapper.j2 because
# cage-init.sh stage B' now needs it INSIDE the cage to install:
#   * OUTPUT -d <vmnet-gateway> -p tcp/udp -j DROP  (cage->macOS-host
#     services: sshd :22, ARD :5900 — reachable outside the egress proxy)
#   * OUTPUT -p udp --dport 53 -m owner ! --uid-owner 201 -j DROP
#     (workload-originated DNS-tunnel exfil past the in-cage dnsmasq)
# The binary being present is therefore REQUIRED, not a finding. Since
# #200 added the old check and #210 invalidated it without updating it,
# this line aborted the phase on every bare-metal run and everything
# below it was dead. See issue #314.
#
# Containment is capability-based now: `cage exec --as-root` wraps the
# session in `setpriv --bounding-set=-net_admin --inh-caps=-net_admin`
# (backends/apple_container.py exec_argv), so uid 0 in the cage lands
# with CAP_NET_ADMIN cleared from CapEff and every mutating netfilter
# call returns EPERM. That is what we assert here.

# Guard first: a MISSING iptables must not make the mutation checks below
# pass vacuously (a command that isn't there also "fails"). It is also a
# real defect in its own right — without iptables, cage-init.sh stage B'
# logs "cage->host lockdown skipped" and the #210 DROP rules never land.
if ! agentcage cage exec "$CAGE" --as-root -- sh -c 'command -v iptables >/dev/null 2>&1'; then
    echo "FAIL: no iptables in cage VM — cage-init.sh stage B' cannot install"
    echo "      the #210 cage->host-gateway / DNS-owner DROP rules, and the"
    echo "      capability assertions below would pass vacuously."
    exit 1
fi

# (a) A mutating iptables operation must FAIL as root in the cage VM.
fw_rc=0
fw_out=$(agentcage cage exec "$CAGE" --as-root -- iptables -F OUTPUT 2>&1) || fw_rc=$?
if [ "$fw_rc" -eq 0 ]; then
    echo "FAIL: --as-root flushed the cage's OUTPUT chain — CAP_NET_ADMIN is"
    echo "      NOT being dropped, so the #210 egress lockdown is bypassable!"
    exit 1
fi
echo "    iptables -F OUTPUT rejected (rc=$fw_rc): $fw_out"

# (b) Same for appending a rule, so we're not just observing a quirk of -F.
fw_rc=0
fw_out=$(agentcage cage exec "$CAGE" --as-root -- \
    iptables -A OUTPUT -p tcp -j ACCEPT 2>&1) || fw_rc=$?
if [ "$fw_rc" -eq 0 ]; then
    echo "FAIL: --as-root appended an OUTPUT ACCEPT rule in the cage VM!"
    exit 1
fi
echo "    iptables -A OUTPUT ... rejected (rc=$fw_rc): $fw_out"

# (c) Root cause, asserted directly: CAP_NET_ADMIN (bit 12 => mask 0x1000)
# must be CLEAR in the effective set of an --as-root session. Reference
# values measured on a real cage (container 1.0.0, ubuntu:24.04 base):
#   CapEff 00000000a80425fb  <- --as-root session, bit 12 CLEAR (0x...2...)
#   CapBnd 00000000a80435fb  <- container's full --cap-add set, bit 12 SET
# The two differ by exactly 0x1000, which is the masking logic below.
capeff=$(agentcage cage exec "$CAGE" --as-root -- \
    sh -c 'grep -m1 "^CapEff:" /proc/self/status' 2>/dev/null \
    | awk '{print $2}' | tr -dc '0-9a-fA-F' || true)
if [ -z "$capeff" ]; then
    echo "FAIL: could not read CapEff from /proc/self/status in the cage VM"
    exit 1
fi
if [ $(( 0x$capeff & 0x1000 )) -ne 0 ]; then
    echo "FAIL: CAP_NET_ADMIN set in CapEff ($capeff) for cage exec --as-root!"
    exit 1
fi
echo "    CapEff=$capeff (CAP_NET_ADMIN bit 12 clear)"

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
# Restart signal = PID 1's start time, read from /proc/1's mtime INSIDE
# the cage VM. The previous probe used
# `container inspect "$CAGE" | jq -r '.[0].process.pid ...'`, but Apple
# `container` 1.0.0's inspect schema has no `process` object at all — it
# is `status.{state,networks,startedDate}` (see
# src/agentcage/apple_container/cli.py::container_state and the schema
# fixtures in tests/test_apple_container.py). jq therefore emitted
# `empty` on BOTH sides and `"" != ""` was always false: the assertion
# passed vacuously and could never have caught a restart. It sits below
# the stale iptables check (issue #314), so nobody noticed. Reading PID
# 1's start time from inside the VM is schema-independent, and an empty
# read is now an explicit FAIL rather than a silent pass.
cage_boot_marker() {
    agentcage cage exec "$CAGE" --as-root -- stat -c %Y /proc/1 2>/dev/null \
        | tr -dc '0-9' || true
}
cage_boot_before=$(cage_boot_marker)
if [ -z "$cage_boot_before" ]; then
    echo "FAIL: cannot read the cage VM's PID-1 start time — restart probe unusable"
    exit 1
fi
agentcage domain add "$CAGE" api.anthropic.com || { echo "FAIL: domain add"; exit 1; }
cage_boot_after=$(cage_boot_marker)
if [ -z "$cage_boot_after" ] || [ "$cage_boot_before" != "$cage_boot_after" ]; then
    echo "FAIL: cage VM restarted on domain add (PID-1 start was $cage_boot_before, now $cage_boot_after)"
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
