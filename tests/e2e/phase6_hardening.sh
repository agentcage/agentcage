#!/usr/bin/env bash
# Phase 6: Container Mode — Edge Cases & Security Hardening
source "$(dirname "$0")/lib.sh"
preflight_check agentcage podman curl
phase_header 6 "Container Mode — Edge Cases & Security Hardening"

CAGE="e2e-hardened"
CONFIGS="$(dirname "$0")/configs"
PORT="${E2E_PORT_HARDENED:-19084}"
BASE="http://localhost:$PORT"

destroy_cage "$CAGE"
register_cage "$CAGE"

echo "Creating hardened cage..."
export E2E_PORT_HARDENED="$PORT"
create_cage "$CONFIGS/hardened.yaml" >/dev/null
if ! wait_ready "$BASE" 120; then
  e2e_fail "6.0" "Setup" "hardened cage not ready"
  print_results; exit 1
fi

# 6.1: Read-only filesystem
assert_cmd_fail "6.1" "Read-only filesystem" \
  podman exec "${CAGE}-cage" touch /usr/testfile

# 6.2: Dropped capabilities
e2e_timer_start
OUTPUT=$(podman exec "${CAGE}-cage" cat /proc/1/status 2>&1) || true
if echo "$OUTPUT" | grep -q "CapEff:.*0000000000000000"; then
  e2e_pass "6.2" "Dropped capabilities"
else
  e2e_fail "6.2" "Dropped capabilities" "CapEff not zeroed"
fi

# 6.3: Non-root user
e2e_timer_start
OUTPUT=$(podman exec "${CAGE}-cage" id 2>&1) || true
if echo "$OUTPUT" | grep -q "uid=1000"; then
  e2e_pass "6.3" "Non-root user"
else
  e2e_fail "6.3" "Non-root user" "$OUTPUT"
fi

# 6.4: Memory limit
e2e_timer_start
OUTPUT=$(podman exec "${CAGE}-cage" cat /sys/fs/cgroup/memory.max 2>&1) || true
if [ "$OUTPUT" = "268435456" ]; then
  e2e_pass "6.4" "Memory limit (256m)"
else
  e2e_fail "6.4" "Memory limit (256m)" "got $OUTPUT"
fi

# 6.5: DNS query logging (now reads from the unified egress journal)
assert_cmd_ok "6.5" "DNS query logging" \
  agentcage cage logs "$CAGE" -s egress -n 20

# 6.6: Proxy connection logging (also egress; mitmproxy + dnsmasq share
# the supervisor's stderr stream)
assert_cmd_ok "6.6" "Proxy connection logging" \
  agentcage cage logs "$CAGE" -s egress -n 20

# 6.7: Severity filtering
assert_cmd_ok "6.7" "Log severity filtering" \
  agentcage cage logs "$CAGE" -l error -n 50

# 6.8: Invalid config rejected
BAD_CONFIG=$(mktemp /tmp/e2e-bad-XXXXXX.yaml)
cat > "$BAD_CONFIG" <<'EOF'
name: "INVALID NAME"
container:
  image: "node:22-slim"
  command: ["node", "app.js"]
  ports:
    - "127.0.0.1:19082:3000"
domains:
  allow:
    - example.com
EOF
assert_cmd_fail "6.8" "Invalid config rejected" \
  agentcage cage create -c "$BAD_CONFIG"
rm -f "$BAD_CONFIG"

# 6.9: Port conflict detected
CONFLICT_CONFIG=$(mktemp /tmp/e2e-conflict-XXXXXX.yaml)
cat > "$CONFLICT_CONFIG" <<EOF
name: e2e-conflict
container:
  image: "node:22-slim"
  command: ["node", "app.js"]
  ports:
    - "127.0.0.1:${PORT}:3000"
domains:
  allow:
    - example.com
EOF
assert_cmd_fail "6.9" "Port conflict detected" \
  agentcage cage create -c "$CONFLICT_CONFIG"
rm -f "$CONFLICT_CONFIG"

# 6.10: Subnet allocation (different /24 for each cage)
e2e_timer_start
SUBNET=$(podman network inspect "${CAGE}-net" 2>/dev/null \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['subnets'][0]['subnet'])" 2>/dev/null || echo "")
if echo "$SUBNET" | grep -qE "^10\.89\.[0-9]+\.0/24$"; then
  e2e_pass "6.10" "Subnet allocation"
else
  e2e_fail "6.10" "Subnet allocation" "unexpected subnet: $SUBNET"
fi

# 6.11: Workspace .git/hooks tmpfs mask blocks cage→host git-hook pivot
# (#170). A cage that bind-mounts ${PROJECT_DIR}:/workspace:rw and applies
# the noexec tmpfs mask on /workspace/.git/hooks/ must NOT let a caged
# agent's write reach the host: the cage writes into a transient tmpfs
# that vanishes on stop, so $PROJECT_DIR/.git/hooks/pre-commit must NOT
# exist on the host afterward. This is the e2e counterpart to the static
# tmpfs-YAML checks in tests/test_scaffolds.py — it verifies the mask has
# the intended security effect against a running cage, not just that the
# config declares it. Container (podman) backend only; apple-container
# does not yet honor tmpfs (#120) and that residual exposure is already
# surfaced as a SECURITY-RELEVANT config warning (config.py).
MASK_CAGE="e2e-mask"
# Must live under $HOME: quadlets.py rejects any container.volumes host path
# that resolves outside the home directory, so a /tmp project dir made this
# whole phase report SKIP ("cage create failed") on every runner instead of
# ever exercising the mask.
MASK_PROJECT="$(mktemp -d "$HOME/.agentcage-e2e-mask-XXXXXX")"
# The mask assumes a git project — create the .git tree podman overlays.
mkdir -p "$MASK_PROJECT/.git/hooks"
# mktemp -d makes 0700; a real checkout is 0755. With `userns: keep-id` the
# host user keeps its own uid in the cage, which is NOT the workload's
# `user: "1000:1000"`, so a 0700 /workspace denies uid 1000 even *search*
# permission and every path below it fails with EACCES before the mask is
# ever reached. Match a real project so this test measures the mask.
chmod 755 "$MASK_PROJECT"
# Sanity: the host pre-condition (no pre-commit hook) holds before the run.
[ ! -f "$MASK_PROJECT/.git/hooks/pre-commit" ] || {
  e2e_fail "6.11" "Workspace .git/hooks tmpfs mask" \
    "host pre-condition broken: pre-commit already exists"
}
export E2E_MASK_PROJECT_DIR="$MASK_PROJECT"
destroy_cage "$MASK_CAGE"
register_cage "$MASK_CAGE"
MASK_CREATE_RC=0
# Only stdout is dropped: create_cage dumps a failing create to stderr
# (#317), and the skip below needs that reason to be visible.
create_cage "$CONFIGS/workspace-mask.yaml" >/dev/null || MASK_CREATE_RC=$?
if [ "$MASK_CREATE_RC" -ne 0 ]; then
  e2e_skip "6.11" "Workspace .git/hooks tmpfs mask" \
    "cage create failed (no podman / buildkit available) — see the dumped create output above"
else
  # `cage create` builds + starts the cage, but a sleep-infinity cage has
  # no HTTP port to wait_ready against. Poll cage exec until the workload
  # is up (cage exec refuses a stopped cage with a clear error).
  MASK_READY=false
  for _ in $(seq 1 30); do
    if agentcage cage exec "$MASK_CAGE" -- true >/dev/null 2>&1; then
      MASK_READY=true
      break
    fi
    sleep 1
  done
  if [ "$MASK_READY" != true ]; then
    e2e_fail "6.11" "Workspace .git/hooks tmpfs mask" \
      "cage not reachable via exec after create"
  else
    # Plant a hook from inside the cage AS THE DEFAULT (non-root) cage user.
    # The write lands in the cage's tmpfs view of /workspace/.git/hooks/, not
    # on the host bind-mount. chmod +x mirrors the real pivot shape. The
    # runtimes give an option-less tmpfs the mode of the directory it masks —
    # here the host's 0755 .git/hooks — with a root-owned root, so without the
    # mask-mode pin (#321) this write fails with EACCES; keep its stderr so
    # that shows up in the failure message instead of an empty file.
    MASK_WRITE_ERR=$(agentcage cage exec "$MASK_CAGE" -- sh -c \
      'echo pwned > /workspace/.git/hooks/pre-commit && chmod +x /workspace/.git/hooks/pre-commit' \
      2>&1 >/dev/null | tr -d '\r' | tr '\n' ' ') || true
    # The write MUST be visible inside the cage (proves the tmpfs is there
    # and writable — the mask is a transient overlay, not a read-only block).
    IN_CAGE=$(agentcage cage exec "$MASK_CAGE" -- \
      cat /workspace/.git/hooks/pre-commit 2>/dev/null | tr -d '\r\n') || true
    # Snapshot the mask's runtime shape while the cage is still up. A bare
    # "Permission denied" cannot distinguish a wrong tmpfs mode (#321) from a
    # /workspace whose modes deny the workload before the mask is reached.
    MASK_DIAG=$(agentcage cage exec "$MASK_CAGE" -- sh -c \
      'id; ls -ldn /workspace /workspace/.git /workspace/.git/hooks; grep hooks /proc/self/mounts' \
      2>&1 | tr -d '\r' | tr '\n' '|') || true
    # Stop the cage so the tmpfs is torn down.
    agentcage cage stop "$MASK_CAGE" >/dev/null 2>&1 || true
    if [ -f "$MASK_PROJECT/.git/hooks/pre-commit" ]; then
      e2e_fail "6.11" "Workspace .git/hooks tmpfs mask" \
        "cage write reached the host — cage→host pivot NOT blocked (in-cage content: ${IN_CAGE:-<empty>})"
    elif [ "$IN_CAGE" != "pwned" ]; then
      e2e_fail "6.11" "Workspace .git/hooks tmpfs mask" \
        "write did not land in the cage tmpfs (in-cage content: ${IN_CAGE:-<empty>}; write stderr: ${MASK_WRITE_ERR:-<none>}; cage view: ${MASK_DIAG:-<none>}) — mask shape changed"
    else
      e2e_pass "6.11" "Workspace .git/hooks tmpfs mask"
    fi
  fi
fi
destroy_cage "$MASK_CAGE"
# Guard the rm: this path is now under $HOME, so an empty MASK_PROJECT must
# never turn into `rm -rf ""`. An `if` and not `[ ... ] && rm`: lib.sh runs the
# phase under `set -e`, where a false test as the last command would abort
# before print_results.
if [ -n "${MASK_PROJECT:-}" ]; then
  rm -rf "$MASK_PROJECT"
fi

print_results
