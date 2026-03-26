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

# 6.5: DNS query logging
assert_cmd_ok "6.5" "DNS query logging" \
  agentcage cage logs "$CAGE" -s dns -n 20

# 6.6: Proxy connection logging
assert_cmd_ok "6.6" "Proxy connection logging" \
  agentcage cage logs "$CAGE" -s proxy -n 20

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

print_results
