#!/usr/bin/env bash
# Phase 5: Container Mode — Backup/Restore & Multi-Cage Isolation
source "$(dirname "$0")/lib.sh"
preflight_check agentcage podman curl
phase_header 5 "Container Mode — Backup/Restore & Multi-Cage Isolation"

CAGE="basic"
CAGE2="e2e-second"
BASE="http://localhost:3000"
CONFIGS="$(dirname "$0")/configs"
SECOND_PORT="${E2E_PORT_SECOND:-19080}"
BASE2="http://localhost:$SECOND_PORT"
BACKUP_FILE=$(mktemp /tmp/e2e-backup-XXXXXX.tar.gz)

# Ensure the basic cage is running
if ! curl -sf "$BASE/" >/dev/null 2>&1; then
  echo "Basic cage not running — creating..."
  destroy_cage "$CAGE"
  register_cage "$CAGE"
  create_cage "$REPO_ROOT/examples/basic/cage.yaml" >/dev/null
  wait_ready "$BASE" 120 || { e2e_fail "5.0" "Setup" "cage not ready"; print_results; exit 1; }
fi

# Create second cage
destroy_cage "$CAGE2"
register_cage "$CAGE2"
echo "Creating second cage..."
export E2E_PORT_SECOND="$SECOND_PORT"
create_cage "$CONFIGS/second.yaml" >/dev/null
wait_ready "$BASE2" 120 || { e2e_fail "5.0" "Setup" "second cage not ready"; print_results; exit 1; }

# 5.1: Both cages running
OUTPUT=$(agentcage cage list 2>&1)
if echo "$OUTPUT" | grep -q "$CAGE" && echo "$OUTPUT" | grep -q "$CAGE2"; then
  e2e_pass "5.1" "Both cages running"
else
  e2e_fail "5.1" "Both cages running"
fi

# 5.2: Subnet isolation
# Wait for each proxy to actually serve its allowed domain (not just 502).
# The second cage proxy often takes longer to be fully ready.
wait_http_code "$BASE/fetch?url=http://httpbin.org/get" 200 90 || true
wait_http_code "$BASE2/fetch?url=http://example.com" 200 90 || true
# Also confirm blocked domains return 403/502 (not 000/200)
wait_http_blocked "$BASE/fetch?url=http://example.com" 30 || true
wait_http_blocked "$BASE2/fetch?url=http://httpbin.org/get" 30 || true

# Now take the final readings
CODE_BASIC_HTTPBIN=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$BASE/fetch?url=http://httpbin.org/get" 2>/dev/null || echo "000")
CODE_BASIC_EXAMPLE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$BASE/fetch?url=http://example.com" 2>/dev/null || echo "000")
CODE_SECOND_EXAMPLE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$BASE2/fetch?url=http://example.com" 2>/dev/null || echo "000")
CODE_SECOND_HTTPBIN=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$BASE2/fetch?url=http://httpbin.org/get" 2>/dev/null || echo "000")
# Blocked domains return 403 (proxy) or 502 (DNS sinkhole) depending on timing
is_blocked() { [ "$1" = "403" ] || [ "$1" = "502" ]; }
if [ "$CODE_BASIC_HTTPBIN" = "200" ] && is_blocked "$CODE_BASIC_EXAMPLE" && \
   [ "$CODE_SECOND_EXAMPLE" = "200" ] && is_blocked "$CODE_SECOND_HTTPBIN"; then
  e2e_pass "5.2" "Subnet isolation"
else
  e2e_fail "5.2" "Subnet isolation" \
    "basic→httpbin=$CODE_BASIC_HTTPBIN basic→example=$CODE_BASIC_EXAMPLE second→example=$CODE_SECOND_EXAMPLE second→httpbin=$CODE_SECOND_HTTPBIN"
fi

# 5.3: Backup cage
if agentcage cage backup "$CAGE" -o "$BACKUP_FILE" >/dev/null 2>&1 && [ -f "$BACKUP_FILE" ]; then
  e2e_pass "5.3" "Backup cage"
else
  e2e_fail "5.3" "Backup cage" "backup file not created"
fi

# 5.4: Destroy original
if agentcage cage destroy "$CAGE" -y >/dev/null 2>&1; then
  e2e_pass "5.4" "Destroy original"
else
  e2e_fail "5.4" "Destroy original"
fi

# 5.5: Restore cage
# Note: restore may fail if the original config used env vars like ${AGENT_DIR}
# that aren't set at restore time. This is a known limitation.
_restore_ok=false
if AGENT_DIR="$AGENT_DIR" agentcage cage restore "$BACKUP_FILE" >/dev/null 2>&1; then
  if wait_ready "$BASE" 90; then
    _restore_ok=true
    e2e_pass "5.5" "Restore cage"
  else
    e2e_fail "5.5" "Restore cage" "restore succeeded but cage not ready within 90s"
  fi
else
  e2e_fail "5.5" "Restore cage" "restore command failed"
fi

if [ "$_restore_ok" = true ]; then
  # 5.6: Restored cage works — proxy may need a moment to forward after restore
  if wait_http_code "$BASE/fetch?url=https://httpbin.org/get" 200 60; then
    e2e_pass "5.6" "Restored cage works"
  else
    CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$BASE/fetch?url=https://httpbin.org/get" 2>/dev/null || echo "000")
    e2e_fail "5.6" "Restored cage works" "expected HTTP 200, got $CODE after 60s"
  fi
else
  e2e_skip "5.6" "Restored cage works" "depends on 5.5"
fi

# Cleanup
destroy_cage "$CAGE"
destroy_cage "$CAGE2"
rm -f "$BACKUP_FILE"

print_results
