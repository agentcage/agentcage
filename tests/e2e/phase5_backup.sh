#!/usr/bin/env bash
# Phase 5: Container Mode — Backup/Restore & Multi-Cage Isolation
source "$(dirname "$0")/lib.sh"
preflight_check agentcage podman curl
phase_header 5 "Container Mode — Backup/Restore & Multi-Cage Isolation"

CAGE="basic"
CAGE2="e2e-second"
BASE="http://localhost:3000"
CONFIGS="$(dirname "$0")/configs"
SECOND_PORT="${E2E_PORT_SECOND:-19083}"
BASE2="http://localhost:$SECOND_PORT"
BACKUP_FILE=$(mktemp /tmp/e2e-backup-XXXXXX.tar.gz)

# Ensure the basic cage is running
if ! curl -sf "$BASE/" >/dev/null 2>&1; then
  echo "Basic cage not running — creating..."
  destroy_cage "$CAGE"
  register_cage "$CAGE"
  create_cage "$CONFIGS/basic.yaml" >/dev/null
  start_mock "$CAGE" httpbin.org
  wait_ready "$BASE" 120 || { e2e_fail "5.0" "Setup" "cage not ready"; print_results; exit 1; }
  repatch_mock "$CAGE" httpbin.org || true
else
  # Basic cage already running (from sequential chain) — ensure mock is up
  start_mock "$CAGE" httpbin.org 2>/dev/null || true
fi

# Create second cage
destroy_cage "$CAGE2"
register_cage "$CAGE2"
echo "Creating second cage..."
export E2E_PORT_SECOND="$SECOND_PORT"
create_cage "$CONFIGS/second.yaml" >/dev/null
start_mock "$CAGE2" example.com
wait_ready "$BASE2" 120 || { e2e_fail "5.0" "Setup" "second cage not ready"; print_results; exit 1; }
repatch_mock "$CAGE2" example.com || true

# Verify the OUTBOUND data path is working for BOTH cages before any
# test runs. wait_ready only checks GET / on the published port and
# can return success while the cage's default route or proxy iptables
# aren't fully set up. wait_data_path probes the actual proxy → mock
# chain and re-patches /etc/hosts on retry.
if ! wait_data_path "$BASE" "/fetch?url=http://httpbin.org/get" "$CAGE" httpbin.org; then
  e2e_fail "5.0" "Setup" "basic cage data path not ready within 120s"
  dump_cage_diagnostics "$CAGE" "5.0 setup failure (basic)"
  print_results; exit 1
fi
if ! wait_data_path "$BASE2" "/fetch?url=http://example.com" "$CAGE2" example.com; then
  e2e_fail "5.0" "Setup" "second cage data path not ready within 120s"
  dump_cage_diagnostics "$CAGE2" "5.0 setup failure (second)"
  print_results; exit 1
fi

# 5.1: Both cages running
e2e_timer_start
OUTPUT=$(agentcage cage list 2>&1)
if echo "$OUTPUT" | grep -q "$CAGE" && echo "$OUTPUT" | grep -q "$CAGE2"; then
  e2e_pass "5.1" "Both cages running"
else
  e2e_fail "5.1" "Both cages running"
fi

# 5.2: Subnet isolation
e2e_timer_start
# Poll all four conditions in a single loop instead of 4 sequential waits.
# This avoids 90+90+30+30=240s worst case when one external domain is slow.
is_blocked() { [ "$1" = "403" ] || [ "$1" = "502" ]; }
_isolation_ok=false
_iso_deadline=$((SECONDS + 120))
_iso_delay=1
while [ "$SECONDS" -lt "$_iso_deadline" ]; do
  CODE_BASIC_HTTPBIN=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE/fetch?url=http://httpbin.org/get" 2>/dev/null || true)
  CODE_BASIC_EXAMPLE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE/fetch?url=http://example.com" 2>/dev/null || true)
  CODE_SECOND_EXAMPLE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE2/fetch?url=http://example.com" 2>/dev/null || true)
  CODE_SECOND_HTTPBIN=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE2/fetch?url=http://httpbin.org/get" 2>/dev/null || true)
  if [ "$CODE_BASIC_HTTPBIN" = "200" ] && is_blocked "$CODE_BASIC_EXAMPLE" && \
     [ "$CODE_SECOND_EXAMPLE" = "200" ] && is_blocked "$CODE_SECOND_HTTPBIN"; then
    _isolation_ok=true
    break
  fi
  sleep "$_iso_delay"
  _iso_delay=$(( _iso_delay + 1 ))
  [ "$_iso_delay" -gt 4 ] && _iso_delay=4
done
if [ "$_isolation_ok" = true ]; then
  e2e_pass "5.2" "Subnet isolation"
else
  e2e_fail "5.2" "Subnet isolation" \
    "basic→httpbin=$CODE_BASIC_HTTPBIN basic→example=$CODE_BASIC_EXAMPLE second→example=$CODE_SECOND_EXAMPLE second→httpbin=$CODE_SECOND_HTTPBIN"
  dump_cage_diagnostics "$CAGE" "5.2 failure (basic)"
  dump_cage_diagnostics "$CAGE2" "5.2 failure (second)"
fi

# 5.3: Backup cage
e2e_timer_start
if agentcage cage backup "$CAGE" -o "$BACKUP_FILE" >/dev/null 2>&1 && [ -f "$BACKUP_FILE" ]; then
  e2e_pass "5.3" "Backup cage"
else
  e2e_fail "5.3" "Backup cage" "backup file not created"
fi

# 5.4: Destroy original
e2e_timer_start
stop_mock "$CAGE"
if agentcage cage destroy "$CAGE" -y >/dev/null 2>&1; then
  e2e_pass "5.4" "Destroy original"
else
  e2e_fail "5.4" "Destroy original"
fi

# 5.5: Restore cage
e2e_timer_start
# Note: restore may fail if the original config used env vars like ${AGENT_DIR}
# that aren't set at restore time. This is a known limitation.
_restore_ok=false
if AGENT_DIR="$AGENT_DIR" agentcage cage restore "$BACKUP_FILE" >/dev/null 2>&1; then
  if wait_ready "$BASE" 90; then
    start_mock "$CAGE" httpbin.org 2>/dev/null || true
    _restore_ok=true
    e2e_pass "5.5" "Restore cage"
  else
    e2e_fail "5.5" "Restore cage" "restore succeeded but cage not ready within 90s"
  fi
else
  e2e_fail "5.5" "Restore cage" "restore command failed"
fi

if [ "$_restore_ok" = true ]; then
  # 5.6: Restored cage works — restore creates a fresh network with new IPs,
  # so re-patch /etc/hosts during the readiness probe to recover from any
  # proxy restart or stale mock IP.
  e2e_timer_start
  if wait_data_path "$BASE" "/fetch?url=http://httpbin.org/get" "$CAGE" httpbin.org; then
    e2e_pass "5.6" "Restored cage works"
  else
    CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$BASE/fetch?url=http://httpbin.org/get" 2>/dev/null || true)
    e2e_fail "5.6" "Restored cage works" "expected HTTP 200, got ${CODE:-000} after 120s"
    dump_cage_diagnostics "$CAGE" "5.6 failure"
  fi
else
  e2e_skip "5.6" "Restored cage works" "depends on 5.5"
fi

# Cleanup
destroy_cage "$CAGE"
destroy_cage "$CAGE2"
rm -f "$BACKUP_FILE"

print_results
