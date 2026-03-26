#!/usr/bin/env bash
# Phase 4: Container Mode — Domain Management & Hot-Reload
source "$(dirname "$0")/lib.sh"
preflight_check agentcage podman curl
phase_header 4 "Container Mode — Domain Management & Hot-Reload"

CAGE="basic"
BASE="http://localhost:3000"

# Ensure the basic cage is running
if ! curl -sf "$BASE/" >/dev/null 2>&1; then
  echo "Basic cage not running — creating..."
  destroy_cage "$CAGE"
  register_cage "$CAGE"
  create_cage "$REPO_ROOT/examples/basic/cage.yaml" >/dev/null
  wait_ready "$BASE" 120 || { e2e_fail "4.0" "Setup" "cage not ready"; print_results; exit 1; }
fi

# 4.1: List domains
assert_output_contains "4.1" "List domains" "httpbin.org" \
  agentcage domain list "$CAGE"

# 4.2: Add domain
e2e_timer_start
if agentcage domain add "$CAGE" example.com >/dev/null 2>&1; then
  wait_ready "$BASE" 60 || true
  repatch_mock "$CAGE" httpbin.org example.com
  e2e_pass "4.2" "Add domain"
else
  e2e_fail "4.2" "Add domain" "command failed"
fi

# 4.3: New domain accessible (poll — proxy may need a moment after hot-reload)
e2e_timer_start
# Domain hot-reload can be slow in CI: the proxy needs to pick up the config change,
# regenerate DNS rules, and restart. Give it up to 120s.
if wait_http_code "$BASE/fetch?url=http://example.com" 200 120; then
  e2e_pass "4.3" "New domain accessible"
else
  e2e_fail "4.3" "New domain accessible" "did not get HTTP 200 within 120s"
fi

# 4.4: Remove domain
e2e_timer_start
if agentcage domain rm "$CAGE" example.com >/dev/null 2>&1; then
  wait_ready "$BASE" 60 || true
  repatch_mock "$CAGE" httpbin.org
  e2e_pass "4.4" "Remove domain"
else
  e2e_fail "4.4" "Remove domain" "command failed"
fi

# 4.5: Removed domain blocked (poll — proxy may need a moment)
e2e_timer_start
wait_ready "$BASE" 60 || true
if wait_http_blocked "$BASE/fetch?url=http://example.com" 45; then
  e2e_pass "4.5" "Removed domain blocked"
else
  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE/fetch?url=http://example.com" 2>/dev/null || echo "000")
  e2e_fail "4.5" "Removed domain blocked" "expected 403/502, got $CODE"
fi

# 4.6: Stop cage
e2e_timer_start
if agentcage cage stop "$CAGE" >/dev/null 2>&1; then
  e2e_pass "4.6" "Stop cage"
else
  e2e_fail "4.6" "Stop cage" "command failed"
fi

# 4.7: Start cage
e2e_timer_start
agentcage cage start "$CAGE" >/dev/null 2>&1
if wait_ready "$BASE" 60; then
  repatch_mock "$CAGE" httpbin.org
  e2e_pass "4.7" "Start cage"
else
  e2e_fail "4.7" "Start cage" "not ready after start"
fi

# 4.8: Restart cage
e2e_timer_start
agentcage cage restart "$CAGE" >/dev/null 2>&1
if wait_ready "$BASE" 60; then
  repatch_mock "$CAGE" httpbin.org
  e2e_pass "4.8" "Restart cage"
else
  e2e_fail "4.8" "Restart cage" "not ready after restart"
fi

print_results
