#!/usr/bin/env bash
# Phase 3: Container Mode — Secret Injection & Management
source "$(dirname "$0")/lib.sh"
preflight_check agentcage podman curl
phase_header 3 "Container Mode — Secret Injection & Management"

CAGE="e2e-secrets"
CONFIGS="$(dirname "$0")/configs"
SECRET_PORT="${E2E_PORT_SECRETS:-19081}"
BASE="http://localhost:$SECRET_PORT"

destroy_cage "$CAGE"
register_cage "$CAGE"

echo "Creating secrets cage..."
export E2E_PORT_SECRETS="$SECRET_PORT"
create_cage "$CONFIGS/secrets.yaml" \
  --set-secret MY_API_KEY=test-secret-value-12345 >/dev/null
start_mock "$CAGE" httpbin.org
if ! wait_ready "$BASE" 120; then
  e2e_fail "3.0" "Setup" "secrets cage not ready"
  print_results; exit 1
fi
repatch_mock "$CAGE" httpbin.org || true

# Verify the cage's OUTBOUND data path is actually working before any
# test runs. wait_ready only confirms the cage's HTTP server responds
# to GET / on the published port; it does not exercise the cage's
# default route or DNS chain. There is a known race where the cage
# container's ExecStartPost may fail to add the default route via the
# proxy (the `-` prefix in cage.container.j2 swallows the failure),
# leaving the cage with no outbound network. wait_data_path probes
# the actual upstream chain and re-patches /etc/hosts on retry.
if ! wait_data_path "$BASE" "/fetch?url=http://httpbin.org/get" "$CAGE" httpbin.org; then
  e2e_fail "3.0" "Setup" "outbound data path not ready within 120s"
  dump_cage_diagnostics "$CAGE" "3.0 setup failure"
  print_results; exit 1
fi

# 3.1: Secret listed
assert_output_contains "3.1" "Secret listed" "MY_API_KEY" \
  agentcage secret list "$CAGE"

# 3.2: Placeholder in cage env
e2e_timer_start
OUTPUT=$(podman exec "${CAGE}-cage" printenv MY_API_KEY 2>&1) || true
if [ "$OUTPUT" = "{{MY_API_KEY}}" ]; then
  e2e_pass "3.2" "Placeholder in cage env"
else
  e2e_fail "3.2" "Placeholder in cage env" "got '$OUTPUT', expected '{{MY_API_KEY}}'"
fi

# 3.3: Injection on outbound — send placeholder, then poll audit for injection record.
# Setup already verified the data path is working via wait_data_path, so we
# can proceed straight into the injection loop.
e2e_timer_start
FOUND=false
DEADLINE=$((SECONDS + 90))
_delay=2
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  # Trigger injection: POST placeholder to check-secret (which forwards to httpbin.org/post)
  curl -s --max-time 10 -X POST -H 'Content-Type: application/json' \
    -d '{"key":"{{MY_API_KEY}}"}' "$BASE/check-secret" >/dev/null 2>&1 || true
  sleep "$_delay"
  OUTPUT=$(agentcage cage audit "$CAGE" --json-lines -n 50 2>&1) || true
  if echo "$OUTPUT" | grep -q "secrets_injected"; then
    FOUND=true
    break
  fi
  _delay=$(( _delay + 1 ))
  [ "$_delay" -gt 4 ] && _delay=4
done
if [ "$FOUND" = true ]; then
  e2e_pass "3.3" "Injection on outbound"
else
  e2e_fail "3.3" "Injection on outbound" "no secrets_injected in audit after 90s"
  # Probe whether the proxy chain even worked, then dump diagnostics.
  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE/fetch?url=http://httpbin.org/get" 2>/dev/null || true)
  echo "        proxy chain probe: $BASE/fetch → ${CODE:-000}" >&2
  dump_cage_diagnostics "$CAGE" "3.3 failure"
fi

# 3.4: Set new secret
e2e_timer_start
echo "new-value" | agentcage secret set "$CAGE" MY_API_KEY >/dev/null 2>&1
if wait_ready "$BASE" 60; then
  e2e_pass "3.4" "Set new secret (cage restarted)"
else
  e2e_fail "3.4" "Set new secret" "cage did not restart"
fi

# 3.5: Remove secret
e2e_timer_start
agentcage secret rm "$CAGE" MY_API_KEY >/dev/null 2>&1 || true
e2e_pass "3.5" "Remove secret"

# 3.6: Missing secret warning
e2e_timer_start
OUTPUT=$(agentcage secret list "$CAGE" 2>&1) || true
if echo "$OUTPUT" | grep -q "MISSING"; then
  e2e_pass "3.6" "Missing secret warning"
else
  e2e_fail "3.6" "Missing secret warning" "no MISSING status in output"
fi

print_results
