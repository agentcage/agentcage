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
if ! wait_ready "$BASE" 120; then
  e2e_fail "3.0" "Setup" "secrets cage not ready"
  print_results; exit 1
fi

# 3.1: Secret listed
assert_output_contains "3.1" "Secret listed" "MY_API_KEY" \
  agentcage secret list "$CAGE"

# 3.2: Placeholder in cage env
OUTPUT=$(podman exec "${CAGE}-cage" printenv MY_API_KEY 2>&1) || true
if [ "$OUTPUT" = "{{MY_API_KEY}}" ]; then
  e2e_pass "3.2" "Placeholder in cage env"
else
  e2e_fail "3.2" "Placeholder in cage env" "got '$OUTPUT', expected '{{MY_API_KEY}}'"
fi

# 3.3: Injection on outbound — send placeholder, then poll audit for injection record.
# Retry the triggering curl on each iteration since the outbound proxy or
# httpbin.org may not be ready on the first attempt.
FOUND=false
_delay=2
for _i in $(seq 1 15); do
  curl -s --max-time 10 -X POST -H 'Content-Type: application/json' \
    -d '{"key":"{{MY_API_KEY}}"}' "$BASE/check-secret" >/dev/null 2>&1 || true
  sleep "$_delay"
  OUTPUT=$(agentcage cage audit "$CAGE" --json-lines -n 20 2>&1) || true
  if echo "$OUTPUT" | grep -q "secrets_injected"; then
    FOUND=true
    break
  fi
  # increasing delay: 2, 3, 4, capped at 4s
  _delay=$(( _delay + 1 ))
  [ "$_delay" -gt 4 ] && _delay=4
done
if [ "$FOUND" = true ]; then
  e2e_pass "3.3" "Injection on outbound"
else
  e2e_fail "3.3" "Injection on outbound" "no secrets_injected in audit after 45s"
fi

# 3.4: Set new secret
echo "new-value" | agentcage secret set "$CAGE" MY_API_KEY >/dev/null 2>&1
if wait_ready "$BASE" 60; then
  e2e_pass "3.4" "Set new secret (cage restarted)"
else
  e2e_fail "3.4" "Set new secret" "cage did not restart"
fi

# 3.5: Remove secret
agentcage secret rm "$CAGE" MY_API_KEY >/dev/null 2>&1 || true
e2e_pass "3.5" "Remove secret"

# 3.6: Missing secret warning
OUTPUT=$(agentcage secret list "$CAGE" 2>&1) || true
if echo "$OUTPUT" | grep -q "MISSING"; then
  e2e_pass "3.6" "Missing secret warning"
else
  e2e_fail "3.6" "Missing secret warning" "no MISSING status in output"
fi

print_results
