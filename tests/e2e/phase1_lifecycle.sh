#!/usr/bin/env bash
# Phase 1: Container Mode — Lifecycle & Core Security
source "$(dirname "$0")/lib.sh"
preflight_check "$AGENTCAGE" podman curl
phase_header 1 "Container Mode — Lifecycle & Core Security"

CAGE="basic"
BASE="http://localhost:3000"
CONFIGS="$(dirname "$0")/configs"

# Clean any stale cage
destroy_cage "$CAGE"
register_cage "$CAGE"

# Setup
echo "Creating cage..."
create_cage "$CONFIGS/basic.yaml" >/dev/null

# 1.0b: destroy + create under the same name yields a new CA. The cage
# unit only starts once the egress has published its cert, so the
# fingerprint is readable as soon as `cage create` returns. Done here,
# before any traffic, so the later tests (and phases 2/4, which reuse
# this cage) run against the recreated cage exactly as they would have.
e2e_timer_start
CA_FIRST=$(cage_ca_fingerprint "$CAGE")
"$AGENTCAGE" cage destroy "$CAGE" -y >/dev/null 2>&1 || true
create_cage "$CONFIGS/basic.yaml" >/dev/null
CA_SECOND=$(cage_ca_fingerprint "$CAGE")
if [ -n "$CA_FIRST" ] && [ -n "$CA_SECOND" ] && [ "$CA_FIRST" != "$CA_SECOND" ]; then
  e2e_pass "1.0b" "Recreated cage gets a new CA"
else
  e2e_fail "1.0b" "Recreated cage gets a new CA" \
    "first=${CA_FIRST:-<none>} second=${CA_SECOND:-<none>}"
fi

# 1.0c: `cage create` records the fingerprint of what it built, so the
# first `cage update` on an untouched cage is a no-op (issue #417). It
# used to find no fingerprint and rebuild; this call was then the
# workaround that took that rebuild before the mock was patched in, so
# 1.9-1.11 below still see a cage whose inputs are recorded either way.
assert_output_contains "1.0c" "First update after create is a no-op" \
  "already up to date" \
  "$AGENTCAGE" cage update "$CAGE" --no-pull

echo "Starting mock server..."
start_mock "$CAGE" httpbin.org example.com

echo "Waiting for readiness..."
if ! wait_ready "$BASE" 120; then
  e2e_fail "1.0" "Agent readiness" "did not become ready within 120s"
  print_results; exit 1
fi

# Re-patch after proxy is fully up (ExecStartPost may have restarted it)
repatch_mock "$CAGE" httpbin.org example.com || true

# Verify the full data path (DNS → iptables → egress proxy → /etc/hosts → mock)
# is actually working before running assertions. wait_ready only checks GET /
# on the cage; it can pass while the upstream chain is still broken.
if ! wait_data_path "$BASE" "/fetch?url=http://httpbin.org/get" "$CAGE" httpbin.org example.com; then
  e2e_fail "1.0" "Data path readiness" "proxy → mock chain not ready within 120s"
  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE/fetch?url=http://httpbin.org/get" 2>/dev/null || true)
  echo "        proxy chain probe: $BASE/fetch → ${CODE:-000}" >&2
  dump_cage_diagnostics "$CAGE" "1.0 readiness failure"
  print_results; exit 1
fi

# Tests
assert_http 200 "$BASE/" "1.1" "Health check"
assert_http 200 "$BASE/fetch?url=http://httpbin.org/get" "1.2" "Allowed domain (httpbin.org)"
assert_http_any "403|502" "$BASE/fetch?url=http://evil.com/exfil" "1.3" "Blocked domain (evil.com)"

# Secret detection — use a pattern that matches the anthropic_key regex.
# The default action on HTTP egress is flag: the request is forwarded
# and the detection lands in the audit log as a flagged decision.
assert_http 200 "$BASE/check-secret" "1.4" "Secret leak flagged (default)" \
  -X POST -H "Content-Type: application/json" \
  -d '{"key":"sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'

# Poll until the flagged decision shows up in the audit log (up to 10s)
_flag_deadline=$((SECONDS + 10))
_flag_found=""
while [ "$SECONDS" -lt "$_flag_deadline" ]; do
  if "$AGENTCAGE" cage audit "$CAGE" -d flagged --json-lines -n 20 2>/dev/null \
      | grep -q anthropic_key; then
    _flag_found=1
    break
  fi
  sleep 1
done
if [ -n "$_flag_found" ]; then
  e2e_pass "1.4b" "Secret detection recorded as flagged in audit log"
else
  e2e_fail "1.4b" "Secret detection recorded as flagged in audit log" \
    "no flagged anthropic_key entry in audit log"
fi

assert_http 200 "$BASE/check-secret" "1.5" "Clean POST allowed" \
  -X POST -H "Content-Type: application/json" \
  -d '{"data":"harmless"}'

# Verify / show / list
assert_output_contains "1.6" "Verify command" "passed" \
  "$AGENTCAGE" cage verify "$CAGE"

assert_output_contains "1.7" "Show command" "running" \
  "$AGENTCAGE" cage show "$CAGE"

assert_output_contains "1.8" "List command" "$CAGE" \
  "$AGENTCAGE" cage list

# `cage update` with nothing changed must not restart anything. The
# container IDs change on any restart (quadlets recreate the container),
# so they are the witness.
_container_ids() {
  podman inspect --format '{{.Id}}' "$CAGE-cage" "$CAGE-egress" 2>/dev/null | tr '\n' ' '
}

# 1.9: --no-pull never asks the registry and leaves the cage alone.
e2e_timer_start
IDS_BEFORE=$(_container_ids)
UPDATE_OUT=$("$AGENTCAGE" cage update "$CAGE" --no-pull 2>&1) || true
if grep -q "already up to date" <<<"$UPDATE_OUT" \
    && ! grep -q "Checking base images" <<<"$UPDATE_OUT" \
    && [ "$(_container_ids)" = "$IDS_BEFORE" ]; then
  e2e_pass "1.9" "cage update --no-pull: no registry check, no restart"
else
  e2e_fail "1.9" "cage update --no-pull: no registry check, no restart" "$UPDATE_OUT"
fi

# 1.10: an unreachable registry is a warning, and the cage keeps running.
e2e_timer_start
IDS_BEFORE=$(_container_ids)
UPDATE_OUT=$(HTTPS_PROXY=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 \
  "$AGENTCAGE" cage update "$CAGE" 2>&1) || true
if grep -q "warning: could not check base images" <<<"$UPDATE_OUT" \
    && grep -q "already up to date" <<<"$UPDATE_OUT" \
    && [ "$(_container_ids)" = "$IDS_BEFORE" ]; then
  e2e_pass "1.10" "cage update offline: warns, no restart"
else
  e2e_fail "1.10" "cage update offline: warns, no restart" "$UPDATE_OUT"
fi

# 1.11: the default update checks the registry. The bases were just
# pulled by `cage create`, so normally nothing moved and nothing
# restarts; if a base really did move upstream in between, the update
# must say so and the restart is the correct outcome.
e2e_timer_start
IDS_BEFORE=$(_container_ids)
UPDATE_OUT=$("$AGENTCAGE" cage update "$CAGE" 2>&1) || true
if grep -q "has a newer image" <<<"$UPDATE_OUT"; then
  if grep -qE "Updated cage|not restarting|up to date" <<<"$UPDATE_OUT"; then
    e2e_pass "1.11" "cage update: base moved upstream, rebuilt"
    repatch_mock "$CAGE" httpbin.org example.com || true
  else
    e2e_fail "1.11" "cage update: base moved upstream, rebuilt" "$UPDATE_OUT"
  fi
elif grep -q "Checking base images" <<<"$UPDATE_OUT" \
    && grep -q "already up to date" <<<"$UPDATE_OUT" \
    && [ "$(_container_ids)" = "$IDS_BEFORE" ]; then
  e2e_pass "1.11" "cage update: registry checked, bases current, no restart"
else
  e2e_fail "1.11" "cage update: registry checked, bases current, no restart" "$UPDATE_OUT"
fi

# Keep cage running for phase 2 / 4 if run together
if [ "${E2E_KEEP_BASIC:-}" = "1" ]; then
  # Remove from cleanup list
  E2E_CAGES_TO_CLEANUP=()
fi

print_results
