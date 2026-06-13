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
  --set-secret MY_API_KEY=test-secret-value-12345 \
  --set-secret MY_AUTO_KEY=auto-secret-value-67890 >/dev/null
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

# 3.2b: Entropic placeholder generated for a rule declared without `placeholder:`
# (cage create persists agentcage:secret:MY_AUTO_KEY:<32hex> into the stored
# config and the cage env carries it).
e2e_timer_start
OUTPUT=$(podman exec "${CAGE}-cage" printenv MY_AUTO_KEY 2>&1) || true
if echo "$OUTPUT" | grep -Eq '^agentcage:secret:MY_AUTO_KEY:[0-9a-f]{32}$'; then
  e2e_pass "3.2b" "Entropic placeholder in cage env"
else
  e2e_fail "3.2b" "Entropic placeholder in cage env" "got '$OUTPUT', expected agentcage:secret:MY_AUTO_KEY:<32hex>"
fi

# 3.2c: Derived placeholders.env exists and carries the generated token
# (cage quadlet reads it via EnvironmentFile=; regenerated with
# proxy-config.yaml on every deploy/restart).
e2e_timer_start
DEPLOY_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/agentcage/cages/$CAGE"
if grep -Eq '^MY_AUTO_KEY=agentcage:secret:MY_AUTO_KEY:[0-9a-f]{32}$' \
     "$DEPLOY_DIR/cage-env/placeholders.env" 2>/dev/null; then
  e2e_pass "3.2c" "placeholders.env derived file"
else
  e2e_fail "3.2c" "placeholders.env derived file" \
    "missing or wrong content in $DEPLOY_DIR/cage-env/placeholders.env"
fi

# 3.2d: Egress staged secret value file (tmpfs, mounted at
# /home/acproxy/secrets) holds the real value — the file channel that
# live secret updates will use.
e2e_timer_start
OUTPUT=$(podman exec "${CAGE}-egress" cat /home/acproxy/secrets/MY_API_KEY 2>&1) || true
if [ "$OUTPUT" = "test-secret-value-12345" ]; then
  e2e_pass "3.2d" "Egress staged secret value file"
else
  e2e_fail "3.2d" "Egress staged secret value file" "got '$OUTPUT'"
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

# 3.3b: Placeholder change applies on plain `cage restart` — no `cage
# update` / quadlet regeneration needed. The cage quadlet reads
# placeholders via EnvironmentFile=, which podman re-reads at container
# creation; `cage restart` regenerates the derived file from cage.yaml.
e2e_timer_start
NEW_PH="agentcage:secret:MY_API_KEY:e2e0000000000001e2e0000000000001"
sed -i "s#{{MY_API_KEY}}#$NEW_PH#g" "$DEPLOY_DIR/cage.yaml"
agentcage cage restart "$CAGE" >/dev/null 2>&1
wait_ready "$BASE" 60 >/dev/null || true
OUTPUT=$(podman exec "${CAGE}-cage" printenv MY_API_KEY 2>&1) || true
if [ "$OUTPUT" = "$NEW_PH" ]; then
  e2e_pass "3.3b" "Placeholder change applied by restart (no update)"
else
  e2e_fail "3.3b" "Placeholder change applied by restart (no update)" \
    "got '$OUTPUT', expected '$NEW_PH'"
fi

# 3.4: Set new secret on a running cage — applied LIVE, zero restart.
# The value is staged into the egress's tmpfs file channel and the proxy
# hot-reloads on the next request; neither container is recreated.
e2e_timer_start
CAGE_STARTED=$(podman inspect --format '{{.State.StartedAt}}' "${CAGE}-cage" 2>/dev/null)
EGRESS_STARTED=$(podman inspect --format '{{.State.StartedAt}}' "${CAGE}-egress" 2>/dev/null)
SET_OUTPUT=$(echo "new-value" | agentcage secret set "$CAGE" MY_API_KEY 2>&1) || true
CAGE_STARTED_2=$(podman inspect --format '{{.State.StartedAt}}' "${CAGE}-cage" 2>/dev/null)
EGRESS_STARTED_2=$(podman inspect --format '{{.State.StartedAt}}' "${CAGE}-egress" 2>/dev/null)
if echo "$SET_OUTPUT" | grep -q "without a restart" \
   && [ "$CAGE_STARTED" = "$CAGE_STARTED_2" ] \
   && [ "$EGRESS_STARTED" = "$EGRESS_STARTED_2" ]; then
  e2e_pass "3.4" "Set new secret (applied live, zero restart)"
else
  e2e_fail "3.4" "Set new secret (applied live, zero restart)" \
    "output: $SET_OUTPUT; cage $CAGE_STARTED -> $CAGE_STARTED_2; egress $EGRESS_STARTED -> $EGRESS_STARTED_2"
fi

# 3.4b: The staged value file carries the new value (host-side check via
# podman unshare — the file is owned by the acproxy subuid).
e2e_timer_start
STAGED=$(podman unshare cat "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/agentcage/$CAGE/secrets/MY_API_KEY" 2>&1) || true
if [ "$STAGED" = "new-value" ]; then
  e2e_pass "3.4b" "Staged value file updated live"
else
  e2e_fail "3.4b" "Staged value file updated live" "got '$STAGED'"
fi

# 3.4c: Proxy injects with the NEW value/rules on the next request — a
# fresh secrets_injected audit entry appears after the live apply.
e2e_timer_start
COUNT_BEFORE=$(agentcage cage audit "$CAGE" --json-lines -n 200 2>/dev/null | grep -c "secrets_injected" || true)
FOUND=false
DEADLINE=$((SECONDS + 60))
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  curl -s --max-time 10 -X POST -H 'Content-Type: application/json' \
    -d "{\"key\":\"$NEW_PH\"}" "$BASE/check-secret" >/dev/null 2>&1 || true
  sleep 2
  COUNT_AFTER=$(agentcage cage audit "$CAGE" --json-lines -n 200 2>/dev/null | grep -c "secrets_injected" || true)
  if [ "${COUNT_AFTER:-0}" -gt "${COUNT_BEFORE:-0}" ]; then
    FOUND=true
    break
  fi
done
if [ "$FOUND" = true ]; then
  e2e_pass "3.4c" "Injection live after zero-restart secret set"
else
  e2e_fail "3.4c" "Injection live after zero-restart secret set" \
    "no new secrets_injected entry within 60s (before=$COUNT_BEFORE after=$COUNT_AFTER)"
fi

# 3.4d: Brand-new secret end-to-end with ZERO restart — one command
# declares the rule (entropic placeholder), stores the value, stages it
# live, and converges the quadlets. New exec sessions carry the
# placeholder immediately (exec-time injection); the proxy injects on
# the next request.
e2e_timer_start
CAGE_STARTED_3=$(podman inspect --format '{{.State.StartedAt}}' "${CAGE}-cage" 2>/dev/null)
echo "brand-new-value-777" | agentcage secret set "$CAGE" BRAND_NEW_KEY \
  --declare --inject-to httpbin.org >/dev/null 2>&1 || true
CAGE_STARTED_4=$(podman inspect --format '{{.State.StartedAt}}' "${CAGE}-cage" 2>/dev/null)
NEW_KEY_PH=$(agentcage cage exec "$CAGE" -- printenv BRAND_NEW_KEY 2>/dev/null | tr -d '\r') || true
if [ "$CAGE_STARTED_3" = "$CAGE_STARTED_4" ] \
   && echo "$NEW_KEY_PH" | grep -Eq '^agentcage:secret:BRAND_NEW_KEY:[0-9a-f]{32}$'; then
  e2e_pass "3.4d" "New secret declared+usable live (exec env, no restart)"
else
  e2e_fail "3.4d" "New secret declared+usable live (exec env, no restart)" \
    "placeholder='$NEW_KEY_PH' restart=$([ "$CAGE_STARTED_3" != "$CAGE_STARTED_4" ] && echo yes || echo no)"
fi

# 3.4e: ...and the proxy injects the brand-new secret's value on the wire.
# The rule is strict (header-only): the agent's /check-secret sends the
# "auth" body field as an Authorization bearer header, which is where the
# proxy substitutes the placeholder. Fresh secrets_injected audit entry =
# proof the live-applied rule + value are active.
e2e_timer_start
COUNT_BEFORE=$(agentcage cage audit "$CAGE" --json-lines -n 300 2>/dev/null | grep -c "secrets_injected" || true)
FOUND=false
DEADLINE=$((SECONDS + 60))
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  curl -s --max-time 10 -X POST -H 'Content-Type: application/json' \
    -d "{\"auth\":\"$NEW_KEY_PH\"}" "$BASE/check-secret" >/dev/null 2>&1 || true
  sleep 2
  COUNT_AFTER=$(agentcage cage audit "$CAGE" --json-lines -n 300 2>/dev/null | grep -c "secrets_injected" || true)
  if [ "${COUNT_AFTER:-0}" -gt "${COUNT_BEFORE:-0}" ]; then
    FOUND=true
    break
  fi
done
if [ "$FOUND" = true ]; then
  e2e_pass "3.4e" "New secret injected on the wire without restart"
else
  e2e_fail "3.4e" "New secret injected on the wire without restart" \
    "no new secrets_injected entry within 60s (before=$COUNT_BEFORE after=$COUNT_AFTER)"
fi

# 3.4f: rotate-placeholders mints a fresh entropic token and applies it.
# MY_AUTO_KEY already carries a generated placeholder (3.2b); rotation must
# replace it with a *different* entropic token, visible in the cage env
# (the rotate restarts the running cage so PID 1 picks it up).
e2e_timer_start
OLD_PH=$(agentcage cage exec "$CAGE" -- printenv MY_AUTO_KEY 2>/dev/null | tr -d '\r') || true
agentcage secret rotate-placeholders "$CAGE" MY_AUTO_KEY >/dev/null 2>&1 || true
if wait_ready "$BASE" 60; then
  NEW_PH=$(agentcage cage exec "$CAGE" -- printenv MY_AUTO_KEY 2>/dev/null | tr -d '\r') || true
  if echo "$NEW_PH" | grep -Eq '^agentcage:secret:MY_AUTO_KEY:[0-9a-f]{32}$' \
     && [ "$NEW_PH" != "$OLD_PH" ]; then
    e2e_pass "3.4f" "rotate-placeholders mints+applies a fresh token"
  else
    e2e_fail "3.4f" "rotate-placeholders mints+applies a fresh token" \
      "old='$OLD_PH' new='$NEW_PH'"
  fi
else
  e2e_fail "3.4f" "rotate-placeholders mints+applies a fresh token" \
    "cage did not come back after rotate"
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

# ── Source backend tests ──────────────────────────────────────────

CAGE_SRC="e2e-secrets-src"
SECRET_PORT_SRC="${E2E_PORT_SECRETS_SRC:-19082}"
BASE_SRC="http://localhost:$SECRET_PORT_SRC"

destroy_cage "$CAGE_SRC"
register_cage "$CAGE_SRC"

# 3.7: env: source resolves from host environment
e2e_timer_start
export E2E_SRC_ENV_SECRET="env-secret-value-99"
export E2E_PORT_SECRETS_SRC="$SECRET_PORT_SRC"
if create_cage "$CONFIGS/secrets-source.yaml" >/dev/null 2>&1; then
  e2e_pass "3.7" "env: source cage created"
else
  e2e_fail "3.7" "env: source cage created" "cage create failed"
fi

# 3.8: cmd: source resolves from shell command
e2e_timer_start
OUTPUT=$(agentcage secret list "$CAGE_SRC" 2>&1) || true
if echo "$OUTPUT" | grep -q "SRC_ENV_KEY" && echo "$OUTPUT" | grep -q "SRC_CMD_KEY"; then
  e2e_pass "3.8" "Source secrets listed"
else
  e2e_fail "3.8" "Source secrets listed" "expected SRC_ENV_KEY and SRC_CMD_KEY in output"
fi

# 3.9: Verify env: secret value was resolved correctly
e2e_timer_start
VALUE=$(podman secret inspect --showsecret --format '{{.SecretData}}' "${CAGE_SRC}.SRC_ENV_KEY" 2>&1) || true
if [ "$VALUE" = "env-secret-value-99" ]; then
  e2e_pass "3.9" "env: value resolved correctly"
else
  e2e_fail "3.9" "env: value resolved correctly" "got '$VALUE', expected 'env-secret-value-99'"
fi

# 3.10: Verify cmd: secret value was resolved correctly
e2e_timer_start
VALUE=$(podman secret inspect --showsecret --format '{{.SecretData}}' "${CAGE_SRC}.SRC_CMD_KEY" 2>&1) || true
if [ "$VALUE" = "cmd-secret-value-42" ]; then
  e2e_pass "3.10" "cmd: value resolved correctly"
else
  e2e_fail "3.10" "cmd: value resolved correctly" "got '$VALUE', expected 'cmd-secret-value-42'"
fi

# 3.11: Source validation catches typos at parse time
e2e_timer_start
TMPYAML=$(mktemp /tmp/e2e-bad-source-XXXXXX.yaml)
cat > "$TMPYAML" <<'YAML'
name: e2e-bad-source
container:
  image: "node:22-slim"
  command: ["echo", "hello"]
secret_injection:
  - env: BAD_KEY
    placeholder: "{{BAD_KEY}}"
    source: "typo-backend:foo"
YAML
OUTPUT=$(agentcage cage create -c "$TMPYAML" 2>&1) || true
rm -f "$TMPYAML"
destroy_cage e2e-bad-source 2>/dev/null || true
if echo "$OUTPUT" | grep -qi "unknown secret source scheme"; then
  e2e_pass "3.11" "Invalid source scheme caught at parse time"
else
  e2e_fail "3.11" "Invalid source scheme caught at parse time" "expected validation error, got: $OUTPUT"
fi

# 3.12: systemd-creds backend (only if available)
e2e_timer_start
if command -v systemd-creds >/dev/null 2>&1 && echo probe | systemd-creds encrypt --name _probe - - >/dev/null 2>&1; then
  CAGE_CREDS="e2e-secrets-creds"
  destroy_cage "$CAGE_CREDS" 2>/dev/null || true
  TMPYAML=$(mktemp /tmp/e2e-creds-XXXXXX.yaml)
  cat > "$TMPYAML" <<YAML
name: $CAGE_CREDS
container:
  image: "node:22-slim"
  command: ["echo", "hello"]
secret_injection:
  - env: CREDS_KEY
    placeholder: "{{CREDS_KEY}}"
    inject_to:
      - httpbin.org
    source: "systemd-creds:"
YAML
  agentcage cage create -c "$TMPYAML" -s CREDS_KEY=creds-test-value >/dev/null 2>&1 || true
  register_cage "$CAGE_CREDS"
  # State dir follows XDG_CONFIG_HOME (default: ~/.config/agentcage/cages/NAME)
  DEPLOY_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/agentcage/cages/$CAGE_CREDS"
  if [ -f "$DEPLOY_DIR/creds/CREDS_KEY.cred" ]; then
    e2e_pass "3.12" "systemd-creds: secret encrypted to .cred file"
  else
    e2e_fail "3.12" "systemd-creds: secret encrypted to .cred file" ".cred file not found in $DEPLOY_DIR/creds/"
  fi
  rm -f "$TMPYAML"
  destroy_cage "$CAGE_CREDS" 2>/dev/null || true
else
  e2e_pass "3.12" "systemd-creds: skipped (not available)"
fi

print_results
