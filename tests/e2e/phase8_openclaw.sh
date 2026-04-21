#!/usr/bin/env bash
# Phase 8: OpenClaw scaffold regression canary.
#
# Catches breakage in ghcr.io/openclaw/openclaw:latest. The openclaw image
# moves independently of agentcage; every recent minor has shipped at least
# one change that silently broke our scaffold (SSRF/HTTP_PROXY, tini/SIGUSR1,
# controlUi origins, matrix extension workspace deps, etc.). This phase runs
# the real `agentcage init --scaffold openclaw` → `cage create` flow and
# asserts each known regression class.
#
# Secret-injection verification uses real external echo services
# (httpbin.org, postman-echo.com) via the cage's mitm proxy — no mock server.
source "$(dirname "$0")/lib.sh"
preflight_check agentcage podman curl jq
phase_header 8 "OpenClaw Scaffold Regression Canary"

CAGE="e2e-openclaw"
PORT=$((E2E_PORT_BASE + 100))
BASE="http://127.0.0.1:$PORT"
SENTINEL="e2e-sk-REAL-DEADBEEF"
GATEWAY_PW="e2e-pw"
BASE_IMAGE="ghcr.io/openclaw/openclaw:latest"

# ── pre-run image identity ──────────────────────────────────────────
# Log the base image digest up front so failure triage knows which
# openclaw build ran. If this fails, the image wasn't pulled at all
# and cage create is about to fail loudly.
if podman image exists "$BASE_IMAGE" 2>/dev/null; then
  echo "openclaw base image:"
  podman image inspect "$BASE_IMAGE" \
    --format '  {{.Id}}  {{index .RepoTags 0}}  created={{.Created}}' \
    2>/dev/null || true
else
  echo "openclaw base image not present locally; cage create will pull it"
fi

# Clean any stale cage
destroy_cage_with_volumes "$CAGE" "${CAGE}-workspace" "${CAGE}-state"

# Cleanup trap — fires on normal exit AND on abort (failing assertion,
# CTRL-C). `destroy_cage` in the lib.sh trap doesn't clean named volumes,
# so we install our own trap that does.
trap 'destroy_cage_with_volumes '"$CAGE"' '"${CAGE}-workspace"' '"${CAGE}-state" EXIT

# ── setup: render real scaffold, patch for CI, create cage ──────────
TMPDIR=$(mktemp -d "/tmp/e2e-openclaw-XXXXXX")
cd "$TMPDIR"

echo "Rendering openclaw scaffold..."
# `agentcage init --scaffold openclaw` exercises the real scaffold
# templating pipeline — the same code path users hit. Past regressions
# have landed in the template, so we render it fresh here rather than
# hand-crafting a YAML.
if ! agentcage init "$CAGE" --scaffold openclaw --port "$PORT" --output cage.yaml --force >/dev/null 2>&1; then
  e2e_fail "8.0" "scaffold init" "agentcage init --scaffold openclaw failed"
  print_results; exit 1
fi

# Patch the rendered cage.yaml for CI resource limits AND for the
# echo-service secret-injection shape. Only test-specific tweaks:
#   - memory 4g / cpus 2.0: GHA ubuntu-24.04 only has 7 GiB total RAM
#   - timeout_start_sec 300: openclaw gateway boot + ghcr pull headroom
#   - allow httpbin.org + postman-echo.com: needed by 8.8b/8.8c
#   - inject_to: httpbin.org (not anthropic.com) so substitution can be
#     observed via a real echo service
sed -i \
  -e 's|^  memory: .*|  memory: "4g"|' \
  -e 's|^  cpus: .*|  cpus: "2.0"|' \
  -e 's|^  timeout_start_sec: .*|  timeout_start_sec: 300|' \
  -e 's|      - anthropic.com$|      - httpbin.org|' \
  cage.yaml

# Append echo-service allowlist entries. The default scaffold allowlist
# section ends with an `# Add domains your agents need access to:` comment
# block; we insert before the final empty/hash block.
# Simplest approach: append to the allow list directly by inserting after
# the last existing allow entry.
python3 - <<'PYEOF'
import re
from pathlib import Path

path = Path("cage.yaml")
text = path.read_text()

# Inject httpbin.org and postman-echo.com into domains.allow by
# appending to the existing allow block. Find the "domains:\n  allow:"
# header and splice after the first allow entry.
m = re.search(r"(domains:\s*\n\s*allow:\s*\n)", text)
if not m:
    raise SystemExit("could not find domains.allow in cage.yaml")

insert_at = m.end()
extra = "    - httpbin.org\n    - postman-echo.com\n"
text = text[:insert_at] + extra + text[insert_at:]
path.write_text(text)
PYEOF

echo "Creating cage (scaffold build may take several minutes cold)..."
# Secrets are passed via -s KEY=VALUE so cage create can install them
# atomically alongside the cage; `agentcage secret set` requires the
# cage to exist, which would be a chicken-and-egg problem here.
e2e_timer_start
if ! agentcage cage create -c cage.yaml \
     -s "OPENCLAW_GATEWAY_PASSWORD=$GATEWAY_PW" \
     -s "ANTHROPIC_API_KEY=$SENTINEL" >/tmp/phase8-create.log 2>&1; then
  e2e_fail "8.0" "cage create" "agentcage cage create failed (see /tmp/phase8-create.log)"
  dump_cage_diagnostics "$CAGE" "8.0 create failure"
  print_results; exit 1
fi

echo "Waiting for gateway readiness (budget 300s)..."
e2e_timer_start
if ! wait_ready "$BASE" 300; then
  e2e_fail "8.0" "gateway readiness" "did not become ready within 300s"
  dump_cage_diagnostics "$CAGE" "8.0 readiness failure"
  print_results; exit 1
fi

# ── Assertions ──────────────────────────────────────────────────────

# 8.1: gateway serves the OpenClaw Control UI unauthenticated.
# Past assumption was 401/403; openclaw actually returns 200 with the
# login HTML on GET / (authentication is per-API-endpoint, not page-level).
# The signal we care about: something identifiable as openclaw is serving
# on this port — not a stray reverse-proxy error page.
e2e_timer_start
body=$(curl -sS --max-time 10 "$BASE/" 2>&1 || true)
if echo "$body" | grep -q "OpenClaw Control"; then
  e2e_pass "8.1" "gateway serves OpenClaw Control UI"
else
  e2e_fail "8.1" "gateway serves OpenClaw Control UI" \
    "expected 'OpenClaw Control' in response; got: $(echo "$body" | head -3)"
fi

# 8.2: openclaw health OK via exec alias. Proves exec_aliases wiring
# + openclaw internal health. If tini weren't PID 1, the SIGUSR1 restart
# would have killed the container before 8.2 runs; reaching here at all
# is a soft witness for tini working.
# openclaw health's output is "Agents: main (default)\nHeartbeat..."
# rather than "ok"; grep for "Agents:" as the reliable indicator.
assert_output_contains "8.2" "openclaw health via exec alias" "Agents:" \
  agentcage cage exec "$CAGE" -- openclaw health

# 8.3: tini is PID 1
e2e_timer_start
pid1_comm=$(podman exec "${CAGE}-cage" cat /proc/1/comm 2>/dev/null | tr -d '\n\r ')
if [ "$pid1_comm" = "tini" ]; then
  e2e_pass "8.3" "tini is PID 1"
else
  e2e_fail "8.3" "tini is PID 1" "expected 'tini', got '$pid1_comm'"
fi

# 8.4: self-restart survives SIGUSR1 (PID-delta witness).
# openclaw forks a supervisor ("openclaw", PID N) and a gateway worker
# ("openclaw-gateway", child of supervisor). The SIGUSR1 handler lives
# in the gateway; signalling the supervisor alone is a no-op. Signalling
# the gateway makes it exit, which also ends the `node openclaw.mjs
# gateway` command, which drops out of the entrypoint.sh while-true loop
# and gets respawned — both PIDs change. Watching the supervisor PID is
# the stronger witness because it proves the container (and tini) stayed
# alive across the restart.
e2e_timer_start
# `pgrep` exits 1 on no-match — wrap in `|| true` so `set -e` doesn't
# kill the phase before we can report 8.4 as a failure.
OLD_SUP=$(podman exec "${CAGE}-cage" pgrep -f '^openclaw$' 2>/dev/null | head -1 || true)
if [ -z "$OLD_SUP" ]; then
  e2e_fail "8.4" "self-restart SIGUSR1" "could not find openclaw supervisor before signal"
else
  podman exec "${CAGE}-cage" pkill -USR1 -f openclaw-gateway 2>/dev/null || true
  NEW_SUP=""
  for _ in $(seq 1 30); do
    sleep 1
    NEW_SUP=$(podman exec "${CAGE}-cage" pgrep -f '^openclaw$' 2>/dev/null | head -1 || true)
    if [ -n "$NEW_SUP" ] && [ "$NEW_SUP" != "$OLD_SUP" ]; then
      break
    fi
  done
  if [ -z "$NEW_SUP" ]; then
    e2e_fail "8.4" "self-restart SIGUSR1" "no openclaw supervisor after signal (container died?)"
  elif [ "$NEW_SUP" = "$OLD_SUP" ]; then
    e2e_fail "8.4" "self-restart SIGUSR1" "supervisor PID unchanged after SIGUSR1 to gateway (restart did not happen)"
  elif ! wait_ready "$BASE/" 60; then
    e2e_fail "8.4" "self-restart SIGUSR1" "gateway did not recover after restart"
  else
    e2e_pass "8.4" "self-restart SIGUSR1 (supervisor PID $OLD_SUP → $NEW_SUP)"
  fi
fi

# 8.5: openclaw.json has SSRF opt-out (guards #71)
e2e_timer_start
if podman exec "${CAGE}-cage" cat /home/node/.openclaw/openclaw.json 2>/dev/null \
   | jq -e '.browser.ssrfPolicy.dangerouslyAllowPrivateNetwork == true' >/dev/null 2>&1; then
  e2e_pass "8.5" "openclaw.json SSRF opt-out (#71)"
else
  e2e_fail "8.5" "openclaw.json SSRF opt-out (#71)" \
    "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork is not true"
fi

# 8.6: controlUi.allowedOrigins includes gateway URL (guards df9fc30)
e2e_timer_start
allowed=$(podman exec "${CAGE}-cage" cat /home/node/.openclaw/openclaw.json 2>/dev/null \
          | jq -r '.gateway.controlUi.allowedOrigins // [] | join(" ")' 2>/dev/null)
if echo "$allowed" | grep -q "http://127.0.0.1:$PORT" \
   && echo "$allowed" | grep -q "http://localhost:$PORT"; then
  e2e_pass "8.6" "controlUi.allowedOrigins includes gateway URL"
else
  e2e_fail "8.6" "controlUi.allowedOrigins includes gateway URL" \
    "missing one of http://127.0.0.1:$PORT or http://localhost:$PORT (got: $allowed)"
fi

# 8.7: matrix extension workspace workaround present (guards fda1ca6)
e2e_timer_start
if podman exec "${CAGE}-cage" sh -c 'test -L /app/node_modules/openclaw && test -s /app/node_modules/openclaw/package.json' 2>/dev/null; then
  e2e_pass "8.7" "matrix extension symlink + resolvable package.json"
else
  e2e_fail "8.7" "matrix extension symlink + resolvable package.json" \
    "/app/node_modules/openclaw symlink missing or target package.json unreadable"
fi

# 8.8a: cage env has literal placeholder (not the real sentinel)
e2e_timer_start
if podman exec "${CAGE}-cage" env 2>/dev/null | grep -q 'ANTHROPIC_API_KEY={{ANTHROPIC_API_KEY}}'; then
  e2e_pass "8.8a" "cage env has literal placeholder"
else
  actual=$(podman exec "${CAGE}-cage" env 2>/dev/null | grep '^ANTHROPIC_API_KEY=' || echo 'not set')
  e2e_fail "8.8a" "cage env has literal placeholder" \
    "expected ANTHROPIC_API_KEY={{ANTHROPIC_API_KEY}}, got: $actual"
fi

# 8.8b: proxy records an injection attempt on the injected domain.
# Follows phase 3's pattern: we assert the PROXY LOGS `secrets_injected`
# for the flow, not that the upstream service actually echoed a modified
# value. Public echo services (httpbin.org, postman-echo.com) cannot be
# a reliable on-wire witness because some CDNs strip/mask Authorization
# at the edge. The audit-log signal is what catches the regression class
# we care about: "proxy stopped attempting injection on configured
# domains."
e2e_timer_start
# Trigger a fresh flow to httpbin.org with the placeholder.
agentcage cage exec "$CAGE" -- sh -c \
  'curl --retry 3 --retry-delay 5 -sS -o /dev/null -x "$HTTPS_PROXY" \
    --max-time 15 \
    -H "Authorization: Bearer {{ANTHROPIC_API_KEY}}" \
    https://httpbin.org/headers' >/dev/null 2>&1 || true
# The audit log lags the wire by ~1s; poll with a modest deadline.
FOUND=false
for _ in $(seq 1 10); do
  sleep 1
  if agentcage cage audit "$CAGE" --json-lines -n 30 2>/dev/null \
     | grep httpbin.org | grep -q '"secrets_injected":\s*\[\s*"ANTHROPIC_API_KEY"\s*\]'; then
    FOUND=true
    break
  fi
done
if [ "$FOUND" = true ]; then
  e2e_pass "8.8b" "proxy logs secrets_injected on injected domain"
else
  e2e_fail "8.8b" "proxy logs secrets_injected on injected domain" \
    "no 'secrets_injected: [ANTHROPIC_API_KEY]' entry for httpbin.org in audit log"
fi

# 8.8c: injection is domain-scoped — postman-echo.com is allowlisted
# but NOT in inject_to. The proxy must NOT log secrets_injected for
# that flow; the placeholder passes through to upstream verbatim.
e2e_timer_start
agentcage cage exec "$CAGE" -- sh -c \
  'curl --retry 3 --retry-delay 5 -sS -o /dev/null -x "$HTTPS_PROXY" \
    --max-time 15 \
    -H "Authorization: Bearer {{ANTHROPIC_API_KEY}}" \
    https://postman-echo.com/headers' >/dev/null 2>&1 || true
LEAKED=false
for _ in $(seq 1 10); do
  sleep 1
  if agentcage cage audit "$CAGE" --json-lines -n 30 2>/dev/null \
     | grep postman-echo.com | grep -q '"secrets_injected":\s*\[\s*"ANTHROPIC_API_KEY"\s*\]'; then
    LEAKED=true
    break
  fi
done
if [ "$LEAKED" = false ]; then
  e2e_pass "8.8c" "injection is domain-scoped (no secrets_injected on postman-echo)"
else
  e2e_fail "8.8c" "injection is domain-scoped (no secrets_injected on postman-echo)" \
    "ANTHROPIC_API_KEY injection leaked to postman-echo.com (not in inject_to list)"
fi

# 8.9: domain allowlist blocks unlisted host
e2e_timer_start
code=$(agentcage cage exec "$CAGE" -- sh -c \
  'curl -sx "$HTTPS_PROXY" -o /dev/null -w "%{http_code}" \
    --max-time 10 https://forbidden.example.com' 2>/dev/null || echo "000")
if [ "$code" = "403" ] || [ "$code" = "502" ]; then
  e2e_pass "8.9" "domain allowlist blocks unlisted host (HTTP $code)"
else
  e2e_fail "8.9" "domain allowlist blocks unlisted host" "expected 403/502, got $code"
fi

# 8.10: nested podman smoke (probe-then-skip).
# The cage runs as root inside its userns (so podman inside reports
# `Rootless=false`), but the OUTER podman is rootless on the host.
# GHA ubuntu-24.04 may not allow the full nested stack; skip if
# `podman ps` doesn't work inside, fail hard if it works but `run`
# doesn't (the regression case we're guarding).
e2e_timer_start
if ! agentcage cage exec "$CAGE" -- podman ps >/dev/null 2>&1; then
  e2e_skip "8.10" "nested podman smoke" "nested podman not usable in this environment"
elif agentcage cage exec "$CAGE" -- podman run --rm docker.io/library/busybox echo ok 2>/dev/null | grep -q '^ok$'; then
  e2e_pass "8.10" "nested podman smoke (busybox)"
else
  e2e_fail "8.10" "nested podman smoke (busybox)" \
    "podman run inside cage failed (scaffold uid/subuid/overlay regression?)"
fi

# Trap handles teardown
print_results
