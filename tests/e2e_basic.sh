#!/usr/bin/env bash
# E2E test for the basic example agent.
# Container-mode only (no KVM / sudo required).
#
# Usage:  bash tests/e2e_basic.sh

set -euo pipefail

CAGE_NAME="basic"
BASE_URL="http://localhost:3000"
PASS=0
FAIL=0

# ── helpers ──────────────────────────────────────────────────────────

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  echo
  echo "==> Destroying cage..."
  agentcage cage destroy "$CAGE_NAME" 2>/dev/null || true
}
trap cleanup EXIT

# ── preflight ────────────────────────────────────────────────────────

echo "==> Preflight checks"
command -v agentcage >/dev/null 2>&1 || { echo "ERROR: agentcage not found in PATH"; exit 1; }
command -v curl      >/dev/null 2>&1 || { echo "ERROR: curl not found in PATH"; exit 1; }

# Destroy any stale cage from a previous run
agentcage cage destroy "$CAGE_NAME" 2>/dev/null || true

# ── create cage ──────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Creating cage from $REPO_ROOT/examples/basic/cage.yaml"
AGENT_DIR="$REPO_ROOT/examples/basic/agent" \
  agentcage cage create -c "$REPO_ROOT/examples/basic/cage.yaml"

# ── wait for readiness ───────────────────────────────────────────────

echo "==> Waiting for agent to become ready (up to 120s)..."
DEADLINE=$((SECONDS + 120))
READY=false
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  if curl -sf "$BASE_URL/" >/dev/null 2>&1; then
    READY=true
    break
  fi
  sleep 2
done

if [ "$READY" = true ]; then
  pass "Agent ready"
else
  fail "Agent did not become ready within 120s"
  echo "RESULTS: $PASS passed, $FAIL failed"
  exit 1
fi

# ── tests ────────────────────────────────────────────────────────────

echo "==> Running endpoint tests"

# 1. GET / → 200
echo "[1] GET /"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/")
if [ "$HTTP_CODE" = "200" ]; then
  pass "GET / returned $HTTP_CODE"
else
  fail "GET / returned $HTTP_CODE (expected 200)"
fi

# 2. GET /fetch?url=https://httpbin.org/get → 200 (allowed domain)
echo "[2] GET /fetch?url=https://httpbin.org/get"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/fetch?url=https://httpbin.org/get")
if [ "$HTTP_CODE" = "200" ]; then
  pass "Allowed domain returned $HTTP_CODE"
else
  fail "Allowed domain returned $HTTP_CODE (expected 200)"
fi

# 3. GET /fetch?url=https://evil.com/exfil → 403 or 502 (blocked domain)
echo "[3] GET /fetch?url=https://evil.com/exfil"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/fetch?url=https://evil.com/exfil")
if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "502" ]; then
  pass "Blocked domain returned $HTTP_CODE"
else
  fail "Blocked domain returned $HTTP_CODE (expected 403 or 502)"
fi

# 4. POST /check-secret with secret → 403 (secret detected)
echo "[4] POST /check-secret (with secret)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d '{"key":"sk-ant-FAKE01-abcdefghijklmnopqrstuvwxyz"}' \
  "$BASE_URL/check-secret")
if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "502" ]; then
  pass "Secret detection returned $HTTP_CODE"
else
  fail "Secret detection returned $HTTP_CODE (expected 403)"
fi

# 5. POST /check-secret with clean data → 200
echo "[5] POST /check-secret (clean)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d '{"data":"harmless"}' \
  "$BASE_URL/check-secret")
if [ "$HTTP_CODE" = "200" ]; then
  pass "Clean POST returned $HTTP_CODE"
else
  fail "Clean POST returned $HTTP_CODE (expected 200)"
fi

# ── results ──────────────────────────────────────────────────────────

echo
echo "RESULTS: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
