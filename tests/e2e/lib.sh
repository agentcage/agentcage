#!/usr/bin/env bash
# E2E test library — shared helpers for all phase scripts.
# Source this from each phase: source "$(dirname "$0")/lib.sh"

set -euo pipefail

# ── state ────────────────────────────────────────────────────────────
E2E_PASS=0
E2E_FAIL=0
E2E_SKIP=0
E2E_TEST_NUM=0
E2E_PHASE="${E2E_PHASE:-0}"
E2E_CAGES_TO_CLEANUP=()

# Port base — override to avoid conflicts with local services.
E2E_PORT_BASE="${E2E_PORT_BASE:-19080}"

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
export AGENT_DIR="$REPO_ROOT/examples/basic/agent"

# ── output ───────────────────────────────────────────────────────────

_test_id() { printf "%d.%d" "$E2E_PHASE" "$1"; }

e2e_pass() {
  local id="$1" desc="$2"
  E2E_PASS=$((E2E_PASS + 1))
  printf "  \033[32mPASS\033[0m  %s  %s\n" "$id" "$desc"
}

e2e_fail() {
  local id="$1" desc="$2" detail="${3:-}"
  E2E_FAIL=$((E2E_FAIL + 1))
  printf "  \033[31mFAIL\033[0m  %s  %s\n" "$id" "$desc"
  [ -n "$detail" ] && printf "        %s\n" "$detail"
}

e2e_skip() {
  local id="$1" desc="$2" reason="${3:-}"
  E2E_SKIP=$((E2E_SKIP + 1))
  printf "  \033[33mSKIP\033[0m  %s  %s  (%s)\n" "$id" "$desc" "$reason"
}

phase_header() {
  local num="$1" title="$2"
  E2E_PHASE="$num"
  printf "\n\033[1m═══ Phase %s: %s ═══\033[0m\n\n" "$num" "$title"
}

# ── assertions ───────────────────────────────────────────────────────

# assert_http CODE URL [CURL_ARGS...] — check HTTP status code
assert_http() {
  local expected="$1" url="$2" id="$3" desc="$4"
  shift 4
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" "$@" "$url" 2>/dev/null || echo "000")
  if [ "$code" = "$expected" ]; then
    e2e_pass "$id" "$desc"
  else
    e2e_fail "$id" "$desc" "expected HTTP $expected, got $code"
  fi
}

# assert_http_any "200|201" URL ID DESC [CURL_ARGS...] — accept multiple codes
assert_http_any() {
  local expected="$1" url="$2" id="$3" desc="$4"
  shift 4
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" "$@" "$url" 2>/dev/null || echo "000")
  if echo "$expected" | grep -qw "$code"; then
    e2e_pass "$id" "$desc"
  else
    e2e_fail "$id" "$desc" "expected HTTP $expected, got $code"
  fi
}

# assert_cmd_ok ID DESC CMD... — check command exits 0
assert_cmd_ok() {
  local id="$1" desc="$2"
  shift 2
  if "$@" >/dev/null 2>&1; then
    e2e_pass "$id" "$desc"
  else
    e2e_fail "$id" "$desc" "command failed: $*"
  fi
}

# assert_cmd_fail ID DESC CMD... — check command exits non-zero
assert_cmd_fail() {
  local id="$1" desc="$2"
  shift 2
  if "$@" >/dev/null 2>&1; then
    e2e_fail "$id" "$desc" "command succeeded but should have failed: $*"
  else
    e2e_pass "$id" "$desc"
  fi
}

# assert_output_contains ID DESC PATTERN CMD... — check output contains pattern
assert_output_contains() {
  local id="$1" desc="$2" pattern="$3"
  shift 3
  local output
  output=$("$@" 2>&1) || true
  if echo "$output" | grep -q "$pattern"; then
    e2e_pass "$id" "$desc"
  else
    e2e_fail "$id" "$desc" "output missing '$pattern'"
  fi
}

# ── wait helpers ─────────────────────────────────────────────────────

# wait_ready URL [TIMEOUT_S] — poll until HTTP 200, return 0/1
wait_ready() {
  local url="$1" timeout="${2:-120}"
  local deadline=$((SECONDS + timeout))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if curl -sf "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# wait_http_code URL EXPECTED [TIMEOUT_S] — poll until specific HTTP code
wait_http_code() {
  local url="$1" expected="$2" timeout="${3:-30}"
  local deadline=$((SECONDS + timeout))
  local delay=1
  while [ "$SECONDS" -lt "$deadline" ]; do
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    if [ "$code" = "$expected" ]; then
      return 0
    fi
    sleep "$delay"
    # exponential backoff: 1, 2, 4, … capped at 8s
    delay=$(( delay * 2 ))
    [ "$delay" -gt 8 ] && delay=8
  done
  return 1
}

# ── cage helpers ─────────────────────────────────────────────────────

# Register a cage for cleanup on exit
register_cage() {
  E2E_CAGES_TO_CLEANUP+=("$1")
}

# Destroy a cage silently
destroy_cage() {
  agentcage cage destroy "$1" -y >/dev/null 2>&1 || true
}

# Create a cage from a config template (expands env vars) and register for cleanup.
# Streams output to stderr so callers can redirect with >/dev/null.
create_cage() {
  local config="$1"
  shift
  local tmpconfig
  tmpconfig=$(mktemp /tmp/e2e-config-XXXXXX.yaml)
  envsubst < "$config" > "$tmpconfig"
  local rc=0
  AGENT_DIR="$AGENT_DIR" agentcage cage create -c "$tmpconfig" "$@" 2>&1 || rc=$?
  rm -f "$tmpconfig"
  return $rc
}

# ── cleanup ──────────────────────────────────────────────────────────

_cleanup_cages() {
  for cage in "${E2E_CAGES_TO_CLEANUP[@]+"${E2E_CAGES_TO_CLEANUP[@]}"}"; do
    destroy_cage "$cage"
  done
}
trap _cleanup_cages EXIT

# ── preflight ────────────────────────────────────────────────────────

preflight_check() {
  local cmds=("$@")
  local missing=()
  for cmd in "${cmds[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "ERROR: missing required commands: ${missing[*]}"
    exit 1
  fi
}

# ── results ──────────────────────────────────────────────────────────

print_results() {
  echo
  printf "\033[1m─── Results ───\033[0m\n"
  printf "  Passed: \033[32m%d\033[0m\n" "$E2E_PASS"
  printf "  Failed: \033[31m%d\033[0m\n" "$E2E_FAIL"
  [ "$E2E_SKIP" -gt 0 ] && printf "  Skipped: \033[33m%d\033[0m\n" "$E2E_SKIP"
  echo
  if [ "$E2E_FAIL" -gt 0 ]; then
    printf "\033[31mFAILED\033[0m\n"
    return 1
  else
    printf "\033[32mALL PASSED\033[0m\n"
    return 0
  fi
}
