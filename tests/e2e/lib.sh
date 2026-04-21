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
E2E_PHASE_START=0
E2E_TEST_START=0
E2E_CAGES_TO_CLEANUP=()

# Port base — override to avoid conflicts with local services.
E2E_PORT_BASE="${E2E_PORT_BASE:-19080}"

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
export AGENT_DIR="$REPO_ROOT/examples/basic/agent"

# ── output ───────────────────────────────────────────────────────────

_test_id() { printf "%d.%d" "$E2E_PHASE" "$1"; }

_fmt_duration() {
  local ms="$1"
  if [ "$ms" -lt 1000 ]; then
    printf "%dms" "$ms"
  elif [ "$ms" -lt 60000 ]; then
    local secs=$((ms / 1000))
    local tenths=$(( (ms % 1000) / 100 ))
    printf "%d.%ds" "$secs" "$tenths"
  else
    local secs=$((ms / 1000))
    printf "%dm%02ds" $((secs / 60)) $((secs % 60))
  fi
}

_test_elapsed_ms() {
  local now
  now=$(date +%s%N)
  echo $(( (now - E2E_TEST_START) / 1000000 ))
}

# Call before each test to start the timer
e2e_timer_start() {
  E2E_TEST_START=$(date +%s%N)
}

e2e_pass() {
  local id="$1" desc="$2"
  local dur
  dur=$(_fmt_duration "$(_test_elapsed_ms)")
  E2E_PASS=$((E2E_PASS + 1))
  printf "  \033[32mPASS\033[0m  %-5s %-40s \033[2m%s\033[0m\n" "$id" "$desc" "$dur"
}

e2e_fail() {
  local id="$1" desc="$2" detail="${3:-}"
  local dur
  dur=$(_fmt_duration "$(_test_elapsed_ms)")
  E2E_FAIL=$((E2E_FAIL + 1))
  printf "  \033[31mFAIL\033[0m  %-5s %-40s \033[2m%s\033[0m\n" "$id" "$desc" "$dur"
  [ -n "$detail" ] && printf "        %s\n" "$detail"
}

e2e_skip() {
  local id="$1" desc="$2" reason="${3:-}"
  E2E_SKIP=$((E2E_SKIP + 1))
  printf "  \033[33mSKIP\033[0m  %-5s %s  (%s)\n" "$id" "$desc" "$reason"
}

phase_header() {
  local num="$1" title="$2"
  E2E_PHASE="$num"
  E2E_PHASE_START=$(date +%s%N)
  printf "\n\033[1m═══ Phase %s: %s ═══\033[0m\n\n" "$num" "$title"
}

# ── assertions ───────────────────────────────────────────────────────

# assert_http CODE URL [CURL_ARGS...] — check HTTP status code
assert_http() {
  e2e_timer_start
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
  e2e_timer_start
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
  e2e_timer_start
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
  e2e_timer_start
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
  e2e_timer_start
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
  local delay=1
  while [ "$SECONDS" -lt "$deadline" ]; do
    if curl -sf --max-time 5 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$delay"
    # linear backoff: 1, 2, 3, capped at 3s (local services, not rate-limited)
    delay=$(( delay + 1 ))
    [ "$delay" -gt 3 ] && delay=3
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
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || true)
    [ -z "$code" ] && code="000"
    if [ "$code" = "$expected" ]; then
      return 0
    fi
    sleep "$delay"
    # linear backoff: 1, 2, 3, 4, capped at 4s
    delay=$(( delay + 1 ))
    [ "$delay" -gt 4 ] && delay=4
  done
  return 1
}

# dump_cage_diagnostics CAGE [TAG]
#   Dump systemd unit state, podman container state, and proxy logs for a
#   cage. Used on test failure to understand what went wrong on the CI
#   runner where we don't have an interactive shell.
dump_cage_diagnostics() {
  local cage="$1" tag="${2:-diagnostics}"
  echo "        ── $tag for cage '$cage' ──" >&2
  echo "        [systemd units]" >&2
  for svc in cage proxy dns; do
    local active sub
    active=$(systemctl --user is-active "${cage}-${svc}.service" 2>&1 || true)
    sub=$(systemctl --user show -p SubState --value "${cage}-${svc}.service" 2>&1 || true)
    local nrestarts
    nrestarts=$(systemctl --user show -p NRestarts --value "${cage}-${svc}.service" 2>&1 || true)
    echo "          ${cage}-${svc}: active=${active} sub=${sub} nrestarts=${nrestarts}" >&2
  done
  echo "        [podman containers]" >&2
  podman ps -a --filter "name=${cage}-" --format "          {{.Names}} {{.Status}} {{.Ports}}" >&2 || true
  echo "        [proxy container logs (last 25 lines)]" >&2
  podman logs --tail 25 "${cage}-proxy" 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [proxy systemd journal (last 25 lines)]" >&2
  journalctl --user -u "${cage}-proxy.service" -n 25 --no-pager 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [proxy /etc/hosts]" >&2
  podman exec "${cage}-proxy" cat /etc/hosts 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [proxy resolved httpbin.org]" >&2
  podman exec "${cage}-proxy" getent hosts httpbin.org 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [proxy network interfaces]" >&2
  podman exec "${cage}-proxy" ip -4 -o addr show 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [proxy iptables nat (PREROUTING)]" >&2
  podman exec --user root "${cage}-proxy" iptables -t nat -L PREROUTING -n -v 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [proxy listening sockets]" >&2
  podman exec "${cage}-proxy" ss -tlnp 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [mock container]" >&2
  podman ps -a --filter "name=${cage}-mock" --format "          {{.Names}} {{.Status}}" >&2 || true
  echo "        [cage container logs (last 25 lines)]" >&2
  podman logs --tail 25 "${cage}-cage" 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [cage systemd journal (last 30 lines)]" >&2
  journalctl --user -u "${cage}-cage.service" -n 30 --no-pager 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [cage netns routing table]" >&2
  local _cage_pid
  _cage_pid=$(podman inspect --format '{{.State.Pid}}' "${cage}-cage" 2>/dev/null || echo "")
  if [ -n "$_cage_pid" ] && [ "$_cage_pid" != "0" ]; then
    nsenter -t "$_cage_pid" -U -n -- ip route 2>&1 | sed 's/^/          /' >&2 || echo "          (nsenter failed)" >&2
    # Pick the proxy IP that lives on the same /24 as the cage (the cage-net interface).
    local _proxy_cage_ip
    _proxy_cage_ip=$(podman inspect --format '{{(index .NetworkSettings.Networks "'"${cage}"'-net").IPAddress}}' "${cage}-proxy" 2>/dev/null)
    echo "        [cage → proxy IP ping (target=$_proxy_cage_ip, 3 probes)]" >&2
    if [ -n "$_proxy_cage_ip" ]; then
      nsenter -t "$_cage_pid" -U -n -- ping -c 3 -W 2 -q "$_proxy_cage_ip" 2>&1 | sed 's/^/          /' >&2 || true
      echo "        [cage → proxy:80 TCP connect]" >&2
      nsenter -t "$_cage_pid" -U -n -- timeout 3 bash -c "</dev/tcp/$_proxy_cage_ip/80" 2>&1 && echo "          OK" >&2 || echo "          FAILED ($?)" >&2
      echo "        [cage → proxy:8443 TCP connect]" >&2
      nsenter -t "$_cage_pid" -U -n -- timeout 3 bash -c "</dev/tcp/$_proxy_cage_ip/8443" 2>&1 && echo "          OK" >&2 || echo "          FAILED ($?)" >&2
    fi
  else
    echo "          (cage container has no valid PID)" >&2
  fi
  echo "        ── end $tag ──" >&2
}

# wait_data_path BASE_URL TEST_PATH CAGE DOMAIN [DOMAIN...]
#   Wait for the full proxy → mock chain to be ready by polling TEST_PATH on
#   the cage. On every retry, re-applies /etc/hosts to recover from a proxy
#   container restart that wiped a previous patch. 60s timeout.
#
#   This is the readiness probe to call between start_mock/repatch_mock and
#   any test that depends on the mock being reachable through the proxy.
#   wait_ready alone isn't enough — it only checks GET / on the cage and
#   doesn't exercise the DNS → iptables → mitmproxy → /etc/hosts → mock path.
#
#   Timeout is generous (120s) because CI parallel phases can saturate
#   Podman, slowing container startup well past the 120s the data path
#   normally needs.
wait_data_path() {
  local base="$1" test_path="$2" cage="$3"; shift 3
  local timeout=120
  local deadline=$((SECONDS + timeout))
  local delay=1
  while [ "$SECONDS" -lt "$deadline" ]; do
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$base$test_path" 2>/dev/null || true)
    if [ "$code" = "200" ]; then
      return 0
    fi
    repatch_mock "$cage" "$@" >/dev/null 2>&1 || true
    sleep "$delay"
    delay=$(( delay + 1 ))
    [ "$delay" -gt 3 ] && delay=3
  done
  return 1
}

# wait_http_blocked URL [TIMEOUT_S] — poll until HTTP 403 or 502, return 0/1
wait_http_blocked() {
  local url="$1" timeout="${2:-30}"
  local deadline=$((SECONDS + timeout))
  local delay=1
  while [ "$SECONDS" -lt "$deadline" ]; do
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
    if [ "$code" = "403" ] || [ "$code" = "502" ]; then
      return 0
    fi
    sleep "$delay"
    # linear backoff: 1, 2, 3, capped at 3s
    delay=$(( delay + 1 ))
    [ "$delay" -gt 3 ] && delay=3
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
  stop_mock "$1"
  agentcage cage destroy "$1" -y >/dev/null 2>&1 || true
}

# destroy_cage_with_volumes CAGE VOL...
#   Destroy a cage and remove caller-named podman volumes.
#   agentcage cage destroy only removes agentcage-prefixed volumes
#   (agentcage-certs-$NAME, agentcage-podman-$NAME); user-named
#   volumes from the cage.yaml named_volumes block survive by design.
#   Test cages want to clean these too so re-runs don't inherit state.
destroy_cage_with_volumes() {
  local cage="$1"; shift
  destroy_cage "$cage"
  for vol in "$@"; do
    podman volume rm -f "$vol" >/dev/null 2>&1 || true
  done
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

# ── mock HTTP server ─────────────────────────────────────────────────
# Replaces external httpbin.org/example.com with a local container on
# the cage network. The proxy's /etc/hosts is patched so outbound
# requests resolve to the mock instead of the real internet.
#
# IMPORTANT: test cage configs must set AGENT_DEMO=false on the agent
# container so the example agent's startup demoCycle does not race
# against the /etc/hosts patch — if the agent resolves the upstream
# domain first, mitmproxy caches the real IP and never honors the patch.

MOCK_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/mock-httpbin.py"

# start_mock CAGE DOMAIN [DOMAIN...]
#   Starts a mock HTTP server on the cage's network and patches the
#   proxy container's /etc/hosts so the given domains resolve to it.
# _patch_proxy_hosts CAGE MOCK_IP DOMAIN [DOMAIN...]
#   Writes a marker-delimited block to the proxy's /etc/hosts.
#   Replaces any existing block so entries don't accumulate.
_patch_proxy_hosts() {
  local cage="$1" mock_ip="$2"; shift 2
  local block="# e2e-mock-start\n"
  for domain in "$@"; do
    block="${block}${mock_ip} ${domain}\n"
  done
  block="${block}# e2e-mock-end"
  podman exec --user root "${cage}-proxy" \
    sh -c "sed -i '/# e2e-mock-start/,/# e2e-mock-end/d' /etc/hosts 2>/dev/null; printf '${block}\n' >> /etc/hosts" 2>/dev/null
}

start_mock() {
  local cage="$1"; shift

  # Remove stale mock container if any
  podman rm -f "${cage}-mock" >/dev/null 2>&1 || true

  # Start mock container (reuses the already-built agentcage-proxy image which has Python)
  # --user root: the image defaults to uid 1000, which can't bind to port 80
  # --sysctl ip_unprivileged_port_start=80: required on hosts where the
  #   default unprivileged port range starts at 1024 (e.g. Arch). Without
  #   this, even root in the container's user namespace can't bind :80.
  #   The proxy quadlet sets the same sysctl (proxy.container.j2).
  if ! podman run -d --name "${cage}-mock" \
    --user root \
    --network "${cage}-net" \
    --sysctl net.ipv4.ip_unprivileged_port_start=80 \
    -v "${MOCK_SCRIPT}:/mock.py:ro" \
    localhost/agentcage-proxy python3 /mock.py >/dev/null 2>&1; then
    echo "WARNING: failed to start mock container for $cage" >&2
    return 1
  fi

  # Get mock IP
  local mock_ip
  mock_ip=$(podman inspect "${cage}-mock" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
  if [ -z "$mock_ip" ]; then
    echo "WARNING: mock container has no IP for $cage" >&2
    stop_mock "$cage"
    return 1
  fi

  # Wait for mock to actually listen on port 80
  local i
  for i in $(seq 1 10); do
    if podman exec "${cage}-mock" python3 -c "
import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1',80)); s.close()
" 2>/dev/null; then
      break
    fi
    if [ "$i" -eq 10 ]; then
      echo "WARNING: mock not listening on port 80 for $cage" >&2
      echo "  container status: $(podman inspect "${cage}-mock" --format '{{.State.Status}}' 2>/dev/null)" >&2
      echo "  container logs:" >&2
      podman logs "${cage}-mock" 2>&1 | tail -10 >&2
      stop_mock "$cage"
      return 1
    fi
    sleep 0.5
  done

  # Patch proxy's /etc/hosts with marker block.
  # Retry — the proxy container may still be starting after cage create.
  local _patched=false
  for i in $(seq 1 15); do
    if _patch_proxy_hosts "$cage" "$mock_ip" "$@" 2>/dev/null &&
       podman exec "${cage}-proxy" grep -q "$mock_ip" /etc/hosts 2>/dev/null; then
      _patched=true
      break
    fi
    sleep 1
  done
  if [ "$_patched" = false ]; then
    echo "WARNING: failed to patch /etc/hosts for $cage after 15s" >&2
    stop_mock "$cage"
    return 1
  fi

  echo "  mock: $mock_ip → $*"
  return 0
}

# repatch_mock CAGE DOMAIN [DOMAIN...]
#   Re-applies /etc/hosts after a proxy container restart (domain add/rm,
#   cage restart, etc. recreate the container, losing the patch).
#   Verifies the patch landed before returning, since the proxy container
#   can be restarted by Restart=on-failure between patch and verification.
repatch_mock() {
  local cage="$1"; shift
  local mock_ip
  mock_ip=$(podman inspect "${cage}-mock" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null) || return 1
  [ -z "$mock_ip" ] && return 1
  local i
  for i in $(seq 1 15); do
    if _patch_proxy_hosts "$cage" "$mock_ip" "$@" 2>/dev/null &&
       podman exec "${cage}-proxy" grep -q "$mock_ip" /etc/hosts 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# stop_mock CAGE — remove mock container
stop_mock() {
  podman rm -f "${1}-mock" >/dev/null 2>&1 || true
}

# ── results ──────────────────────────────────────────────────────────

print_results() {
  local phase_ms=0
  if [ "$E2E_PHASE_START" -gt 0 ]; then
    local now
    now=$(date +%s%N)
    phase_ms=$(( (now - E2E_PHASE_START) / 1000000 ))
  fi
  local phase_dur
  phase_dur=$(_fmt_duration "$phase_ms")
  echo
  printf "\033[1m─── Results (%s) ───\033[0m\n" "$phase_dur"
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
