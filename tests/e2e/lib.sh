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
export AGENT_DIR="$REPO_ROOT/tests/e2e/fixtures/agent"

# The CLI under test. Every phase invokes "$AGENTCAGE" rather than a bare
# `agentcage` off PATH so the whole suite can be pointed at a different
# build — the e2e suite is the conformance oracle a rewritten (Rust) binary
# has to satisfy, and swapping the binary must not mean editing 100+ call
# sites. Exported so subshells, `env`-spawned phase scripts, and background
# jobs all inherit the same choice:
#
#   AGENTCAGE=/path/to/target/release/agentcage bash tests/e2e/run.sh container
#
# Defined with `:-` so an inherited value always wins. run.sh carries the
# same definition because it does not source this file.
export AGENTCAGE="${AGENTCAGE:-agentcage}"

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
  # Herestring, not `echo ... | grep -q`: grep's early exit on a match
  # would SIGPIPE `echo`, and `pipefail` would then report the match as a
  # failure. A herestring keeps grep's pattern semantics with no pipe.
  if grep -q "$pattern" <<<"$output"; then
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
#   Dump systemd unit state, podman container state, and egress logs for a
#   cage. Used on test failure to understand what went wrong on the CI
#   runner where we don't have an interactive shell.
#
#   v0.22: the proxy + dns sidecars are now unified into a single
#   <cage>-egress container; the diagnostic dumps reflect that shape.
dump_cage_diagnostics() {
  local cage="$1" tag="${2:-diagnostics}"
  echo "        ── $tag for cage '$cage' ──" >&2
  echo "        [systemd units]" >&2
  for svc in cage egress; do
    local active sub
    active=$(systemctl --user is-active "${cage}-${svc}.service" 2>&1 || true)
    sub=$(systemctl --user show -p SubState --value "${cage}-${svc}.service" 2>&1 || true)
    local nrestarts
    nrestarts=$(systemctl --user show -p NRestarts --value "${cage}-${svc}.service" 2>&1 || true)
    echo "          ${cage}-${svc}: active=${active} sub=${sub} nrestarts=${nrestarts}" >&2
  done
  echo "        [podman containers]" >&2
  podman ps -a --filter "name=${cage}-" --format "          {{.Names}} {{.Status}} {{.Ports}}" >&2 || true
  echo "        [egress container logs (last 25 lines)]" >&2
  podman logs --tail 25 "${cage}-egress" 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [egress systemd journal (last 25 lines)]" >&2
  journalctl --user -u "${cage}-egress.service" -n 25 --no-pager 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [egress /etc/hosts]" >&2
  podman exec "${cage}-egress" cat /etc/hosts 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [egress resolved httpbin.org]" >&2
  podman exec "${cage}-egress" getent hosts httpbin.org 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [egress network interfaces]" >&2
  podman exec "${cage}-egress" ip -4 -o addr show 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [egress iptables nat (PREROUTING)]" >&2
  podman exec --user root "${cage}-egress" iptables -t nat -L PREROUTING -n -v 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [egress listening sockets]" >&2
  podman exec "${cage}-egress" ss -tlnp 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [mock container]" >&2
  podman ps -a --filter "name=${cage}-mock" --format "          {{.Names}} {{.Status}}" >&2 || true
  # The mock must live in the CURRENT egress namespace; a mismatch means
  # the egress restarted and nothing re-homed the mock (repatch_mock).
  echo "          mock netns:   $(_mock_netns "$cage")" >&2
  echo "          egress netns: $(_egress_netns "$cage")" >&2
  echo "        [mock container logs (last 10 lines)]" >&2
  podman logs --tail 10 "${cage}-mock" 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [cage container logs (last 25 lines)]" >&2
  podman logs --tail 25 "${cage}-cage" 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [cage systemd journal (last 30 lines)]" >&2
  journalctl --user -u "${cage}-cage.service" -n 30 --no-pager 2>&1 | sed 's/^/          /' >&2 || true
  echo "        [cage netns routing table]" >&2
  local _cage_pid
  _cage_pid=$(podman inspect --format '{{.State.Pid}}' "${cage}-cage" 2>/dev/null || echo "")
  if [ -n "$_cage_pid" ] && [ "$_cage_pid" != "0" ]; then
    nsenter -t "$_cage_pid" -U -n -- ip route 2>&1 | sed 's/^/          /' >&2 || echo "          (nsenter failed)" >&2
    # Pick the egress IP that lives on the same /24 as the cage (the cage-net interface).
    local _egress_cage_ip
    # `|| true`: a failing inspect must not abort the diagnostic dump
    # half-way through under `set -e` (#317).
    _egress_cage_ip=$(podman inspect --format '{{(index .NetworkSettings.Networks "'"${cage}"'-net").IPAddress}}' "${cage}-egress" 2>/dev/null || true)
    echo "        [cage → egress IP ping (target=$_egress_cage_ip, 3 probes)]" >&2
    if [ -n "$_egress_cage_ip" ]; then
      nsenter -t "$_cage_pid" -U -n -- ping -c 3 -W 2 -q "$_egress_cage_ip" 2>&1 | sed 's/^/          /' >&2 || true
      echo "        [cage → egress:80 TCP connect]" >&2
      nsenter -t "$_cage_pid" -U -n -- timeout 3 bash -c "</dev/tcp/$_egress_cage_ip/80" 2>&1 && echo "          OK" >&2 || echo "          FAILED ($?)" >&2
      echo "        [cage → egress:8443 TCP connect]" >&2
      nsenter -t "$_cage_pid" -U -n -- timeout 3 bash -c "</dev/tcp/$_egress_cage_ip/8443" 2>&1 && echo "          OK" >&2 || echo "          FAILED ($?)" >&2
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

# Destroy a cage silently.
#
# Unlike create_cage (#317) this one stays silent on failure ON PURPOSE:
# every phase calls it up-front to clear a *possibly non-existent* stale
# cage, so a non-zero exit is the normal case and carries no signal. The
# `|| true` is likewise deliberate — a failed destroy must never abort a
# phase under `set -e`.
destroy_cage() {
  stop_mock "$1"
  "$AGENTCAGE" cage destroy "$1" -y >/dev/null 2>&1 || true
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

# cage_ca_fingerprint CAGE
#   SHA-256 of the CA certificate CAGE trusts, read from inside the cage
#   at the path its own SSL_CERT_FILE names — so the check follows the
#   cage's env rather than hard-coding where the cert is mounted. Prints
#   nothing if the cage is not running. Every cage gets a CA of its own
#   (EGRESS-PORT-PLAN.md D11): two cages never share one, and a cage
#   destroyed and created again under the same name gets a new one.
cage_ca_fingerprint() {
  podman exec "$1-cage" sh -c 'sha256sum "$SSL_CERT_FILE"' 2>/dev/null | cut -d' ' -f1
}

# _dump_captured LABEL OUTPUT
#   Print a captured command's combined output to stderr, indented and
#   framed like dump_cage_diagnostics. Used by the helpers below so a
#   failing command explains itself even when the caller redirects the
#   helper's stdout to /dev/null.
_dump_captured() {
  local label="$1" output="$2"
  {
    echo "        ── $label ──"
    if [ -n "$output" ]; then
      printf '%s\n' "$output" | sed 's/^/          /'
    else
      echo "          (no output)"
    fi
    echo "        ── end $label ──"
  } >&2
}

# Create a cage from a config template (expands env vars).
#
# Output handling (issue #317): `agentcage cage create` output is CAPTURED,
# not streamed. On success nothing is printed, so phases keep their clean
# output with the customary `create_cage ... >/dev/null`. On failure the
# captured output is dumped to stderr before returning the non-zero rc, so
# a broken create explains itself instead of producing a bare
# `Phase N: FAIL (0/0)`. Capturing here (rather than asking callers to stop
# redirecting) is what makes the diagnostic survive `>/dev/null` callers.
create_cage() {
  local config="$1"
  shift
  local tmpconfig
  tmpconfig=$(mktemp /tmp/e2e-config-XXXXXX.yaml)
  envsubst < "$config" > "$tmpconfig"
  local rc=0 output
  output=$(AGENT_DIR="$AGENT_DIR" "$AGENTCAGE" cage create -c "$tmpconfig" "$@" 2>&1) || rc=$?
  rm -f "$tmpconfig"
  if [ "$rc" -ne 0 ]; then
    _dump_captured "cage create FAILED (exit $rc): $(basename "$config")" "$output"
    # `systemctl start` reports a failed Requires= dependency as the
    # single line "A dependency job for <cage>-cage.service failed",
    # naming neither the dependency nor the reason — and on a CI runner
    # there is no second chance to go and look. `dump_cage_diagnostics`
    # answers what that line leaves open: unit states, podman container
    # states, the egress container log and its journal.
    local cage_name
    cage_name=$(sed -n 's/^name:[[:space:]]*//p' "$config" | head -1)
    if [ -n "$cage_name" ]; then
      dump_cage_diagnostics "$cage_name" "create failure"
    fi
  fi
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
# Replaces external httpbin.org/example.com with a local HTTP server so
# tests don't depend on the internet. The mock runs in its OWN container
# (a stock python image — the egress image ships no interpreter the
# harness may rely on) that shares the egress container's network
# namespace and listens on 127.0.0.1:80 there. The egress's /etc/hosts
# is patched so the mocked names resolve to 127.0.0.1, i.e. to the mock.
#
# Why share the egress netns rather than put the mock on the cage
# network: only the egress's own outbound connections can reach a
# loopback listener in its namespace. The cage cannot address it (cage
# traffic to the egress on :80 is REDIRECTed into the proxy before it
# could hit a local socket), and nothing outside the pod sees it.
#
# IMPORTANT: test cage configs must set AGENT_DEMO=false on the agent
# container so the example agent's startup demoCycle does not race
# against the /etc/hosts patch — if the agent resolves the upstream
# domain first, the proxy caches the real IP and never honors the patch.

_E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCK_SCRIPT="$_E2E_DIR/mock-httpbin.py"

# The mock's image: stock python on alpine, pinned by exact tag AND
# multi-arch index digest so a registry retag can't change what runs.
# Kept in its own file so CI can key its image cache on it. Override with
# E2E_MOCK_IMAGE (e.g. a pre-mirrored copy) — anything with python3 on
# PATH works, the mock is stdlib-only.
E2E_MOCK_IMAGE="${E2E_MOCK_IMAGE:-$(tr -d '[:space:]' < "$_E2E_DIR/mock-image.ref")}"

# Upstream names are mapped to this address in the egress's /etc/hosts.
MOCK_IP=127.0.0.1

# Label on the mock container recording which network namespace it was
# started in (see _egress_netns).
_MOCK_NETNS_LABEL=agentcage.e2e.netns

# _egress_netns CAGE
#   Print the network-namespace path of the RUNNING egress container, or
#   nothing when it is not running (or not visible to podman at all).
#
#   The mock joins by this path (`--network ns:<path>`) rather than with
#   `--network container:<cage>-egress`. Same shared namespace, but the
#   container: form registers the mock as a DEPENDENT of the egress, and
#   podman then refuses to remove or `--replace` the egress ("has
#   dependent containers which must be removed before it") — which is
#   exactly what every egress restart does (domain add/rm, cage restart,
#   restore: the quadlet's ExecStop is `podman rm -f`). The ns: form has no
#   lifecycle link; the price is that a restarted egress gets a fresh
#   namespace and the mock is left behind in the old one, which
#   repatch_mock detects through the path changing and fixes by moving
#   the mock over.
_egress_netns() {
  # `|| true`: a missing container must yield empty output, not abort the
  # caller under `set -e` (#317).
  podman inspect --format \
    '{{if .State.Running}}{{.NetworkSettings.SandboxKey}}{{end}}' \
    "${1}-egress" 2>/dev/null || true
}

# _mock_netns CAGE — the namespace the RUNNING mock was started in, or
# nothing when it is gone or exited.
_mock_netns() {
  podman inspect --format \
    "{{if .State.Running}}{{index .Config.Labels \"${_MOCK_NETNS_LABEL}\"}}{{end}}" \
    "${1}-mock" 2>/dev/null || true
}

# _run_mock CAGE NETNS
#   (Re)create the mock container inside NETNS and wait until it listens.
_run_mock() {
  local cage="$1" netns="$2"
  podman rm -f -t 0 "${cage}-mock" >/dev/null 2>&1 || true

  # No --sysctl / --user tweaks needed: binding :80 happens in the
  # egress's namespace, where the egress quadlet already lowered
  # ip_unprivileged_port_start, and the image runs as (userns) root anyway.
  # podman also rejects net.* sysctls on a joined namespace.
  #
  # Capture podman's own error (#317): a bare "failed to start mock
  # container" hides the actual cause (pull failure, stale netns, …).
  local run_out run_rc=0
  run_out=$(podman run -d --name "${cage}-mock" \
    --network "ns:${netns}" \
    --label "${_MOCK_NETNS_LABEL}=${netns}" \
    -v "${MOCK_SCRIPT}:/mock.py:ro" \
    "$E2E_MOCK_IMAGE" python3 /mock.py "$MOCK_IP" 2>&1) || run_rc=$?
  if [ "$run_rc" -ne 0 ]; then
    echo "WARNING: failed to start mock container for $cage (image: $E2E_MOCK_IMAGE)" >&2
    _dump_captured "podman run FAILED (exit $run_rc)" "$run_out"
    return 1
  fi

  # Wait for the mock to actually listen. The probe runs in the MOCK
  # container (which has python), never in the egress: nothing in the
  # harness may assume an interpreter in the egress image. Both share the
  # namespace, so this is the same socket the egress will connect to.
  local i
  for i in $(seq 1 20); do
    if podman exec "${cage}-mock" python3 -c "
import socket; s=socket.socket(); s.settimeout(1); s.connect(('${MOCK_IP}',80)); s.close()
" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  echo "WARNING: mock not listening on ${MOCK_IP}:80 for $cage" >&2
  echo "  container status: $(podman inspect "${cage}-mock" --format '{{.State.Status}}' 2>/dev/null || true)" >&2
  echo "  container logs:" >&2
  podman logs "${cage}-mock" 2>&1 | tail -10 >&2 || true
  stop_mock "$cage"
  return 1
}

# _patch_egress_hosts CAGE MOCK_IP DOMAIN [DOMAIN...]
#   Writes a marker-delimited block to the egress container's /etc/hosts.
#   Replaces any existing block so entries don't accumulate.
_patch_egress_hosts() {
  local cage="$1" mock_ip="$2"; shift 2
  # Strip our previous marker block, then append a fresh one. Repatch
  # is called every retry inside wait_data_path and across phases that
  # reuse the same cage (phase 4 keeps the basic cage from phase 1),
  # so without a strip step /etc/hosts accumulates stale entries —
  # and NSS returns the FIRST match, so a stale line would win.
  #
  # Block writes via `cat > /etc/hosts` (NOT a temp file + rename —
  # podman bind-mounts /etc/hosts and the rename fails silently across
  # the bind boundary, leaving the file untouched).
  #
  # Only POSIX sh + awk + cat are used inside the egress — no
  # interpreter — so this works against any egress image.
  local block
  block="# e2e-mock-start"
  for domain in "$@"; do
    block="${block}
${mock_ip} ${domain}"
  done
  block="${block}
# e2e-mock-end"
  printf '%s\n' "$block" | podman exec --user root -i "${cage}-egress" \
    sh -c '
      new_block=$(cat) || exit 1
      kept=$(awk "/^# e2e-mock-start/{s=1;next} /^# e2e-mock-end/{s=0;next} !s{print}" /etc/hosts) || exit 1
      printf "%s\n%s\n" "$kept" "$new_block" > /etc/hosts
    ' 2>/dev/null || return 1
  # NB: we deliberately do NOT SIGHUP dnsmasq after the patch. If
  # dnsmasq picked up /etc/hosts → 127.0.0.1, the cage's DNS would
  # resolve httpbin.org to loopback and the request would never reach
  # the egress at all. Instead dnsmasq keeps forwarding httpbin.org to
  # the upstream (server=/httpbin.org/<upstream>) → returns the REAL
  # public IP. The cage connects to the real IP, the packet enters the
  # egress on the cage-net interface, PREROUTING REDIRECT lands it on
  # the transparent proxy at :8443, and the proxy (keeping the Host
  # header) resolves the name via getaddrinfo, which reads /etc/hosts at
  # request time (no caching that needs invalidation) and connects to
  # the mock on 127.0.0.1. The flow is therefore inspected and audited
  # exactly like a real upstream request (Phase 2's
  # ``cage audit --host httpbin.org`` depends on that).
  return 0
}

# _egress_hosts_patched CAGE MOCK_IP DOMAIN [DOMAIN...]
#   True when every "MOCK_IP DOMAIN" line is present in the egress's
#   /etc/hosts. Matches whole lines: 127.0.0.1 is in every /etc/hosts
#   already (localhost), so grepping for the bare IP proves nothing.
_egress_hosts_patched() {
  local cage="$1" mock_ip="$2"; shift 2
  local lines=() domain
  for domain in "$@"; do
    lines+=("${mock_ip} ${domain}")
  done
  podman exec "${cage}-egress" sh -c '
    for l in "$@"; do grep -qxF "$l" /etc/hosts || exit 1; done
  ' sh "${lines[@]}" 2>/dev/null
}

# start_mock CAGE DOMAIN [DOMAIN...]
#   Starts the mock inside the cage's egress network namespace and patches
#   the egress's /etc/hosts so the given domains resolve to it.
start_mock() {
  local cage="$1"; shift

  # Remove stale mock container if any
  stop_mock "$cage"

  # The egress may still be starting right after `cage create`; wait for
  # it to be running (it then has a namespace to join).
  local netns="" i
  for i in $(seq 1 30); do
    netns=$(_egress_netns "$cage")
    [ -n "$netns" ] && break
    sleep 1
  done
  if [ -z "$netns" ]; then
    # A cage that `cage create` reported as created but whose egress podman
    # cannot see almost always means a NON-podman backend (vm /
    # apple-container) built it, in a different container store — the exact
    # #317 failure mode.
    echo "WARNING: egress container ${cage}-egress is not running in the podman store" >&2
    echo "         (podman inspect: $(podman inspect --format '{{.State.Status}}' "${cage}-egress" 2>&1 || true))." >&2
    echo "         If the cage was created with a vm or apple-container backend its" >&2
    echo "         egress lives in a different container store — see issue #317." >&2
    return 1
  fi

  _run_mock "$cage" "$netns" || return 1

  # Patch egress's /etc/hosts with marker block.
  # Retry — the egress container may still be settling after cage create.
  local _patched=false
  for i in $(seq 1 15); do
    if _patch_egress_hosts "$cage" "$MOCK_IP" "$@" &&
       _egress_hosts_patched "$cage" "$MOCK_IP" "$@"; then
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

  echo "  mock: $MOCK_IP (in ${cage}-egress netns) → $*"
  return 0
}

# repatch_mock CAGE DOMAIN [DOMAIN...]
#   Re-applies the mock after an egress container restart (domain add/rm,
#   cage restart, etc. recreate the container): moves the mock into the new
#   egress namespace if it changed, then re-applies /etc/hosts. Verifies
#   the patch landed before returning, since the egress container can be
#   restarted by Restart=on-failure between patch and verification.
#   Returns 1 without starting anything for a cage that never had a mock.
repatch_mock() {
  local cage="$1"; shift
  podman container exists "${cage}-mock" 2>/dev/null || return 1
  local i netns
  for i in $(seq 1 15); do
    netns=$(_egress_netns "$cage")
    if [ -n "$netns" ]; then
      if [ "$(_mock_netns "$cage")" != "$netns" ]; then
        _run_mock "$cage" "$netns" >/dev/null 2>&1 || { sleep 1; continue; }
      fi
      if _patch_egress_hosts "$cage" "$MOCK_IP" "$@" &&
         _egress_hosts_patched "$cage" "$MOCK_IP" "$@"; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

# stop_mock CAGE — remove mock container. `-t 0`: python as PID 1 ignores
# SIGTERM, so a graceful stop would just burn podman's 10s timeout.
stop_mock() {
  podman rm -f -t 0 "${1}-mock" >/dev/null 2>&1 || true
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
