#!/usr/bin/env bash
# Phase 6: Container Mode — Edge Cases & Security Hardening
source "$(dirname "$0")/lib.sh"
preflight_check "$AGENTCAGE" podman curl jq
phase_header 6 "Container Mode — Edge Cases & Security Hardening"

CAGE="e2e-hardened"
CONFIGS="$(dirname "$0")/configs"
PORT="${E2E_PORT_HARDENED:-19084}"
BASE="http://localhost:$PORT"

destroy_cage "$CAGE"
register_cage "$CAGE"

echo "Creating hardened cage..."
export E2E_PORT_HARDENED="$PORT"
create_cage "$CONFIGS/hardened.yaml" >/dev/null
if ! wait_ready "$BASE" 120; then
  e2e_fail "6.0" "Setup" "hardened cage not ready"
  print_results; exit 1
fi

# 6.1: Read-only filesystem
assert_cmd_fail "6.1" "Read-only filesystem" \
  podman exec "${CAGE}-cage" touch /usr/testfile

# 6.2: Dropped capabilities
e2e_timer_start
OUTPUT=$(podman exec "${CAGE}-cage" cat /proc/1/status 2>&1) || true
if echo "$OUTPUT" | grep -q "CapEff:.*0000000000000000"; then
  e2e_pass "6.2" "Dropped capabilities"
else
  e2e_fail "6.2" "Dropped capabilities" "CapEff not zeroed"
fi

# 6.3: Non-root user
e2e_timer_start
OUTPUT=$(podman exec "${CAGE}-cage" id 2>&1) || true
if echo "$OUTPUT" | grep -q "uid=1000"; then
  e2e_pass "6.3" "Non-root user"
else
  e2e_fail "6.3" "Non-root user" "$OUTPUT"
fi

# 6.4: Memory limit
e2e_timer_start
OUTPUT=$(podman exec "${CAGE}-cage" cat /sys/fs/cgroup/memory.max 2>&1) || true
if [ "$OUTPUT" = "268435456" ]; then
  e2e_pass "6.4" "Memory limit (256m)"
else
  e2e_fail "6.4" "Memory limit (256m)" "got $OUTPUT"
fi

# 6.5: DNS query logging (now reads from the unified egress journal)
assert_cmd_ok "6.5" "DNS query logging" \
  "$AGENTCAGE" cage logs "$CAGE" -s egress -n 20

# 6.6: Proxy connection logging (also egress; the proxy + dnsmasq share
# the supervisor's stderr stream)
assert_cmd_ok "6.6" "Proxy connection logging" \
  "$AGENTCAGE" cage logs "$CAGE" -s egress -n 20

# 6.7: Severity filtering
assert_cmd_ok "6.7" "Log severity filtering" \
  "$AGENTCAGE" cage logs "$CAGE" -l error -n 50

# 6.8: Invalid config rejected
BAD_CONFIG=$(mktemp /tmp/e2e-bad-XXXXXX.yaml)
cat > "$BAD_CONFIG" <<'EOF'
name: "INVALID NAME"
container:
  image: "node:22-slim"
  command: ["node", "app.js"]
  ports:
    - "127.0.0.1:19082:3000"
domains:
  allow:
    - example.com
EOF
assert_cmd_fail "6.8" "Invalid config rejected" \
  "$AGENTCAGE" cage create -c "$BAD_CONFIG"
rm -f "$BAD_CONFIG"

# 6.9: Port conflict detected
CONFLICT_CONFIG=$(mktemp /tmp/e2e-conflict-XXXXXX.yaml)
cat > "$CONFLICT_CONFIG" <<EOF
name: e2e-conflict
container:
  image: "node:22-slim"
  command: ["node", "app.js"]
  ports:
    - "127.0.0.1:${PORT}:3000"
domains:
  allow:
    - example.com
EOF
assert_cmd_fail "6.9" "Port conflict detected" \
  "$AGENTCAGE" cage create -c "$CONFLICT_CONFIG"
rm -f "$CONFLICT_CONFIG"

# 6.10: Subnet allocation (different /24 for each cage)
e2e_timer_start
SUBNET=$(podman network inspect "${CAGE}-net" 2>/dev/null \
  | jq -r '.[0].subnets[0].subnet // empty' 2>/dev/null || echo "")
if echo "$SUBNET" | grep -qE "^10\.89\.[0-9]+\.0/24$"; then
  e2e_pass "6.10" "Subnet allocation"
else
  e2e_fail "6.10" "Subnet allocation" "unexpected subnet: $SUBNET"
fi

# 6.11: Workspace .git/hooks tmpfs mask blocks cage→host git-hook pivot
# (#170). A cage that bind-mounts ${PROJECT_DIR}:/workspace:rw and applies
# the noexec tmpfs mask on /workspace/.git/hooks/ must NOT let a caged
# agent's write reach the host: the cage writes into a transient tmpfs
# that vanishes on stop, so $PROJECT_DIR/.git/hooks/pre-commit must NOT
# exist on the host afterward. This is the e2e counterpart to the static
# tmpfs checks in the quadlet golden tests — it verifies the mask has
# the intended security effect against a running cage, not just that the
# config declares it. Container (podman) backend only; apple-container
# does not yet honor tmpfs (#120) and that residual exposure is already
# surfaced as a security-relevant config validation warning.
MASK_CAGE="e2e-mask"
# Must live under $HOME: quadlet rendering rejects any container.volumes host path
# that resolves outside the home directory, so a /tmp project dir made this
# whole phase report SKIP ("cage create failed") on every runner instead of
# ever exercising the mask.
MASK_PROJECT="$(mktemp -d "$HOME/.agentcage-e2e-mask-XXXXXX")"
# The mask assumes a git project — create the .git tree podman overlays.
mkdir -p "$MASK_PROJECT/.git/hooks"
# mktemp -d makes 0700; a real checkout is 0755. With `userns: keep-id` the
# host user keeps its own uid in the cage, which is NOT the workload's
# `user: "1000:1000"`, so a 0700 /workspace denies uid 1000 even *search*
# permission and every path below it fails with EACCES before the mask is
# ever reached. Match a real project so this test measures the mask.
chmod 755 "$MASK_PROJECT"
# Sanity: the host pre-condition (no pre-commit hook) holds before the run.
[ ! -f "$MASK_PROJECT/.git/hooks/pre-commit" ] || {
  e2e_fail "6.11" "Workspace .git/hooks tmpfs mask" \
    "host pre-condition broken: pre-commit already exists"
}
export E2E_MASK_PROJECT_DIR="$MASK_PROJECT"
destroy_cage "$MASK_CAGE"
register_cage "$MASK_CAGE"
MASK_CREATE_RC=0
# Only stdout is dropped: create_cage dumps a failing create to stderr
# (#317), and the skip below needs that reason to be visible.
create_cage "$CONFIGS/workspace-mask.yaml" >/dev/null || MASK_CREATE_RC=$?
if [ "$MASK_CREATE_RC" -ne 0 ]; then
  e2e_skip "6.11" "Workspace .git/hooks tmpfs mask" \
    "cage create failed (no podman / buildkit available) — see the dumped create output above"
else
  # `cage create` builds + starts the cage, but a sleep-infinity cage has
  # no HTTP port to wait_ready against. Poll cage exec until the workload
  # is up (cage exec refuses a stopped cage with a clear error).
  MASK_READY=false
  for _ in $(seq 1 30); do
    if "$AGENTCAGE" cage exec "$MASK_CAGE" -- true >/dev/null 2>&1; then
      MASK_READY=true
      break
    fi
    sleep 1
  done
  if [ "$MASK_READY" != true ]; then
    e2e_fail "6.11" "Workspace .git/hooks tmpfs mask" \
      "cage not reachable via exec after create"
  else
    # Plant a hook from inside the cage AS THE DEFAULT (non-root) cage user.
    # The write lands in the cage's tmpfs view of /workspace/.git/hooks/, not
    # on the host bind-mount. chmod +x mirrors the real pivot shape. The
    # runtimes give an option-less tmpfs the mode of the directory it masks —
    # here the host's 0755 .git/hooks — with a root-owned root, so without the
    # mask-mode pin (#321) this write fails with EACCES; keep its stderr so
    # that shows up in the failure message instead of an empty file.
    MASK_WRITE_ERR=$("$AGENTCAGE" cage exec "$MASK_CAGE" -- sh -c \
      'echo pwned > /workspace/.git/hooks/pre-commit && chmod +x /workspace/.git/hooks/pre-commit' \
      2>&1 >/dev/null | tr -d '\r' | tr '\n' ' ') || true
    # The write MUST be visible inside the cage (proves the tmpfs is there
    # and writable — the mask is a transient overlay, not a read-only block).
    IN_CAGE=$("$AGENTCAGE" cage exec "$MASK_CAGE" -- \
      cat /workspace/.git/hooks/pre-commit 2>/dev/null | tr -d '\r\n') || true
    # Snapshot the mask's runtime shape while the cage is still up. A bare
    # "Permission denied" cannot distinguish a wrong tmpfs mode (#321) from a
    # /workspace whose modes deny the workload before the mask is reached.
    MASK_DIAG=$("$AGENTCAGE" cage exec "$MASK_CAGE" -- sh -c \
      'id; ls -ldn /workspace /workspace/.git /workspace/.git/hooks; grep hooks /proc/self/mounts' \
      2>&1 | tr -d '\r' | tr '\n' '|') || true
    # Stop the cage so the tmpfs is torn down.
    "$AGENTCAGE" cage stop "$MASK_CAGE" >/dev/null 2>&1 || true
    if [ -f "$MASK_PROJECT/.git/hooks/pre-commit" ]; then
      e2e_fail "6.11" "Workspace .git/hooks tmpfs mask" \
        "cage write reached the host — cage→host pivot NOT blocked (in-cage content: ${IN_CAGE:-<empty>})"
    elif [ "$IN_CAGE" != "pwned" ]; then
      e2e_fail "6.11" "Workspace .git/hooks tmpfs mask" \
        "write did not land in the cage tmpfs (in-cage content: ${IN_CAGE:-<empty>}; write stderr: ${MASK_WRITE_ERR:-<none>}; cage view: ${MASK_DIAG:-<none>}) — mask shape changed"
    else
      e2e_pass "6.11" "Workspace .git/hooks tmpfs mask"
    fi
  fi
fi
destroy_cage "$MASK_CAGE"
# Guard the rm: this path is now under $HOME, so an empty MASK_PROJECT must
# never turn into `rm -rf ""`. An `if` and not `[ ... ] && rm`: lib.sh runs the
# phase under `set -e`, where a false test as the last command would abort
# before print_results.
if [ -n "${MASK_PROJECT:-}" ]; then
  rm -rf "$MASK_PROJECT"
fi

# 6.12: A custom inspector (a WebAssembly component) blocks a request.
# Uses examples/inspectors/header-policy with block_on_missing, so every
# request without X-Trace-ID is refused before any upstream connect. The
# component is built outside the harness (it needs the wasm32-wasip2
# target): E2E_INSPECTOR_WASM names it, else the test skips. A positive
# control follows: a request WITH the header passes the plugin.
PLUGIN_CAGE="e2e-plugin"
PLUGIN_PORT="${E2E_PORT_PLUGIN:-19087}"
PLUGIN_BASE="http://localhost:$PLUGIN_PORT"
if [ -z "${E2E_INSPECTOR_WASM:-}" ] || [ ! -f "${E2E_INSPECTOR_WASM:-}" ]; then
  e2e_skip "6.12" "Custom WebAssembly inspector blocks" \
    "E2E_INSPECTOR_WASM not set (build examples/inspectors/header-policy for wasm32-wasip2)"
else
  PLUGIN_DIR="$(mktemp -d "$HOME/.agentcage-e2e-plugin-XXXXXX")"
  cp "$E2E_INSPECTOR_WASM" "$PLUGIN_DIR/header_policy_inspector.wasm"
  PLUGIN_CONFIG="$PLUGIN_DIR/cage.yaml"
  # create_cage runs the config through envsubst, so ${AGENT_DIR} stays
  # literal here. The plugin path is absolute: create_cage stages the
  # config in /tmp, and a relative path resolves against the config.
  cat > "$PLUGIN_CONFIG" <<PLUGIN_YAML
name: $PLUGIN_CAGE
container:
  image: "node:22-slim"
  command: ["node", "/app/agent.js"]
  volumes:
    - "\${AGENT_DIR}:/app:ro"
  ports:
    - "127.0.0.1:${PLUGIN_PORT}:3000"
  env:
    AGENT_DEMO: "false"
domains:
  allow:
    - httpbin.org
inspectors:
  - name: header-policy
    path: $PLUGIN_DIR/header_policy_inspector.wasm
    config:
      block_on_missing: true
PLUGIN_YAML
  destroy_cage "$PLUGIN_CAGE"
  register_cage "$PLUGIN_CAGE"
  e2e_timer_start
  if ! create_cage "$PLUGIN_CONFIG" >/dev/null; then
    e2e_fail "6.12" "Custom WebAssembly inspector blocks" "cage create failed (output dumped above)"
  else
    start_mock "$PLUGIN_CAGE" httpbin.org >/dev/null || true
    WANT="Missing mandatory header: x-trace-id"
    PLUGIN_BODY=""
    PLUGIN_CODE=""
    # The chain runs on inbound requests too (only the domain check is
    # skipped there), so the probes to the cage carry the header; the
    # cage's own fetch does not, and is what the plugin refuses.
    for _ in $(seq 1 60); do
      PLUGIN_BODY=$(curl -s --max-time 10 -H 'X-Trace-ID: e2e' -w '\n%{http_code}' \
        "$PLUGIN_BASE/fetch?url=http://httpbin.org/get" 2>/dev/null || true)
      PLUGIN_CODE=$(printf '%s' "$PLUGIN_BODY" | tail -n1)
      if [ "$PLUGIN_CODE" = "403" ] && printf '%s' "$PLUGIN_BODY" | grep -qF "$WANT"; then
        break
      fi
      sleep 2
    done
    if [ "$PLUGIN_CODE" != "403" ] || ! printf '%s' "$PLUGIN_BODY" | grep -qF "$WANT"; then
      e2e_fail "6.12" "Custom WebAssembly inspector blocks" \
        "expected 403 with \"$WANT\", got ${PLUGIN_CODE:-000}: $(printf '%s' "$PLUGIN_BODY" | head -c 400)"
      dump_cage_diagnostics "$PLUGIN_CAGE" "6.12 plugin failure"
    else
      # Positive control: with the header the plugin has nothing to say,
      # so the request reaches the mock.
      WITH_HEADER=""
      for _ in $(seq 1 30); do
        WITH_HEADER=$("$AGENTCAGE" cage exec "$PLUGIN_CAGE" -- node -e \
          "fetch('http://httpbin.org/get',{headers:{'X-Trace-ID':'e2e'}}).then(r=>console.log(r.status)).catch(e=>console.log('ERR '+e.message))" \
          2>/dev/null | tr -d '\r' | tail -n1) || true
        [ "$WITH_HEADER" = "200" ] && break
        repatch_mock "$PLUGIN_CAGE" httpbin.org >/dev/null 2>&1 || true
        sleep 2
      done
      if [ "$WITH_HEADER" = "200" ]; then
        e2e_pass "6.12" "Custom WebAssembly inspector blocks"
      else
        e2e_fail "6.12" "Custom WebAssembly inspector blocks" \
          "blocked without the header, but a request WITH X-Trace-ID got: ${WITH_HEADER:-<nothing>}"
      fi
    fi
  fi
  stop_mock "$PLUGIN_CAGE"
  destroy_cage "$PLUGIN_CAGE"
  if [ -n "${PLUGIN_DIR:-}" ]; then
    rm -rf "$PLUGIN_DIR"
  fi
fi

# ── 6.13–6.18: the egress container's own shape ─────────────────────
# Checked against the hardened cage's live egress (still running: the
# phase's EXIT trap destroys it). What the supervisor promises: dnsmasq
# and the proxy each under their own uid with a minimal bounding set, the
# netfilter shape that makes the egress the cage's only way out, the
# listeners, the ready marker the host waits for, and a public-certs
# directory that can never hand the CA's private key to a cage.
EGRESS="${CAGE}-egress"

# _proc_ids PID — "<real uid> <CapBnd>" of PID inside the egress.
_proc_ids() {
  podman exec "$EGRESS" awk '/^Uid:/{u=$2} /^CapBnd:/{c=$2} END{print u, c}' \
    "/proc/$1/status" 2>/dev/null || true
}

# 6.13: the ready marker (written only after iptables, dnsmasq and the
# proxy are all up).
assert_cmd_ok "6.13" "Egress ready marker" \
  podman exec "$EGRESS" test -f /var/log/agentcage/ready

# 6.14: dnsmasq runs as acdns (uid 201) and keeps only
# cap_net_bind_service (bit 10, 0x400) in its bounding set: it binds :53
# through a file capability, which the bounding set must still allow at
# execve. Any other bit means the supervisor's setpriv filter broke.
e2e_timer_start
DNS_PID=$(podman exec "$EGRESS" cat /home/acdns/dnsmasq.pid 2>/dev/null | tr -d '[:space:]' || true)
DNS_IDS=""
[ -n "$DNS_PID" ] && DNS_IDS=$(_proc_ids "$DNS_PID")
if [ "$DNS_IDS" = "201 0000000000000400" ]; then
  e2e_pass "6.14" "Egress: dnsmasq uid 201, CapBnd 0x400"
else
  e2e_fail "6.14" "Egress: dnsmasq uid 201, CapBnd 0x400" \
    "dnsmasq pid '${DNS_PID}': uid/CapBnd '${DNS_IDS}' (want '201 0000000000000400')"
fi

# 6.15: the proxy runs as acproxy (uid 200) with an EMPTY bounding set.
e2e_timer_start
PROXY_SEEN=""
PROXY_OK=false
for pid in $(podman exec "$EGRESS" pgrep -f /opt/agentcage/agentcage-egress 2>/dev/null || true); do
  ids=$(_proc_ids "$pid")
  PROXY_SEEN="${PROXY_SEEN}pid $pid: '$ids'; "
  if [ "$ids" = "200 0000000000000000" ]; then
    PROXY_OK=true
    break
  fi
done
if [ "$PROXY_OK" = true ]; then
  e2e_pass "6.15" "Egress: proxy uid 200, empty CapBnd"
else
  e2e_fail "6.15" "Egress: proxy uid 200, empty CapBnd" \
    "${PROXY_SEEN:-no agentcage-egress process found} (want '200 0000000000000000')"
fi

# 6.16: netfilter shape — FORWARD drops by default (the egress is not a
# router for the cage), and PREROUTING redirects the inspected ports 80
# and 443 into the transparent proxy.
e2e_timer_start
FWD=$(podman exec --user root "$EGRESS" iptables -L FORWARD -n 2>&1 || true)
NAT=$(podman exec --user root "$EGRESS" iptables -t nat -L PREROUTING -n 2>&1 || true)
if grep -q 'policy DROP' <<<"$FWD" &&
   grep 'REDIRECT' <<<"$NAT" | grep -qw 'dpt:80' &&
   grep 'REDIRECT' <<<"$NAT" | grep -qw 'dpt:443'; then
  e2e_pass "6.16" "Egress: FORWARD DROP, REDIRECT 80+443"
else
  e2e_fail "6.16" "Egress: FORWARD DROP, REDIRECT 80+443" \
    "FORWARD: $(tr '\n' '|' <<<"$FWD") PREROUTING: $(tr '\n' '|' <<<"$NAT")"
fi

# 6.17: listeners — dnsmasq on :53 (udp and tcp), the proxy on :8443
# (transparent) and :8080 (explicit).
e2e_timer_start
TCP=$(podman exec "$EGRESS" ss -lnt 2>&1 || true)
UDP=$(podman exec "$EGRESS" ss -lnu 2>&1 || true)
MISSING=""
grep -q ':53 ' <<<"$UDP" || MISSING="$MISSING udp:53"
for p in 53 8443 8080; do
  grep -q ":$p " <<<"$TCP" || MISSING="$MISSING tcp:$p"
done
if [ -z "$MISSING" ]; then
  e2e_pass "6.17" "Egress: listeners :53 :8443 :8080"
else
  e2e_fail "6.17" "Egress: listeners :53 :8443 :8080" "not listening:$MISSING"
fi

# 6.18: public-certs, the directory a cage may be given, holds the public
# CA certificate under its one neutral name and nothing else — in
# particular never the CA's private key.
e2e_timer_start
PUBLIC=$(podman exec "$EGRESS" ls -A /home/acproxy/public-certs 2>&1 || true)
if [ "$PUBLIC" = "agentcage-ca.pem" ]; then
  e2e_pass "6.18" "Egress: public-certs only CA cert"
else
  e2e_fail "6.18" "Egress: public-certs only CA cert" \
    "contents: $(tr '\n' ' ' <<<"$PUBLIC")"
fi

print_results
