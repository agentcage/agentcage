#!/usr/bin/env bash
# Phase 7: VM Mode — Lifecycle & Core Security
source "$(dirname "$0")/lib.sh"
preflight_check agentcage podman curl limactl
phase_header 7 "VM Mode — Lifecycle & Core Security"

if [ ! -e /dev/kvm ] && [ "$(uname)" = "Linux" ]; then
  echo "WARNING: /dev/kvm not found — VM tests will likely fail"
fi

CAGE="e2e-vm"
CONFIGS="$(dirname "$0")/configs"
PORT="${E2E_PORT_VM:-19080}"
BASE="http://localhost:$PORT"
VM_NAME="agentcage-$CAGE"

destroy_cage "$CAGE"
register_cage "$CAGE"

# Build the agent image on the host
echo "Building basic-agent image..."
podman build -t basic-agent "$REPO_ROOT/examples/basic/agent" >/dev/null 2>&1

echo "Creating VM cage (this takes a few minutes)..."
export E2E_PORT_VM="$PORT"
create_cage "$CONFIGS/vm.yaml" >/dev/null 2>&1 || true

# The cage service may fail because the image isn't in the VM yet
# Transfer it and start manually
if ! limactl shell "$VM_NAME" -- podman image exists localhost/basic-agent:latest 2>/dev/null; then
  echo "Transferring agent image into VM..."
  podman save localhost/basic-agent:latest | limactl shell "$VM_NAME" -- podman load >/dev/null 2>&1
fi

# Start services
limactl shell "$VM_NAME" -- systemctl --user reset-failed 2>/dev/null || true
limactl shell "$VM_NAME" -- systemctl --user start "${CAGE}-cage.service" 2>/dev/null || true

echo "Waiting for VM cage readiness (up to 240s)..."
if ! wait_ready "$BASE" 240; then
  e2e_fail "7.0" "VM cage readiness" "not ready within 240s"
  agentcage cage logs "$CAGE" -s proxy -n 20 2>/dev/null || true
  print_results; exit 1
fi

# ── VM Lifecycle ────────────────────────────────────────────────────
VM_STATUS=$(limactl list --json "$VM_NAME" 2>/dev/null \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "unknown")
if [ "$VM_STATUS" = "Running" ]; then
  e2e_pass "7.1" "VM created and running"
else
  e2e_fail "7.1" "VM created and running" "status: $VM_STATUS"
fi

assert_http 200 "$BASE/" "7.2" "Health check" --max-time 10

assert_output_contains "7.3" "Verify command" "passed" \
  agentcage cage verify "$CAGE"

assert_output_contains "7.4" "Show command (isolation=vm)" "vm" \
  agentcage cage show "$CAGE"

assert_output_contains "7.5" "List command" "$CAGE" \
  agentcage cage list

# ── VM Core Security ────────────────────────────────────────────────
assert_http 200 "$BASE/fetch?url=https://httpbin.org/get" "7.6" "Allowed domain" --max-time 10
assert_http_any "403|502" "$BASE/fetch?url=https://evil.com/exfil" "7.7" "Blocked domain" --max-time 10

assert_http_any "403|502" "$BASE/check-secret" "7.8" "Secret detection" \
  --max-time 10 -X POST -H "Content-Type: application/json" \
  -d '{"key":"sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'

assert_http 200 "$BASE/check-secret" "7.9" "Clean POST allowed" \
  --max-time 10 -X POST -H "Content-Type: application/json" \
  -d '{"data":"harmless"}'

# ── VM Observability ────────────────────────────────────────────────
assert_cmd_ok "7.10" "Logs: cage" agentcage cage logs "$CAGE" -s cage -n 5
assert_cmd_ok "7.11" "Logs: proxy" agentcage cage logs "$CAGE" -s proxy -n 5
assert_cmd_ok "7.12" "Logs: dns" agentcage cage logs "$CAGE" -s dns -n 5

assert_output_contains "7.13" "Audit entries" '"decision"' \
  agentcage cage audit "$CAGE" --json-lines -n 5

assert_output_contains "7.14" "Audit filter (blocked)" '"blocked"' \
  agentcage cage audit "$CAGE" -d blocked --json-lines

# HAR
HAR_FILE=$(mktemp /tmp/e2e-vm-har-XXXXXX.har)
if agentcage cage har "$CAGE" --view inbound -o "$HAR_FILE" >/dev/null 2>&1; then
  e2e_pass "7.15" "HAR export (VM)"
else
  e2e_fail "7.15" "HAR export (VM)" "har command failed"
fi
rm -f "$HAR_FILE"

# ── VM Mount Isolation ──────────────────────────────────────────────
assert_cmd_fail "7.16" "Home dir NOT mounted" \
  limactl shell "$VM_NAME" -- ls ~/Documents

assert_cmd_fail "7.17" "SSH keys NOT accessible" \
  limactl shell "$VM_NAME" -- ls ~/.ssh

assert_cmd_fail "7.18" "GPG keys NOT accessible" \
  limactl shell "$VM_NAME" -- ls ~/.gnupg

assert_cmd_ok "7.19" "Config dir mounted" \
  limactl shell "$VM_NAME" -- ls ~/.config/agentcage/

assert_cmd_fail "7.20" "Config dir read-only" \
  limactl shell "$VM_NAME" -- touch ~/.config/agentcage/testfile

assert_cmd_ok "7.21" "Containers dir mounted (rw)" \
  limactl shell "$VM_NAME" -- ls ~/.config/containers/systemd/

assert_cmd_ok "7.22" "State dir mounted (rw)" \
  limactl shell "$VM_NAME" -- ls ~/.local/share/agentcage/

# ── VM Domain Management ───────────────────────────────────────────
assert_output_contains "7.27" "List domains" "httpbin.org" \
  agentcage domain list "$CAGE"

if agentcage domain add "$CAGE" example.com >/dev/null 2>&1; then
  e2e_pass "7.28" "Add domain"
else
  e2e_fail "7.28" "Add domain" "command failed"
fi

if agentcage domain rm "$CAGE" example.com >/dev/null 2>&1; then
  e2e_pass "7.30" "Remove domain"
else
  e2e_fail "7.30" "Remove domain" "command failed"
fi

# ── VM Lifecycle Management ─────────────────────────────────────────
echo "Stopping VM cage..."
if agentcage cage stop "$CAGE" >/dev/null 2>&1; then
  e2e_pass "7.32" "Stop VM cage"
else
  e2e_fail "7.32" "Stop VM cage"
fi

VM_STATUS=$(limactl list --json "$VM_NAME" 2>/dev/null \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "unknown")
if [ "$VM_STATUS" = "Stopped" ]; then
  e2e_pass "7.33" "VM stopped"
else
  e2e_fail "7.33" "VM stopped" "status: $VM_STATUS"
fi

echo "Starting VM cage..."
agentcage cage start "$CAGE" >/dev/null 2>&1
if wait_ready "$BASE" 240; then
  e2e_pass "7.34" "Start VM cage"
else
  e2e_fail "7.34" "Start VM cage" "not ready after start"
fi

echo "Restarting VM cage..."
agentcage cage restart "$CAGE" >/dev/null 2>&1
if wait_ready "$BASE" 240; then
  e2e_pass "7.36" "Restart VM cage"
else
  e2e_fail "7.36" "Restart VM cage" "not ready after restart"
fi

# ── VM Exec ─────────────────────────────────────────────────────────
assert_output_contains "7.38" "Exec in VM cage" "hello" \
  agentcage cage exec "$CAGE" -s cage -- echo hello

assert_output_contains "7.39" "Exec in VM proxy" "hello" \
  agentcage cage exec "$CAGE" -s proxy -- echo hello

# ── VM Destroy ──────────────────────────────────────────────────────
echo "Destroying VM cage..."
if agentcage cage destroy "$CAGE" -y >/dev/null 2>&1; then
  e2e_pass "7.40" "Destroy VM cage"
  E2E_CAGES_TO_CLEANUP=()  # already destroyed
else
  e2e_fail "7.40" "Destroy VM cage"
fi

if ! limactl list --json "$VM_NAME" >/dev/null 2>&1; then
  e2e_pass "7.41" "VM gone"
else
  e2e_fail "7.41" "VM gone" "Lima instance still exists"
fi

if [ ! -f ~/.config/agentcage/lima/lima.yaml ]; then
  e2e_pass "7.42" "No leftover config"
else
  e2e_fail "7.42" "No leftover config"
fi

print_results
