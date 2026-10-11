#!/usr/bin/env bash
# Phase 9: Egress features — protocol relays, Policy API, WebSocket,
# passthrough, the block body.
#
# The other container phases drive plain HTTP through the egress. This one
# covers what they never reach, against mocks in the egress's network
# namespace so nothing depends on a real mail server or LLM provider:
#
#   * IMAP and SMTP protocol relays end to end (mock-services.py upstreams)
#   * the Policy API with the decider answered by a stub LLM, and one
#     traffic-watcher scan against the same stub
#   * a WebSocket round trip, with a secret placeholder injected into a
#     message and redacted back out of the echo
#   * a passthrough domain (the cage sees the upstream's own certificate)
#     and the D4 guard against SNI spoofing (Rust egress only)
#   * the 403 block body, byte for byte
#
# Every in-cage client is tests/e2e/fixtures/probe/probe.js, mounted at
# /probe: node:22-slim has neither curl nor python.
#
# Must pass on both engines (AGENTCAGE_EGRESS_ENGINE=rust or unset); where
# the Python egress lacks a behaviour by design the assertion is gated on
# the engine with the reason next to it.
source "$(dirname "$0")/lib.sh"
preflight_check "$AGENTCAGE" podman curl openssl python3 sha256sum
phase_header 9 "Egress features — relays, Policy API, WebSocket, passthrough"

CAGE="e2e-egress"
CONFIGS="$(dirname "$0")/configs"
PORT="${E2E_PORT_EGRESS:-19089}"
BASE="http://localhost:$PORT"
ENGINE="${AGENTCAGE_EGRESS_ENGINE:-python}"
SERVICES_SCRIPT="$_E2E_DIR/mock-services.py"
DEPLOY_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/agentcage/cages/$CAGE"

# Credentials the egress holds and the cage never sees.
MAIL_USER="e2e-user"
MAIL_PASSWORD="e2e-mail-password-31337"
LLM_KEY="e2e-llm-key-27182"
WS_VALUE="ws-real-value-4242"

# The passthrough upstream's certificate, made here so no private key is
# ever committed. Under $HOME rather than /tmp: rootless podman on some
# hosts cannot bind-mount another user's private /tmp.
WORK="$(mktemp -d "$HOME/.agentcage-e2e-egress-XXXXXX")"
chmod 755 "$WORK"

_phase9_cleanup() {
  podman rm -f -t 0 "${CAGE}-svc" >/dev/null 2>&1 || true
  _cleanup_cages
  if [ -n "${WORK:-}" ]; then
    rm -rf "$WORK"
  fi
}
trap _phase9_cleanup EXIT

destroy_cage "$CAGE"
podman rm -f -t 0 "${CAGE}-svc" >/dev/null 2>&1 || true
register_cage "$CAGE"

# ── helpers ──────────────────────────────────────────────────────────

# probe ARGS... — run probe.js in the cage, print its one JSON line.
probe() {
  "$AGENTCAGE" cage exec "$CAGE" -- node /probe/probe.js "$@" 2>/dev/null \
    | tr -d '\r' | grep '^{' | tail -n1 || true
}

# jget PATH — a field of the JSON document on stdin, printed raw (strings
# unquoted, everything else as JSON). PATH is dot-separated; a number
# indexes a list. Missing → empty.
jget() {
  python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    for k in sys.argv[1].split("."):
        d = d[int(k)] if isinstance(d, list) else d[k]
except Exception:
    sys.exit(0)
print(d if isinstance(d, str) else json.dumps(d), end="")
' "$1"
}

sha256() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

# stub_findings — how many findings from the stub LLM the watcher lists.
stub_findings() {
  grep -c 'e2e stub finding' <<<"$("$AGENTCAGE" watcher findings "$CAGE" --json -n 0 2>/dev/null)" || true
}

# svc_log FILE — a mock-services log file (empty when absent).
svc_log() { podman exec "${CAGE}-svc" cat "/tmp/mock-log/$1" 2>/dev/null || true; }

# audit_lines — the cage's audit records, one JSON object per line.
audit_lines() { "$AGENTCAGE" cage audit "$CAGE" --json-lines -n 1000 2>/dev/null || true; }

# wait_audit PATTERN... — poll (20s) until one audit line contains every
# PATTERN (fixed strings). Audit records are written asynchronously.
wait_audit() {
  local line ok p
  for _ in $(seq 1 20); do
    while IFS= read -r line; do
      ok=true
      for p in "$@"; do
        case "$line" in *"$p"*) ;; *) ok=false; break ;; esac
      done
      if [ "$ok" = true ]; then return 0; fi
    done < <(audit_lines)
    sleep 1
  done
  return 1
}

# start_services — run mock-services.py in its own container in the
# egress's network namespace (the same arrangement as start_mock; see
# lib.sh for why the namespace is joined by path), and wait until all four
# listeners answer.
start_services() {
  local netns
  for _ in $(seq 1 30); do
    netns=$(_egress_netns "$CAGE")
    [ -n "$netns" ] && break
    sleep 1
  done
  [ -n "$netns" ] || return 1
  podman rm -f -t 0 "${CAGE}-svc" >/dev/null 2>&1 || true
  local out rc=0
  out=$(podman run -d --name "${CAGE}-svc" \
    --network "ns:${netns}" \
    -v "${SERVICES_SCRIPT}:/mock-services.py:ro" \
    -v "${WORK}:/pt:ro" \
    "$E2E_MOCK_IMAGE" python3 /mock-services.py /pt/pt.crt /pt/pt.key 2>&1) || rc=$?
  if [ "$rc" -ne 0 ]; then
    _dump_captured "podman run mock-services FAILED (exit $rc)" "$out"
    return 1
  fi
  for _ in $(seq 1 20); do
    if podman exec "${CAGE}-svc" python3 -c "
import socket
for port in (3143, 3025, 18089, 443):
    s = socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', port)); s.close()
" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  _dump_captured "mock-services logs" "$(podman logs "${CAGE}-svc" 2>&1 | tail -20)"
  return 1
}

# patch_hosts_block MARKER LINE... — a second marker-delimited block in the
# egress's /etc/hosts, next to start_mock's (whose rewrite keeps it).
patch_hosts_block() {
  local marker="$1"; shift
  local block="# ${marker}-start" l
  for l in "$@"; do
    block="${block}
${l}"
  done
  block="${block}
# ${marker}-end"
  printf '%s\n' "$block" | podman exec --user root -i "${CAGE}-egress" sh -c '
    new_block=$(cat) || exit 1
    kept=$(awk -v s="# $1-start" -v e="# $1-end" "\$0==s{x=1;next} \$0==e{x=0;next} !x{print}" /etc/hosts) || exit 1
    printf "%s\n%s\n" "$kept" "$new_block" > /etc/hosts
  ' sh "$marker"
}

# ── setup ────────────────────────────────────────────────────────────

echo "Creating egress-features cage ($ENGINE egress)..."
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$WORK/pt.key" -out "$WORK/pt.crt" \
  -subj "/O=e2e passthrough mock/CN=pt.e2e.test" \
  -addext "subjectAltName=DNS:pt.e2e.test" >/dev/null 2>&1
chmod 644 "$WORK/pt.key" "$WORK/pt.crt"

export E2E_PORT_EGRESS="$PORT"
export E2E_PROBE_DIR="$_E2E_DIR/fixtures/probe"
if ! create_cage "$CONFIGS/egress-features.yaml" \
  --set-secret "E2E_MAIL_USER=$MAIL_USER" \
  --set-secret "E2E_MAIL_PASSWORD=$MAIL_PASSWORD" \
  --set-secret "E2E_LLM_KEY=$LLM_KEY" \
  --set-secret "WS_TOKEN=$WS_VALUE" >/dev/null; then
  e2e_fail "9.0" "Setup" "cage create failed (output dumped above)"
  print_results; exit 1
fi
FINDINGS_BEFORE=$(stub_findings)
# example.net is the name the decider grants (9.13); the egress resolves
# it to the mock like httpbin.org, the cage through its own DNS.
start_mock "$CAGE" httpbin.org example.net
if ! start_services; then
  e2e_fail "9.0" "Setup" "mock services did not start"
  print_results; exit 1
fi
if ! wait_ready "$BASE" 120 ||
   ! wait_data_path "$BASE" "/fetch?url=http://httpbin.org/get" "$CAGE" httpbin.org example.net; then
  e2e_fail "9.0" "Setup" "cage or its outbound data path not ready within 120s"
  dump_cage_diagnostics "$CAGE" "9.0 setup failure"
  print_results; exit 1
fi

# Point both LLM agents at the stub. The host refuses an http:// base_url
# (the API key would travel in clear), and the stub cannot present a
# certificate the egress trusts (it verifies against the Mozilla roots
# only), so the DEPLOYED egress config is rewritten in place instead:
# both engines re-read it when its mtime changes, and neither checks the
# scheme itself. A truncating write, not a rename, because the file is
# bind-mounted into the egress by inode. Nothing later in this phase
# restarts the cage, which would regenerate the file from cage.yaml.
PROXY_CFG="$DEPLOY_DIR/proxy-config.yaml"
if ! grep -q 'https://llm.e2e.invalid' "$PROXY_CFG" 2>/dev/null; then
  e2e_fail "9.0" "Setup" "base_url not found in $PROXY_CFG"
  print_results; exit 1
fi
_cfg=$(sed 's#https://llm\.e2e\.invalid#http://127.0.0.1:18089#g' "$PROXY_CFG")
printf '%s\n' "$_cfg" > "$PROXY_CFG"

# The passthrough name resolves, in the egress, to the egress's own
# address on the cage network, where mock-services.py's TLS listener
# answers. The cage dials that address directly (no DNS in the cage).
EGRESS_IP=$(podman inspect --format \
  '{{(index .NetworkSettings.Networks "'"${CAGE}"'-net").IPAddress}}' "${CAGE}-egress" 2>/dev/null || true)
patch_hosts_block e2e-pt "${EGRESS_IP} pt.e2e.test" || true

# ── 9.1: block body ──────────────────────────────────────────────────
# A request for a host outside the allowlist, sent to an address directly
# (192.0.2.1, TEST-NET-1) so the cage's DNS — which does not resolve
# unlisted names — is not involved. The egress answers from the Host
# header with the block body, which agents parse: pinned byte for byte.
e2e_timer_start
OUT=$(probe http-raw 192.0.2.1 80 blocked.e2e.test /exfil)
WANT='{"blocked": true, "reason": "domain not in allowlist: blocked.e2e.test", "host": "blocked.e2e.test", "by": "agentcage"}'
GOT_STATUS=$(jget status <<<"$OUT")
GOT_BODY=$(jget body <<<"$OUT")
if [ "$GOT_STATUS" = "403" ] && [ "$GOT_BODY" = "$WANT" ]; then
  e2e_pass "9.1" "403 block body is byte-exact"
else
  e2e_fail "9.1" "403 block body is byte-exact" "got: $OUT"
fi

# ── 9.2–9.6: IMAP relay ──────────────────────────────────────────────
# One session through the relay (write_mode: organise, Trash denied):
#   a1 LOGIN            answered by the relay itself
#   a2 SELECT INBOX     forwarded
#   a3 FETCH            forwarded, the mock's message comes back
#   a4 STORE \Seen      allowed in organise, forwarded
#   a5 EXPUNGE          refused in organise
#   a6 STORE \Deleted   refused in organise
#   a7 SELECT Trash     refused by folder_denylist
IMAP_OUT=$(probe imap egress 2143 \
  "LOGIN cage-user cage-pass" \
  "SELECT INBOX" \
  "FETCH 1 BODY[]" \
  "STORE 1 +FLAGS (\\Seen)" \
  "EXPUNGE" \
  "STORE 1 +FLAGS (\\Deleted)" \
  "SELECT Trash" \
  "LOGOUT")
IMAP_LOG=$(svc_log imap.log)

e2e_timer_start
GREETING=$(jget greeting <<<"$IMAP_OUT")
if [[ "$GREETING" == "* PREAUTH"* ]] && [[ "$(jget responses.0 <<<"$IMAP_OUT")" == *"a1 OK"* ]] &&
   grep -qF "LOGIN \"$MAIL_USER\" \"$MAIL_PASSWORD\"" <<<"$IMAP_LOG" &&
   ! grep -q "cage-pass" <<<"$IMAP_LOG"; then
  e2e_pass "9.2" "IMAP: PREAUTH, login answered locally"
else
  e2e_fail "9.2" "IMAP: PREAUTH, login answered locally" \
    "greeting='$GREETING' a1='$(jget responses.0 <<<"$IMAP_OUT")' upstream log: $(tr '\n' '|' <<<"$IMAP_LOG")"
fi

e2e_timer_start
if [[ "$(jget responses.2 <<<"$IMAP_OUT")" == *"hello from the mock imap server"*"a3 OK"* ]] &&
   [[ "$(jget responses.3 <<<"$IMAP_OUT")" == *"a4 OK"* ]] && grep -q '^a4 STORE' <<<"$IMAP_LOG"; then
  e2e_pass "9.3" "IMAP: read and allowed write forwarded"
else
  e2e_fail "9.3" "IMAP: read and allowed write forwarded" "session: $IMAP_OUT"
fi

e2e_timer_start
if [[ "$(jget responses.4 <<<"$IMAP_OUT")" == *"a5 NO"* ]] &&
   [[ "$(jget responses.5 <<<"$IMAP_OUT")" == *"a6 NO"* ]] &&
   ! grep -qE '^a(5|6) ' <<<"$IMAP_LOG"; then
  e2e_pass "9.4" "IMAP: write_mode refuses EXPUNGE, \\Deleted"
else
  e2e_fail "9.4" "IMAP: write_mode refuses EXPUNGE, \\Deleted" \
    "a5='$(jget responses.4 <<<"$IMAP_OUT")' a6='$(jget responses.5 <<<"$IMAP_OUT")' upstream: $(tr '\n' '|' <<<"$IMAP_LOG")"
fi

e2e_timer_start
A7=$(jget responses.6 <<<"$IMAP_OUT")
if [[ "$A7" == *"a7 NO"*"denied by folder_denylist"* ]] && ! grep -q '^a7 ' <<<"$IMAP_LOG"; then
  e2e_pass "9.5" "IMAP: folder_denylist refuses SELECT Trash"
else
  e2e_fail "9.5" "IMAP: folder_denylist refuses SELECT Trash" "a7='$A7'"
fi

e2e_timer_start
if wait_audit '"imap_command"' '"blocked"' 'EXPUNGE' &&
   wait_audit '"imap_command"' '"blocked"' 'Trash'; then
  e2e_pass "9.6" "IMAP: refusals audited"
else
  e2e_fail "9.6" "IMAP: refusals audited" \
    "imap records: $(audit_lines | grep imap_command | tail -5 | tr '\n' '|')"
fi

# ── 9.7–9.10: SMTP relay ─────────────────────────────────────────────
e2e_timer_start
OUT=$(probe smtp egress 2025 agent@example.com bob@example.com "e2e-normal-message-1")
if [[ "$(jget end <<<"$OUT")" == 250* ]] && grep -q 'e2e-normal-message-1' <<<"$(svc_log smtp.jsonl)" &&
   wait_audit '"smtp_data"' '"allowed"'; then
  e2e_pass "9.7" "SMTP: message delivered and audited"
else
  e2e_fail "9.7" "SMTP: message delivered and audited" \
    "session: $OUT; delivered: $(svc_log smtp.jsonl | tr '\n' '|')"
fi

# A credential-shaped string in the body: the secrets inspector runs on
# relayed mail too (bypass_inspectors_for_allowlisted: [] keeps it on for
# the allowlisted recipient). Assembled at run time so the repository
# holds no complete key-shaped literal.
e2e_timer_start
FAKE_KEY="sk-ant-""api03-$(printf 'e2eQ%.0s' $(seq 1 10))"
OUT=$(probe smtp egress 2025 agent@example.com bob@example.com "e2e-secret-message key=$FAKE_KEY")
if [[ "$(jget end <<<"$OUT")" == 550* ]] && ! grep -q 'e2e-secret-message' <<<"$(svc_log smtp.jsonl)" &&
   wait_audit '"smtp_data"' '"blocked"'; then
  e2e_pass "9.8" "SMTP: message with a secret blocked"
else
  e2e_fail "9.8" "SMTP: message with a secret blocked" "session: $OUT"
fi

e2e_timer_start
OUT=$(probe smtp egress 2025 agent@example.com eve@evil.e2e.test "e2e-wrong-recipient")
if [[ "$(jget rcpt.0 <<<"$OUT")" == 550* ]] && ! grep -q 'e2e-wrong-recipient' <<<"$(svc_log smtp.jsonl)" &&
   wait_audit '"smtp_command"' '"blocked"' 'eve@evil.e2e.test'; then
  e2e_pass "9.9" "SMTP: recipient allowlist enforced"
else
  e2e_fail "9.9" "SMTP: recipient allowlist enforced" "session: $OUT"
fi

# The client disconnects half way through DATA (no final "."): the relay
# must not deliver what it has so far.
e2e_timer_start
OUT=$(probe smtp egress 2025 agent@example.com bob@example.com "e2e-aborted-message" abort)
sleep 2
if [[ "$(jget data <<<"$OUT")" == 354* ]] && ! grep -q 'e2e-aborted-message' <<<"$(svc_log smtp.jsonl)"; then
  e2e_pass "9.10" "SMTP: mid-DATA disconnect not delivered"
else
  e2e_fail "9.10" "SMTP: mid-DATA disconnect not delivered" \
    "session: $OUT; delivered: $(svc_log smtp.jsonl | tr '\n' '|')"
fi

# ── 9.11–9.18: Policy API with a stub decider ────────────────────────
e2e_timer_start
OUT=$(probe api GET /v1/health)
if [ "$(jget status <<<"$OUT")" = "200" ] && [ "$(jget body <<<"$OUT" | jget status)" = "ok" ]; then
  e2e_pass "9.11" "Policy API: GET /v1/health"
else
  e2e_fail "9.11" "Policy API: GET /v1/health" "got: $OUT"
fi

e2e_timer_start
OUT=$(probe api GET /v1/allowlist)
if [ "$(jget status <<<"$OUT")" = "200" ] && [[ "$(jget body <<<"$OUT")" == *'"httpbin.org"'* ]]; then
  e2e_pass "9.12" "Policy API: GET /v1/allowlist"
else
  e2e_fail "9.12" "Policy API: GET /v1/allowlist" "got: $OUT"
fi

# example.net is not reachable before the grant...
BEFORE=$(probe get http://example.net/before)

# ...the stub grants it (the egress may take a moment to apply the
# rewritten base_url, so retry while the answer is an LLM failure)...
e2e_timer_start
for _ in $(seq 1 10); do
  OUT=$(probe api POST /v1/allowlist/requests '{"domain":"example.net","reason":"e2e: the stub grants this"}')
  [ "$(jget status <<<"$OUT")" = "200" ] && break
  sleep 2
done
GRANT_BODY=$(jget body <<<"$OUT")
if [ "$(jget status <<<"$OUT")" = "200" ] && [ "$(jget status <<<"$GRANT_BODY")" = "granted" ] &&
   grep '"tool": "decide"' <<<"$(svc_log llm.jsonl)" | grep '"domain": "example.net"' |
     grep -cF "\"x_api_key\": \"$LLM_KEY\"" >/dev/null; then
  e2e_pass "9.13" "Policy API: stub decider grants"
else
  e2e_fail "9.13" "Policy API: stub decider grants" \
    "got: $OUT; stub saw: $(svc_log llm.jsonl | tail -3 | tr '\n' '|')"
fi

# ...and the grant is live: published to the cage's DNS (the egress's
# granted-names file, which dnsmasq is rendered from) and admitted by the
# egress's allowlist — the name is no longer refused as outside it. The
# request still does not reach the mock, and must not: the mock is on
# loopback, and a host allowed ONLY by a grant that resolves to a
# non-global address is refused by the peer guard (a grant must never
# become a way into the egress's own networks). So the block reason
# changes from the allowlist's to the guard's, which pins both.
e2e_timer_start
AFTER=""
for _ in $(seq 1 20); do
  AFTER=$(probe get http://example.net/after)
  [[ "$(jget body <<<"$AFTER" | jget reason)" == "granted domain example.net "*"non-global address"* ]] && break
  sleep 1
done
PUBLISHED=$(podman exec "${CAGE}-egress" cat /home/acproxy/dns/granted 2>/dev/null || true)
if [[ "$(jget body <<<"$BEFORE" | jget reason)" == "domain not in allowlist: example.net" ]] &&
   [ "$(jget status <<<"$AFTER")" = "403" ] &&
   [[ "$(jget body <<<"$AFTER" | jget reason)" == "granted domain example.net "*"non-global address"* ]] &&
   grep -qx 'example.net' <<<"$PUBLISHED" &&
   [[ "$(probe api GET /v1/allowlist)" == *example.net* ]]; then
  e2e_pass "9.14" "Policy API: grant published and admitted"
else
  e2e_fail "9.14" "Policy API: grant published and admitted" \
    "before: $BEFORE; after: $AFTER; dns/granted: $(tr '\n' ' ' <<<"$PUBLISHED")"
fi

e2e_timer_start
if grep -q 'example.net' <<<"$("$AGENTCAGE" cage grants "$CAGE" list 2>&1)"; then
  e2e_pass "9.15" "Host CLI: cage grants list shows the grant"
else
  e2e_fail "9.15" "Host CLI: cage grants list shows the grant" \
    "$("$AGENTCAGE" cage grants "$CAGE" list 2>&1 | tail -5 | tr '\n' '|')"
fi

e2e_timer_start
OUT=$(probe api POST /v1/allowlist/requests '{"domain":"deny.example.org","reason":"e2e: the stub denies this"}')
BODY=$(jget body <<<"$OUT")
if [ "$(jget status <<<"$OUT")" = "403" ] && [ "$(jget status <<<"$BODY")" = "denied" ] &&
   [ "$(jget reason <<<"$BODY")" = "stub denies deny.example.org" ]; then
  e2e_pass "9.16" "Policy API: stub denial → 403 with its reason"
else
  e2e_fail "9.16" "Policy API: stub denial → 403 with its reason" "got: $OUT"
fi

# The never-grant floor answers before any LLM call: a wildcard-DNS name
# encoding a private address is refused, not retryable, and the stub never
# hears of it.
e2e_timer_start
OUT=$(probe api POST /v1/allowlist/requests '{"domain":"10-0-0-1.nip.io","reason":"e2e: never grantable"}')
BODY=$(jget body <<<"$OUT")
if [ "$(jget status <<<"$OUT")" = "403" ] && [ "$(jget retryable <<<"$BODY")" = "false" ] &&
   ! grep -q 'nip.io' <<<"$(svc_log llm.jsonl)"; then
  e2e_pass "9.17" "Policy API: never-grant floor (encoded IP)"
else
  e2e_fail "9.17" "Policy API: never-grant floor (encoded IP)" "got: $OUT"
fi

# The agent gives grants back: out of the published names, the host's
# view and the allowlist. example.net stays refused whatever its grant
# says — both engines remember a host caught resolving to a non-global
# address for the life of the process — so the allowlist half is shown on
# a second grant, example.org, never fetched while granted: once removed,
# a request for it is refused as outside the allowlist again.
e2e_timer_start
GRANT2=$(probe api POST /v1/allowlist/requests '{"domain":"example.org","reason":"e2e: granted, then given back"}')
LISTED=$(probe api GET /v1/allowlist)
OUT=$(probe api POST /v1/allowlist/removals '{"domain":"example.net"}')
OUT2=$(probe api POST /v1/allowlist/removals '{"domain":"example.org"}')
GONE=""
for _ in $(seq 1 20); do
  GONE=$(probe get http://example.org/gone)
  [ "$(jget body <<<"$GONE" | jget reason)" = "domain not in allowlist: example.org" ] && break
  sleep 1
done
PUBLISHED=$(podman exec "${CAGE}-egress" cat /home/acproxy/dns/granted 2>/dev/null || true)
GRANTS=$("$AGENTCAGE" cage grants "$CAGE" list 2>&1)
if [ "$(jget status <<<"$GRANT2")" = "200" ] && [[ "$LISTED" == *example.org* ]] &&
   [ "$(jget body <<<"$OUT" | jget status)" = "removed" ] &&
   [ "$(jget body <<<"$OUT2" | jget status)" = "removed" ] &&
   [ "$(jget body <<<"$GONE" | jget reason)" = "domain not in allowlist: example.org" ] &&
   ! grep -qE '^example\.(net|org)$' <<<"$PUBLISHED" &&
   ! grep -qE 'example\.(net|org)' <<<"$GRANTS"; then
  e2e_pass "9.18" "Policy API: removal revokes the grant"
else
  e2e_fail "9.18" "Policy API: removal revokes the grant" \
    "grant: $GRANT2; removals: $OUT $OUT2; fetch after: $GONE; dns/granted: $(tr '\n' ' ' <<<"$PUBLISHED"); grants: $(tr '\n' '|' <<<"$GRANTS")"
fi

# ── 9.19–9.20: WebSocket ─────────────────────────────────────────────
e2e_timer_start
# The Policy API tests just above rewrite the egress config and grants;
# the first upgrade can land on a reload in progress, so give it three
# attempts. A real WebSocket regression fails all three.
for _attempt in 1 2 3; do
  OUT=$(probe ws ws://httpbin.org/ws "e2e-ws-hello")
  REPLY=$(jget reply <<<"$OUT")
  [ "$(jget echo <<<"$REPLY")" = "e2e-ws-hello" ] && break
  sleep 2
done
if [ "$(jget echo <<<"$REPLY")" = "e2e-ws-hello" ] &&
   [ "$(jget sha256 <<<"$REPLY")" = "$(sha256 "e2e-ws-hello")" ]; then
  e2e_pass "9.19" "WebSocket: message round trip"
else
  e2e_fail "9.19" "WebSocket: message round trip" "got: $OUT"
fi

# The placeholder goes out, the real value reaches the mock (its digest
# proves it), and the echo carrying the real value comes back redacted to
# the placeholder.
e2e_timer_start
WS_PH=$("$AGENTCAGE" cage exec "$CAGE" -- printenv WS_TOKEN 2>/dev/null | tr -d '\r' | tail -n1 || true)
OUT=$(probe ws ws://httpbin.org/ws "token=$WS_PH")
REPLY=$(jget reply <<<"$OUT")
if [ -n "$WS_PH" ] && [ "$WS_PH" != "$WS_VALUE" ] &&
   [ "$(jget sha256 <<<"$REPLY")" = "$(sha256 "token=$WS_VALUE")" ] &&
   [ "$(jget echo <<<"$REPLY")" = "token=$WS_PH" ]; then
  e2e_pass "9.20" "WebSocket: placeholder injected, echo redacted"
else
  e2e_fail "9.20" "WebSocket: placeholder injected, echo redacted" \
    "placeholder='$WS_PH' got: $OUT (want sha256 of token=<real value>: $(sha256 "token=$WS_VALUE"))"
fi

# ── 9.21–9.22: passthrough ───────────────────────────────────────────
# SNI pt.e2e.test to the address the name resolves to: spliced, so the
# cage sees the mock's self-signed certificate, not one from the cage CA.
e2e_timer_start
OUT=$(probe tls-peer egress 443 pt.e2e.test)
if [ "$(jget issuerO <<<"$OUT")" = "e2e passthrough mock" ] &&
   ! grep 'pt.e2e.test' <<<"$(audit_lines)" | grep -c '"method"' >/dev/null; then
  e2e_pass "9.21" "Passthrough: upstream's own certificate"
else
  e2e_fail "9.21" "Passthrough: upstream's own certificate" \
    "got: $OUT; egress ip: ${EGRESS_IP:-?}; audit: $(audit_lines | grep 'pt.e2e.test' | tail -2 | tr '\n' '|')"
fi

# D4 (EGRESS-PORT-PLAN.md §2): the same SNI to an address that is NOT one
# of the name's must be intercepted, not spliced — otherwise any IP is an
# uninspected tunnel for a cage that names a passthrough domain. The
# Python egress predates D4 and splices on the SNI alone, so the
# assertion is Rust-only.
if [ "$ENGINE" = "rust" ]; then
  e2e_timer_start
  OUT=$(probe tls-peer 192.0.2.10 443 pt.e2e.test)
  if [[ "$(jget issuer <<<"$OUT")" == "agentcage egress CA"* ]]; then
    e2e_pass "9.22" "Passthrough: spoofed SNI intercepted (D4)"
  else
    e2e_fail "9.22" "Passthrough: spoofed SNI intercepted (D4)" "got: $OUT"
  fi
else
  e2e_skip "9.22" "Passthrough: spoofed SNI intercepted (D4)" \
    "Python egress has no D4 check: it splices on the SNI alone"
fi

# ── 9.23: traffic watcher ────────────────────────────────────────────
# One scan against the stub: the watcher's first scan is due 60-90 s after
# the egress started (interval_seconds: 60, jittered), and the phase's
# traffic gives it a non-empty window. The stub reports one finding.
# Counted against the findings present at setup: a cage's data directory
# (capture, grants, watcher output) outlives `cage destroy`, so a previous
# run's finding may already be listed.
e2e_timer_start
FOUND=false
for _ in $(seq 1 45); do
  if [ "$(stub_findings)" -gt "$FINDINGS_BEFORE" ]; then
    FOUND=true
    break
  fi
  sleep 4
done
STATUS_RC=0
STATUS=$("$AGENTCAGE" watcher status "$CAGE" 2>&1) || STATUS_RC=$?
LLM_LOG=$(svc_log llm.jsonl)
if [ "$FOUND" = true ] && grep -q '"tool": "review"' <<<"$LLM_LOG" &&
   [ "$STATUS_RC" = 0 ] && grep -qE 'scans run: +[1-9]' <<<"$STATUS"; then
  e2e_pass "9.23" "Watcher: a scan with the stub records a finding"
else
  e2e_fail "9.23" "Watcher: a scan with the stub records a finding" \
    "found=$FOUND; status (rc $STATUS_RC): $(tr '\n' '|' <<<"$STATUS"); stub calls: $(tail -3 <<<"$LLM_LOG" | tr '\n' '|')"
fi

print_results
