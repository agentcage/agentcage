#!/bin/sh
# agentcage-egress supervisor — runs under tini (PID 1) inside the
# unified egress container. Mirrors stages 30-50 of the apple-container
# supervisor (dnsmasq → wait → mitmproxy → wait), adapted for the
# router-shaped FORWARD-chain iptables model instead of the in-netns
# OUTPUT-chain model the apple-container uses.
#
# Strict ordering: each step must complete (or be ready) before the next
# starts, so `touch /var/log/agentcage/ready` in step F means iptables is
# applied AND dnsmasq is listening AND mitmproxy is listening AND
# mitmproxy has produced its CA cert. PR 2's backend health-checks read
# that marker before declaring the cage ready.
#
# POSIX sh, not bash — no `wait -n`, no arrays, no `[[ ]]`. Test with
# `dash` if possible.
set -eu

log() { printf '[egress-supervisor] %s\n' "$*" >&2; }
die() { log "FATAL: $1"; exit "${2:-99}"; }

#-- Step A. iptables setup -------------------------------------------------
# The egress container acts as a ROUTER between the cage netns and the
# internet (NOT an in-netns OUTPUT filter — that's the apple-container
# shape, where the proxy/dns/cage workloads share a netns). Here, traffic
# from the cage enters via eth0; we REDIRECT inspected tcp ports to the
# local mitmproxy on :8443 and apply a default-DROP FORWARD policy.
INSPECTED_TCP_PORTS="80 443"
PASSTHROUGH_TCP_PORTS=""
ALLOW_UDP_PORTS=""
if [ -f /etc/agentcage/iptables.env ]; then
  # shellcheck disable=SC1091
  . /etc/agentcage/iptables.env
fi
log "step A: iptables setup (inspected=[$INSPECTED_TCP_PORTS] passthrough=[$PASSTHROUGH_TCP_PORTS] udp=[$ALLOW_UDP_PORTS])"

for port in $INSPECTED_TCP_PORTS; do
  iptables -t nat -A PREROUTING -i eth0 -p tcp --dport "$port" -j REDIRECT --to-ports 8443 \
    || die "iptables PREROUTING REDIRECT failed (port $port)" 10
done

iptables -P FORWARD DROP \
  || die "iptables FORWARD DROP policy failed" 11
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
  || die "iptables FORWARD established/related accept failed" 12
iptables -A FORWARD -p icmp --icmp-type echo-request -j ACCEPT \
  || die "iptables FORWARD icmp echo-request accept failed" 13

for port in $PASSTHROUGH_TCP_PORTS; do
  iptables -A FORWARD -p tcp --dport "$port" -j ACCEPT \
    || die "iptables FORWARD passthrough tcp accept failed (port $port)" 14
done
for port in $ALLOW_UDP_PORTS; do
  iptables -A FORWARD -p udp --dport "$port" -j ACCEPT \
    || die "iptables FORWARD allow udp accept failed (port $port)" 15
done

# IPv6 forwarding default-DROP. Best-effort — some kernels (notably
# minimal CI environments) ship without ip6tables loaded; loud DROP is
# still preferable to silent forwarding so we keep it best-effort here.
ip6tables -P FORWARD DROP 2>/dev/null || log "warn: ip6tables FORWARD DROP unavailable (no v6 stack?)"

sysctl -w net.ipv4.ip_forward=1 >/dev/null \
  || die "sysctl net.ipv4.ip_forward=1 failed (need NET_ADMIN cap?)" 16
sysctl -w net.ipv4.ip_unprivileged_port_start=80 >/dev/null \
  || die "sysctl net.ipv4.ip_unprivileged_port_start=80 failed" 17

#-- Step B. Start dnsmasq (uid 201, CapBnd=cap_net_bind_service only) -----
# dnsmasq must bind :53 (privileged port). It carries the file cap
# `cap_net_bind_service=+ep` set in the Containerfile. For that file cap
# to take effect on execve(), TWO conditions must hold:
#   1. The process's bounding set MUST contain cap_net_bind_service
#      (otherwise the kernel silently drops it).
#   2. NoNewPrivs MUST NOT be set (per capabilities(7): "If the
#      no_new_privs bit is set then file capabilities are silently
#      not granted on execve(2)").
# So we keep --bounding-set=-all,+cap_net_bind_service (drops EVERYTHING
# except the one cap dnsmasq needs) and we CANNOT use --no-new-privs.
#
# This is still safe against the B3-eng-review concern (compromised
# dnsmasq exec'ing setuid-root to reacquire NET_ADMIN): the bounding
# set ⊇ CapBnd of any child process, and we've reduced it to just
# cap_net_bind_service. A setuid-root child becomes uid 0 with CapBnd =
# {cap_net_bind_service} — it can bind privileged ports but cannot
# iptables -F, cannot mount, cannot iptables anything.
#
# TODO(measurement): --as=256M for dnsmasq covers a 10k-entry allowlist
# with headroom (eyeballed from the apple-container supervisor's working
# set). Provisional — tune after measurement in a follow-up PR.
log "step B: starting dnsmasq (uid 201, CapBnd={net_bind_service}, prlimit --as=256M)"
if [ -f /etc/agentcage/dnsmasq.conf ]; then
  prlimit --as=$((256 * 1024 * 1024)) -- \
    setpriv --reuid=acdns --regid=acdns --clear-groups \
            --bounding-set=-all,+net_bind_service --inh-caps=-all -- \
    /opt/agentcage/dns-audit.sh \
      /usr/sbin/dnsmasq -k \
        --pid-file=/run/dnsmasq.pid \
        --conf-file=/etc/agentcage/dnsmasq.conf \
        --servers-file=/etc/agentcage/dns-allowlist.conf \
    &
else
  # Smoke-test path: no per-cage config staged yet. Start dnsmasq with a
  # minimal inline default so the supervisor can still come up and the
  # smoke test can exercise the listener readiness path.
  log "step B: no /etc/agentcage/dnsmasq.conf — using inline smoke-test defaults"
  prlimit --as=$((256 * 1024 * 1024)) -- \
    setpriv --reuid=acdns --regid=acdns --clear-groups \
            --bounding-set=-all,+net_bind_service --inh-caps=-all -- \
    /usr/sbin/dnsmasq -k \
      --pid-file=/run/dnsmasq.pid \
      --no-resolv --no-hosts \
      --listen-address=0.0.0.0 --port=53 \
      --domain-needed --bogus-priv \
    &
fi
DNSMASQ_PID=$!

#-- Step C. Wait for dnsmasq listening on :53 ------------------------------
log "step C: waiting for dnsmasq to bind :53 (max 30s)"
i=0
while [ "$i" -lt 30 ]; do
  if ss -lnup 2>/dev/null | grep -q ':53 '; then
    break
  fi
  if ! kill -0 "$DNSMASQ_PID" 2>/dev/null; then
    die "dnsmasq exited before binding :53" 30
  fi
  sleep 1; i=$((i+1))
done
ss -lnup 2>/dev/null | grep -q ':53 ' \
  || die "dnsmasq did not bind :53 within 30s" 31

#-- Step D. Start mitmproxy (uid 200, CapBnd-stripped) ---------------------
# Same CapBnd-drop flags as dnsmasq above — see step B for rationale.
#
# TODO(measurement): --as=2G for mitmproxy covers PyInstaller's ~700MB
# mmap overhead plus runtime working set with headroom. Provisional —
# tune after measurement in a follow-up PR.
log "step D: starting mitmproxy (uid 200, CapBnd=0, prlimit --as=2G)"
if [ -f /etc/agentcage/addon.py ]; then
  prlimit --as=$((2 * 1024 * 1024 * 1024)) -- \
    setpriv --reuid=acproxy --regid=acproxy --clear-groups \
            --no-new-privs --bounding-set=-all --inh-caps=-all -- \
    env HOME=/home/acproxy \
    /opt/agentcage/mitmproxy/mitmdump \
      -s /etc/agentcage/addon.py \
      --mode regular@:8080 \
      --mode transparent@8443 \
      --set connection_strategy=lazy \
    &
else
  # Smoke-test path: no addon staged. Run mitmproxy with default
  # behavior so the listener and CA generation paths can be exercised.
  log "step D: no /etc/agentcage/addon.py — skipping -s addon"
  prlimit --as=$((2 * 1024 * 1024 * 1024)) -- \
    setpriv --reuid=acproxy --regid=acproxy --clear-groups \
            --no-new-privs --bounding-set=-all --inh-caps=-all -- \
    env HOME=/home/acproxy \
    /opt/agentcage/mitmproxy/mitmdump \
      --mode regular@:8080 \
      --mode transparent@8443 \
      --set connection_strategy=lazy \
    &
fi
MITMPROXY_PID=$!

#-- Step E. Wait for mitmproxy listening on :8443 + CA cert ----------------
# Both conditions must hold: if we only check the port the supervisor
# can finish before mitmproxy has written its CA, and PR 2's trust-store
# install step would race. Conversely, the CA file appears slightly
# before the listener accepts connections, so a CA-only check has a
# false-positive window where the cage workload would get
# "connection refused" from the REDIRECT target.
log "step E: waiting for mitmproxy listener :8443 AND CA cert (max 30s)"
CA_PATH=/home/acproxy/.mitmproxy/mitmproxy-ca-cert.pem
i=0
while [ "$i" -lt 30 ]; do
  if [ -s "$CA_PATH" ] && ss -lnt 2>/dev/null | grep -q ':8443 '; then
    break
  fi
  if ! kill -0 "$MITMPROXY_PID" 2>/dev/null; then
    die "mitmproxy exited before listener+CA ready" 50
  fi
  sleep 1; i=$((i+1))
done
[ -s "$CA_PATH" ] \
  || die "mitmproxy CA cert never appeared at $CA_PATH within 30s" 51
ss -lnt 2>/dev/null | grep -q ':8443 ' \
  || die "mitmproxy listener never came up on :8443 within 30s" 52
log "step E: mitmproxy ready (CA at $CA_PATH, listening on :8443)"

#-- Step F. Readiness marker -----------------------------------------------
# Backends (PR 2) poll for this file to declare the cage ready. Must be
# the LAST thing the supervisor does before entering the monitor loop —
# anything written before this point is part of the readiness contract.
touch /var/log/agentcage/ready
log "step F: ready marker written; entering monitor loop"

#-- Step G. Monitor loop ---------------------------------------------------
# Two `kill -0` polls in the while condition — dash has no `wait -n`, so
# we just sleep+poll. tini handles SIGCHLD reaping and SIGTERM
# propagation, so once either child dies the kill -0 fails on the next
# iteration and we exit 1 — tini will then propagate the exit to the
# container runtime.
while kill -0 "$DNSMASQ_PID" 2>/dev/null && kill -0 "$MITMPROXY_PID" 2>/dev/null; do
  sleep 1
done
echo "child died, exiting" >&2
exit 1
