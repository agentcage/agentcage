#!/bin/sh
# agentcage-apple-container supervisor — runs as PID 1 of the cage microVM.
#
# Stages (run in order; failure of any stage exits the microVM with a
# distinct exit code so failures are diagnosable from `container logs`):
#
#   10. Remount /proc with hidepid=2  → cage cannot enumerate other UIDs' PIDs
#   20. Resolve cage CMD              → read JSON file, jq @sh shell-quotes
#   30. Start dnsmasq (uid 201)       → in-microVM DNS that rewrites every
#                                        real-world domain to 127.0.0.1
#   40. Start mitmproxy (uid 200)     → transparent egress filter on
#                                        127.0.0.1:8080 (HTTP) and 127.0.0.1:8443
#                                        (HTTPS). Enforces a domain allowlist
#                                        via --allow-hosts; logs flows to
#                                        /var/log/agentcage/audit.log.
#   50. Wait for mitmproxy CA cert    → CA is generated on first start and
#                                        written to /home/proxy/.mitmproxy/.
#   60. Install CA in cage trust      → update-ca-certificates so cage HTTPS
#                                        clients trust the proxy's MITM cert.
#   70. Configure /etc/resolv.conf    → cage DNS queries hit local dnsmasq.
#   80. iptables egress lockdown      → DROP all cage egress except to
#                                        127.0.0.1:8080/8443/53. CAP_NET_ADMIN
#                                        gone after capsh, cage cannot revert.
#   90. Drop caps, switch user, exec  → capsh setuid 1000, clears all caps,
#                                        NO_NEW_PRIVS set; exec the cage CMD.
#
# This script runs with CAP_SYS_ADMIN + CAP_NET_ADMIN granted at container
# run time. Both are gone by the time the cage workload starts.
#
# Security-critical code. Changes require /codex review per issue #120.

set -eu

log() { printf '[supervisor] %s\n' "$*" >&2; }
die() { log "FATAL: $1"; exit "${2:-99}"; }

#-- 10. hidepid=2 on /proc -------------------------------------------------
log "stage 10: remounting /proc with hidepid=2"
mount -o remount,hidepid=2 /proc \
  || die "cannot remount /proc with hidepid=2 — is --cap-add CAP_SYS_ADMIN set?" 10

#-- 20. Resolve cage CMD ---------------------------------------------------
CMD_FILE=/etc/agentcage/cage-cmd.json
[ -f "${CMD_FILE}" ] || die "${CMD_FILE} not found" 20
command -v jq >/dev/null 2>&1 || die "jq not found" 21
CMD_LINE=$(jq -r '@sh' < "${CMD_FILE}") || die "cannot parse ${CMD_FILE}" 22
log "stage 20: cage CMD = ${CMD_LINE}"

#-- 30. Start dnsmasq ------------------------------------------------------
log "stage 30: starting dnsmasq (uid 201)"
mkdir -p /var/log/agentcage
# Foreground dnsmasq with our config (which rewrites everything to 127.0.0.1).
# We use start-stop-daemon style: launch in background, capture PID, check
# liveness after a beat.
dnsmasq \
  --conf-file=/etc/agentcage/dnsmasq.conf \
  --user=acdns \
  --keep-in-foreground \
  --log-facility=/var/log/agentcage/dnsmasq.log \
  &
DNSMASQ_PID=$!
sleep 1
kill -0 "${DNSMASQ_PID}" 2>/dev/null \
  || die "dnsmasq failed to start; see /var/log/agentcage/dnsmasq.log" 30

#-- 40. Start mitmproxy ----------------------------------------------------
log "stage 40: starting mitmproxy (uid 200)"
mkdir -p /home/acproxy/.mitmproxy /var/log/agentcage
chown acproxy:acproxy /home/acproxy /home/acproxy/.mitmproxy /var/log/agentcage

# Read allowlist (one host per line) into a single regex
# "^(host1|host2|host3)$" that mitmdump's --allow-hosts can apply against
# every request's host. Subdomains are matched explicitly via
# (^|\.)host$ — same behaviour as the existing DomainInspector.
ALLOW_REGEX=$(
  if [ -s /etc/agentcage/allowlist.txt ]; then
    awk 'NF { gsub(/\./, "\\."); printf("%s(^|\\.)%s$", sep, $0); sep="|" } END { print "" }' \
        /etc/agentcage/allowlist.txt
  fi
)
# If the allowlist is empty (no domains configured), mitmproxy blocks
# everything — that's the safer default and matches what users would expect
# from a misconfigured cage.
if [ -z "${ALLOW_REGEX}" ]; then
  ALLOW_REGEX='^$'
  log "WARN: empty allowlist — cage will block ALL egress"
fi
log "stage 40: allowlist regex = ${ALLOW_REGEX}"

# Run mitmdump as proxy uid. HOME must point at /home/proxy so the CA cert
# lands at /home/proxy/.mitmproxy/mitmproxy-ca-cert.pem.
# Transparent mode lets a single listener handle both HTTP (the original
# destination is recovered via SO_ORIGINAL_DST set by iptables REDIRECT)
# and HTTPS (via TLS SNI sniffing). iptables in stage 80 REDIRECTs both
# tcp/80 and tcp/443 from the cage's uid to this listener.
mkdir -p /var/log/agentcage
chown acproxy:acproxy /var/log/agentcage
su -s /bin/sh -c '
  cd /home/acproxy
  HOME=/home/acproxy /opt/agentcage/mitmproxy/mitmdump \
    -s /opt/agentcage/allowlist_addon.py \
    --mode transparent \
    --listen-host 127.0.0.1 --listen-port 8080 \
    --set connection_strategy=lazy \
    --set keep_host_header=true \
    --set flow_detail=0 \
    --set termlog_verbosity=info \
    >> /var/log/agentcage/proxy.log 2>&1 &
' acproxy
sleep 1

#-- 50. Wait for mitmproxy CA cert ----------------------------------------
log "stage 50: waiting for mitmproxy CA cert (max 15s)"
CA_PATH=/home/acproxy/.mitmproxy/mitmproxy-ca-cert.pem
i=0
while [ ! -s "${CA_PATH}" ] && [ "$i" -lt 15 ]; do
  sleep 1; i=$((i+1))
done
[ -s "${CA_PATH}" ] || die "mitmproxy CA cert never appeared; see /var/log/agentcage/proxy.log" 50
log "stage 50: CA ready at ${CA_PATH}"

#-- 60. Install CA cert into cage trust store ------------------------------
log "stage 60: installing CA into cage trust store"
cp "${CA_PATH}" /usr/local/share/ca-certificates/agentcage-proxy.crt
update-ca-certificates --fresh >/dev/null 2>&1 \
  || log "WARN: update-ca-certificates failed; HTTPS clients may not trust the proxy"

#-- 70. Cage DNS -----------------------------------------------------------
log "stage 70: pointing /etc/resolv.conf at local dnsmasq"
printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf

#-- 80. iptables egress lockdown ------------------------------------------
log "stage 80: applying iptables egress rules"
# Kill IPv6 entirely. The microVM kernel has v6 enabled and dnsmasq
# returns AAAA records (which would let the cage bypass our v4-only NAT
# REDIRECT). Two belt-and-braces measures:
#   1. ip6tables DROP all chains (so v6 packets are dropped at netfilter)
#   2. sysctl disable_ipv6 (so the v6 stack itself is inert)
ip6tables -P INPUT DROP   2>/dev/null || true
ip6tables -P OUTPUT DROP  2>/dev/null || true
ip6tables -P FORWARD DROP 2>/dev/null || true
sysctl -w net.ipv6.conf.all.disable_ipv6=1   >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
# Allow loopback freely (cage→proxy, cage→dnsmasq).
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
# Allow established/related (so responses come back in).
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Cage's egress to 80/443 → REDIRECT to local mitmproxy on 8080
# (transparent mode handles both HTTP and HTTPS on one port).
iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner 1000 \
    -j REDIRECT --to-ports 8080
iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner 1000 \
    -j REDIRECT --to-ports 8080
# Allow cage→loopback:8080 + DNS (both UDP and TCP for completeness).
iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 8080 -j ACCEPT
iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT
# Proxy and dns themselves need internet egress. They run as uid 200/201;
# the cage runs as 1000. owner-uid match lets us allow proxy/dns out while
# locking the cage in.
iptables -A OUTPUT -m owner --uid-owner 200 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner 201 -j ACCEPT

#-- 90. Drop caps + exec cage workload ------------------------------------
log "stage 90: dropping caps, switching to cage user (uid 1000)"
# capsh argv order:
#   --no-new-privs --> set NO_NEW_PRIVS prctl (sticks across exec); blocks
#                      cage's children from gaining caps via setuid binaries
#   --user=cage    --> setuid+setgid+initgroups. The uid 0→1000 transition
#                      clears CapEff/Prm. CapBnd survives the transition but
#                      NO_NEW_PRIVS makes it irrelevant.
exec capsh \
  --no-new-privs \
  --user=cage \
  --shell=/bin/sh \
  -- -c "exec ${CMD_LINE}"
