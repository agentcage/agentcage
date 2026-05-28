#!/bin/sh
# agentcage-apple-container cage-init — PID 1 of the slim cage microVM.
#
# This script replaces the 329-line supervisor.sh from the legacy single-
# microVM model. In the 2-microVM model (PR 3 of #196), mitmproxy + dnsmasq
# + iptables live in a sibling <cage>-egress microVM (built from the
# shared agentcage-egress image). This cage microVM contains only the
# user's workload + this tiny init script — no proxy, no DNS, no
# iptables, no jq, no secrets.
#
# Stages:
#   A. Wait for the egress sibling to be ARP-reachable. Apple's container
#      network plugin is eventually-consistent; without this wait the
#      `ip route replace default` below can succeed before the L2 path
#      is populated, blackholing the first packets.
#   B. Replace the default route with one via the egress sibling. The
#      egress container's iptables PREROUTING REDIRECTs cage tcp/80 +
#      tcp/443 to its in-process mitmproxy on :8443 — same flow shape as
#      container/vm in PR 2.
#   C. Best-effort install the proxy CA into the system trust store. The
#      egress sibling writes mitmproxy-ca-cert.pem into a shared /certs
#      bind-mount; we race the egress's first-startup write briefly.
#   D. capsh-drop NoNewPrivs + bounding set + setuid to the uid-1000
#      user, then exec the user's original argv via the shell-escaped
#      one-shot script baked at image build time (see Containerfile.j2's
#      cage-cmd.sh — shlex.quote'd host-side so no metacharacter risk).
#
# Runs as root with --cap-add CAP_NET_ADMIN granted at container run.
# CAP_NET_ADMIN is needed for stage B's `ip route replace`; capsh drops
# it before the workload runs.
#
# POSIX sh, not bash — Apple's `container run` execs us directly without
# a login shell; we must not depend on bash-isms.
set -eu

log() { printf '[cage-init] %s\n' "$*" >&2; }
die() { log "FATAL: $1"; exit "${2:-99}"; }

#-- Stage A. Wait for egress sibling reachable -----------------------------
# AGENTCAGE_EGRESS_IP is passed by the backend's `start()` after reading
# `container inspect <name>-egress`'s allocated IP. ping -c 1 -W 1
# returns 0 on the first ICMP reply, so 30 attempts at 0.5s gives us up
# to ~15s of L2 grace — enough for Apple's network plugin without making
# the failure case feel like a hang.
[ -n "${AGENTCAGE_EGRESS_IP:-}" ] \
  || die "AGENTCAGE_EGRESS_IP env var unset; backend must pass it via --env" 1

log "stage A: waiting for egress sibling ${AGENTCAGE_EGRESS_IP} to be ARP-reachable"
egress_ok=0
i=0
while [ "$i" -lt 30 ]; do
  if ping -c 1 -W 1 "${AGENTCAGE_EGRESS_IP}" >/dev/null 2>&1; then
    egress_ok=1
    break
  fi
  sleep 0.5
  i=$((i + 1))
done
[ "$egress_ok" -eq 1 ] \
  || die "egress sibling at ${AGENTCAGE_EGRESS_IP} unreachable after 30 attempts" 1

#-- Stage B. Default route via egress sibling ------------------------------
# `ip route replace` is idempotent — equivalent to `add` if missing or
# `change` if present, so we can re-run cage-init (e.g. cage restart)
# without `del then add` racing.
log "stage B: setting default route via ${AGENTCAGE_EGRESS_IP}"
ip route replace default via "${AGENTCAGE_EGRESS_IP}" \
  || die "failed to set default route via ${AGENTCAGE_EGRESS_IP} — CAP_NET_ADMIN missing?" 2

#-- Stage C. Install proxy CA into the cage's trust store -----------------
# The egress sibling writes mitmproxy-ca-cert.pem into the shared /certs
# bind-mount on its first startup. Cage and egress mount the same host
# dir (the backend wires this via two --volume flags pointing at the
# same host path). Wait up to 10s for the file; fall through silently
# on timeout because (a) HTTPS to the proxy will fail loudly anyway,
# and (b) some operator workflows (e.g. cage exec into a pre-existing
# container after `cage edit`) don't need the trust store updated.
log "stage C: waiting for egress CA cert at /certs/mitmproxy-ca-cert.pem"
i=0
while [ "$i" -lt 20 ]; do
  if [ -s /certs/mitmproxy-ca-cert.pem ]; then
    break
  fi
  sleep 0.5
  i=$((i + 1))
done

if [ -s /certs/mitmproxy-ca-cert.pem ]; then
  # update-ca-certificates is debian/ubuntu-specific. ca-certificates
  # was installed in the wrapper Containerfile, so it should exist; but
  # tolerate missing for distros where the wrapper's apt branch didn't
  # match (alpine apk path, future bases). The cage will then see
  # certificate-verify failures on HTTPS — louder than silent breakage.
  cp /certs/mitmproxy-ca-cert.pem \
     /usr/local/share/ca-certificates/agentcage-proxy.crt 2>/dev/null || true
  update-ca-certificates >/dev/null 2>&1 || true
  log "stage C: proxy CA installed into trust store"
else
  log "stage C: no /certs/mitmproxy-ca-cert.pem after 10s — HTTPS to the proxy may fail (egress still booting?)"
fi

#-- Stage D. Drop privileges + exec the user's CMD ------------------------
# Resolve the cage user's NAME (capsh's --user= takes a name, not a uid;
# the name varies by base image: ubuntu / node / claude / cage).
CAGE_USER=$(getent passwd 1000 | cut -d: -f1)
[ -n "${CAGE_USER}" ] \
  || die "no uid-1000 user in cage image — wrapper Containerfile should have created one" 3
CAGE_HOME=$(getent passwd 1000 | cut -d: -f6)
[ -n "${CAGE_HOME}" ] \
  || die "no home directory for uid 1000 — wrapper Containerfile useradd should have set one" 3

log "stage D: dropping caps, switching to '${CAGE_USER}' (uid 1000), exec'ing cage CMD"

# capsh changes uid/caps but does NOT update env vars. cage-init runs
# as root with HOME=/root inherited from the entrypoint; without these
# exports the dropped-priv workload would see HOME=/root, which is
# 0700 root-owned, so any tool that touches its config dir (claude-
# code's ~/.claude/, npm's ~/.npm/, pip's ~/.cache/) fails EACCES and
# in claude-code 2.1.x specifically that means a silent exit-0 from
# `claude -p`. Set HOME/USER/LOGNAME explicitly; capsh passes env
# through to the exec target.
export HOME="${CAGE_HOME}"
export USER="${CAGE_USER}"
export LOGNAME="${CAGE_USER}"

# capsh chain (order matters):
#   --no-new-privs  — prctl(PR_SET_NO_NEW_PRIVS). Sticks across exec.
#   --drop=all      — empty bounding set BEFORE setuid (closes setuid-
#                     root reacquisition path).
#   --user=$NAME    — setuid+setgid+initgroups to the cage user. uid
#                     0→1000 clears CapEff/CapPrm/CapInh; CapBnd is
#                     already empty.
#
# The exec target is /opt/agentcage/cage-cmd.sh — a shell script baked
# at image build time by the wrapper Containerfile, containing the
# user's argv shell-quoted via Python's shlex.quote(). No jq, no
# runtime parsing, no shell-metacharacter risk; the argv is preserved
# verbatim because each element was quote-escaped host-side.
exec capsh \
  --no-new-privs \
  --drop=all \
  --user="${CAGE_USER}" \
  --shell=/bin/sh \
  -- /opt/agentcage/cage-cmd.sh
