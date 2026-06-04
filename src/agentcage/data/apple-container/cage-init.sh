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

#-- Stage A'. Local dnsmasq scoped to the cage's allowlisted apexes --------
# apple-container's default /etc/resolv.conf points the cage at the
# vmnet host gateway (<subnet>.1) whose recursive resolver answers
# arbitrary queries — that's a DNS-tunnel exfil channel that bypasses
# the egress filter. We run a local dnsmasq inside this microVM,
# listening only on loopback, scoped to the cage's `domains.allow`
# apexes (per-zone `server=` for allowed zones, `address=/#/` sinkhole
# for the rest), and repoint /etc/resolv.conf at it.
#
# Upstream: the per-zone forwarders point at the EGRESS SIBLING
# (AGENTCAGE_EGRESS_IP), NOT directly at a resolver. apple-container
# requires macOS 26+ (see apple_container/prerequisites.py), where
# inter-microVM UDP is delivered, so the cage can reach the egress's
# dnsmasq over UDP :53. Routing every lookup through the egress keeps it
# the single network chokepoint for ALL egress traffic, DNS included;
# the egress in turn forwards to the vmnet gateway, which apple-container
# NATs to the host's CURRENT /etc/resolv.conf — so DNS follows host
# network changes (Wi-Fi/VPN) transparently, with no restart or rebuild.
#
# The bind-mounted dnsmasq.conf / dns-allowlist.conf encode the apex list
# but carry the host-resolver IP baked at `cage update` time (used as the
# upstream by the egress only). We strip those baked `server=` upstreams
# and regenerate per-zone forwarders pointing at the egress, keeping the
# sinkhole + options. The conf file is bind-mounted from the egress-config
# dir.
#
# Best-effort: the wrapper Containerfile installs dnsmasq-base; bases
# without a package manager (distroless, etc.) skip the install and
# this block falls through with the apple gateway resolver intact —
# loud warning is preferable to silently broken DNS.
if command -v dnsmasq >/dev/null 2>&1 \
   && [ -f /etc/agentcage/dnsmasq.conf ]; then
  log "stage A': starting local dnsmasq on 127.0.0.1:53 (scoped DNS)"
  mkdir -p /run/agentcage
  # The bind-mounted dnsmasq.conf sets `log-facility=/var/log/agentcage
  # /dnsmasq.log` (rendered for the egress sibling which has that path
  # mounted). dnsmasq treats cmdline `--log-facility` as additive, so
  # `--log-facility=-` doesn't override the conf entry — both are kept
  # and dnsmasq tries to open the file, which doesn't exist in the
  # cage. Create the directory so the open succeeds (the file ends up
  # in the cage's writable rootfs; no operator-visible side effect).
  # acdns:acdns ownership so the dropped-priv dnsmasq can write it.
  mkdir -p /var/log/agentcage
  chown acdns:acdns /var/log/agentcage 2>/dev/null || true
  chmod 0755 /var/log/agentcage
  # The bind-mounted dnsmasq.conf is the same one the egress sibling
  # uses, which sets `listen-address=0.0.0.0`. We can't simply override
  # that on the cmdline (dnsmasq's --listen-address is ADDITIVE, not
  # replace, and a duplicate listen-address triggers an "Address
  # already in use" error). Instead, pair `--bind-interfaces` with
  # `--except-interface=eth0` — dnsmasq computes per-interface
  # sockets from the listen-address set, then drops the excluded
  # interfaces. Net effect: dnsmasq listens only on loopback even
  # though the conf says 0.0.0.0.
  # --user=acdns — drop privileges; setcap cap_net_bind_service in
  # the wrapper Containerfile lets uid 201 still bind :53.
  # --log-facility=- — log to stderr (no /var/log/agentcage/ in the
  # cage; that mount only exists in the egress sibling).
  # Re-point the per-zone upstreams at the egress sibling. Strip the baked
  # `server=` upstreams from the conf (keep the `address=/#/` sinkhole +
  # options), and regenerate a servers-file whose forwarders target the
  # egress. The apex list is read from the bind-mounted servers-file
  # (preferred) or the conf. AGENTCAGE_EGRESS_IP equals the cage's default
  # route (set in stage B); deriving from the route keeps the same value
  # available to `domain add/rm`'s live SIGHUP (see reload_domains).
  _cage_conf=/etc/agentcage/dnsmasq.conf
  _cage_servers="${AGENTCAGE_DNS_SERVERS_FILE:-}"
  if [ -n "${AGENTCAGE_EGRESS_IP:-}" ] \
     && grep -v '^server=/' /etc/agentcage/dnsmasq.conf \
          > /run/agentcage/dnsmasq.cage.conf 2>/dev/null \
     && awk -F/ -v up="${AGENTCAGE_EGRESS_IP}" '/^server=\//{print "server=/" $2 "/" up}' \
          "${AGENTCAGE_DNS_SERVERS_FILE:-/etc/agentcage/dnsmasq.conf}" \
          > /run/agentcage/dns-allowlist.cage.conf 2>/dev/null; then
    _cage_conf=/run/agentcage/dnsmasq.cage.conf
    _cage_servers=/run/agentcage/dns-allowlist.cage.conf
    log "stage A': forwarding allowlisted zones via egress sibling ${AGENTCAGE_EGRESS_IP} (host-tracking, transparent across host network changes)"
  else
    log "warn: AGENTCAGE_EGRESS_IP unset or config rewrite failed — using baked resolver upstream (DNS may go stale on host network change)"
  fi
  /usr/sbin/dnsmasq \
    --conf-file="${_cage_conf}" \
    ${_cage_servers:+--servers-file="${_cage_servers}"} \
    --bind-interfaces \
    --except-interface=eth0 \
    --user=acdns \
    --pid-file=/run/agentcage/dnsmasq.pid \
    --log-facility=- \
    || die "dnsmasq failed to start in the cage — check setcap on /usr/sbin/dnsmasq" 4
  # Wait briefly for the listener to come up so the resolv.conf
  # rewrite below doesn't race with the workload's first lookup.
  i=0
  while [ "$i" -lt 20 ]; do
    if ss -lun 2>/dev/null | grep -q '127\.0\.0\.1:53 '; then
      break
    fi
    sleep 0.1
    i=$((i + 1))
  done
  # Repoint /etc/resolv.conf at the in-cage dnsmasq. Atomic rename so
  # a concurrent reader never sees a half-written file. Explicit
  # if/then/else (instead of `A && B || log`) because shellcheck's
  # SC2015 correctly notes that `A && B || C` runs C when A succeeds
  # but B fails — fine here, but the warn path is the same either way
  # so the structured form is clearer.
  if printf 'nameserver 127.0.0.1\noptions edns0\n' \
       > /etc/resolv.conf.agentcage \
     && mv /etc/resolv.conf.agentcage /etc/resolv.conf; then
    :
  else
    log "warn: failed to rewrite /etc/resolv.conf — DNS may still leak to apple gateway"
  fi
else
  log "warn: dnsmasq or /etc/agentcage/dnsmasq.conf missing — DNS NOT scoped (apple gateway will resolve arbitrary apexes; DNS-tunnel exfil exposure)"
fi

#-- Stage B. Default route via egress sibling ------------------------------
# `ip route replace` is idempotent — equivalent to `add` if missing or
# `change` if present, so we can re-run cage-init (e.g. cage restart)
# without `del then add` racing.
log "stage B: setting default route via ${AGENTCAGE_EGRESS_IP}"
ip route replace default via "${AGENTCAGE_EGRESS_IP}" \
  || die "failed to set default route via ${AGENTCAGE_EGRESS_IP} — CAP_NET_ADMIN missing?" 2

#-- Stage B'. Lock down the OUTPUT chain ----------------------------------
# Two cage→outside abuse paths get closed here.
#
# (1) Cage→macOS-host services. Apple's container runtime puts the
#     host on the cage's vmnet subnet at the .1 address; the host's
#     loopback services (sshd :22, Apple Remote Desktop :5900) are
#     reachable directly via that gateway — completely outside the
#     egress proxy, which only intercepts :80/:443 via PREROUTING
#     REDIRECT. The cage has no legitimate reason to talk to that
#     gateway at all: HTTPS goes via the egress sibling, DNS via the
#     in-cage dnsmasq on loopback (stage A'). DROP all TCP + UDP to
#     the gateway IP.
#
# (2) Workload-originated DNS exfil. Even with the in-cage dnsmasq
#     scoped to the per-cage allowlist, a uid-1000 process could
#     bypass it by sending UDP :53 directly to ANY external resolver
#     (e.g. `dig @1.1.1.1 evil.example`) — the scoped dnsmasq is
#     decorative if the workload can just pick a different server.
#     Restrict UDP :53 to packets originated by the in-cage dnsmasq
#     (acdns, uid 201) via the xt_owner module. Cage exec --user 0
#     still can't unstick this because the cage exec wrapper drops
#     CAP_NET_ADMIN before exec, so root can't `iptables -F`.
#
# Derive the apple-vmnet host IP as <subnet>.1 — apple-container
# always assigns the host the first usable address on the bridge
# subnet; our default route via the egress sibling sits elsewhere
# on the same /24. Anchoring on the cage's own eth0 IP keeps this
# robust if apple changes the default subnet allocation later.
_local_ip=$(ip -o -4 addr show eth0 2>/dev/null \
  | awk '/inet / {sub(/\/.*/,"",$4); print $4; exit}')
_apple_host_gw=$(printf '%s\n' "${_local_ip}" \
  | awk -F. 'NF==4 {print $1"."$2"."$3".1"}')
if [ -n "${_apple_host_gw}" ] && command -v iptables >/dev/null 2>&1; then
  log "stage B': dropping cage→host-gateway ${_apple_host_gw} (all TCP/UDP); restricting outbound UDP :53 to the in-cage dnsmasq uid"
  iptables -A OUTPUT -d "${_apple_host_gw}" -p tcp -j DROP \
    || log "warn: iptables TCP DROP rule for ${_apple_host_gw} failed (cage→host SSH/ARD remains reachable)"
  iptables -A OUTPUT -d "${_apple_host_gw}" -p udp -j DROP \
    || log "warn: iptables UDP DROP rule for ${_apple_host_gw} failed"
  # Only the in-cage dnsmasq (acdns, uid 201) may originate UDP :53
  # to external resolvers. Loopback traffic is allowed first so the
  # workload's regular `getent` / `socket.gethostbyname` lookups reach
  # the local dnsmasq on 127.0.0.1:53 — otherwise the uid-owner rule
  # would catch them too (uid 1000 → dst :53 → DROP) and break all
  # DNS in the cage. Without the loopback exemption, the only way to
  # query DNS would be `dig @127.0.0.1` running as acdns, which no
  # workload does.
  #
  # If acdns wasn't created (wrapper image without dnsmasq) the
  # DROP rule still installs and blocks ALL non-loopback UDP :53 —
  # safer than leaving the exfil channel open silently.
  iptables -A OUTPUT -o lo -p udp --dport 53 -j ACCEPT \
    || log "warn: iptables loopback :53 ACCEPT failed — workload DNS may break"
  iptables -A OUTPUT -p udp --dport 53 -m owner ! --uid-owner 201 -j DROP \
    || log "warn: iptables UDP-53 uid-owner DROP failed — workload can DNS-tunnel via direct UDP :53 to any resolver"
else
  log "warn: cannot derive apple-vmnet gateway IP or iptables missing — cage→host lockdown skipped"
fi

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
