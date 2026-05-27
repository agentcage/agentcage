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

# dnsmasq writes its pidfile here. We use /home/acdns/ — pre-chowned to
# acdns at image build time (Containerfile.egress) — instead of /run or
# /var/run because:
#   * /run is a tmpfs created fresh at container start, so a build-time
#     chown wouldn't survive into the runtime.
#   * the runtime chown approach we used initially relied on CAP_CHOWN
#     being in the container's default cap set. Rootless podman setups
#     with hardened `containers.conf` (`default_capabilities = []`) drop
#     that — the chown failed with EPERM, the supervisor exited under
#     `set -eu`, and the egress never came up. Putting the pidfile under
#     a path pre-chowned in an image layer eliminates the runtime cap
#     dependency entirely.
# The pidfile is what `domain add` / `domain rm` use to SIGHUP dnsmasq
# without restarting the egress container.
DNSMASQ_PID_FILE=/home/acdns/dnsmasq.pid

#-- Step A. iptables setup -------------------------------------------------
# The egress container acts as a ROUTER between the cage netns and the
# internet (NOT an in-netns OUTPUT filter — that's the apple-container
# shape, where the proxy/dns/cage workloads share a netns). Here, traffic
# from the cage enters via eth0; we REDIRECT inspected tcp ports to the
# local mitmproxy on :8443 and apply a default-DROP FORWARD policy.
#
# Port policy:
#   INSPECTED_TCP_PORTS  — REDIRECTed to :8443 (mitmproxy transparent mode)
#   PASSTHROUGH_TCP_PORTS — FORWARD ACCEPT, never enters mitmproxy
#   ALLOW_UDP_PORTS       — FORWARD ACCEPT for UDP
# All three are sourced from the egress Quadlet's Environment= entries
# (egress.container.j2), populated from cage.yaml's ``ports.tcp.allow``
# / ``ports.tcp.passthrough`` / ``ports.udp.allow``. The smoke-test path
# (test_egress_image.py — runs the container without a Quadlet) falls
# back to "80 443" only when the env var is genuinely unset so the
# default cage policy still surfaces when a tester drops the container
# straight onto the cli without the Quadlet's full env block.
# /etc/agentcage/iptables.env is still sourced as a tertiary override
# for ad-hoc operator probes; unused in the regular Quadlet path.
INSPECTED_TCP_PORTS="${INSPECTED_TCP_PORTS-80 443}"
PASSTHROUGH_TCP_PORTS="${PASSTHROUGH_TCP_PORTS-}"
ALLOW_UDP_PORTS="${ALLOW_UDP_PORTS-}"
if [ -f /etc/agentcage/iptables.env ]; then
  # shellcheck disable=SC1091
  . /etc/agentcage/iptables.env
fi
log "step A: iptables setup (inspected=[$INSPECTED_TCP_PORTS] passthrough=[$PASSTHROUGH_TCP_PORTS] udp=[$ALLOW_UDP_PORTS])"

for port in $INSPECTED_TCP_PORTS; do
  # No ``-i <iface>`` selector: podman's CNI does NOT deterministically
  # map the per-cage network to ``eth0`` — on the GitHub runner the
  # default ``podman`` network came in on eth0 and the cage-net on
  # eth1, so an ``-i eth0`` filter REDIRECTed nothing and the cage's
  # HTTP got TCP RST from the egress because port 80 wasn't actually
  # listening. The legacy proxy.container.j2 also had no -i filter.
  # Without it, traffic arriving on the podman-net interface also
  # matches — but that's not an exploitable path: mitmproxy in
  # transparent mode reads SO_ORIGINAL_DST to know where to forward,
  # and a non-REDIRECTed foreign connection would put the egress's own
  # IP there, so mitmproxy would attempt to connect to itself. The
  # regular forward proxy on :8080 is independently scoped via
  # AGENTCAGE_REGULAR_BIND={ip_egress}:8080 (see Quadlet).
  iptables -t nat -A PREROUTING -p tcp --dport "$port" -j REDIRECT --to-ports 8443 \
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

# NOTE on lateral-traversal residual:
#
# The egress is on two networks — the per-cage ``{name}-net`` (cage-
# facing) AND the default ``podman`` network (host-facing for outbound).
# Binding mitmproxy to ip_egress:8080 (see Quadlet AGENTCAGE_REGULAR_BIND)
# is sufficient to stop a foreign rootless container from reaching us
# via our PODMAN-NETWORK IP, but not via our CAGE-NETWORK IP — the
# host's bridge routing happily forwards packets between any two
# rootless container networks it knows about, and SNAT/MASQUERADE
# rewrites the source IP into our cage subnet on the way in, so a
# subnet-source filter at INPUT would NOT match the attacker's packets
# (their src appears as 10.X.Y.1 i.e. our cage-net gateway). RPF via
# conf/*.rp_filter would help but requires CAP_SYS_ADMIN at runtime,
# which we don't grant. The legacy 3-service proxy was vulnerable to
# the same path. A structural fix is out of scope for this supervisor
# and tracked separately — likely either removing ``Network=podman``
# from the egress quadlet (and finding a different outbound path that
# doesn't bridge with other rootless containers) or adding host-level
# pf/nft rules outside the container's reach.

# IPv6 forwarding default-DROP. Best-effort — some kernels (notably
# minimal CI environments) ship without ip6tables loaded; loud DROP is
# still preferable to silent forwarding so we keep it best-effort here.
ip6tables -P FORWARD DROP 2>/dev/null || log "warn: ip6tables FORWARD DROP unavailable (no v6 stack?)"

# Both sysctls below are also settable at container-creation time via
# the Quadlet's `Sysctl=` directive (the container/vm backends do this
# because rootless podman doesn't grant CAP_SYS_ADMIN even with
# `--cap-add net_admin`, so `sysctl -w` from inside fails). We attempt
# them anyway so apple-container (which doesn't have a Quadlet
# pre-stage) gets them, but tolerate EPERM/etc. — at runtime we verify
# the values via /proc/sys/ reads instead.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.ip_unprivileged_port_start=80 >/dev/null 2>&1 || true

# Verify ip_forward is on — if neither Quadlet nor in-container sysctl
# succeeded, this is fatal because the FORWARD chain becomes
# unreachable (packets blackhole at the IP layer before reaching it).
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
  die "net.ipv4.ip_forward=1 not set; the Quadlet must set Sysctl=net.ipv4.ip_forward=1 OR the container must have CAP_SYS_ADMIN" 16
fi

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
  # apple-container path: per-cage dnsmasq.conf bind-mounted by the
  # backend (handles allowlist scoping + sinkhole + filter-AAAA).
  prlimit --as=$((256 * 1024 * 1024)) -- \
    setpriv --reuid=acdns --regid=acdns --clear-groups \
            --bounding-set=-all,+net_bind_service --inh-caps=-all -- \
    /opt/agentcage/dns-audit.sh \
      /usr/sbin/dnsmasq -k \
        --pid-file="$DNSMASQ_PID_FILE" \
        --conf-file=/etc/agentcage/dnsmasq.conf \
        --servers-file=/etc/agentcage/dns-allowlist.conf \
    &
elif [ -f /etc/agentcage/dns-allowlist.conf ]; then
  # container/vm path: no per-cage dnsmasq.conf is rendered (the Quadlet
  # template bind-mounts only dns-allowlist.conf). Match legacy
  # dns.container.j2's command-line shape: --no-resolv (no default
  # upstream — non-allowlisted zones return REFUSED), --address=/#/...
  # sinkhole for A/AAAA inside non-allowed zones, --servers-file for the
  # per-cage allowlist (one `server=/<allowed-apex>/<upstream>` per
  # allowed domain × upstream pair). This closes the same non-A-record
  # exfil channel that the apple-container dnsmasq.conf.j2 closes.
  log "step B: container/vm path — applying allowlist flags inline"
  # NB: we do NOT pass --no-hosts. dnsmasq reads /etc/hosts inside the
  # egress container by default, which the e2e harness uses to redirect
  # specific upstream domains (e.g. httpbin.org → the mock container's
  # cage-net IP) for testing the proxy chain end-to-end without external
  # DNS. The legacy dns.container.j2 didn't pass --no-hosts either —
  # the additional hardening it would provide is minimal (only the
  # egress container's own hostname and 127.0.0.1 are in /etc/hosts by
  # default; operators who care can mount an empty /etc/hosts).
  prlimit --as=$((256 * 1024 * 1024)) -- \
    setpriv --reuid=acdns --regid=acdns --clear-groups \
            --bounding-set=-all,+net_bind_service --inh-caps=-all -- \
    /opt/agentcage/dns-audit.sh \
      /usr/sbin/dnsmasq -k \
        --pid-file="$DNSMASQ_PID_FILE" \
        --no-resolv \
        --listen-address=0.0.0.0 \
        --port=53 \
        --address=/#/198.51.100.1 \
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
      --pid-file="$DNSMASQ_PID_FILE" \
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
# Addon code is static and lives in the image at /opt/agentcage/addon.py
# (with sibling packages inspectors/, transforms/, relays/, capture.py,
# secret_injector.py — mitmproxy's script loader puts the addon's dir on
# sys.path so they resolve relative to /opt/agentcage/). Per-cage config
# (allowlist, secret_injection rules, capture settings) is at
# /etc/agentcage/config.yaml via bind-mount.
#
# TODO(measurement): --as=2G for mitmproxy covers PyInstaller's ~700MB
# mmap overhead plus runtime working set with headroom. Provisional —
# tune after measurement in a follow-up PR.
log "step D: starting mitmproxy (uid 200, CapBnd=0, prlimit --as=2G)"

# Build reverse-mode flags for inbound port forwards (legacy proxy's
# `--mode reverse:http://<ip_cage>:<port>@0.0.0.0:<port>`). The backend
# stages this via two env vars:
#   AGENTCAGE_INBOUND_PORTS  — space-separated container ports
#   AGENTCAGE_CAGE_IP        — cage container's IP on the cage-net
# If unset, no reverse-mode flags are emitted (no inbound forwarding).
EXTRA_MODES=""
if [ -n "${AGENTCAGE_INBOUND_PORTS:-}" ] && [ -n "${AGENTCAGE_CAGE_IP:-}" ]; then
  for p in $AGENTCAGE_INBOUND_PORTS; do
    EXTRA_MODES="$EXTRA_MODES --mode reverse:http://$AGENTCAGE_CAGE_IP:$p@0.0.0.0:$p"
  done
  log "step D: inbound forwards: $AGENTCAGE_INBOUND_PORTS via cage=$AGENTCAGE_CAGE_IP"
fi

if [ -f /etc/agentcage/config.yaml ]; then
  # shellcheck disable=SC2086  # EXTRA_MODES is intentionally word-split
  prlimit --as=$((2 * 1024 * 1024 * 1024)) -- \
    setpriv --reuid=acproxy --regid=acproxy --clear-groups \
            --no-new-privs --bounding-set=-all --inh-caps=-all -- \
    env HOME=/home/acproxy AGENTCAGE_CONFIG=/etc/agentcage/config.yaml \
    mitmdump \
      -s /opt/agentcage/addon.py \
      --mode "regular@${AGENTCAGE_REGULAR_BIND:-:8080}" \
      --mode transparent@8443 \
      $EXTRA_MODES \
      --set connection_strategy=lazy \
    &
else
  # Smoke-test path: no config staged. Run mitmproxy WITHOUT the addon so
  # the smoke test can exercise listener + CA generation without needing
  # a valid AGENTCAGE_CONFIG file. Production never hits this path —
  # backends always stage config.yaml.
  log "step D: no /etc/agentcage/config.yaml — running without addon (smoke-test mode)"
  prlimit --as=$((2 * 1024 * 1024 * 1024)) -- \
    setpriv --reuid=acproxy --regid=acproxy --clear-groups \
            --no-new-privs --bounding-set=-all --inh-caps=-all -- \
    env HOME=/home/acproxy \
    mitmdump \
      --mode "regular@${AGENTCAGE_REGULAR_BIND:-:8080}" \
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
