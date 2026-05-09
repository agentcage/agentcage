#!/bin/sh
set -e

# ── Certificate setup ──
# Install mitmproxy CA cert so the cage proxy is trusted for HTTPS.
cp /certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt \
  && update-ca-certificates 2>/dev/null || true

# Add to NSS database for Chromium/Electron. Best-effort: skip if the
# enclosing path isn't writable (cages with a read-only root FS and no
# /home/node/.pki tmpfs would otherwise fail hard under `set -e`).
# Surface the degraded state so operators can see TLS inspection is off
# for browser traffic (agents relying on mitmproxy cert trust will see
# cert errors until a /home/node/.pki tmpfs is added to cage.yaml).
if mkdir -p /home/node/.pki/nssdb 2>/dev/null; then
  certutil -d sql:/home/node/.pki/nssdb -N --empty-password 2>/dev/null || true
  certutil -d sql:/home/node/.pki/nssdb -A -t 'C,,' -n mitmproxy \
    -i /certs/mitmproxy-ca-cert.pem 2>/dev/null || true
else
  echo "warning: /home/node/.pki not writable; Chromium/Electron in this cage will not trust the mitmproxy CA. Add '/home/node/.pki:rw,size=16M' to tmpfs in cage.yaml to enable TLS inspection for browser traffic." >&2
fi

# ── OpenClaw config ──
# Write default config if none exists.  CAGE_PROXY_IP and CAGE_GATEWAY_PORT
# are set by the cage.yaml template.
chmod 700 /home/node/.openclaw
if [ ! -f /home/node/.openclaw/openclaw.json ]; then
  # browser.ssrfPolicy.dangerouslyAllowPrivateNetwork: openclaw's browser
  # plugin refuses to navigate whenever HTTP_PROXY/HTTPS_PROXY env vars
  # are set ("strict browser SSRF policy cannot be enforced while env
  # proxy variables are set"). In agentcage, egress is already policed
  # by the mitm proxy + domain allowlist + inspectors, so this redundant
  # guard just blocks the browser tool. Opt out — cage egress controls
  # remain authoritative.
  printf '{"browser": {"defaultProfile": "openclaw", "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": true}}, "gateway": {"trustedProxies": ["%s"], "controlUi": {"allowedOrigins": ["http://localhost:%s", "http://127.0.0.1:%s"]} } }' \
    "${CAGE_PROXY_IP}" "${CAGE_GATEWAY_PORT}" "${CAGE_GATEWAY_PORT}" \
    > /home/node/.openclaw/openclaw.json
fi
chmod 600 /home/node/.openclaw/openclaw.json

# ── Run OpenClaw ──
# `exec` so this shell is replaced by the openclaw process: openclaw
# becomes PID 2 directly under tini, with no shell wrapper between
# them. That matters because openclaw 2026.5+ uses SIGUSR1 for its
# in-process restart (PID stays alive; see openclaw upstream's
# `restart mode: in-process restart` log). When
# `agentcage cage restart` delivers SIGUSR1 via
# `podman kill --signal=SIGUSR1`, tini forwards it to PID 2; without
# the exec, PID 2 was a /bin/sh that has no SIGUSR1 handler and dies
# on the kernel's default action, taking the whole container down
# (status=138 / 128+SIGUSR1).
#
# We used to wrap this in `while true; ... done` to respawn after an
# openclaw exit. That loop dates from pre-2026.5 openclaw, where
# SIGUSR1 caused a process exit + entrypoint-loop respawn. 2026.5+
# never exits on SIGUSR1, so the loop only triggered on real crashes —
# which the cage unit's `Restart=on-failure` already handles.
exec node openclaw.mjs gateway --allow-unconfigured --bind lan --auth password
