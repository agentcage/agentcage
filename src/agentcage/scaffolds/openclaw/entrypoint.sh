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
# Loop so that OpenClaw's SIGUSR1-based self-restart (which exits the
# current process and spawns a new one) doesn't kill the container.
# tini is PID 1 and handles signal forwarding + zombie reaping.
while true; do
  node openclaw.mjs gateway --allow-unconfigured --bind lan --auth password
  echo 'cage: openclaw exited, restarting in 2s...'
  sleep 2
done
