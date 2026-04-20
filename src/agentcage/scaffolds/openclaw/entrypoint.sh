#!/bin/sh
set -e

# ── Certificate setup ──
# Install mitmproxy CA cert so the cage proxy is trusted for HTTPS.
cp /certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt \
  && update-ca-certificates 2>/dev/null || true

# Add to NSS database for Chromium/Electron. Best-effort: skip if the
# enclosing path isn't writable (cages with a read-only root FS and no
# /home/node/.pki tmpfs would otherwise fail hard under `set -e`).
if mkdir -p /home/node/.pki/nssdb 2>/dev/null; then
  certutil -d sql:/home/node/.pki/nssdb -N --empty-password 2>/dev/null || true
  certutil -d sql:/home/node/.pki/nssdb -A -t 'C,,' -n mitmproxy \
    -i /certs/mitmproxy-ca-cert.pem 2>/dev/null || true
fi

# ── OpenClaw config ──
# Write default config if none exists.  CAGE_PROXY_IP and CAGE_GATEWAY_PORT
# are set by the cage.yaml template.
chmod 700 /home/node/.openclaw
if [ ! -f /home/node/.openclaw/openclaw.json ]; then
  printf '{"browser": {"defaultProfile": "openclaw"}, "gateway": {"trustedProxies": ["%s"], "controlUi": {"allowedOrigins": ["http://localhost:%s", "http://127.0.0.1:%s"]} } }' \
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
