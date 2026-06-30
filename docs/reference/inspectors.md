<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Inspectors

Pluggable HTTP-request scanners that **block**, **flag**, or **allow** each request. The chain short-circuits on the first hard block. Read this when configuring secret detection, body-size caps, entropy thresholds, or custom checks.

## Built-in inspectors

| Inspector | Default | Description |
|-----------|---------|-------------|
| `domain` | on | Domain allowlist/blocklist enforcement. Config-less — driven by the top-level [`domains:`](domains.md) block. |
| `secrets` | on | Regex-based secret leak detection. See [Secrets inspector](#secrets-inspector). |
| `body-size` | on | Request body size limits (loaded when `max_request_body` > 0; default is 10 MB). Per-host overrides via `host_max_bytes`. See [Body-size inspector](#body-size-inspector). |
| `content-type` | on | Content-type mismatch detection and base64 blob scanning. See [Content-type inspector](#content-type-inspector). |
| `entropy` | opt-in *(since 0.16)* | Shannon entropy analysis — detects encrypted/compressed payloads. See [Entropy inspector](#entropy-inspector). |

The `domain`, `secrets`, `body-size`, and `content-type` inspectors load automatically from their top-level config sections (`body-size` loads whenever `max_request_body` is non-zero).

The `entropy` inspector is opt-in. Enable it with a top-level `entropy:` block or by listing it under `inspectors:`:

```yaml
# Option 1 — top-level block, empty {} applies defaults (threshold 7.0, block mode)
entropy: {}

# Option 2 — top-level block with overrides
entropy:
  threshold: 7.0
  action: block

# Option 3 — under the inspectors list
inspectors:
  - name: entropy
```

All built-in scaffolds list `- name: entropy` under `inspectors:`, so cages created from a scaffold keep entropy loaded. `entropy: false` remains a no-op for backward compatibility.

## Secrets inspector

The `secrets` inspector pattern-matches outbound traffic against known secret formats. By default a detected secret results in a **block** (403 response). Set `action: flag` to record the detection in the audit log and let the request proceed instead. Use `allow_to_domains` to exempt specific secrets when sent to their legitimate API endpoints.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable/disable secret scanning. |
| `action` | `string` | `"block"` | `"block"` (return 403) or `"flag"` (allow but record in the audit log). Any other value falls back to `"block"`. |
| `builtin_allow_to_domains` | `bool` | `true` | Include built-in secret-to-domain mappings (e.g. `anthropic_key` → `anthropic.com`). Set to `false` to require all exemptions to be explicit. |
| `allow_to_domains` | `map[string, list]` | `{}` | Pattern name to list of domains where that secret type is allowed. Merged with built-in mappings (user entries win). |
| `extra_patterns` | `list[object]` | `[]` | Additional patterns — each entry needs `name` plus either `pattern` (regex) or `env` (exact-match from env var). |

### Built-in patterns

19 patterns ship out-of-the-box:

| Pattern | Regex | Example match |
|---------|-------|---------------|
| `openai_key` | `sk-proj-[a-zA-Z0-9]{20,}` | `sk-proj-abc123...` |
| `anthropic_key` | `sk-ant-[a-zA-Z0-9\-]{20,}` | `sk-ant-abc123...` |
| `aws_access_key` | `AKIA[A-Z2-7]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| `github_token` | `gh[ps]_[A-Za-z0-9]{36}` | `ghp_abc123...` |
| `github_pat` | `github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}` | `github_pat_abc123...` |
| `google_api_key` | `AIza[0-9A-Za-z\-_]{35}` | `AIzaSyA...` |
| `slack_token` | `xox[bpors]-[0-9]{10,}-[a-zA-Z0-9-]+` | `xoxb-123456...` |
| `stripe_key` | `[sr]k_(live\|test)_[0-9a-zA-Z]{24,}` | `sk_live_abc123...` |
| `private_key` | `-----BEGIN[ A-Z]*PRIVATE KEY-----` | PEM private key headers |
| `gitlab_token` | `glpat-[A-Za-z0-9\-_]{20,}` | `glpat-abc123...` |
| `huggingface_token` | `hf_[a-zA-Z]{34}` | `hf_abc123...` |
| `databricks_token` | `dapi[0-9a-f]{32}` | `dapi0123456789abcdef...` |
| `azure_jwt` | `eyJ[A-Za-z0-9_-]{50,}\.eyJ[A-Za-z0-9_-]{50,}` | `eyJhbG...eyJpc...` |
| `openrouter_key` | `sk-or-v1-[a-f0-9]{64}` | `sk-or-v1-abc123...` |
| `perplexity_key` | `pplx-[a-zA-Z0-9]{48}` | `pplx-abc123...` |
| `brave_api_key` | `(?<![A-Za-z0-9_-])BSAI[a-zA-Z0-9_-]{28}(?![A-Za-z0-9_-])` | `BSAIabc...` (32 chars total) |
| `telegram_bot_token` | `[0-9]{8,10}:[A-Za-z0-9_-]{35}` | `123456789:AAAA...` |
| `discord_bot_token` | `[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}` | `MAAA...BBBB.CCCC...` |
| `firecrawl_key` | `fc-[a-zA-Z0-9]{32,}` | `fc-abc123...` |

### Built-in domain exemptions

By default, each built-in secret pattern is automatically allowed to reach its provider domain (e.g. `anthropic_key` → `anthropic.com`, `openai_key` → `openai.com`). You don't need to manually configure `allow_to_domains` for standard secrets.

User-specified `allow_to_domains` entries are merged with the built-in defaults — your entries extend (not replace) the built-ins. If you specify the same pattern name, your entry overrides the built-in for that pattern.

To disable built-in exemptions entirely:

```yaml
secrets:
  builtin_allow_to_domains: false
```

### Custom domain exemptions

```yaml
secrets:
  allow_to_domains:
    custom_key:
      - my-service.example.com
    anthropic_key:          # overrides built-in
      - my-proxy.example.com
```

Subdomains are matched automatically, so `anthropic.com` covers `api.anthropic.com`.

### Extra patterns

Each entry in `extra_patterns` requires a `name` and either `pattern` or `env`:

- **`pattern`** — a regex that triggers on any match (e.g. `BSA[a-zA-Z0-9]{20,}`).
- **`env`** — the name of an environment variable. The proxy reads its value at startup and matches it as a literal string (using `re.escape`). If the variable is not set, the pattern is silently skipped.

`env` is useful when a regex would false-positive on binary or base64 data, or when the secret format isn't distinctive enough for a reliable regex. `pattern` and `env` are mutually exclusive; if both are present, `env` takes precedence.

```yaml
secrets:
  extra_patterns:
    # Regex-based detection
    - name: custom_token
      pattern: "MYTOKEN_[A-Z]{20}"
    # Exact-match from environment variable
    - name: brave_api_key
      env: BRAVE_API_KEY
  allow_to_domains:
    brave_api_key:
      - search.brave.com
```

## Body-size inspector

Caps inbound and outbound request bodies. The global limit comes from the top-level `max_request_body` key (default 10 MB; `0` disables). Per-host overrides — for example, to allow larger document uploads to a paperless-ngx instance without raising the global ceiling — are configured by re-declaring the `body-size` inspector under `inspectors:`:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `max_bytes` | `int` | `0` (when re-declared) / `max_request_body` (when not) | Global cap in bytes. |
| `host_max_bytes` | `dict[string, int]` | `{}` | Per-host overrides (subdomain suffix matching, most-specific match wins). Set a host to `0` to disable the cap for that host. |

```yaml
max_request_body: 10485760           # 10 MB global default

inspectors:
  - name: body-size
    config:
      max_bytes: 10485760            # keep the global default
      host_max_bytes:
        paperless.example.com: 104857600   # 100 MB for document uploads
```

## Entropy inspector

Detects high-entropy payloads that may indicate encrypted or compressed data exfiltration.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `threshold` | `float` | `7.0` | Entropy threshold in bits/byte (0.0–8.0) to trigger. |
| `min_body_bytes` | `int` | `256` | Minimum body size to evaluate. |
| `action` | `string` | `"block"` | `"block"` or `"flag"`. |
| `exempt_content_types` | `list[string]` | `["image/", "application/gzip", "application/zip", "application/octet-stream"]` | Content-type prefixes to skip. |

Reference entropy ranges:

| Content | Entropy (bits/byte) |
|---------|---------------------|
| Plain text / HTML / JSON | 3.5 – 5.5 |
| Source code | 4.5 – 5.5 |
| Base64-encoded data | ~6.0 |
| Compressed (gzip, zstd) | 7.5 – 8.0 |
| Encrypted (AES, ChaCha) | 7.9 – 8.0 |

## Content-type inspector

Detects content-type mismatches (text type with high entropy) and hidden base64 blobs.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `entropy_ceiling` | `float` | `6.5` | Max expected entropy for text content types. |
| `detect_base64` | `bool` | `true` | Enable base64 blob detection. |
| `base64_min_len` | `int` | `256` | Minimum base64 match length to trigger. |
| `action` | `string` | `"block"` | `"block"` or `"flag"`. |
| `host_exempt_content_types` | `dict[string, list[string]]` | `{}` | Per-host content-type exemptions (subdomain suffix matching). Mirrors the entropy inspector's knob — use it for legitimate high-entropy bodies declared as a "text-like" content-type, e.g. `multipart/form-data` PDF uploads to a paperless-ngx host. |

Text content-type prefixes checked: `application/json`, `application/xml`, `text/`, `application/x-www-form-urlencoded`, `multipart/form-data`.

Example — let multipart PDF uploads through to a paperless-ngx instance without weakening the inspector for any other host:

```yaml
inspectors:
  - name: entropy
    config:
      host_exempt_content_types:
        paperless.example.com: ["multipart/form-data"]
  - name: content-type
    config:
      host_exempt_content_types:
        paperless.example.com: ["multipart/form-data"]
```

## Writing custom inspectors

Create a Python file with a class that extends `Inspector`:

```python
from inspectors.base import Inspector, InspectionResult, InspectionContext

class MyInspector(Inspector):
    name = "my-check"

    def configure(self, config: dict) -> None:
        self.forbidden = config.get("forbidden_word", "EXFIL")

    def inspect_request(self, ctx: InspectionContext) -> InspectionResult | None:
        if ctx.body_text and self.forbidden in ctx.body_text:
            return InspectionResult(
                inspector=self.name,
                action="block",
                reason=f"body contains forbidden word: {self.forbidden}",
            )
        return None  # returning None means this inspector abstains
```

Reference it in your config:

```yaml
inspectors:
  - name: my-check
    path: /path/to/my_inspector.py
    config:
      forbidden_word: "EXFIL"
```

Mount the inspector file into the proxy container via the `volumes` config option, or bake it into a custom `Containerfile.proxy`.

> **Note:** Inspectors can also implement `inspect_response(ctx)` to inspect inbound responses using the same `InspectionContext` and `InspectionResult` types. Response inspection runs after the request has been forwarded and the response received.

### InspectionContext fields

Every inspector receives an `InspectionContext` with pre-computed data:

| Field | Type | Description |
|-------|------|-------------|
| `url` | `str` | Full request URL. |
| `host` | `str` | Target hostname. |
| `method` | `str` | HTTP method (GET, POST, ...). |
| `headers` | `dict[str, str]` | Request/response headers. |
| `content_type` | `str` | Content-Type header value. |
| `body_bytes` | `bytes \| None` | Raw body bytes. |
| `body_text` | `str \| None` | Decoded body text (best-effort). |
| `body_size` | `int` | Body size in bytes. |
| `body_entropy` | `float \| None` | Shannon entropy (bits/byte, 0.0–8.0). |
| `prior_results` | `list` | Results from inspectors earlier in the chain. |

### InspectionResult fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `inspector` | `str` | *(required)* | Inspector name. |
| `action` | `str` | `"block"` | `"block"` or `"flag"`. |
| `reason` | `str` | `""` | Human-readable explanation. |
| `severity` | `str` | `"warning"` | `"debug"`, `"info"`, `"warning"`, `"error"`, `"critical"`. |
| `score` | `float` | `0.0` | Numeric score (for anomaly-scoring use cases). |
| `metadata` | `dict` | `{}` | Arbitrary inspector-specific data. |

## Related

- [Secret injection](secret-injection.md) — injection runs before inspectors; the `secrets` inspector provides defense-in-depth.
- [Domains](domains.md) — drives the `domain` inspector.
- [Protocol relays](protocol-relays.md) — SMTP `DATA` payloads run through this chain (with `domain` skipped).
- [Traffic capture](capture.md) — capture fires on the same inspector decisions.
- [Ports](ports.md) — inspectors only see traffic on the inspected TCP set.
