# Configuration Reference

Full reference for all agentcage configuration settings — types, defaults, and examples.

For architecture details, see [Architecture](architecture.md).
Example configs: [`basic/config.yaml`](../examples/basic/) | [`openclaw/config.yaml`](../examples/openclaw/)

## Table of Contents

- [Top-level settings](#top-level-settings)
- [Container settings](#container-settings-container)
- [Container hardening](#container-hardening)
- [Restart policy and timeouts](#restart-policy-and-timeouts)
- [Secret injection](#secret-injection-secret_injection)
- [Domain filtering](#domain-filtering-domains)
- [Secret detection](#secret-detection-secrets)
- [Inspectors](#inspectors)
  - [Built-in inspectors](#built-in-inspectors)
  - [Entropy inspector](#entropy-inspector)
  - [Content-type inspector](#content-type-inspector)
  - [Writing custom inspectors](#writing-custom-inspectors)

---

## Top-level settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `name` | `string` | *(required)* | Project name — used as the prefix for container names, network name, and quadlet filenames (e.g. `myapp` produces `myapp-cage`, `myapp-proxy`, etc.) |
| `log_allowed` | `bool` | `true` | Log allowed requests to the proxy journal |
| `max_request_body` | `int` | `10485760` (10 MB) | Max request body size in bytes. Set to `0` to disable the body-size limit |
| `dns_servers` | `list[string]` | `["1.1.1.1", "8.8.8.8"]` | Upstream DNS servers used by both the dnsmasq sidecar and the proxy container |

### `dns_servers` example

```yaml
dns_servers:
  - 100.100.100.100   # Tailscale MagicDNS (for *.ts.net)
  - 1.1.1.1
  - 8.8.8.8
```

---

## Container settings (`container:`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `image` | `string` | *(required)* | Container image for the agent |
| `command` | `list[string]` | *(none)* | Command to run in the agent container (e.g. `["node", "app.js"]`) |
| `volumes` | `list[string]` | `[]` | Bind mount specs (`host:container`). Host paths are resolved to absolute paths at generation time. If you move files after generating, regenerate the quadlets |
| `env` | `map[string, string]` | `{}` | Environment variables. `${VAR}` references are expanded from your current shell environment at generation time — the values are baked into the generated quadlet files, not resolved at container start |
| `named_volumes` | `map[string, string]` | `{}` | Podman named volume to mount spec (e.g. `mydata: "/data:rw"`). Not resolved with realpath |
| `tmpfs` | `list[string]` | `[]` | tmpfs mount specs (useful for writable areas on read-only containers) |
| `ports` | `list[string]` | `[]` | Published port specs (e.g. `"127.0.0.1:8080:8080"`) |
| `podman_secrets` | `list[string]` | `[]` | [Podman secret](https://docs.podman.io/en/latest/markdown/podman-secret.1.html) names (injected as env vars) |
| `user` | `string` | `"1000:1000"` | UID:GID to run as. Set to `""` to use the image default. See [Podman `--user`](https://docs.podman.io/en/latest/markdown/podman-run.1.html) |
| `memory` | `string` | *(none)* | Memory limit (e.g. `"4g"`). See [Podman `--memory`](https://docs.podman.io/en/latest/markdown/podman-run.1.html) |
| `cpus` | `string` | *(none)* | CPU limit (e.g. `"2.0"`). See [Podman `--cpus`](https://docs.podman.io/en/latest/markdown/podman-run.1.html) |

---

## Container hardening

These settings are nested under `container:` in the config file. All hardening options are **enabled by default**.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `read_only` | `bool` | `true` | Read-only root filesystem. See [Podman `ReadOnly=`](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) |
| `drop_capabilities` | `string \| list` | `"ALL"` | Linux capabilities to drop. `"ALL"` drops everything; use a list for specific caps (e.g. `[NET_RAW]`). Set to `[]` to keep all caps. See [Podman `DropCapability=`](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) |
| `add_capabilities` | `list[string]` | `[]` | Capabilities to add back (e.g. `[NET_BIND_SERVICE]`). See [Podman `AddCapability=`](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) |
| `no_new_privileges` | `bool` | `true` | Prevent privilege escalation. See [Podman `NoNewPrivileges=`](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) |
| `security_label_disable` | `bool` | `true` | Disable SELinux/AppArmor labeling. See [Podman `SecurityLabelDisable=`](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) |

---

## Restart policy and timeouts

These settings are nested under `container:` in the config file.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `restart` | `string` | `"on-failure"` | Systemd restart policy: `"no"`, `"on-failure"`, `"always"` |
| `restart_sec` | `int` | `10` | Seconds to wait before restart |
| `timeout_start_sec` | `int` | *(none)* | Systemd `TimeoutStartSec` |
| `timeout_stop_sec` | `int` | `30` | Systemd `TimeoutStopSec` |

---

## Secret injection (`secret_injection:`)

Secret injection prevents API keys and other sensitive values from ever entering the cage container. Instead of passing real secrets to the cage, it receives placeholder tokens (e.g. `{{ANTHROPIC_API_KEY}}`). The proxy transparently swaps placeholders for real values on outbound requests and redacts real values back to placeholders on inbound responses.

Secrets listed in `secret_injection` are **automatically excluded** from the cage's Podman secrets. The proxy container receives the real value, and the cage container receives the placeholder as an environment variable.

| Setting | Type | Required | Description |
|---------|------|----------|-------------|
| `env` | `string` | yes | Environment variable name holding the real secret (read by the proxy at startup) |
| `placeholder` | `string` | yes | Token the cage sees and uses in requests (e.g. `"{{ANTHROPIC_API_KEY}}"`) |
| `inject_to` | `list[string]` | no | Domains where placeholders are replaced with real values. If omitted, injection applies to all domains |

### Domain restrictions

When `inject_to` is set for a rule, the proxy only injects the real value for requests to matching domains (subdomains are matched automatically). If the cage sends a placeholder to any other domain, the request is **blocked** with a 403 response.

When `inject_to` is omitted, the real value is injected for all outbound requests and redacted from all inbound responses.

### Response redaction

Inbound responses are always redacted regardless of domain -- any occurrence of a real secret value in response headers or body is replaced with the corresponding placeholder before the cage receives it.

### Example

```yaml
secret_injection:
  - env: ANTHROPIC_API_KEY
    placeholder: "{{ANTHROPIC_API_KEY}}"
    inject_to:
      - anthropic.com            # only inject to *.anthropic.com
  - env: BRAVE_API_KEY
    placeholder: "{{BRAVE_API_KEY}}"
    inject_to:
      - search.brave.com
  - env: SUPPORT_EMAIL            # non-secret sensitive value
    placeholder: "{{SUPPORT_EMAIL}}"
    # no inject_to → inject/redact everywhere
```

Secrets that don't need injection (e.g. gateway passwords used only within the cage) should remain in `podman_secrets` as before.

> **Note:** Secret injection and the `secrets` inspector are complementary. The injector proactively prevents the cage from seeing real secrets, while the `secrets` inspector provides defense-in-depth by pattern-matching against known credential formats. Both can be active at the same time. Since injection runs *before* inspectors, the `secrets` inspector sees the real key in the modified request -- keep `allow_to_domains` entries for injected secrets so the inspector doesn't block them.

---

## Domain filtering (`domains:`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `mode` | `string` | *(none)* | `"allowlist"` or `"blocklist"`. Omit the entire `domains:` section to allow all domains |
| `list` | `list[string]` | `[]` | Domains to allow/block |

Subdomains are matched automatically — adding `example.com` also matches `api.example.com`, `sub.api.example.com`, etc.

```yaml
domains:
  mode: allowlist
  list:
    - api.anthropic.com
    - github.com        # also matches *.github.com
    - pypi.org
```

---

## Secret detection (`secrets:`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable/disable secret scanning |
| `builtin_allow_to_domains` | `bool` | `true` | Include built-in secret-to-domain mappings (e.g. `anthropic_key` → `anthropic.com`). Set to `false` to require all exemptions to be explicit |
| `allow_to_domains` | `map[string, list]` | `{}` | Pattern name to list of domains where that secret type is allowed. Merged with built-in mappings (user entries win) |
| `extra_patterns` | `list[object]` | `[]` | Additional patterns — each entry needs `name` plus either `pattern` (regex) or `env` (exact-match from env var) |

Detected secrets always result in a **block** action (403 response). Use `allow_to_domains` to exempt specific secrets from blocking when sent to their legitimate API endpoints.

### Built-in patterns

19 patterns are included out-of-the-box:

| Pattern | Regex | Example match |
|---------|-------|---------------|
| `openai_key` | `sk-proj-[a-zA-Z0-9]{20,}` | `sk-proj-abc123...` |
| `anthropic_key` | `sk-ant-[a-zA-Z0-9\-]{20,}` | `sk-ant-abc123...` |
| `aws_access_key` | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| `github_token` | `gh[ps]_[A-Za-z0-9_]{36,}` | `ghp_abc123...` |
| `github_pat` | `github_pat_[A-Za-z0-9_]{22,}` | `github_pat_abc123...` |
| `google_api_key` | `AIza[0-9A-Za-z\-_]{35}` | `AIzaSyA...` |
| `slack_token` | `xox[bpors]-[0-9]{10,}-[a-zA-Z0-9-]+` | `xoxb-123456...` |
| `stripe_key` | `[sr]k_(live\|test)_[0-9a-zA-Z]{24,}` | `sk_live_abc123...` |
| `private_key` | `-----BEGIN[ A-Z]*PRIVATE KEY-----` | PEM private key headers |
| `gitlab_token` | `glpat-[A-Za-z0-9\-_]{20,}` | `glpat-abc123...` |
| `huggingface_token` | `hf_[A-Za-z0-9]{20,}` | `hf_abc123...` |
| `databricks_token` | `dapi[0-9a-f]{32}` | `dapi0123456789abcdef...` |
| `azure_jwt` | `eyJ[A-Za-z0-9_-]{50,}\.eyJ[A-Za-z0-9_-]{50,}` | `eyJhbG...eyJpc...` |
| `openrouter_key` | `sk-or-v1-[a-f0-9]{64}` | `sk-or-v1-abc123...` |
| `perplexity_key` | `pplx-[a-f0-9]{64}` | `pplx-abc123...` |
| `brave_api_key` | `BSA[a-zA-Z0-9]{20,}` | `BSAabc123...` |
| `telegram_bot_token` | `[0-9]{8,10}:[A-Za-z0-9_-]{35}` | `123456789:AAAA...` |
| `discord_bot_token` | `[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}` | `MAAA...BBBB.CCCC...` |
| `firecrawl_key` | `fc-[a-zA-Z0-9]{32,}` | `fc-abc123...` |

### Built-in domain exemptions

By default, each built-in secret pattern is automatically allowed to reach its provider domain (e.g. `anthropic_key` → `anthropic.com`, `openai_key` → `openai.com`). This means you don't need to manually configure `allow_to_domains` for standard API keys.

User-specified `allow_to_domains` entries are merged with the built-in defaults — your entries extend (not replace) the built-ins. If you specify the same pattern name, your entry overrides the built-in for that pattern.

To disable built-in domain exemptions entirely:

```yaml
secrets:
  builtin_allow_to_domains: false
```

### Custom domain exemptions

To add exemptions for custom patterns or override built-in mappings:

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

---

## Inspectors

agentcage uses a **pluggable inspector chain**. Each HTTP request passes through a sequence of inspectors that can **block**, **flag**, or **allow** it. The chain short-circuits on the first hard block.

### Built-in inspectors

| Inspector | Default | Description |
|-----------|---------|-------------|
| `domain` | on | Domain allowlist/blocklist enforcement |
| `secrets` | on | Regex-based secret/credential leak detection (always blocks) |
| `body-size` | on | Request body size limits (loaded when `max_request_body` > 0; default is 10 MB) |
| `entropy` | off | Shannon entropy analysis — detects encrypted/compressed payloads |
| `content-type` | off | Content-type mismatch detection and base64 blob scanning |

The `domain`, `secrets`, and `body-size` inspectors are loaded automatically from their top-level config sections. The `entropy` and `content-type` inspectors must be explicitly enabled via the `inspectors:` section:

```yaml
inspectors:
  - name: entropy
    config:
      threshold: 7.0
  - name: content-type
    config:
      detect_base64: true
```

You can also enable them with no config to use all defaults:

```yaml
inspectors:
  - name: entropy
  - name: content-type
```

### Entropy inspector

Detects high-entropy payloads that may indicate encrypted or compressed data exfiltration.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `threshold` | `float` | `7.0` | Entropy threshold in bits/byte (0.0–8.0) to trigger |
| `min_body_bytes` | `int` | `256` | Minimum body size to evaluate |
| `action` | `string` | `"flag"` | `"block"` or `"flag"` |
| `exempt_content_types` | `list[string]` | `["image/", "application/gzip", "application/zip", "application/octet-stream"]` | Content-type prefixes to skip |

Reference entropy ranges:

| Content | Entropy (bits/byte) |
|---------|---------------------|
| Plain text / HTML / JSON | 3.5 – 5.5 |
| Source code | 4.5 – 5.5 |
| Base64-encoded data | ~6.0 |
| Compressed (gzip, zstd) | 7.5 – 8.0 |
| Encrypted (AES, ChaCha) | 7.9 – 8.0 |

### Content-type inspector

Detects content-type mismatches (text type with high entropy) and hidden base64 blobs.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `entropy_ceiling` | `float` | `6.5` | Max expected entropy for text content types |
| `detect_base64` | `bool` | `true` | Enable base64 blob detection |
| `base64_min_len` | `int` | `256` | Minimum base64 match length to trigger |
| `action` | `string` | `"flag"` | `"block"` or `"flag"` |

Text content-type prefixes checked: `application/json`, `application/xml`, `text/`, `application/x-www-form-urlencoded`, `multipart/form-data`.

### Writing custom inspectors

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

Then reference it in your config:

```yaml
inspectors:
  - name: my-check
    path: /path/to/my_inspector.py
    config:
      forbidden_word: "EXFIL"
```

Mount the inspector file into the proxy container via the `volumes` config option, or bake it into a custom `Containerfile.proxy`.

> **Note:** Inspectors can also implement `inspect_response(ctx)` to inspect inbound responses using the same `InspectionContext` and `InspectionResult` types. Response inspection runs after the request has been forwarded and the response received.

#### InspectionContext fields

Every inspector receives an `InspectionContext` with pre-computed data:

| Field | Type | Description |
|-------|------|-------------|
| `url` | `str` | Full request URL |
| `host` | `str` | Target hostname |
| `method` | `str` | HTTP method (GET, POST, ...) |
| `headers` | `dict[str, str]` | Request/response headers |
| `content_type` | `str` | Content-Type header value |
| `body_bytes` | `bytes \| None` | Raw body bytes |
| `body_text` | `str \| None` | Decoded body text (best-effort) |
| `body_size` | `int` | Body size in bytes |
| `body_entropy` | `float \| None` | Shannon entropy (bits/byte, 0.0–8.0) |
| `prior_results` | `list` | Results from inspectors earlier in the chain |

#### InspectionResult fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `inspector` | `str` | *(required)* | Inspector name |
| `action` | `str` | `"block"` | `"block"` or `"flag"` |
| `reason` | `str` | `""` | Human-readable explanation |
| `severity` | `str` | `"medium"` | `"info"`, `"low"`, `"medium"`, `"high"`, `"critical"` |
| `score` | `float` | `0.0` | Numeric score (for anomaly-scoring use cases) |
| `metadata` | `dict` | `{}` | Arbitrary inspector-specific data |
