<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Secret injection

Keep real secrets out of the cage container by handing it placeholder tokens and swapping them at the proxy. Read this when configuring any cage that needs API credentials.

Secrets listed in `secret_injection` are automatically excluded from the cage's Podman secrets. The proxy container receives the real value; the cage container receives the placeholder as an environment variable.

## Settings

| Setting | Type | Required | Description |
|---------|------|----------|-------------|
| `env` | `string` | yes | Environment variable name holding the real secret (read by the proxy at startup). |
| `placeholder` | `string` | yes | Token the cage sees and uses in requests (e.g. `"{{ANTHROPIC_API_KEY}}"`). |
| `inject_to` | `list[string]` | no | Domains where placeholders are replaced with real values. If omitted, injection applies to all domains. |
| `source` | `string` | no | Where to load the secret from. See [Secret backends](#secret-backends). If omitted, set it via `agentcage secret set`. |
| `transform` | `string` | no | Convert the underlying secret into a derived value at request time (e.g. mint a short-lived OAuth access token). See [Transforms](#transforms). |
| `transform_config` | `mapping` | no | Per-transform options. Required keys depend on the transform. |

## Secret backends

The `source` field controls where agentcage loads the secret value from.

| Scheme | Example | Description |
|--------|---------|-------------|
| `env:VAR` | `source: "env:ANTHROPIC_API_KEY"` | Read from a host environment variable. If `VAR` is omitted, uses the `env` field name. Resolved at cage create/start time. |
| `cmd:COMMAND` | `source: "cmd:op read op://Private/anthropic/credential --no-newline"` | Run a shell command and capture stdout. Supports 1Password, `pass`, `vault`, `gpg`, etc. 30s timeout. |
| `systemd-creds:` | `source: "systemd-creds:"` | Secret encrypted at rest with systemd-creds (TPM2 or host key). Decrypted into the Podman secret store at service start. Linux only, requires systemd 250+. Auto-detected as default on supported systems. |
| `podman:` | `source: "podman:"` | Explicitly use the Podman secret store. |
| *(absent)* | | Set the secret via `agentcage secret set` or `--set-secret`. On Linux with systemd 250+, `agentcage secret set` encrypts with systemd-creds automatically. |

```yaml
# 1Password via command backend
secret_injection:
  - env: ANTHROPIC_API_KEY
    placeholder: "{{ANTHROPIC_API_KEY}}"
    inject_to: ["api.anthropic.com"]
    source: "cmd:op read op://Private/anthropic/credential --no-newline"

# Host environment variable (CI/CD)
secret_injection:
  - env: OPENAI_API_KEY
    placeholder: "{{OPENAI_API_KEY}}"
    inject_to: ["api.openai.com"]
    source: "env:OPENAI_API_KEY"

# Explicit systemd-creds (auto-detected on Linux)
secret_injection:
  - env: ANTHROPIC_API_KEY
    placeholder: "{{ANTHROPIC_API_KEY}}"
    inject_to: ["api.anthropic.com"]
    source: "systemd-creds:"
```

> **Security note:** The `cmd:` backend runs shell commands with the privileges of the user running agentcage. This is the same trust boundary as Containerfile execution. If your `cage.yaml` comes from an untrusted source, review `source: "cmd:..."` entries before running `cage create`.

## Migrating between backends

To switch a cage between secret backends (e.g. legacy Podman store → systemd-creds), re-set each secret under the new backend:

1. `agentcage secret list <cage>` — capture the list of secret keys defined for the cage.
2. Edit `cage.yaml` and set `secret.backend` to the desired backend.
3. `agentcage cage update <cage>` — regenerate quadlets with the new backend.
4. `agentcage secret set <cage> <key>` for each key from step 1 — values are stored under the new backend.

Existing values in the old backend are not migrated automatically; once the cage is updated and new secrets are set, the old store entries are unused and can be removed with `podman secret rm` or left in place (they are inert).

## Domain restrictions

When `inject_to` is set for a rule, the proxy only injects the real value for requests to matching domains (subdomains are matched automatically). If the cage sends a placeholder to any other domain, the request is **flagged**.

When `inject_to` is omitted, the real value is injected for all outbound requests and redacted from all inbound responses.

## Literal value blocking

If a real secret value appears in any outbound request or WebSocket frame (in the URL, headers, or body), the request is **blocked** with severity `critical`. This is a defense-in-depth measure: the cage should never know real secret values, so their presence indicates the agent learned the secret outside the placeholder system (e.g. through conversation context). This check applies to all domains, including `inject_to` domains.

## Response redaction

Inbound responses are always redacted regardless of domain — any occurrence of a real secret value in response headers or body is replaced with the corresponding placeholder before the cage receives it.

## Transforms

A static `secret_injection` rule replaces a placeholder with a stored value verbatim. That works when the credential travels on the wire as-is (an API key in an `Authorization` header). It does **not** work when the underlying credential is a high-privilege long-lived secret that must be exchanged in-process for a short-lived derived value before any HTTPS request — the canonical example being a Google service-account private key, which the agent must use to sign JWTs that are then traded for OAuth2 access tokens.

A `transform` lifts that exchange into the proxy. The cage agent only ever sends the placeholder; the proxy holds the underlying credential, mints the derived value at request time, and substitutes it on the wire. The cage never sees the long-lived secret.

When `transform` is set on a rule:

- The underlying secret loaded from `env` is held only in proxy process memory.
- A literal-value match against the underlying secret is treated as **block-everywhere**, including `inject_to` domains, because the cage should never legitimately produce the raw bytes.
- If the transform fails (rate limit, mint endpoint error), the placeholder is left in place. The cage's request will fail with an unauthenticated upstream response — never silent leakage.

### google-jwt-bearer

Mints short-lived Google OAuth2 access tokens from a service-account JSON key via the JWT-bearer flow.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `scopes` | `list[string]` | yes | OAuth2 scopes to request. The minted token covers the union; out-of-scope API calls are rejected by Google. |
| `audience` | `string` | no | Token endpoint. Defaults to `https://oauth2.googleapis.com/token`. |
| `mint_rate_per_hour` | `int` | no | Cap on actual mints per hour to bound damage if a malicious skill spams the broker. Cache hits do not count. Default `60`. |
| `refresh_margin` | `int` | no | Seconds before Google's `expires_in` to refresh proactively. Default `300`. |

```yaml
secret_injection:
  - env: GOOGLE_SA_KEY_JSON
    placeholder: "{{GOOGLE_BEARER}}"
    transform: google-jwt-bearer
    transform_config:
      scopes:
        - https://www.googleapis.com/auth/gmail.readonly
        - https://www.googleapis.com/auth/calendar.readonly
    inject_to: [googleapis.com]
    source: "systemd-creds:"
```

The cage agent calls Google APIs with `Authorization: Bearer {{GOOGLE_BEARER}}`. The proxy mints a real `ya29.<...>` token at request time, caches it for ~50 minutes, and rewrites the header. Pair this with the built-in `google_oauth_access_token` secrets-inspector pattern (active by default) so a leak of the minted token to a non-Google host is blocked.

## Example

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

> **Note:** Secret injection and the [secrets inspector](inspectors.md#secrets-inspector) are complementary. The injector proactively prevents the cage from seeing real secrets; the inspector provides defense-in-depth by pattern-matching against known secret formats. Both can be active at the same time. Since injection runs before inspectors, the inspector sees the real key in the modified request — keep `allow_to_domains` entries for injected secrets so the inspector doesn't block them.

## Related

- [Protocol relays](protocol-relays.md) — the same goal for non-HTTP protocols (IMAP, SMTP).
- [Inspectors](inspectors.md) — defense-in-depth pattern detection that pairs with injection.
- [Domains](domains.md) — `inject_to` reuses the domain-matching rules from this page.
- [Ports](ports.md) — injection only fires on inspected TCP, never on passthrough or UDP.
