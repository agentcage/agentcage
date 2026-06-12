<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Secret injection

Keep real secrets out of the cage container by handing it placeholder tokens and swapping them at the proxy. Read this when configuring any cage that needs API credentials.

Secrets listed in `secret_injection` are automatically excluded from the cage's Podman secrets. The proxy container receives the real value; the cage container receives the placeholder as an environment variable.

## Settings

| Setting | Type | Required | Description |
|---------|------|----------|-------------|
| `env` | `string` | yes | Environment variable name holding the real secret (read by the proxy at startup). |
| `placeholder` | `string` | no | Token the cage sees and uses in requests. **Omit it** (recommended) and agentcage generates an entropic token like `{{placeholder_anthropic_api_key_9f3a1c0b7d2e4a85}}`, persisted into the cage's stored config at create/update/edit time. See [Placeholder entropy](#placeholder-entropy). |
| `inject_to` | `list[string]` | no | Domains where placeholders are replaced with real values. If omitted, injection applies to all domains. |
| `inject_body` | `bool` | no | When `false` (the default), placeholders are only substituted inside known credential-bearing request headers (the [auth-header allow-list](#injection-scope)). Set to `true` to also inject into the request URL (query string), every header, the request body, and WebSocket frames. See [Injection scope](#injection-scope). |
| `inject_headers` | `list[string]` | no | Extra request headers — added to the built-in auth-header allow-list — to treat as credential-bearing under the strict default. Matched case-insensitively. Use for APIs whose auth header isn't a common convention. See [Injection scope](#injection-scope). |
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
# 1Password via command backend (placeholder omitted → auto-generated)
secret_injection:
  - env: ANTHROPIC_API_KEY
    inject_to: ["api.anthropic.com"]
    source: "cmd:op read op://Private/anthropic/credential --no-newline"

# Host environment variable (CI/CD)
secret_injection:
  - env: OPENAI_API_KEY
    inject_to: ["api.openai.com"]
    source: "env:OPENAI_API_KEY"

# Explicit systemd-creds (auto-detected on Linux)
secret_injection:
  - env: ANTHROPIC_API_KEY
    inject_to: ["api.anthropic.com"]
    source: "systemd-creds:"
```

## Placeholder entropy

When a rule omits `placeholder:`, agentcage generates
`{{placeholder_<env_lowercase>_<16 hex chars>}}` (64 bits of entropy) and
persists it into the cage's stored config the first time the rule is deployed
(`cage create`, `cage update -c`, `cage edit`, or `agentcage run`). The token
stays stable across updates — it is carried over by `env` name rather than
regenerated, so long-running processes inside the cage keep working.

Why entropy matters: the proxy substitutes the placeholder as a **literal
string** wherever injection applies. A guessable placeholder like
`{{GH_TOKEN}}` is an accidental-substitution hazard — if a file the agent
sends outbound legitimately contains that text (a template file, docs, CI
config), the real secret would be injected into it. A random suffix makes
such collisions vanishingly unlikely. `agentcage cage create` warns when an
explicit placeholder uses the bare `{{ENV_NAME}}` convention.

Explicit `placeholder:` values remain fully supported — some clients validate
credential format before sending (e.g. a `ghp_`-prefixed fake to pass a
client-side check). To see the generated token for a cage, run
`agentcage secret list <cage>` (placeholders are decoys, never sensitive).

> **Note:** filling an omitted placeholder rewrites the stored `cage.yaml`
> (under `~/.config/agentcage/cages/<name>/`), which normalizes the YAML and
> drops comments in that file. Configs generated from scaffolds already carry
> a generated placeholder, so they are stored untouched.

## How placeholders and values reach the containers

Placeholders are delivered to the cage via a derived env-file —
`<state>/<name>/cage-env/placeholders.env`, referenced by the cage quadlet's
`EnvironmentFile=` and bind-mounted (directory) at `/run/agentcage/env`.
Podman re-reads the file at every container creation, and the file is
regenerated from the stored `cage.yaml` on every deploy **and restart** — so
a placeholder change applies with a plain `agentcage cage restart`, no
`cage update` needed. The same directory is visible inside the cage, so
in-cage shells can `source /run/agentcage/env/placeholders.env`.

Real secret values are staged by the egress service at every start as 0600
files in a per-cage tmpfs directory (`$XDG_RUNTIME_DIR/agentcage/<name>/secrets`),
bind-mounted read-only into the **egress only** at `/home/acproxy/secrets`
(the cage never sees them). Staging uses `podman secret inspect --showsecret`
and is best-effort on podman older than 4.7 — the `Secret=` env channel still
carries the boot-time value there; only live value updates depend on the
file channel.

## Live updates: `secret set` without a restart

On the container and vm backends, `agentcage secret set` on a **running**
cage applies the new value live: the value is re-staged into the tmpfs file
channel and the proxy hot-reloads its rules on the next request — neither
container is recreated. The proxy prefers staged files over its (frozen)
process environment, so the change is effective for all subsequent requests
within moments. `agentcage secret rm` works the same way, staging an empty
tombstone file so injection and redaction stop immediately instead of
falling back to the stale value frozen in the egress environment.

### Adding a brand-new secret in one command

```bash
agentcage secret set mycage NEW_API_KEY --declare --inject-to api.example.com
```

`--declare` appends a `secret_injection` rule (entropic placeholder) to the
stored cage.yaml, stores the value, stages it live, and converges the
quadlet unit files — all without restarting. New `cage exec` / `cage shell`
sessions carry the placeholder immediately: exec sessions read the current
placeholders from the stored config at exec time, so even secrets declared
after the cage container started are usable in a fresh session. Omitting
`--inject-to` makes the rule inject for **all** allowed domains — the CLI
warns; scope it when you can. `--placeholder` overrides the generated
token. Without `--declare`, setting an undeclared key stores an inert
orphan value (the CLI now says so and points at `--declare`).

`secret set` also quietly regenerates and reinstalls the cage's quadlets
(no restart) so a crash-restart or reboot comes up with the new secret's
`Secret=`/staging lines — the unit files never drift from `cage.yaml`.

Notes and limits:

- Already-running processes inside the cage keep their current environment;
  the boot process (PID 1) picks up new placeholders on the next restart
  via the `EnvironmentFile=` channel. New exec sessions are current always.
- Cages whose **running** egress predates the staging mount fall back to a
  restart — which adopts the freshly converged units, so the *next*
  `secret set` goes live.
- apple-container keeps the restart-on-set behavior for now (its staging
  lifecycle is tied to `start()`); exec-time placeholder injection works
  there too.
- Long-lived connections (websockets, streaming responses) opened before
  the change keep their original values until re-established — same
  semantics as every other proxy hot-reloaded setting.

> **Security note:** The `cmd:` backend runs shell commands with the privileges of the user running agentcage. This is the same trust boundary as Containerfile execution. If your `cage.yaml` comes from an untrusted source, review `source: "cmd:..."` entries before running `cage create`.

## Migrating between backends

To switch a cage between secret backends (e.g. legacy Podman store → systemd-creds), re-set each secret under the new backend:

1. `agentcage secret list <cage>` — capture the list of secret keys defined for the cage.
2. Edit `cage.yaml` and set `secret.backend` to the desired backend.
3. `agentcage cage update <cage>` — regenerate quadlets with the new backend.
4. `agentcage secret set <cage> <key>` for each key from step 1 — values are stored under the new backend.

Existing values in the old backend are not migrated automatically; once the cage is updated and new secrets are set, the old store entries are unused and can be removed with `podman secret rm` or left in place (they are inert).

> **Orphan secrets:** `agentcage secret set <cage> <key>` stores a value even when no `secret_injection` rule, `podman_secret`, or relay credential references `<key>`. Such a value is staged at start but never injected or redacted. `agentcage secret list` shows these with type `orphan` so you can either add a matching rule or remove the value with `agentcage secret rm`.

## Domain restrictions

When `inject_to` is set for a rule, the proxy only injects the real value for requests to matching domains (subdomains are matched automatically). If the cage sends a placeholder to any other domain, the request is **flagged**.

When `inject_to` is omitted, the real value is injected for all outbound requests and redacted from all inbound responses.

## Injection scope

By default secret injection is **strict**: the proxy only swaps a placeholder for its real value when the placeholder appears in a **credential-bearing request header** (the auth channel). Placeholders left anywhere else — the URL/query string, the request body, or a non-credential header — pass through unchanged. This keeps credentials confined to the auth channel and avoids accidentally writing secrets into request bodies that might be logged or echoed.

A request header is treated as credential-bearing when its name **contains `auth`, `key`, or `token`** (case-insensitive). This single heuristic covers the documented auth header of virtually every API without hard-coding vendor names — for example `Authorization`, `x-api-key` (**Anthropic**), `api-key` (Azure, Pinecone), `apikey` (Supabase), `x-goog-api-key` (Google), `private-token` (GitLab), `x-auth-key` (Cloudflare), `x-subscription-token` (Brave), `dd-api-key` (Datadog), `circle-token` (CircleCI), `x-figma-token`, `fastly-key`, `x-shopify-access-token`, and so on all match.

> Anthropic's API authenticates with `x-api-key` (not `Authorization`). It matches on `key`, so `secret_injection` works against `api.anthropic.com` out of the box.

If your API uses a credential header whose name has **none** of those keywords (e.g. Honeycomb's `X-Honeycomb-Team`), add it explicitly with `inject_headers` (matched case-insensitively; the keyword default still applies to your other headers):

```yaml
secret_injection:
  - env: HONEYCOMB_API_KEY
    placeholder: "{{HONEYCOMB_API_KEY}}"
    inject_to: ["api.honeycomb.io"]
    inject_headers: ["X-Honeycomb-Team"]
```

If the API carries the credential **outside any header** — a `?api_key=` query parameter (SerpAPI), `?auth=` / `?access_token=` (Firebase), or a JSON body field (Plaid) — header injection can't reach it (the keyword heuristic applies to header *names* only, not the URL or body). Set `inject_body: true` to substitute placeholders in the URL, every header, the request body, and WebSocket frames:

```yaml
secret_injection:
  - env: SERPAPI_KEY
    placeholder: "{{SERPAPI_KEY}}"
    inject_to: ["serpapi.com"]
    inject_body: true   # key travels as ?api_key=
```

> **Security note:** `inject_body: true` is looser by design — a placeholder anywhere in the body is replaced, including bodies that may be logged or echoed downstream. Prefer the header-based default (with `inject_headers` if needed) whenever the API supports a header credential.

Response redaction and literal-value blocking are unaffected by these toggles — real secret values are always redacted from responses and always blocked when found leaking outbound, regardless of `inject_body` / `inject_headers`.

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
