# Configuration Reference

Full reference for all agentcage configuration settings — types, defaults, and examples.

For architecture details, see [Architecture](architecture.md).
Example configs: [`basic/cage.yaml`](../examples/basic/) | [`openclaw/cage.yaml`](../src/agentcage/scaffolds/openclaw/)

## Table of Contents

- [Top-level settings](#top-level-settings)
- [Container settings](#container-settings-container)
  - [Ports](#ports)
- [Container hardening](#container-hardening)
- [Traffic capture](#traffic-capture-capture)
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
| `isolation` | `string` | `"container"` | Isolation backend: `"container"` (rootless Podman, default) or `"vm"` (Lima VM). Old `"firecracker"` configs are silently upgraded to `"vm"`. |
| `lifecycle` | `string` | `"service"` | Cage lifecycle mode: `"service"` (always running, auto-restart), `"interactive"` (on-demand, stops on exit, state preserved), or `"ephemeral"` (stops on exit, destroyed by `cage prune`). |
| `scaffold` | `string` | `""` | Scaffold name used to generate this config (shown in `cage list` output). |
| `log_allowed` | `bool` | `false` | Log allowed requests to the proxy journal |
| `max_request_body` | `int` | `10485760` (10 MB) | Max request body size in bytes. Set to `0` to disable the body-size limit |
| `dns_servers` | `list[string]` | *(from host `/etc/resolv.conf`)* | Upstream DNS servers used by both the dnsmasq sidecar and the proxy container |

### VM settings (`vm:`)

VM-specific settings. Only used when `isolation: vm`.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `vcpus` | int | `4` | Number of virtual CPUs to allocate to the VM. |
| `mem_mb` | int | `4096` | VM memory in megabytes. |

See [Lima VM Isolation](vm.md) for setup and details.

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
| `ports` | `list[string]` | `[]` | Published port specs — see [Ports](#ports) below |
| `podman_secrets` | `list[string]` | `[]` | [Podman secret](https://docs.podman.io/en/latest/markdown/podman-secret.1.html) names (injected as env vars) |
| `user` | `string` | `"1000:1000"` | UID:GID to run as. Set to `""` to use the image default. See [Podman `--user`](https://docs.podman.io/en/latest/markdown/podman-run.1.html) |
| `userns` | `string` | `""` | User namespace mode (e.g. `"keep-id"`). See [Podman `--userns`](https://docs.podman.io/en/latest/markdown/podman-run.1.html) |
| `memory` | `string` | *(none)* | Memory limit (e.g. `"4g"`). See [Podman `--memory`](https://docs.podman.io/en/latest/markdown/podman-run.1.html) |
| `cpus` | `string` | *(none)* | CPU limit (e.g. `"2.0"`). See [Podman `--cpus`](https://docs.podman.io/en/latest/markdown/podman-run.1.html) |
| `nested_containers` | `bool` | `false` | Enable podman-in-podman support. See [Nested containers](#nested-containers) below |

### Ports

Publish container ports to the host. Each entry is a string in one of two formats:

| Format | Example | Description |
|--------|---------|-------------|
| `"BIND:HOST_PORT:CONTAINER_PORT"` | `"127.0.0.1:8080:80"` | Bind to a specific interface |
| `"HOST_PORT:CONTAINER_PORT"` | `"8080:80"` | Bind to localhost (`127.0.0.1`) |

Ports must be integers between 1 and 65535. The three-part form with an explicit bind address is recommended — binding to `127.0.0.1` ensures the port is only accessible from the host, not from the network.

```yaml
container:
  ports:
    # Recommended: bind to localhost only
    - "127.0.0.1:8080:8080"

    # Bind to all interfaces (accessible from LAN)
    - "0.0.0.0:3000:3000"

    # Short form (binds to 127.0.0.1)
    - "9090:9090"
```

Port conflicts are detected at `cage create` / `cage update` time — if a host port is already in use, the command fails with a suggestion to pick a different port.

### Nested containers

When `nested_containers: true` is set, the cage container can run podman (and docker via a shim) to spawn inner containers. This is required for AI agent frameworks like NanoClaw that create Docker containers as part of their workflow.

Enabling this option automatically:
- Adds 16 Linux capabilities (SYS_ADMIN, SYS_CHROOT, MKNOD, etc.) instead of the default `DropCapability=ALL`
- Forces `User=0` and `NoNewPrivileges=false`
- Adds `/dev/fuse` device and `seccomp=unconfined`
- Creates a persistent storage volume for inner podman state
- Bind-mounts a Docker CLI shim and podman config files

The nested-containers base image must be built first with `./build.sh` from the scaffold directory. See the [NanoClaw guide](../src/agentcage/scaffolds/nanoclaw/README.md) for a complete walkthrough.

```yaml
container:
  image: "localhost/agentcage-nested"
  nested_containers: true
```

> **Security note:** Nested containers require elevated capabilities that weaken container hardening. All network-level protections (proxy inspection, domain filtering, secret detection) remain active. Only supported with `isolation: container`. See [Security & Threat Model](security.md) for details.

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
| `timeout_start_sec` | `int` | `120` | Systemd `TimeoutStartSec` |
| `timeout_stop_sec` | `int` | `30` | Systemd `TimeoutStopSec` |

---

## Secret injection (`secret_injection:`)

Secret injection prevents secrets from ever entering the cage container. Instead of passing real secrets to the cage, it receives placeholder tokens (e.g. `{{ANTHROPIC_API_KEY}}`). The proxy transparently swaps placeholders for real values on outbound requests and redacts real values back to placeholders on inbound responses.

Secrets listed in `secret_injection` are **automatically excluded** from the cage's Podman secrets. The proxy container receives the real value, and the cage container receives the placeholder as an environment variable.

| Setting | Type | Required | Description |
|---------|------|----------|-------------|
| `env` | `string` | yes | Environment variable name holding the real secret (read by the proxy at startup) |
| `placeholder` | `string` | yes | Token the cage sees and uses in requests (e.g. `"{{ANTHROPIC_API_KEY}}"`) |
| `inject_to` | `list[string]` | no | Domains where placeholders are replaced with real values. If omitted, injection applies to all domains |
| `source` | `string` | no | Where to load the secret from. See [Secret backends](#secret-backends) below. If omitted, the secret must be set via `agentcage secret set` |
| `transform` | `string` | no | Convert the underlying secret into a derived value at request time (e.g. mint a short-lived OAuth access token from a service-account private key). See [Transforms](#transforms) below. |
| `transform_config` | `mapping` | no | Per-transform options. Required keys depend on the transform. |

### Secret backends

The `source` field controls where agentcage loads the secret value from. This enables integration with external secret managers and encrypted storage.

| Scheme | Example | Description |
|--------|---------|-------------|
| `env:VAR` | `source: "env:ANTHROPIC_API_KEY"` | Read from a host environment variable. If `VAR` is omitted, uses the `env` field name. Resolved at cage create/start time. |
| `cmd:COMMAND` | `source: "cmd:op read op://Private/anthropic/credential --no-newline"` | Run a shell command and capture stdout. Supports any CLI tool (1Password, `pass`, `vault`, `gpg`). 30s timeout. Resolved at cage create/start time. |
| `systemd-creds:` | `source: "systemd-creds:"` | Secret encrypted at rest with systemd-creds (TPM2 or host key). Decrypted into Podman secret store at service start time. Linux only, requires systemd 250+. Auto-detected as default on supported systems. |
| `podman:` | `source: "podman:"` | Explicitly use the Podman secret store (existing behavior). |
| (absent) | | Secret must be set via `agentcage secret set` or `--set-secret`. On Linux with systemd 250+, `agentcage secret set` encrypts with systemd-creds automatically. |

**Examples:**

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

**Security note:** The `cmd:` backend runs shell commands with the privileges of the user running agentcage. This is the same trust boundary as Containerfile execution. If your `cage.yaml` comes from an untrusted source, review `source: "cmd:..."` entries before running `cage create`.

**Migration:** Existing cages with secrets in Podman's store can be migrated to systemd-creds encryption with `agentcage secret migrate CAGE`.

### Domain restrictions

When `inject_to` is set for a rule, the proxy only injects the real value for requests to matching domains (subdomains are matched automatically). If the cage sends a placeholder to any other domain, the request is **flagged**.

When `inject_to` is omitted, the real value is injected for all outbound requests and redacted from all inbound responses.

### Literal value blocking

If a real secret value appears in any outbound request or WebSocket frame (in the URL, headers, or body), the request is **blocked** with severity `critical`. This is a defense-in-depth measure: the cage should never know real secret values, so their presence indicates the agent learned the secret outside the placeholder system (e.g. through conversation context). This check applies to all domains, including `inject_to` domains. Domains listed in `redact_to` are exempt because outbound redaction handles the substitution.

### Response redaction

Inbound responses are always redacted regardless of domain -- any occurrence of a real secret value in response headers or body is replaced with the corresponding placeholder before the cage receives it.

### Transforms

A static `secret_injection` rule replaces a placeholder with a stored real value verbatim. That works when the credential travels on the wire as-is (an API key in an `Authorization` header). It does **not** work when the underlying credential is a high-privilege long-lived secret that is supposed to be exchanged in-process for a short-lived derived value before any HTTPS request — the canonical example being a Google service-account private key, which the agent must use to sign JWTs that are then traded for OAuth2 access tokens.

A `transform` lifts that exchange into the proxy. The cage agent only ever sends the placeholder; the proxy holds the underlying credential, mints the derived value at request time, and substitutes it on the wire. The cage never sees the long-lived secret.

When `transform` is set on a rule:
- The underlying secret loaded from `env` is held only in proxy process memory.
- A literal-value match against the underlying secret is treated as **block-everywhere**, including `inject_to` domains, because the cage should never legitimately produce the raw bytes (the proxy mints derived values for it).
- If the transform fails (rate-limit hit, mint endpoint error, etc.), the placeholder is left in place. The cage's request will fail with an unauthenticated upstream response — never silent leakage.

#### `google-jwt-bearer`

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

> **Note:** Secret injection and the `secrets` inspector are complementary. The injector proactively prevents the cage from seeing real secrets, while the `secrets` inspector provides defense-in-depth by pattern-matching against known secret formats. Both can be active at the same time. Since injection runs *before* inspectors, the `secrets` inspector sees the real key in the modified request -- keep `allow_to_domains` entries for injected secrets so the inspector doesn't block them.

---

## Protocol relays (`protocol_relays:`)

`secret_injection` only handles credentials that travel over HTTP(S). For non-HTTP protocols (IMAP, etc.), use a **protocol relay**: a stateful in-proxy listener that performs the upstream authentication on behalf of the cage and bridges the post-auth byte stream while applying a per-protocol policy.

Like `secret_injection`, the goal is the same: the cage container holds no upstream credentials. It connects to a localhost address inside the proxy container; the relay handles auth and forwards traffic.

| Setting | Type | Required | Description |
|---------|------|----------|-------------|
| Setting | Type | Required | Description |
|---------|------|----------|-------------|
| `name` | `string` | yes | Human-readable identifier (used in audit logs). |
| `type` | `string` | yes | Protocol type. Currently: `imap`, `smtp`. |
| `listen` | `string` | yes | `host:port` the relay binds inside the proxy container. The cage points its client here. |
| `upstream.host` | `string` | yes | Real upstream server hostname. |
| `upstream.port` | `int` | yes | Real upstream port (e.g. 993 for IMAPS, 465 for SMTPS). |
| `upstream.tls` | `bool` | no | Whether to use TLS upstream. Default `true`. |
| `auth.type` | `string` | yes | Auth scheme. `imap-login` for IMAP; `smtp-plain` for SMTP. |
| `auth.user_source` | `string` | yes | Source for the username. Same scheme grammar as `secret_injection.source` (`env:`, `cmd:`, `systemd-creds:`, `podman:`). |
| `auth.password_source` | `string` | yes | Source for the password, same grammar as above. |

### IMAP-specific policy (`type: imap`)

| Setting | Type | Required | Description |
|---------|------|----------|-------------|
| `policy.readonly` | `bool` | no | If `true`, block APPEND/DELETE/STORE/EXPUNGE/CREATE/RENAME/MOVE/COPY plus the write subcommands of UID. Default `false`. |
| `policy.folder_allowlist` | `list[string]` | no | If non-empty, restrict SELECT/EXAMINE/STATUS to these mailbox names. LIST/LSUB always pass through (metadata only). Default `[]` (no filter). |
| `policy.require_authentication` | `bool` | no | If `true` (default), rewrite SEARCH commands to require `dkim=pass spf=pass dmarc=pass` server-side, and block sequence-numbered FETCH/STORE so the cage can't bypass the filter. See "Inbound message filtering" below. Set `false` if the upstream MTA doesn't stamp `Authentication-Results`. |
| `policy.from_allowlist` | `list[string]` | no | If non-empty, AND-restrict SEARCH responses to messages whose `From` header substring-matches one of the listed addresses. Composes with `require_authentication` — both filters narrow the same SEARCH. See "Inbound message filtering" below. Default `[]` (no constraint). **Only safe when paired with `require_authentication`** — substring match alone can be spoofed via the From display-name field. |
| `policy.conn_rate_limit` | `string` | no | Connection rate cap, e.g. `"30/min"`. Default `"30/min"`. |

### SMTP-specific policy (`type: smtp`)

| Setting | Type | Required | Description |
|---------|------|----------|-------------|
| `policy.sender_allowlist` | `list[string]` | no | If non-empty, only these `MAIL FROM` addresses are accepted. Empty = any. |
| `policy.recipient_allowlist.addresses` | `list[string]` | no | Exact addresses allowed in `RCPT TO`. |
| `policy.recipient_allowlist.domains` | `list[string]` | no | Domain suffixes allowed in `RCPT TO` (e.g. `example.com` matches `bob@x.example.com`). |
| `policy.max_message_bytes` | `int` | no | Upper bound on `DATA` payload. Default 5 MiB. |
| `policy.max_recipients` | `int` | no | Upper bound on `RCPT TO` per transaction. Default 10. |
| `policy.send_rate_limit` | `string` | no | Cap on accepted DATA transactions, e.g. `"20/hour"`. Default `"20/hour"`. |
| `policy.conn_rate_limit` | `string` | no | Cap on inbound connections from the cage. Default `"30/min"`. |
| `policy.bypass_inspectors_for_allowlisted` | `list[string]` | no | Inspector names to skip on `DATA` when every recipient matched `recipient_allowlist`. Default `["secrets", "entropy", "content-type"]` — the three inspectors most prone to false-positive on legitimate human email content (forwarded recovery codes, base64 attachments, PGP-signed text/plain, long URLs). Set to `[]` to keep strict body filtering even for trusted recipients. `body-size` always applies as a structural cap. |

If both `addresses` and `domains` are empty, the recipient gate is open — every `RCPT TO` is accepted. Setting either turns it on; an address is admitted iff it matches `addresses` or its domain matches `domains`. As a shorthand you can pass a flat list for `recipient_allowlist`, treated as `addresses`.

In addition to the per-protocol policy above, the SMTP relay runs every `DATA` payload through the proxy's existing inspector chain (`secrets`, `entropy`, `content-type`, `body-size`). A blocking inspector result rejects the message with `550` before it reaches upstream — so a leaked Anthropic key in an outbound email body is blocked the same way it would be on an HTTP request. The `domain` inspector is intentionally skipped (its host-allowlist is HTTP-shaped; the equivalent SMTP gate is `recipient_allowlist`).

**Trust the recipient gate for body content.** When `recipient_allowlist` is non-empty AND every recipient in the transaction matched it (blocked recipients got `550` at `RCPT TO` time and never made it to `DATA`), the inspectors named in `bypass_inspectors_for_allowlisted` are skipped. The default skip set is `secrets` + `entropy` + `content-type`, on the theory that an operator who explicitly named trusted recipients is willing to accept "agent emailed Luca a recovery code," "agent forwarded a base64 attachment to Luca," and "agent sent a PGP-signed mail with a 600-char signature in the body" instead of having those messages blocked. The `content-type` inspector in particular has a different cost/benefit balance for SMTP than for HTTP: a 600-char base64 chunk in a `text/plain` HTTP body is a strong exfil signal, but in email it's a normal artifact of forwarded content, signatures, and quoted tokens. `body-size` always runs as a structural cap. With no allowlist (open recipient gate) the bypass cannot trigger — inspectors run strictly. A `smtp_data_bypass` audit entry records every bypass for visibility.

### IMAP relay behavior

On client connect, the relay opens an authenticated TLS connection upstream and replies to the client with `* PREAUTH ...` — the canonical IMAP signal that the connection is already authenticated. Compliant clients (himalaya, mutt, etc.) skip LOGIN and proceed.

If the cage tries LOGIN or AUTHENTICATE anyway, the relay intercepts and forges an `OK already authenticated` response — the spurious credentials never reach the upstream server.

Each policy decision (allowed, blocked, login attempt) emits a structured log line that the proxy container forwards to the existing audit pipeline.

### Inbound message filtering

Two policy fields — `require_authentication` and `from_allowlist` — narrow which messages the cage can see, by rewriting SEARCH commands on their way upstream so the IMAP server applies the filter server-side. Both compose: when both are active, a UID must satisfy every active filter to appear in SEARCH responses.

**Mechanism (shared by both filters).** Every `SEARCH` and `UID SEARCH` command from the cage is rewritten on its way upstream. The relay appends additional IMAP search criteria (RFC 3501 §6.4.4) to the client's original criteria. IMAP search keys are implicit-AND, so appending narrows the result set without disturbing what the client asked for. The upstream IMAP server applies the filter. The relay forwards the response verbatim. The cage only ever learns UIDs of messages that satisfy both its own criteria and the configured filters.

To prevent bypass, sequence-numbered `FETCH` and `STORE` are rejected at the command layer when any filter is active (`UID FETCH` / `UID STORE` remain allowed). Without this gate, a cage could issue `FETCH 1:* (UID)` and learn UIDs the rewritten SEARCH would have hidden. Multi-line SEARCH commands containing IMAP literal-string criteria (`{N}\r\n<bytes>`) are rejected with `NO`, since the rewrite logic only handles single-line commands. Modern IMAP clients (himalaya, mutt) build queries with quoted strings, not literals, so this is a no-op for the supported deployments.

A `kind: imap_search_rewritten` audit entry records every rewrite, with `reason` listing the active filters (`require_authentication`, `from_allowlist`, or `require_authentication+from_allowlist`). Sequence-numbered FETCH/STORE rejections emit `kind: imap_command` with `decision: blocked, reason: UID-prefix required when inbound filter is active`.

#### `require_authentication` (default `true`)

Appends three `HEADER "Authentication-Results"` criteria — for `dkim=pass`, `spf=pass`, and `dmarc=pass` — so the cage only sees mail the upstream MTA stamped as authenticated at the receiving boundary. The receiving MTA (Migadu, Fastmail, etc.) writes the `Authentication-Results:` header on every inbound message; the relay reads its stamp via the IMAP server's substring search.

`HEADER` is a substring match on the raw header value. The RFC 8601 result tokens (`none`, `pass`, `fail`, `neutral`, `softfail`, `temperror`, `permerror`, `policy`) are a closed set with `pass` as the only one starting with that string, so `dkim=pass` substring match is precise enough in practice. The relay does not parse the `Authentication-Results` value structurally — that's the upstream MTA's job.

**Default on.** Most upstream MTAs stamp `Authentication-Results`, and a cage acting on unauthenticated mail is almost always wrong. Set `false` only when the upstream MTA doesn't write that header, or for relays explicitly intended for unfiltered access (e.g. an admin/inspection relay).

#### `from_allowlist` (default `[]`)

Appends `OR FROM "addr1" FROM "addr2" ...` criteria so the cage only sees mail from the allowlisted senders. For N addresses, the relay emits N−1 `OR` keywords followed by N `FROM "..."` keys, which IMAP parses left-fold ((`a OR b) OR c`).

```yaml
policy:
  from_allowlist: [luca@luca.io, mirta.rotondo@gmail.com]
```

**Caveat: `from_allowlist` is only safe when paired with `require_authentication`.** IMAP `FROM` is a substring match on the entire raw From header, including the display-name part. A forged `From: "luca@luca.io" <attacker@evil.com>` would substring-match the allowlist on the display name even though the actual sender is `attacker@evil.com`. With `require_authentication` on, DKIM/DMARC alignment at the upstream MTA already rejects messages whose `From` domain doesn't match the signing domain — so the impostor is filtered out before the cage's SEARCH ever runs. Without `require_authentication`, `from_allowlist` trusts the From substring at face value. Both filters together is the supported configuration.

### SMTP relay behavior

The relay opens a single TLS connection to the upstream submission host (port 465 / SMTPS), performs `EHLO` + `AUTH PLAIN` with proxy-held credentials, and reuses that connection for every transaction in the cage's session.

The cage talks plaintext SMTP to the relay's listener. The relay greets it with `220 agentcage-smtp-relay ready` and advertises capabilities the cage actually needs (`8BITMIME`, `SIZE`, `PIPELINING`, `ENHANCEDSTATUSCODES`, `SMTPUTF8`) but **deliberately does not advertise `STARTTLS` or `AUTH`** — the connection is already on loopback inside the proxy and the relay handled real auth upstream. If the cage sends `AUTH` anyway, the relay forges `235` without forwarding any credential bytes.

Per `RCPT TO`, the relay decides allow/deny against `recipient_allowlist`. Standard SMTP semantics: a transaction with mixed legitimate + disallowed recipients delivers to the legitimate ones and gives the cage `550` for each disallowed address. A transaction whose recipients are *all* rejected fails — `MAIL FROM` is the natural retry point.

`DATA` is buffered, dot-unstuffed, then run through the inspector chain (skipping the HTTP-only `domain` inspector). Any `block` result causes a `550` and the transaction is dropped — upstream never sees the message. Inspectors that return `flag` are audited but not blocking. Allowed messages are forwarded to upstream with proper dot-stuffing, and the upstream's queue ID is echoed back in the `250` response.

### Example (Migadu IMAP, read-only INBOX)

```yaml
protocol_relays:
  - name: migadu-imap
    type: imap
    listen: "10.89.0.11:1143"
    upstream:
      host: imap.migadu.com
      port: 993
      tls: true
    auth:
      type: imap-login
      user_source: "systemd-creds:MIGADU_USER"
      password_source: "systemd-creds:MIGADU_PASSWORD"
    policy:
      readonly: true
      folder_allowlist: [INBOX, Sent]
      conn_rate_limit: 30/min
```

Inside the cage, point the IMAP client (himalaya, etc.) at `proxy.cage.local:1143` with no password — the relay supplies it. Tighten `domains.allow` to drop `imap.migadu.com`: only the relay should reach the real IMAP host.

### Example (Migadu SMTP, allowlist + body inspection)

```yaml
protocol_relays:
  - name: migadu-smtp
    type: smtp
    listen: "0.0.0.0:1025"
    upstream:
      host: smtp.migadu.com
      port: 465
      tls: true
    auth:
      type: smtp-plain
      user_source: "podman:MIGADU_USER"
      password_source: "podman:MIGADU_PASSWORD"
    policy:
      sender_allowlist: ["agent@example.com"]
      recipient_allowlist:
        addresses: ["friend@example.com"]
        domains:   ["example.com"]
      max_message_bytes: 5242880
      max_recipients: 5
      send_rate_limit: "20/hour"
```

Inside the cage, point the SMTP client at `proxy.cage.local:1025` with no auth — the relay supplies it. Body filtering happens automatically: the same `secrets` inspector that catches an Anthropic key in an HTTP request body will catch one in an outbound email.

> **Note:** Secrets named in `auth.user_source` / `auth.password_source` are automatically stripped from the cage's `podman_secrets` and `env` blocks the same way `secret_injection.env` is — they exist only in the proxy.

---

## Domain filtering (`domains:`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `allow` | `list[string]` | `[]` | Allowlist mode — only these domains (and their subdomains) are reachable |
| `block` | `list[string]` | `[]` | Blocklist mode — all domains except these are reachable |
| `passthrough` | `list[string]` | `[]` | Domains that bypass TLS interception (no MITM). Still subject to DNS filtering |

**Rules:**
- `allow:` present → allowlist mode (only listed domains reachable)
- `block:` present → blocklist mode (all except listed domains)
- Both `allow` + `block` → validation error
- Neither → no filtering (all domains reachable)
- `passthrough:` → listed domains pass TLS through without interception

Subdomains are matched automatically — adding `example.com` also matches `api.example.com`, `sub.api.example.com`, etc.

### Basic allowlist

```yaml
domains:
  allow:
    - api.anthropic.com
    - github.com        # also matches *.github.com
    - pypi.org
```

### TLS passthrough

Some protocols (WhatsApp/Noise Protocol, gRPC with certificate pinning) break under MITM interception. Use `passthrough` to let these connections through without TLS interception while still enforcing DNS-level domain filtering:

```yaml
domains:
  allow:
    - anthropic.com
    - whatsapp.com
    - whatsapp.net
  passthrough:
    - whatsapp.com
    - whatsapp.net
```

Passthrough domains are automatically added to the DNS allowlist for resolution. The proxy will not intercept or inspect TLS traffic to these domains — use this only for protocols that require it.

> **Security note:** Passthrough domains bypass all proxy inspection (secret detection, entropy analysis, content-type checks). Only add domains that genuinely require direct TLS connections.

### Blocklist mode

```yaml
domains:
  block:
    - evil.com
    - malware.example.org
```

### Legacy format (backward compatible)

The old `mode` + `list` format is still accepted:

```yaml
# Deprecated — use allow/block instead
domains:
  mode: allowlist
  list:
    - api.anthropic.com
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
| `brave_api_key` | `BSAI[a-zA-Z0-9_-]{20,255}` | `BSAabc123...` |
| `telegram_bot_token` | `[0-9]{8,10}:[A-Za-z0-9_-]{35}` | `123456789:AAAA...` |
| `discord_bot_token` | `[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}` | `MAAA...BBBB.CCCC...` |
| `firecrawl_key` | `fc-[a-zA-Z0-9]{32,}` | `fc-abc123...` |

### Built-in domain exemptions

By default, each built-in secret pattern is automatically allowed to reach its provider domain (e.g. `anthropic_key` → `anthropic.com`, `openai_key` → `openai.com`). This means you don't need to manually configure `allow_to_domains` for standard secrets.

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

## Traffic capture (`capture:`)

Traffic capture records full request/response bodies (decrypted) to a JSONL file for forensic analysis and HAR export. This is opt-in and disabled by default.

Each captured flow contains two perspectives:
- **INBOUND** — what the bot sees inside the cage (placeholders, redacted secrets). Safe to share.
- **OUTBOUND** — what goes on the wire (real injected secrets, raw server responses). Treat as sensitive.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enable_har` | `bool` | `false` | Enable HAR traffic capture. Creates a volume mount for the capture file. |
| `max_body_size` | `int` | `10485760` (10 MB) | Truncate bodies larger than this. Truncated entries are marked with `bodyTruncated: true`. |
| `min_action` | `string` | `"all"` | Minimum inspector action to trigger capture: `"all"` (capture everything), `"flag"` (flagged + blocked only), `"block"` (blocked only). |
| `domains` | `list[string]` | `[]` | Domain allowlist — only capture flows to matching domains. Empty = capture all. Subdomains are matched automatically. |
| `exclude_domains` | `list[string]` | `[]` | Domain blocklist — skip flows to matching domains. |

### Example

```yaml
capture:
  enable_har: true
  max_body_size: 10485760     # 10MB (default)
  min_action: all             # capture everything
  domains: []                 # all domains
  exclude_domains: []         # no exclusions
```

### Capture only blocked/flagged traffic to specific domains

```yaml
capture:
  enable_har: true
  min_action: flag            # skip allowed requests
  domains:
    - anthropic.com           # only capture anthropic traffic
  max_body_size: 1048576      # 1MB — keep capture file small
```

### Storage considerations

- Each simple API call generates ~1-5 KB of capture data.
- Large request/response bodies (file uploads, model outputs) can be much larger — use `max_body_size` to cap per-body size.
- The capture file grows indefinitely. For long-running cages, use `min_action: flag` or `domains` to limit what's recorded.
- Export with `agentcage cage har --since 1h` to get time-bounded snapshots.

### Exporting captured traffic

Use `agentcage cage har` to export captured traffic as HAR 1.2 JSON:

```bash
# Export inbound perspective (safe to share)
agentcage cage har mycage -o agent-view.har

# Export outbound perspective (contains real secrets)
agentcage cage har mycage --view outbound -o wire-view.har

# Export only blocked requests from last hour
agentcage cage har mycage --decision blocked --since 1h
```

See [CLI Reference — cage har](cli.md#cage-har) for full options.

---

## Inspectors

agentcage uses a **pluggable inspector chain**. Each HTTP request passes through a sequence of inspectors that can **block**, **flag**, or **allow** it. The chain short-circuits on the first hard block.

### Built-in inspectors

| Inspector | Default | Description |
|-----------|---------|-------------|
| `domain` | on | Domain allowlist/blocklist enforcement |
| `secrets` | on | Regex-based secret leak detection (always blocks) |
| `body-size` | on | Request body size limits (loaded when `max_request_body` > 0; default is 10 MB). Per-host overrides via `host_max_bytes` — see below |
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

### Body-size inspector

Caps inbound and outbound request bodies. The global limit is set via the top-level `max_request_body` key (default 10 MB; `0` disables). Per-host overrides — for example, to allow larger document uploads to a paperless-ngx instance without raising the global ceiling — are configured by re-declaring the `body-size` inspector in the `inspectors:` section:

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
| `severity` | `str` | `"warning"` | `"debug"`, `"info"`, `"warning"`, `"error"`, `"critical"` |
| `score` | `float` | `0.0` | Numeric score (for anomaly-scoring use cases) |
| `metadata` | `dict` | `{}` | Arbitrary inspector-specific data |
