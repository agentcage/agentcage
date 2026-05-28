<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Protocol relays

Credential brokers for non-HTTP protocols (IMAP, SMTP) that mirror what [secret injection](secret-injection.md) does for HTTP. The cage holds no upstream credentials; it connects to a localhost address inside the proxy container while the relay handles auth and policy.

## Common settings

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
| `auth.password_source` | `string` | yes | Source for the password, same grammar. |

> **Note:** Secrets named in `auth.user_source` / `auth.password_source` are automatically stripped from the cage's `podman_secrets` and `env` blocks the same way `secret_injection.env` is — they exist only in the proxy.

## IMAP policy

For `type: imap`:

| Setting | Type | Required | Description |
|---------|------|----------|-------------|
| `policy.readonly` | `bool` | no | If `true`, block APPEND/DELETE/STORE/EXPUNGE/CREATE/RENAME/MOVE/COPY plus the write subcommands of UID. Default `false`. |
| `policy.folder_allowlist` | `list[string]` | no | If non-empty, restrict SELECT/EXAMINE/STATUS to these mailbox names. LIST/LSUB always pass through (metadata only). Default `[]` (no filter). |
| `policy.conn_rate_limit` | `string` | no | Connection rate cap, e.g. `"30/min"`. Default `"30/min"`. |

### IMAP behavior

On client connect, the relay opens an authenticated TLS connection upstream and replies to the client with `* PREAUTH ...` — the canonical IMAP signal that the connection is already authenticated. Compliant clients (himalaya, mutt, etc.) skip LOGIN and proceed.

If the cage tries LOGIN or AUTHENTICATE anyway, the relay intercepts and forges an `OK already authenticated` response — the spurious credentials never reach the upstream server.

Each policy decision (allowed, blocked, login attempt) emits a structured log line that the proxy container forwards to the existing audit pipeline.

### IMAP example: Migadu, read-only INBOX

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

Inside the cage, point the IMAP client at `proxy.cage.local:1143` with no password — the relay supplies it. Tighten `domains.allow` to drop `imap.migadu.com`: only the relay should reach the real IMAP host.

## SMTP policy

For `type: smtp`:

| Setting | Type | Required | Description |
|---------|------|----------|-------------|
| `policy.sender_allowlist` | `list[string]` | no | If non-empty, only these `MAIL FROM` addresses are accepted. Empty = any. |
| `policy.recipient_allowlist.addresses` | `list[string]` | no | Exact addresses allowed in `RCPT TO`. |
| `policy.recipient_allowlist.domains` | `list[string]` | no | Domain suffixes allowed in `RCPT TO` (e.g. `example.com` matches `bob@x.example.com`). |
| `policy.max_message_bytes` | `int` | no | Upper bound on `DATA` payload. Default 5 MiB. |
| `policy.max_recipients` | `int` | no | Upper bound on `RCPT TO` per transaction. Default 10. |
| `policy.send_rate_limit` | `string` | no | Cap on accepted DATA transactions, e.g. `"20/hour"`. Default `"20/hour"`. |
| `policy.conn_rate_limit` | `string` | no | Cap on inbound connections from the cage. Default `"30/min"`. |
| `policy.bypass_inspectors_for_allowlisted` | `list[string]` | no | Inspector names to skip on `DATA` when every recipient matched `recipient_allowlist`. Default `["secrets", "entropy", "content-type"]`. Set to `[]` to keep strict body filtering even for trusted recipients. `body-size` always applies as a structural cap. |

If both `addresses` and `domains` are empty, the recipient gate is open — every `RCPT TO` is accepted. Setting either turns it on; an address is admitted iff it matches `addresses` or its domain matches `domains`. As a shorthand you can pass a flat list for `recipient_allowlist`, treated as `addresses`.

In addition to the per-protocol policy, the SMTP relay runs every `DATA` payload through the proxy's existing inspector chain (`secrets`, `entropy`, `content-type`, `body-size`). A blocking inspector result rejects the message with `550` before it reaches upstream — so a leaked Anthropic key in an outbound email body is blocked the same way it would be on an HTTP request. The `domain` inspector is intentionally skipped (its host-allowlist is HTTP-shaped; the equivalent SMTP gate is `recipient_allowlist`).

### Trusting the recipient gate for body content

When `recipient_allowlist` is non-empty AND every recipient in the transaction matched it (blocked recipients got `550` at `RCPT TO` time and never reached `DATA`), the inspectors named in `bypass_inspectors_for_allowlisted` are skipped. The default skip set — `secrets` + `entropy` + `content-type` — assumes an operator who explicitly named trusted recipients is willing to accept "agent emailed Luca a recovery code," "agent forwarded a base64 attachment to Luca," and "agent sent a PGP-signed mail with a 600-char signature in the body" instead of having those messages blocked.

The `content-type` inspector in particular has a different cost/benefit balance for SMTP than for HTTP: a 600-char base64 chunk in a `text/plain` HTTP body is a strong exfil signal, but in email it's a normal artifact of forwarded content and signatures. `body-size` always runs as a structural cap. With no allowlist (open recipient gate) the bypass cannot trigger — inspectors run strictly. A `smtp_data_bypass` audit entry records every bypass for visibility.

### SMTP behavior

The relay opens a single TLS connection to the upstream submission host (port 465 / SMTPS), performs `EHLO` + `AUTH PLAIN` with proxy-held credentials, and reuses that connection for every transaction in the cage's session.

The cage talks plaintext SMTP to the relay's listener. The relay greets it with `220 agentcage-smtp-relay ready` and advertises capabilities the cage actually needs (`8BITMIME`, `SIZE`, `PIPELINING`, `ENHANCEDSTATUSCODES`, `SMTPUTF8`) but deliberately does not advertise `STARTTLS` or `AUTH` — the connection is already on loopback inside the proxy and the relay handled real auth upstream. If the cage sends `AUTH` anyway, the relay forges `235` without forwarding any credential bytes.

Per `RCPT TO`, the relay decides allow/deny against `recipient_allowlist`. Standard SMTP semantics: a transaction with mixed legitimate and disallowed recipients delivers to the legitimate ones and gives the cage `550` for each disallowed address. A transaction whose recipients are all rejected fails — `MAIL FROM` is the natural retry point.

`DATA` is buffered, dot-unstuffed, then run through the inspector chain (skipping the HTTP-only `domain` inspector). Any `block` result causes a `550` and the transaction is dropped — upstream never sees the message. Inspectors that return `flag` are audited but not blocking. Allowed messages are forwarded to upstream with proper dot-stuffing, and the upstream's queue ID is echoed back in the `250` response.

### SMTP example: Migadu with allowlist + body inspection

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

## Related

- [Secret injection](secret-injection.md) — the HTTP analog. Same `source:` grammar for credentials.
- [Inspectors](inspectors.md) — runs against SMTP `DATA` payloads with the `domain` inspector skipped.
- [Ports](ports.md) — `listen` ports are reserved against the inspected TCP set.
- [Domains](domains.md) — drop the relay's upstream host from `allow` so only the relay can reach it.
