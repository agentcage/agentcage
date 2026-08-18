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
| `upstream.ca_file` | `string` | no | Path on the **host** to a PEM certificate, added to the proxy's CA store for this upstream. For upstreams no public CA signs. Read at deploy time. Requires `tls: true`. |
| `upstream.ca_pem` | `string` | no | The same certificate inline, for config that has to be self-contained. Mutually exclusive with `ca_file`. Requires `tls: true`. |
| `upstream.tls_servername` | `string` | no | Name sent in SNI and checked against the upstream certificate, when it differs from `upstream.host`. Required when `host` is an IP literal. Requires `tls: true`. |
| `auth.type` | `string` | yes | Auth scheme. `imap-login` for IMAP; `smtp-plain` for SMTP. |
| `auth.user_source` | `string` | yes | Source for the username. Same scheme grammar as `secret_injection.source` (`env:`, `cmd:`, `systemd-creds:`, `podman:`). |
| `auth.password_source` | `string` | yes | Source for the password, same grammar. |

> **Note:** Secrets named in `auth.user_source` / `auth.password_source` are automatically stripped from the cage's `podman_secrets` and `env` blocks the same way `secret_injection.env` is — they exist only in the proxy.

## Upstreams no public CA signs

By default the relay verifies the upstream against the proxy container's system CA store, which is what a public mail host needs. Two kinds of upstream can't be reached that way:

- a **self-hosted mail server** behind a private CA, and
- a **local decrypting daemon** — Proton Mail Bridge, Hydroxide, a Gmail OAuth shim — which mints its own self-signed certificate at setup and listens on a container or loopback address.

For these, point `upstream.ca_file` at the certificate on the host:

```yaml
protocol_relays:
  - name: bridge-imap
    type: imap
    listen: "0.0.0.0:1243"
    upstream:
      host: 10.88.0.5          # the bridge daemon's container address
      port: 1143
      tls: true
      tls_servername: bridge.local
      ca_file: ~/.config/protonmail/bridge-v3/cert.pem
    auth:
      type: imap-login
      user_source: "podman:BRIDGE_USER"
      password_source: "podman:BRIDGE_PASSWORD"
    policy:
      readonly: true
      folder_allowlist: [INBOX]
```

`~` and `$VARS` are expanded. `upstream.ca_pem` takes the same certificate inline instead, for config that has to be self-contained; setting both is an error rather than a silent precedence rule.

Four properties worth being explicit about:

**The path is read on the host, at deploy time.** The relay runs inside the proxy container, where a host path means nothing, so the CLI reads the file and hands the proxy the contents in `proxy-config.yaml`. That file is rewritten on every deploy and restart path, so a daemon that regenerates its certificate is picked up by `agentcage cage restart` with no config edit. Bind-mounting the file instead would pin an inode — a certificate that gets *replaced* rather than rewritten would be missed — and would need separate plumbing in each of the three backends.

**A missing or non-PEM file fails the deploy.** Better a refused deploy than a relay that can't verify its upstream at 3am and reports only `certificate verify failed`.

**The certificate is added to the system store, not substituted for it.** A relay with an extra anchor still trusts every public CA, so one relay's private certificate is never the reason another can't reach a normal mail host. The trade-off is that this is not pinning: a public CA that mis-issues for the same name still satisfies the check.

**Verification and hostname checking stay on.** There is deliberately no "skip verification" knob: the relay hands the upstream real credentials, so an unverified upstream is an unauthenticated one. This is why `tls_servername` exists — when you point a relay at an IP literal, no certificate can name it, so add the certificate and supply the name it *does* carry. (If the certificate already has an IP SAN for the address you dial, you don't need the override.)

Setting any of these alongside `tls: false` is a config error rather than a no-op: a CA sitting next to a plaintext connection reads as "verified" in review while verifying nothing.

## IMAP policy

For `type: imap`:

| Setting | Type | Required | Description |
|---------|------|----------|-------------|
| `policy.write_mode` | `string` | no | `none` \| `organise` \| `full`. See below. Defaults to whatever `readonly` implies. |
| `policy.readonly` | `bool` | no | Older spelling of the same thing: `true` == `write_mode: none`. Blocks APPEND/DELETE/STORE/EXPUNGE/CREATE/RENAME/MOVE/COPY plus the write subcommands of UID. Default `false`. |
| `policy.folder_allowlist` | `list[string]` | no | If non-empty, restrict SELECT/EXAMINE/STATUS to these mailbox names. LIST/LSUB always pass through (metadata only). Default `[]` (no filter). |
| `policy.folder_denylist` | `list[string]` | no | Mailboxes that may never be selected. Denial wins over the allowlist. Case-insensitive. Default `[]`. |
| `policy.conn_rate_limit` | `string` | no | Connection rate cap, e.g. `"30/min"`. Default `"30/min"`. |

### Write modes

`write_mode` chooses how much an agent may change, and exists because the two
booleans on offer before — read everything or write everything — did not cover
the common case of "let it tidy my mail but never destroy any".

| mode | permits |
|------|---------|
| `none` | reads only. Identical to `readonly: true`, which still works. |
| `organise` | reads, plus `MOVE`, `COPY` and flagging. Refuses anything that destroys mail or restructures the mailbox. |
| `full` | no restrictions. Identical to `readonly: false`. |

`organise` refuses `EXPUNGE`, `UID EXPUNGE`, `CLOSE`, `APPEND`, `DELETE`,
`RENAME`, `SETMETADATA`, `SETACL`, `DELETEACL` — and any `STORE` that would
**add** the `\Deleted` flag. `-FLAGS (\Deleted)` is allowed: taking the flag
off un-deletes a message.

`CREATE` **is** permitted. The line the mode draws is "refuse what destroys,
permit what is recoverable", and a new folder can simply be deleted again;
requiring the mailbox owner to hand-create every destination first defeats the
point. `DELETE` and `RENAME` fail the same test and stay refused — `DELETE`
removes a folder and whatever is filed in it, and `RENAME` silently breaks
server-side filters that refer to folders by name, with nothing about the
result looking broken.

Two details make that list what it is rather than just "block EXPUNGE":

- **`CLOSE` expunges.** RFC 3501 §6.4.2 has `CLOSE` silently remove every
  `\Deleted` message in the selected mailbox. Denying `EXPUNGE` while allowing
  `CLOSE` would leave the destructive path open behind an innocuous verb.
- **The flag is refused, not just the reap.** With `\Deleted` unsettable there
  is nothing for an expunge to destroy even if one is reached another way. It
  also means the client gets a clear refusal at the point of the mistake
  rather than a surprise later.

Setting `readonly` and `write_mode` to contradicting values is a config error,
not a precedence puzzle.

### Keeping an agent out of one folder

`folder_denylist` names mailboxes that may never be `SELECT`ed, and wins over
`folder_allowlist`. The motivating case is Trash:

```yaml
policy:
  write_mode: organise
  folder_denylist: [Trash]
```

**`MOVE` and `COPY` destinations are deliberately not checked** — only
`SELECT`, `EXAMINE` and `STATUS` take a mailbox argument the policy inspects.
So an agent under this config can still file a message *into* Trash, but cannot
open Trash and act on what is already there. Combined with `organise`, "delete"
can only ever mean "move to Trash", and the mail stays recoverable.

Matching is case-insensitive: servers disagree about the case of special-use
mailbox names, and a denylist that missed `trash` because the server said
`Trash` would fail open.

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
