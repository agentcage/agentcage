# Protocol Relays Reference

`protocol_relays` is a list of IMAP and SMTP relays that run inside the egress. The cage connects to a relay in plaintext without credentials. The relay holds the mailbox credentials, opens its own TLS connection to the real server, logs in there for the cage, and applies a policy to every command the cage sends. The cage never sees the password.

For a walkthrough, see [Custom Inspectors & Protocol Relays](../how-to/custom-inspectors.md#4-hardened-protocol-relays-imap--smtp). This page lists every key, its default, and what the relays record.

## Example

```yaml
protocol_relays:
  - name: mail-read
    type: imap
    listen: "0.0.0.0:1143"
    upstream:
      host: imap.example.com
      port: 993 # implicit TLS; STARTTLS ports do not work
    auth:
      user_source: env:MAIL_USER
      password_source: env:MAIL_PASSWORD
    policy:
      write_mode: organise # none | organise | full
      folder_denylist: [Trash]
      conn_rate_limit: "30/min"

  - name: mail-send
    type: smtp
    listen: "0.0.0.0:1025"
    upstream:
      host: smtp.example.com
      port: 465 # implicit TLS; 587 (STARTTLS) does not work
    auth:
      user_source: env:MAIL_USER
      password_source: env:MAIL_PASSWORD
    policy:
      sender_allowlist: [agent@example.com]
      recipient_allowlist:
        domains: [example.com]
      max_recipients: 5
      send_rate_limit: "10/hour"
```

Store the credentials before the cage starts. `-s NAME` prompts for the value:

```bash
agentcage cage create -c cage.yaml -s MAIL_USER -s MAIL_PASSWORD
# later, to rotate:
agentcage secret set <cage> MAIL_PASSWORD
```

## Reaching a relay from the cage

The relay listens inside the egress, which is a separate network namespace from the cage. A loopback `listen` address such as `127.0.0.1:1143` is unreachable from the cage, so use `0.0.0.0:<port>`. The cage connects to the egress's address on that port:

| Backend | Egress address inside the cage |
| :-- | :-- |
| `container`, `vm` | The host part of `$HTTPS_PROXY` (`http://<egress>:8080`). It is also the cage's DNS server. |
| `apple-container` | `$AGENTCAGE_EGRESS_IP` |

Picking the port:
- **Must not be inspected.** The listen port can't be in the inspected `ports.tcp.allow` set (`allow` minus `passthrough`). Those ports are redirected into the HTTP proxy, and `cage create` refuses the collision.
- **Must be free in the egress.** Port 53 (DNS) and ports 8080/8443 (the HTTP proxy) are taken, as are any inbound `container.ports` forwards.
- **No `ports` entry needed.** The cage reaches the egress directly, and `ports.tcp.allow` governs the cage's outbound traffic to the internet, not this connection.

`0.0.0.0` binds every egress interface, including the one on the host-facing podman network.

The relay opens its upstream connection from the egress itself. `domains` and `ports` filter the cage's traffic, so `upstream.host` needs no entry in either.

Point the cage's mail client at that address and port with no TLS and no password:
- The IMAP relay greets with `* PREAUTH`, so a compliant client skips login.
- The SMTP relay advertises `AUTH PLAIN LOGIN` because some clients refuse to send without it. It accepts any AUTH the client sends without forwarding it.

## Keys both relay types take

| Key | Default | Accepted values |
| :-- | :-- | :-- |
| `name` | required | Non-empty. Used in error messages and as `relay` in audit records. Must be unique: the egress refuses a second entry with the same name. |
| `type` | required | `imap` or `smtp`, exactly. |
| `listen` | required | `host:port`, where the relay binds. Use `0.0.0.0:<port>` (see above). An empty host means `0.0.0.0`. |
| `upstream.host` | required | The mail server's hostname, or an IP literal (with `tls_servername`, see below). |
| `upstream.port` | required | `1`–`65535`. A quoted number is accepted, but a YAML boolean (`yes`, `no`, `on`, `off`) is not. |
| `upstream.tls` | `true` | `true`: implicit TLS (IMAPS 993, SMTPS 465). `false`: plaintext, only for an upstream on a trusted local path. No STARTTLS: see [Upstream TLS](#upstream-tls). |
| `upstream.ca_file` | none | A host path to a PEM certificate to trust in addition to the system store. See [Upstream TLS](#upstream-tls). |
| `upstream.ca_pem` | none | The same certificate inline, as a PEM string. Use `ca_file` or `ca_pem`, not both. |
| `upstream.tls_servername` | none | The name to send in SNI and to check the certificate against, when it differs from `upstream.host`. |
| `auth.user_source` | none | `env:NAME` or `systemd-creds:NAME`. See [Credentials](#credentials). |
| `auth.password_source` | none | As `auth.user_source`. |
| `auth.type` | none | Read by neither relay. IMAP always logs in with `LOGIN`, and SMTP always with `AUTH PLAIN`. It is accepted and carried through for compatibility only. |
| `policy.conn_rate_limit` | `"30/min"` | A [rate string](#rate-strings). Caps new cage connections per window. Over the cap, IMAP answers `* BYE rate limit` and SMTP answers `421`, and the connection closes. |
| `policy.idle_timeout_seconds` | IMAP `1800`, SMTP `300` | Seconds. `0` disables. What the timeout covers differs per type: see [IMAP](#imap-type-imap) and [SMTP](#smtp-type-smtp). |

The relays ignore the other type's policy keys. Validation still checks `write_mode`, `readonly` and the folder lists on an SMTP relay.

### Credentials

The relay reads each credential by the `NAME` after the colon, from the secret files and environment the egress unit provides:

- **`env:NAME`** reads the secret store's entry `NAME`. Set it with `-s NAME` at `cage create`, or with `agentcage secret set <cage> NAME`. The host environment is never read, on any backend.
- **`systemd-creds:NAME`** reads the same entry, decrypted from `NAME.cred` when the egress starts.
- **`cmd:` and `podman:`** are refused at `cage create` and `cage update` for relay credentials. Nothing runs a relay's `cmd:` command, so the "name" would be the command text, and a `podman:` name never reaches a vm guest.
- **A bare `NAME`** with no scheme is refused at `cage create`.

The host removes every relay credential name from the cage's `container.env` and `podman_secrets`, so the values reach the egress only. If either credential resolves to an empty value, the relay doesn't start: the egress records `relay_init_failed` with `credentials not resolved`.

Changing a value with `agentcage secret set` takes effect without a restart. On its next config reload the egress sees the re-staged credential, then stops that relay and starts it again with the new value (see [Changing relays on a running cage](#changing-relays-on-a-running-cage)).

### Upstream TLS

Both relays connect upstream with **implicit TLS** or in plaintext (`tls: false`). Neither speaks STARTTLS, in either direction, so use the TLS-on-connect port: 993 for IMAP and 465 for SMTP. A TLS handshake against a STARTTLS port (143 or 587) fails.

Certificate verification and hostname checking are always on. There is no option to skip them, because the relay sends real credentials to whatever answers.

- **`ca_file`** is read by the host on every `cage create`, `update` and `restart`, and placed into the egress config as `ca_pem`. A certificate that a local daemon regenerates is picked up by the next `cage restart`. `~` and `$VAR` are expanded. The file must contain a `-----BEGIN CERTIFICATE-----` block; if it is missing, unreadable or not PEM, the deploy fails.
- **`ca_pem`** must contain a `-----BEGIN CERTIFICATE-----` block.
- **Additive, not a pin.** Both add a certificate to the system CA store. A public CA that issues for the same name is still trusted.
- **`tls_servername`** is for an upstream addressed by IP, such as a local bridge daemon on a container subnet. A certificate can rarely name that address, so give the name it does carry.
- **Plaintext refuses them.** `ca_file`, `ca_pem` and `tls_servername` with `tls: false` are an error, since nothing would be verified. Note that YAML reads a bare `tls: no` as `false`, but the quoted string `"false"` is truthy and leaves TLS on.

### Rate strings

`conn_rate_limit` and `send_rate_limit` take `<count>/<unit>`:

- **Count:** a whole number of ASCII digits.
- **Unit:** one of `sec` or `s` (1 second), `min` or `m` (60 seconds), `hour` or `h` (3600 seconds), in any case (`"10/MIN"` works).
- **Whitespace:** allowed around the count, the slash and the unit.

For example: `"30/min"`, `"20/hour"`, `"5 / s"`. `"10/minute"` and `"1.5/min"` are not rate strings: `cage create` and `cage update` refuse them, naming the field. Each limit is a sliding window over the last `<unit>`. A missing, empty or `null` value means the default.

## IMAP (`type: imap`)

When the cage connects, the relay opens the upstream connection and sends `LOGIN` with the stored credentials. It then greets the cage with `* PREAUTH [CAPABILITY ...]`, forwarding the upstream's capabilities. It removes `COMPRESS=DEFLATE`, because the relay can't apply policy to a compressed stream. Outside `write_mode: full` it also removes `REPLACE`. It adds `IMAP4rev1` if the upstream didn't list it.

If the cage sends `LOGIN` or `AUTHENTICATE` anyway, the relay answers `OK` without forwarding it.

The relay's own replies (the `NO` to a refused command, that `OK`, a `BAD`) are only ever sent between complete server responses. With pipelined commands, a reply that is ready while the server is half way through a response, for example inside a `FETCH` literal, waits for that response to end. Replies keep their order among themselves, but one can arrive before the server's reply to a command the cage sent earlier, as from a server running pipelined commands concurrently.

After that the relay checks each command line from the cage and forwards it or answers it itself (see [Literals](#literals) for commands that carry data, and [Line endings](#line-endings)). Server responses are passed through unchanged, apart from the capability filtering above, the line endings, and the `+` the relay holds back when it rewrites a `{n+}` literal.

| Key | Default | Accepted values |
| :-- | :-- | :-- |
| `policy.write_mode` | `full` (or what `readonly` implies) | `none`, `organise` or `full`, case-insensitive. See the table below. |
| `policy.readonly` | `false` | The older spelling: `true` means `write_mode: none`, `false` means `full`. Setting both is refused unless they agree. Use `write_mode`. |
| `policy.folder_allowlist` | `[]` (any folder) | A list of mailbox names. Only these may be opened. |
| `policy.folder_denylist` | `[]` | A list of mailbox names that may never be opened. Denial wins over the allowlist. |
| `policy.idle_timeout_seconds` | `1800` | Limits how long the relay waits for the upstream while connecting and logging in. Once the session is bridged there is no timeout, because an IMAP `IDLE` legitimately sits quiet for about 29 minutes between heartbeats. If the upstream greeting does not arrive in time, the cage gets `* BYE upstream silent`. |

### `write_mode`

| Mode | Refused (answered `NO <command> not permitted`) | Typical use |
| :-- | :-- | :-- |
| `none` | `APPEND`, `CLOSE`, `COPY`, `CREATE`, `DELETE`, `DELETEACL`, `EXPUNGE`, `MOVE`, `RENAME`, `REPLACE`, `SETACL`, `SETANNOTATION`, `SETMETADATA`, `SETQUOTA`, `STORE`, and `UID COPY`, `UID EXPUNGE`, `UID MOVE`, `UID REPLACE`, `UID STORE` | Read-only access. `FETCH`, `SEARCH`, `UID FETCH` and `UID SEARCH` still work. |
| `organise` | `APPEND`, `CLOSE`, `DELETE`, `DELETEACL`, `EXPUNGE`, `RENAME`, `REPLACE`, `SETACL`, `SETANNOTATION`, `SETMETADATA`, `SETQUOTA`, `UID EXPUNGE`, `UID REPLACE`, any `STORE` / `UID STORE` that sets `\Deleted` with `FLAGS` or `+FLAGS` (including `.SILENT`), and any `STORE` / `UID STORE` with an `ANNOTATION` item (RFC 5257 message annotations) | Filing and flagging without destroying mail. Allowed: `COPY`, `MOVE`, `CREATE`, the other flags, and `-FLAGS (\Deleted)`, which un-deletes. |
| `full` | nothing | No write restrictions. Folder lists still apply. |

The reasons behind the `organise` list:
- **`CLOSE`** is refused in both restricted modes because it expunges every `\Deleted` message in the selected mailbox (RFC 3501 §6.4.2).
- **`APPEND`** would put fabricated mail into the mailbox.
- **`REPLACE`** (RFC 8508) is an `APPEND` and an `EXPUNGE` in one command. In these two modes the relay also leaves `REPLACE` out of the capabilities it advertises, so clients don't try it.
- **`RENAME`** can silently break server-side filing rules that refer to folders by name.
- **`SETQUOTA`** (RFC 9208), **`SETMETADATA`** (RFC 5464), Cyrus's **`SETANNOTATION`** and **`STORE ... ANNOTATION`** (RFC 5257) change account, mailbox or message settings rather than file or flag mail. `STORE ... ANNOTATION` is refused wherever the `ANNOTATION` token appears in the arguments, so a keyword flag literally named `ANNOTATION` is refused too.

A command that isn't listed for a mode is forwarded.

### Literals

A message the cage uploads with `APPEND`, and any string argument sent as an IMAP literal (`{n}` followed by n bytes, RFC 3501 §4.3), is data, not commands. The relay checks the line that starts a command, then streams the literal through byte for byte, never reading its lines as commands, and treats the line after it as the rest of the same command. A body line such as `x LOGIN u p` or `a1 COMPRESS DEFLATE` reaches the upstream as part of the message, in every `write_mode`.

The relay only forwards a literal's bytes after the upstream has answered the line announcing it with `+`, so the two always agree on where the literal ends:
- **`{n}` (synchronising):** the relay passes the upstream's `+` to the cage. If the upstream answers `NO` or `BAD` instead, the cage sends no literal, and the relay reads what follows as the next command.
- **`{n+}` (non-synchronising, RFC 7888 `LITERAL+` / `LITERAL-`):** the cage sends the literal without waiting. The relay announces it to the upstream as `{n}`, holds the literal until the upstream's `+` (which the cage does not see), then forwards it. If the upstream refuses, the relay drops the literal and the rest of the command. This costs one round trip per literal.
- **`~{n}` / `~{n+}` (RFC 3516 `BINARY`):** handled the same way.
- **Refused commands:** a command the relay refuses never reaches the upstream. For `{n}` the relay answers `NO` in place of the `+`, so the cage never sends the literal. For `{n+}` it reads and drops exactly n bytes, then the rest of the command.
- **Ordering:** a command with a literal waits until every command forwarded before it has completed, so that the upstream's untagged `+` can only belong to that literal and not to, say, an `IDLE`.
- **Size:** a literal may be at most 64 MiB. A larger one is refused with `NO [TOOBIG]` and a `blocked` audit entry. For `{n}` the session goes on. For `{n+}`, or a literal later in a command that has already been partly forwarded, the relay then closes the session with `* BYE literal too large`.
- **Malformed:** a line ending in something brace-shaped that is not a literal (`{5-}`, `{ 5}`) is refused with `BAD malformed literal`.

A line whose tag is not a valid IMAP tag (RFC 3501 §9: printable ASCII except `(`, `)`, `{`, `%`, `*`, `"`, `\` and `+`) is answered `* BAD invalid command tag` and not forwarded. An upstream echoing a `+` or `*` tag back would make its reply read as a continuation request or an untagged response.

### Line endings

RFC 3501 ends every line with CRLF and allows no other CR or LF outside a literal. Implementations disagree on what to do with the others, and wherever the relay and a server or client end a line in different places, they read different commands or responses from the same bytes. Literal bytes are never touched.
- **Bare CR from the cage:** a command line holding a CR that is not the one right before its LF is refused with `BAD bare CR in command line` (tagged, or `*` when the tag isn't valid) and a `blocked` audit entry, and not forwarded. A server that also ends a line at a bare CR would otherwise run `a1 NOOP<CR>b EXPUNGE` as two commands, the second never checked. If the line is the rest of a command after a literal, part of which has already been forwarded, the relay closes the session with `* BYE bare CR in command line` instead.
- **NUL from the cage:** RFC 3501 §9 leaves NUL out of `CHAR` and `CHAR8`, so only a literal8 (`~{n}`) may hold one. A command line holding a NUL is refused the same way, with `BAD NUL in command line` (or `* BYE NUL in command line` after a literal). A server that reads lines as C strings stops at the NUL and would act on less of the line than the relay checked.
- **Bare LF from the cage:** ends the line, as it does for most servers, and the line is forwarded ending in CRLF. Splitting at every LF, the relay sees every command boundary a server might, and the rewrite makes a server that ends lines only at CRLF see the same ones.
- **Server responses:** outside literals, each line reaches the cage ending in CRLF (a bare LF ending it is rewritten) with every other CR replaced by a space. Otherwise a client that ends lines at a bare CR, or only at CRLF, could read a literal where the relay saw none, and take a relay reply, or the server's next response, for part of it.

### Folder lists

`folder_allowlist` and `folder_denylist` are checked against the mailbox argument of every command that names a folder:
- **Commands:** `SELECT`, `EXAMINE` and `STATUS`; `GETQUOTAROOT` (RFC 9208); `GETMETADATA` and `SETMETADATA` (RFC 5464, the argument after `GETMETADATA`'s options list if it has one); `GETANNOTATION` and `SETANNOTATION`; `GETACL`, `MYRIGHTS`, `LISTRIGHTS`, `SETACL` and `DELETEACL` (RFC 4314); `SUBSCRIBE` and `UNSUBSCRIBE`; `DELETE`; and `RENAME`, judged on the folder being renamed (renaming a denied folder would open it under the new name). Each one reports on the folder or changes it, and even a reply about its quota or ACL confirms that a denied folder exists. A refusal reads `NO <command> <mailbox> denied by folder_denylist` (or `not in folder_allowlist`), the same as for `SELECT`. In `GETMETADATA`, `SETMETADATA`, `GETANNOTATION` and `SETANNOTATION` the mailbox `""` means the server's own annotations and is not checked.
- **Matching:** names are compared in one canonical form: Unicode NFC, case-folded (`Trash` matches `trash`, `INBOX` matches `inbox`). A decomposed `É` matches a precomposed one. There are no wildcards and no hierarchy rules: denying `Trash` does not deny `Trash/Old`, so list each folder.
- **Non-ASCII names:** a folder has two spellings. One is modified UTF-7 (RFC 3501 §5.1.3, for example `&AMk-t&AOk-`), which clients use by default. The other is UTF-8 (`Été`), used once the client has sent `ENABLE UTF8=ACCEPT` (RFC 6855) or `ENABLE IMAP4rev2`. Configured names may be written either way.
  - A **deny** entry matches every spelling of its folder, however the cage writes it.
  - The **allowlist** admits a name in the reading the server will use: the decoded modified UTF-7 until UTF-8 names have been enabled (or from the start, if the server only speaks IMAP4rev2 or `UTF8=ONLY`). After that, a name must be allowed in every reading. For example, `&AMk-t&AOk-` is then refused, because the server may take it as that literal string, while `Été` in UTF-8 passes.
- **Argument forms:** an atom, a quoted string, or a literal. A literal name of up to 1 KiB is read before the decision: for `{n}` the relay sends the cage the `+` itself. A name that is not valid UTF-8 or a longer literal is refused as unparseable. So is a literal anywhere else on the line, except in the commands whose later arguments are strings (`GETMETADATA`, `SETMETADATA`, `GETANNOTATION`, `SETANNOTATION`, `LISTRIGHTS`, `SETACL`, `DELETEACL`, `RENAME`), where an annotation value, an identifier or a new name may be a literal once the mailbox has been written out in front of it as a quoted string or an atom with no `{` in it.
- **Other mailboxes:** while either list is set, the relay also refuses the commands that report on mailboxes other than the selected one. These are `LIST` / `LSUB` with `RETURN (STATUS ...)` (RFC 5819), `ESEARCH` (RFC 7377 multi-mailbox search) and `NOTIFY SET` (RFC 5465); `NOTIFY NONE` is allowed. It also leaves `LIST-STATUS`, `MULTISEARCH` and `NOTIFY` out of the capabilities it advertises.
- **Not checked:**
  - Plain `LIST` and `LSUB`, so the cage can discover folder names.
  - The destination of `COPY`, `MOVE` and `APPEND`. The lists govern which folders the cage may read, and filing mail somewhere reads nothing. Checking destinations would also break the denylist's main use: denying `Trash` so that deleting can only mean moving to `Trash`. Use `write_mode` to stop filing. The new name in `RENAME` and the folder `CREATE` makes are destinations in the same sense.
  - The quota root of `GETQUOTA` and `SETQUOTA`, which is not a mailbox name.

## SMTP (`type: smtp`)

The relay greets with `220`. To `EHLO` it advertises `AUTH PLAIN LOGIN`, `8BITMIME`, `SIZE <max_message_bytes>`, `PIPELINING`, `ENHANCEDSTATUSCODES` and `SMTPUTF8`, and never `STARTTLS`. It runs the transaction itself and opens the upstream connection only when a message has passed every check.

The upstream login is `EHLO agentcage.local` followed by `AUTH PLAIN`. That connection is reused for the rest of the cage's session.

| Key | Default | Accepted values |
| :-- | :-- | :-- |
| `policy.sender_allowlist` | `[]` (any sender) | A list of addresses. `MAIL FROM` is refused (`550`) unless it matches one exactly, case-insensitive. |
| `policy.recipient_allowlist` | `{}` (any recipient) | A mapping with `addresses` (exact, case-insensitive) and `domains` (the domain or any subdomain: `example.com` matches `ops.example.com`). A plain list is shorthand for `addresses`. Each `RCPT TO` that matches neither is refused (`550 5.7.1`). |
| `policy.max_recipients` | `10` | Recipients per message. The one over the cap gets `452 4.5.3`. |
| `policy.max_message_bytes` | `5242880` (5 MiB) | Message size after dot-unstuffing. Larger messages get `552 5.3.4`. |
| `policy.send_rate_limit` | `"20/hour"` | A [rate string](#rate-strings). Over the limit, `DATA` gets `451 4.7.0`. A message that is not delivered (too large, blocked by an inspector, refused upstream, or timed out) gives its slot back, so the limit counts deliveries the upstream accepted. |
| `policy.bypass_inspectors_for_allowlisted` | `[secrets, entropy, content-type]` | Inspector names skipped when a `recipient_allowlist` is set. Recipients outside the allowlist were already refused, so every remaining one matched it. `[]` keeps every inspector on for trusted recipients too. With no recipient allowlist, nothing is skipped. |
| `policy.idle_timeout_seconds` | `300` | Applies to every read from the cage and from the upstream. An idle cage gets `421 4.4.2` and the connection closes. A stalled `DATA` gets `451 4.4.2`. |

With neither `sender_allowlist` nor `recipient_allowlist` set, the relay sends mail from any sender to any recipient. Set both.

Every message body goes through the egress's inspector chain before it is forwarded. That's the same chain HTTP requests use, minus the domain inspector (`recipient_allowlist` does that job here). The `secrets` inspector blocks on relays unless `secrets.action` says otherwise. A block answers `550 5.7.0 <reason>`. A `flag` delivers the message and records `smtp_data_flag`.

Other commands:
- `RSET`, `NOOP`: `250`
- `VRFY`: `252`
- `QUIT`: `221`
- anything else: `502`

Commands before `EHLO`/`HELO` get `503`. If the upstream fails during delivery, the cage gets `451 4.4.0` and the next message opens a fresh upstream connection.

## Validation

`cage create` and `cage update` refuse a relay entry when:
- **Required keys:** `name`, `type` or `listen` is missing or empty, or `type` is not `imap` or `smtp`.
- **Upstream:** `upstream` has no `host`, its `port` is outside `1`–`65535`, or the port is a YAML boolean.
- **TLS:** `ca_file` and `ca_pem` are both set, `ca_pem` holds no `-----BEGIN CERTIFICATE-----` block, or `ca_file`, `ca_pem` or `tls_servername` is set with `tls: false`.
- **Policy:** `policy` is not a mapping, `write_mode` is not one of the three modes, `readonly` contradicts `write_mode`, or a folder list is not a list.
- **Credentials:** a credential source names an unknown scheme, uses `cmd:` or `podman:`, or has an empty `NAME`.
- **Rate limits:** `conn_rate_limit` or `send_rate_limit` is not a [rate string](#rate-strings).
- **Ports:** the listen port collides with an inspected `ports.tcp.allow` port.

The egress runs the same structural checks again when it loads the config. An entry that fails is skipped and recorded as `relay_config_invalid`. Other relays and HTTP traffic are unaffected.

## Audit records

Relays write structured records to the egress audit stream, the same one HTTP decisions go to. `agentcage cage logs <cage> -s egress` shows them. Every record has a `kind` and the `relay` name.

| `kind` | `decision` | When |
| :-- | :-- | :-- |
| `relay_config_invalid` | none | The entry failed validation in the egress, or reuses a name. `error` says why. |
| `relay_init_failed` | none | The relay could not be built, for example because a credential did not resolve. `error` says why. |
| `relay_start_failed` | none | The listener could not start: port in use, or a malformed `listen`. |
| `imap_command` | `intercepted` | The cage sent `LOGIN` / `AUTHENTICATE`. |
| `imap_command` | `blocked` | A command was refused by `write_mode` or a folder list, or because of its form: `reason` is `invalid tag`, `bare CR in command line`, `NUL in command line`, `malformed literal` or `literal too large`. Carries `command`, `reason`, and `mailbox` for folder refusals. |
| `imap_command` | `allowed` | A forwarded command, recorded only while allowed-request logging is on (`logging.allowed_requests`, off by default). |
| `imap_upstream_unreachable` | none | The upstream connection failed. Carries `upstream` and `error`. |
| `smtp_command` | `intercepted` | The cage sent `AUTH`. |
| `smtp_command` | `blocked` | A refused sender or recipient, too many recipients, the send rate limit, an oversize message or a `DATA` timeout. Carries `command`, `reason`, and the `sender` / `recipient` where relevant. |
| `smtp_session` | `closed` | The cage was idle past `idle_timeout_seconds`. |
| `smtp_data` | `allowed` | Delivered. Recorded while allowed-request logging is on (`logging.allowed_requests`, off by default), and always for a message an inspector flagged. Carries `sender`, `recipients` (those the upstream accepted), `recipients_rejected_upstream`, `size` and `upstream_status`. |
| `smtp_data` | `blocked` | An inspector blocked the body. Carries `inspector`, `reason`, `severity`, `sender`, `recipients` and `size`. |
| `smtp_data` | `upstream_error` | The upstream refused or failed the delivery. Carries `error`. |
| `smtp_data_flag` | `flagged` | An inspector flagged a body that was delivered anyway. One record per flag, with `inspector`, `reason`, `severity`, `sender` and `recipients`. |
| `smtp_data_bypass` | none | Inspectors were skipped because every recipient was allowlisted. Carries `bypassed`, `sender` and `recipients`. |


## Changing relays on a running cage

The egress applies `protocol_relays` changes without a restart. It picks up a changed config, including a credential re-staged by `agentcage secret set`, within about a second:
- **Unchanged entry, same credentials:** keeps running, along with its open sessions.
- **Changed entry, or a re-staged credential:** stopped and started again.
- **Removed entry:** stopped.
- **New entry:** validated and started as at boot.

A relay that keeps running takes the new `logging.allowed_requests` and the new inspector chain, so an inspector added to or removed from the config (in `inspectors:` or by its top-level key) applies to its next message.
