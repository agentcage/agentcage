# How-To: Custom Inspectors & Protocol Relays

agentcage evaluates every request leaving the sandbox with a chain of inspectors. This guide explains how to write your own inspector as a WebAssembly plugin, and how to configure hardened protocol relays for non-HTTP traffic (such as IMAP and SMTP).

---

## 1. Authoring Custom Inspectors

Custom inspectors let you enforce your own rules on top of the built-in ones: data loss prevention (DLP) patterns, internal token formats, mandatory headers, forbidden file types.

A custom inspector is a **WebAssembly component** that the egress proxy loads next to its built-in inspectors. It sees every request (and, if it wants, every response and WebSocket message) and can **flag** it (let it through, audited as `flagged`) or **block** it (the cage gets a 403). The plugin runs sandboxed: it has no filesystem, network, environment or clock, only the request it is handed, and every call has a CPU and memory budget.

You write it in Rust with the `agentcage-inspector-sdk` crate. (Any language that can build a component for the `agentcage:inspector@1.0.0` WIT world works; the WIT file ships in the crate under `wit/inspector.wit`.)

> Python inspectors (`path: something.py`) are no longer supported. They were never mounted into the egress, so no cage could have been running one. Port the logic to the SDK below; the `configure` / `inspect_request` / `inspect_response` shape is the same.

### Create the plugin crate

```bash
rustup target add wasm32-wasip2
cargo new --lib header-policy
cd header-policy
cargo add agentcage-inspector-sdk
```

In `Cargo.toml`, make it a `cdylib`:

```toml
[lib]
crate-type = ["cdylib"]

[profile.release]
opt-level = "z"
lto = true
strip = true
```

### The `Inspector` trait

Implement `Inspector` for a type that is `Default`, and export it with `export_inspector!`:

```rust
// src/lib.rs
use agentcage_inspector_sdk::{export_inspector, Context, Inspector, Severity, Value, Verdict};

#[derive(Default)]
struct HeaderPolicy {
    required_header: String,
    block_on_missing: bool,
}

impl Inspector for HeaderPolicy {
    /// Called with the cage.yaml entry's `config:` (as JSON) when the
    /// plugin is loaded and whenever the cage's config changes. Each call
    /// starts from `HeaderPolicy::default()`. Returning `Err` rejects the
    /// config; the egress keeps the previous one and logs the message.
    fn configure(&mut self, config: &Value) -> Result<(), String> {
        self.required_header = config
            .get("required_header")
            .and_then(Value::as_str)
            .unwrap_or("X-Trace-ID")
            .to_ascii_lowercase();
        self.block_on_missing = config
            .get("block_on_missing")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(())
    }

    /// Called for every outbound request. `None` abstains.
    fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
        if ctx.has_header(&self.required_header) {
            return None;
        }
        let reason = format!("Missing mandatory header: {}", self.required_header);
        Some(if self.block_on_missing {
            Verdict::block(reason).with_severity(Severity::Error)
        } else {
            Verdict::flag(reason)
        })
    }

    // `inspect_response` defaults to abstaining; override it to inspect
    // responses and inbound WebSocket messages.
}

export_inspector!(HeaderPolicy);
```

Build it:

```bash
cargo build --release --target wasm32-wasip2
# target/wasm32-wasip2/release/header_policy.wasm
```

Two complete examples live in the agentcage repository under `examples/inspectors/`: `header-policy` (the one above) and `dlp-regex` (block bodies, URLs or headers that match configured regular expressions).

### What an inspector sees

`Context` carries the request as the cage sent it, before secret injection, so it sees secret **placeholders**, never real secret values:

| Field | Meaning |
| :-- | :-- |
| `url`, `host`, `method` | The request line. For a response, the request's. |
| `headers` | `(name, value)` pairs in wire order, case and duplicates kept. `ctx.header(name)` and `ctx.header_values(name)` match names case-insensitively. |
| `content_type` | The `Content-Type` value, or `""`. |
| `body` | The body with any `Content-Encoding` removed, or `None`. |
| `body_text` | The body decoded as text (declared charset, else UTF-8 for JSON/HTML/XML/JS/CSS, else Latin-1), or `None`. |
| `body_size`, `body_entropy` | Size in bytes; Shannon entropy in bits per byte (`None` for an empty body). |
| `prior_results` | Findings from inspectors earlier in the chain (built-ins run first). |
| `direction` | `Outbound` (cage to world) or `Inbound` (reverse-proxied traffic to a port the cage exposes). |
| `phase` | `Request`, `Response` or `WebSocket` (one complete message; `inspect_request` sees the ones the cage sends, `inspect_response` the ones it receives). Relayed mail (SMTP `DATA`) arrives as a `Request`. |

A `Verdict` has an action (`block` or `flag`), a reason, a severity (`debug`, `info`, `warning` (default), `error`, `critical`) and optional metadata. The reason goes into the audit log and, for a block, into the 403 body the cage receives, so never put secret values or matched sensitive text in it. Metadata is visible to later inspectors only. A verdict is always attributed to the `name` the plugin was given in `cage.yaml`; a plugin cannot report as another inspector.

### The sandbox and its limits

- **No capabilities.** The plugin cannot open files, sockets, read the environment (it sees an empty one) or a clock. Code that tries traps, and the request is blocked.
- **CPU budget.** Each call gets about 50 ms worth of fuel (a deterministic instruction count, the same on every machine). Running out blocks the request.
- **Memory.** An instance may use up to 64 MiB of linear memory, which has to hold the body (twice, as bytes and as text). Exceeding it blocks the request.
- **Fail closed.** A panic, trap, exhausted budget or malformed verdict becomes a `block` with the reason `inspector <name> failed: …`, and the broken instance is discarded.
- **Concurrency.** The egress runs several instances of a plugin in parallel and replaces instances at will (after a failure, on a config change). Keep all state in `configure`; do not count on anything surviving between calls.

---

## 2. Registering Inspectors in `cage.yaml`

Reference the built component in `cage.yaml`. `path` is relative to the directory containing `cage.yaml` and must name a `.wasm` file:

```yaml
inspectors:
  - name: header-policy
    path: plugins/header_policy.wasm
    config:
      required_header: X-Trace-ID
      block_on_missing: true
```

`agentcage cage create` and `agentcage cage update` copy each referenced plugin into the cage's data directory and mount it read-only into the egress at `/etc/agentcage/inspectors`. Plugins are part of the cage's fingerprint, so rebuilding a plugin and running `cage update` picks up the new version:

```bash
agentcage cage update my-agent
```

Custom inspectors run after the built-in ones (`domain`, `secrets`, `body-size`, `entropy`, `content-type`), in the order listed. The first `block` ends the chain.

---

## 3. Testing & Validating Inspectors

### A. Stage in `flag` Mode
When deploying a new inspector, have it return `Verdict::flag` rather than `Verdict::block` (the example's `block_on_missing: false`). Traffic keeps flowing while every hit is written to the audit log as `flagged`.

### B. Monitor Inspector Decisions
Stream decisions generated by your custom inspector:

```bash
agentcage cage audit my-agent --inspector header-policy --follow
```

Output:
```text
2026-09-08 10:45:22 [FLAGGED] api.github.com (inspector: header-policy) - Missing mandatory header: x-trace-id
```

Once confirmed that legitimate traffic is not impacted, switch the inspector to blocking.

### C. Unit-test the logic natively
The `Inspector` trait is plain Rust, so the logic can be tested with `cargo test` on your machine. Add `"rlib"` next to `"cdylib"` in `crate-type`, build a `Context` by hand, and call `inspect_request` directly.

---

## 4. Hardened Protocol Relays (IMAP & SMTP)

Many AI agents need to read or draft emails (e.g. triaging support inboxes). However, granting an agent raw IMAP/SMTP credentials hands it unrestricted access to read private emails or send spam.

agentcage solves this by running **hardened protocol relays** inside the egress gateway.

### How Protocol Relays Work
- Each relay listens inside the **egress** container on the `listen` address you configure. The agent connects to it over the cage network, in plaintext and without credentials.
- The relay authenticates upstream with real credentials from agentcage's secret store. They are delivered only to the egress and never reach the cage.
- The relay enforces fine-grained policy gates (folder allowlists, IMAP write modes, sender and recipient allowlists, rate limits).

### Example SMTP Relay in `cage.yaml`:

```yaml
protocol_relays:
  - name: mail-relay
    type: smtp
    listen: "0.0.0.0:1025"
    upstream:
      host: "smtp.sendgrid.net"
      port: 465 # implicit TLS (SMTPS); STARTTLS on 587 is not supported
      tls: true
    auth:
      type: smtp-plain
      user_source: "env:SENDGRID_USER"
      password_source: "env:SENDGRID_API_KEY"
    policy:
      sender_allowlist: ["bot@example.com"]
      recipient_allowlist:
        domains: ["example.com"] # Can only email internal staff
      send_rate_limit: "10/hour"
      max_message_bytes: 5242880 # 5 MB cap
```

Store both credentials before deploying: `agentcage secret set my-agent SENDGRID_USER` and `agentcage secret set my-agent SENDGRID_API_KEY`. Credential sources take the form `scheme:NAME`, where the scheme is `env:` or `systemd-creds:` and `NAME` is the secret's name. A bare name with no scheme is rejected at `cage create`. On every backend, both schemes read the secret store's entry `NAME`. A shell environment variable with the same name is not read.

### Example IMAP Relay in `cage.yaml`:

```yaml
protocol_relays:
  - name: inbox
    type: imap
    listen: "0.0.0.0:1143"
    upstream:
      host: "imap.example.com"
      port: 993 # implicit TLS (IMAPS); STARTTLS on 143 is not supported
      tls: true
    auth:
      type: imap-login
      user_source: "env:IMAP_USER"
      password_source: "env:IMAP_PASSWORD"
    policy:
      write_mode: none # read-only: no flagging, moving or deleting
      folder_allowlist: ["INBOX"]
```

### Connecting from the cage

The cage and the egress are separate network namespaces, so a relay listening on `127.0.0.1` is unreachable from the cage. Listen on `0.0.0.0:<port>` and point the agent at the **egress's address** on that port:

- **container and vm cages:** the egress address is the host part of `$HTTPS_PROXY` (`http://<egress-ip>:8080`). The same address is the cage's nameserver in `/etc/resolv.conf`.
- **apple-container cages:** the egress address is in `$AGENTCAGE_EGRESS_IP`.

For the SMTP example above, the agent's mail client uses host `<egress-ip>`, port `1025`, plain SMTP, no TLS and no password. The relay accepts and ignores any `AUTH` the client sends. For IMAP, the relay greets the client already authenticated (`PREAUTH`).

Choose a listen port that is not in `ports.tcp.allow` (80 and 443 by default) and that the egress does not already use (53, 8080, 8443). The egress redirects connections on inspected ports to its HTTP proxy, so a relay listening there never sees them. Note that `0.0.0.0` also binds the egress's interface on podman's default network, which other rootless containers on the same host can reach. The relay's policy is the only thing gating them.

Rules for both relay types:

- **Upstream TLS is implicit TLS or nothing.** `tls: true` starts the TLS handshake as soon as the connection opens (SMTPS on 465, IMAPS on 993). `tls: false` is plaintext end to end. Neither relay speaks STARTTLS: not upstream, so a submission port like 587 or IMAP on 143 does not work with `tls: true`, and not to the agent either.
- **Rate limits are `"<count>/<unit>"`.** The unit is lowercase `sec`/`s`, `min`/`m` or `hour`/`h`, for example `"10/min"` or `"20/hour"`. Any other spelling, such as `"10/minute"`, is not accepted. `cage create` does not catch it: the relay refuses to start and logs a `relay_init_failed` audit record. `send_rate_limit` (SMTP) counts messages the upstream accepted and defaults to `"20/hour"`. `conn_rate_limit` (both) defaults to `"30/min"`.
- **Policy keys are per protocol.** `write_mode`/`readonly`, `folder_allowlist` and `folder_denylist` apply to IMAP. `sender_allowlist`, `recipient_allowlist`, `max_message_bytes` and `max_recipients` apply to SMTP. A key on the wrong relay type is ignored.

If the agent tries to email an address outside `recipient_allowlist`, the relay refuses that `RCPT TO` with a `550`. A message whose body trips an inspector (a leaked secret, for instance) is refused with a `550` at the end of `DATA`. Both refusals are written to the egress audit log as `smtp_command` and `smtp_data` records.

---

## Next Steps

- **[System Architecture](../explain/architecture.md)** — Detailed proxy pipeline flow.
- **[Configuration Reference](../reference/configuration.md)** — Syntax for `inspectors` and `protocol_relays`.
- **[Auditing How-To](manage-egress-and-domains.md)** — Inspecting audit logs and findings.
