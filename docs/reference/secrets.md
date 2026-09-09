# Secrets Management Reference

agentcage implements a **zero-leak secret architecture**. Real API keys, tokens, and credentials **never enter the sandboxed workload container**. 

Instead, the agent container only ever holds cryptographically random decoy tokens. Real secrets remain encrypted on the host, where the egress proxy swaps them on the wire outbound and redacts them inbound.

---

## The Secret Lifecycle

```
[ Operator ]
     │
     ▼ (agentcage secret set my-agent ANTHROPIC_API_KEY)
[ Encrypted Host Storage ]
  • Linux: systemd-creds (TPM2 / host key encrypted)
  • macOS: macOS Keychain
     │
     ▼ (agentcage cage create)
[ Mint Entropic Placeholder ]
  agentcage:secret:ANTHROPIC_API_KEY:4f2a7b8c9d0e1f2a3b4c5d6e7f8a9b0c
     │
     ├───────────────────────────────────────────┐
     │ Injected into Container                   │ Loaded into Egress Proxy
     ▼                                           ▼
[ Workload Container ]                     [ Egress Proxy Addon ]
  ANTHROPIC_API_KEY=agentcage:secret:…       Mapping: placeholder ↔ Real Secret
     │                                           │
     ▼ (Outbound HTTPS Request)                  ▼
  Authorization: Bearer agentcage:secret:…  ──▶ [ Wire Substitution ]
                                                  Authorization: Bearer sk-ant-api03-...
                                                         │
                                                         ▼
                                                  [ Upstream API ]
                                                         │
                                                         ▼ (Inbound Response)
                                            ──▶ [ Streaming Reverse Redactor ]
                                                  (Redacts any echoed real key)
                                                         │
                                                         ▼
                                            [ Workload Container ]
```

---

## 1. Entropic Placeholder Format

Placeholders are generated at cage creation or during placeholder rotation. Each placeholder is an immutable, 128-bit random token formatted as:

```text
agentcage:secret:<VARIABLE_NAME>:<32_HEX_CHARS>
```

Example:
```text
agentcage:secret:ANTHROPIC_API_KEY:a1b2c3d4e5f60718293a4b5c6d7e8f90
```

### Why Entropic Placeholders?
- **Guess-Resistant**: Unlike static placeholders (such as `{{API_KEY}}`), entropic placeholders cannot be guessed or forged by malicious dependencies.
- **Self-Identifying**: The `agentcage:secret:` prefix allows the proxy's reverse response redactor to instantly distinguish placeholders from arbitrary application data.
- **Safe to Leak**: If a prompt injection tricks an agent into running `env` or printing variables to a public GitHub issue, only the harmless placeholder string is revealed.

---

## 2. At-Rest Encrypted Storage

Secrets are stored outside the cage directory in host-level secure vaults:

| Platform | Storage Backend | Encryption Mechanism |
| :--- | :--- | :--- |
| **Linux (systemd ≥ 250)** | `systemd-creds` | Encrypted using host TPM2 or root systemd credential key. Saved to `~/.config/agentcage/cages/<name>/creds/`. |
| **macOS (All versions)** | macOS Keychain | Stored securely in the user's login Keychain under service `agentcage.<name>`. |
| **Fallback (Plaintext)** | File storage (`0600`) | Stored in cleartext only if `secrets.allow_plaintext: true` is explicitly configured. |

### Strict Fail-Closed Guarantee
agentcage defaults to **fail-closed** encryption. If `systemd-creds` or the macOS Keychain is unavailable, `agentcage secret set` will refuse to store credentials in cleartext unless the operator explicitly sets `secrets.allow_plaintext: true` in `cage.yaml`.

---

## 3. Wire Substitution & Reverse Redaction

### Outbound Substitution
When an outbound request leaves the cage:
1. The proxy matches the destination domain against the declared `inject_to` rule in `cage.yaml`.
2. If the domain matches, the proxy scans credential-bearing headers (`Authorization`, `x-api-key`, `x-token`, etc.).
3. The placeholder is substituted with the real secret bytes on the wire.
4. If `inject_body: true` is enabled, the proxy additionally scans and replaces placeholders inside JSON or form-encoded payloads.

### Inbound Reverse Redaction
If the upstream API reflects the submitted credential (for example, in an error payload: `Invalid token: sk-ant-api03-...`), the proxy's inbound streaming filter intercepts the response body and headers. Any substring matching the real secret is immediately redacted back to its placeholder before the response enters the workload container.

---

## 4. Zero-Restart Secret Updates

In agentcage, updating a secret does **not** require stopping or restarting the running container:

```bash
agentcage secret set my-agent ANTHROPIC_API_KEY
```

1. The new secret value is stored encrypted on the host.
2. The CLI signals the running proxy addon via an atomic file swap.
3. The proxy reloads its in-memory substitution table instantly.
4. The workload container continues running without dropping active connections.

---

## 5. Secret Rotation (`rotate-placeholders`)

If you suspect a decoy placeholder has been exposed or want to refresh tokens periodically:

```bash
agentcage secret rotate-placeholders my-agent
```

This command:
1. Mints fresh 128-bit random tokens for all declared secrets.
2. Updates `cage.yaml` and proxy mapping tables.
3. Restarts the cage so running agent processes pick up the fresh environment variables.

---

## 6. CLI Command Summary

| Command | Action |
| :--- | :--- |
| `agentcage secret set <cage> <key>` | Prompt for and securely store a secret value. |
| `agentcage secret set <cage> <key> --declare` | Store secret and automatically add `secret_injection` rule to `cage.yaml`. |
| `agentcage secret list <cage>` | List all configured secrets, storage status, and mapped placeholders. |
| `agentcage secret rm <cage> <key>` | Delete a secret from host storage. |
| `agentcage secret rotate-placeholders <cage>` | Mint fresh random decoy placeholders for injection rules. |

---

## Next Steps

- **[Configuration Reference](configuration.md)** — Learn how to define `secret_injection` rules.
- **[Security Model](../explain/security-model.md)** — Threat boundaries and credential confinement.
