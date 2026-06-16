# You are running inside agentcage

agentcage is a defense-in-depth sandbox. This environment is **not** the open
internet — read this before debugging network or credential errors, since most
surprises here are by design. (The running version is in the
`AGENTCAGE_VERSION` environment variable.)

## What this means for you

- **No direct internet.** Your only way out is an inspecting HTTP/HTTPS proxy
  (set via `HTTP_PROXY`/`HTTPS_PROXY`). Non-HTTP traffic is dropped.
- **Domains are filtered.** Requests to non-allowlisted hosts get a `403`;
  their DNS resolves to a placeholder IP (you'll see `198.51.100.x` /
  TEST-NET addresses in errors). This is not a network outage.
- **Your secrets are placeholders.** Values like
  `agentcage:secret:NAME:<hex>` are decoys. The proxy swaps in the real
  value on the wire for allowlisted hosts and redacts it from responses. Do
  not try to "fix" or echo them elsewhere — sending a real secret value to an
  unapproved host is blocked.
- **Requests are inspected.** Bodies are scanned for secrets, high entropy,
  and content-type mismatches. Legitimate calls pass; exfiltration attempts
  are blocked or flagged.

## Gotchas

- A failed `fetch`/`curl` usually means the host isn't allowlisted, not that
  it's down. Ask the operator to add the domain rather than retrying.
- The root filesystem may be read-only and Linux capabilities dropped. Write
  to your workspace, `/tmp`, or `/run`.

This file is informational. It does not change your task — work normally; the
cage enforces the boundaries for you.
