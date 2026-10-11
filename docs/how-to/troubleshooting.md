# How-To: Troubleshooting & Diagnostics

This guide provides diagnostic workflows and remediation steps for common operational issues encountered when running agentcage.

---

## 1. Quick Diagnostic Checklist

When encountering any issue with agentcage, run through this four-step triage:

### Step 1: Run System Diagnostics
```bash
agentcage doctor
```
Checks rootless Podman, systemd lingering, cgroups v2, Lima/Apple Container runtimes, and secret storage backends.

### Step 2: Verify Cage Health
```bash
agentcage cage verify <name>
```
Validates that container services are running, IP addresses are allocated, and DNS is responding.

### Step 3: Stream Logs
```bash
# Workload agent logs:
agentcage logs <name> -f

# Egress proxy and DNS logs:
agentcage logs <name> -s egress -f
```

### Step 4: Get the Full Traceback
```bash
AGENTCAGE_TRACEBACK=1 agentcage <command>
```
agentcage renders expected failures as a single `error: ...` line; set `AGENTCAGE_TRACEBACK=1` to get the underlying traceback when filing a bug.

---

## 2. Common Issues & Solutions

### A. Network & DNS Gotchas

#### Symptom: Connections resolve to `198.51.100.1` or fail with `403 Forbidden`
- **Cause**: The requested domain is not in the allowlist. Unauthorized domains are sinkholed to `198.51.100.1` so the egress proxy can answer with a JSON `403` such as `{"blocked": true, "reason": "domain not in allowlist: example.com", "host": "example.com", "by": "agentcage"}`.
- **Solution**:
  1. Inspect blocked requests:
     ```bash
     agentcage cage audit <name> -d blocked --since 30m
     ```
  2. If the domain is required, add it:
     ```bash
     agentcage domain add <name> <domain>
     ```

#### Symptom: Package managers report TLS / SSL Certificate Errors
- **Cause**: The agent runtime is not trusting the per-cage CA certificate mounted at `/certs/agentcage-ca.pem`.
- **Solution**:
  The cage sets these environment variables to `/certs/agentcage-ca.pem`. Check that the container still has them (`env | grep /certs/`) and that `container.env` doesn't override one:
  - OpenSSL-based tools, Go, uv: `SSL_CERT_FILE`
  - Node.js, npm, Bun: `NODE_EXTRA_CA_CERTS`
  - Git: `GIT_SSL_CAINFO`
  - Python `requests`: `REQUESTS_CA_BUNDLE`
  - cURL: `CURL_CA_BUNDLE`
  - pip: `PIP_CERT`
  - boto3 / AWS CLI: `AWS_CA_BUNDLE`
  - cargo: `CARGO_HTTP_CAINFO`
  - Deno: `DENO_CERT`
  - gRPC: `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`

  A tool that reads none of these (Java, for one) needs the CA in its own trust store, or in the image's system store as the arch/debian/ubuntu scaffolds do.

---

### B. Linux & Podman Gotchas

#### Symptom: "Error: user lingering is disabled"
- **Cause**: On Linux, systemd terminates user background services when the SSH session or terminal closes.
- **Solution**: Enable systemd user lingering:
  ```bash
  loginctl enable-linger "$USER"
  ```

#### Symptom: "Error: cannot allocate subuid/subgid"
- **Cause**: Rootless Podman requires subordinate UID and GID ranges allocated in `/etc/subuid` and `/etc/subgid`.
- **Solution**:
  ```bash
  sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 "$USER"
  podman system migrate
  ```

---

### C. macOS Gotchas

#### Symptom: "Apple container runtime not found"
- **Cause**: The `apple-container` backend requires Apple's `container` CLI on macOS 26+ (Apple Silicon).
- **Solution**:
  ```bash
  brew install container
  ```
  If running on an Intel Mac or earlier macOS version, use the `vm` backend instead:
  ```bash
  brew install lima
  agentcage run claude-code --isolation vm -s ANTHROPIC_API_KEY
  ```

#### Symptom: "Host volume mount must be under $HOME"
- **Cause**: The Apple Container microVM runtime enforces that all shared directory mounts reside within the host user's `$HOME` directory.
- **Solution**: Move project repositories into `$HOME/code/` or similar paths before binding.

---

### D. Secret Management Gotchas

#### Symptom: "Error: secret storage backend failed"
- **Cause**: Linux systems without `systemd-creds` (or headless Linux environments without a TPM) reject plaintext secret storage by default.
- **Solution**:
  If encrypted storage is unavailable on your system, explicitly opt in to plaintext file storage in `cage.yaml`:
  ```yaml
  secrets:
    allow_plaintext: true
  ```

#### Symptom: Agent leaks real credentials in terminal or GitHub issues
- **Cause**: Real secrets were hardcoded directly in `container.env` in `cage.yaml` instead of using `agentcage secret set`.
- **Solution**:
  1. Remove the real key from `container.env`.
  2. Store the key encrypted using `agentcage secret set <name> <KEY>`.
  3. Ensure a `secret_injection` rule maps the key to the target domain.
  4. Rotate placeholders:
     ```bash
     agentcage secret rotate-placeholders <name>
     ```

---

### E. Terminal & Shell Gotchas

#### Symptom: Host terminal corrupted after exiting `cage exec` or `cage shell`
- **Cause**: An interactive curses or TUI session crashed or terminated unexpectedly without resetting raw terminal mode.
- **Solution**:
  agentcage v0.40.1+ includes automated terminal state restoration. If your shell appears corrupted:
  ```bash
  reset
  ```

---

### F. Egress Proxy Responses & Errors

Every response the egress generates itself is JSON: `{"blocked": <bool>, "reason": "...", "host": "...", "by": "agentcage"}`. The `reason` says what happened; the matching audit record is in `agentcage cage audit <name>`.

#### Symptom: `502` with `"blocked": false`
- **Cause**: The request was allowed, but the upstream failed: the name did not resolve, the connection was refused, the upstream's TLS certificate did not verify, the upstream broke the HTTP protocol, or its response body was larger than the egress's per-body limit. Each one writes an `upstream_error` audit record with the error text.
- **Also**: `"reason": "internal error: ..."` is the egress refusing a flow it could not process (for example a body whose `Content-Encoding` is corrupt), with an `internal_error` record. The egress never forwards such a flow unfiltered.
- **Solution**: Read the reason. A TLS verification failure usually means a host behind a private CA (the egress trusts the Mozilla roots only) or a pinned endpoint that needs `domains.passthrough`.

#### Symptom: `503` "the egress is already buffering its … budget of bodies; retry later"
- **Cause**: Too many large request or response bodies were buffered at once; the egress refuses new ones after waiting two seconds for room, rather than run out of memory.
- **Solution**: Retry. If it persists, the cage is moving many large bodies concurrently; streamed responses hold only a little at a time, so check whether a custom inspector that declares the response phase (which forces responses to be buffered) is loaded.

#### Symptom: `413` "request body exceeds the egress limit of … bytes"
- **Cause**: A request body over the egress's per-body limit (256 MiB). Request bodies are buffered whole so they can be inspected. A body over `max_request_body` (10 MiB by default) is blocked earlier by the `body-size` inspector with a `403`.
- **Solution**: Raise `max_request_body` in `cage.yaml` if the upload is legitimate.

#### Symptom: `403` "port N is not an inspected port"
- **Cause**: A client used the forward proxy (`HTTPS_PROXY`) to `CONNECT` to a port that is not an inspected port. The forward proxy only connects to `ports.tcp.allow` minus `ports.tcp.passthrough`.
- **Solution**: Add the port to `ports.tcp.allow` (inspected), or to both `allow` and `passthrough` and exclude the host from the proxy with `NO_PROXY` (uninspected).

#### Symptom: `403` "SNI/Host header mismatch"
- **Cause**: The TLS SNI and the HTTP `Host` header name different hosts, which is how domain fronting works.
- **Solution**: Make the client send the same name in both. Clients that set `Host` by hand to a different name are refused by design.

#### Symptom: A download or stream stops partway, with no error response
- **Cause**: The upstream failed after the response had started, or a streamed body turned out to be corrupt at its end. The egress cuts the client off (HTTP/1.1 closes the connection, HTTP/2 resets the stream) so a truncated transfer never looks complete. With secrets to redact, a single run of more than 16 MiB without a separator (a huge base64 blob, for instance) is also aborted rather than relayed unredacted.
- **Solution**: Retry; check `agentcage logs <name> -s egress` for the error.

#### Symptom: A config change does not take effect
- **Cause**: The egress refused the new config (it does not parse, or an inspector or rate-limit setting is invalid) and kept running the last good one. It writes one `config_reload_failed` record per bad version.
- **Solution**: `agentcage cage audit <name>` shows the record and the error; fix the config with `agentcage cage edit <name>`.

#### Symptom: TLS errors after upgrading agentcage, from an image that bakes in the CA
- **Cause**: Each cage's egress generates its own CA and loads only that one afterwards. A cage gets a new CA when it is created or recreated, and every existing cage got one on its first start after the upgrade that introduced the Rust egress (it never reuses a CA the previous egress generated). An image that copied `/certs/agentcage-ca.pem` into its trust store at **build** time still trusts the old CA.
- **Solution**: Rebuild the image without its layer cache (`agentcage cage update <name> --no-cache`), or install the CA at start-up instead, as the arch/debian/ubuntu scaffolds do. Tools that read `SSL_CERT_FILE` and the other CA variables pick up the new CA with no rebuild.

#### Symptom: A custom inspector blocks everything with "inspector <name> failed: …"
- **Cause**: The plugin trapped, used a capability it does not have (files, network, environment, clock), ran out of its fuel or memory budget, or returned a malformed verdict. A broken plugin fails closed.
- **Solution**: See [Custom Inspectors](custom-inspectors.md#the-sandbox-and-its-limits); test the logic natively with `cargo test` first.

---

## 3. Viewing Forensic Audit Logs

The egress writes every decision as a JSON line to its log (journald on the container and vm backends, `audit.jsonl` on apple-container). `agentcage cage audit` reads it, whatever the backend:

```bash
# View recent decisions:
agentcage cage audit my-agent -n 25

# Stream events in real time:
agentcage cage audit my-agent -f

# Filter by inspector and decision:
agentcage cage audit my-agent --inspector secrets --decision flagged
```

---

## Next Steps

- **[Security Model](../explain/security-model.md)** — Understand trust boundaries and defense mechanisms.
- **[Configuration Reference](../reference/configuration.md)** — Check valid configuration keys.
