# How-To: Troubleshooting & Diagnostics

This guide provides diagnostic workflows and remediation steps for common operational issues encountered when running agentcage.

---

## 1. Quick Diagnostic Checklist

When encountering any issue with agentcage, run through this three-step triage:

### Step 1: Run System Diagnostics
```bash
agentcage doctor
```
Checks Python runtime, rootless Podman, systemd lingering, cgroups v2, Lima/Apple Container runtimes, and secret storage backends.

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

---

## 2. Common Issues & Solutions

### A. Network & DNS Gotchas

#### Symptom: Connections resolve to `198.51.100.1` or fail with `403 Forbidden`
- **Cause**: The requested domain is not in the allowlist. Unauthorized domains are sinkholed to `198.51.100.1` so the proxy can return a structured 403 response.
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
- **Cause**: The agent runtime is not trusting the per-cage CA certificate mounted at `/certs/mitmproxy-ca-cert.pem`.
- **Solution**:
  Verify the following environment variables are set inside the container:
  - Python: `REQUESTS_CA_BUNDLE=/certs/mitmproxy-ca-cert.pem`
  - Node.js: `NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem`
  - cURL: `CURL_CA_BUNDLE=/certs/mitmproxy-ca-cert.pem`
  - Git: `git config --global http.sslCAInfo /certs/mitmproxy-ca-cert.pem`

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

## 3. Viewing Forensic Audit Logs

Every request decision is logged to `~/.local/share/agentcage/<name>/audit.jsonl`:

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
