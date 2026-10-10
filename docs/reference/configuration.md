# Configuration Reference (`cage.yaml`)

Every agentcage sandbox is defined by a single declarative YAML configuration file, traditionally named `cage.yaml`.

When a cage is created via `agentcage cage create -c cage.yaml`, the validated configuration is persisted to `~/.config/agentcage/cages/<name>/cage.yaml` as the canonical source of truth.

---

## Minimal Example

```yaml
name: my-agent
isolation: container # container | apple-container | vm (default: auto)

container:
  image: "node:22-slim"
  command: ["bash"]
  volumes:
    - ".:/workspace:rw"

domains:
  mode: allowlist
  allow:
    - api.anthropic.com
    - github.com
    - registry.npmjs.org

secret_injection:
  - env: ANTHROPIC_API_KEY
    inject_to:
      - api.anthropic.com
    inject_headers: true
```

---

## Top-Level Schema

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `name` | string | **Required** | Unique cage name. Lowercase alphanumeric and hyphens (`^[a-z0-9][a-z0-9-]{0,62}$`). |
| `isolation` | string | `auto` | Isolation backend: `container` (Linux Podman), `apple-container` (macOS 26+ microVMs), or `vm` (Lima). |
| `lifecycle` | string | `service` | Execution mode: `service` (managed systemd service, auto-restarts), `interactive` (terminal session), or `ephemeral` (destroyed upon process exit). |
| `scaffold` | string | `null` | Name of the scaffold template used to initialize the cage. |
| `help` | string | `null` | Custom operational documentation displayed when running `agentcage show <name>`. |
| `dns_servers` | list[string] | `host` | Upstream DNS resolvers. Defaults to host resolvers (excluding loopbacks like `127.0.0.53`). |
| `apple_container_autostart` | boolean | `false` | For macOS `apple-container`: installs a launchd agent to restart the cage on user login. |
| `exec_aliases` | map[string, list[string]] | `{}` | Custom command shortcuts for `agentcage exec` (e.g. `claude: ["claude", "--print"]`). |
| `container` | object | `{}` | Workload sandbox container specification. |
| `domains` | object | `{}` | Egress DNS and network domain filtering policy. |
| `ports` | object | `{}` | Layer 4 transport layer port filtering (TCP, UDP, ICMP). |
| `secrets` | object | `{}` | Encrypted secret storage backend configuration. |
| `secret_injection` | list[object] | `[]` | Declarative rules for injecting real credentials on the wire. |
| `agents` | object | `{}` | Autonomous LLM policy gatekeepers (`decider`, `watcher`). |
| `inspectors` | list[object] | Built-ins | Custom Python traffic inspection plugins. |
| `protocol_relays`| list[object] | `[]` | Hardened non-HTTP protocol relays (IMAP, SMTP). See [Protocol Relays Reference](protocol-relays.md). |
| `logging` | object | `{}` | Operational and DNS query logging verbosity. |
| `capture` | object | `{}` | L7 payload capture and HAR 1.2 generation settings. |
| `vm` | object | `{}` | Resource allocations for the Lima VM backend. |

---

## 1. `container` Configuration

Defines the environment, resources, and privileges of the sandboxed agent container:

```yaml
container:
  image: "node:22-slim"
  command: ["node", "server.js"]
  user: "1000:1000"
  read_only: true
  drop_capabilities: ["ALL"]
  add_capabilities: []
  no_new_privileges: true
  memory: "4g"
  cpus: "2.0"
  volumes:
    - ".:/workspace:rw"
  named_volumes:
    npm-cache: "/home/node/.npm"
  tmpfs:
    - "/tmp:rw,noexec,nosuid,size=512m"
  env:
    NODE_ENV: "development"
  ports: []
  nested_containers: false
  restart: "on-failure"
  restart_sec: 10
```

### Detailed Properties

- **`image`** *(string, default: "node:22-slim")*: OCI base container image to pull and run.
- **`command`** *(list[string], optional)*: Entrypoint arguments passed to the container workload.
- **`user`** *(string, default: "1000:1000")*: UID:GID inside the container. Avoid running as `0:0` (root).
- **`read_only`** *(boolean, default: true)*: Mounts the container root filesystem as read-only.
- **`drop_capabilities`** *(list[string], default: ["ALL"])*: Linux capabilities dropped from the workload process.
- **`add_capabilities`** *(list[string], default: [])*: Explicit Linux capabilities to retain (use with extreme caution).
- **`no_new_privileges`** *(boolean, default: true)*: Prevents processes from gaining additional privileges via `setuid` binaries.
- **`memory`** *(string, optional)*: Memory limit (e.g. `"2g"`, `"4096m"`).
- **`cpus`** *(string, optional)*: Maximum CPU cores allocated (e.g. `"2.0"`).
- **`volumes`** *(list[string], default: [])*: Host directory bind mounts in `source:target[:flags]` format (e.g. `".:/workspace:rw"`). Mounts to `/workspace` automatically have `.git/hooks` and `.claude/` masked via tmpfs overlays.
- **`named_volumes`** *(map[string, string], default: {})*: Persistent Podman named volumes mapped to container mount paths.
- **`tmpfs`** *(list[string], default: [])*: Tmpfs mounts in `target[:options]` format (e.g. `"/tmp:rw,noexec,nosuid,size=512m"`).
- **`env`** *(map[string, string], default: {})*: Environment variables injected into the container. *Never place real secrets here; use `secret_injection`.*

  **Values are expanded against the host's environment** at deploy time,
  with `os.path.expandvars` semantics: `$NAME` and `${NAME}` are replaced
  by the host process's value for `NAME`, and a name the host does not
  define is left alone. The expansion has been there since 0.1.0 and both
  backends do it, but it was never written down, so two consequences are
  worth stating plainly:

  - A value that merely *contains* a dollar sign followed by a name the
    host exports is rewritten. There is no escape: `$$` stays `$$`, and
    `$NAME` for a name the host does not define stays `$NAME`, so a
    literal `${PATH}` cannot be delivered to the cage through this field.
  - A `cage.yaml` you did not write can read your shell's environment.
    `env: { X: "${OPENAI_API_KEY}" }` copies that key into the cage and
    into the generated unit file on disk. Read the `env:` block of any
    config you did not author, the same way you would read its `volumes:`.

  `secret_injection` is the supported way to give a cage a real
  credential: the value reaches the egress proxy and is substituted into
  the outbound request, so it never enters the workload's environment at
  all.
- **`ports`** *(list[string], default: [])*: Inbound host ports to publish (e.g. `["127.0.0.1:8080:8080"]`). Traffic passes through an inbound reverse proxy.
- **`nested_containers`** *(boolean, default: false)*: Enables nested rootless Podman execution inside the cage.
- **`restart`** *(string, default: "on-failure")*: Systemd container restart policy (`always`, `on-failure`, `no`).

---

## 2. `domains` (Egress Policy)

Defines network filtering rules enforced by `dnsmasq` and `mitmdump`:

```yaml
domains:
  mode: allowlist # allowlist | blocklist (default: allowlist)
  allow:
    - api.anthropic.com
    - github.com
    - "*.githubusercontent.com"
  block:
    - telemetry.example.com
  passthrough:
    - pinned-api.example.com
  expires:
    temp-download.com: "2026-09-08T18:00:00Z"
```

- **`mode`** *(string, default: "allowlist")*:
  - `allowlist`: Default-deny. Only domains matching `allow` or active runtime grants can resolve and connect.
  - `blocklist`: Default-allow. All domains connect except those listed in `block`.
- **`allow`** *(list[string])*: Allowed domain patterns. Leading wildcards (e.g. `*.npmjs.org`) match all subdomains. Single-label LAN hostnames are accepted for operator configurations.
- **`block`** *(list[string])*: Explicitly forbidden domains. Overrides allow rules.
- **`passthrough`** *(list[string])*: Domains exempt from TLS MITM decryption. The proxy tunnels raw TCP streams without inspecting bodies or injecting secrets. Required for services using certificate pinning.
- **`expires`** *(map[string, string])*: ISO 8601 timestamps defining when specific domain entries automatically expire.

---

## 3. `ports` (Layer 4 Filtering)

Controls packet-level transport filtering in the egress container `iptables`:

```yaml
ports:
  tcp:
    allow: [80, 443] # Permitted outbound destination TCP ports
    passthrough: [] # Ports that bypass the local proxy entirely
  udp:
    allow: [] # Permitted outbound UDP ports (default: none)
  icmp:
    allow: false # Allow outbound ping/ICMP (default: false)
```

---

## 4. `secrets` & `secret_injection`

Configures host-side encrypted secret storage and wire-level placeholder substitution:

```yaml
secrets:
  backend: auto # auto | systemd-creds | keychain | plaintext
  scope: user # user | system
  allow_plaintext: false # Disallow unencrypted secret files

secret_injection:
  - env: ANTHROPIC_API_KEY
    placeholder: null # Auto-generates `agentcage:secret:ANTHROPIC_API_KEY:<hex>`
    inject_to:
      - api.anthropic.com
    inject_headers: true # Substitute in Authorization/x-api-key headers
    inject_body: false # Scan and substitute in JSON/form bodies
    source: null # Optional path or CLI command to resolve secret
    transform: null # Optional transform (e.g. "google-jwt-bearer")
```

- **`env`** *(string, required)*: Environment variable name presented inside the workload container.
- **`placeholder`** *(string, optional)*: Explicit placeholder string. When omitted, agentcage mints a cryptographically random 128-bit entropic token (`agentcage:secret:NAME:<hex>`).
- **`inject_to`** *(list[string], default: all allowed)*: Restricts secret substitution to requests targeting these specific domains.
- **`inject_headers`** *(boolean, default: true)*: Replaces placeholders in HTTP request headers.
- **`inject_body`** *(boolean, default: false)*: Scans and replaces placeholders inside HTTP request payloads.

---

## 5. `agents` (Decider & Watcher)

Two optional LLM agents that run inside the egress. The **decider** rules on the domain requests a cage makes through the [Policy API](policy-api.md). The **watcher** reviews the cage's recent traffic after the fact and can revoke runtime grants. Both are off unless `enable: true`, and a disabled agent's other settings are not used. See [Policy API & Decider](../explain/policy-api.md) and [Traffic Watcher](../explain/traffic-watcher.md) for how they behave.

```yaml
domains:
  allow:
    - pypi.org
    - files.pythonhosted.org

agents:
  decider:
    enable: true
    provider: openrouter # anthropic | openai | openrouter
    model: z-ai/glm-5.3
    api_key: env:OPENROUTER_API_KEY # required; env:NAME or systemd-creds:NAME
    context: >
      This cage is running a Python unit test suite.
      Approve access to official PyPI and GitHub releases.
      Deny access to file upload services and social networks.
    rate_limit:
      requests_per_second: 2.0
      burst: 5

  watcher:
    enable: true
    provider: openrouter
    model: z-ai/glm-5.3
    api_key: env:OPENROUTER_API_KEY # the decider's key may be reused
    interval_seconds: 900 # one scan every 15 minutes at most
    window_seconds: 3600 # look-back for the first scan after an egress (re)start
    max_flows: 200 # capture samples per digest
    max_digest_tokens: 8000 # spend ceiling per scan
    auto_revoke: true # revoke runtime grants the analysis condemns
    dedup_samples: true # collapse repeated flow shapes into one sample
    context: >
      Inspect traffic for data exfiltration patterns or encoded source code.
```

The LLM settings sit directly on each agent block. `rate_limit` is the only nested mapping. A key the host does not know is ignored without a warning, so check the spelling. Flat `rate_limit_rps` / `rate_limit_burst`, for example, do nothing.

`api_key` names an egress-only secret: the egress reads the value and the cage never sees it. Store it like any other secret, with `agentcage secret set <cage> NAME` or `-s NAME` at `cage create`. An `env:` name is also removed from the cage's `container.env`.

### Defaults and accepted values

Keys both agents take:

| Key | Default | Accepted values |
| :-- | :-- | :-- |
| `enable` | `false` | `true` or `false`. A real boolean: `"false"` in quotes is refused. |
| `provider` | none, required | `anthropic`, `openai` or `openrouter`, exactly (lowercase). |
| `model` | none, required | The provider's model identifier. |
| `api_key` | none, required | `env:NAME` or `systemd-creds:NAME`. `cmd:` and other schemes are refused: the egress has no shell. |
| `base_url` | the provider's own endpoint | An `https://` URL with a host. `http://` is refused because the key is sent on every call. |
| `timeout_seconds` | decider `15`, watcher `30` | Finite and greater than 0. |
| `max_tokens` | `8192` | At least `1024`. The budget includes a reasoning model's thinking tokens, so a smaller value can leave no room for the answer. Providers bill tokens generated, not this ceiling. |
| `context` | `""` (off) | A string of at most 4096 characters after trimming. It is added to the agent's system prompt as trusted operator guidance. It does not override the never-grant floor or the rate limit. |

`agents.decider` only:

| Key | Default | Accepted values |
| :-- | :-- | :-- |
| `host` | `agentcage.local` | A dotted hostname. Not an IP literal or a single label, and not listed in `domains.allow`, `block` or `passthrough`. This is the synthetic control host the cage calls. |
| `rate_limit.requests_per_second` | `1.0` | `>= 0`. `0` disables the limit. |
| `rate_limit.burst` | `5` | `>= 0`. |

The decider requires `domains` allowlist mode. In blocklist mode everything not blocked is already reachable, so a grant means nothing. Some decider limits are fixed and have no config key:
- at most 32 runtime grants at once;
- it never grants `internal`, `local`, `localhost`, `metadata.goog` or the control host, and that includes their subdomains.

`agents.watcher` only:

| Key | Default | Accepted values |
| :-- | :-- | :-- |
| `interval_seconds` | `900` | `>= 60`. One scan per interval at most, and none when the window had no traffic. |
| `window_seconds` | `3600` | Greater than 0 and at most `86400`. How far back into the capture the first scan after an egress (re)start reads. |
| `max_flows` | `200` | `10` to `2000`. |
| `max_digest_tokens` | `8000` | `0` (unbounded, with a warning) or `2000` to `500000`. This is the only setting that caps spend whatever the traffic volume. |
| `auto_revoke` | `true` | A real boolean. With `false`, revocations become findings for you to apply. |
| `dedup_samples` | `true` | A real boolean. |

The watcher refuses `domains` blocklist mode: there the baseline is the block list, so its recommendations would widen egress instead of narrowing it. `cage create` warns when `max_digest_tokens` and `interval_seconds` together allow more than 5 million input tokens a day.

The agent schema was flattened in 0.40. These older forms are refused:
- `domains.auto`;
- a top-level `watcher:`;
- any agent other than `decider` and `watcher`;
- `kind:`;
- LLM fields nested under `agent:` or `decider:`.

---

## 6. `capture` & `logging`

Controls forensic recording and HAR 1.2 export:

```yaml
capture:
  enable_har: true # Record HTTP flows for HAR export
  max_body_size: 1048576 # 1 MB maximum body capture per request
  max_file_size: 104857600 # 100 MB max capture.jsonl before rotation
  min_action: allowed # Minimum action to record (allowed | flagged | blocked)
  domains: [] # Capture only these domains (empty = all)
  exclude_domains: [] # Skip capturing for high-volume endpoints

logging:
  level: info # debug | info | warning | error | critical
  dns_queries: true # Log all DNS queries to journalctl
  proxy_connections: true # Log TCP connection events
  allowed_requests: false # Log successful HTTP requests
```

A WebSocket is captured as one entry, written when the socket closes: the
upgrade request and its `101` response, then the messages of both directions
in order (`ws_messages`). Each message's data is capped at `max_body_size`, and
one socket keeps at most 4096 messages and `max_body_size` bytes of message data
in total; the number of messages past that limit is recorded as
`ws_messages_omitted`. `min_action` is applied to the socket's worst outcome, so
a socket with a flagged or blocked message is recorded under `flag` or `block`.

---

## 7. `vm` (Lima Backend Sizing)

When running under `isolation: vm`, configures resource allocations for the guest Linux microVM:

```yaml
vm:
  vcpus: 4 # Number of virtual CPU cores
  mem_mb: 4096 # Memory allocation in megabytes (4 GB)
```

---

## 8. `protocol_relays` (IMAP & SMTP)

A list of hardened IMAP and SMTP relays that run in the egress, hold the mailbox credentials, and apply policy to every command the cage sends. Every key, its default and what the relays log is in the **[Protocol Relays Reference](protocol-relays.md)**.

---

## Next Steps

- **[CLI Reference](cli.md)** — Learn all commands to create, update, and manage cages.
- **[Protocol Relays Reference](protocol-relays.md)** — `protocol_relays` keys, defaults and audit records.
- **[Policy API Reference](policy-api.md)** — HTTP endpoints for dynamic domain requests.
- **[Secrets Reference](secrets.md)** — Secret storage and placeholder lifecycles.
