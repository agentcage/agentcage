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
| `inspectors` | list[object] | `[]` | Settings for the built-in inspectors, and custom inspectors (WebAssembly components). See [Inspectors](#7-inspectors). |
| `max_request_body` | integer | `10485760` | Request body limit of the `body-size` inspector, in bytes. `0` disables it. |
| `entropy` | object | off | Enables and configures the `entropy` inspector. See [Inspectors](#7-inspectors). |
| `content_type` | object or `false` | on | Configures the `content-type` inspector; `false` turns it off. |
| `rate_limit` | object | 10 rps, burst 50 | Per-host request rate limit in the egress (`requests_per_second`, `burst`). |
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
- **`named_volumes`** *(map[string, string], default: {})*: Persistent Podman named volumes mapped to container mount paths. Names agentcage creates volumes under are refused, because each belongs to one cage and one of them holds that cage's CA private key: `agentcage-certs-*`, `agentcage-public-certs-*`, `agentcage-podman-*`, and any name ending in `.volume` (a quadlet unit reference). The same applies to a `volumes` entry whose source is a bare volume name rather than a path.
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

Defines the domain policy, enforced by `dnsmasq` (which names resolve) and by the egress proxy's `domain` inspector (which requests are allowed):

```yaml
domains:
  mode: allowlist # allowlist | blocklist (default: allowlist)
  allow:
    - api.anthropic.com
    - github.com
    - githubusercontent.com # also covers raw.githubusercontent.com etc.
  block:
    - telemetry.example.com
  passthrough:
    - pinned-api.example.com
  expires:
    temp-download.com: "2026-09-08T18:00:00+00:00"
```

- **`mode`** *(string, default: "allowlist")*:
  - `allowlist`: Default-deny. Only domains matching `allow` or active runtime grants can resolve and connect.
  - `blocklist`: Default-allow. All domains connect except those listed in `block`.
- **`allow`** *(list[string])*: Allowed domains. Each entry matches the name itself and every subdomain (`npmjs.org` covers `registry.npmjs.org`); there is no wildcard syntax, and `*.npmjs.org` is refused. Entries are plain lowercase hostnames; single-label LAN hostnames are accepted.
- **`block`** *(list[string])*: Forbidden domains in `blocklist` mode, matched the same way.
- **`passthrough`** *(list[string])*: Domains (and their subdomains) whose TLS is not terminated. The egress splices the connection as raw TCP, so nothing in it is inspected, captured or injected. Use it only for clients that pin certificates and cannot trust the cage CA. A passthrough connection is spliced only when its destination address is one the name resolves to; otherwise it is intercepted like any other.
- **`expires`** *(map[string, string])*: Per-domain expiry (allowlist mode), as an ISO 8601 timestamp with a UTC offset. An expired entry is blocked at once by the domain inspector, even while DNS still resolves it. `agentcage domain add --expires-in` writes these.

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

- **`tcp.allow`**: every allowed port that is not also in `tcp.passthrough` is an *inspected* port: the egress redirects it to its proxy, which handles TLS and plain HTTP on it and closes anything else. The forward proxy (`HTTPS_PROXY`) only connects to inspected ports, too: `CONNECT host:22` is refused with a `403` unless 22 is inspected. 8080 and 8443 are the egress's own listeners and cannot be inspected ports.
- **`tcp.passthrough`**: allowed ports forwarded at layer 3 without inspection, audit or capture.
- **`udp.allow`**: UDP is never inspected; listed ports are forwarded as they are.

---

## 4. `secrets` & `secret_injection`

Configures host-side encrypted secret storage and wire-level placeholder substitution:

```yaml
secrets:
  backend: auto # auto | systemd-creds | system-keychain | plaintext
  scope: auto # auto | user | system (systemd-creds only)
  allow_plaintext: false # Disallow unencrypted secret files

secret_injection:
  - env: ANTHROPIC_API_KEY
    placeholder: null # Auto-generates `agentcage:secret:ANTHROPIC_API_KEY:<hex>`
    inject_to:
      - api.anthropic.com
    inject_headers: [] # Extra header names to treat as credential-bearing
    inject_body: false # Also substitute in the URL, every header and the body
    source: null # Where the value comes from (env:/systemd-creds:/podman:/cmd:)
    transform: null # Optional transform ("google-jwt-bearer")
    transform_config: {} # The transform's own settings
```

- **`env`** *(string, required)*: Environment variable name presented inside the workload container.
- **`placeholder`** *(string, optional)*: Explicit placeholder string. When omitted, agentcage mints a cryptographically random 128-bit entropic token (`agentcage:secret:NAME:<hex>`).
- **`inject_to`** *(list[string], default: [])*: The domains the real value may be sent to. Each entry also covers its subdomains (`example.com` covers `api.example.com`, not `notexample.com`). **Empty means the value is never injected.** A request that carries the real value to any other host is blocked, and the placeholder sent to another host is flagged.
- **`inject_headers`** *(list[string], default: [])*: By default the placeholder is replaced only in credential-bearing request headers: a header whose name contains `auth`, `key` or `token` (`Authorization`, `x-api-key`, `x-auth-token`, …), including inside `Authorization: Basic`. List any other header names here (case-insensitive), e.g. `x-honeycomb-team`.
- **`inject_body`** *(boolean, default: false)*: Also replace the placeholder in the URL (which may change where the request goes), in every header and in the body. A rewritten body is sent without `Content-Encoding` and with a corrected `Content-Length`.
- **`transform`** *(string, optional)*: `google-jwt-bearer` turns a Google service-account key into short-lived OAuth access tokens: the egress signs an RS256 JWT, exchanges it at `transform_config.audience` (default `https://oauth2.googleapis.com/token`) for `transform_config.scopes`, caches the token until `refresh_margin` seconds (default 300) before it expires, mints at most `mint_rate_per_hour` (default 60) tokens an hour, and injects the token instead of the key. Minted tokens are redacted like the key itself.

Setting a header collapses its duplicates into one comma-joined value. Every real value (and every live minted token) is redacted back to its placeholder in responses, WebSocket messages, the capture file and the audit log, including its percent-encoded, JSON-escaped and base64 forms.

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
      requests_per_second: 1.0
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
  max_body_size: 10485760 # 10 MiB of each body is kept (default)
  max_file_size: 134217728 # rotate capture.jsonl to capture.jsonl.1 at 128 MiB (default; 0 = never)
  min_action: all # Least severe outcome to record (all | flag | block)
  domains: [] # Capture only these domains (empty = all)
  exclude_domains: [] # Skip capturing for high-volume endpoints

logging:
  level: info # debug | info | warning | error | critical
  dns_queries: false # Log every DNS query dnsmasq answers
  proxy_connections: false # Log every connection the proxy accepts
  allowed_requests: false # Log allowed HTTP requests (requests that injected or redacted a secret are always logged)
```

`enable_har` is off by default. Bodies are recorded with `Content-Encoding` removed; one longer than `max_body_size` is truncated and marked as such. Both views of an entry (`cage har --view inbound` and `--view outbound`) hold placeholders, never real secret values or minted tokens. A streamed response is captured as it streams, keeping its first `max_body_size` bytes; a `max_body_size` of `0` (unlimited) makes the egress buffer responses whole instead of streaming them.

`min_action` filters by the flow's outcome: `all` records every flow, `flag`
only flagged and blocked ones, `block` only blocked ones. Any other value is
rejected. Earlier versions of this page showed `allowed | flagged | blocked`;
the egress never understood those and recorded every flow for them. They are
now read as `all`, `flag` and `block`, with a warning to change the spelling.

A WebSocket is captured as one entry, written when the socket closes: the
upgrade request and its `101` response, then the messages of both directions
in order (`ws_messages`). Each message's data is capped at `max_body_size`, and
one socket keeps at most 4096 messages and `max_body_size` bytes of message data
in total; the number of messages past that limit is recorded as
`ws_messages_omitted`. `min_action` is applied to the socket's worst outcome, so
a socket with a flagged or blocked message is recorded under `flag` or `block`.

---

## 7. Inspectors

Every request the cage sends passes through a chain of inspectors in the egress: the built-ins first, in the order `domain`, `secrets`, `body-size`, `entropy`, `content-type`, then custom inspectors in the order listed. The first `block` ends the chain and the cage gets a `403`; a `flag` lets the request through and is audited as `flagged`. The built-ins inspect requests (and WebSocket messages the cage sends), not responses.

The built-ins are configured by top-level keys:

```yaml
max_request_body: 10485760 # body-size: 10 MiB (default); 0 disables

secrets: # the secrets inspector reads the same block as secret storage
  action: flag # flag (default) | block
  extra_patterns: [] # more patterns: {name, pattern} (a regex)
  allow_to_domains: {} # pattern name -> domains it may be sent to

entropy: # off unless present
  threshold: 7.0 # bits/byte for bodies
  min_body_bytes: 256
  check_url_params: true
  check_url_path: true
  url_threshold: 5.5
  url_min_value_bytes: 64
  action: block

content_type: # on by default; `content_type: false` turns it off
  entropy_ceiling: 6.5
  detect_base64: true
  base64_min_len: 256
  action: block

rate_limit: # per host, in the egress
  requests_per_second: 10 # 0 disables
  burst: 50
```

An `inspectors:` entry naming a built-in replaces that built-in's whole configuration (and can enable `entropy`):

```yaml
inspectors:
  - name: entropy
    config:
      threshold: 7.5
```

A custom inspector is a WebAssembly component (`.wasm`) built with the `agentcage-inspector-sdk` crate:

```yaml
inspectors:
  - name: header-policy # any name except a built-in's
    path: plugins/header_policy.wasm # relative to the cage.yaml's directory, or absolute
    config: # handed to the plugin's configure()
      required_header: X-Trace-ID
```

`cage create` and `cage update` copy each plugin into the cage and mount it read-only into the egress; a changed plugin file makes `cage update` redeploy. A path that does not end in `.wasm` is refused, and a `.py` path is refused with a pointer to the migration guide: Python inspectors are no longer supported. Plugins run with no capabilities and a CPU and memory budget, and a plugin that fails counts as a `block`. See [Custom Inspectors](../how-to/custom-inspectors.md).

---

## 8. `vm` (Lima Backend Sizing)

When running under `isolation: vm`, configures resource allocations for the guest Linux microVM:

```yaml
vm:
  vcpus: 4 # Number of virtual CPU cores
  mem_mb: 4096 # Memory allocation in megabytes (4 GB)
```

---

## 9. `protocol_relays` (IMAP & SMTP)

A list of hardened IMAP and SMTP relays that run in the egress, hold the mailbox credentials, and apply policy to every command the cage sends. Every key, its default and what the relays log is in the **[Protocol Relays Reference](protocol-relays.md)**.

---

## Next Steps

- **[CLI Reference](cli.md)** — Learn all commands to create, update, and manage cages.
- **[Protocol Relays Reference](protocol-relays.md)** — `protocol_relays` keys, defaults and audit records.
- **[Policy API Reference](policy-api.md)** — HTTP endpoints for dynamic domain requests.
- **[Secrets Reference](secrets.md)** — Secret storage and placeholder lifecycles.
