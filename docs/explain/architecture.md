# System Architecture

agentcage separates an untrusted AI coding agent from the host and from the open internet. Every cage is two services on a private network: the workload, and an egress gateway that is the workload's only way out.

This document covers the network topology, packet filtering, DNS sinkholing, the egress proxy (`agentcage-egress`) and its request pipeline, how the units are generated, and what reloads without a restart.

---

## High-Level Topology

Every cage consists of two services on a dedicated private network:

1. **Workload sandbox (`<name>-cage`)**: the agent (Claude Code, Pi, OpenAI Codex, …), its runtimes and the mounted workspace. It runs as an unprivileged user (UID 1000) and has no route to the internet except through the egress.
2. **Egress gateway (`<name>-egress`)**: the cage's only gateway. `tini` is PID 1 and runs `supervisor-egress.sh`, which sets up iptables and then starts two unprivileged processes, each with an address-space limit (`prlimit`) and a capability bounding set cut down to what it needs (`NET_BIND_SERVICE` for dnsmasq to bind port 53, nothing at all for the proxy):
   - `dnsmasq` (UID 201): the cage's DNS server. It forwards allowlisted names and sinkholes everything else.
   - `agentcage-egress` (UID 200): the egress proxy, a single static Rust binary. It terminates and inspects TLS, runs the inspector chain, injects and redacts secrets, writes the audit log and the capture file, and hosts the Policy API, the traffic watcher and the protocol relays.

The egress image is `debian:trixie-slim` with `dnsmasq`, `iptables`, `tini` and a few utilities, plus the `agentcage-egress` binary. It contains no interpreter. The host binary carries the egress binary for its own architecture (a macOS arm64 host carries the linux-aarch64 build its VM runs), so the image is built locally from what the host binary embeds; its tag (`localhost/agentcage-egress:<version>-<hash>`) changes whenever the binary or any other input changes.

```
┌─────────────────────────── HOST MACHINE ───────────────────────────────────────────┐
│                                                                                    │
│  ~/.config/agentcage/cages/<name>/                                                 │
│    ├── cage.yaml            (declarative source of truth)                          │
│    ├── proxy-config.yaml    (the subset of cage.yaml the egress reads)             │
│    ├── dns-allowlist.conf   (generated dnsmasq zone directives)                    │
│    └── creds/*.cred         (encrypted secrets: systemd-creds / Keychain)          │
│                                                                                    │
│  ~/.local/share/agentcage/<name>/                                                  │
│    ├── capture/capture.jsonl (request/response capture, placeholders only)         │
│    ├── grants/              (grants.yaml overlay, watcher findings and state)      │
│    └── inspectors/          (custom inspector .wasm files, mounted read-only)      │
│                                                                                    │
│  ┌───────────── Private Bridge Network: <name>-net (Internal=true) ────────────┐   │
│  │                                                                             │   │
│  │   ┌──────────────────────────┐          ┌────────────────────────────────┐  │   │
│  │   │  WORKLOAD SANDBOX (cage) │          │  EGRESS GATEWAY (egress)       │  │   │
│  │   │                          │  DNS/53  │  tini (PID 1) → supervisor     │  │   │
│  │   │  • UID 1000              │─────────▶│   ├── dnsmasq (UID 201)        │  │   │
│  │   │  • capabilities dropped  │          │   │    allowlisted → upstream  │  │   │
│  │   │  • no_new_privileges     │          │   │    other → 198.51.100.1    │  │   │
│  │   │  • read-only rootfs      │  TCP     │   │                            │  │   │
│  │   │  • masks on .git/hooks   │─────────▶│   └── agentcage-egress (200)   │  │   │
│  │   │                          │          │        :8080 forward proxy     │  │   │
│  │   │  Secret placeholders:    │          │        :8443 transparent       │  │   │
│  │   │  agentcage:secret:KEY:…  │          │        :<p>  reverse (inbound) │  │   │
│  │   │                          │          │        inspector chain         │  │   │
│  │   │  CA public certificate:  │          │        secret injection        │  │   │
│  │   │  /certs/agentcage-ca.pem │          │        audit + capture         │  │   │
│  │   └──────────────────────────┘          │        Policy API, watcher,    │  │   │
│  │        default route via egress         │        IMAP/SMTP relays        │  │   │
│  │                                         └───────────────┬────────────────┘  │   │
│  └─────────────────────────────────────────────────────────│───────────────────┘   │
│                                                            │ iptables:             │
│                                                            │  FORWARD policy DROP  │
│                                                            │  IPv6 FORWARD DROP    │
└────────────────────────────────────────────────────────────│───────────────────────┘
                                                             ▼
                                                     INTERNET / UPSTREAM
```

---

## 1. Network Isolation & Routing

### A. The internal bridge (`Internal=true`)
On Linux and inside the Lima VM, agentcage creates a Podman bridge network with `Internal=true`. Podman attaches no NAT gateway to it, so containers on it have **no route to the host or the internet** of their own.

### B. Gateway routing
The workload's default gateway is the egress container. The workload has no `CAP_NET_ADMIN` or `CAP_NET_RAW`, so it cannot change its routes.

### C. Default-deny packet filtering
The supervisor installs the egress's netfilter rules before anything else starts:
- **Default policy**: `iptables -P FORWARD DROP` and `ip6tables -P FORWARD DROP`.
- **Inspected ports**: every port in `ports.tcp.allow` that is not in `ports.tcp.passthrough` (by default 80 and 443) is redirected to the transparent listener, plain HTTP and TLS alike:
  ```bash
  iptables -t nat -A PREROUTING -p tcp --dport 80  -j REDIRECT --to-ports 8443
  iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
  ```
- **Passthrough ports** (`ports.tcp.passthrough`) and `ports.udp.allow` are forwarded at layer 3 and never reach the proxy.
- **ICMP** echo-request is dropped unless `ports.icmp.allow: true`.

On the container and vm backends the cage also gets `HTTP_PROXY`/`HTTPS_PROXY` pointing at the forward proxy (`http://<egress-ip>:8080`), so most clients send `CONNECT` there instead of relying on the redirect. Both paths go through the same pipeline.

---

## 2. DNS Filtering & Sinkholing

### A. Upstream resolution vs. sinkhole
- **Allowlisted names** (the baseline in `domains.allow` plus live runtime grants) are forwarded to the upstream resolvers (`dns_servers`, by default the host's resolvers without loopback stubs like `127.0.0.53`).
- **Every other name** resolves to `198.51.100.1` (TEST-NET-2, RFC 5737).

### B. Why a sinkhole instead of NXDOMAIN
An `NXDOMAIN` makes a client fail with a DNS error that reads like a typo. With the sinkhole the client connects to `198.51.100.1:443`; the connection is redirected to the egress, which reads the real name from the TLS SNI or the `Host` header and answers with a JSON `403` that names the host and the reason. An agent can tell it was refused by policy, and ask for the domain through the [Policy API](policy-api.md).

### C. Anti-evasion
- **IP literals** never match the allowlist: the domain inspector compares names, and an address has no allowed suffix.
- **Encoded private addresses** such as `169-254-169-254.nip.io` or `10.0.0.1.sslip.io` are refused by the Policy API and can never be granted.
- **Runtime grants are DNS-applied inside the egress.** See [Egress-local DNS apply](egress-local-dns-apply.md).

---

## 3. TLS Interception

### A. A CA per cage
Each cage's egress generates its own certificate authority the first time it starts:
- The key is ECDSA P-256 and the subject is `CN=agentcage egress CA (<cage name>)`. It is written to the egress's private CA directory (`/home/acproxy/ca`, backed by that cage's own `<name>-certs` volume) as `ca-key.pem` (mode 0600) and `ca-cert.pem`. On later starts the egress loads that CA and nothing else from the directory.
- The key never leaves that volume: it is not shared with the workload, not copied between cages, not in backups, and it is removed with the cage. `cage create` refuses to reuse a certs volume a failed destroy left behind.
- Leaf certificates are minted per server name from the client's SNI (or the destination address when there is none), signed by the CA and cached. Every leaf carries one ECDSA P-256 key generated at start-up, so the CA key signs certificates and nothing else.
- The public certificate is published as `agentcage-ca.pem` and mounted read-only into the workload at `/certs/agentcage-ca.pem`.
- Environment variables point the common toolchains at it: `SSL_CERT_FILE` (OpenSSL-based tools, Go, uv), `NODE_EXTRA_CA_CERTS` (Node, npm, Bun), `GIT_SSL_CAINFO` (git), `REQUESTS_CA_BUNDLE` (Python `requests`), `CURL_CA_BUNDLE` (curl), `PIP_CERT` (pip), `AWS_CA_BUNDLE` (boto3, the AWS CLI), `CARGO_HTTP_CAINFO` (cargo), `DENO_CERT` (Deno) and `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH` (gRPC). Most of them replace the tool's default roots, so a tool trusts only the cage CA; every intercepted connection is signed by it. A `container.env` entry that sets one of these replaces the default.

Because the CA is per cage and generated in place, an image that copies the CA into its trust store **at build time** has to be rebuilt when the cage's CA changes (a new cage, or a cage whose certs volume was recreated). Copying it at start-up, as the arch/debian/ubuntu scaffolds do, needs nothing.

### B. Upstream TLS
The egress verifies every upstream certificate against the Mozilla root store compiled into the binary (`webpki-roots`), with the hostname checked. There is no option to skip verification. Both sides negotiate HTTP/2 or HTTP/1.1 by ALPN, independently: an HTTP/2 client can reach an HTTP/1.1 upstream and the other way round. Both sides resume TLS sessions, so a client that reconnects to the same name, or the egress reconnecting to a host it talked to recently, skips the full handshake.

### C. Strict SNI ↔ Host matching
To stop domain fronting (an allowlisted name in the SNI, another host in the `Host` header), the egress requires the TLS SNI and the HTTP `Host` to be the same name (case and a trailing dot ignored, the port in `Host` ignored). A mismatch is a `403`.

### D. The peer guard for runtime grants
A host that is reachable **only** because of a runtime grant (no baseline entry covers it) is checked at connect time: the egress resolves it, and if any answer is not a globally routable address (RFC 1918, loopback, link-local, CGNAT, ULA, an IPv4-mapped form of any of these, …) it refuses the connection, writes a `private_peer_blocked` record and refuses that host from then on. The egress connects to exactly the addresses it vetted, so the name cannot re-resolve somewhere else between the check and the connect. Baseline entries are the operator's own and are not checked this way, which is what lets an operator allow a LAN host.

---

## 4. The Egress Proxy

### A. Listeners and protocol detection

| Listener | Port | Used for |
| :-- | :-- | :-- |
| Forward proxy | `<egress-ip>:8080` | `CONNECT host:port` and absolute-form HTTP from clients that honour `HTTP(S)_PROXY`. Targets are limited to the inspected ports; any other port is a `403` and a `blocked` record. |
| Transparent | `:8443` | Everything iptables redirects from an inspected port. The original destination comes from `SO_ORIGINAL_DST`; the upstream is re-targeted to the SNI/`Host` name, not the original IP. |
| Reverse | one per `container.ports` entry | Inbound connections to a port the cage publishes. The client's forwarding headers (`X-Forwarded-*`, `X-Real-IP`, `Forwarded`) are stripped, and an `Origin` header is rewritten to `<scheme>://<Host>` so the workload's own origin check accepts it. The domain inspector does not apply to inbound traffic; the other inspectors do. |

On the transparent listener and inside a `CONNECT` tunnel the egress peeks at the first bytes:
- a TLS `ClientHello` is terminated with a leaf for its SNI, and what is inside is served as HTTP/2 or HTTP/1.1 according to ALPN;
- plain HTTP is served as HTTP/1.1;
- anything else (SSH, a raw TCP protocol) is closed before an upstream socket is opened, with a `tcp_bypass_blocked` record.

**Passthrough.** A name in `domains.passthrough` (and its subdomains) is spliced as raw TCP, with no TLS termination and no inspection, injection or capture. The splice is granted only when the connection's real destination address is one the SNI name resolves to; a client that sends a passthrough name to some other address gets a normal intercepted connection instead.

**Nothing leaves before the decision.** A client's TLS handshake completes and its whole request is read before anything is resolved or connected upstream. A blocked request, a `429` or a Policy API call never opens an upstream socket.

### B. The request pipeline

```
Request (forward, transparent or reverse listener)
   │
   ├─ config changed? reload it (mtime check)
   ├─ Policy API host (agentcage.local)? ──▶ answered in-process
   ├─ SNI ≠ Host ────────────────────────▶ 403
   ├─ per-host rate limit exceeded ──────▶ 429
   ├─ host poisoned by the peer guard ───▶ 403
   ├─ injection policy: a real secret value
   │  heading outside its inject_to ─────▶ block (403)
   │
   ├─ inspector chain (on a worker thread, sees placeholders only)
   │    domain → secrets → body-size → entropy → content-type → custom (wasm)
   │    first block wins ────────────────▶ 403
   │
   ├─ secret injection (placeholder → real value, inject_to hosts only)
   ├─ audit: allowed / flagged
   ▼
Upstream: resolve → peer guard → connect (pooled) → TLS → HTTP/2 or HTTP/1.1
   │       failure ──────────────────────▶ 502 + upstream_error
   ▼
Response
   ├─ custom inspectors that inspect responses (if any) ──▶ 403
   ├─ redaction: every real secret value / minted token → its placeholder
   ├─ capture (both views hold placeholders only)
   ▼
Client
```

CPU-bound work (the inspector chain, injection, redaction of large bodies, the decider call) runs on a bounded pool of blocking workers, so one large body never stalls other connections.

### C. Responses the egress writes itself
Every response the egress generates is JSON in one shape:

```json
{"blocked": true, "reason": "<why>", "host": "<host>", "by": "agentcage"}
```

| Status | `blocked` | When | Audit record |
| :-- | :-- | :-- | :-- |
| `403` | `true` | An inspector blocked the request, SNI ≠ Host, a poisoned host, a forward-proxy port that is not inspected | `blocked` |
| `413` | `true` | The request body is larger than the egress's per-body limit | `blocked` |
| `429` | `true` | The host's token bucket is empty (`rate limit exceeded`) | `blocked` |
| `502` | `false` | The upstream failed: refused, unresolvable, TLS failure, protocol error, a response body over the limit | `upstream_error` |
| `502` | `false` | An internal error on the flow (a body that cannot be decoded, an injection that cannot be applied) | `internal_error` |
| `503` | `false` | The egress is already buffering its whole body budget; retry later | `upstream_error` or `blocked` |

**Fail closed.** No error path lets a request through unfiltered: an internal error is a `502`, a custom inspector that traps or runs out of budget counts as a block, and a config edit that does not load leaves the last good config running (with one `config_reload_failed` record per bad version). If the config fails at boot, the egress refuses every request until a good version lands.

### D. Bodies, streaming and memory
- **Requests are buffered** whole before the pipeline runs, because the inspectors and the injector need the whole body. A body over the per-body limit (`egress.max_body_bytes` in `cage.yaml`, 256 MiB by default) is refused with a `413`. Below that hard limit, the `body-size` inspector blocks bodies over the policy limit (`max_request_body`, 10 MiB by default) with a `403`.
- **Responses are streamed** whenever no rule needs the whole body, which is the normal case (only a custom inspector that declares the response phase, a `Content-Encoding` the egress cannot decode incrementally (`zstd`, stacked encodings) or a capture `max_body_size` of `0` or less forces buffering). A streamed response reaches the client as the upstream sends it: constant memory, no added time to first byte, server-sent events and LLM token streams flow through unchanged.
- **Redaction while streaming.** When the cage has secrets to redact, a streamed body is redacted on the fly, byte for byte what redacting the whole body would produce. A compressed body (`gzip`, `deflate`, `br`) is then decoded and sent identity-encoded, without `Content-Encoding` and `Content-Length`. The redactor holds back only the bytes after the last separator it has seen (a newline, a space, most punctuation), so text and event streams pass with no hold-back; a single run without any separator (a base64 blob, a hex string) is held until it ends, up to 16 MiB, and past that the exchange is aborted rather than relayed unredacted.
- **Mid-stream failures.** If the upstream fails after the response has started, or a streamed body turns out to be corrupt at its end, the client connection is cut: HTTP/1.1 closes the connection, HTTP/2 resets the stream. A client therefore sees a truncated transfer, never a complete-looking one.
- **A process-wide budget.** Every buffered body counts against one budget for the whole egress (`egress.body_budget_bytes`, 1 GiB by default). A body that would exceed it waits up to two seconds for room, then is refused with a `503`; the first 1 MiB of each body is never refused, so small requests keep working while large transfers are throttled. This keeps a burst of large bodies from exhausting the egress's address-space limit and taking down every connection of the cage. That limit (`prlimit --as`, set by the supervisor when the egress starts) is 2 GiB, or the budget plus 1 GiB when the budget is raised past 1 GiB; both settings apply on a config reload, except that a budget raised past what the running egress's limit leaves room for is held at that room until the egress restarts.

### E. HTTP details
- HTTP/1.1 header case, order and duplicates are kept on the wire in both directions; `Content-Length` and chunked framing are re-validated against request smuggling.
- HTTP/2 is spoken on both sides when both ends offer it. Upstream connections are pooled across client connections (idle HTTP/1.1 connections and shared HTTP/2 sessions), and a pooled connection is reused only for a request that would have opened an identical one, after the peer guard has re-approved the address it reached.
- WebSockets are relayed message by message. Every complete text or binary message goes through the injection policy, the inspector chain and redaction like a request or response body; a blocked message is dropped.
- Upstream names are resolved with `getaddrinfo` on every connection, with no cache, so `/etc/hosts` and DNS changes take effect at once.

### F. Secret injection and redaction
The cage only ever holds placeholders (`agentcage:secret:<NAME>:<32 hex>`). On a request to a host in a rule's `inject_to`, the egress swaps the placeholder for the real value: by default only in credential-bearing headers (a name containing `auth`, `key` or `token`, or listed in `inject_headers`), including inside `Authorization: Basic`; with `inject_body: true` also in the URL, every header and the body. A rewritten body is sent identity-encoded with a corrected `Content-Length`.

In the other direction every real value, and every token a transform minted that may still be live, becomes its placeholder again: in responses, in WebSocket messages, in the capture file and in every audit record. Redaction also catches each value in its percent-encoded, JSON-escaped and base64 forms and writes the placeholder in the same encoding. Before anything is rewritten, a request that carries a real value to a host outside its rule's `inject_to` is blocked.

### G. Audit and capture
Every decision is one JSON line, written to the egress's stderr (read by the host through journald or `podman logs`), to `/var/log/agentcage/audit.jsonl` until it reaches 16 MiB (the apple-container backend reads this file), and to the traffic watcher's in-memory ring. HTTP decisions carry `ts, direction, method, host, port, path, url, decision, reason` and the inspectors' verdicts; other records carry a `kind`: `tcp_bypass_blocked`, `private_peer_blocked`, `upstream_error`, `internal_error`, `config_reload_failed`, `policy_*`, `watcher_*`, `relay_*`, `imap_*`, `smtp_*`. Allowed requests are logged only with `logging.allowed_requests: true`, except that one that injected or redacted a secret is always logged. `agentcage cage audit` reads all of them.

With `capture.enable_har: true` the egress writes one line per flow to `capture.jsonl` (rotated to `capture.jsonl.1` at `capture.max_file_size`), which `agentcage cage har` turns into HAR. The request is recorded with placeholders and the response after redaction, so the file never holds a real secret value or a minted token.

---

## 5. Units & Supervision

### A. Linux quadlets
On Linux, agentcage writes systemd user quadlets under `~/.config/containers/systemd/`:
- `<name>-net.network`: the bridge network, `Internal=true`.
- `<name>-egress.container`: the egress, with `NET_ADMIN` for its iptables setup (and the few capabilities the supervisor needs to start its children, which drop them: dnsmasq keeps only `NET_BIND_SERVICE`, `agentcage-egress` none), the proxy config, DNS allowlist, CA volumes, capture and grants directories, staged secrets and (when used) the custom inspector directory mounted in.
- `<name>-cage.container`: the workload. Its `ExecStartPre` waits for the egress to publish `agentcage-ca.pem`, which happens only after the proxy is listening.

systemd handles restarts, ordering (`After=<name>-egress.service`) and logging (`journalctl`).

### B. Readiness
The supervisor starts dnsmasq, then `agentcage-egress`. The binary loads (or, on first start, generates) the CA, binds its listeners, and only then writes the public certificate. The supervisor waits for both the certificate and the `:8443` listener, publishes the certificate to the public-certs volume, and touches `/var/log/agentcage/ready`. From then on it checks both children every second and exits if either dies, so the runtime restarts the egress.

### C. macOS
- **Apple Container (`apple-container`)**: two microVMs per cage, `<name>-egress` (the same egress image) and `<name>-cage`, supervised by agentcage and launchd.
- **Lima VM (`vm`)**: a dedicated Lima VM that runs rootless Podman and the same quadlets inside.

---

## 6. Live-Reload Seams

| Change | Command | Mechanism | Restart? |
| :--- | :--- | :--- | :--- |
| **Baseline domains** | `agentcage domain add/rm` | Rewrites `cage.yaml`, `proxy-config.yaml` and `dns-allowlist.conf`; the egress picks up the config by its mtime, dnsmasq re-reads its servers file on `SIGHUP`. | No |
| **Runtime grants** | Policy API `POST /v1/allowlist/requests` | The egress grants in memory, persists `grants.yaml` in the grants directory and publishes the granted names; the supervisor re-renders dnsmasq's servers file within a second. | No |
| **Secret values** | `agentcage secret set` | Stages the new value in the egress's secrets directory and touches the proxy config, so the egress re-resolves every secret. | No |
| **Policy and inspectors** | `agentcage cage edit` | Rewrites `proxy-config.yaml` in place. The egress checks its mtime every second and at the start of every request, and swaps the new config in atomically; in-flight requests finish on the config they started with. Relays and capture follow the new config too. | No |
| **Image, mounts, plugins** | `agentcage cage update` | Regenerates the units (and rebuilds images) and restarts what changed. | Yes |

---

## Next Steps

- **[Isolation Backends](isolation-backends.md)** — Compare `container`, `apple-container`, and `vm`.
- **[Security Model](security-model.md)** — The defense-in-depth layers and residual risks.
- **[Policy API Architecture](policy-api.md)** — The decider agent and runtime grants.
