<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Security model

agentcage is a defense-in-depth proxy sandbox. It exists to reduce the risk of data exfiltration from an AI agent — both deliberate exfiltration by a compromised agent and accidental leakage through legitimate-looking requests. Read this when deciding whether agentcage's protections match your threat model.

## Threat model

The primary threat is an AI agent exfiltrating secrets, source, or context via HTTP requests.

### In scope

- HTTP/HTTPS exfiltration — secrets or sensitive data in request bodies, headers, or URLs
- Accidental secret leakage in outbound requests
- Unauthorized API calls to non-allowlisted domains
- Encoded payload smuggling — base64 or compressed blobs hidden in normal-looking requests
- WebSocket exfiltration after handshake

### Out of scope

- Non-HTTP protocols (blocked by network isolation, but not inspected)
- DNS exfiltration through allowlisted apex domains (see [Known limitations](#known-limitations))
- Container or kernel escapes in `container` mode (shared kernel; `vm` and `apple-container` defend against this)
- Side-channel attacks and timing-based leaks
- Multi-request evasion — splitting secrets across many small requests
- Confused-deputy attacks through legitimate requests to allowed domains

### Threats by isolation mode

| Threat | container | vm | apple-container |
|---|---|---|---|
| HTTP/HTTPS exfiltration | Defended | Defended | Defended |
| Secret leakage | Defended | Defended | Defended |
| Unauthorized API calls | Defended | Defended | Defended |
| DNS exfiltration | Partial | Partial | Partial |
| Container/runtime escape | **Out of scope** | Defended | Defended |
| Kernel exploit | **Out of scope** | Defended | Defended |
| Side-channel attacks | Out of scope | Out of scope | Out of scope |

For the backend trade-offs, see [Isolation modes](isolation-modes.md).

## Defense layers

agentcage applies overlapping defenses. Each one stands alone; none is the only line.

1. **Network isolation.** The cage has no internet gateway. The only path out is the egress sibling; inbound published ports also flow through the inspector chain.
2. **Domain filtering.** Allowlist or blocklist controls which hosts the agent reaches; non-matching requests get a 403. See [Domains](../reference/domains.md).
3. **DNS filtering.** In allowlist mode, queries for non-allowlisted apexes resolve to a placeholder IP and non-A query types are refused.
4. **Secret injection.** The cage holds placeholders. The proxy substitutes real values on the wire and redacts them on inbound responses. A real secret value appearing in an outbound request is blocked. Transforms let credentials never enter the cage at all. See [Secret injection](../reference/secret-injection.md).
5. **Payload inspection.** Inspectors scan every request (and WebSocket frame after handshake) for known secret patterns, high-entropy bodies, content-type mismatches, base64 blobs, and oversized payloads. Custom inspectors extend the chain. See [Inspectors](../reference/inspectors.md).
6. **Rate limiting.** Per-host token bucket bounds request flooding and timing-based evasion.
7. **Audit logging.** Blocked and flagged decisions are written as structured JSON lines. Allowed requests are opt-in.

## Fail-closed design

If the egress sibling goes down, the cage gets connection errors — not unfiltered internet access. The cage has no internet gateway, so a proxy failure means no connectivity at all. Generated units restart on failure to recover from transient crashes.

## Container hardening

By default, the cage runs with a read-only root filesystem, all Linux capabilities dropped, and no-new-privileges. The egress runs as a non-root user. Nested containers (`nested_containers: true`, `container` mode only) relax several of these defaults to enable podman-in-podman; network-level protections still apply, and inner-container traffic is forced through the same egress filter.

## Workspace mount hardening

Scaffolds bind-mount the project directory at `/workspace:rw` so the agent can
edit your code. That directory also contains host-trusted, executable-on-the-host
configuration — most dangerously `.git/hooks/`. A malicious in-cage agent that
writes `/workspace/.git/hooks/pre-commit` would have that script run as **you**,
on the **host**, the next time you `git commit` outside any cage — a full
cage→host pivot via an everyday action ([#170]).

agentcage masks `/workspace/.git/hooks` with an ephemeral tmpfs (a bare
`--tmpfs` on the apple-container backend). In-cage writes there land in the
overlay and vanish when the cage stops; your real `.git/hooks` is never touched.
The mask is applied **only when `/workspace` is a host bind that already
contains `.git/hooks`** — masking an absent path would make the runtime create
the mountpoint *through* the bind, littering non-repo projects with a stray
`.git/` (see `docs/spikes/2026-06-tmpfs-workspace-mask-spike.md`). It is enforced
across all isolation modes and is on by default; set `git_hooks_mask: false` per
cage to opt out (then cage-side hook edits persist to the host repo). One
consequence: cage-side `git commit` no longer fires host-installed hooks (e.g. a
`pre-commit` framework), which most agents don't rely on.

This closes the most direct pivot, not the whole class. Other in-workspace
surfaces an agent can still write — `.git/config` (`core.sshCommand`,
`remote.origin.url`), `.gitattributes` smudge/clean filters, project-local agent
config such as `.claude/settings.json` ([#173]), `Makefile` / `package.json`
lifecycle scripts — remain the operator's responsibility to review before
running them on the host.

[#170]: https://github.com/agentcage/agentcage/issues/170
[#173]: https://github.com/agentcage/agentcage/issues/173

## Supply chain

Container base images are pinned by digest. Python runtime deps are minimal. Custom inspector paths and bind-mount paths are validated. Cage names are pattern-checked before they reach generated unit files. Templates render in a sandboxed environment.

## OWASP top 10 for agentic applications (2026)

| Risk | Coverage |
|---|---|
| ASI01 Agent Goal Hijack | Out of scope — agentcage inspects traffic, not intent |
| ASI02 Tool Misuse | Strong — domain allowlist + DNS + WebSocket inspection |
| ASI03 Identity/Privilege Abuse | Strong — agent never holds real secrets |
| ASI04 Supply Chain | Strong — pinned images, restricted inspector paths |
| ASI05 Code Execution | Strong — read-only root, dropped caps, no-new-privileges |
| ASI08 Cascading Failures | Strong — fail-closed, restart-on-failure, rate limiting |
| ASI09 Human Trust | Strong — persistent structured audit log |
| ASI10 Rogue Agents | Strong — isolation + multi-layer inspection |

ASI06 (Memory Poisoning) and ASI07 (Inter-Agent Comms) don't apply to agentcage's single-agent network-inspection scope.

## Known limitations

**Multi-request evasion.** Agents can split a secret across many requests to defeat regex matching. Entropy and content-type inspectors catch some encoded exfiltration but not all splitting strategies.

**Exfiltration through allowed domains.** Data can be smuggled inside requests to allowed endpoints — issue titles, search queries, package metadata. Subdomain labels under an allowlisted apex (e.g. `<encoded>.cdn.jsdelivr.net`) are also recursively resolved upstream, giving low-bandwidth DNS covert channels. Audit logs and rate limiting bound these channels.

**Supply chain poisoning.** Agents can install packages from allowlisted registries. Container hardening limits blast radius but doesn't prevent access to the agent's own workspace. Consider pre-approved package lists for high-security deployments.

**Shared kernel (`container` mode only).** A kernel or runtime CVE bypasses all container-level protections. Use `vm` or `apple-container` to eliminate this. See [Isolation modes](isolation-modes.md).

## Traffic capture and HAR export

When capture is enabled, the proxy records decrypted request/response bodies; `cage har` exports them. See [Capture](../reference/capture.md).

- **Outbound captures contain real secrets** — after injection, the wire view holds real API keys, tokens, and cookies. The CLI defaults to the inbound (placeholder) view and warns when you opt into outbound; treat outbound HAR files with the same controls as the secrets themselves.
- **Inbound captures may contain sensitive content** — PII, user queries, model responses. The Okta breach (2023) showed how HAR files uploaded to support portals led to session hijacking. Handle them under the same data governance as the agent's operational data.

## Secret backend trust boundaries

Secrets can come from environment variables, `systemd-creds` (encrypted at rest, bound to the machine), or a `cmd:` shell hook. The `cmd:` source executes with the privileges of the user invoking agentcage — review any `source: "cmd:..."` entries in a `cage.yaml` sourced from an untrusted location before running `cage create`.

`systemd-creds` blobs are bound to the host machine. A motherboard swap, TPM reset, or BIOS update may render them unrecoverable; use `cage backup --include-secrets` for portable backups.

## Reporting security issues

Report security vulnerabilities via email to **security@agentcage.ai**. Do not open a public GitHub issue. See [SECURITY.md](../../SECURITY.md).

## Related

- [Architecture](architecture.md) — topology and inspector chain
- [Isolation modes](isolation-modes.md) — backend trade-offs
- [Secret injection](../reference/secret-injection.md), [Inspectors](../reference/inspectors.md), [Ports](../reference/ports.md)
