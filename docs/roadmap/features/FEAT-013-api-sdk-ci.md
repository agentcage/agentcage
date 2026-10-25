# FEAT-013: Local API, SDKs and CI integration

| | |
| :--- | :--- |
| **Status** | Proposed |
| **Priority** | P2 |
| **Phase** | 5 |
| **Depends on** | [FEAT-006](FEAT-006-cli-automation.md) |
| **Related** | [FEAT-012](FEAT-012-mcp-gateway.md), [FEAT-018](FEAT-018-team-governance.md) |

## Problem

agentcage can only be driven through a human CLI. There is no supported way
for a test harness, web UI, CI job or multi-agent orchestrator to create a
cage, run a command, stream events and tear it down. Shelling out and parsing
text is the only option.

## Proposal

### `agentcage serve`

A local-only control API:

- Unix socket by default; optional loopback TCP with a bearer token.
- No remote bind by default; remote access is a separate decision.
- Endpoints:
  - `POST /v1/cages` create/run
  - `GET /v1/cages` list
  - `GET /v1/cages/{name}` status/show
  - `POST /v1/cages/{name}/exec` run a command
  - `GET /v1/cages/{name}/events` stream SSE/JSONL
  - `POST /v1/cages/{name}/stop|destroy`
  - `GET /v1/cages/{name}/audit` and `/har`
- Idempotency keys for create/exec; stable error envelope.
- OpenAPI schema is the source of truth for SDKs.
- Auth: per-user token, file mode 0600; no token in argv or logs.
- The API must not expose raw secret values or arbitrary host paths.

### SDKs

- Python and TypeScript clients generated or hand-written against the OpenAPI
  schema.
- Convenience methods: `create`, `run`, `exec`, `events`, `destroy`,
  `audit`, `har`.
- Async/await support in both; timeouts and cancellation.
- Do not wrap the whole CLI; expose the lifecycle contract.

### GitHub Action

A composite action that:

1. installs a pinned, checksum-verified release;
2. creates a cage with a supplied `cage.yaml`;
3. runs a command or agent;
4. uploads audit/HAR/timing artifacts;
5. destroys the cage with `--rm` even on failure.

Document required runners (Linux rootless Podman/VM) and reduced isolation in
CI.

## Implementation

- Add `cli/serve.rs` and a small HTTP stack; reuse JSON types from FEAT-006.
- Use a Unix socket with peer credentials where possible; if TCP, require
  bearer token and bind loopback.
- Serialize lifecycle operations per cage to avoid create/destroy races.
- Stream events from existing files; do not duplicate the audit writer.
- Generate SDKs from OpenAPI or keep a single hand-written source and test
  compatibility.
- The GitHub Action should cache only immutable images; never cache secrets.

## Acceptance criteria

- [ ] `agentcage serve` exposes the documented endpoints on a Unix socket.
- [ ] A Python SDK can create, exec, stream and destroy a cage in CI.
- [ ] A TypeScript SDK passes the same contract tests.
- [ ] The API rejects missing/invalid tokens and never prints them.
- [ ] The GitHub Action uploads artifacts and destroys on failure.
- [ ] OpenAPI schema and SDK tests are in the repository.

## Tests

- API contract tests against a fake backend.
- SDK integration against the real CLI in e2e.
- Auth/negative tests.
- GitHub Action smoke test on a supported runner.

## Risks

- A local API expands the attack surface; keep it opt-in and local-only.
- SDKs are a compatibility burden; version the API and publish deprecation
  policy.
- CI runners may not support rootless Podman/KVM; document fallbacks.
EOF