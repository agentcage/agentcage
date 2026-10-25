# FEAT-012: MCP gateway and MCP server

| | |
| :--- | :--- |
| **Status** | Proposed |
| **Priority** | P1 |
| **Phase** | 4 |
| **Depends on** | Security design spike |
| **Related** | [FEAT-013](FEAT-013-api-sdk-ci.md), [FEAT-014](FEAT-014-filesystem-and-socket-policy.md) |

## Problem

MCP servers are becoming the way agents use tools, credentials and external
services. They often run on the host with broad filesystem, network and
credential access. agentcage currently controls HTTP egress but not MCP tool
calls, and an agent cannot use a host MCP server without opening a direct
path out of the cage.

## Proposal

### Gateway

```yaml
mcp:
  servers:
    github:
      transport: stdio
      command: ["npx", "-y", "@modelcontextprotocol/server-github"]
      secrets: [GITHUB_TOKEN]
      allowed_tools: ["search_repositories", "get_file_contents"]
```

```text
agentcage mcp add NAME --url URL
agentcage mcp add NAME --command CMD
agentcage mcp ls
agentcage mcp rm NAME
agentcage mcp load NAME --cage CAGE
```

- Host-managed registry, one gateway endpoint for the cage.
- OAuth and secret injection happen outside the cage; the cage sees tool
  results, not the raw credential.
- Per-server and per-tool allowlists; every call is audited.
- Unknown tools fail closed; tool descriptions are treated as untrusted.
- The gateway must not give the cage a raw host socket or host shell.

### MCP server for agentcage

`agentcage mcp serve` exposes cage lifecycle/audit queries as MCP tools:

- list cages, create/run a cage, exec a command, stop/destroy;
- read audit summary, blocked hosts and watcher findings;
- request a domain grant on the host side.

This lets an orchestrator use agentcage as its sandbox layer.

## Design spike (required before code)

1. Where do stdio MCP servers run: host broker, egress sidecar, or a dedicated
   sandbox? Each has a different trust boundary.
2. How are OAuth tokens stored/refreshed and kept out of the cage?
3. How are tool names/descriptions validated against prompt injection?
4. How does the gateway authenticate the cage connection?
5. How are tool calls represented in the audit/HAR schema?
6. What is the failure mode when the gateway or server dies?

Security review must approve the design before implementation.

## Acceptance criteria

- [ ] A design document covers the six questions above.
- [ ] A single-server prototype can expose one tool to a cage with a tool
      allowlist and audit.
- [ ] A denied tool call is clear and fail-closed.
- [ ] No raw host socket or credential is reachable from the cage.
- [ ] `agentcage mcp serve` can create and destroy a cage in an integration
      test.

## Tests

- MCP protocol fixture tests.
- Tool allowlist/deny tests.
- OAuth redaction tests.
- Audit schema snapshot.
- e2e with one mock MCP server.

## Risks

- MCP is a new security boundary; do not ship without a threat model.
- Tool descriptions are prompt-injection vectors.
- Host stdio servers may need host filesystem access; scope carefully.
