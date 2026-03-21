"""MCP (Model Context Protocol) server support.

Provides a registry of well-known MCP servers and helpers for resolving
server names to their configuration (npm package, required domains, etc.).

MCP servers run as processes inside the agent container — agentcage's job
is to install the packages and add their required domains to the allowlist.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class McpServerConfig:
    """Configuration for a single MCP server."""

    name: str = ""
    package: str = ""  # npm package name (e.g. "@anthropic/mcp-server-github")
    command: list[str] = field(default_factory=list)  # override command
    env: dict[str, str] = field(default_factory=dict)  # server-specific env vars
    domains: list[str] = field(default_factory=list)  # additional domains needed


# Well-known MCP servers that can be referenced by short name.
MCP_REGISTRY: dict[str, McpServerConfig] = {
    "github": McpServerConfig(
        name="github",
        package="@anthropic/mcp-server-github",
        domains=["api.github.com", "github.com"],
    ),
    "filesystem": McpServerConfig(
        name="filesystem",
        package="@anthropic/mcp-server-filesystem",
    ),
    "postgres": McpServerConfig(
        name="postgres",
        package="@anthropic/mcp-server-postgres",
    ),
    "memory": McpServerConfig(
        name="memory",
        package="@anthropic/mcp-server-memory",
    ),
    "fetch": McpServerConfig(
        name="fetch",
        package="@anthropic/mcp-server-fetch",
    ),
    "puppeteer": McpServerConfig(
        name="puppeteer",
        package="@anthropic/mcp-server-puppeteer",
    ),
}


def resolve_mcp_server(name: str) -> McpServerConfig:
    """Look up an MCP server by short name.

    Raises ``ValueError`` if the name is not in the registry.
    """
    if name in MCP_REGISTRY:
        # Return a copy so callers can modify without affecting the registry
        src = MCP_REGISTRY[name]
        return McpServerConfig(
            name=src.name,
            package=src.package,
            command=list(src.command),
            env=dict(src.env),
            domains=list(src.domains),
        )
    available = ", ".join(sorted(MCP_REGISTRY))
    raise ValueError(
        f"Unknown MCP server '{name}'. "
        f"Available: {available}. "
        f"Use mcp_servers in cage.yaml for custom servers."
    )


def merge_mcp_domains(
    allow_list: list[str],
    servers: list[McpServerConfig],
) -> list[str]:
    """Merge MCP server domains into an existing domain allow list.

    Returns a new list with any missing domains appended. If the allow
    list is empty (not in allowlist mode), returns it unchanged.
    """
    if not allow_list and not servers:
        return allow_list
    merged = list(allow_list)
    existing = set(merged)
    for server in servers:
        for domain in server.domains:
            if domain not in existing:
                merged.append(domain)
                existing.add(domain)
    return merged


def mcp_npm_packages(servers: list[McpServerConfig]) -> list[str]:
    """Return the list of npm packages to install for the given servers."""
    return [s.package for s in servers if s.package]
