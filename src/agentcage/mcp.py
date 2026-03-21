"""MCP (Model Context Protocol) server support.

Provides a registry of well-known MCP servers and helpers for resolving
server names to their configuration (npm package, required domains, etc.).

MCP servers run as processes inside the agent container — agentcage's job
is to install the packages and add their required domains to the allowlist.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# npm package names must match: optional @scope/name with alphanumeric, -, .
_VALID_NPM_PACKAGE = re.compile(
    r'^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$'
)


@dataclass
class McpServerConfig:
    """Configuration for a single MCP server."""

    name: str = ""
    package: str = ""  # npm package name (e.g. "@modelcontextprotocol/server-github")
    command: list[str] = field(default_factory=list)  # override command
    env: dict[str, str] = field(default_factory=dict)  # server-specific env vars
    domains: list[str] = field(default_factory=list)  # additional domains needed


# Well-known MCP servers that can be referenced by short name.
MCP_REGISTRY: dict[str, McpServerConfig] = {
    "github": McpServerConfig(
        name="github",
        package="@modelcontextprotocol/server-github",
        domains=["api.github.com", "github.com"],
    ),
    "filesystem": McpServerConfig(
        name="filesystem",
        package="@modelcontextprotocol/server-filesystem",
    ),
    "postgres": McpServerConfig(
        name="postgres",
        package="@modelcontextprotocol/server-postgres",
    ),
    "memory": McpServerConfig(
        name="memory",
        package="@modelcontextprotocol/server-memory",
    ),
    "puppeteer": McpServerConfig(
        name="puppeteer",
        package="@modelcontextprotocol/server-puppeteer",
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

    Returns a new list with any missing domains appended.

    Only call this when the cage is in allowlist mode — it always merges
    domains regardless of list contents.
    """
    if not servers:
        return list(allow_list)
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


def _validate_package_name(package: str) -> None:
    """Raise ValueError if *package* is not a valid npm package name.

    This prevents shell injection via crafted package names in
    Containerfile RUN lines.
    """
    if not _VALID_NPM_PACKAGE.match(package):
        raise ValueError(
            f"Invalid npm package name: {package!r}. "
            f"Package names must match the npm naming rules."
        )


def extend_containerfile(containerfile_path: str, servers: list[McpServerConfig]) -> None:
    """Append ``npm install -g`` lines for MCP server packages to a Containerfile.

    Validates package names before writing to prevent injection.
    The install runs as root and then restores the previous USER directive
    (or omits the trailing USER line if no prior USER was set).
    """
    packages = mcp_npm_packages(servers)
    if not packages:
        return

    for pkg in packages:
        _validate_package_name(pkg)

    # Detect the last USER directive in the existing Containerfile so we
    # can restore it after running npm install as root.
    last_user = None
    with open(containerfile_path) as f:
        for line in f:
            stripped = line.strip()
            if stripped.upper().startswith("USER "):
                last_user = stripped.split(None, 1)[1]

    pkg_str = " ".join(packages)
    with open(containerfile_path, "a") as f:
        f.write(f"\n# MCP servers (added by agentcage)\n")
        f.write(f"USER root\n")
        f.write(f"RUN npm install -g {pkg_str}\n")
        if last_user and last_user != "root":
            f.write(f"USER {last_user}\n")
