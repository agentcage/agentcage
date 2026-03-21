"""Tests for MCP (Model Context Protocol) server support."""

import textwrap

import pytest

from agentcage.mcp import (
    MCP_REGISTRY,
    McpServerConfig,
    merge_mcp_domains,
    mcp_npm_packages,
    resolve_mcp_server,
)
from agentcage.config import load_config


class TestMcpServerConfig:
    def test_defaults(self):
        cfg = McpServerConfig()
        assert cfg.name == ""
        assert cfg.package == ""
        assert cfg.command == []
        assert cfg.env == {}
        assert cfg.domains == []

    def test_all_fields(self):
        cfg = McpServerConfig(
            name="github",
            package="@anthropic/mcp-server-github",
            command=["mcp-server-github"],
            env={"GITHUB_TOKEN": "tok"},
            domains=["api.github.com", "github.com"],
        )
        assert cfg.name == "github"
        assert cfg.package == "@anthropic/mcp-server-github"
        assert cfg.command == ["mcp-server-github"]
        assert cfg.env == {"GITHUB_TOKEN": "tok"}
        assert cfg.domains == ["api.github.com", "github.com"]


class TestMcpRegistry:
    def test_registry_has_common_servers(self):
        assert "github" in MCP_REGISTRY
        assert "filesystem" in MCP_REGISTRY
        assert "postgres" in MCP_REGISTRY
        assert "memory" in MCP_REGISTRY

    def test_registry_entries_have_packages(self):
        for name, cfg in MCP_REGISTRY.items():
            assert cfg.name == name
            assert cfg.package, f"Registry entry '{name}' missing package"

    def test_github_has_domains(self):
        gh = MCP_REGISTRY["github"]
        assert "api.github.com" in gh.domains
        assert "github.com" in gh.domains


class TestResolveMcpServer:
    def test_resolve_known_server(self):
        server = resolve_mcp_server("github")
        assert server.name == "github"
        assert server.package == "@anthropic/mcp-server-github"
        assert "api.github.com" in server.domains

    def test_resolve_returns_copy(self):
        s1 = resolve_mcp_server("github")
        s2 = resolve_mcp_server("github")
        s1.domains.append("extra.com")
        assert "extra.com" not in s2.domains

    def test_resolve_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown MCP server 'nonexistent'"):
            resolve_mcp_server("nonexistent")

    def test_error_lists_available(self):
        with pytest.raises(ValueError, match="Available:"):
            resolve_mcp_server("nonexistent")


class TestMergeMcpDomains:
    def test_empty_lists(self):
        result = merge_mcp_domains([], [])
        assert result == []

    def test_no_servers(self):
        allow = ["anthropic.com"]
        result = merge_mcp_domains(allow, [])
        assert result == ["anthropic.com"]

    def test_adds_new_domains(self):
        allow = ["anthropic.com"]
        servers = [
            McpServerConfig(name="github", domains=["api.github.com", "github.com"]),
        ]
        result = merge_mcp_domains(allow, servers)
        assert "anthropic.com" in result
        assert "api.github.com" in result
        assert "github.com" in result

    def test_no_duplicates(self):
        allow = ["github.com", "anthropic.com"]
        servers = [
            McpServerConfig(name="github", domains=["github.com", "api.github.com"]),
        ]
        result = merge_mcp_domains(allow, servers)
        assert result.count("github.com") == 1

    def test_multiple_servers(self):
        allow = ["anthropic.com"]
        servers = [
            McpServerConfig(name="github", domains=["github.com"]),
            McpServerConfig(name="custom", domains=["custom.api.com"]),
        ]
        result = merge_mcp_domains(allow, servers)
        assert len(result) == 3
        assert "github.com" in result
        assert "custom.api.com" in result

    def test_servers_without_domains(self):
        allow = ["anthropic.com"]
        servers = [McpServerConfig(name="filesystem")]
        result = merge_mcp_domains(allow, servers)
        assert result == ["anthropic.com"]


class TestMcpNpmPackages:
    def test_empty(self):
        assert mcp_npm_packages([]) == []

    def test_extracts_packages(self):
        servers = [
            McpServerConfig(name="github", package="@anthropic/mcp-server-github"),
            McpServerConfig(name="fs", package="@anthropic/mcp-server-filesystem"),
        ]
        assert mcp_npm_packages(servers) == [
            "@anthropic/mcp-server-github",
            "@anthropic/mcp-server-filesystem",
        ]

    def test_skips_empty_package(self):
        servers = [
            McpServerConfig(name="custom"),
            McpServerConfig(name="github", package="@anthropic/mcp-server-github"),
        ]
        assert mcp_npm_packages(servers) == ["@anthropic/mcp-server-github"]


class TestMcpConfigParsing:
    def test_parse_mcp_servers_from_yaml(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/test:latest
            mcp_servers:
              - name: github
                package: "@anthropic/mcp-server-github"
                domains:
                  - api.github.com
                  - github.com
              - name: filesystem
                package: "@anthropic/mcp-server-filesystem"
        """))
        cfg = load_config(str(p))
        assert len(cfg.mcp_servers) == 2
        assert cfg.mcp_servers[0].name == "github"
        assert cfg.mcp_servers[0].package == "@anthropic/mcp-server-github"
        assert cfg.mcp_servers[0].domains == ["api.github.com", "github.com"]
        assert cfg.mcp_servers[1].name == "filesystem"
        assert cfg.mcp_servers[1].package == "@anthropic/mcp-server-filesystem"
        assert cfg.mcp_servers[1].domains == []

    def test_parse_mcp_with_env(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/test:latest
            mcp_servers:
              - name: github
                package: "@anthropic/mcp-server-github"
                env:
                  GITHUB_TOKEN: "tok123"
                domains:
                  - github.com
        """))
        cfg = load_config(str(p))
        assert cfg.mcp_servers[0].env == {"GITHUB_TOKEN": "tok123"}

    def test_parse_mcp_with_command(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/test:latest
            mcp_servers:
              - name: custom
                package: "custom-mcp"
                command: ["node", "server.js"]
        """))
        cfg = load_config(str(p))
        assert cfg.mcp_servers[0].command == ["node", "server.js"]

    def test_no_mcp_servers_default(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/test:latest
        """))
        cfg = load_config(str(p))
        assert cfg.mcp_servers == []

    def test_empty_mcp_servers(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/test:latest
            mcp_servers: []
        """))
        cfg = load_config(str(p))
        assert cfg.mcp_servers == []


class TestMcpDomainMergingInQuadlets:
    """Verify MCP domains are merged in the quadlet DNS allowlist."""

    def test_mcp_domains_in_effective_allowlist(self, tmp_path):
        from agentcage.quadlets import _effective_dns_allowlist

        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/test:latest
            domains:
              allow:
                - anthropic.com
            mcp_servers:
              - name: github
                package: "@anthropic/mcp-server-github"
                domains:
                  - api.github.com
                  - github.com
        """))
        cfg = load_config(str(p))
        result = _effective_dns_allowlist(cfg)
        assert "anthropic.com" in result
        assert "api.github.com" in result
        assert "github.com" in result

    def test_no_mcp_domains_without_allowlist(self, tmp_path):
        from agentcage.quadlets import _effective_dns_allowlist

        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/test:latest
            mcp_servers:
              - name: github
                package: "@anthropic/mcp-server-github"
                domains:
                  - github.com
        """))
        cfg = load_config(str(p))
        # No domains.allow → not in allowlist mode → returns empty
        result = _effective_dns_allowlist(cfg)
        assert result == []
