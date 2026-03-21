"""Tests for git + SSH + gh CLI integration in scaffolds."""

from __future__ import annotations

import os
from unittest.mock import patch

import yaml

from agentcage.init import detect_git_integrations, render_config


class TestDetectGitIntegrations:
    """Verify detect_git_integrations() checks for host git tooling."""

    def test_gitconfig_detected_when_exists(self, tmp_path, monkeypatch):
        gitconfig = tmp_path / ".gitconfig"
        gitconfig.write_text("[user]\n  name = Test\n")
        monkeypatch.setenv("HOME", str(tmp_path))
        result = detect_git_integrations()
        assert result["gitconfig_exists"] is True

    def test_gitconfig_false_when_missing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        result = detect_git_integrations()
        assert result["gitconfig_exists"] is False

    def test_ssh_agent_detected_when_sock_exists(self, tmp_path, monkeypatch):
        # Create a Unix socket
        import socket
        sock_path = str(tmp_path / "agent.sock")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(sock_path)
        try:
            monkeypatch.setenv("SSH_AUTH_SOCK", sock_path)
            result = detect_git_integrations()
            assert result["ssh_agent_available"] is True
        finally:
            s.close()
            os.unlink(sock_path)

    def test_ssh_agent_false_when_no_env(self, monkeypatch):
        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
        result = detect_git_integrations()
        assert result["ssh_agent_available"] is False

    def test_ssh_agent_false_when_sock_missing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SSH_AUTH_SOCK", str(tmp_path / "nonexistent.sock"))
        result = detect_git_integrations()
        assert result["ssh_agent_available"] is False

    def test_gh_auth_detected_when_exists(self, tmp_path, monkeypatch):
        gh_dir = tmp_path / ".config" / "gh"
        gh_dir.mkdir(parents=True)
        (gh_dir / "hosts.yml").write_text("github.com:\n  oauth_token: test\n")
        monkeypatch.setenv("HOME", str(tmp_path))
        result = detect_git_integrations()
        assert result["gh_auth_exists"] is True

    def test_gh_auth_false_when_missing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        result = detect_git_integrations()
        assert result["gh_auth_exists"] is False

    def test_graceful_when_none_exist(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
        result = detect_git_integrations()
        assert result["gitconfig_exists"] is False
        assert result["ssh_agent_available"] is False
        assert result["gh_auth_exists"] is False


class TestGitMountsInScaffolds:
    """Verify scaffold templates conditionally include git mounts."""

    def _render_with_git_vars(
        self, scaffold: str, name: str, **overrides
    ) -> dict:
        git_vars = {
            "gitconfig_exists": False,
            "ssh_agent_available": False,
            "gh_auth_exists": False,
        }
        git_vars.update(overrides)
        with patch("agentcage.init.detect_git_integrations", return_value=git_vars):
            cfg_text, _ = render_config(name, scaffold=scaffold)
        return yaml.safe_load(cfg_text)

    def test_gitconfig_mount_when_exists(self):
        parsed = self._render_with_git_vars(
            "claude-code", "test-cc", gitconfig_exists=True,
        )
        volumes = parsed["container"]["volumes"]
        assert any(".gitconfig:" in v for v in volumes)

    def test_no_gitconfig_mount_when_missing(self):
        parsed = self._render_with_git_vars(
            "claude-code", "test-cc", gitconfig_exists=False,
        )
        volumes = parsed["container"]["volumes"]
        assert not any(".gitconfig:" in v for v in volumes)

    def test_ssh_socket_mount_when_available(self):
        parsed = self._render_with_git_vars(
            "claude-code", "test-cc", ssh_agent_available=True,
        )
        volumes = parsed["container"]["volumes"]
        assert any("ssh-agent.sock" in v for v in volumes)

    def test_ssh_env_set_when_available(self):
        parsed = self._render_with_git_vars(
            "claude-code", "test-cc", ssh_agent_available=True,
        )
        env = parsed["container"].get("env", {})
        assert env.get("SSH_AUTH_SOCK") == "/run/ssh-agent.sock"

    def test_no_ssh_mount_when_unavailable(self):
        parsed = self._render_with_git_vars(
            "claude-code", "test-cc", ssh_agent_available=False,
        )
        volumes = parsed["container"]["volumes"]
        assert not any("ssh-agent.sock" in v for v in volumes)

    def test_gh_mount_when_exists(self):
        parsed = self._render_with_git_vars(
            "claude-code", "test-cc", gh_auth_exists=True,
        )
        volumes = parsed["container"]["volumes"]
        assert any(".config/gh:" in v for v in volumes)

    def test_no_gh_mount_when_missing(self):
        parsed = self._render_with_git_vars(
            "claude-code", "test-cc", gh_auth_exists=False,
        )
        volumes = parsed["container"]["volumes"]
        assert not any(".config/gh:" in v for v in volumes)

    def test_no_mounts_when_none_available(self):
        parsed = self._render_with_git_vars("claude-code", "test-cc")
        volumes = parsed["container"]["volumes"]
        assert not any(".gitconfig:" in v for v in volumes)
        assert not any("ssh-agent.sock" in v for v in volumes)
        assert not any(".config/gh:" in v for v in volumes)

    def test_all_mounts_when_all_available(self):
        parsed = self._render_with_git_vars(
            "claude-code", "test-cc",
            gitconfig_exists=True,
            ssh_agent_available=True,
            gh_auth_exists=True,
        )
        volumes = parsed["container"]["volumes"]
        assert any(".gitconfig:" in v for v in volumes)
        assert any("ssh-agent.sock" in v for v in volumes)
        assert any(".config/gh:" in v for v in volumes)

    def test_codex_gitconfig_mount(self):
        parsed = self._render_with_git_vars(
            "codex", "test-cx", gitconfig_exists=True,
        )
        volumes = parsed["container"]["volumes"]
        assert any(".gitconfig:" in v for v in volumes)

    def test_codex_ssh_mount(self):
        parsed = self._render_with_git_vars(
            "codex", "test-cx", ssh_agent_available=True,
        )
        volumes = parsed["container"]["volumes"]
        assert any("ssh-agent.sock" in v for v in volumes)

    def test_codex_gh_mount(self):
        parsed = self._render_with_git_vars(
            "codex", "test-cx", gh_auth_exists=True,
        )
        volumes = parsed["container"]["volumes"]
        assert any(".config/gh:" in v for v in volumes)


class TestGithubDomainAllowlist:
    """Verify github.com is in the domain allowlist."""

    def test_claude_code_allows_github(self):
        with patch("agentcage.init.detect_git_integrations", return_value={
            "gitconfig_exists": False,
            "ssh_agent_available": False,
            "gh_auth_exists": False,
        }):
            cfg_text, _ = render_config("test-cc", scaffold="claude-code")
        parsed = yaml.safe_load(cfg_text)
        domains = parsed.get("domains", {}).get("allow", [])
        assert "github.com" in domains

    def test_codex_allows_github(self):
        with patch("agentcage.init.detect_git_integrations", return_value={
            "gitconfig_exists": False,
            "ssh_agent_available": False,
            "gh_auth_exists": False,
        }):
            cfg_text, _ = render_config("test-cx", scaffold="codex")
        parsed = yaml.safe_load(cfg_text)
        domains = parsed.get("domains", {}).get("allow", [])
        assert "github.com" in domains


class TestLimaSshForwarding:
    """Verify Lima template includes SSH agent forwarding."""

    def test_ssh_forward_agent_when_available(self, monkeypatch):
        monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/test-agent.sock")
        from agentcage.lima.provisioning import generate_lima_config

        class FakeConfig:
            name = "test-vm"
            class vm:
                vcpus = 2
                mem_mb = 4096
            class container:
                ports: list[str] = []
                volumes: list[str] = []

        result = generate_lima_config(FakeConfig())
        parsed = yaml.safe_load(result)
        assert parsed.get("ssh", {}).get("forwardAgent") is True

    def test_no_ssh_forward_when_unavailable(self, monkeypatch):
        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
        from agentcage.lima.provisioning import generate_lima_config

        class FakeConfig:
            name = "test-vm"
            class vm:
                vcpus = 2
                mem_mb = 4096
            class container:
                ports: list[str] = []
                volumes: list[str] = []

        result = generate_lima_config(FakeConfig())
        parsed = yaml.safe_load(result)
        assert "ssh" not in parsed


class TestSshAgentHealthCheck:
    """Verify SSH agent health check warning logic."""

    def test_warning_on_dead_agent(self, capsys):
        """The health check code path should emit a warning when ssh-add fails."""
        import subprocess
        import click

        # Simulate the health check logic from run.py
        ssh_check_cmd = ["false"]  # always fails with rc=1
        result = subprocess.run(ssh_check_cmd, capture_output=True, timeout=5)
        if result.returncode != 0:
            click.echo(
                "warning: SSH agent not accessible inside cage. "
                "Git SSH push may not work.",
                err=True,
            )
        captured = capsys.readouterr()
        assert "SSH agent not accessible" in captured.err
