"""Tests for agentcage.run module (generate_name, execute)."""

import re
from unittest.mock import patch

import pytest

from agentcage.run import _vm_podman_prefix, generate_name


class TestVmPodmanPrefix:
    """The interactive session must reach Podman inside the VM on macOS."""

    def test_vm_routes_through_limactl(self):
        assert _vm_podman_prefix("vm", "my-cage") == [
            "limactl", "shell", "agentcage-my-cage", "--",
        ]

    def test_container_needs_no_prefix(self):
        assert _vm_podman_prefix("container", "my-cage") == []


class TestGenerateName:
    """Verify auto-naming for ephemeral/interactive cages."""

    @patch("agentcage.run.state.list_deployments", return_value=[])
    def test_produces_valid_cage_name(self, _mock):
        name = generate_name("claude-code")
        assert re.match(r'^[a-z0-9][a-z0-9-]{0,62}$', name)
        assert name.startswith("claude-")
        # Should use short prefix, not full scaffold name
        assert not name.startswith("claude-code-")

    @patch("agentcage.run.state.list_deployments", return_value=[])
    def test_names_are_unique(self, _mock):
        names = {generate_name("test") for _ in range(50)}
        assert len(names) >= 40

    @patch("agentcage.run.state.list_deployments",
           return_value=["test-bold-fox", "test-calm-owl"])
    def test_avoids_existing_names(self, _mock):
        for _ in range(20):
            name = generate_name("test")
            assert name not in ("test-bold-fox", "test-calm-owl")

    @patch("agentcage.run.state.list_deployments", return_value=[])
    def test_name_not_too_long(self, _mock):
        name = generate_name("claude-code")
        assert len(name) <= 63

    @patch("agentcage.run.state.list_deployments", return_value=[])
    def test_includes_scaffold_prefix(self, _mock):
        name = generate_name("codex")
        assert name.startswith("codex-")
        # Should have adjective-noun after prefix
        parts = name.split("-")
        assert len(parts) >= 3
