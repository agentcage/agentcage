"""Tests for ported defaults: inspector auto-loading."""

import sys
import textwrap
import types
from pathlib import Path
from unittest.mock import MagicMock

import yaml
import pytest


# ── Stub mitmproxy before importing addon ────────────────────

_mitmproxy = types.ModuleType("mitmproxy")
_mitmproxy.__path__ = []  # make it a package so submodule imports work
_mitmproxy.ctx = MagicMock()
_mitmproxy.http = MagicMock()
_proxy = types.ModuleType("mitmproxy.proxy")
_proxy.__path__ = []
_mode_specs = types.ModuleType("mitmproxy.proxy.mode_specs")
_mode_specs.ReverseMode = MagicMock()
_mitmproxy.proxy = _proxy
_proxy.mode_specs = _mode_specs
sys.modules.setdefault("mitmproxy", _mitmproxy)
sys.modules.setdefault("mitmproxy.ctx", _mitmproxy.ctx)
sys.modules.setdefault("mitmproxy.http", _mitmproxy.http)
sys.modules.setdefault("mitmproxy.proxy", _proxy)
sys.modules.setdefault("mitmproxy.proxy.mode_specs", _mode_specs)

from addon import Agentcage  # noqa: E402


# ── addon.py: entropy + content-type on by default ──────────


class TestDefaultInspectors:
    """Verify entropy and content-type inspectors load without config."""

    def _make_addon(self, yaml_content: str) -> Agentcage:
        """Create a Agentcage addon from YAML without mitmproxy."""
        addon = Agentcage()
        addon.cfg = yaml.safe_load(yaml_content) or {}
        logging_cfg = addon.cfg.get("logging") or {}
        if "allowed_requests" in logging_cfg:
            addon.log_allowed = bool(logging_cfg["allowed_requests"])
        else:
            addon.log_allowed = bool(addon.cfg.get("log_allowed", False))
        addon.inspectors = []
        addon._load_builtin_inspectors()
        addon._load_custom_inspectors()
        return addon

    def test_entropy_and_content_type_load_by_default(self):
        addon = self._make_addon("domains: {}")
        names = [i.name for i in addon.inspectors]
        assert "entropy" in names
        assert "content-type" in names

    def test_entropy_defaults_to_block_mode(self):
        addon = self._make_addon("domains: {}")
        entropy = next(i for i in addon.inspectors if i.name == "entropy")
        assert entropy.action == "block"
        assert entropy.threshold == 7.0
        assert entropy.min_body_bytes == 256

    def test_content_type_defaults_to_block_mode(self):
        addon = self._make_addon("domains: {}")
        ct = next(i for i in addon.inspectors if i.name == "content-type")
        assert ct.action == "block"
        assert ct.entropy_ceiling == 6.5
        assert ct.detect_base64 is True

    def test_entropy_disabled_with_false(self):
        addon = self._make_addon("entropy: false\ndomains: {}")
        names = [i.name for i in addon.inspectors]
        assert "entropy" not in names

    def test_content_type_disabled_with_false(self):
        addon = self._make_addon("content_type: false\ndomains: {}")
        names = [i.name for i in addon.inspectors]
        assert "content-type" not in names

    def test_custom_entropy_config_overrides_defaults(self):
        addon = self._make_addon(textwrap.dedent("""\
            domains: {}
            entropy:
              threshold: 6.0
              action: block
        """))
        entropy = next(i for i in addon.inspectors if i.name == "entropy")
        assert entropy.threshold == 6.0
        assert entropy.action == "block"

    def test_minimal_config_loads_all_five_inspectors(self):
        """A bare config should load domain, secrets, body-size, entropy, content-type."""
        addon = self._make_addon("domains: {}\nsecrets: {}")
        names = sorted(i.name for i in addon.inspectors)
        assert names == ["body-size", "content-type", "domain", "entropy", "secrets"]

    def test_openclaw_preset_loads_inspectors(self):
        """The openclaw scaffold config should load entropy + content-type."""
        from agentcage.init import render_config
        cfg_text = render_config("test-oc", scaffold="openclaw")
        addon = self._make_addon(cfg_text)
        names = [i.name for i in addon.inspectors]
        assert "entropy" in names
        assert "content-type" in names
        assert "domain" in names
        assert "secrets" in names

    def test_picoclaw_preset_loads_inspectors(self):
        """The picoclaw scaffold config should load entropy + content-type."""
        from agentcage.init import render_config
        cfg_text = render_config("test-pico", scaffold="picoclaw")
        addon = self._make_addon(cfg_text)
        names = [i.name for i in addon.inspectors]
        assert "entropy" in names
        assert "content-type" in names
        assert "domain" in names

    def test_picoclaw_preset_parses_via_load_config(self, tmp_path):
        """The picoclaw scaffold should produce valid YAML that load_config accepts."""
        from agentcage.init import render_config
        from agentcage.config import load_config
        cfg_text = render_config("test-pico", scaffold="picoclaw")
        cfg_file = tmp_path / "picoclaw.yaml"
        cfg_file.write_text(cfg_text)
        cfg = load_config(str(cfg_file))
        assert cfg.name == "test-pico"
        assert cfg.container.image == "docker.io/sipeed/picoclaw:latest"
        assert cfg.container.command == ["gateway"]
        assert cfg.container.memory == "256m"
        assert cfg.container.cpus == "0.5"


# ── CLI: verify and deploy arg parsing ────────────────────


class TestCLI:
    """Test Python CLI argument parsing via click.testing.CliRunner."""

    def _run(self, args):
        from click.testing import CliRunner
        from agentcage.cli import main
        return CliRunner().invoke(main, args, catch_exceptions=False)

    def test_verify_requires_name(self):
        result = self._run(["cage", "verify"])
        assert result.exit_code != 0

    def test_verify_help(self):
        result = self._run(["cage", "verify", "--help"])
        assert result.exit_code == 0
        assert "healthy" in result.output

    def test_main_help_shows_groups(self):
        result = self._run(["--help"])
        assert result.exit_code == 0
        assert "cage" in result.output
        assert "secret" in result.output

    def test_cage_help_shows_subcommands(self):
        result = self._run(["cage", "--help"])
        assert result.exit_code == 0
        assert "create" in result.output
        assert "update" in result.output
        assert "destroy" in result.output
        assert "verify" in result.output
        assert "list" in result.output
        assert "reload" in result.output

    def test_secret_help_shows_subcommands(self):
        result = self._run(["secret", "--help"])
        assert result.exit_code == 0
        assert "list" in result.output
        assert "set" in result.output
        assert "rm" in result.output


class TestAddonLogAllowed:
    """Test log_allowed default and logging config precedence."""

    def _make_addon(self, yaml_content: str) -> Agentcage:
        addon = Agentcage()
        addon.cfg = yaml.safe_load(yaml_content) or {}
        logging_cfg = addon.cfg.get("logging") or {}
        if "allowed_requests" in logging_cfg:
            addon.log_allowed = bool(logging_cfg["allowed_requests"])
        else:
            addon.log_allowed = bool(addon.cfg.get("log_allowed", True))
        addon.inspectors = []
        return addon

    def test_default_true(self):
        addon = self._make_addon("name: test\n")
        assert addon.log_allowed is True

    def test_legacy_log_allowed_true(self):
        addon = self._make_addon("log_allowed: true\n")
        assert addon.log_allowed is True

    def test_legacy_log_allowed_false(self):
        addon = self._make_addon("log_allowed: false\n")
        assert addon.log_allowed is False

    def test_new_logging_allowed_requests_true(self):
        addon = self._make_addon(textwrap.dedent("""\
            logging:
              allowed_requests: true
        """))
        assert addon.log_allowed is True

    def test_new_key_overrides_legacy(self):
        addon = self._make_addon(textwrap.dedent("""\
            log_allowed: true
            logging:
              allowed_requests: false
        """))
        assert addon.log_allowed is False

    def test_legacy_fallback_when_no_new_key(self):
        addon = self._make_addon(textwrap.dedent("""\
            log_allowed: true
            logging:
              dns_queries: true
        """))
        assert addon.log_allowed is True

