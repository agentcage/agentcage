"""Tests for ported defaults: inspector auto-loading."""

import sys
import textwrap
import types
from unittest.mock import MagicMock

import yaml
import pytest


# ── Stub mitmproxy before importing addon ────────────────────

_mitmproxy = types.ModuleType("mitmproxy")
_mitmproxy.ctx = MagicMock()
_mitmproxy.http = MagicMock()
sys.modules.setdefault("mitmproxy", _mitmproxy)
sys.modules.setdefault("mitmproxy.ctx", _mitmproxy.ctx)
sys.modules.setdefault("mitmproxy.http", _mitmproxy.http)

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

    def test_openclaw_simplified_config_still_loads_inspectors(self):
        """The simplified openclaw config (no inspectors: section) should still
        get entropy + content-type loaded by default."""
        with open("/home/luca/github/openclaw-setup/config/lobstercage/config.yaml") as f:
            cfg_text = f.read()
        addon = self._make_addon(cfg_text)
        names = [i.name for i in addon.inspectors]
        assert "entropy" in names
        assert "content-type" in names
        assert "domain" in names
        assert "secrets" in names


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

