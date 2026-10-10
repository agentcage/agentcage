"""Tests for ported defaults: inspector auto-loading (egress side).

Boundary note (docs/history/rust-port-plan.md §2.4): ``addon.py`` is the
egress side; the host-side halves of this file are Rust tests now. The
scaffold-to-addon handshake is asserted against
``tests/fixtures/contracts/scaffold_inspectors.json``.
"""

import sys
import textwrap
import types
from unittest.mock import MagicMock

import yaml


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

from addon import Agentcage, _log_allowed  # noqa: E402


# ── addon.py: entropy + content-type on by default ──────────


class TestDefaultInspectors:
    """Verify entropy and content-type inspectors load without config."""

    def _make_addon(self, yaml_content: str) -> Agentcage:
        """Create a Agentcage addon from YAML without mitmproxy."""
        addon = Agentcage()
        addon.cfg = yaml.safe_load(yaml_content) or {}
        addon.log_allowed = _log_allowed(addon.cfg)
        addon.inspectors = []
        addon._load_inspectors()
        return addon

    def test_entropy_not_loaded_by_default(self):
        """Bare config (no `entropy:` key, no `inspectors:` entry) → entropy
        inspector is NOT loaded. Opt-in default flip (vs. 0.15.4)."""
        addon = self._make_addon("domains: {}")
        names = [i.name for i in addon.inspectors]
        assert "entropy" not in names

    def test_content_type_loads_by_default(self):
        addon = self._make_addon("domains: {}")
        names = [i.name for i in addon.inspectors]
        assert "content-type" in names

    def test_entropy_opt_in_empty_dict_loads_defaults(self):
        """`entropy: {}` opts in with default config."""
        addon = self._make_addon("entropy: {}\ndomains: {}")
        entropy = next(i for i in addon.inspectors if i.name == "entropy")
        assert entropy.action == "block"
        assert entropy.threshold == 7.0
        assert entropy.min_body_bytes == 256

    def test_entropy_opt_in_via_inspectors_block(self):
        """`inspectors: - name: entropy` opts in via the custom-inspector path."""
        addon = self._make_addon(textwrap.dedent("""\
            domains: {}
            inspectors:
              - name: entropy
        """))
        names = [i.name for i in addon.inspectors]
        assert "entropy" in names

    def test_entropy_opt_in_via_inspectors_block_with_config(self):
        """`inspectors: - name: entropy` with explicit config applies overrides."""
        addon = self._make_addon(textwrap.dedent("""\
            domains: {}
            inspectors:
              - name: entropy
                config:
                  threshold: 7.5
                  action: flag
        """))
        entropy = next(i for i in addon.inspectors if i.name == "entropy")
        assert entropy.threshold == 7.5
        assert entropy.action == "flag"

    def test_content_type_defaults_to_block_mode(self):
        addon = self._make_addon("domains: {}")
        ct = next(i for i in addon.inspectors if i.name == "content-type")
        assert ct.action == "block"
        assert ct.entropy_ceiling == 6.5
        assert ct.detect_base64 is True

    def test_entropy_disabled_with_false(self):
        """Legacy `entropy: false` still doesn't load (regression guard)."""
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

    def test_minimal_config_loads_four_inspectors(self):
        """A bare config (no entropy opt-in) loads domain, secrets,
        body-size, content-type — entropy is opt-in."""
        addon = self._make_addon("domains: {}\nsecrets: {}")
        names = sorted(i.name for i in addon.inspectors)
        assert names == ["body-size", "content-type", "domain", "secrets"]

    def test_minimal_config_with_entropy_opt_in(self):
        """Explicit `entropy: {}` brings back all five inspectors."""
        addon = self._make_addon("domains: {}\nsecrets: {}\nentropy: {}")
        names = sorted(i.name for i in addon.inspectors)
        assert names == ["body-size", "content-type", "domain", "entropy", "secrets"]



class TestAddonLogAllowed:
    """``logging.allowed_requests`` resolution in the egress.

    ``load`` and ``configure`` both resolve it through ``_log_allowed``;
    the host-agreement table is ``logging_defaults.json`` (see
    ``TestLoggingDefaults`` in ``test_contract_fixtures.py``).
    """

    def _make_addon(self, yaml_content: str) -> Agentcage:
        addon = Agentcage()
        addon.cfg = yaml.safe_load(yaml_content) or {}
        addon.log_allowed = _log_allowed(addon.cfg)
        addon.inspectors = []
        return addon

    def test_default_false(self):
        """No logging block: off, the host's documented default."""
        addon = self._make_addon("domains: {}\n")
        assert addon.log_allowed is False

    def test_default_false_with_an_unrelated_logging_block(self):
        addon = self._make_addon(textwrap.dedent("""\
            logging:
              level: debug
        """))
        assert addon.log_allowed is False

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


class TestAddonLogAllowedLoadAndReload:
    """The real ``load`` and hot-reload paths, from a config file.

    proxy-config.yaml carries the operator's ``logging`` block as written,
    so a cage that never mentions it reaches the egress with no
    ``allowed_requests`` key at all.
    """

    @staticmethod
    def _write(path, text: str, bump: int) -> None:
        import os

        path.write_text(text)
        st = os.stat(path)
        os.utime(path, (st.st_atime, st.st_mtime + bump))

    def test_load_without_a_logging_block_is_off_and_reload_follows(
        self, tmp_path, monkeypatch
    ):
        import addon as addon_mod

        monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", "")
        cfg = tmp_path / "config.yaml"
        monkeypatch.setattr(addon_mod, "CONFIG_PATH", str(cfg))
        self._write(cfg, "domains:\n  allow: [example.com]\n", 1)

        addon = addon_mod.Agentcage()
        addon.load(loader=None)
        assert addon.log_allowed is False

        self._write(cfg, textwrap.dedent("""\
            domains:
              allow: [example.com]
            logging:
              allowed_requests: true
        """), 5)
        addon._maybe_reload()
        assert addon.log_allowed is True

        # Dropping the key again is a return to the default, not a
        # sticky last value.
        self._write(cfg, "domains:\n  allow: [example.com]\n", 10)
        addon._maybe_reload()
        assert addon.log_allowed is False

