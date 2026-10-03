"""A host-rendered scaffold must produce a config the egress addon can load.

``agentcage.init.render_config`` (host, becoming Rust) writes the cage.yaml
that ``addon._load_builtin_inspectors`` (egress, Python forever) reads back.
That makes the scaffold output a format contract, and this is the only test
that exercises both ends of it at once — so it belongs to neither suite after
the split.

RUST-PORT-PLAN.md §2.2 collects the format contracts (proxy-config shape,
grants-overlay JSON, placeholder grammar, audit/capture schemas) into
language-neutral fixtures in PR **A4**; the scaffold-to-addon handshake belongs
with them. See ``tests/cross_language/__init__.py``.

Split out of ``tests/test_defaults.py``; the test name is unchanged.
"""

import sys
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

from addon import Agentcage  # noqa: E402


def _make_addon(yaml_content: str) -> Agentcage:
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


def test_openclaw_preset_loads_inspectors():
    """The openclaw scaffold loads content-type/domain/secrets — but not
    the entropy inspector, which scaffolds no longer opt into."""
    from agentcage.init import render_config
    cfg_text = render_config("test-oc", scaffold="openclaw")
    addon = _make_addon(cfg_text)
    names = [i.name for i in addon.inspectors]
    assert "content-type" in names
    assert "domain" in names
    assert "secrets" in names
    assert "entropy" not in names
