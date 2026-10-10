"""Shared test setup for the egress proxy suite."""

import sys
import types
from unittest.mock import MagicMock


# ── Stub mitmproxy at collection time ────────────────────────
# The proxy modules (addon, secret_injector) import mitmproxy at
# top-level. Stub it before any test module imports them so the
# tests can run on the host without the proxy container's deps.
_mitmproxy = types.ModuleType("mitmproxy")
_mitmproxy.__path__ = []
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

