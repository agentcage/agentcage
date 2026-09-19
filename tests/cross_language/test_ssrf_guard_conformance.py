"""The host and proxy copies of the never-grant rules must agree.

RUST-PORT-PLAN.md §2.2 lists these as two of the four shared-logic sites that
become cross-language contracts:

    | host                         | proxy                          |
    | config.encoded_private_ip    | policy_api._encoded_private_ip |
    | cli._is_never_grant          | policy_api._is_never_grant     |

They are duplicated today and held in sync only by the assertions below, which
import both sides at once. After the port the host half is Rust, so these
assertions cannot live in either suite.

**PR A4 replaces this file** with a language-neutral JSON fixture of
``(input, expected)`` cases generated from the Python implementation, asserted
independently by a Rust test and by pytest — so neither side can drift silently
even though nothing imports the other any more. See ``tests/cross_language/__init__.py``.

Split out of ``tests/test_policy_api_ssrf_guard.py``; test names are unchanged
so failures stay greppable against history.
"""

from __future__ import annotations

import sys
import types

from tests.cross_language.vectors import ALLOWED, BYPASS


def _addon():
    """The in-container addon, importable without mitmproxy installed."""
    sys.modules.setdefault("mitmproxy", types.ModuleType("mitmproxy"))
    sys.modules.setdefault("mitmproxy.http", types.ModuleType("mitmproxy.http"))
    from agentcage.data.proxy import policy_api as pa
    api = pa.PolicyApi.__new__(pa.PolicyApi)
    api._never_grant = {"internal", "local", "localhost", "agentcage.local"}
    return api, pa


def test_host_and_addon_implementations_agree():
    from agentcage.config import encoded_private_ip
    _, pa = _addon()
    for d in BYPASS + ALLOWED:
        assert encoded_private_ip(d) == pa._encoded_private_ip(d), d


def test_addon_and_config_never_grant_sets_agree():
    """The two copies are duplicated by necessity; they must not drift."""
    from agentcage.config import _AUTO_NEVER_GRANT
    api, _ = _addon()
    api.host = "agentcage.local"
    addon_set = api._effective_never_grant([])
    assert set(_AUTO_NEVER_GRANT) <= addon_set, (
        f"config has {set(_AUTO_NEVER_GRANT) - addon_set} that the addon lacks"
    )
