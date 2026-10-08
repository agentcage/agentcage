"""The capture writer's default size cap is a host/proxy format contract.

``CaptureWriter`` (egress, Python forever) falls back to a default
``max_file_size``; ``agentcage.config.MAX_CAPTURE_FILE_BYTES`` (host, becoming
Rust) is the value the host documents and validates against. They are the same
number in two places, and nothing but this assertion keeps them equal.

RUST-PORT-PLAN.md §2.2 lists the capture.jsonl schema among the format
contracts that become language-neutral fixtures in PR **A4**; this default
belongs with them. Until then the assertion lives here, importing both sides on
purpose. See ``tests/cross_language/__init__.py``.

Split out of ``tests/test_capture.py``; the test name is unchanged.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROXY_DIR = str(Path(__file__).resolve().parents[2] / "src" / "agentcage" / "data" / "proxy")
if _PROXY_DIR not in sys.path:
    sys.path.insert(0, _PROXY_DIR)

from capture import CaptureWriter  # noqa: E402


def _cfg(**over):
    cfg = {"enable_har": True, "max_body_size": 10485760,
           "min_action": "all", "domains": [], "exclude_domains": []}
    cfg.update(over)
    return cfg


def test_default_cap_is_applied(tmp_path):
    # An operator who never sets max_file_size still gets a bound.
    from agentcage.config import MAX_CAPTURE_FILE_BYTES
    w = CaptureWriter(_cfg(), str(tmp_path / "capture.jsonl"))
    assert w._max_file == MAX_CAPTURE_FILE_BYTES
