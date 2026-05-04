"""Integration tests for the addon's protocol-relay lifecycle hooks.

Covers A1 (the ``done()`` hook actually calls ``relay.stop()``) and A5
(``relay.start()`` failures land in the audit pipeline, not as
unhandled task exceptions).

mitmproxy isn't a runtime dependency of the test environment because
the proxy ships in its own container — so these tests stub the parts
of the mitmproxy API the addon imports, then drive the addon directly.
"""

from __future__ import annotations

import asyncio
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


@pytest.fixture(autouse=True)
def _imap_creds(monkeypatch):
    monkeypatch.setenv("TEST_IMAP_USER", "real-user@example.com")
    monkeypatch.setenv("TEST_IMAP_PASS", "real-app-password")


def _make_addon(audit_path="/tmp/_test_audit.jsonl"):
    """Build a minimally configured Agentcage instance suitable for
    driving lifecycle hooks. Skips ``load()`` because that wires the
    full inspector chain we don't need here."""
    addon = Agentcage()
    addon.cfg = {}
    addon.log_allowed = False
    addon._audit_file = None  # _audit_write tolerates None
    return addon


def _relay_entry(upstream_port: int, *, name: str = "t-imap") -> dict:
    return {
        "name": name,
        "type": "imap",
        "listen": "127.0.0.1:0",
        "upstream": {
            "host": "127.0.0.1",
            "port": upstream_port,
            "tls": False,
        },
        "auth": {
            "type": "imap-login",
            "user_source": "env:TEST_IMAP_USER",
            "password_source": "env:TEST_IMAP_PASS",
        },
        "policy": {},
    }


async def _start_silent_upstream() -> tuple[asyncio.AbstractServer, int]:
    """A no-op upstream that holds connections open, simulating a
    real IMAP server that's mid-IDLE."""
    async def _h(reader, writer):
        try:
            writer.write(b"* OK [CAPABILITY IMAP4rev1] silent\r\n")
            await writer.drain()
            # Echo "OK" to anything until disconnect.
            while True:
                line = await reader.readline()
                if not line:
                    return
                tag = line.split(b" ", 1)[0]
                writer.write(tag + b" OK noop\r\n")
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(_h, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


# ── A1: done() drains in-flight relay sessions ───────────


class TestDoneHook:
    def test_done_stops_all_relays(self):
        """Each registered relay's ``stop()`` is awaited from done()."""

        async def _go():
            from relays.imap import ImapRelay

            upstream, up_port = await _start_silent_upstream()
            try:
                addon = _make_addon()
                relay_a = ImapRelay(_relay_entry(up_port, name="a"))
                relay_b = ImapRelay(_relay_entry(up_port, name="b"))
                await relay_a.start()
                await relay_b.start()
                addon._relays = [relay_a, relay_b]

                # Sanity: both servers are listening.
                assert relay_a._server is not None
                assert relay_b._server is not None

                await addon.done()

                # Both relays cleared their server handles in stop().
                assert relay_a._server is None
                assert relay_b._server is None
            finally:
                upstream.close()
                await upstream.wait_closed()

        asyncio.run(_go())

    def test_done_cancels_inflight_session(self):
        """A long-running client session is cancelled when done() runs.

        Without the done() hook (pre-A1), the session would survive
        proxy shutdown and the cage would see a TCP reset instead of
        a clean close.
        """

        async def _go():
            from relays.imap import ImapRelay

            upstream, up_port = await _start_silent_upstream()
            try:
                addon = _make_addon()
                relay = ImapRelay(_relay_entry(up_port))
                await relay.start()
                addon._relays = [relay]

                port = relay._server.sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", port
                )
                try:
                    # Drain PREAUTH so the bridge is fully active.
                    await reader.readline()
                    # The session task is now in `asyncio.wait` over
                    # the two pipe tasks — exactly the state that
                    # done()/stop() must drain.
                    assert relay._sessions, "session task should be tracked"

                    await addon.done()

                    # All session tasks should be done after done().
                    for task in list(relay._sessions):
                        assert task.done(), task
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
            finally:
                upstream.close()
                await upstream.wait_closed()

        asyncio.run(_go())

    def test_done_is_a_noop_when_no_relays_configured(self):
        async def _go():
            addon = _make_addon()
            # _relays is intentionally absent (mirrors the addon's
            # behavior when no protocol_relays config is present).
            await addon.done()  # must not raise

        asyncio.run(_go())


# ── A5: start() failures surface via audit pipeline ──────


class TestStartFailureCallback:
    def test_start_failure_logs_to_audit_via_callback(self):
        """Two relays bound to the same listener port — the second
        ``start()`` raises OSError. The done_callback we attached must
        catch the exception and feed it to the audit pipeline rather
        than letting Python emit ``Task exception was never retrieved``
        at GC time."""

        async def _go():
            from relays.imap import ImapRelay

            upstream, up_port = await _start_silent_upstream()
            entries: list[dict] = []
            try:
                # Pin the listen port on relay 'a', then ask 'b' to bind
                # the same port — the second bind fails inside start().
                first = ImapRelay(_relay_entry(up_port, name="a"))
                await first.start()
                pinned = first._server.sockets[0].getsockname()[1]

                addon = _make_addon()
                addon._audit_write = entries.append  # capture audit dicts
                addon.cfg = {
                    "protocol_relays": [
                        {
                            "name": "b",
                            "type": "imap",
                            "listen": f"127.0.0.1:{pinned}",
                            "upstream": {
                                "host": "127.0.0.1",
                                "port": up_port,
                                "tls": False,
                            },
                            "auth": {
                                "type": "imap-login",
                                "user_source": "env:TEST_IMAP_USER",
                                "password_source": "env:TEST_IMAP_PASS",
                            },
                            "policy": {},
                        }
                    ]
                }
                addon._start_protocol_relays()
                # The scheduled start() task runs on the next loop tick.
                # Yield to let the task run and the callback fire.
                for _ in range(20):
                    await asyncio.sleep(0.01)
                    if any(
                        e.get("kind") == "relay_start_failed"
                        for e in entries
                    ):
                        break

                failed = [
                    e for e in entries
                    if e.get("kind") == "relay_start_failed"
                ]
                assert failed, entries
                assert failed[0]["relay"] == "b"
            finally:
                await first.stop()
                upstream.close()
                await upstream.wait_closed()

        asyncio.run(_go())
