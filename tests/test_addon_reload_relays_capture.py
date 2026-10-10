"""Hot-reload of ``protocol_relays`` and ``capture`` (Phase 0a fix D7b).

``cage edit`` reports both sections as live-applied, but the addon only
started relays in ``running()`` and built the capture writer in
``load()``: ``_maybe_reload`` touched neither, so adding, removing or
changing a relay, or toggling/tuning HAR capture, silently needed an
egress restart.

The contract these tests pin:

* relays are diffed by ``name``. An identical entry whose credentials
  still resolve to the same values keeps its running relay (and its
  sessions); a changed entry or a rotated credential stops it and
  starts a fresh relay from the new entry, on the same port if it kept
  it; a
  removed entry is stopped; an added one is validated and started the
  way boot does it, with the same audit records on failure.
* the capture writer is rebuilt when the ``capture`` section changes:
  disabling closes it, enabling opens it, a changed limit/filter takes
  effect. In-flight staged entries complete under the new writer; a
  disable drops them.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
from unittest.mock import MagicMock

import pytest
import yaml


# ── Fixtures and helpers ─────────────────────────────────


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Point the addon at a temp config + capture path, no audit file."""
    from agentcage.data.proxy import addon as addon_mod

    monkeypatch.setenv("TEST_IMAP_USER", "real-user@example.com")
    monkeypatch.setenv("TEST_IMAP_PASS", "real-app-password")
    monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", "")
    cfg_path = tmp_path / "config.yaml"
    cap_path = tmp_path / "capture" / "capture.jsonl"
    monkeypatch.setattr(addon_mod, "CONFIG_PATH", str(cfg_path))
    monkeypatch.setattr(addon_mod, "CAPTURE_PATH", str(cap_path))
    return addon_mod, cfg_path, cap_path


def _write_cfg(path, **sections):
    cfg = {"domains": {"allow": ["example.com"]}}
    cfg.update(sections)
    path.write_text(yaml.safe_dump(cfg))
    # Force a visible mtime change even on coarse-timestamp filesystems.
    st = os.stat(path)
    bump = getattr(_write_cfg, "_n", 0) + 5
    _write_cfg._n = bump
    os.utime(path, (st.st_atime, st.st_mtime + bump))


def _make_addon(env, **sections):
    addon_mod, cfg_path, _ = env
    _write_cfg(cfg_path, **sections)
    addon = addon_mod.Agentcage()
    addon.load(loader=None)
    audit: list[dict] = []
    # Relays bind ``audit_log`` at construction, so this has to be in
    # place before running() builds them.
    addon._audit_write = audit.append
    return addon, audit


def _reload(env, addon, **sections):
    _, cfg_path, _ = env
    _write_cfg(cfg_path, **sections)
    addon._maybe_reload()


async def _settle(addon):
    """Wait for the scheduled relay stop/start work to finish."""
    task = getattr(addon, "_relay_apply_task", None)
    if task is not None:
        await asyncio.wait([task])
    # One more tick so start() done-callbacks (if any) have run.
    await asyncio.sleep(0)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _relay(addon, name):
    running = addon._relays_by_name.get(name)
    return None if running is None else running.relay


def _port(relay) -> int:
    return relay._server.sockets[0].getsockname()[1]


def _imap_entry(up_port, *, name="mail", listen="127.0.0.1:0",
                folder_allowlist=None):
    return {
        "name": name,
        "type": "imap",
        "listen": listen,
        "upstream": {"host": "127.0.0.1", "port": up_port, "tls": False},
        "auth": {
            "type": "imap-login",
            "user_source": "env:TEST_IMAP_USER",
            "password_source": "env:TEST_IMAP_PASS",
        },
        "policy": {"folder_allowlist": list(folder_allowlist or [])},
    }


async def _start_upstream():
    """A permissive fake IMAP upstream: OK to LOGIN and every command."""
    async def _h(reader, writer):
        try:
            writer.write(b"* OK [CAPABILITY IMAP4rev1] fake\r\n")
            await writer.drain()
            while True:
                line = await reader.readline()
                if not line:
                    return
                parts = line.split(b" ", 2)
                cmd = parts[1].rstrip(b"\r\n").upper() if len(parts) > 1 else b""
                writer.write(parts[0] + b" OK " + cmd + b" completed\r\n")
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(_h, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _select(port: int, folder: bytes) -> bytes:
    """Open a relay session, SELECT a folder, return the tagged reply."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await reader.readline()  # PREAUTH greeting
        writer.write(b"a1 SELECT " + folder + b"\r\n")
        await writer.drain()
        while True:
            line = await asyncio.wait_for(reader.readline(), 5)
            if not line or line.startswith(b"a1 "):
                return line
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _run_with_upstream(test):
    """Run ``test(up_port)`` on a fresh loop with a fake upstream."""
    async def _go():
        upstream, up_port = await _start_upstream()
        try:
            await test(up_port)
        finally:
            upstream.close()
            await upstream.wait_closed()
    asyncio.run(_go())


# ── Relays ───────────────────────────────────────────────


class TestRelayReload:
    def test_relay_added_on_reload_starts(self, env):
        async def _t(up):
            addon, audit = _make_addon(env)
            addon.running()
            await _settle(addon)
            assert _relay(addon, "mail") is None

            _reload(env, addon, protocol_relays=[_imap_entry(up)])
            await _settle(addon)
            relay = _relay(addon, "mail")
            assert relay is not None and relay._server is not None
            assert (await _select(_port(relay), b"INBOX")).startswith(b"a1 OK")
            await addon.done()

        _run_with_upstream(_t)

    def test_removed_relay_stops(self, env):
        async def _t(up):
            addon, _ = _make_addon(env, protocol_relays=[
                _imap_entry(up, name="keep"), _imap_entry(up, name="drop")])
            addon.running()
            await _settle(addon)
            dropped = _relay(addon, "drop")
            port = _port(dropped)

            _reload(env, addon, protocol_relays=[_imap_entry(up, name="keep")])
            await _settle(addon)
            assert _relay(addon, "drop") is None
            assert dropped._server is None
            assert dropped not in addon._relays
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", port)
            await addon.done()

        _run_with_upstream(_t)

    def test_changed_relay_restarts_with_new_policy_on_same_port(self, env):
        """A policy edit takes effect, and the relay keeps its listen
        port: the old listener must be closed before the new one binds,
        or the replacement fails with EADDRINUSE."""
        async def _t(up):
            listen = f"127.0.0.1:{_free_port()}"
            addon, audit = _make_addon(env, protocol_relays=[
                _imap_entry(up, listen=listen)])
            addon.running()
            await _settle(addon)
            old = _relay(addon, "mail")
            port = _port(old)
            assert (await _select(port, b"Trash")).startswith(b"a1 OK")

            _reload(env, addon, protocol_relays=[
                _imap_entry(up, listen=listen, folder_allowlist=["INBOX"])])
            await _settle(addon)
            new = _relay(addon, "mail")
            assert new is not old
            assert old._server is None
            assert not [e for e in audit if e.get("kind") == "relay_start_failed"], audit
            assert new._server is not None and _port(new) == port
            reply = await _select(port, b"Trash")
            assert reply.startswith(b"a1 NO") and b"folder_allowlist" in reply
            await addon.done()

        _run_with_upstream(_t)

    def test_unchanged_relay_is_not_restarted(self, env):
        """An unrelated edit (here: adding a second relay) leaves the
        existing relay object, listener and live session alone."""
        async def _t(up):
            entry = _imap_entry(up, name="mail")
            addon, _ = _make_addon(env, protocol_relays=[entry])
            addon.running()
            await _settle(addon)
            relay = _relay(addon, "mail")
            server = relay._server

            reader, writer = await asyncio.open_connection(
                "127.0.0.1", _port(relay))
            try:
                await reader.readline()  # PREAUTH
                _reload(env, addon, rate_limit={"burst": 7}, protocol_relays=[
                    entry, _imap_entry(up, name="other")])
                await _settle(addon)
                assert _relay(addon, "mail") is relay
                assert relay._server is server
                # The session opened before the reload still works.
                writer.write(b"a1 NOOP\r\n")
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), 5)
                assert line.startswith(b"a1 OK"), line
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            assert _relay(addon, "other") is not None
            await addon.done()

        _run_with_upstream(_t)

    def test_rotated_credential_restarts_an_unchanged_entry(
            self, env, monkeypatch):
        """``secret set`` re-stages a relay credential and bumps the
        config mtime without touching the entry. A relay reads its
        credentials only when built, so the reload must rebuild it —
        and only it."""
        async def _t(up):
            mail = _imap_entry(up, name="mail")
            other = dict(_imap_entry(up, name="other"))
            other["auth"] = dict(other["auth"],
                                 password_source="env:TEST_OTHER_PASS")
            monkeypatch.setenv("TEST_OTHER_PASS", "other-password")
            addon, _ = _make_addon(env, protocol_relays=[mail, other])
            addon.running()
            await _settle(addon)
            old, kept = _relay(addon, "mail"), _relay(addon, "other")

            monkeypatch.setenv("TEST_IMAP_PASS", "rotated-password")
            _reload(env, addon, protocol_relays=[mail, other])
            await _settle(addon)
            new = _relay(addon, "mail")
            assert new is not old and old._server is None
            assert new._password == "rotated-password"
            assert _relay(addon, "other") is kept
            await addon.done()

        _run_with_upstream(_t)

    def test_invalid_relay_on_reload_audits_and_spares_the_others(self, env):
        async def _t(up):
            good = _imap_entry(up, name="good")
            addon, audit = _make_addon(env, protocol_relays=[good])
            addon.running()
            await _settle(addon)
            relay = _relay(addon, "good")

            bad = {"name": "bad", "type": "imap"}  # no listen/upstream
            _reload(env, addon, rate_limit={"burst": 7},
                    protocol_relays=[good, bad])
            await _settle(addon)
            invalid = [e for e in audit if e.get("kind") == "relay_config_invalid"]
            assert [e["relay"] for e in invalid] == ["bad"]
            assert _relay(addon, "bad") is None
            assert _relay(addon, "good") is relay and relay._server is not None
            # The rest of the reload still applied.
            assert addon._rl_burst == 7
            await addon.done()

        _run_with_upstream(_t)

    def test_relay_init_failure_on_reload_audits(self, env, monkeypatch):
        async def _t(up):
            addon, audit = _make_addon(env)
            addon.running()
            monkeypatch.delenv("TEST_IMAP_PASS")
            _reload(env, addon, protocol_relays=[_imap_entry(up)])
            await _settle(addon)
            failed = [e for e in audit if e.get("kind") == "relay_init_failed"]
            assert [e["relay"] for e in failed] == ["mail"]
            assert _relay(addon, "mail") is None
            await addon.done()

        _run_with_upstream(_t)

    def test_start_failure_on_reload_audits_and_is_retried(self, env):
        """A relay whose start() fails is dropped from the running set,
        so the next reload tries it again instead of calling it
        unchanged."""
        async def _t(up):
            blocker = socket.socket()
            blocker.bind(("127.0.0.1", 0))
            blocker.listen()
            listen = f"127.0.0.1:{blocker.getsockname()[1]}"
            addon, audit = _make_addon(env)
            addon.running()
            try:
                _reload(env, addon, protocol_relays=[
                    _imap_entry(up, listen=listen)])
                await _settle(addon)
                failed = [e for e in audit
                          if e.get("kind") == "relay_start_failed"]
                assert [e["relay"] for e in failed] == ["mail"]
                assert _relay(addon, "mail") is None
            finally:
                blocker.close()

            _reload(env, addon, rate_limit={"burst": 9}, protocol_relays=[
                _imap_entry(up, listen=listen)])
            await _settle(addon)
            relay = _relay(addon, "mail")
            assert relay is not None and relay._server is not None
            await addon.done()

        _run_with_upstream(_t)

    def test_duplicate_relay_name_is_rejected(self, env):
        """Diffing is by name, so a second entry with a taken name is a
        config error rather than a second, untracked listener."""
        async def _t(up):
            addon, audit = _make_addon(env, protocol_relays=[
                _imap_entry(up), _imap_entry(up, folder_allowlist=["INBOX"])])
            addon.running()
            await _settle(addon)
            invalid = [e for e in audit if e.get("kind") == "relay_config_invalid"]
            assert [e["relay"] for e in invalid] == ["mail"]
            assert len(addon._relays) == 1
            reply = await _select(_port(_relay(addon, "mail")), b"Trash")
            assert reply.startswith(b"a1 OK")  # the first entry won
            await addon.done()

        _run_with_upstream(_t)

    def test_done_waits_for_inflight_restart(self, env):
        """Shutdown right after a reload must not leave the replacement
        listener bound after done() returns."""
        async def _t(up):
            addon, _ = _make_addon(env)
            addon.running()
            _reload(env, addon, protocol_relays=[_imap_entry(up)])
            relay = _relay(addon, "mail")
            await addon.done()
            assert relay._server is None

        _run_with_upstream(_t)


# ── Settings pushed into kept relays ─────────────────────


_MARKER_INSPECTOR_SRC = """\
from inspectors.base import InspectionResult, Inspector


class ReloadMarkerInspector(Inspector):
    name = "reload-marker"

    def configure(self, config):
        self.marker = (config or {}).get("marker", "RELOAD_MARKER_42")

    def inspect_request(self, ctx):
        if ctx.body_text and self.marker in ctx.body_text:
            return InspectionResult(
                inspector=self.name,
                action="block",
                reason="contains " + self.marker,
                severity="critical",
            )
        return None
"""

_MARKER = "RELOAD_MARKER_42"
# An AWS-style access key id: a built-in secrets pattern.
_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture
def marker_inspector(tmp_path, monkeypatch):
    """A custom inspector file the ``inspectors:`` section can load."""
    d = tmp_path / "inspectors"
    d.mkdir()
    path = d / "reload_marker.py"
    path.write_text(_MARKER_INSPECTOR_SRC)
    monkeypatch.setenv("AGENTCAGE_INSPECTOR_DIRS", str(d))
    return {"name": "reload-marker", "path": str(path)}


@pytest.fixture
def smtp_creds(monkeypatch):
    monkeypatch.setenv("TEST_SMTP_USER", "agent@example.com")
    monkeypatch.setenv("TEST_SMTP_PASS", "real-app-password")


def _smtp_entry(up_port, *, name="out"):
    return {
        "name": name,
        "type": "smtp",
        "listen": "127.0.0.1:0",
        "upstream": {"host": "127.0.0.1", "port": up_port, "tls": False},
        "auth": {
            "type": "smtp-plain",
            "user_source": "env:TEST_SMTP_USER",
            "password_source": "env:TEST_SMTP_PASS",
        },
        "policy": {"send_rate_limit": "100/min", "conn_rate_limit": "100/min"},
    }


def _run_with_smtp_upstream(test):
    """Run ``test(up_port, recorder)`` on a fresh loop with a fake SMTP
    upstream."""
    from tests.test_protocol_relays_smtp import (
        FakeSmtpRecorder,
        _start_fake_upstream,
    )

    async def _go():
        recorder = FakeSmtpRecorder()
        upstream, up_port = await _start_fake_upstream(
            recorder, "agent@example.com", "real-app-password")
        try:
            await test(up_port, recorder)
        finally:
            upstream.close()
            await upstream.wait_closed()
    asyncio.run(_go())


async def _smtp_send(port: int, body: str) -> int:
    """Send one message through the relay; return the reply code to the
    end of DATA."""
    from tests.test_protocol_relays_smtp import _cmd, _read_response

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await _read_response(reader)  # greeting
        await _cmd(writer, reader, b"EHLO cage.local")
        await _cmd(writer, reader, b"MAIL FROM:<agent@example.com>")
        await _cmd(writer, reader, b"RCPT TO:<friend@example.com>")
        await _cmd(writer, reader, b"DATA")
        writer.write(b"Subject: t\r\n\r\n" + body.encode() + b"\r\n.\r\n")
        await writer.drain()
        code, _ = await asyncio.wait_for(_read_response(reader), 5)
        await _cmd(writer, reader, b"QUIT")
        return code
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _allowed_imap(audit):
    return [e["command"] for e in audit
            if e.get("kind") == "imap_command"
            and e.get("decision") == "allowed"]


class TestKeptRelayFollowsReload:
    """A relay a reload keeps (its entry unchanged) must still pick up
    the reload's ``logging.allowed_requests`` and inspector chain: it
    was built with the old ones, and nothing else hands it the new."""

    @pytest.mark.parametrize("spelling", ["logging", "legacy"])
    def test_allowed_requests_flip_reaches_a_kept_imap_relay(
            self, env, spelling):
        def _flag(on):
            if spelling == "logging":
                return {"logging": {"allowed_requests": on}}
            return {"log_allowed": on}

        async def _t(up):
            entry = _imap_entry(up)
            addon, audit = _make_addon(
                env, protocol_relays=[entry], **_flag(False))
            addon.running()
            await _settle(addon)
            relay = _relay(addon, "mail")

            reader, writer = await asyncio.open_connection(
                "127.0.0.1", _port(relay))

            async def _noop(tag):
                writer.write(tag + b" NOOP\r\n")
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), 5)
                assert line.startswith(tag + b" OK"), line

            try:
                await reader.readline()  # PREAUTH
                await _noop(b"a1")
                assert _allowed_imap(audit) == []

                _reload(env, addon, protocol_relays=[entry], **_flag(True))
                await _settle(addon)
                assert _relay(addon, "mail") is relay  # not restarted
                # Same session, opened before the reload.
                await _noop(b"a2")
                assert _allowed_imap(audit) == ["NOOP"]

                _reload(env, addon, protocol_relays=[entry], **_flag(False))
                await _settle(addon)
                assert _relay(addon, "mail") is relay
                await _noop(b"a3")
                assert _allowed_imap(audit) == ["NOOP"]
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            await addon.done()

        _run_with_upstream(_t)

    def test_inspector_added_by_reload_reaches_a_kept_smtp_relay(
            self, env, marker_inspector, smtp_creds):
        async def _t(up, recorder):
            entry = _smtp_entry(up)
            addon, audit = _make_addon(env, protocol_relays=[entry])
            addon.running()
            await _settle(addon)
            relay = _relay(addon, "out")
            assert await _smtp_send(_port(relay), _MARKER) == 250

            _reload(env, addon, protocol_relays=[entry],
                    inspectors=[marker_inspector])
            await _settle(addon)
            assert _relay(addon, "out") is relay  # not restarted
            assert await _smtp_send(_port(relay), _MARKER) == 550
            blocked = [e for e in audit if e.get("kind") == "smtp_data"
                       and e.get("decision") == "blocked"]
            assert [e["inspector"] for e in blocked] == ["reload-marker"]
            assert len(recorder.transactions) == 1
            await addon.done()

        _run_with_smtp_upstream(_t)

    def test_inspector_removed_from_the_chain_stops_applying(
            self, env, marker_inspector, smtp_creds):
        """Reload itself never shrinks the shared chain today (an entry
        dropped from ``inspectors:`` keeps running on HTTP until restart),
        but whatever the shared chain is after a reload is what a kept
        relay runs: here an inspector taken out of it."""
        async def _t(up, recorder):
            entry = _smtp_entry(up)
            addon, _ = _make_addon(env, protocol_relays=[entry],
                                   inspectors=[marker_inspector])
            addon.running()
            await _settle(addon)
            relay = _relay(addon, "out")
            assert await _smtp_send(_port(relay), _MARKER) == 550

            addon.inspectors = [i for i in addon.inspectors
                                if i.name != "reload-marker"]
            _reload(env, addon, protocol_relays=[entry])
            await _settle(addon)
            assert _relay(addon, "out") is relay
            assert await _smtp_send(_port(relay), _MARKER) == 250
            assert len(recorder.transactions) == 1
            await addon.done()

        _run_with_smtp_upstream(_t)

    def test_refreshed_chain_keeps_the_relay_adjustments(
            self, env, marker_inspector, smtp_creds):
        """The pushed chain is built as at relay start: no domain
        inspector, and the secrets inspector forced to block although
        HTTP only flags by default."""
        from inspectors.domain import DomainInspector

        async def _t(up, recorder):
            addon_mod = env[0]
            entry = _smtp_entry(up)
            addon, audit = _make_addon(
                env, protocol_relays=[entry], secrets={"enabled": True})
            addon.running()
            await _settle(addon)
            relay = _relay(addon, "out")

            _reload(env, addon, protocol_relays=[entry],
                    secrets={"enabled": True},
                    inspectors=[marker_inspector])
            await _settle(addon)
            assert _relay(addon, "out") is relay
            chain = list(relay._inspectors)
            assert "reload-marker" in [i.name for i in chain]
            assert not any(isinstance(i, DomainInspector) for i in chain)
            secrets = next(i for i in chain if i.name == "secrets")
            assert isinstance(secrets, addon_mod._RelaySecretsInspector)
            assert secrets._inner is next(
                i for i in addon.inspectors if i.name == "secrets")

            assert await _smtp_send(_port(relay), "key " + _AWS_KEY) == 550
            blocked = [e for e in audit if e.get("kind") == "smtp_data"
                       and e.get("decision") == "blocked"]
            assert [e["inspector"] for e in blocked] == ["secrets"]
            assert recorder.transactions == []
            await addon.done()

        _run_with_smtp_upstream(_t)


# ── Capture ──────────────────────────────────────────────


def _flow(body: bytes, flow_id="f1"):
    flow = MagicMock()
    flow.id = flow_id
    flow.request.method = "POST"
    flow.request.url = "https://example.com/x"
    flow.request.http_version = "HTTP/1.1"
    flow.request.headers.items.return_value = []
    flow.request.content = body
    return flow


def _write_one(addon, flow_id="f1"):
    snap = addon._capture.snapshot_request(_flow(b"x", flow_id))
    addon._capture.write_entry(
        flow_id=flow_id, direction="outbound", decision="allowed",
        host="example.com", method="POST", path="/x", inspectors=[],
        inbound_req=snap, inbound_resp={}, outbound_req=snap,
        outbound_resp={})


def _lines(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


class TestCaptureReload:
    def test_capture_enabled_on_reload_starts_writing(self, env):
        _, _, cap_path = env
        addon, _ = _make_addon(env)
        assert addon._capture is None

        _reload(env, addon, capture={"enable_har": True})
        assert addon._capture is not None
        _write_one(addon)
        assert [e["flow_id"] for e in _lines(cap_path)] == ["f1"]

    def test_capture_disabled_on_reload_stops(self, env):
        _, _, cap_path = env
        addon, _ = _make_addon(env, capture={"enable_har": True})
        old = addon._capture
        _write_one(addon, "before")
        addon._cap_pending["inflight"] = {"decision": "allowed"}

        _reload(env, addon, capture={"enable_har": False})
        assert addon._capture is None
        assert old._file is None  # closed, not leaked
        # Staged entries cannot complete without a writer: dropped.
        assert addon._cap_pending == {}
        assert [e["flow_id"] for e in _lines(cap_path)] == ["before"]

    def test_capture_limit_change_takes_effect(self, env):
        _, _, cap_path = env
        addon, _ = _make_addon(
            env, capture={"enable_har": True, "max_body_size": 1024})
        body = b"a" * 100
        assert "bodyTruncated" not in addon._capture.snapshot_request(_flow(body))

        old = addon._capture
        old.add_ws_message("ws1", {"type": "send", "data": "hi"})
        addon._cap_pending["inflight"] = {"decision": "allowed"}
        _reload(env, addon, capture={"enable_har": True, "max_body_size": 10})
        snap = addon._capture.snapshot_request(_flow(body))
        assert snap["bodyTruncated"] is True and len(snap["body"]) == 10
        assert old._file is None
        # In-flight flows survive the swap and finish under the new
        # writer, buffered WebSocket frames included.
        assert "inflight" in addon._cap_pending
        assert addon._capture.pop_ws_messages("ws1") == [
            {"type": "send", "data": "hi"}]

    def test_unchanged_capture_section_keeps_the_writer(self, env):
        addon, _ = _make_addon(env, capture={"enable_har": True})
        writer = addon._capture
        _reload(env, addon, capture={"enable_har": True},
                rate_limit={"burst": 3})
        assert addon._capture is writer

    def test_capture_stays_off_without_capture_path(self, env, monkeypatch):
        addon_mod, _, _ = env
        monkeypatch.setattr(addon_mod, "CAPTURE_PATH", "")
        addon, _ = _make_addon(env)
        _reload(env, addon, capture={"enable_har": True})
        assert addon._capture is None

    def test_bad_capture_edit_keeps_the_working_writer(self, env):
        addon, _ = _make_addon(env, capture={"enable_har": True})
        writer = addon._capture
        _reload(env, addon, capture={"enable_har": True,
                                     "max_body_size": "lots"})
        assert addon._capture is writer and writer._file is not None
        # A later good edit is still applied (the bad one was not
        # recorded as current).
        _reload(env, addon, capture={"enable_har": True, "max_body_size": 5})
        assert addon._capture is not writer
        assert addon._capture._max_body == 5
