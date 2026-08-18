"""End-to-end tests for the IMAP relay.

Strategy: spin up a fake upstream IMAP server, the relay, and a client
all in the test process on an asyncio loop. Each test orchestrates a
single client session, asserts on what the upstream actually saw, then
tears down. No real network, no TLS — TLS handling is exercised in
integration but bypassed here.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional

import pytest

from relays.imap import (
    ImapRelay,
    _ConnRateLimiter,
    _extract_mailbox,
    _parse_rate_limit,
    _quote,
)


# ── Fake upstream IMAP server ────────────────────────────


@dataclass
class FakeUpstreamRecorder:
    """Records what the upstream actually saw — used for assertions."""

    login_seen: Optional[tuple[str, str]] = None
    commands: list[bytes] = field(default_factory=list)


async def _start_fake_upstream(
    recorder: FakeUpstreamRecorder,
    expected_user: str,
    expected_pass: str,
    fail_login: bool = False,
    greeting: bytes = b"* OK [CAPABILITY IMAP4rev1] fake upstream ready\r\n",
) -> tuple[asyncio.AbstractServer, int]:
    """Start an asyncio TCP server pretending to be a Migadu IMAP host."""

    async def _handle(reader, writer):
        try:
            writer.write(greeting)
            await writer.drain()
            line = await reader.readline()
            if not line:
                return
            recorder.commands.append(line)
            parts = line.split(b" ", 2)
            if len(parts) < 3:
                writer.write(parts[0] + b" BAD malformed login\r\n")
                await writer.drain()
                return
            tag = parts[0]
            if parts[1].upper() != b"LOGIN":
                writer.write(tag + b" BAD expected LOGIN\r\n")
                await writer.drain()
                return
            rest = parts[2].rstrip(b"\r\n")
            sp = rest.split(b" ", 1)
            user = sp[0].strip(b'"').decode()
            pwd = sp[1].strip(b'"').decode() if len(sp) > 1 else ""
            recorder.login_seen = (user, pwd)
            if fail_login or user != expected_user or pwd != expected_pass:
                writer.write(tag + b" NO bad credentials\r\n")
                await writer.drain()
                return
            writer.write(tag + b" OK LOGIN completed\r\n")
            await writer.drain()
            while True:
                line = await reader.readline()
                if not line:
                    return
                recorder.commands.append(line)
                parts = line.split(b" ", 2)
                tag = parts[0]
                cmd = parts[1].rstrip(b"\r\n").upper() if len(parts) > 1 else b""
                if cmd == b"LOGOUT":
                    writer.write(b"* BYE\r\n")
                    writer.write(tag + b" OK LOGOUT completed\r\n")
                    await writer.drain()
                    return
                writer.write(tag + b" OK " + cmd + b" completed\r\n")
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


def _relay_entry(
    upstream_port: int,
    *,
    name: str = "test-imap",
    listen: str = "127.0.0.1:0",
    readonly: bool = False,
    folder_allowlist: Optional[list[str]] = None,
    conn_rate_limit: str = "30/min",
) -> dict:
    return {
        "name": name,
        "type": "imap",
        "listen": listen,
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
        "policy": {
            "readonly": readonly,
            "folder_allowlist": folder_allowlist or [],
            "conn_rate_limit": conn_rate_limit,
        },
    }


@asynccontextmanager
async def _running_relay(entry: dict):
    relay = ImapRelay(entry)
    await relay.start()
    try:
        port = relay._server.sockets[0].getsockname()[1]
        yield relay, port
    finally:
        await relay.stop()


@asynccontextmanager
async def _imap_client(port: int):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        yield reader, writer
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _read_until_tag(reader: asyncio.StreamReader, tag: bytes) -> bytes:
    """Read lines until one starts with the given tag. Return that line."""
    while True:
        line = await reader.readline()
        if not line:
            raise EOFError("connection closed before tagged response")
        if line.startswith(tag + b" "):
            return line


# ── Pure-function helpers ───────────────────────────────


class TestParseRateLimit:
    def test_min(self):
        assert _parse_rate_limit("30/min") == (30, 60)

    def test_sec(self):
        assert _parse_rate_limit("5/sec") == (5, 1)

    def test_hour(self):
        assert _parse_rate_limit("1000/hour") == (1000, 3600)

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            _parse_rate_limit("nonsense")


class TestRateLimiter:
    def test_allows_up_to_max(self):
        rl = _ConnRateLimiter("3/min")
        assert rl.take() is True
        assert rl.take() is True
        assert rl.take() is True
        assert rl.take() is False

    def test_window_expiry_releases_slots(self, monkeypatch):
        rl = _ConnRateLimiter("2/min")
        rl.take()
        rl.take()
        assert rl.take() is False
        # Pretend 61 seconds passed by rewinding the recorded timestamps.
        rl._timestamps = [t - 61 for t in rl._timestamps]
        assert rl.take() is True


class TestQuote:
    def test_simple(self):
        assert _quote("user") == b'"user"'

    def test_escapes_quote(self):
        assert _quote('he"llo') == b'"he\\"llo"'

    def test_escapes_backslash(self):
        assert _quote("a\\b") == b'"a\\\\b"'


class TestExtractMailbox:
    def test_atom(self):
        assert _extract_mailbox(b"INBOX\r\n") == "INBOX"

    def test_atom_with_args(self):
        assert _extract_mailbox(b"INBOX (UNSEEN)\r\n") == "INBOX"

    def test_quoted(self):
        assert _extract_mailbox(b'"My Folder"\r\n') == "My Folder"

    def test_quoted_with_escape(self):
        assert _extract_mailbox(b'"foo\\"bar"\r\n') == 'foo"bar'

    def test_literal_returns_none(self):
        assert _extract_mailbox(b"{12}\r\n") is None

    def test_empty_returns_none(self):
        assert _extract_mailbox(b"\r\n") is None


# ── End-to-end relay sessions ───────────────────────────


@pytest.fixture(autouse=True)
def _imap_creds(monkeypatch):
    monkeypatch.setenv("TEST_IMAP_USER", "real-user@example.com")
    monkeypatch.setenv("TEST_IMAP_PASS", "real-app-password")


def _run(coro):
    """Helper for non-async tests."""
    return asyncio.run(coro)


class TestUpstreamAuthInjection:
    """Cage sends nothing; relay LOGINs upstream with the real password."""

    def test_relay_authenticates_upstream(self):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                async with _running_relay(_relay_entry(up_port)) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        # Cage receives PREAUTH greeting.
                        greeting = await reader.readline()
                        assert greeting.startswith(b"* PREAUTH")
                        # Cage issues NOOP without ever sending a password.
                        writer.write(b"a1 NOOP\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                        assert b"OK" in line
                # Upstream saw a LOGIN with the real credentials.
                assert recorder.login_seen == (
                    "real-user@example.com", "real-app-password",
                )
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_cage_login_attempt_does_not_reach_upstream(self):
        """If the cage tries LOGIN on the PREAUTH'd connection, the relay
        intercepts and forges an OK — the spurious LOGIN must NOT travel
        upstream where it would replace our real credentials with garbage.
        """
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                async with _running_relay(_relay_entry(up_port)) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()  # PREAUTH
                        writer.write(b'a1 LOGIN "fake" "fake"\r\n')
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                        assert b"OK" in line
                # Upstream commands list: only the relay-issued LOGIN,
                # plus whatever followed (none here). The fake LOGIN
                # bytes from the cage must not appear.
                upstream_cmds = b"".join(recorder.commands)
                assert b'"fake"' not in upstream_cmds
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


class TestReadOnlyPolicy:
    def test_append_blocked(self):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                entry = _relay_entry(up_port, readonly=True)
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 APPEND INBOX {3}\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                        assert line.startswith(b"a1 NO")
                        assert b"readonly" in line
                # Upstream must not have seen APPEND.
                assert all(
                    not c.upper().startswith(b"APPEND")
                    for c in recorder.commands
                )
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_select_still_allowed_in_readonly(self):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                entry = _relay_entry(up_port, readonly=True)
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 SELECT INBOX\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                        assert line.startswith(b"a1 OK")
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


class TestFolderAllowlist:
    def test_select_outside_allowlist_blocked(self):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                entry = _relay_entry(up_port, folder_allowlist=["INBOX"])
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 SELECT Trash\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                        assert line.startswith(b"a1 NO")
                        assert b"folder_allowlist" in line
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_select_in_allowlist_allowed(self):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                entry = _relay_entry(up_port, folder_allowlist=["INBOX"])
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 SELECT INBOX\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                        assert line.startswith(b"a1 OK")
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_examine_outside_allowlist_blocked(self):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                entry = _relay_entry(up_port, folder_allowlist=["INBOX"])
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 EXAMINE Trash\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                        assert line.startswith(b"a1 NO")
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_list_unaffected_by_allowlist(self):
        """LIST is metadata-only and intentionally bypasses folder filter."""
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                entry = _relay_entry(up_port, folder_allowlist=["INBOX"])
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b'a1 LIST "" "*"\r\n')
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                        assert line.startswith(b"a1 OK")
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


class TestRateLimit:
    def test_excess_connections_refused(self):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                entry = _relay_entry(up_port, conn_rate_limit="2/min")
                async with _running_relay(entry) as (_, port):
                    # First two connections succeed (PREAUTH greeting).
                    for _ in range(2):
                        async with _imap_client(port) as (r, _w):
                            assert (await r.readline()).startswith(b"* PREAUTH")
                    # Third should get BYE rate limit.
                    async with _imap_client(port) as (r, _w):
                        line = await r.readline()
                        assert b"BYE" in line and b"rate" in line
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


class TestUpstreamLoginFailure:
    def test_failure_propagates_to_client(self):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
                fail_login=True,
            )
            try:
                async with _running_relay(_relay_entry(up_port)) as (_, port):
                    async with _imap_client(port) as (reader, _w):
                        line = await reader.readline()
                        assert b"BYE" in line and b"auth failed" in line
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── Constructor / init validation ───────────────────────


class TestConstruction:
    def test_missing_credentials_raises(self, monkeypatch):
        monkeypatch.delenv("TEST_IMAP_USER", raising=False)
        monkeypatch.delenv("TEST_IMAP_PASS", raising=False)
        with pytest.raises(ValueError, match="credentials not resolved"):
            ImapRelay(_relay_entry(1))

    def test_invalid_listen_raises_at_start(self):
        async def _go():
            entry = _relay_entry(1, listen="not-a-host:port")
            relay = ImapRelay(entry)
            with pytest.raises(ValueError, match="invalid listen"):
                await relay.start()
        _run(_go())


# ── A3: UID subcommand-aware readonly policy ─────────────


class TestUidReadonlyPolicy:
    """`UID FETCH`/`UID SEARCH` are reads and must work in readonly mode.
    `UID STORE`/`COPY`/`MOVE`/`EXPUNGE` mutate state and must be blocked.
    Pre-fix, bare `UID` was deny-listed and broke every modern client.
    """

    def _readonly_with_upstream(self):
        return _start_fake_upstream(
            FakeUpstreamRecorder(),
            "real-user@example.com",
            "real-app-password",
        )

    def test_uid_fetch_allowed_in_readonly(self):
        """REGRESSION: bare-UID deny used to block this."""
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                entry = _relay_entry(up_port, readonly=True)
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 UID FETCH 1:* (FLAGS)\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                        assert line.startswith(b"a1 OK"), line
                # Upstream must have actually seen UID FETCH.
                assert any(
                    b"UID FETCH" in c.upper()
                    for c in recorder.commands
                ), recorder.commands
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_uid_search_allowed_in_readonly(self):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                entry = _relay_entry(up_port, readonly=True)
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 UID SEARCH ALL\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                        assert line.startswith(b"a1 OK"), line
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    @pytest.mark.parametrize("subcmd", [b"STORE", b"COPY", b"MOVE", b"EXPUNGE"])
    def test_uid_writes_blocked_in_readonly(self, subcmd):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                entry = _relay_entry(up_port, readonly=True)
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        # Use a permissive payload; we only care that
                        # the command never reaches upstream.
                        writer.write(b"a1 UID " + subcmd + b" 1 X\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                        assert line.startswith(b"a1 NO"), line
                        assert b"readonly" in line
                # Upstream must NOT have seen this UID subcommand.
                assert all(
                    b"UID " + subcmd not in c.upper()
                    for c in recorder.commands
                ), recorder.commands
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── A4: PREAUTH forwards upstream CAPABILITY ─────────────


class TestPreAuthCapabilityForwarding:
    def test_forwards_upstream_capability_from_greeting(self):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder,
                "real-user@example.com",
                "real-app-password",
                greeting=(
                    b"* OK [CAPABILITY IMAP4rev1 IDLE MOVE NAMESPACE] "
                    b"upstream ready\r\n"
                ),
            )
            try:
                async with _running_relay(_relay_entry(up_port)) as (_, port):
                    async with _imap_client(port) as (reader, _w):
                        greeting = await reader.readline()
                        assert greeting.startswith(b"* PREAUTH ")
                        assert b"IDLE" in greeting
                        assert b"MOVE" in greeting
                        assert b"NAMESPACE" in greeting
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_strips_compress_deflate(self):
        """COMPRESS=DEFLATE wraps the byte stream and would blind the
        relay's command-level policy. Must be filtered out."""
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder,
                "real-user@example.com",
                "real-app-password",
                greeting=(
                    b"* OK [CAPABILITY IMAP4rev1 IDLE COMPRESS=DEFLATE] "
                    b"upstream ready\r\n"
                ),
            )
            try:
                async with _running_relay(_relay_entry(up_port)) as (_, port):
                    async with _imap_client(port) as (reader, _w):
                        greeting = await reader.readline()
                        assert greeting.startswith(b"* PREAUTH ")
                        assert b"IDLE" in greeting
                        assert b"COMPRESS" not in greeting
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_falls_back_to_imap4rev1_when_no_capability_advertised(self):
        async def _go():
            # Greeting without bracketed CAPABILITY; the relay should
            # still serve a valid PREAUTH greeting. (The relay also
            # issues an explicit CAPABILITY command in this case; the
            # fake upstream OK-replies to it as `OK CAPABILITY completed`
            # which has no CAPABILITY tokens, so the fallback engages.)
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder,
                "real-user@example.com",
                "real-app-password",
                greeting=b"* OK plain ready\r\n",
            )
            try:
                async with _running_relay(_relay_entry(up_port)) as (_, port):
                    async with _imap_client(port) as (reader, _w):
                        greeting = await reader.readline()
                        assert greeting.startswith(
                            b"* PREAUTH [CAPABILITY IMAP4rev1] "
                        )
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── T1: upstream connection failure surfaces as `* BYE` ──


class TestUpstreamUnreachable:
    def test_connect_refused_sends_bye(self):
        async def _go():
            # Find a port that's certain to refuse: bind+close one
            # right before pointing the relay at it.
            tmp = await asyncio.start_server(
                lambda r, w: None, "127.0.0.1", 0
            )
            dead_port = tmp.sockets[0].getsockname()[1]
            tmp.close()
            await tmp.wait_closed()

            entry = _relay_entry(dead_port)
            async with _running_relay(entry) as (_, port):
                async with _imap_client(port) as (reader, _w):
                    line = await reader.readline()
                    assert b"BYE" in line
                    assert b"upstream unreachable" in line

        _run(_go())


# ── A2: structured audit log per decision ────────────────


class TestAuditLogIntegration:
    def test_block_decision_emits_structured_audit_entry(self):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            entries: list[dict] = []

            relay = ImapRelay(
                _relay_entry(up_port, readonly=True),
                audit_log=entries.append,
            )
            await relay.start()
            try:
                port = relay._server.sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", port
                )
                try:
                    await reader.readline()  # PREAUTH
                    writer.write(b"a1 APPEND INBOX (\\Seen) {3}\r\n")
                    await writer.drain()
                    await _read_until_tag(reader, b"a1")
                finally:
                    writer.close()
                    await writer.wait_closed()
            finally:
                await relay.stop()
                upstream.close()
                await upstream.wait_closed()

            blocks = [
                e for e in entries
                if e.get("kind") == "imap_command"
                and e.get("decision") == "blocked"
            ]
            assert blocks, entries
            assert blocks[0]["command"] == "APPEND"
            assert blocks[0]["relay"]
            assert "readonly" in blocks[0]["reason"]

        _run(_go())

    def test_upstream_unreachable_emits_audit_entry(self):
        async def _go():
            tmp = await asyncio.start_server(
                lambda r, w: None, "127.0.0.1", 0
            )
            dead_port = tmp.sockets[0].getsockname()[1]
            tmp.close()
            await tmp.wait_closed()

            entries: list[dict] = []
            relay = ImapRelay(_relay_entry(dead_port), audit_log=entries.append)
            await relay.start()
            try:
                port = relay._server.sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", port
                )
                try:
                    await reader.readline()
                finally:
                    writer.close()
                    await writer.wait_closed()
            finally:
                await relay.stop()

            assert any(
                e.get("kind") == "imap_upstream_unreachable"
                for e in entries
            ), entries

        _run(_go())


# ── C4: per-command "allowed" log level ──────────────────


class TestAllowedLogLevel:
    def test_allowed_logs_at_debug_by_default(self, caplog):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                async with _running_relay(_relay_entry(up_port)) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 NOOP\r\n")
                        await writer.drain()
                        await _read_until_tag(reader, b"a1")
            finally:
                upstream.close()
                await upstream.wait_closed()

        import logging as _logging
        with caplog.at_level(_logging.DEBUG, logger="agentcage.relays.imap"):
            _run(_go())

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == _logging.DEBUG
            and "allowed" in r.getMessage()
        ]
        info_msgs = [
            r for r in caplog.records
            if r.levelno == _logging.INFO
            and "allowed NOOP" in r.getMessage()
        ]
        assert debug_msgs, "expected DEBUG-level allowed log"
        assert not info_msgs, "default mode must not emit INFO for allowed cmds"

    def test_allowed_logs_at_info_when_log_allowed_true(self, caplog):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            try:
                relay = ImapRelay(_relay_entry(up_port), log_allowed=True)
                await relay.start()
                try:
                    port = relay._server.sockets[0].getsockname()[1]
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", port
                    )
                    try:
                        await reader.readline()
                        writer.write(b"a1 NOOP\r\n")
                        await writer.drain()
                        await _read_until_tag(reader, b"a1")
                    finally:
                        writer.close()
                        await writer.wait_closed()
                finally:
                    await relay.stop()
            finally:
                upstream.close()
                await upstream.wait_closed()

        import logging as _logging
        with caplog.at_level(_logging.INFO, logger="agentcage.relays.imap"):
            _run(_go())

        info_msgs = [
            r for r in caplog.records
            if r.levelno == _logging.INFO
            and "allowed NOOP" in r.getMessage()
        ]
        assert info_msgs, "log_allowed=True must promote allowed to INFO"


# ── C3: shared validation module ─────────────────────────


class TestSharedValidation:
    def test_validate_rejects_invalid_port(self):
        from relays._validate import validate_relay_entry
        with pytest.raises(ValueError, match="upstream requires"):
            validate_relay_entry({
                "name": "r", "type": "imap", "listen": "127.0.0.1:1143",
                "upstream": {"host": "example.com", "port": 0},
            })

    def test_validate_rejects_unknown_type(self):
        from relays._validate import validate_relay_entry
        with pytest.raises(ValueError, match="unknown protocol_relays type"):
            validate_relay_entry({
                "name": "r", "type": "xmpp", "listen": "127.0.0.1:5222",
                "upstream": {"host": "example.com", "port": 5222},
            })

    def test_validate_rejects_missing_required(self):
        from relays._validate import validate_relay_entry
        with pytest.raises(ValueError, match="requires name/type/listen"):
            validate_relay_entry({"type": "imap", "listen": "127.0.0.1:1143"})

    def test_validate_passes_well_formed(self):
        from relays._validate import validate_relay_entry
        validate_relay_entry({
            "name": "r", "type": "imap", "listen": "127.0.0.1:1143",
            "upstream": {"host": "imap.example.com", "port": 993},
        })  # no exception

    def _entry(self, **upstream) -> dict:
        entry = {
            "name": "r", "type": "imap", "listen": "127.0.0.1:1143",
            "upstream": {"host": "imap.example.com", "port": 993},
        }
        entry["upstream"].update(upstream)
        return entry

    def test_validate_rejects_ca_pem_that_is_a_path(self):
        """The commonest mistake: `ca_pem: /certs/bridge.pem`. The error
        points at ca_file rather than letting a path be loaded as PEM and
        fail at connect time instead of config time.
        """
        from relays._validate import validate_relay_entry
        with pytest.raises(ValueError, match="does not look like"):
            validate_relay_entry(self._entry(ca_pem="/certs/bridge.pem"))

    def test_validate_rejects_non_string_ca_pem(self):
        from relays._validate import validate_relay_entry
        with pytest.raises(ValueError, match="must be a PEM string"):
            validate_relay_entry(self._entry(ca_pem=["cert"]))

    def test_validate_rejects_pin_on_plaintext_upstream(self):
        """A CA next to `tls: false` reads as "verified" in review but
        verifies nothing — reject rather than silently ignore.
        """
        from relays._validate import validate_relay_entry
        pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        with pytest.raises(ValueError, match="requires upstream.tls: true"):
            validate_relay_entry(self._entry(tls=False, ca_pem=pem))

    def test_validate_rejects_servername_on_plaintext_upstream(self):
        from relays._validate import validate_relay_entry
        with pytest.raises(ValueError, match="requires upstream.tls: true"):
            validate_relay_entry(
                self._entry(tls=False, tls_servername="bridge.local")
            )

    def test_validate_rejects_non_string_ca_file(self):
        from relays._validate import validate_relay_entry
        with pytest.raises(ValueError, match="must be a path string"):
            validate_relay_entry(self._entry(ca_file=["/certs/x.pem"]))

    def test_validate_rejects_ca_file_and_ca_pem_together(self):
        """Ambiguous about which wins — say so rather than pick silently."""
        from relays._validate import validate_relay_entry
        pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        with pytest.raises(ValueError, match="both ca_file and ca_pem"):
            validate_relay_entry(self._entry(ca_file="/c.pem", ca_pem=pem))

    def test_validate_rejects_ca_file_on_plaintext_upstream(self):
        from relays._validate import validate_relay_entry
        with pytest.raises(ValueError, match="requires upstream.tls: true"):
            validate_relay_entry(self._entry(tls=False, ca_file="/c.pem"))

    def test_validate_passes_upstream_with_ca_file(self):
        from relays._validate import validate_relay_entry
        validate_relay_entry(
            self._entry(ca_file="/certs/bridge.pem",
                        tls_servername="bridge.local")
        )  # no exception

    def test_validate_passes_upstream_with_extra_ca(self):
        from relays._validate import validate_relay_entry
        pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        validate_relay_entry(
            self._entry(ca_pem=pem, tls_servername="bridge.local")
        )  # no exception



# ── A2: idle timeout in pre-bridge phase ────────────────


class TestImapIdleTimeout:
    """A cage that opens the IMAP listener but never speaks (or whose
    upstream goes silent during auth) must not pin the connection slot
    forever. The bridge phase intentionally has no timeout because IMAP
    IDLE legitimately sits quiet for ~29 minutes between heartbeats
    (RFC 2177); only pre-bridge auth reads enforce the cap.
    """

    def test_silent_upstream_during_auth_surfaces_bye(self):
        async def _go():
            # Fake upstream that accepts the TCP connection but never
            # sends the * OK greeting. We block on `reader.read()` so
            # the handler exits as soon as the relay closes its end —
            # if we used `asyncio.sleep` here, `Server.wait_closed()`
            # in the cleanup would block on the still-running task.
            async def _silent(reader, writer):
                try:
                    await reader.read()  # exits at EOF
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            silent = await asyncio.start_server(_silent, "127.0.0.1", 0)
            silent_port = silent.sockets[0].getsockname()[1]
            try:
                entry = _relay_entry(silent_port)
                entry["policy"]["idle_timeout_seconds"] = 1
                async with _running_relay(entry) as (_, port):
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", port,
                    )
                    try:
                        line = await asyncio.wait_for(
                            reader.readline(), timeout=5,
                        )
                        assert line.startswith(b"* BYE"), line
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
            finally:
                silent.close()
                await silent.wait_closed()

        _run(_go())


# ── write_mode: organise ─────────────────────────────────


class TestWriteModeOrganise:
    """`organise` lets an agent file and flag mail but never destroy it.

    The motivating case: an assistant reading someone else's mailbox should
    be able to tidy it — move to folders, move to Trash, mark read — while
    being unable to remove anything permanently, because that failure is
    silent and irreversible.
    """

    def _relay(self, upstream_port: int, **policy):
        entry = _relay_entry(upstream_port)
        entry["policy"] = {**entry.get("policy", {}), **policy}
        return entry

    def _send(self, upstream_port, command: bytes, **policy):
        """Send one command through the relay, return its tagged response."""
        async def _go():
            entry = self._relay(upstream_port, **policy)
            async with _running_relay(entry) as (_, port):
                async with _imap_client(port) as (reader, writer):
                    await reader.readline()  # PREAUTH
                    writer.write(command)
                    await writer.drain()
                    return await _read_until_tag(reader, b"a1")
        return _run(_go())

    def _with_upstream(self, fn):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password")
            try:
                return await fn(port, recorder)
            finally:
                upstream.close()
                await upstream.wait_closed()
        return _run(_go())

    # -- allowed in organise --------------------------------------------

    @pytest.mark.parametrize("command", [
        b'a1 MOVE 1 "Trash"\r\n',
        b'a1 UID MOVE 5 "Folders/Bills"\r\n',
        b'a1 COPY 1 "Archive"\r\n',
        b'a1 STORE 1 +FLAGS (\\Seen)\r\n',
        b'a1 UID STORE 5 +FLAGS.SILENT (\\Flagged)\r\n',
        b'a1 STORE 1 -FLAGS (\\Deleted)\r\n',   # un-deleting is fine
    ])
    def test_filing_and_flagging_pass_through(self, command):
        async def _check(port, recorder):
            entry = self._relay(port, write_mode="organise")
            async with _running_relay(entry) as (_, p):
                async with _imap_client(p) as (reader, writer):
                    await reader.readline()
                    writer.write(command)
                    await writer.drain()
                    await asyncio.sleep(0.05)
            return recorder.commands
        cmds = self._with_upstream(_check)
        # reached the upstream rather than being forged back by the relay
        assert any(command.split(b" ", 1)[1] in c for c in cmds), cmds

    # -- denied in organise ---------------------------------------------

    @pytest.mark.parametrize("command,label", [
        (b"a1 EXPUNGE\r\n", "EXPUNGE"),
        (b"a1 UID EXPUNGE 5\r\n", "UID EXPUNGE"),
        (b"a1 CLOSE\r\n", "CLOSE"),
        (b'a1 APPEND "INBOX" {3}\r\n', "APPEND"),
        (b'a1 DELETE "Archive"\r\n', "DELETE"),
        (b'a1 CREATE "New"\r\n', "CREATE"),
        (b'a1 RENAME "a" "b"\r\n', "RENAME"),
    ])
    def test_destructive_commands_refused(self, command, label):
        def _check(port, recorder):
            async def _inner():
                entry = self._relay(port, write_mode="organise")
                async with _running_relay(entry) as (_, p):
                    async with _imap_client(p) as (reader, writer):
                        await reader.readline()
                        writer.write(command)
                        await writer.drain()
                        return await _read_until_tag(reader, b"a1")
            return _inner()
        line = self._with_upstream(lambda port, rec: _check(port, rec))
        assert b"NO" in line, (label, line)
        assert b"organise" in line, (label, line)

    def test_close_is_refused_because_it_expunges(self):
        """RFC 3501 §6.4.2: CLOSE expunges \\Deleted as a side effect.

        Denying EXPUNGE while allowing CLOSE would leave the destructive
        path open behind an innocuous verb, so this is not merely tidiness.
        """
        def _check(port, recorder):
            async def _inner():
                entry = self._relay(port, write_mode="organise")
                async with _running_relay(entry) as (_, p):
                    async with _imap_client(p) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 CLOSE\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                await asyncio.sleep(0.05)
                return line, recorder.commands
            return _inner()
        line, cmds = self._with_upstream(lambda p, r: _check(p, r))
        assert b"NO" in line
        assert not any(b"CLOSE" in c for c in cmds), "CLOSE reached upstream"

    @pytest.mark.parametrize("command", [
        b"a1 STORE 1 +FLAGS (\\Deleted)\r\n",
        b"a1 STORE 1 FLAGS (\\Deleted \\Seen)\r\n",
        b"a1 UID STORE 5 +FLAGS.SILENT (\\Deleted)\r\n",
        b"a1 store 1 +flags (\\deleted)\r\n",          # case-insensitive
    ])
    def test_setting_the_deleted_flag_is_refused(self, command):
        """Refusing the flag, not just EXPUNGE, means an expunge reached by
        any other route has nothing to reap."""
        def _check(port, recorder):
            async def _inner():
                entry = self._relay(port, write_mode="organise")
                async with _running_relay(entry) as (_, p):
                    async with _imap_client(p) as (reader, writer):
                        await reader.readline()
                        writer.write(command)
                        await writer.drain()
                        return await _read_until_tag(reader, b"a1")
            return _inner()
        line = self._with_upstream(lambda p, r: _check(p, r))
        assert b"NO" in line, line
        assert b"Deleted" in line or b"organise" in line, line


class TestFolderDenylist:
    def _entry(self, upstream_port, **policy):
        entry = _relay_entry(upstream_port)
        entry["policy"] = {**entry.get("policy", {}), **policy}
        return entry

    def _select(self, mailbox: bytes, **policy):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password")
            try:
                async with _running_relay(self._entry(port, **policy)) as (_, p):
                    async with _imap_client(p) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 SELECT " + mailbox + b"\r\n")
                        await writer.drain()
                        return await _read_until_tag(reader, b"a1")
            finally:
                upstream.close()
                await upstream.wait_closed()
        return _run(_go())

    def test_denied_folder_refused(self):
        line = self._select(b'"Trash"', folder_denylist=["Trash"])
        assert b"NO" in line and b"folder_denylist" in line, line

    def test_other_folders_still_selectable(self):
        line = self._select(b'"INBOX"', folder_denylist=["Trash"])
        assert b"OK" in line, line

    def test_denylist_is_case_insensitive(self):
        """Servers disagree on the case of special-use mailbox names; a
        denylist that missed `trash` because the server said `Trash` would
        fail open, which is the wrong direction for this list."""
        line = self._select(b'"trash"', folder_denylist=["Trash"])
        assert b"NO" in line, line

    def test_denylist_beats_allowlist(self):
        line = self._select(
            b'"Trash"',
            folder_allowlist=["INBOX", "Trash"],
            folder_denylist=["Trash"],
        )
        assert b"NO" in line and b"folder_denylist" in line, line


class TestWriteModeValidation:
    def _entry(self, **policy) -> dict:
        return {
            "name": "r", "type": "imap", "listen": "127.0.0.1:1143",
            "upstream": {"host": "imap.example.com", "port": 993},
            "policy": policy,
        }

    def test_rejects_unknown_mode(self):
        from relays._validate import validate_relay_entry
        with pytest.raises(ValueError, match="write_mode must be one of"):
            validate_relay_entry(self._entry(write_mode="readonlyish"))

    def test_rejects_contradicting_readonly(self):
        """readonly: true + write_mode: full is ambiguous. Guessing which
        the operator meant is the wrong call for a policy gating writes."""
        from relays._validate import validate_relay_entry
        with pytest.raises(ValueError, match="contradict"):
            validate_relay_entry(self._entry(readonly=True, write_mode="full"))

    def test_allows_consistent_pair(self):
        from relays._validate import validate_relay_entry
        validate_relay_entry(self._entry(readonly=True, write_mode="none"))

    def test_rejects_non_list_denylist(self):
        from relays._validate import validate_relay_entry
        with pytest.raises(ValueError, match="folder_denylist must be a list"):
            validate_relay_entry(self._entry(folder_denylist="Trash"))

    def test_accepts_organise(self):
        from relays._validate import validate_relay_entry
        validate_relay_entry(
            self._entry(write_mode="organise", folder_denylist=["Trash"])
        )


class TestWriteModeDefaults:
    """Existing configs must behave exactly as before."""

    def _cfg(self, **policy):
        from relays.imap import _RelayConfig
        return _RelayConfig({
            "name": "r", "type": "imap", "listen": "127.0.0.1:0",
            "upstream": {"host": "h", "port": 1}, "policy": policy,
        })

    def test_readonly_true_maps_to_none(self):
        assert self._cfg(readonly=True).write_mode == "none"

    def test_readonly_false_maps_to_full(self):
        assert self._cfg(readonly=False).write_mode == "full"

    def test_absent_policy_maps_to_full(self):
        assert self._cfg().write_mode == "full"

    def test_explicit_write_mode_wins(self):
        assert self._cfg(write_mode="organise").write_mode == "organise"
