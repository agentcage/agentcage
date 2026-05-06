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


# ── require_authentication: filtering tests ────────────


from relays import _imap_responses


class TestEvaluateAuthenticationResults:
    """Pure-function check on the Authentication-Results evaluator."""

    def test_all_pass(self):
        h = "m8i.io; dkim=pass header.d=luca.io; spf=pass; dmarc=pass"
        assert _imap_responses.evaluate_authentication_results(h) is True

    def test_dkim_fail(self):
        h = "m8i.io; dkim=fail; spf=pass; dmarc=pass"
        assert _imap_responses.evaluate_authentication_results(h) is False

    def test_spf_temperror(self):
        h = "m8i.io; dkim=pass; spf=temperror; dmarc=pass"
        assert _imap_responses.evaluate_authentication_results(h) is False

    def test_dmarc_missing(self):
        h = "m8i.io; dkim=pass; spf=pass"
        assert _imap_responses.evaluate_authentication_results(h) is False

    def test_empty(self):
        assert _imap_responses.evaluate_authentication_results("") is False

    def test_folded_header(self):
        h = "m8i.io;\n\tdkim=pass header.d=luca.io;\n\tspf=pass;\n\tdmarc=pass"
        assert _imap_responses.evaluate_authentication_results(h) is True

    def test_first_occurrence_wins_for_relayed_results(self):
        # If an upstream re-stamp says fail then a later hop says pass,
        # the receiver-of-record (first stamp) decides.
        h = "m8i.io; dkim=fail; dkim=pass; spf=pass; dmarc=pass"
        assert _imap_responses.evaluate_authentication_results(h) is False


class TestParseSearchResponseLine:
    def test_with_uids(self):
        assert _imap_responses.parse_search_response_line(
            b"* SEARCH 12 17 23\r\n"
        ) == [12, 17, 23]

    def test_empty_search(self):
        assert _imap_responses.parse_search_response_line(
            b"* SEARCH\r\n"
        ) == []

    def test_not_a_search_line(self):
        assert _imap_responses.parse_search_response_line(
            b"* OK something\r\n"
        ) is None

    def test_garbage_uids_returns_none(self):
        assert _imap_responses.parse_search_response_line(
            b"* SEARCH 12 not-a-uid 23\r\n"
        ) is None


class TestEncodeSearchResponse:
    def test_with_uids(self):
        assert _imap_responses.encode_search_response([1, 2, 3]) == \
            b"* SEARCH 1 2 3\r\n"

    def test_empty(self):
        assert _imap_responses.encode_search_response([]) == b"* SEARCH\r\n"


class TestExtractAuthenticationResults:
    def test_simple(self):
        blob = (
            b"Authentication-Results: m8i.io; dkim=pass; spf=pass; "
            b"dmarc=pass\r\n\r\n"
        )
        v = _imap_responses.extract_authentication_results(blob)
        assert v is not None
        assert "dkim=pass" in v

    def test_folded(self):
        blob = (
            b"Authentication-Results: m8i.io;\r\n"
            b"\tdkim=pass header.d=luca.io;\r\n"
            b"\tspf=pass;\r\n"
            b"\tdmarc=pass\r\n\r\n"
        )
        v = _imap_responses.extract_authentication_results(blob)
        assert v is not None
        assert _imap_responses.evaluate_authentication_results(v) is True

    def test_missing(self):
        blob = b"Subject: hi\r\n\r\n"
        assert _imap_responses.extract_authentication_results(blob) is None


class TestFetchResponseParser:
    def test_single_record(self):
        blob = (
            b"Authentication-Results: m8i.io; dkim=pass; spf=pass; "
            b"dmarc=pass\r\n\r\n"
        )
        chunk = (
            b"* 1 FETCH (UID 12 BODY[HEADER.FIELDS (AUTHENTICATION-RESULTS)] {"
            + str(len(blob)).encode() + b"}\r\n"
            + blob
            + b")\r\n"
            b"r0001 OK FETCH completed\r\n"
        )
        parser = _imap_responses.FetchResponseParser()
        parser.feed(chunk)
        records = parser.take_fetched()
        assert len(records) == 1
        uid, body = records[0]
        assert uid == 12
        assert b"dkim=pass" in body
        assert parser.tagged_response is not None
        assert parser.tagged_response.startswith(b"r0001 OK")

    def test_multiple_records(self):
        def _record(seq, uid, header):
            return (
                f"* {seq} FETCH (UID {uid} BODY[HEADER.FIELDS "
                f"(AUTHENTICATION-RESULTS)] ".encode()
                + b"{" + str(len(header)).encode() + b"}\r\n"
                + header
                + b")\r\n"
            )
        h_pass = b"Authentication-Results: m8i.io; dkim=pass; spf=pass; dmarc=pass\r\n\r\n"
        h_fail = b"Authentication-Results: m8i.io; dkim=fail; spf=pass; dmarc=pass\r\n\r\n"
        chunks = (
            _record(1, 100, h_pass)
            + _record(2, 101, h_fail)
            + b"r0001 OK FETCH completed\r\n"
        )
        parser = _imap_responses.FetchResponseParser()
        parser.feed(chunks)
        records = parser.take_fetched()
        assert [uid for uid, _ in records] == [100, 101]

    def test_split_across_feeds(self):
        blob = b"Authentication-Results: m8i.io; dkim=pass; spf=pass; dmarc=pass\r\n\r\n"
        full = (
            b"* 1 FETCH (UID 12 BODY[HEADER.FIELDS (AUTHENTICATION-RESULTS)] {"
            + str(len(blob)).encode() + b"}\r\n"
            + blob
            + b")\r\n"
            b"r0001 OK FETCH completed\r\n"
        )
        parser = _imap_responses.FetchResponseParser()
        # Feed in awkward 7-byte chunks.
        for i in range(0, len(full), 7):
            parser.feed(full[i:i + 7])
        records = parser.take_fetched()
        assert len(records) == 1
        assert records[0][0] == 12


# ── End-to-end filtering ───────────────────────────────


@dataclass
class _FakeMessage:
    uid: int
    authres: str  # the inside of the Authentication-Results header


async def _start_filtering_upstream(
    messages: list[_FakeMessage],
    *,
    expected_user: str = "real-user@example.com",
    expected_pass: str = "real-app-password",
) -> tuple[asyncio.AbstractServer, int, "list[bytes]"]:
    """Fake upstream that handles LOGIN, EXAMINE, SEARCH ALL, and
    UID FETCH ... BODY[HEADER.FIELDS (Authentication-Results)].

    Returns (server, port, recorded_commands). One server instance can
    serve multiple connections (the relay opens a side-channel one for
    its own header fetches in addition to the main client connection).
    """
    recorded: list[bytes] = []

    by_uid = {m.uid: m for m in messages}

    async def _handle(reader, writer):
        try:
            writer.write(b"* OK [CAPABILITY IMAP4rev1] fake ready\r\n")
            await writer.drain()
            authed = False
            while True:
                line = await reader.readline()
                if not line:
                    return
                recorded.append(line)
                parts = line.split(b" ", 2)
                if len(parts) < 2:
                    continue
                tag = parts[0]
                cmd = parts[1].rstrip(b"\r\n").upper()
                rest = parts[2].rstrip(b"\r\n") if len(parts) >= 3 else b""

                if cmd == b"LOGIN":
                    sp = rest.split(b" ", 1)
                    user = sp[0].strip(b'"').decode()
                    pwd = (
                        sp[1].strip(b'"').decode() if len(sp) > 1 else ""
                    )
                    if user == expected_user and pwd == expected_pass:
                        writer.write(tag + b" OK LOGIN ok\r\n")
                        authed = True
                    else:
                        writer.write(tag + b" NO bad creds\r\n")
                    await writer.drain()
                    continue
                if not authed:
                    writer.write(tag + b" BAD must auth\r\n")
                    await writer.drain()
                    continue
                if cmd == b"EXAMINE" or cmd == b"SELECT":
                    writer.write(b"* " + str(len(messages)).encode()
                                 + b" EXISTS\r\n")
                    writer.write(tag + b" OK EXAMINE done\r\n")
                    await writer.drain()
                    continue
                if cmd == b"SEARCH" or (
                    cmd == b"UID" and rest.upper().startswith(b"SEARCH")
                ):
                    uids = sorted(by_uid)
                    if uids:
                        writer.write(
                            b"* SEARCH " + b" ".join(
                                str(u).encode() for u in uids
                            ) + b"\r\n"
                        )
                    else:
                        writer.write(b"* SEARCH\r\n")
                    writer.write(tag + b" OK SEARCH done\r\n")
                    await writer.drain()
                    continue
                if cmd == b"UID" and rest.upper().startswith(b"FETCH"):
                    after = rest.split(b" ", 1)[1] if b" " in rest else b""
                    uid_set = after.split(b" ", 1)[0]
                    target_uids: list[int] = []
                    for tok in uid_set.split(b","):
                        try:
                            target_uids.append(int(tok))
                        except ValueError:
                            pass
                    for uid in target_uids:
                        msg = by_uid.get(uid)
                        if msg is None:
                            continue
                        body = (
                            f"Authentication-Results: {msg.authres}\r\n\r\n"
                        ).encode()
                        prefix = (
                            f"* {uid} FETCH (UID {uid} BODY[HEADER.FIELDS "
                            f"(AUTHENTICATION-RESULTS)] ".encode()
                            + b"{" + str(len(body)).encode() + b"}\r\n"
                        )
                        writer.write(prefix + body + b")\r\n")
                    writer.write(tag + b" OK FETCH done\r\n")
                    await writer.drain()
                    continue
                if cmd == b"LOGOUT":
                    writer.write(b"* BYE\r\n")
                    writer.write(tag + b" OK LOGOUT\r\n")
                    await writer.drain()
                    return
                # Anything else: respond OK so capability/noop/etc. work.
                writer.write(tag + b" OK " + cmd + b" done\r\n")
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
    return server, port, recorded


def _filter_relay_entry(upstream_port: int) -> dict:
    return {
        "name": "filter-imap",
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
        "policy": {
            "require_authentication": True,
            "conn_rate_limit": "30/min",
        },
    }


async def _read_search_then_ok(
    reader: asyncio.StreamReader, tag: bytes,
) -> tuple[list[int], bytes]:
    """Read until the tagged response, returning (uids, tagged_line)."""
    uids: list[int] = []
    while True:
        line = await reader.readline()
        if not line:
            raise EOFError
        s = _imap_responses.parse_search_response_line(line)
        if s is not None:
            uids = s
            continue
        if line.startswith(tag + b" "):
            return uids, line


class TestRequireAuthentication:
    """Verify the inbound message inspector filters SEARCH responses."""

    def test_filters_failing_dkim(self):
        async def _go():
            messages = [
                _FakeMessage(10, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
                _FakeMessage(11, "m8i.io; dkim=fail; spf=pass; dmarc=pass"),
                _FakeMessage(12, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
            ]
            up, up_port, _ = await _start_filtering_upstream(messages)
            try:
                async with _running_relay(_filter_relay_entry(up_port)) as (
                    _, port,
                ):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()  # PREAUTH
                        writer.write(b"a1 EXAMINE INBOX\r\n")
                        await writer.drain()
                        await _read_until_tag(reader, b"a1")
                        writer.write(b"a2 UID SEARCH ALL\r\n")
                        await writer.drain()
                        uids, ok = await _read_search_then_ok(reader, b"a2")
                        assert b" OK " in ok
                        assert uids == [10, 12]
            finally:
                up.close()
                await up.wait_closed()
        _run(_go())

    def test_filters_missing_authentication_results_header(self):
        async def _go():
            messages = [
                _FakeMessage(10, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
                _FakeMessage(11, ""),  # empty header value → fail closed
                _FakeMessage(12, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
            ]
            up, up_port, _ = await _start_filtering_upstream(messages)
            try:
                async with _running_relay(_filter_relay_entry(up_port)) as (
                    _, port,
                ):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 EXAMINE INBOX\r\n")
                        await writer.drain()
                        await _read_until_tag(reader, b"a1")
                        writer.write(b"a2 UID SEARCH ALL\r\n")
                        await writer.drain()
                        uids, _ok = await _read_search_then_ok(reader, b"a2")
                        assert uids == [10, 12]
            finally:
                up.close()
                await up.wait_closed()
        _run(_go())

    def test_passes_when_all_messages_pass(self):
        async def _go():
            messages = [
                _FakeMessage(20, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
                _FakeMessage(21, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
            ]
            up, up_port, _ = await _start_filtering_upstream(messages)
            try:
                async with _running_relay(_filter_relay_entry(up_port)) as (
                    _, port,
                ):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 EXAMINE INBOX\r\n")
                        await writer.drain()
                        await _read_until_tag(reader, b"a1")
                        writer.write(b"a2 UID SEARCH ALL\r\n")
                        await writer.drain()
                        uids, _ok = await _read_search_then_ok(reader, b"a2")
                        assert uids == [20, 21]
            finally:
                up.close()
                await up.wait_closed()
        _run(_go())

    def test_drops_all_when_all_fail(self):
        async def _go():
            messages = [
                _FakeMessage(30, "m8i.io; dkim=fail; spf=pass; dmarc=pass"),
                _FakeMessage(31, "m8i.io; dkim=pass; spf=fail; dmarc=pass"),
            ]
            up, up_port, _ = await _start_filtering_upstream(messages)
            try:
                async with _running_relay(_filter_relay_entry(up_port)) as (
                    _, port,
                ):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 EXAMINE INBOX\r\n")
                        await writer.drain()
                        await _read_until_tag(reader, b"a1")
                        writer.write(b"a2 UID SEARCH ALL\r\n")
                        await writer.drain()
                        uids, ok = await _read_search_then_ok(reader, b"a2")
                        assert b" OK " in ok
                        assert uids == []
            finally:
                up.close()
                await up.wait_closed()
        _run(_go())

    def test_repeated_search_uses_per_session_cache(self):
        """A second SEARCH for the same UIDs must NOT trigger a second
        side-channel UID FETCH — verdicts are cached per session."""
        async def _go():
            messages = [
                _FakeMessage(40, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
                _FakeMessage(41, "m8i.io; dkim=fail; spf=pass; dmarc=pass"),
            ]
            up, up_port, recorded = await _start_filtering_upstream(messages)
            try:
                async with _running_relay(_filter_relay_entry(up_port)) as (
                    _, port,
                ):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 EXAMINE INBOX\r\n")
                        await writer.drain()
                        await _read_until_tag(reader, b"a1")
                        writer.write(b"a2 UID SEARCH ALL\r\n")
                        await writer.drain()
                        uids1, _ = await _read_search_then_ok(reader, b"a2")
                        writer.write(b"a3 UID SEARCH ALL\r\n")
                        await writer.drain()
                        uids2, _ = await _read_search_then_ok(reader, b"a3")
                        assert uids1 == [40] == uids2
                # Side-channel UID FETCH appeared exactly once.
                fetches = [
                    c for c in recorded
                    if b" UID " in c and b"FETCH" in c.upper()
                    and b"BODY.PEEK" in c.upper()
                ]
                assert len(fetches) == 1, fetches
            finally:
                up.close()
                await up.wait_closed()
        _run(_go())

    def test_sequence_numbered_fetch_rejected(self):
        async def _go():
            messages = [
                _FakeMessage(10, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
            ]
            up, up_port, _ = await _start_filtering_upstream(messages)
            try:
                async with _running_relay(_filter_relay_entry(up_port)) as (
                    _, port,
                ):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 EXAMINE INBOX\r\n")
                        await writer.drain()
                        await _read_until_tag(reader, b"a1")
                        writer.write(b"a2 FETCH 1:* (UID)\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a2")
                        assert b" NO " in line
                        assert b"UID" in line
            finally:
                up.close()
                await up.wait_closed()
        _run(_go())

    def test_sequence_numbered_store_rejected(self):
        async def _go():
            messages = [
                _FakeMessage(10, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
            ]
            up, up_port, _ = await _start_filtering_upstream(messages)
            try:
                async with _running_relay(_filter_relay_entry(up_port)) as (
                    _, port,
                ):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 EXAMINE INBOX\r\n")
                        await writer.drain()
                        await _read_until_tag(reader, b"a1")
                        writer.write(b"a2 STORE 1 +FLAGS \\Seen\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a2")
                        assert b" NO " in line
            finally:
                up.close()
                await up.wait_closed()
        _run(_go())

    def test_uid_fetch_passes_through_unchanged(self):
        """UID FETCH for a known-passing UID must return real data —
        the relay only filters SEARCH, FETCH responses are pass-through.
        """
        async def _go():
            messages = [
                _FakeMessage(50, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
            ]
            up, up_port, _ = await _start_filtering_upstream(messages)
            try:
                async with _running_relay(_filter_relay_entry(up_port)) as (
                    _, port,
                ):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 EXAMINE INBOX\r\n")
                        await writer.drain()
                        await _read_until_tag(reader, b"a1")
                        writer.write(b"a2 UID SEARCH ALL\r\n")
                        await writer.drain()
                        uids, _ = await _read_search_then_ok(reader, b"a2")
                        assert uids == [50]
                        writer.write(
                            b"a3 UID FETCH 50 (FLAGS)\r\n"
                        )
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a3")
                        assert b" OK " in line
            finally:
                up.close()
                await up.wait_closed()
        _run(_go())

    def test_disabled_by_default_no_filter(self):
        """With require_authentication unset, SEARCH responses are
        verbatim-forwarded — failing UIDs are visible."""
        async def _go():
            messages = [
                _FakeMessage(60, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
                _FakeMessage(61, "m8i.io; dkim=fail; spf=pass; dmarc=pass"),
            ]
            up, up_port, _ = await _start_filtering_upstream(messages)
            try:
                entry = _relay_entry(up_port)  # no require_authentication
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 EXAMINE INBOX\r\n")
                        await writer.drain()
                        await _read_until_tag(reader, b"a1")
                        writer.write(b"a2 UID SEARCH ALL\r\n")
                        await writer.drain()
                        uids, _ = await _read_search_then_ok(reader, b"a2")
                        assert uids == [60, 61]
            finally:
                up.close()
                await up.wait_closed()
        _run(_go())

    def test_sidechannel_fetch_failure_drops_all(self):
        """If the side-channel can't reach upstream (broken connection,
        bad credentials), every UID in the batch is dropped — fail closed."""
        async def _go():
            # Upstream that accepts the main connection's LOGIN+SEARCH
            # but refuses LOGIN on side-channel connections (after the
            # first one).
            login_count = [0]
            messages = [
                _FakeMessage(70, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
            ]
            by_uid = {m.uid: m for m in messages}

            async def _handle(reader, writer):
                try:
                    writer.write(
                        b"* OK [CAPABILITY IMAP4rev1] fake ready\r\n"
                    )
                    await writer.drain()
                    line = await reader.readline()
                    if not line:
                        return
                    parts = line.split(b" ", 2)
                    tag = parts[0]
                    cmd = parts[1].rstrip(b"\r\n").upper()
                    if cmd != b"LOGIN":
                        writer.write(tag + b" BAD\r\n")
                        await writer.drain()
                        return
                    login_count[0] += 1
                    if login_count[0] > 1:
                        writer.write(tag + b" NO bad creds\r\n")
                        await writer.drain()
                        return
                    writer.write(tag + b" OK LOGIN ok\r\n")
                    await writer.drain()
                    while True:
                        line = await reader.readline()
                        if not line:
                            return
                        parts = line.split(b" ", 2)
                        tag = parts[0]
                        cmd = parts[1].rstrip(b"\r\n").upper()
                        rest = parts[2].rstrip(b"\r\n") if len(parts) >= 3 else b""
                        if cmd in (b"EXAMINE", b"SELECT"):
                            writer.write(b"* 1 EXISTS\r\n")
                            writer.write(tag + b" OK done\r\n")
                            await writer.drain()
                            continue
                        if cmd == b"UID" and rest.upper().startswith(b"SEARCH"):
                            uids = sorted(by_uid)
                            writer.write(
                                b"* SEARCH " + b" ".join(
                                    str(u).encode() for u in uids
                                ) + b"\r\n"
                            )
                            writer.write(tag + b" OK done\r\n")
                            await writer.drain()
                            continue
                        writer.write(tag + b" OK\r\n")
                        await writer.drain()
                except (ConnectionResetError, BrokenPipeError):
                    pass
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            up = await asyncio.start_server(_handle, "127.0.0.1", 0)
            up_port = up.sockets[0].getsockname()[1]
            try:
                async with _running_relay(_filter_relay_entry(up_port)) as (
                    _, port,
                ):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()
                        writer.write(b"a1 EXAMINE INBOX\r\n")
                        await writer.drain()
                        await _read_until_tag(reader, b"a1")
                        writer.write(b"a2 UID SEARCH ALL\r\n")
                        await writer.drain()
                        uids, ok = await _read_search_then_ok(reader, b"a2")
                        # Side-channel can't auth → no verdicts → drop all.
                        assert uids == []
                        assert b" OK " in ok
            finally:
                up.close()
                await up.wait_closed()
        _run(_go())

    def test_capabilities_strip_esearch_when_filtering(self):
        async def _go():
            messages = [
                _FakeMessage(80, "m8i.io; dkim=pass; spf=pass; dmarc=pass"),
            ]
            # Override the greeting to advertise ESEARCH so we can check
            # the relay strips it.
            recorded: list[bytes] = []

            async def _handle(reader, writer):
                try:
                    writer.write(
                        b"* OK [CAPABILITY IMAP4rev1 ESEARCH IDLE] ready\r\n"
                    )
                    await writer.drain()
                    line = await reader.readline()
                    recorded.append(line)
                    parts = line.split(b" ", 2)
                    tag = parts[0]
                    writer.write(tag + b" OK LOGIN ok\r\n")
                    await writer.drain()
                    while True:
                        line = await reader.readline()
                        if not line:
                            return
                        recorded.append(line)
                        parts = line.split(b" ", 2)
                        tag = parts[0]
                        writer.write(tag + b" OK\r\n")
                        await writer.drain()
                except (ConnectionResetError, BrokenPipeError):
                    pass
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            up = await asyncio.start_server(_handle, "127.0.0.1", 0)
            up_port = up.sockets[0].getsockname()[1]
            try:
                async with _running_relay(_filter_relay_entry(up_port)) as (
                    _, port,
                ):
                    async with _imap_client(port) as (reader, _writer):
                        greeting = await reader.readline()
                        assert greeting.startswith(b"* PREAUTH")
                        # ESEARCH must be absent from the relay's
                        # advertised capability list.
                        assert b"ESEARCH" not in greeting
                        # IDLE remains.
                        assert b"IDLE" in greeting
            finally:
                up.close()
                await up.wait_closed()
        _run(_go())
