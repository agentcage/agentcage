"""End-to-end tests for the IMAP relay.

Strategy: spin up a fake upstream IMAP server, the relay, and a client
all in the test process on an asyncio loop. Each test orchestrates a
single client session, asserts on what the upstream actually saw, then
tears down. No real network, no TLS — TLS handling is exercised in
integration but bypassed here.
"""

from __future__ import annotations

import asyncio
import re
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
    # Every byte received after LOGIN, in order (literals=True only).
    raw: bytearray = field(default_factory=bytearray)


_UPSTREAM_LITERAL_RE = re.compile(rb"~?\{(\d+)(\+?)\}\r\n\Z")


async def _read_upstream_command(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    recorder: FakeUpstreamRecorder,
    refuse_literal: frozenset,
) -> tuple[bytes, bool]:
    """Read one whole command the way a server does, literals included.

    A synchronising literal is answered with ``+`` before its bytes are
    read, unless the command is in *refuse_literal*: then the server answers
    ``NO`` and the command ends there, its literal unsent. Returns the
    command's bytes (b"" at EOF) and whether it was refused that way.
    """
    cmd = b""
    while True:
        line = await reader.readline()
        recorder.raw += line
        cmd += line
        if not line:
            return cmd, False
        m = _UPSTREAM_LITERAL_RE.search(line)
        if m is None:
            return cmd, False
        if not m.group(2):
            name = cmd.split(None, 2)[1].upper()
            if name in refuse_literal:
                tag = cmd.split(None, 1)[0]
                writer.write(tag + b" NO [TRYCREATE] no such mailbox\r\n")
                await writer.drain()
                return cmd, True
            writer.write(b"+ go ahead\r\n")
            await writer.drain()
        payload = await reader.readexactly(int(m.group(1)))
        recorder.raw += payload
        cmd += payload


async def _start_fake_upstream(
    recorder: FakeUpstreamRecorder,
    expected_user: str,
    expected_pass: str,
    fail_login: bool = False,
    greeting: bytes = b"* OK [CAPABILITY IMAP4rev1] fake upstream ready\r\n",
    scripted: Optional[dict[bytes, list[bytes]]] = None,
    literals: bool = False,
    refuse_literal: frozenset = frozenset(),
) -> tuple[asyncio.AbstractServer, int]:
    """Start an asyncio TCP server pretending to be a Migadu IMAP host.

    ``scripted`` maps an upper-case command to the reply the upstream sends
    instead of its usual one-line OK: a list of chunks, each written and
    drained on its own with a pause in between so the relay reads them
    separately. ``<TAG>`` in a chunk is replaced with the command's tag.

    With ``literals``, commands are read whole, literals and all (see
    _read_upstream_command), each recorded as one entry in
    ``recorder.commands``, and ``IDLE`` is served: ``+ idling``, then
    ``OK`` on ``DONE`` or ``BAD`` (the line discarded) on anything else.
    """

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
                if literals:
                    line, refused = await _read_upstream_command(
                        reader, writer, recorder, refuse_literal,
                    )
                else:
                    line, refused = await reader.readline(), False
                if not line:
                    return
                recorder.commands.append(line)
                if refused:
                    continue
                parts = line.split(b" ", 2)
                tag = parts[0]
                cmd = parts[1].rstrip(b"\r\n").upper() if len(parts) > 1 else b""
                if literals and cmd == b"IDLE":
                    writer.write(b"+ idling\r\n")
                    await writer.drain()
                    done = await reader.readline()
                    recorder.raw += done
                    if done.rstrip(b"\r\n").upper() == b"DONE":
                        writer.write(tag + b" OK IDLE terminated\r\n")
                    else:
                        writer.write(tag + b" BAD expected DONE\r\n")
                    await writer.drain()
                    continue
                if cmd == b"LOGOUT":
                    writer.write(b"* BYE\r\n")
                    writer.write(tag + b" OK LOGOUT completed\r\n")
                    await writer.drain()
                    return
                if scripted and cmd in scripted:
                    for chunk in scripted[cmd]:
                        writer.write(chunk.replace(b"<TAG>", tag))
                        await writer.drain()
                        await asyncio.sleep(0.02)
                    continue
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

    def test_unit_is_case_insensitive(self):
        # The unit is lowercased after matching, so "MIN" was always
        # meant to work; the regex refused it before the lowercase ran.
        assert _parse_rate_limit("10/MIN") == (10, 60)
        assert _parse_rate_limit("2 / Hour") == (2, 3600)

    def test_grammar_is_ascii_only(self):
        # The host validates the same grammar, so both sides must agree
        # on what a digit and a space are: ASCII, not Unicode.
        with pytest.raises(ValueError):
            _parse_rate_limit("\u0661\u0660/min")
        with pytest.raises(ValueError):
            _parse_rate_limit("10/\u017f")


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

    @pytest.mark.parametrize("policy", [
        {"write_mode": "none"},
        {"readonly": True},  # legacy spelling of write_mode: none
    ], ids=["write_mode-none", "legacy-readonly"])
    def test_close_blocked_because_it_expunges(self, policy):
        """RFC 3501 §6.4.2: CLOSE expunges every \\Deleted message in the
        selected mailbox. Readonly denies STORE, so the relay cannot set
        the flag — but another client can, and a readonly relay that let
        CLOSE through would destroy that mail."""
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            entries: list[dict] = []
            try:
                entry = _relay_entry(up_port)
                entry["policy"] = {**entry["policy"], **policy}
                relay = ImapRelay(entry, audit_log=entries.append)
                await relay.start()
                try:
                    port = relay._server.sockets[0].getsockname()[1]
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()  # PREAUTH
                        writer.write(b"a1 CLOSE\r\n")
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                    await asyncio.sleep(0.05)
                finally:
                    await relay.stop()
            finally:
                upstream.close()
                await upstream.wait_closed()
            return line, recorder.commands, entries

        line, cmds, entries = _run(_go())
        assert line.startswith(b"a1 NO CLOSE not permitted (readonly)"), line
        assert not any(b"CLOSE" in c.upper() for c in cmds), \
            "CLOSE reached upstream"
        blocks = [
            e for e in entries
            if e.get("kind") == "imap_command"
            and e.get("decision") == "blocked"
        ]
        assert [b["command"] for b in blocks] == ["CLOSE"], entries
        assert blocks[0]["reason"] == "readonly policy"


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


class TestCredentialLookup:
    """Credentials resolve through the egress's shared secret lookup:
    staged file (``$AGENTCAGE_SECRETS_DIR/<NAME>``) → env. The apple-container backend delivers secrets ONLY as staged
    files, and only the staged file carries a live ``agentcage secret
    set`` — an env-only relay started with no credentials there."""

    @pytest.fixture
    def dirs(self, monkeypatch, tmp_path):
        staged = tmp_path / "secrets"
        runtime = tmp_path / "runtime"
        staged.mkdir()
        runtime.mkdir()
        monkeypatch.setenv("AGENTCAGE_SECRETS_DIR", str(staged))
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
        return staged, runtime

    def test_staged_file_beats_env(self, dirs):
        staged, _ = dirs
        (staged / "TEST_IMAP_USER").write_text("staged-user@example.com\n")
        (staged / "TEST_IMAP_PASS").write_text("staged-password\n")
        relay = ImapRelay(_relay_entry(1))
        # Trailing newline stripped, as the injector does.
        assert relay._user == "staged-user@example.com"
        assert relay._password == "staged-password"

    def test_staged_file_only_no_env(self, dirs, monkeypatch):
        """The apple-container case: nothing in env at all."""
        staged, _ = dirs
        monkeypatch.delenv("TEST_IMAP_USER", raising=False)
        monkeypatch.delenv("TEST_IMAP_PASS", raising=False)
        (staged / "TEST_IMAP_USER").write_text("staged-user@example.com\n")
        (staged / "TEST_IMAP_PASS").write_text("staged-password\n")
        relay = ImapRelay(_relay_entry(1))
        assert relay._user == "staged-user@example.com"
        assert relay._password == "staged-password"

    def test_empty_staged_file_is_a_tombstone(self, dirs):
        """An existing-but-empty staged file (``secret rm``) must not
        fall back to the stale boot-time env value."""
        staged, _ = dirs
        (staged / "TEST_IMAP_PASS").write_text("")
        with pytest.raises(ValueError, match="credentials not resolved"):
            ImapRelay(_relay_entry(1))

    def test_missing_staged_file_falls_back_to_env(self, dirs):
        relay = ImapRelay(_relay_entry(1))
        assert relay._user == "real-user@example.com"
        assert relay._password == "real-app-password"

    def test_runtime_dir_file_is_ignored(self, dirs):
        """No ``$XDG_RUNTIME_DIR`` step: nothing stages secrets there, and
        in the egress it only ever meant ``/run/<NAME>``."""
        _, runtime = dirs
        (runtime / "TEST_IMAP_PASS").write_text("runtime-password\n")
        relay = ImapRelay(_relay_entry(1))
        assert relay._password == "real-app-password"

    @pytest.mark.parametrize("scheme", ["env", "systemd-creds"])
    def test_delivered_schemes_resolve_by_name(self, dirs, scheme):
        """Every scheme the host delivers lands under NAME, the part after
        the colon."""
        from secret_lookup import resolve_credential

        staged, _ = dirs
        (staged / "MAIL_PW").write_text("staged-password\n")
        assert resolve_credential(f"{scheme}:MAIL_PW") == "staged-password"

    def test_cmd_source_is_refused_not_looked_up_by_its_command_text(self, dirs):
        """``cmd:``'s NAME is the command text: nothing runs it for a
        relay, so the lookup could only ever find a secret that happens to
        be named after the command. Refused, so the relay fails to start
        (audited) instead of logging in with whatever that name holds."""
        from secret_lookup import resolve_credential

        staged, _ = dirs
        (staged / "printf fake").write_text("named-after-the-command\n")
        with pytest.raises(ValueError, match="unsupported relay credential"):
            resolve_credential("cmd:printf fake")
        entry = _relay_entry(1)
        entry["auth"]["password_source"] = "cmd:printf fake"
        with pytest.raises(ValueError, match="unsupported relay credential"):
            ImapRelay(entry)

    def test_podman_source_is_refused(self, dirs):
        """The host refuses ``podman:`` relay credentials at validation;
        the egress refuses them too rather than resolving by NAME."""
        from secret_lookup import resolve_credential

        staged, _ = dirs
        (staged / "MAIL_PASS").write_text("would-have-resolved\n")
        with pytest.raises(ValueError, match="unsupported relay credential"):
            resolve_credential("podman:MAIL_PASS")


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
        b'a1 CREATE "Folders/Investments"\r\n',  # making a folder is recoverable
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


class TestReplaceRefused:
    """RFC 8508 REPLACE / UID REPLACE append a new message and expunge the
    old one in a single command. `none` and `organise` refuse APPEND and
    EXPUNGE individually, so they must refuse the combination too —
    otherwise an upstream advertising REPLACE hands the cage a way to
    rewrite (and so destroy) mail behind one unlisted verb."""

    _COMMANDS = [
        (b'a1 REPLACE 1 "Drafts" {12}\r\n', "REPLACE"),
        (b'a1 UID REPLACE 5 "Drafts" {12}\r\n', "UID REPLACE"),
        (b'a1 uid replace 5 "Drafts" {12}\r\n', "UID REPLACE"),  # case
    ]

    @staticmethod
    def _exchange(policy: dict, command: bytes):
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
            )
            entries: list[dict] = []
            try:
                entry = _relay_entry(up_port)
                entry["policy"] = {**entry["policy"], **policy}
                relay = ImapRelay(entry, audit_log=entries.append)
                await relay.start()
                try:
                    port = relay._server.sockets[0].getsockname()[1]
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()  # PREAUTH
                        writer.write(command)
                        await writer.drain()
                        line = await _read_until_tag(reader, b"a1")
                    await asyncio.sleep(0.05)
                finally:
                    await relay.stop()
            finally:
                upstream.close()
                await upstream.wait_closed()
            return line, recorder.commands, entries

        return _run(_go())

    @pytest.mark.parametrize("policy,wire,reason", [
        ({"write_mode": "none"}, b"readonly", "readonly policy"),
        ({"readonly": True}, b"readonly", "readonly policy"),
        ({"write_mode": "organise"}, b"write_mode organise",
         "write_mode organise"),
    ], ids=["write_mode-none", "legacy-readonly", "organise"])
    @pytest.mark.parametrize("command,label", _COMMANDS,
                             ids=["REPLACE", "UID-REPLACE", "lowercase"])
    def test_refused(self, policy, wire, reason, command, label):
        line, cmds, entries = self._exchange(policy, command)
        expected = (
            b"a1 NO " + label.encode() + b" not permitted (" + wire + b")"
        )
        assert line.rstrip(b"\r\n") == expected, line
        assert not any(b"REPLACE" in c.upper() for c in cmds), \
            "REPLACE reached upstream"
        blocks = [
            e for e in entries
            if e.get("kind") == "imap_command"
            and e.get("decision") == "blocked"
        ]
        assert [b["command"] for b in blocks] == [label], entries
        assert blocks[0]["reason"] == reason

    @pytest.mark.parametrize("command,label", _COMMANDS,
                             ids=["REPLACE", "UID-REPLACE", "lowercase"])
    def test_allowed_in_full(self, command, label):
        line, cmds, entries = self._exchange({"write_mode": "full"}, command)
        assert line.startswith(b"a1 OK"), line
        assert any(b"REPLACE" in c.upper() for c in cmds), cmds
        assert not any(e.get("decision") == "blocked" for e in entries)

    # -- advertised capabilities ----------------------------------------

    @staticmethod
    def _preauth(policy: dict) -> bytes:
        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder,
                "real-user@example.com",
                "real-app-password",
                greeting=(
                    b"* OK [CAPABILITY IMAP4rev1 IDLE REPLACE MOVE "
                    b"COMPRESS=DEFLATE] upstream ready\r\n"
                ),
            )
            try:
                entry = _relay_entry(up_port)
                entry["policy"] = {**entry["policy"], **policy}
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, _w):
                        return await reader.readline()
            finally:
                upstream.close()
                await upstream.wait_closed()

        return _run(_go())

    @pytest.mark.parametrize("policy", [
        {"write_mode": "none"},
        {"readonly": True},
        {"write_mode": "organise"},
    ], ids=["write_mode-none", "legacy-readonly", "organise"])
    def test_replace_not_advertised_where_refused(self, policy):
        """Like COMPRESS=DEFLATE: don't advertise what the client can't
        use, so a well-behaved client never tries it."""
        greeting = self._preauth(policy)
        assert greeting.startswith(b"* PREAUTH [CAPABILITY "), greeting
        tokens = greeting.split(b"]", 1)[0].split()[3:]
        assert b"REPLACE" not in tokens, greeting
        assert b"COMPRESS=DEFLATE" not in tokens, greeting
        assert b"IDLE" in tokens and b"MOVE" in tokens, greeting

    def test_replace_still_advertised_in_full(self):
        greeting = self._preauth({"write_mode": "full"})
        tokens = greeting.split(b"]", 1)[0].split()[3:]
        assert b"REPLACE" in tokens, greeting
        assert b"COMPRESS=DEFLATE" not in tokens, greeting


async def _relay_session(
    policy: dict,
    commands: list[bytes],
    *,
    scripted: Optional[dict[bytes, list[bytes]]] = None,
    greeting: bytes = b"* OK [CAPABILITY IMAP4rev1] fake upstream ready\r\n",
) -> tuple[list[bytes], list[bytes], list[dict]]:
    """Send each command (tags a1, a2, ...) through a relay with *policy*.

    Returns every byte the client received for each command (untagged
    lines included, up to and including its tagged line), what the
    upstream saw, and the relay's audit entries.
    """
    recorder = FakeUpstreamRecorder()
    upstream, up_port = await _start_fake_upstream(
        recorder, "real-user@example.com", "real-app-password",
        greeting=greeting, scripted=scripted,
    )
    entries: list[dict] = []
    replies: list[bytes] = []
    try:
        entry = _relay_entry(up_port)
        entry["policy"] = {**entry["policy"], **policy}
        relay = ImapRelay(entry, audit_log=entries.append)
        await relay.start()
        try:
            port = relay._server.sockets[0].getsockname()[1]
            async with _imap_client(port) as (reader, writer):
                await reader.readline()  # PREAUTH
                for command in commands:
                    tag = command.split(None, 1)[0]
                    writer.write(command)
                    await writer.drain()
                    got = b""
                    while True:
                        line = await asyncio.wait_for(reader.readline(), 5)
                        if not line:
                            raise EOFError(got)
                        got += line
                        if line.startswith(tag + b" "):
                            break
                    replies.append(got)
            await asyncio.sleep(0.05)
        finally:
            await relay.stop()
    finally:
        upstream.close()
        await upstream.wait_closed()
    return replies, recorder.commands, entries


def _blocked(entries: list[dict]) -> list[dict]:
    return [
        e for e in entries
        if e.get("kind") == "imap_command" and e.get("decision") == "blocked"
    ]


_ALL_MODES = pytest.mark.parametrize("policy", [
    {"write_mode": "none"},
    {"readonly": True},
    {"write_mode": "organise"},
    {"write_mode": "full"},
], ids=["write_mode-none", "legacy-readonly", "organise", "full"])


class TestStreamSwitchingCommandsRefused:
    """RFC 4978 COMPRESS switches the connection to DEFLATE right after the
    upstream's OK. From then on every rule the relay applies (write_mode,
    folders, audit) reads compressed bytes and matches nothing, so a
    compressed EXPUNGE sails through a readonly relay. It has to be refused
    in every mode, `full` included: no mode can be enforced, or even
    audited, over a stream the relay cannot read. STARTTLS and
    UNAUTHENTICATE are refused for the same reason (see imap.py)."""

    @_ALL_MODES
    @pytest.mark.parametrize("command", [
        b"a1 COMPRESS DEFLATE\r\n",
        b"a1 compress deflate\r\n",
        b"a1 Compress Deflate\r\n",
    ], ids=["upper", "lower", "mixed"])
    def test_compress_refused(self, policy, command):
        replies, cmds, entries = _run(_relay_session(
            policy, [command, b"a2 NOOP\r\n"],
        ))
        assert replies[0] == (
            b"a1 NO COMPRESS not permitted "
            b"(relay cannot inspect a compressed stream)\r\n"
        ), replies[0]
        assert not any(b"COMPRESS" in c.upper() for c in cmds), \
            "COMPRESS reached upstream"
        blocks = _blocked(entries)
        assert [b["command"] for b in blocks] == ["COMPRESS"], entries
        assert blocks[0]["reason"] == "relay cannot inspect a compressed stream"
        # The session carries on, uncompressed.
        assert replies[1] == b"a2 OK NOOP completed\r\n", replies[1]

    @pytest.mark.parametrize("command", [
        b"a1  COMPRESS DEFLATE\r\n",
        b"a1\tCOMPRESS DEFLATE\r\n",
        b" a1 COMPRESS DEFLATE\r\n",
    ], ids=["double-space", "tab", "leading-space"])
    def test_compress_refused_despite_odd_whitespace(self, command):
        """A lenient upstream may accept a command the relay split
        differently: with the old single-space split, `a1  COMPRESS`
        looked like command "" to the relay and was forwarded."""
        replies, cmds, entries = _run(_relay_session(
            {"write_mode": "full"}, [command],
        ))
        assert replies[0].startswith(b"a1 NO COMPRESS not permitted"), \
            replies[0]
        assert not any(b"COMPRESS" in c.upper() for c in cmds), cmds
        assert [b["command"] for b in _blocked(entries)] == ["COMPRESS"]

    @_ALL_MODES
    @pytest.mark.parametrize("command,label,reason", [
        (b"a1 STARTTLS\r\n", "STARTTLS", "relay cannot inspect a TLS stream"),
        (b"a1 unauthenticate\r\n", "UNAUTHENTICATE",
         "relay session stays authenticated"),
    ], ids=["STARTTLS", "UNAUTHENTICATE"])
    def test_other_stream_switching_commands_refused(
        self, policy, command, label, reason,
    ):
        replies, cmds, entries = _run(_relay_session(policy, [command]))
        assert replies[0] == (
            b"a1 NO " + label.encode() + b" not permitted ("
            + reason.encode() + b")\r\n"
        ), replies[0]
        assert not any(label.encode() in c.upper() for c in cmds), cmds
        assert [b["command"] for b in _blocked(entries)] == [label], entries


class TestUpstreamCapabilityResponsesFiltered:
    """The PREAUTH greeting hid COMPRESS=DEFLATE (and REPLACE where refused),
    but the upstream's reply to a CAPABILITY command, and [CAPABILITY ...]
    codes in later status responses, reached the cage raw."""

    _CAPS = b"IMAP4rev1 IDLE REPLACE MOVE COMPRESS=DEFLATE STARTTLS"

    @staticmethod
    def _tokens(line: bytes) -> list[bytes]:
        if line.startswith(b"* CAPABILITY"):
            return line.split()[2:]
        return line.split(b"[CAPABILITY", 1)[1].split(b"]", 1)[0].split()

    def _check(self, line: bytes, policy: dict) -> None:
        tokens = self._tokens(line)
        assert b"COMPRESS=DEFLATE" not in tokens, line
        assert b"STARTTLS" not in tokens, line
        assert b"IDLE" in tokens and b"MOVE" in tokens, line
        if policy.get("write_mode") == "full":
            assert b"REPLACE" in tokens, line
        else:
            assert b"REPLACE" not in tokens, line

    @_ALL_MODES
    def test_untagged_capability_reply_filtered(self, policy):
        replies, _, _ = _run(_relay_session(
            policy, [b"a1 CAPABILITY\r\n"],
            scripted={b"CAPABILITY": [
                b"* CAPABILITY " + self._CAPS + b"\r\n"
                b"<TAG> OK CAPABILITY completed\r\n",
            ]},
        ))
        lines = replies[0].splitlines(keepends=True)
        assert lines[1] == b"a1 OK CAPABILITY completed\r\n", replies[0]
        self._check(lines[0], policy)
        assert lines[0].endswith(b"\r\n"), lines[0]

    @_ALL_MODES
    def test_capability_line_split_across_upstream_chunks(self, policy):
        replies, _, _ = _run(_relay_session(
            policy, [b"a1 CAPABILITY\r\n"],
            scripted={b"CAPABILITY": [
                b"* CAPABILITY IMAP4rev1 IDLE REPLACE MOVE COMPR",
                b"ESS=DEFLATE STARTTLS\r\n<TAG> OK CAPABILITY completed\r\n",
            ]},
        ))
        lines = replies[0].splitlines(keepends=True)
        self._check(lines[0], policy)
        assert lines[1] == b"a1 OK CAPABILITY completed\r\n", replies[0]

    @_ALL_MODES
    def test_tagged_ok_capability_code_filtered(self, policy):
        replies, _, _ = _run(_relay_session(
            policy, [b"a1 NOOP\r\n"],
            scripted={b"NOOP": [
                b"<TAG> OK [CAPABILITY " + self._CAPS + b"] NOOP completed\r\n",
            ]},
        ))
        self._check(replies[0], policy)
        assert replies[0].startswith(b"a1 OK [CAPABILITY IMAP4rev1 IDLE")
        assert replies[0].endswith(b"] NOOP completed\r\n"), replies[0]

    @_ALL_MODES
    def test_untagged_ok_capability_code_filtered(self, policy):
        replies, _, _ = _run(_relay_session(
            policy, [b"a1 NOOP\r\n"],
            scripted={b"NOOP": [
                b"* OK [CAPABILITY " + self._CAPS + b"] still here\r\n",
                b"<TAG> OK NOOP completed\r\n",
            ]},
        ))
        self._check(replies[0].splitlines()[0], policy)

    def test_large_fetch_literal_passes_byte_exact(self):
        """The filter must not touch message bodies. This one is bigger
        than the relay's read size and its line-hold limit, has a line
        longer than that limit, and contains lines that look like
        capability responses and literal announcements: all mail, all to be
        delivered unchanged."""
        import random
        rng = random.Random(4978)
        body = (
            b"Subject: hi\r\n\r\n"
            b"* CAPABILITY IMAP4rev1 COMPRESS=DEFLATE REPLACE\r\n"
            b"a1 OK [CAPABILITY COMPRESS=DEFLATE] fake\r\n"
            b"* 2 FETCH (BODY[] {99999}\r\n"
            + b"x" * (300 * 1024) + b"\r\n"
            + rng.randbytes(700 * 1024).replace(b"<TAG>", b"<tag>")
            + b"\r\n* CAPABILITY COMPRESS=DEFLATE\r\n"
        )
        head = b"* 1 FETCH (UID 7 BODY[] {%d}\r\n" % len(body)
        tail = b" FLAGS (\\Seen))\r\n"
        reply = head + body + tail + b"<TAG> OK FETCH completed\r\n"
        expected = reply.replace(b"<TAG>", b"a1")
        # Odd-sized chunks, so boundaries fall inside the literal and lines.
        chunks = [
            expected[i:i + 70001] for i in range(0, len(expected), 70001)
        ]

        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
                scripted={b"FETCH": chunks},
            )
            try:
                entry = _relay_entry(up_port)
                entry["policy"] = {**entry["policy"], "write_mode": "none"}
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()  # PREAUTH
                        writer.write(b"a1 FETCH 1 (UID BODY[] FLAGS)\r\n")
                        await writer.drain()
                        return await asyncio.wait_for(
                            reader.readexactly(len(expected)), 10,
                        )
            finally:
                upstream.close()
                await upstream.wait_closed()

        got = _run(_go())
        assert got == expected


class TestResponseFilter:
    """The upstream -> client filter on its own, fed arbitrary chunkings."""

    STREAM = (
        b"* CAPABILITY IMAP4rev1 COMPRESS=DEFLATE IDLE REPLACE\r\n"
        b"a1 OK CAPABILITY completed\r\n"
        b"* 1 FETCH (BODY[] {54}\r\n"
        b"* CAPABILITY IMAP4rev1 COMPRESS=DEFLATE IDLE REPLACE\r\n"
        b" BODY[HEADER] ~{9}\r\n* OK [CA)\r\n"
        b"a2 OK FETCH completed\r\n"
        # free text ending in {n}: not a literal
        b"a3 BAD unknown command {20}\r\n"
        b"* OK [CAPABILITY IMAP4rev1 COMPRESS=DEFLATE] hi\r\n"
        b"+ go ahead {3}\r\n"
        b"a4 OK [CAPABILITY COMPRESS=DEFLATE REPLACE IDLE] done\r\n"
        b"a5 OK [CAPABILITYX COMPRESS=DEFLATE] other code\r\n"
    )
    EXPECTED = (
        b"* CAPABILITY IMAP4rev1 IDLE\r\n"
        b"a1 OK CAPABILITY completed\r\n"
        b"* 1 FETCH (BODY[] {54}\r\n"
        b"* CAPABILITY IMAP4rev1 COMPRESS=DEFLATE IDLE REPLACE\r\n"
        b" BODY[HEADER] ~{9}\r\n* OK [CA)\r\n"
        b"a2 OK FETCH completed\r\n"
        b"a3 BAD unknown command {20}\r\n"
        b"* OK [CAPABILITY IMAP4rev1] hi\r\n"
        b"+ go ahead {3}\r\n"
        b"a4 OK [CAPABILITY IDLE] done\r\n"
        b"a5 OK [CAPABILITYX COMPRESS=DEFLATE] other code\r\n"
    )

    @staticmethod
    def _filter():
        from relays.imap import _ResponseFilter, _capability_hidden
        return _ResponseFilter(lambda t: _capability_hidden(t, "none"))

    def test_whole_stream(self):
        f = self._filter()
        assert f.feed(self.STREAM) + f.finish() == self.EXPECTED

    def test_every_two_chunk_split(self):
        for cut in range(1, len(self.STREAM)):
            f = self._filter()
            got = (
                f.feed(self.STREAM[:cut]) + f.feed(self.STREAM[cut:])
                + f.finish()
            )
            assert got == self.EXPECTED, cut

    def test_byte_at_a_time(self):
        f = self._filter()
        got = b"".join(
            f.feed(self.STREAM[i:i + 1]) for i in range(len(self.STREAM))
        )
        assert got + f.finish() == self.EXPECTED

    def test_full_mode_keeps_replace(self):
        from relays.imap import _ResponseFilter, _capability_hidden
        f = _ResponseFilter(lambda t: _capability_hidden(t, "full"))
        assert f.feed(
            b"* CAPABILITY IMAP4rev1 compress=deflate REPLACE\r\n"
        ) == b"* CAPABILITY IMAP4rev1 REPLACE\r\n"

    def test_partial_line_is_held_until_its_end(self):
        f = self._filter()
        assert f.feed(b"* CAPABILITY IMAP4rev1 COMPRESS=DEF") == b""
        assert f.feed(b"LATE\r\n") == b"* CAPABILITY IMAP4rev1\r\n"

    def test_overlong_line_streams_raw_with_bounded_hold(self):
        from relays.imap import _HELD_LINE_LIMIT
        f = self._filter()
        line = b"* SEARCH" + b" 12345" * (_HELD_LINE_LIMIT // 3) + b"\r\n"
        out = b""
        for i in range(0, len(line), 8192):
            out += f.feed(line[i:i + 8192])
            assert len(f._held) <= _HELD_LINE_LIMIT + 8192
        assert out == line
        # and the next line is filtered again
        assert f.feed(b"* CAPABILITY X COMPRESS=DEFLATE\r\n") == \
            b"* CAPABILITY X\r\n"

    def test_overlong_capability_line_is_refused_not_leaked(self):
        from relays.imap import _HELD_LINE_LIMIT, _UnfilterableResponse
        f = self._filter()
        f.feed(b"a1 OK [CAPABILITY COMPRESS=DEFLATE")
        with pytest.raises(_UnfilterableResponse):
            for _ in range(_HELD_LINE_LIMIT // 8192 + 2):
                f.feed(b"A" * 8192)


class TestQuotaAndAnnotationWrites:
    """SETQUOTA (RFC 9208) and annotation writes (RFC 5257 STORE ...
    ANNOTATION, Cyrus SETANNOTATION) change account and message settings,
    not mail filing. `none` refuses all writes and `organise` only files
    and flags, so both must refuse them; `full` passes them through."""

    _COMMANDS = [
        (b'a1 SETQUOTA "" (STORAGE 512)\r\n', "SETQUOTA", None),
        (b'a1 setquota "" (STORAGE 512)\r\n', "SETQUOTA", None),
        (b'a1 SETANNOTATION INBOX "/comment" ("value.shared" "x")\r\n',
         "SETANNOTATION", None),
        (b'a1 STORE 1 ANNOTATION (/comment (value.priv "x"))\r\n',
         "STORE", "annotation"),
        (b'a1 UID STORE 5 annotation (/comment (value.priv "x"))\r\n',
         "UID STORE", "annotation"),
        (b'a1 STORE 1 (UNCHANGEDSINCE 12) ANNOTATION '
         b'(/comment (value.priv "x"))\r\n', "STORE", "annotation"),
    ]
    _IDS = ["SETQUOTA", "setquota", "SETANNOTATION", "STORE-ANNOTATION",
            "UID-STORE-ANNOTATION", "STORE-UNCHANGEDSINCE-ANNOTATION"]

    @pytest.mark.parametrize("policy,wire,reason", [
        ({"write_mode": "none"}, b"readonly", "readonly policy"),
        ({"readonly": True}, b"readonly", "readonly policy"),
        ({"write_mode": "organise"}, b"write_mode organise",
         "write_mode organise"),
    ], ids=["write_mode-none", "legacy-readonly", "organise"])
    @pytest.mark.parametrize("command,label,detail", _COMMANDS, ids=_IDS)
    def test_refused(self, policy, wire, reason, command, label, detail):
        replies, cmds, entries = _run(_relay_session(policy, [command]))
        assert replies[0] == (
            b"a1 NO " + label.encode() + b" not permitted (" + wire + b")\r\n"
        ), replies[0]
        assert cmds == [cmds[0]], f"reached upstream: {cmds[1:]}"
        blocks = _blocked(entries)
        assert [b["command"] for b in blocks] == [label], entries
        if detail and policy.get("write_mode") == "organise":
            reason = f"{reason} ({detail})"
        assert blocks[0]["reason"] == reason

    @pytest.mark.parametrize("command,label,detail", _COMMANDS, ids=_IDS)
    def test_allowed_in_full(self, command, label, detail):
        replies, cmds, entries = _run(_relay_session(
            {"write_mode": "full"}, [command],
        ))
        assert replies[0].startswith(b"a1 OK"), replies[0]
        assert cmds[1:] == [command], cmds
        assert not _blocked(entries)


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


# ── Literals from the cage ──────────────────────────────


async def _literal_session(
    policy: dict,
    client,
    *,
    refuse_literal: frozenset = frozenset(),
    log_allowed: bool = False,
):
    """Run *client(reader, writer)* against a relay with *policy* in front
    of a literal-aware upstream. Returns what *client* returned, the
    upstream's recorder and the relay's audit entries."""
    recorder = FakeUpstreamRecorder()
    upstream, up_port = await _start_fake_upstream(
        recorder, "real-user@example.com", "real-app-password",
        literals=True, refuse_literal=refuse_literal,
    )
    entries: list[dict] = []
    try:
        entry = _relay_entry(up_port)
        entry["policy"] = {**entry["policy"], **policy}
        relay = ImapRelay(
            entry, audit_log=entries.append, log_allowed=log_allowed,
        )
        await relay.start()
        try:
            port = relay._server.sockets[0].getsockname()[1]
            async with _imap_client(port) as (reader, writer):
                await reader.readline()  # PREAUTH
                result = await asyncio.wait_for(client(reader, writer), 5)
            await asyncio.sleep(0.05)
        finally:
            await relay.stop()
    finally:
        upstream.close()
        await upstream.wait_closed()
    return result, recorder, entries


async def _send_command(reader, writer, pieces: list[bytes]) -> list[bytes]:
    """Send one command as a compliant client would.

    *pieces* alternates lines and literal payloads: line, payload, line,
    ..., line. Before the payload of a synchronising literal the client
    waits for ``+``; a tagged response instead ends the command there.
    A non-synchronising (``{n+}``) payload goes straight out. Returns every
    line received, up to and including the command's tagged response.
    """
    tag = pieces[0].split(None, 1)[0]
    got: list[bytes] = []

    async def _line() -> bytes:
        line = await asyncio.wait_for(reader.readline(), 5)
        if not line:
            raise EOFError(got)
        got.append(line)
        return line

    for i in range(0, len(pieces), 2):
        writer.write(pieces[i])
        await writer.drain()
        if i + 1 == len(pieces):
            break
        if not pieces[i].endswith(b"+}\r\n"):
            while True:
                line = await _line()
                if line.startswith(b"+"):
                    break
                if line.startswith(tag + b" "):
                    return got
        writer.write(pieces[i + 1])
        await writer.drain()
    while not (await _line()).startswith(tag + b" "):
        pass
    return got


async def _command(reader, writer, line: bytes) -> list[bytes]:
    return await _send_command(reader, writer, [line])


# A message whose body has lines that read as IMAP commands, including ones
# the relay refuses or intercepts in every mode.
_TRICKY_BODY = (
    b"From: someone@example.com\r\n"
    b"Subject: notes\r\n"
    b"\r\n"
    b"a1 COMPRESS DEFLATE\r\n"
    b"x LOGIN u p\r\n"
    b"y EXPUNGE\r\n"
    b"Please starttls\r\n"
    b"Please login when you can\r\n"
    b"z UNAUTHENTICATE\r\n"
    b"+ NOOP\r\n"
    b"* tail {5}\r\n"
)


def _without_login(cmds: list[bytes]) -> list[bytes]:
    return [c for c in cmds if b" LOGIN \"real-user" not in c]


class TestClientLiterals:
    """Literal payload from the cage is data: forwarded byte for byte and
    never read as commands, while every real command line is still
    checked. Before, each payload line went through the policy check as
    if it were a command, so a body line like `Please login ...` was
    swallowed (answered OK by the relay), and lines whose second word is
    COMPRESS, STARTTLS or UNAUTHENTICATE were refused even in `full`."""

    @pytest.mark.parametrize("marker", [b"{%d}", b"{%d+}", b"~{%d}"],
                             ids=["sync", "non-sync", "binary"])
    def test_append_body_reaches_upstream_byte_exact(self, marker):
        body = _TRICKY_BODY + (b"\x00\xff\r\n" if b"~" in marker else b"")
        head = b"a1 APPEND INBOX (\\Seen) " + marker % len(body) + b"\r\n"

        async def _client(reader, writer):
            got = await _send_command(reader, writer, [head, body, b"\r\n"])
            got += await _command(reader, writer, b"a2 NOOP\r\n")
            return got

        got, rec, entries = _run(_literal_session(
            {"write_mode": "full"}, _client, log_allowed=True,
        ))
        # A non-synchronising literal goes upstream as a synchronising one.
        sent_head = head.replace(b"+}", b"}")
        assert _without_login(rec.commands) == [
            sent_head + body + b"\r\n", b"a2 NOOP\r\n",
        ]
        assert got[-2:] == [
            b"a1 OK APPEND completed\r\n", b"a2 OK NOOP completed\r\n",
        ], got
        # The cage sees a "+" only where it asked for one.
        pluses = [g for g in got if g.startswith(b"+")]
        assert len(pluses) == (0 if b"+}" in marker else 1), got
        # Nothing in the body was audited as a command.
        assert [(e["decision"], e["command"]) for e in entries] == [
            ("allowed", "APPEND"), ("allowed", "NOOP"),
        ], entries

    @pytest.mark.parametrize("policy", [
        {"write_mode": "none"}, {"write_mode": "organise"},
    ], ids=["none", "organise"])
    def test_refused_sync_literal_is_never_sent(self, policy):
        """The relay answers NO in place of the "+", so a compliant client
        never sends the payload, and the next command is checked as one."""
        async def _client(reader, writer):
            got = await _send_command(reader, writer, [
                b"a1 APPEND INBOX {%d}\r\n" % len(_TRICKY_BODY),
                _TRICKY_BODY, b"\r\n",
            ])
            got += await _command(reader, writer, b"a2 EXPUNGE\r\n")
            got += await _command(reader, writer, b"a3 NOOP\r\n")
            return got

        got, rec, entries = _run(_literal_session(policy, _client))
        assert [g.split(None, 2)[:2] for g in got] == [
            [b"a1", b"NO"], [b"a2", b"NO"], [b"a3", b"OK"],
        ], got
        assert _without_login(rec.commands) == [b"a3 NOOP\r\n"]
        assert [e["command"] for e in _blocked(entries)] == [
            "APPEND", "EXPUNGE",
        ], entries

    @pytest.mark.parametrize("policy", [
        {"write_mode": "none"}, {"write_mode": "organise"},
    ], ids=["none", "organise"])
    def test_refused_non_sync_literal_is_dropped_exactly(self, policy):
        """With `{n+}` the cage sends the payload unasked; the relay drops
        exactly n bytes and the rest of the command, and forwards none of
        it. The payload deliberately ends mid-line, so an off-by-one in
        either direction would show up in the next command."""
        payload = b"b NOOP\r\nc SELECT INBOX\r\nd EXAMINE x"
        second = b"e STATUS INBOX (MESSAGES)\r\n"

        async def _client(reader, writer):
            got = await _send_command(reader, writer, [
                b"a1 APPEND INBOX {%d+}\r\n" % len(payload), payload,
                b" (\\Seen) {%d+}\r\n" % len(second), second,
                b"\r\n",
            ])
            got += await _command(reader, writer, b"a2 EXPUNGE\r\n")
            got += await _command(reader, writer, b"a3 NOOP\r\n")
            return got

        got, rec, entries = _run(_literal_session(policy, _client))
        assert [g.split(None, 2)[:2] for g in got] == [
            [b"a1", b"NO"], [b"a2", b"NO"], [b"a3", b"OK"],
        ], got
        assert _without_login(rec.commands) == [b"a3 NOOP\r\n"]
        assert [e["command"] for e in _blocked(entries)] == [
            "APPEND", "EXPUNGE",
        ], entries

    def test_upstream_refusing_sync_literal(self):
        """A tagged NO instead of "+" ends the command: the client sends
        no payload and the relay reads the next line as a command."""
        async def _client(reader, writer):
            got = await _send_command(reader, writer, [
                b"a1 APPEND Nope {%d}\r\n" % len(_TRICKY_BODY),
                _TRICKY_BODY, b"\r\n",
            ])
            got += await _command(reader, writer, b"a2 NOOP\r\n")
            return got

        got, rec, entries = _run(_literal_session(
            {"write_mode": "full"}, _client,
            refuse_literal=frozenset({b"APPEND"}),
        ))
        assert got == [
            b"a1 NO [TRYCREATE] no such mailbox\r\n",
            b"a2 OK NOOP completed\r\n",
        ], got
        assert _without_login(rec.commands) == [
            b"a1 APPEND Nope {%d}\r\n" % len(_TRICKY_BODY), b"a2 NOOP\r\n",
        ]
        assert not _blocked(entries)

    def test_upstream_refusing_non_sync_literal(self):
        """The relay announced the cage's `{n+}` upstream as `{n}`; when
        the upstream refuses it, the payload the cage already sent is
        dropped, not read as commands."""
        payload = b"b COMPRESS DEFLATE\r\nc NOOP\r\n"

        async def _client(reader, writer):
            got = await _send_command(reader, writer, [
                b"a1 APPEND Nope {%d+}\r\n" % len(payload), payload,
                b"\r\n",
            ])
            got += await _command(reader, writer, b"a2 NOOP\r\n")
            return got

        got, rec, entries = _run(_literal_session(
            {"write_mode": "full"}, _client,
            refuse_literal=frozenset({b"APPEND"}),
        ))
        assert got == [
            b"a1 NO [TRYCREATE] no such mailbox\r\n",
            b"a2 OK NOOP completed\r\n",
        ], got
        assert _without_login(rec.commands) == [
            b"a1 APPEND Nope {%d}\r\n" % len(payload), b"a2 NOOP\r\n",
        ]
        assert not _blocked(entries)

    @pytest.mark.parametrize("second", [b"{%d}", b"{%d+}"],
                             ids=["sync-sync", "sync-non-sync"])
    def test_multiappend_two_literals(self, second):
        """RFC 3502 MULTIAPPEND: the command goes on after each literal
        until a line ends without one."""
        m1 = _TRICKY_BODY
        m2 = b"Subject: two\r\n\r\nq LOGIN a b\r\nr compress deflate\r\n"
        pieces = [
            b"a1 APPEND INBOX (\\Seen) {%d}\r\n" % len(m1), m1,
            b' (\\Flagged) "10-Oct-2026 10:00:00 +0000" '
            + second % len(m2) + b"\r\n", m2,
            b"\r\n",
        ]

        async def _client(reader, writer):
            return await _send_command(reader, writer, pieces)

        got, rec, entries = _run(_literal_session(
            {"write_mode": "full"}, _client,
        ))
        assert _without_login(rec.commands) == [
            b"".join(pieces).replace(b"+}", b"}"),
        ]
        assert got[-1] == b"a1 OK APPEND completed\r\n", got
        assert len(got) == (3 if second == b"{%d}" else 2), got
        assert not _blocked(entries)

    def test_oversized_sync_literal_refused(self):
        from relays.imap import _MAX_LITERAL_BYTES

        async def _client(reader, writer):
            got = await _command(
                reader, writer,
                b"a1 APPEND INBOX {%d}\r\n" % (_MAX_LITERAL_BYTES + 1),
            )
            got += await _command(reader, writer, b"a2 NOOP\r\n")
            return got

        got, rec, entries = _run(_literal_session(
            {"write_mode": "full"}, _client,
        ))
        assert got == [
            b"a1 NO [TOOBIG] literal larger than %d bytes\r\n"
            % _MAX_LITERAL_BYTES,
            b"a2 OK NOOP completed\r\n",
        ], got
        assert _without_login(rec.commands) == [b"a2 NOOP\r\n"]
        blocks = _blocked(entries)
        assert [(b["command"], b["reason"]) for b in blocks] == [
            ("APPEND", "literal too large"),
        ], entries

    @pytest.mark.parametrize("count", [
        b"%d+" % (64 * 1024 * 1024 + 1),
        b"9" * 40 + b"+",
    ], ids=["just-over", "40-digits"])
    def test_oversized_non_sync_literal_closes_session(self, count):
        """The relay can't skip a payload it won't read, so after the NO it
        ends the session rather than read the payload as commands."""
        async def _client(reader, writer):
            writer.write(b"a1 APPEND INBOX {" + count + b"}\r\n")
            writer.write(b"b COMPRESS DEFLATE\r\n")
            await writer.drain()
            return await asyncio.wait_for(reader.read(), 5)

        got, rec, entries = _run(_literal_session(
            {"write_mode": "full"}, _client,
        ))
        lines = got.splitlines(keepends=True)
        assert lines[0].startswith(b"a1 NO [TOOBIG]"), got
        assert lines[1:] == [b"* BYE literal too large\r\n"], got
        assert _without_login(rec.commands) == []
        assert [b["reason"] for b in _blocked(entries)] == [
            "literal too large",
        ]

    def test_oversized_literal_mid_command_closes_session(self):
        from relays.imap import _MAX_LITERAL_BYTES

        async def _client(reader, writer):
            got = await _send_command(reader, writer, [
                b"a1 APPEND INBOX {3}\r\n", b"abc",
                b" {%d}\r\n" % (_MAX_LITERAL_BYTES + 1),
            ])
            return got

        async def _until_closed(reader, writer):
            try:
                return await _client(reader, writer)
            except EOFError as e:
                return e.args[0]

        got, rec, entries = _run(_literal_session(
            {"write_mode": "full"}, _until_closed,
        ))
        assert got == [b"+ go ahead\r\n", b"* BYE literal too large\r\n"], got
        assert [b["reason"] for b in _blocked(entries)] == [
            "literal too large",
        ]

    @pytest.mark.parametrize("marker", [b"{%d}", b"{%d+}"],
                             ids=["sync", "non-sync"])
    def test_literal_split_across_small_writes(self, marker):
        head = b"a1 APPEND INBOX " + marker % len(_TRICKY_BODY) + b"\r\n"

        async def _client(reader, writer):
            async def _dribble(data: bytes):
                for i in range(0, len(data), 3):
                    writer.write(data[i:i + 3])
                    await writer.drain()
                    await asyncio.sleep(0.001)

            await _dribble(head)
            if b"+}" not in marker:
                assert (await reader.readline()).startswith(b"+")
            await _dribble(_TRICKY_BODY + b"\r\n")
            return await _read_until_tag(reader, b"a1")

        line, rec, entries = _run(_literal_session(
            {"write_mode": "full"}, _client,
        ))
        assert line == b"a1 OK APPEND completed\r\n"
        assert _without_login(rec.commands) == [
            head.replace(b"+}", b"}") + _TRICKY_BODY + b"\r\n",
        ]
        assert not _blocked(entries)

    @pytest.mark.parametrize("line", [
        b"+ NOOP\r\n", b"* NOOP\r\n", b"a(1 NOOP\r\n", b"+\r\n",
    ], ids=["plus", "star", "paren", "bare-plus"])
    def test_invalid_tag_refused(self, line):
        """A "+" tag echoed back by the upstream would read as a
        continuation request, so such a line never reaches it."""
        async def _client(reader, writer):
            writer.write(line)
            await writer.drain()
            got = [await asyncio.wait_for(reader.readline(), 5)]
            return got + await _command(reader, writer, b"a2 NOOP\r\n")

        got, rec, entries = _run(_literal_session(
            {"write_mode": "full"}, _client,
        ))
        assert got == [
            b"* BAD invalid command tag\r\n", b"a2 OK NOOP completed\r\n",
        ], got
        assert _without_login(rec.commands) == [b"a2 NOOP\r\n"]
        assert [b["reason"] for b in _blocked(entries)] == ["invalid tag"]

    @pytest.mark.parametrize("marker", [b"{5-}", b"{ 5}", b"{}", b"{5+ }"])
    def test_malformed_literal_refused(self, marker):
        async def _client(reader, writer):
            got = await _command(
                reader, writer, b"a1 SEARCH TEXT " + marker + b"\r\n",
            )
            return got + await _command(reader, writer, b"a2 NOOP\r\n")

        got, rec, entries = _run(_literal_session(
            {"write_mode": "full"}, _client,
        ))
        assert got == [
            b"a1 BAD malformed literal\r\n", b"a2 OK NOOP completed\r\n",
        ], got
        assert _without_login(rec.commands) == [b"a2 NOOP\r\n"]

    def test_idle_then_done(self):
        """DONE is a one-word line; it must still pass."""
        async def _client(reader, writer):
            writer.write(b"a1 IDLE\r\n")
            await writer.drain()
            got = [await asyncio.wait_for(reader.readline(), 5)]
            writer.write(b"DONE\r\n")
            await writer.drain()
            return got + [await _read_until_tag(reader, b"a1")]

        got, rec, _ = _run(_literal_session({"write_mode": "none"}, _client))
        assert got == [b"+ idling\r\n", b"a1 OK IDLE terminated\r\n"]

    def test_idle_continuation_is_not_taken_for_a_literal(self):
        """`+` has no tag. A cage that pipelines a literal behind an IDLE
        must not get IDLE's `+ idling` taken as the go-ahead for its
        literal: the relay would forward the payload while the upstream,
        still idling, refuses the line announcing it and then reads the
        payload as a command. So the relay holds a literal back until
        nothing else it forwarded is outstanding."""
        payload = b"b COMPRESS DEFLATE\r\n"

        async def _client(reader, writer):
            writer.write(
                b"a1 IDLE\r\n"
                b"a2 SEARCH TEXT {%d+}\r\n" % len(payload)
                + payload + b"\r\n"
            )
            await writer.drain()
            got = await asyncio.wait_for(reader.readline(), 5)
            await asyncio.sleep(0.3)
            return got

        got, rec, _ = _run(_literal_session({"write_mode": "full"}, _client))
        assert got == b"+ idling\r\n"
        assert b"COMPRESS" not in bytes(rec.raw), bytes(rec.raw)
        assert b"SEARCH" not in bytes(rec.raw), bytes(rec.raw)

    def test_literal_waits_for_pipelined_commands(self):
        """A literal command pipelined behind ordinary ones still works:
        it is held until they complete, then relayed."""
        async def _client(reader, writer):
            writer.write(
                b"a1 NOOP\r\na2 SELECT INBOX\r\n"
                b"a3 APPEND INBOX {%d+}\r\n" % len(_TRICKY_BODY)
                + _TRICKY_BODY + b"\r\na4 NOOP\r\n"
            )
            await writer.drain()
            return await _read_until_tag(reader, b"a4")

        got, rec, entries = _run(_literal_session(
            {"write_mode": "full"}, _client,
        ))
        assert got == b"a4 OK NOOP completed\r\n"
        assert _without_login(rec.commands) == [
            b"a1 NOOP\r\n", b"a2 SELECT INBOX\r\n",
            b"a3 APPEND INBOX {%d}\r\n" % len(_TRICKY_BODY)
            + _TRICKY_BODY + b"\r\n",
            b"a4 NOOP\r\n",
        ]

    def test_login_literal_intercepted_and_payload_dropped(self):
        """LOGIN is answered by the relay; a `{n+}` password after it is
        dropped, not forwarded and not read as a command."""
        async def _client(reader, writer):
            got = await _send_command(reader, writer, [
                b"a1 LOGIN {4+}\r\n", b"user", b" {13+}\r\n",
                b"x EXPUNGE\r\n\r\n", b"\r\n",
            ])
            return got + await _command(reader, writer, b"a2 NOOP\r\n")

        got, rec, entries = _run(_literal_session(
            {"write_mode": "none"}, _client,
        ))
        assert got == [
            b"a1 OK already authenticated (relay handled login)\r\n",
            b"a2 OK NOOP completed\r\n",
        ], got
        assert _without_login(rec.commands) == [b"a2 NOOP\r\n"]


# ── Relay replies vs upstream responses ─────────────────


class TestRelayRepliesBetweenResponses:
    """The relay's own replies (NO to a refused command, the OK to LOGIN)
    were written to the cage by the client -> upstream task while the
    upstream -> client task could be half way through a response. With
    pipelined commands a reply could land inside a FETCH literal, where it
    became part of the message body, and the client's parse of the stream
    was off from there on. Replies now wait for the response in progress
    to end."""

    # Whole responses, as the client must see them. None of them carries
    # capabilities, so the filter forwards them unchanged.
    RESPONSES = [
        b"* 1 FETCH (UID 7 BODY[] {23}\r\nline one\r\na2 NO fake\r\n"
        b" FLAGS (\\Seen))\r\n",
        b"* 2 FETCH (BODY[HEADER] ~{4}\r\nab\r\n BODY[TEXT] {0}\r\n)\r\n",
        b"a1 OK FETCH completed\r\n",
        b"+ go ahead {3}\r\n",          # free text, not a literal
        b"* OK still here {4}\r\n",     # likewise
        b"a3 BAD no {2}\r\n",           # likewise
        b"* 3 EXISTS\r\n",
    ]
    REPLY = b"a9 NO APPEND not permitted (readonly)\r\n"

    @staticmethod
    def _filter():
        from relays.imap import _ResponseFilter, _capability_hidden
        return _ResponseFilter(lambda t: _capability_hidden(t, "none"))

    def _expected(self, forwarded: int) -> bytes:
        stream = b"".join(self.RESPONSES)
        ends = [0]
        for r in self.RESPONSES:
            ends.append(ends[-1] + len(r))
        at = min(e for e in ends if e >= forwarded)
        return stream[:at] + self.REPLY + stream[at:]

    def test_reply_lands_on_the_first_boundary_at_every_cut(self):
        stream = b"".join(self.RESPONSES)
        for cut in range(len(stream) + 1):
            f = self._filter()
            out = f.feed(stream[:cut])
            forwarded = len(out)
            out += f.insert(self.REPLY)
            out += f.feed(stream[cut:]) + f.finish()
            assert out == self._expected(forwarded), cut

    def test_replies_keep_their_order(self):
        stream = b"".join(self.RESPONSES)
        cut = stream.index(b"line one")
        f = self._filter()
        out = f.feed(stream[:cut])
        for i in range(3):
            assert f.insert(b"a%d NO x\r\n" % i) == b""
        out += f.feed(stream[cut:])
        first = len(self.RESPONSES[0])
        assert out == (
            stream[:first] + b"a0 NO x\r\na1 NO x\r\na2 NO x\r\n"
            + stream[first:]
        )

    def test_reply_waits_for_an_overlong_line_streamed_raw(self):
        from relays.imap import _HELD_LINE_LIMIT
        f = self._filter()
        line = b"* SEARCH" + b" 12345" * (_HELD_LINE_LIMIT // 3) + b"\r\n"
        out = f.feed(line[:_HELD_LINE_LIMIT + 100])
        assert out, "the overlong line should be streaming by now"
        assert f.insert(self.REPLY) == b""
        out += f.feed(line[_HELD_LINE_LIMIT + 100:])
        assert out == line + self.REPLY

    # -- end to end ---------------------------------------------------------

    @staticmethod
    def _parse_one(buf: bytes) -> Optional[int]:
        """Length of the first whole response in *buf* (literals in
        untagged responses followed), or None if it isn't all there."""
        pos = 0
        while True:
            nl = buf.find(b"\n", pos)
            if nl < 0:
                return None
            line = buf[pos:nl + 1]
            m = re.search(rb"\{(\d+)\}\r\n\Z", line)
            if m and buf.startswith(b"* "):
                pos = nl + 1 + int(m.group(1))
                if pos > len(buf):
                    return None
                continue
            return nl + 1

    async def _read_responses(self, reader, tags: set,
                              buf: bytes = b"") -> list[bytes]:
        """Split what the client receives (starting with *buf*) into whole
        responses until every tag in *tags* has had its tagged one."""
        got: list[bytes] = []
        pending = set(tags)
        buf = bytes(buf)
        while pending:
            n = self._parse_one(buf)
            if n is None:
                data = await asyncio.wait_for(reader.read(65536), 5)
                if not data:
                    raise EOFError(got, buf)
                buf += data
                continue
            resp, buf = buf[:n], buf[n:]
            got.append(resp)
            pending.discard(resp.split(None, 1)[0])
        assert buf == b"", buf
        return got

    def _session(self, chunks: list[bytes], seen: int, refused: list[bytes],
                 *, then: Optional[bytes] = None):
        """a1 FETCH answered with *chunks* (paced); once the client has
        read *seen* bytes of it, it pipelines the *refused* commands (and
        *then*, a command the relay forwards)."""
        tags = {b"a1"} | {c.split(None, 1)[0] for c in refused}
        if then is not None:
            tags.add(then.split(None, 1)[0])

        async def _go():
            recorder = FakeUpstreamRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "real-user@example.com", "real-app-password",
                scripted={b"FETCH": chunks},
            )
            try:
                entry = _relay_entry(up_port, readonly=True)
                async with _running_relay(entry) as (_, port):
                    async with _imap_client(port) as (reader, writer):
                        await reader.readline()  # PREAUTH
                        writer.write(b"a1 FETCH 1 (UID BODY[] FLAGS)\r\n")
                        await writer.drain()
                        head = await asyncio.wait_for(
                            reader.readexactly(seen), 5,
                        )
                        writer.write(b"".join(refused) + (then or b""))
                        await writer.drain()
                        return await self._read_responses(
                            reader, tags, head,
                        )
            finally:
                upstream.close()
                await upstream.wait_closed()

        return _run(_go())

    def test_refusal_never_lands_inside_a_fetch_literal(self):
        import random
        body = random.Random(23).randbytes(100_000).replace(b"\n", b" ")
        fetch = (
            b"* 1 FETCH (UID 7 BODY[] {%d}\r\n" % len(body)
            + body + b" FLAGS (\\Seen))\r\n"
        )
        reply = fetch + b"<TAG> OK FETCH completed\r\n"
        chunks = [reply[i:i + 9000] for i in range(0, len(reply), 9000)]
        got = self._session(
            chunks, seen=9000,
            refused=[b"a2 APPEND INBOX {3}\r\n"],
            then=b"a3 NOOP\r\n",
        )
        assert got == [
            fetch,
            b"a2 NO APPEND not permitted (readonly)\r\n",
            b"a1 OK FETCH completed\r\n",
            b"a3 OK NOOP completed\r\n",
        ], [g[:80] for g in got]

    def test_several_refusals_wait_and_keep_their_order(self):
        body = b"x" * 5000 + b"\r\n" + b"y" * 5000
        fetch = (
            b"* 1 FETCH (BODY[] {%d}\r\n" % len(body) + body + b")\r\n"
        )
        reply = fetch + b"<TAG> OK FETCH completed\r\n"
        chunks = [reply[:3000], reply[3000:8000], reply[8000:]]
        got = self._session(chunks, seen=3000, refused=[
            b"a2 APPEND INBOX {3}\r\n",
            b"a3 STORE 1 +FLAGS (\\Seen)\r\n",
            b'a4 LOGIN "u" "p"\r\n',
            b"a5 EXPUNGE\r\n",
        ])
        assert got == [
            fetch,
            b"a2 NO APPEND not permitted (readonly)\r\n",
            b"a3 NO STORE not permitted (readonly)\r\n",
            b"a4 OK already authenticated (relay handled login)\r\n",
            b"a5 NO EXPUNGE not permitted (readonly)\r\n",
            b"a1 OK FETCH completed\r\n",
        ], [g[:80] for g in got]

    def test_refusal_waits_for_the_line_after_a_literal(self):
        """After a literal the response goes on (` FLAGS ...)`); that is
        still inside the response."""
        fetch = b"* 1 FETCH (BODY[] {5}\r\nhello FLAGS (\\Seen))\r\n"
        literal_end = fetch.index(b" FLAGS")
        # The relay forwards up to the end of the literal and holds the
        # partial line after it.
        cut = literal_end + 4
        chunks = [fetch[:cut], fetch[cut:] + b"<TAG> OK FETCH completed\r\n"]
        got = self._session(chunks, seen=literal_end,
                            refused=[b"a2 DELETE Trash\r\n"])
        assert got == [
            fetch,
            b"a2 NO DELETE not permitted (readonly)\r\n",
            b"a1 OK FETCH completed\r\n",
        ], got

    def test_refusal_goes_ahead_of_a_line_not_yet_forwarded(self):
        """A partial line the relay is holding hasn't reached the client,
        so a reply sent now is still between responses."""
        first = b"* 1 FETCH (UID 7)\r\n"
        second = b"* 2 FETCH (FLAGS (\\Seen) UID 8)\r\n"
        cut = len(first) + 12
        stream = first + second + b"<TAG> OK FETCH completed\r\n"
        chunks = [stream[:cut], stream[cut:]]
        got = self._session(chunks, seen=len(first),
                            refused=[b"a2 EXPUNGE\r\n"])
        assert got == [
            first,
            b"a2 NO EXPUNGE not permitted (readonly)\r\n",
            second,
            b"a1 OK FETCH completed\r\n",
        ], got
