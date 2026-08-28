"""End-to-end tests for the SMTP relay.

Strategy mirrors test_protocol_relays.py: spin up a fake upstream SMTP
server, the relay, and a client all in the test process. Assert on
what upstream actually saw and on the audit-log entries the relay
emits. No real network, no TLS handshake (TLS plumbing is exercised
in production).
"""

from __future__ import annotations

import asyncio
import re
from base64 import b64decode
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional

import pytest

from inspectors.base import (
    Inspector,
    InspectionContext,
    InspectionResult,
)
from relays.smtp import (
    SmtpRelay,
    _RateLimiter,
    _extract_address,
    _parse_rate_limit,
)


# ── Fake upstream SMTP server ────────────────────────────


@dataclass
class FakeSmtpRecorder:
    auth_seen: Optional[tuple[str, str]] = None
    transactions: list[dict] = field(default_factory=list)
    reject_rcpts: set[str] = field(default_factory=set)
    fail_auth: bool = False


async def _start_fake_upstream(
    recorder: FakeSmtpRecorder,
    expected_user: str,
    expected_pass: str,
) -> tuple[asyncio.AbstractServer, int]:
    """Start an asyncio TCP server pretending to be a Migadu submission host."""

    async def _handle(reader, writer):
        try:
            writer.write(b"220 fake.upstream ESMTP\r\n")
            await writer.drain()
            txn: dict = {"sender": "", "recipients": [], "data": b""}
            while True:
                line = await reader.readline()
                if not line:
                    return
                upper = line.upper()
                if upper.startswith(b"EHLO") or upper.startswith(b"HELO"):
                    writer.write(
                        b"250-fake.upstream\r\n"
                        b"250-AUTH PLAIN LOGIN\r\n"
                        b"250-SIZE 10485760\r\n"
                        b"250 8BITMIME\r\n"
                    )
                    await writer.drain()
                    continue
                if upper.startswith(b"AUTH PLAIN"):
                    token = line[len(b"AUTH PLAIN "):].strip()
                    try:
                        decoded = b64decode(token).split(b"\0")
                        user = decoded[1].decode()
                        pwd = decoded[2].decode()
                    except Exception:
                        writer.write(b"535 5.7.8 bad auth\r\n")
                        await writer.drain()
                        continue
                    recorder.auth_seen = (user, pwd)
                    if recorder.fail_auth or user != expected_user or pwd != expected_pass:
                        writer.write(b"535 5.7.8 bad credentials\r\n")
                        await writer.drain()
                        continue
                    writer.write(b"235 2.7.0 authenticated\r\n")
                    await writer.drain()
                    continue
                if upper.startswith(b"MAIL FROM"):
                    addr_match = re.search(rb"<([^>]+)>", line)
                    txn = {
                        "sender": addr_match.group(1).decode() if addr_match else "",
                        "recipients": [],
                        "data": b"",
                    }
                    writer.write(b"250 2.1.0 ok\r\n")
                    await writer.drain()
                    continue
                if upper.startswith(b"RCPT TO"):
                    addr_match = re.search(rb"<([^>]+)>", line)
                    rcpt = addr_match.group(1).decode() if addr_match else ""
                    if rcpt in recorder.reject_rcpts:
                        writer.write(b"550 5.7.1 upstream-reject\r\n")
                    else:
                        txn["recipients"].append(rcpt)
                        writer.write(b"250 2.1.5 ok\r\n")
                    await writer.drain()
                    continue
                if upper.startswith(b"DATA"):
                    writer.write(b"354 end with .\r\n")
                    await writer.drain()
                    body = bytearray()
                    while True:
                        ln = await reader.readline()
                        if ln == b".\r\n" or ln == b".\n":
                            break
                        if ln.startswith(b".."):
                            ln = ln[1:]
                        body.extend(ln)
                    txn["data"] = bytes(body)
                    recorder.transactions.append(dict(txn))
                    writer.write(b"250 2.0.0 queued as ABC123\r\n")
                    await writer.drain()
                    continue
                if upper.startswith(b"RSET"):
                    txn = {"sender": "", "recipients": [], "data": b""}
                    writer.write(b"250 2.0.0 ok\r\n")
                    await writer.drain()
                    continue
                if upper.startswith(b"QUIT"):
                    writer.write(b"221 2.0.0 bye\r\n")
                    await writer.drain()
                    return
                if upper.startswith(b"NOOP"):
                    writer.write(b"250 2.0.0 ok\r\n")
                    await writer.drain()
                    continue
                writer.write(b"502 5.5.1 unknown\r\n")
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
    return server, server.sockets[0].getsockname()[1]


_UNSET = object()


def _relay_entry(
    upstream_port: int,
    *,
    name: str = "test-smtp",
    listen: str = "127.0.0.1:0",
    sender_allowlist: Optional[list[str]] = None,
    recipient_addresses: Optional[list[str]] = None,
    recipient_domains: Optional[list[str]] = None,
    max_message_bytes: int = 5_242_880,
    max_recipients: int = 10,
    send_rate_limit: str = "100/min",
    conn_rate_limit: str = "100/min",
    bypass_inspectors_for_allowlisted=_UNSET,
) -> dict:
    policy: dict = {
        "sender_allowlist": sender_allowlist or [],
        "recipient_allowlist": {
            "addresses": recipient_addresses or [],
            "domains": recipient_domains or [],
        },
        "max_message_bytes": max_message_bytes,
        "max_recipients": max_recipients,
        "send_rate_limit": send_rate_limit,
        "conn_rate_limit": conn_rate_limit,
    }
    if bypass_inspectors_for_allowlisted is not _UNSET:
        policy["bypass_inspectors_for_allowlisted"] = (
            bypass_inspectors_for_allowlisted
        )
    return {
        "name": name,
        "type": "smtp",
        "listen": listen,
        "upstream": {
            "host": "127.0.0.1",
            "port": upstream_port,
            "tls": False,
        },
        "auth": {
            "type": "smtp-plain",
            "user_source": "env:TEST_SMTP_USER",
            "password_source": "env:TEST_SMTP_PASS",
        },
        "policy": policy,
    }


@asynccontextmanager
async def _running_relay(entry: dict, **kwargs):
    relay = SmtpRelay(entry, **kwargs)
    await relay.start()
    try:
        port = relay._server.sockets[0].getsockname()[1]
        yield relay, port
    finally:
        await relay.stop()


@asynccontextmanager
async def _smtp_client(port: int):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        yield reader, writer
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _read_response(reader) -> tuple[int, list[str]]:
    """Read a multi-line SMTP response. Returns (code, lines)."""
    lines: list[str] = []
    while True:
        ln = await reader.readline()
        if not ln:
            raise EOFError("connection closed during response")
        code = int(ln[:3])
        sep = ln[3:4]
        lines.append(ln[4:].decode("utf-8", errors="replace").rstrip("\r\n"))
        if sep != b"-":
            return code, lines


async def _cmd(writer, reader, line: bytes) -> tuple[int, list[str]]:
    if not line.endswith(b"\r\n"):
        line = line + b"\r\n"
    writer.write(line)
    await writer.drain()
    return await _read_response(reader)


@pytest.fixture(autouse=True)
def _smtp_creds(monkeypatch):
    monkeypatch.setenv("TEST_SMTP_USER", "agent@example.com")
    monkeypatch.setenv("TEST_SMTP_PASS", "real-app-password")


def _run(coro):
    return asyncio.run(coro)


# ── Pure helpers ─────────────────────────────────────────


class TestParseRateLimit:
    def test_min(self):
        assert _parse_rate_limit("20/hour") == (20, 3600)

    def test_invalid(self):
        with pytest.raises(ValueError):
            _parse_rate_limit("nonsense")


class TestRateLimiter:
    def test_caps(self):
        rl = _RateLimiter("2/min")
        assert rl.take() is True
        assert rl.take() is True
        assert rl.take() is False


class TestExtractAddress:
    def test_brackets(self):
        assert _extract_address("<friend@example.com>") == "friend@example.com"

    def test_brackets_with_other_text(self):
        assert _extract_address("<friend@example.com> SIZE=42") == "friend@example.com"

    def test_bare(self):
        assert _extract_address("friend@example.com") == "friend@example.com"

    def test_empty(self):
        assert _extract_address("") is None

    def test_brackets_passthrough(self):
        # We accept <bare-token> as-is; address validation is the
        # upstream MTA's job. Null sender <> is also valid (bounces).
        assert _extract_address("<bare>") == "bare"


# ── Constructor ──────────────────────────────────────────


class TestConstruction:
    def test_missing_credentials_raises(self, monkeypatch):
        monkeypatch.delenv("TEST_SMTP_USER", raising=False)
        monkeypatch.delenv("TEST_SMTP_PASS", raising=False)
        with pytest.raises(ValueError, match="credentials not resolved"):
            SmtpRelay(_relay_entry(1))

    def test_invalid_listen_raises_at_start(self):
        async def _go():
            entry = _relay_entry(1, listen="not-a-host:port")
            relay = SmtpRelay(entry)
            with pytest.raises(ValueError, match="invalid listen"):
                await relay.start()

        _run(_go())


# ── Happy-path delivery ──────────────────────────────────


class TestHappyPath:
    def test_send_round_trip(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            try:
                async with _running_relay(_relay_entry(up_port)) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        code, _ = await _read_response(r)
                        assert code == 220
                        code, _ = await _cmd(w, r, b"EHLO cage.local")
                        assert code == 250
                        code, _ = await _cmd(
                            w, r, b"MAIL FROM:<agent@example.com>",
                        )
                        assert code == 250
                        code, _ = await _cmd(
                            w, r, b"RCPT TO:<friend@example.com>",
                        )
                        assert code == 250
                        code, _ = await _cmd(w, r, b"DATA")
                        assert code == 354
                        w.write(
                            b"From: agent@example.com\r\n"
                            b"To: friend@example.com\r\n"
                            b"Subject: hi\r\n"
                            b"\r\n"
                            b"Hello there.\r\n"
                            b".\r\n"
                        )
                        await w.drain()
                        code, msg = await _read_response(r)
                        assert code == 250
                        await _cmd(w, r, b"QUIT")
                # Upstream should have seen the AUTH and one txn.
                assert recorder.auth_seen == (
                    "agent@example.com", "real-app-password",
                )
                assert len(recorder.transactions) == 1
                txn = recorder.transactions[0]
                assert txn["sender"] == "agent@example.com"
                assert txn["recipients"] == ["friend@example.com"]
                assert b"Subject: hi" in txn["data"]
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── Per-RCPT decisions ───────────────────────────────────


class TestRecipientAllowlist:
    def test_one_allowed_one_blocked_proceeds_with_allowed(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entries: list[dict] = []
            entry = _relay_entry(
                up_port,
                recipient_addresses=["friend@example.com"],
            )
            try:
                async with _running_relay(
                    entry, audit_log=entries.append
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        code_ok, _ = await _cmd(
                            w, r, b"RCPT TO:<friend@example.com>",
                        )
                        assert code_ok == 250
                        code_no, lines = await _cmd(
                            w, r, b"RCPT TO:<attacker@evil.com>",
                        )
                        assert code_no == 550
                        assert any("not permitted" in l for l in lines)
                        await _cmd(w, r, b"DATA")
                        w.write(b"X\r\n.\r\n")
                        await w.drain()
                        code, _ = await _read_response(r)
                        assert code == 250
                        await _cmd(w, r, b"QUIT")
                # Upstream saw exactly one RCPT (the allowed one).
                assert len(recorder.transactions) == 1
                assert recorder.transactions[0]["recipients"] == [
                    "friend@example.com"
                ]
                blocked_audit = [
                    e for e in entries
                    if e.get("decision") == "blocked"
                    and e.get("command") == "RCPT"
                ]
                assert blocked_audit
                assert blocked_audit[0]["recipient"] == "attacker@evil.com"
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_domain_allowlist_matches_subdomain(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entry = _relay_entry(up_port, recipient_domains=["example.com"])
            try:
                async with _running_relay(entry) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        code, _ = await _cmd(
                            w, r, b"RCPT TO:<bob@accounts.example.com>",
                        )
                        assert code == 250
                        code, _ = await _cmd(
                            w, r, b"RCPT TO:<bob@other.com>",
                        )
                        assert code == 550
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_no_allowlist_means_any(self):
        """Empty allowlist = no policy = allow any (insecure default
        documented in dataclass)."""
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entry = _relay_entry(up_port)  # no allowlist
            try:
                async with _running_relay(entry) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        code, _ = await _cmd(
                            w, r, b"RCPT TO:<anyone@example.com>",
                        )
                        assert code == 250
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── Sender allowlist ─────────────────────────────────────


class TestSenderAllowlist:
    def test_blocked_sender_rejects_at_mail_from(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entry = _relay_entry(
                up_port, sender_allowlist=["agent@example.com"],
            )
            try:
                async with _running_relay(entry) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        code, lines = await _cmd(
                            w, r, b"MAIL FROM:<spoof@evil.com>",
                        )
                        assert code == 550
                        assert any("not permitted" in l for l in lines)
                        # Allowed sender works.
                        code, _ = await _cmd(
                            w, r, b"MAIL FROM:<agent@example.com>",
                        )
                        assert code == 250
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── Caps: max_recipients, max_message_bytes, send_rate_limit ─


class TestSendRateLimitAccounting:
    """Regression: rate limiter must count UPSTREAM-ACCEPTED deliveries,
    not raw DATA attempts. Pre-fix, an inspector-blocked or oversize
    rejection consumed a rate-limit slot — so a client that triggered a
    flood of inspector-blocked retries (e.g. a himalaya retry loop on a
    base64-in-text/plain message) burned its hourly quota and locked
    itself out for an hour with zero successful sends.
    """

    def test_inspector_blocked_send_does_not_consume_slot(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entry = _relay_entry(up_port, send_rate_limit="2/min")
            try:
                async with _running_relay(
                    entry, inspectors=[_MarkerInspector()],
                ) as (_, port):
                    # Three blocked attempts: each trips the inspector
                    # but must NOT consume a rate-limit slot.
                    for _ in range(3):
                        async with _smtp_client(port) as (r, w):
                            await _read_response(r)
                            await _cmd(w, r, b"EHLO cage.local")
                            await _cmd(
                                w, r,
                                b"MAIL FROM:<agent@example.com>",
                            )
                            await _cmd(
                                w, r,
                                b"RCPT TO:<friend@example.com>",
                            )
                            await _cmd(w, r, b"DATA")
                            w.write(
                                b"Subject: bad\r\n\r\n"
                                b"contains EXFIL_MARKER_99\r\n.\r\n"
                            )
                            await w.drain()
                            code, _ = await _read_response(r)
                            assert code == 550
                    # Two clean sends should now both succeed under the
                    # 2/min cap. Pre-fix, the cap would already be
                    # exhausted by the 3 blocked attempts above.
                    for i in range(2):
                        async with _smtp_client(port) as (r, w):
                            await _read_response(r)
                            await _cmd(w, r, b"EHLO cage.local")
                            await _cmd(
                                w, r,
                                b"MAIL FROM:<agent@example.com>",
                            )
                            await _cmd(
                                w, r,
                                b"RCPT TO:<friend@example.com>",
                            )
                            await _cmd(w, r, b"DATA")
                            w.write(b"Subject: ok\r\n\r\nhi\r\n.\r\n")
                            await w.drain()
                            code, _ = await _read_response(r)
                            assert code == 250, (
                                f"send #{i+1} should succeed, got {code}"
                            )
                # Upstream got exactly 2 transactions (the clean ones).
                assert len(recorder.transactions) == 2
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_oversize_does_not_consume_slot(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entry = _relay_entry(
                up_port, max_message_bytes=64, send_rate_limit="2/min",
            )
            try:
                async with _running_relay(entry) as (_, port):
                    # Three oversize attempts — none should count.
                    for _ in range(3):
                        async with _smtp_client(port) as (r, w):
                            await _read_response(r)
                            await _cmd(w, r, b"EHLO cage.local")
                            await _cmd(
                                w, r, b"MAIL FROM:<agent@example.com>",
                            )
                            await _cmd(
                                w, r, b"RCPT TO:<friend@example.com>",
                            )
                            await _cmd(w, r, b"DATA")
                            w.write(b"X" * 200 + b"\r\n.\r\n")
                            await w.drain()
                            code, _ = await _read_response(r)
                            assert code == 552
                    # Two clean small sends should still fit under cap.
                    for i in range(2):
                        async with _smtp_client(port) as (r, w):
                            await _read_response(r)
                            await _cmd(w, r, b"EHLO cage.local")
                            await _cmd(
                                w, r, b"MAIL FROM:<agent@example.com>",
                            )
                            await _cmd(
                                w, r, b"RCPT TO:<friend@example.com>",
                            )
                            await _cmd(w, r, b"DATA")
                            w.write(b"hi\r\n.\r\n")
                            await w.drain()
                            code, _ = await _read_response(r)
                            assert code == 250, (
                                f"send #{i+1} should succeed, got {code}"
                            )
                assert len(recorder.transactions) == 2
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_upstream_error_does_not_consume_slot(self):
        async def _go():
            # Upstream that closes on every RCPT.
            recorder = FakeSmtpRecorder()
            recorder.reject_rcpts = {"friend@example.com"}
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            try:
                # Open a SECOND fake upstream that DOES accept, and we'll
                # swap to it after the upstream-error retries. Simpler:
                # use the same fake upstream but only check that after
                # 3 upstream errors, the rate limit isn't exhausted.
                entry = _relay_entry(up_port, send_rate_limit="2/min")
                async with _running_relay(entry) as (_, port):
                    for _ in range(3):
                        async with _smtp_client(port) as (r, w):
                            await _read_response(r)
                            await _cmd(w, r, b"EHLO cage.local")
                            await _cmd(
                                w, r, b"MAIL FROM:<agent@example.com>",
                            )
                            await _cmd(
                                w, r, b"RCPT TO:<friend@example.com>",
                            )
                            await _cmd(w, r, b"DATA")
                            w.write(b"hi\r\n.\r\n")
                            await w.drain()
                            code, _ = await _read_response(r)
                            assert code == 451  # upstream_error
                    # Now stop rejecting — the cap should not be hit.
                    recorder.reject_rcpts.clear()
                    for i in range(2):
                        async with _smtp_client(port) as (r, w):
                            await _read_response(r)
                            await _cmd(w, r, b"EHLO cage.local")
                            await _cmd(
                                w, r, b"MAIL FROM:<agent@example.com>",
                            )
                            await _cmd(
                                w, r, b"RCPT TO:<friend@example.com>",
                            )
                            await _cmd(w, r, b"DATA")
                            w.write(b"hi\r\n.\r\n")
                            await w.drain()
                            code, _ = await _read_response(r)
                            assert code == 250
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


class TestCaps:
    def test_max_recipients_enforced(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entry = _relay_entry(up_port, max_recipients=2)
            try:
                async with _running_relay(entry) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        for i in range(2):
                            code, _ = await _cmd(
                                w, r,
                                f"RCPT TO:<u{i}@x.com>".encode(),
                            )
                            assert code == 250
                        code, _ = await _cmd(
                            w, r, b"RCPT TO:<u3@x.com>",
                        )
                        assert code == 452
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_max_message_bytes_enforced(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entry = _relay_entry(up_port, max_message_bytes=128)
            try:
                async with _running_relay(entry) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<u@x.com>")
                        await _cmd(w, r, b"DATA")
                        # Send a body larger than 128 bytes.
                        w.write(b"X" * 200 + b"\r\n.\r\n")
                        await w.drain()
                        code, lines = await _read_response(r)
                        assert code == 552
                        assert any("size" in l.lower() for l in lines)
                # Upstream must NOT have seen anything.
                assert recorder.transactions == []
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_send_rate_limit(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entry = _relay_entry(up_port, send_rate_limit="2/min")
            try:
                async with _running_relay(entry) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        for i in range(2):
                            await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                            await _cmd(w, r, b"RCPT TO:<u@x.com>")
                            await _cmd(w, r, b"DATA")
                            w.write(b"hi\r\n.\r\n")
                            await w.drain()
                            code, _ = await _read_response(r)
                            assert code == 250
                        # Third should be rate-limited.
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<u@x.com>")
                        code, _ = await _cmd(w, r, b"DATA")
                        assert code == 451
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── AUTH interception ────────────────────────────────────


class TestEhloAdvertisement:
    """Regression: real-world clients (himalaya, msmtp) refuse to send
    mail when the server doesn't advertise any AUTH method, even on a
    plaintext connection where they don't strictly need to authenticate.
    The relay must advertise AUTH PLAIN LOGIN; the AUTH itself is forged
    by the relay, not forwarded upstream."""

    def test_ehlo_advertises_auth(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            try:
                async with _running_relay(_relay_entry(up_port)) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        code, lines = await _cmd(w, r, b"EHLO test.local")
                        assert code == 250
                        joined = " ".join(lines)
                        assert "AUTH PLAIN LOGIN" in joined, joined
                        # And no STARTTLS — already plaintext on loopback.
                        assert "STARTTLS" not in joined
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


class TestAuthIntercept:
    def test_client_auth_plain_intercepted(self):
        """Cage tries AUTH PLAIN on the relay-authed connection. The
        relay forges 235 without forwarding the credential bytes."""
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            try:
                async with _running_relay(_relay_entry(up_port)) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        # Cage attempts AUTH; relay forges 235.
                        from base64 import b64encode
                        token = b64encode(b"\0fake\0fake").decode()
                        code, _ = await _cmd(
                            w, r,
                            b"AUTH PLAIN " + token.encode(),
                        )
                        assert code == 235
                        # Upstream auth was already done with REAL creds.
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<u@x.com>")
                        code, _ = await _cmd(w, r, b"DATA")
                        assert code == 354
                        w.write(b"hi\r\n.\r\n")
                        await w.drain()
                        await _read_response(r)
                # Upstream saw the REAL credentials, never the cage's.
                assert recorder.auth_seen == (
                    "agent@example.com", "real-app-password",
                )
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── Inspector chain integration ──────────────────────────


class _MarkerInspector(Inspector):
    """Test inspector that blocks any body containing a marker word."""

    name = "marker"
    marker = "EXFIL_MARKER_99"

    def configure(self, config: dict) -> None:
        pass

    def inspect_request(self, ctx):
        if ctx.body_text and self.marker in ctx.body_text:
            return InspectionResult(
                inspector=self.name,
                action="block",
                reason=f"contains {self.marker}",
                severity="critical",
            )
        return None


class TestInspectorIntegration:
    def test_inspector_block_rejects_data(self):
        """A blocking inspector on the body causes the relay to reject
        DATA with 550 and the upstream never sees the message."""
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entries: list[dict] = []
            try:
                async with _running_relay(
                    _relay_entry(up_port),
                    audit_log=entries.append,
                    inspectors=[_MarkerInspector()],
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        w.write(
                            b"Subject: leak\r\n\r\n"
                            b"This contains EXFIL_MARKER_99 in body\r\n"
                            b".\r\n"
                        )
                        await w.drain()
                        code, lines = await _read_response(r)
                        assert code == 550
                        assert any(
                            "EXFIL_MARKER_99" in l for l in lines
                        )
                # Upstream never saw the transaction.
                assert recorder.transactions == []
                # Audit log records the inspector block.
                blocks = [
                    e for e in entries
                    if e.get("kind") == "smtp_data"
                    and e.get("decision") == "blocked"
                ]
                assert blocks
                assert blocks[0]["inspector"] == "marker"
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_inspector_allow_passes_through(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            try:
                async with _running_relay(
                    _relay_entry(up_port),
                    inspectors=[_MarkerInspector()],
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        w.write(
                            b"Subject: clean\r\n\r\n"
                            b"This message contains nothing scary.\r\n"
                            b".\r\n"
                        )
                        await w.drain()
                        code, _ = await _read_response(r)
                        assert code == 250
                assert len(recorder.transactions) == 1
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_secrets_inspector_blocks_anthropic_key_in_body(self):
        """Use the real SecretsInspector to verify the wire-up: a
        leaked Anthropic key in an outbound email body must be
        blocked. allow_to_domains doesn't help because the SMTP host
        isn't anthropic.com."""
        from inspectors.secrets import SecretsInspector

        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            insp = SecretsInspector()
            insp.configure({"enabled": True, "action": "block"})
            try:
                async with _running_relay(
                    _relay_entry(up_port), inspectors=[insp]
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        # Realistic-looking key; matches the regex.
                        w.write(
                            b"Subject: secret leak\r\n\r\n"
                            b"Here is the key: "
                            b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAA\r\n"
                            b".\r\n"
                        )
                        await w.drain()
                        code, lines = await _read_response(r)
                        assert code == 550
                        assert any("anthropic" in l.lower() for l in lines)
                assert recorder.transactions == []
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── Allowlist-trust bypass ───────────────────────────────


class TestAllowlistInspectorBypass:
    """When all recipients are in recipient_allowlist, configured
    inspectors are skipped on DATA. Default skip set is {secrets,
    entropy, content-type} so legitimate human email content (forwarded
    recovery codes, base64 attachments, PGP-signed text/plain, long
    URLs) reaches the trusted recipient. body-size still applies as a
    structural cap."""

    def test_default_bypass_lets_secret_through_to_allowlisted(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            from inspectors.secrets import SecretsInspector
            insp = SecretsInspector()
            insp.configure({"enabled": True, "action": "block"})
            entries: list[dict] = []
            try:
                async with _running_relay(
                    _relay_entry(
                        up_port, recipient_addresses=["friend@example.com"],
                    ),
                    audit_log=entries.append,
                    inspectors=[insp],
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        w.write(
                            b"Subject: forwarded recovery info\r\n\r\n"
                            b"Here is your key: "
                            b"sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
                            b".\r\n"
                        )
                        await w.drain()
                        code, _ = await _read_response(r)
                        assert code == 250
                # Upstream actually delivered the message.
                assert len(recorder.transactions) == 1
                # Audit entry recorded that secrets was bypassed.
                bypasses = [
                    e for e in entries
                    if e.get("kind") == "smtp_data_bypass"
                ]
                assert bypasses, entries
                assert "secrets" in bypasses[0]["bypassed"]
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_explicit_empty_bypass_keeps_strict_mode(self):
        """Operator opts out: secrets in body block even for
        allowlisted recipients."""
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            from inspectors.secrets import SecretsInspector
            insp = SecretsInspector()
            insp.configure({"enabled": True, "action": "block"})
            try:
                async with _running_relay(
                    _relay_entry(
                        up_port,
                        recipient_addresses=["friend@example.com"],
                        bypass_inspectors_for_allowlisted=[],
                    ),
                    inspectors=[insp],
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        w.write(
                            b"Subject: leak\r\n\r\n"
                            b"sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
                            b".\r\n"
                        )
                        await w.drain()
                        code, _ = await _read_response(r)
                        assert code == 550
                assert recorder.transactions == []
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_no_allowlist_means_no_bypass(self):
        """Empty allowlist = no recipient policy = no body trust.
        Inspectors run strictly even with the default bypass list,
        because there's no allowlist match to bypass against."""
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            from inspectors.secrets import SecretsInspector
            insp = SecretsInspector()
            insp.configure({"enabled": True, "action": "block"})
            try:
                # No recipient_allowlist => bypass cannot trigger.
                async with _running_relay(
                    _relay_entry(up_port),
                    inspectors=[insp],
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        w.write(
                            b"Subject: leak\r\n\r\n"
                            b"sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
                            b".\r\n"
                        )
                        await w.drain()
                        code, _ = await _read_response(r)
                        assert code == 550
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_default_bypass_lets_base64_through_to_allowlisted(self):
        """Real-world jacque scenario: a forwarded mail in text/plain
        contains a 600+ char base64 chunk (PGP signature, quoted token,
        long URL). Pre-fix the content-type inspector blocked these
        even for allowlisted recipients, triggering himalaya retry
        loops. Default bypass now includes content-type."""
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            from inspectors.content_type import ContentTypeInspector
            insp = ContentTypeInspector()
            insp.configure({})  # defaults
            entries: list[dict] = []
            try:
                async with _running_relay(
                    _relay_entry(
                        up_port, recipient_addresses=["friend@example.com"],
                    ),
                    audit_log=entries.append,
                    inspectors=[insp],
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        big_b64 = b"A" * 700  # >256, looks base64-ish
                        w.write(
                            b"Subject: forwarded\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"\r\n"
                            b"forwarded chunk: " + big_b64 + b"\r\n.\r\n"
                        )
                        await w.drain()
                        code, _ = await _read_response(r)
                        assert code == 250, code
                # Upstream actually delivered.
                assert len(recorder.transactions) == 1
                # Audit recorded the bypass including content-type.
                bypasses = [
                    e for e in entries
                    if e.get("kind") == "smtp_data_bypass"
                ]
                assert bypasses
                assert "content-type" in bypasses[0]["bypassed"]
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_bypass_does_not_skip_body_size(self):
        """body-size is structural, never bypassed by default. Even
        a trusted recipient cannot receive a 100MB DATA payload."""
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            from inspectors.body_size import BodySizeInspector
            insp = BodySizeInspector()
            insp.configure({"max_bytes": 256})
            try:
                async with _running_relay(
                    _relay_entry(
                        up_port, recipient_addresses=["friend@example.com"],
                    ),
                    inspectors=[insp],
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        w.write(b"X" * 1024 + b"\r\n.\r\n")
                        await w.drain()
                        code, _ = await _read_response(r)
                        # body-size inspector blocks regardless of allowlist.
                        assert code == 550
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── Dot-stuffing round-trip ──────────────────────────────


class TestDotStuffing:
    def test_dot_at_line_start_unstuffed_then_restuffed(self):
        """A line starting with "." in the message must be unstuffed by
        the relay's reader (RFC 5321 §4.5.2) and then re-stuffed when
        forwarded upstream. Verify by sending a body whose textual
        content includes a leading-dot line and checking what upstream
        actually stored."""
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            try:
                async with _running_relay(_relay_entry(up_port)) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        # Client wire form: ".." prefix on the dotted line.
                        w.write(
                            b"Subject: dotty\r\n\r\n"
                            b"line1\r\n"
                            b"..dotted-line\r\n"
                            b"line3\r\n"
                            b".\r\n"
                        )
                        await w.drain()
                        code, _ = await _read_response(r)
                        assert code == 250
                txn = recorder.transactions[0]
                # Upstream should have received the un-stuffed text
                # (single-dot leading line), since the upstream parser
                # also unstuffs.
                assert b"\r\n.dotted-line\r\n" in txn["data"]
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── Audit pipeline shape ─────────────────────────────────


class TestAuditEntries:
    def test_allowed_delivery_emits_audit_entry(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entries: list[dict] = []
            try:
                async with _running_relay(
                    _relay_entry(up_port), audit_log=entries.append
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        w.write(b"Subject: hi\r\n\r\nbody\r\n.\r\n")
                        await w.drain()
                        await _read_response(r)
                # Should be at least one smtp_data allowed entry.
                allowed = [
                    e for e in entries
                    if e.get("kind") == "smtp_data"
                    and e.get("decision") == "allowed"
                ]
                assert allowed
                e = allowed[0]
                assert e["sender"] == "agent@example.com"
                assert e["recipients"] == ["friend@example.com"]
                assert e["size"] > 0
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── #224: upstream-rejected RCPTs surfaced in the audit log ──


class TestUpstreamRcptRejectionAudit:
    """When the cage's ``recipient_allowlist`` passes a set of RCPTs
    but the upstream rejects a subset, the ``allowed`` audit entry must
    record *who actually received* the message separately from *who the
    cage let through but the upstream refused*. Pre-fix both were
    flattened into a single ``recipients`` list under
    ``decision: allowed``, so forensics could not tell which recipients
    the message actually reached."""

    def test_rejected_rcpts_recorded_separately_from_accepted(self):
        async def _go():
            recorder = FakeSmtpRecorder()
            # Upstream rejects two of the five allowlisted recipients.
            recorder.reject_rcpts = {
                "gone@up.example.com",
                "also-gone@up.example.com",
            }
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entries: list[dict] = []
            entry = _relay_entry(
                up_port,
                recipient_domains=["example.com"],
            )
            try:
                async with _running_relay(
                    entry, audit_log=entries.append,
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        for rcpt in (
                            "ok1@example.com",
                            "gone@up.example.com",
                            "ok2@example.com",
                            "also-gone@up.example.com",
                            "ok3@example.com",
                        ):
                            code, _ = await _cmd(
                                w, r, f"RCPT TO:<{rcpt}>".encode(),
                            )
                            # The cage allowlisted all of them, so
                            # every RCPT is accepted by the relay.
                            assert code == 250, (rcpt, code)
                        await _cmd(w, r, b"DATA")
                        w.write(b"Subject: hi\r\n\r\nbody\r\n.\r\n")
                        await w.drain()
                        code, _ = await _read_response(r)
                        assert code == 250, code
                allowed = [
                    e for e in entries
                    if e.get("kind") == "smtp_data"
                    and e.get("decision") == "allowed"
                ]
                assert allowed
                e = allowed[0]
                # The audit `recipients` field lists ONLY the recipients
                # the upstream actually accepted.
                assert sorted(e["recipients"]) == [
                    "ok1@example.com",
                    "ok2@example.com",
                    "ok3@example.com",
                ]
                # Rejected RCPTs are carried in a dedicated field.
                assert sorted(e["recipients_rejected_upstream"]) == [
                    "also-gone@up.example.com",
                    "gone@up.example.com",
                ]
                # Upstream only queued one message — to the accepted set.
                assert len(recorder.transactions) == 1
                assert sorted(recorder.transactions[0]["recipients"]) == [
                    "ok1@example.com",
                    "ok2@example.com",
                    "ok3@example.com",
                ]
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_all_accepted_omits_empty_rejected_field(self):
        """When upstream accepts every RCPT, the rejected field is an
        empty list (present, not absent)."""
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entries: list[dict] = []
            try:
                async with _running_relay(
                    _relay_entry(up_port, recipient_domains=["example.com"]),
                    audit_log=entries.append,
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        w.write(b"hi\r\n.\r\n")
                        await w.drain()
                        await _read_response(r)
                allowed = [
                    e for e in entries
                    if e.get("kind") == "smtp_data"
                    and e.get("decision") == "allowed"
                ]
                assert allowed
                e = allowed[0]
                assert e["recipients"] == ["friend@example.com"]
                assert e["recipients_rejected_upstream"] == []
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── A1: upstream connection failures surface as 451 + audit entry ──


class TestUpstreamConnectionFailure:
    """REGRESSION: pre-fix, an upstream that wouldn't accept the TCP
    connection caused the cage's session to drop with no SMTP response
    and no audit entry. Mirrors the IMAP-side test from PR #85's review.
    """

    def test_connect_refused_sends_451(self):
        async def _go():
            # Find a port that will refuse TCP connect.
            tmp = await asyncio.start_server(
                lambda r, w: None, "127.0.0.1", 0,
            )
            dead_port = tmp.sockets[0].getsockname()[1]
            tmp.close()
            await tmp.wait_closed()

            entries: list[dict] = []
            entry = _relay_entry(dead_port)
            async with _running_relay(
                entry, audit_log=entries.append,
            ) as (_, port):
                async with _smtp_client(port) as (r, w):
                    await _read_response(r)
                    await _cmd(w, r, b"EHLO cage.local")
                    await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                    await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                    await _cmd(w, r, b"DATA")
                    w.write(b"hi\r\n.\r\n")
                    await w.drain()
                    code, lines = await _read_response(r)
                    assert code == 451, code
                    assert any("upstream" in l.lower() for l in lines)

            errors = [
                e for e in entries
                if e.get("kind") == "smtp_data"
                and e.get("decision") == "upstream_error"
            ]
            assert errors, entries
            assert "error" in errors[0]

        _run(_go())

    def test_upstream_auth_rejected_sends_451(self):
        """Upstream accepts the TCP/TLS connection and EHLO but rejects
        AUTH PLAIN. Same code path as connect-refused: relay surfaces
        451 + audit upstream_error."""
        async def _go():
            recorder = FakeSmtpRecorder()
            recorder.fail_auth = True
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entries: list[dict] = []
            try:
                async with _running_relay(
                    _relay_entry(up_port),
                    audit_log=entries.append,
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        w.write(b"hi\r\n.\r\n")
                        await w.drain()
                        code, _ = await _read_response(r)
                        assert code == 451, code
                errors = [
                    e for e in entries
                    if e.get("kind") == "smtp_data"
                    and e.get("decision") == "upstream_error"
                ]
                assert errors
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())

    def test_all_recipients_upstream_rejected(self):
        """Cage's recipient passes our policy; upstream rejects every
        RCPT TO. ``_UpstreamSmtp.deliver`` raises; relay returns 451."""
        async def _go():
            recorder = FakeSmtpRecorder()
            recorder.reject_rcpts = {"friend@example.com"}
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entries: list[dict] = []
            try:
                async with _running_relay(
                    _relay_entry(up_port),
                    audit_log=entries.append,
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        w.write(b"hi\r\n.\r\n")
                        await w.drain()
                        code, _ = await _read_response(r)
                        assert code == 451, code
                # Audit captures the upstream rejection.
                errors = [
                    e for e in entries
                    if e.get("kind") == "smtp_data"
                    and e.get("decision") == "upstream_error"
                ]
                assert errors
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── A2: idle timeouts close the session cleanly ─────────


class TestIdleTimeouts:
    def test_cage_idle_disconnect(self):
        """Cage opens TCP, sends nothing. Relay closes after the
        configured idle window and emits a smtp_session audit entry.
        """
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entry = _relay_entry(up_port)
            entry["policy"]["idle_timeout_seconds"] = 1
            entries: list[dict] = []
            try:
                async with _running_relay(
                    entry, audit_log=entries.append,
                ) as (_, port):
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", port,
                    )
                    try:
                        # Drain the 220 greeting then sit silent.
                        await _read_response(reader)
                        # Wait for the relay to close us out.
                        line = await asyncio.wait_for(
                            reader.readline(), timeout=5,
                        )
                        # Should be the relay's 421 idle-timeout farewell.
                        assert line.startswith(b"421"), line
                        assert b"idle" in line.lower()
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                # Audit should record the closure.
                closes = [
                    e for e in entries
                    if e.get("kind") == "smtp_session"
                    and e.get("decision") == "closed"
                ]
                assert closes
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())


# ── Inspector flag-action recorded but not blocking ─────


class _MarkerFlagInspector(Inspector):
    """Test inspector that flags (not blocks) on a marker word."""

    name = "marker-flag"
    marker = "FLAG_MARKER_42"

    def configure(self, config: dict) -> None:
        pass

    def inspect_request(self, ctx):
        if ctx.body_text and self.marker in ctx.body_text:
            return InspectionResult(
                inspector=self.name,
                action="flag",
                reason=f"flagged {self.marker}",
                severity="warning",
            )
        return None


class TestInspectorFlagAction:
    def test_flag_does_not_block_but_audits(self):
        """An inspector that returns ``action: flag`` should not stop
        the message from being delivered, but the relay must record a
        ``smtp_data_flag`` audit entry."""
        async def _go():
            recorder = FakeSmtpRecorder()
            upstream, up_port = await _start_fake_upstream(
                recorder, "agent@example.com", "real-app-password",
            )
            entries: list[dict] = []
            try:
                async with _running_relay(
                    _relay_entry(up_port),
                    audit_log=entries.append,
                    inspectors=[_MarkerFlagInspector()],
                ) as (_, port):
                    async with _smtp_client(port) as (r, w):
                        await _read_response(r)
                        await _cmd(w, r, b"EHLO cage.local")
                        await _cmd(w, r, b"MAIL FROM:<agent@example.com>")
                        await _cmd(w, r, b"RCPT TO:<friend@example.com>")
                        await _cmd(w, r, b"DATA")
                        w.write(
                            b"Subject: hi\r\n\r\n"
                            b"contains FLAG_MARKER_42 in body\r\n.\r\n"
                        )
                        await w.drain()
                        code, _ = await _read_response(r)
                        assert code == 250, code
                # Upstream got the message.
                assert len(recorder.transactions) == 1
                # Audit recorded the flag.
                flags = [
                    e for e in entries
                    if e.get("kind") == "smtp_data_flag"
                ]
                assert flags
                assert flags[0]["inspector"] == "marker-flag"
            finally:
                upstream.close()
                await upstream.wait_closed()

        _run(_go())
