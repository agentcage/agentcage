"""Upstream TLS policy for protocol relays: extra CA + SNI override.

``test_protocol_relays.py`` deliberately bypasses TLS (``tls: false``)
so it can assert on plaintext command flow. These tests do the opposite:
a real handshake against a self-signed upstream, because the thing under
test *is* certificate verification — a mocked SSLContext would only
prove we called Python.

The certificate is minted in-process (no fixture files) and issued for
``bridge.local`` while the fake upstream listens on 127.0.0.1. That is
the exact shape of the case this feature exists for: a relay pointed at
an IP literal whose certificate can never name it.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import ssl
from contextlib import asynccontextmanager
from typing import Optional

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from relays._tls import build_upstream_ssl_context, upstream_connect_kwargs
from relays.imap import ImapRelay
from relays.smtp import SmtpRelay


# ── Self-signed certificate minting ──────────────────────


def _make_self_signed(common_name: str, tmp_path, *, with_ip_san: bool = False):
    """Mint a self-signed cert/key pair. Returns (pem, certfile, keyfile).

    Self-signed and CA-flagged, matching what a local decrypting daemon
    generates at setup: the leaf is its own trust anchor, which is
    precisely what ``ca_pem`` adds to the store.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    sans: list[x509.GeneralName] = [x509.DNSName(common_name)]
    if with_ip_san:
        sans.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(key, hashes.SHA256())
    )
    certfile = tmp_path / f"{common_name}.crt"
    keyfile = tmp_path / f"{common_name}.key"
    pem = cert.public_bytes(serialization.Encoding.PEM)
    certfile.write_bytes(pem)
    keyfile.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return pem.decode(), str(certfile), str(keyfile)


# ── Fake TLS upstream + relay harness ────────────────────


@asynccontextmanager
async def _tls_upstream(certfile: str, keyfile: str):
    """Fake IMAP upstream behind TLS that accepts any LOGIN."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)

    async def _handle(reader, writer):
        try:
            writer.write(b"* OK [CAPABILITY IMAP4rev1] fake tls upstream\r\n")
            await writer.drain()
            line = await reader.readline()
            if not line:
                return
            tag = line.split(b" ", 1)[0]
            writer.write(tag + b" OK [CAPABILITY IMAP4rev1] logged in\r\n")
            await writer.drain()
            await reader.read()
        except (ConnectionResetError, ssl.SSLError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    server = await asyncio.start_server(_handle, "127.0.0.1", 0, ssl=ctx)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


@asynccontextmanager
async def _running_relay(entry: dict, audit: Optional[list] = None):
    relay = ImapRelay(
        entry, audit_log=(audit.append if audit is not None else None)
    )
    await relay.start()
    try:
        yield relay._server.sockets[0].getsockname()[1]
    finally:
        await relay.stop()


async def _greeting(port: int) -> bytes:
    """Connect as the cage would and read the relay's opening line."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        return await asyncio.wait_for(reader.readline(), timeout=10)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _relay_entry(upstream_port: int, **upstream) -> dict:
    entry = {
        "name": "extra-ca-imap",
        "type": "imap",
        "listen": "127.0.0.1:0",
        "upstream": {"host": "127.0.0.1", "port": upstream_port, "tls": True},
        "auth": {
            "type": "imap-login",
            "user_source": "env:TEST_TLS_IMAP_USER",
            "password_source": "env:TEST_TLS_IMAP_PASS",
        },
    }
    entry["upstream"].update(upstream)
    return entry


def _run(coro):
    """Helper for non-async tests."""
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _imap_creds(monkeypatch):
    monkeypatch.setenv("TEST_TLS_IMAP_USER", "real-user@example.com")
    monkeypatch.setenv("TEST_TLS_IMAP_PASS", "real-app-password")


# ── Context construction ─────────────────────────────────


class TestContextConstruction:
    def test_no_tls_returns_no_context(self):
        assert build_upstream_ssl_context(tls=False) is None
        assert upstream_connect_kwargs(tls=False) == {"ssl": None}

    def test_servername_omitted_on_plaintext(self):
        """asyncio rejects server_hostname without ssl — never emit it."""
        kwargs = upstream_connect_kwargs(
            tls=False, tls_servername="bridge.local"
        )
        assert "server_hostname" not in kwargs

    def test_servername_passed_through_on_tls(self):
        kwargs = upstream_connect_kwargs(
            tls=True, tls_servername="bridge.local"
        )
        assert kwargs["server_hostname"] == "bridge.local"

    def test_default_context_verifies_and_checks_hostname(self):
        ctx = build_upstream_ssl_context(tls=True)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    def test_ca_pem_keeps_verification_on(self, tmp_path):
        pem, _, _ = _make_self_signed("bridge.local", tmp_path)
        ctx = build_upstream_ssl_context(tls=True, ca_pem=pem)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    def test_ca_pem_extends_the_system_store(self, tmp_path):
        """Additive: the extra anchor joins the public CAs, it doesn't
        replace them. One relay's private certificate must not be the
        reason the next relay can't reach a normal mail host.

        Written as a delta rather than an absolute count so it holds on
        hosts with an empty or unenumerable CA bundle — the 3.13/3.14 CI
        runners report zero system anchors.
        """
        pem, _, _ = _make_self_signed("bridge.local", tmp_path)
        system = build_upstream_ssl_context(tls=True)
        extended = build_upstream_ssl_context(tls=True, ca_pem=pem)

        assert len(extended.get_ca_certs()) == len(system.get_ca_certs()) + 1
        subjects = [c["subject"] for c in extended.get_ca_certs()]
        assert ((("commonName", "bridge.local"),),) in subjects


# ── End-to-end against a self-signed upstream ────────────


class TestExtraCaUpstream:
    def test_extra_ca_connects_to_self_signed_upstream(self, tmp_path):
        pem, certfile, keyfile = _make_self_signed("bridge.local", tmp_path)

        async def _go():
            async with _tls_upstream(certfile, keyfile) as up_port:
                entry = _relay_entry(
                    up_port, ca_pem=pem, tls_servername="bridge.local"
                )
                async with _running_relay(entry) as port:
                    assert (await _greeting(port)).startswith(b"* PREAUTH")

        _run(_go())

    def test_self_signed_upstream_rejected_without_extra_ca(self, tmp_path):
        """The default path must still fail closed on an unknown CA."""
        _, certfile, keyfile = _make_self_signed("bridge.local", tmp_path)
        audit: list[dict] = []

        async def _go():
            async with _tls_upstream(certfile, keyfile) as up_port:
                entry = _relay_entry(up_port, tls_servername="bridge.local")
                async with _running_relay(entry, audit) as port:
                    assert (await _greeting(port)).startswith(b"* BYE")

        _run(_go())

        failures = [
            e for e in audit if e["kind"] == "imap_upstream_unreachable"
        ]
        assert len(failures) == 1
        assert "certificate verify failed" in failures[0]["error"]

    def test_pin_without_servername_fails_hostname_check(self, tmp_path):
        """Pinning the cert is not enough when the relay dials an IP.

        The cert names ``bridge.local``; the relay connects to 127.0.0.1
        and checks *that* name unless ``tls_servername`` overrides it.
        Hostname verification stays on, so this must fail rather than
        quietly pass because the chain happened to be trusted.
        """
        pem, certfile, keyfile = _make_self_signed("bridge.local", tmp_path)
        audit: list[dict] = []

        async def _go():
            async with _tls_upstream(certfile, keyfile) as up_port:
                async with _running_relay(
                    _relay_entry(up_port, ca_pem=pem), audit
                ) as port:
                    assert (await _greeting(port)).startswith(b"* BYE")

        _run(_go())

        failures = [
            e for e in audit if e["kind"] == "imap_upstream_unreachable"
        ]
        assert len(failures) == 1
        # OpenSSL words this as "IP address mismatch" when the dialed
        # host is an address rather than a name — the anchor was accepted,
        # the name check is what rejected it.
        assert "not valid for '127.0.0.1'" in failures[0]["error"]

    def test_ip_san_cert_needs_no_servername_override(self, tmp_path):
        """An IP-SAN cert verifies against the dialed address directly."""
        pem, certfile, keyfile = _make_self_signed(
            "bridge.local", tmp_path, with_ip_san=True
        )

        async def _go():
            async with _tls_upstream(certfile, keyfile) as up_port:
                async with _running_relay(
                    _relay_entry(up_port, ca_pem=pem)
                ) as port:
                    assert (await _greeting(port)).startswith(b"* PREAUTH")

        _run(_go())

    def test_unrelated_ca_does_not_satisfy_verification(self, tmp_path):
        """Adding *a* certificate doesn't trust *any* certificate — an
        anchor for a different key must still fail verification."""
        _, certfile, keyfile = _make_self_signed("bridge.local", tmp_path)
        other_pem, _, _ = _make_self_signed("impostor.local", tmp_path)
        audit: list[dict] = []

        async def _go():
            async with _tls_upstream(certfile, keyfile) as up_port:
                entry = _relay_entry(
                    up_port, ca_pem=other_pem, tls_servername="bridge.local"
                )
                async with _running_relay(entry, audit) as port:
                    assert (await _greeting(port)).startswith(b"* BYE")

        _run(_go())

        failures = [
            e for e in audit if e["kind"] == "imap_upstream_unreachable"
        ]
        assert len(failures) == 1
        assert "certificate verify failed" in failures[0]["error"]


# ── SMTP parity ──────────────────────────────────────────


@asynccontextmanager
async def _tls_smtp_upstream(certfile: str, keyfile: str):
    """Fake submission host behind TLS: greeting, EHLO, AUTH PLAIN."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)

    async def _handle(reader, writer):
        try:
            writer.write(b"220 fake.upstream ESMTP\r\n")
            await writer.drain()
            while True:
                line = await reader.readline()
                if not line:
                    return
                upper = line.upper()
                if upper.startswith(b"EHLO") or upper.startswith(b"HELO"):
                    writer.write(b"250-fake.upstream\r\n250 AUTH PLAIN\r\n")
                elif upper.startswith(b"AUTH"):
                    writer.write(b"235 2.7.0 authenticated\r\n")
                elif upper.startswith(b"QUIT"):
                    writer.write(b"221 bye\r\n")
                    await writer.drain()
                    return
                else:
                    writer.write(b"250 ok\r\n")
                await writer.drain()
        except (ConnectionResetError, ssl.SSLError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    server = await asyncio.start_server(_handle, "127.0.0.1", 0, ssl=ctx)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


def _smtp_relay_entry(upstream_port: int, **upstream) -> dict:
    entry = {
        "name": "extra-ca-smtp",
        "type": "smtp",
        "listen": "127.0.0.1:0",
        "upstream": {"host": "127.0.0.1", "port": upstream_port, "tls": True},
        "auth": {
            "type": "smtp-plain",
            "user_source": "env:TEST_TLS_IMAP_USER",
            "password_source": "env:TEST_TLS_IMAP_PASS",
        },
    }
    entry["upstream"].update(upstream)
    return entry


class TestSmtpRelayParity:
    """The SMTP relay reads the same two keys through the same helper.

    Covered separately from the IMAP tests because a typo in either
    ``_SmtpConfig`` field name would leave the shared helper correct and
    the SMTP relay silently falling back to the system CA store.
    """

    def test_extra_ca_connects_to_self_signed_upstream(self, tmp_path):
        pem, certfile, keyfile = _make_self_signed("bridge.local", tmp_path)

        async def _go():
            async with _tls_smtp_upstream(certfile, keyfile) as up_port:
                relay = SmtpRelay(
                    _smtp_relay_entry(
                        up_port, ca_pem=pem, tls_servername="bridge.local"
                    )
                )
                upstream = await relay._connect_upstream()
                assert upstream is not None
                # Release it, or the fake server's handler sits in
                # readline() forever and wait_closed() never returns.
                await upstream.close()

        _run(_go())

    def test_self_signed_upstream_rejected_without_extra_ca(self, tmp_path):
        _, certfile, keyfile = _make_self_signed("bridge.local", tmp_path)

        async def _go():
            async with _tls_smtp_upstream(certfile, keyfile) as up_port:
                relay = SmtpRelay(
                    _smtp_relay_entry(up_port, tls_servername="bridge.local")
                )
                with pytest.raises(ssl.SSLCertVerificationError):
                    await relay._connect_upstream()

        _run(_go())
