"""SMTP relay — stateful TCP proxy that holds the upstream password,
authenticates on the cage's behalf, gates recipients against an
allowlist, and runs the proxy's existing inspector chain on every
DATA payload before forwarding upstream.

Threat model: the cage container holds no SMTP credentials. It connects
plaintext to the relay's listener inside the proxy container, the relay
opens an authenticated TLS connection upstream, performs AUTH PLAIN, and
proxies SMTP transactions while applying policy.

Without this relay, an SMTP-able cage is a wide-open exfiltration
channel: a compromised agent could email stolen data to any address.
The relay closes that channel by:
  * recipient_allowlist  — ``RCPT TO`` is denied unless the address or
    its domain matches.
  * sender_allowlist     — ``MAIL FROM`` is denied unless allowed.
  * inspector chain      — the assembled RFC822 message goes through
    the same secrets/entropy/content-type/body-size inspectors used on
    HTTP. A leaked API key in an outbound email body blocks the message.
  * size + recipient + rate caps — bound the blast radius if anything
    above leaks.

State machine (relay-side):

    CONNECT         -> 220 greeting
    EHLO/HELO       -> 250-... capability list (no STARTTLS, no AUTH)
    AUTH PLAIN/...  -> 235 (forged; relay handled real AUTH upstream)
    MAIL FROM:<a>   -> sender_allowlist check; 250 / 550
    RCPT TO:<a>     -> recipient_allowlist check; per-recipient 250 / 550
    DATA            -> 354; buffer body until "\\r\\n.\\r\\n";
                       size cap, inspector chain, then forward upstream
    RSET            -> 250; clear transaction
    NOOP / VRFY     -> 250 / 252
    QUIT            -> 221; close

Upstream connection is opened lazily (on the first MAIL FROM after the
cage's greeting) and reused for every transaction in the same client
session. AUTH happens once per upstream connection.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import ssl
import time
from base64 import b64encode
from email import message_from_bytes
from email.policy import compat32 as _email_policy
from typing import Callable, Optional

from inspectors.base import InspectionContext, InspectionResult, Inspector
from inspectors.util import shannon_entropy

log = logging.getLogger("agentcage.relays.smtp")


_RATE_LIMIT_RE = re.compile(r"^\s*(\d+)\s*/\s*(sec|s|min|m|hour|h)\s*$")
_RATE_UNIT_SECS = {"sec": 1, "s": 1, "min": 60, "m": 60, "hour": 3600, "h": 3600}


def _parse_rate_limit(spec: str) -> tuple[int, int]:
    """Parse '20/hour' into (count, window_seconds)."""
    m = _RATE_LIMIT_RE.match(spec)
    if not m:
        raise ValueError(f"invalid rate spec: {spec!r}")
    return int(m.group(1)), _RATE_UNIT_SECS[m.group(2).lower()]


class _RateLimiter:
    """Sliding-window rate limiter. Single asyncio loop, no locking."""

    def __init__(self, spec: str) -> None:
        self._max, self._window = _parse_rate_limit(spec)
        self._timestamps: list[float] = []

    def take(self) -> bool:
        now = time.monotonic()
        cutoff = now - self._window
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        if len(self._timestamps) >= self._max:
            return False
        self._timestamps.append(now)
        return True


def _resolve_credential(source: str) -> str:
    """Read the credential value at relay startup. All four schemes
    (env:, cmd:, systemd-creds:, podman:) populate the proxy
    container's environment at unit start."""
    scheme, _, arg = (source or "").partition(":")
    if scheme in ("env", "cmd", "systemd-creds", "podman", ""):
        if not arg:
            return ""
        return os.environ.get(arg, "")
    raise ValueError(f"unsupported relay credential source: {source!r}")


class _SmtpConfig:
    """In-proxy view of a ``protocol_relays`` entry of type smtp.
    Mirrors ``relays.imap._RelayConfig`` for code-shape parity.
    """

    def __init__(self, entry: dict) -> None:
        self.name: str = str(entry.get("name") or "")
        self.listen: str = str(entry.get("listen") or "")
        upstream = entry.get("upstream") or {}
        self.upstream_host: str = str(upstream.get("host") or "")
        self.upstream_port: int = int(upstream.get("port") or 0)
        self.upstream_tls: bool = bool(upstream.get("tls", True))

        auth = entry.get("auth") or {}
        self.auth_type: str = str(auth.get("type") or "smtp-plain")
        self.user_source: str = str(auth.get("user_source") or "")
        self.password_source: str = str(auth.get("password_source") or "")

        policy = entry.get("policy") or {}
        rcpt = policy.get("recipient_allowlist") or {}
        if isinstance(rcpt, list):
            rcpt = {"addresses": rcpt}
        self.sender_allowlist: list[str] = [
            s.lower() for s in (policy.get("sender_allowlist") or [])
        ]
        self.recipient_addresses: set[str] = {
            a.lower() for a in (rcpt.get("addresses") or [])
        }
        self.recipient_domains: list[str] = [
            d.lower() for d in (rcpt.get("domains") or [])
        ]
        self.max_message_bytes: int = int(
            policy.get("max_message_bytes", 5_242_880)
        )
        self.max_recipients: int = int(policy.get("max_recipients", 10))
        self.conn_rate_limit: str = str(
            policy.get("conn_rate_limit") or "30/min"
        )
        self.send_rate_limit: str = str(
            policy.get("send_rate_limit") or "20/hour"
        )
        # Per-readline idle timeout. RFC 5321 §4.5.3.2 minimums are 5 min
        # for command-class lines, 10 min for DATA reception. We use a
        # single 300s default and apply it to every readline so a silent
        # cage cannot pin a connection slot indefinitely. 0 disables.
        self.idle_timeout_seconds: int = int(
            policy.get("idle_timeout_seconds", 300)
        )
        if "bypass_inspectors_for_allowlisted" in policy:
            bypass = policy.get("bypass_inspectors_for_allowlisted") or []
        else:
            bypass = ["secrets", "entropy"]
        self.bypass_inspectors_for_allowlisted: set[str] = {
            str(name) for name in bypass
        }


_ADDR_RE = re.compile(r"<([^>]+)>")


def _extract_address(arg: str) -> Optional[str]:
    """Parse an SMTP address literal. ``MAIL FROM:<luca@example.com>``
    or ``RCPT TO:<bob@example.com>`` arguments. Falls back to bare
    address (no angle brackets) per RFC 5321 lenient handling.
    """
    m = _ADDR_RE.search(arg)
    if m:
        return m.group(1).strip()
    s = arg.strip()
    if s and "@" in s:
        return s
    return None


class SmtpRelay:
    """Single SMTP relay instance: one listener, one upstream target."""

    def __init__(
        self,
        entry: dict,
        *,
        audit_log: Optional[Callable[[dict], None]] = None,
        log_allowed: bool = False,
        inspectors: Optional[list[Inspector]] = None,
    ) -> None:
        self._cfg = _SmtpConfig(entry)
        self._user = _resolve_credential(self._cfg.user_source)
        self._password = _resolve_credential(self._cfg.password_source)
        if not self._user or not self._password:
            raise ValueError(
                f"smtp relay {self._cfg.name}: credentials not resolved "
                f"(user_source={self._cfg.user_source!r}, "
                f"password_source={self._cfg.password_source!r})"
            )
        self._conn_limiter = _RateLimiter(self._cfg.conn_rate_limit)
        self._send_limiter = _RateLimiter(self._cfg.send_rate_limit)
        self._server: Optional[asyncio.AbstractServer] = None
        self._sessions: set[asyncio.Task] = set()
        self._audit_log: Callable[[dict], None] = audit_log or (lambda _e: None)
        self._log_allowed = log_allowed
        # Inspector chain comes from the proxy addon. Domain-style
        # inspectors aren't meaningful for SMTP — the addon filters
        # them out before passing this list in.
        self._inspectors: list[Inspector] = list(inspectors or [])

    async def start(self) -> None:
        host, _, port_s = self._cfg.listen.rpartition(":")
        if not port_s.isdigit():
            raise ValueError(f"invalid listen address: {self._cfg.listen!r}")
        self._server = await asyncio.start_server(
            self._handle_client, host or "0.0.0.0", int(port_s)
        )
        log.info(
            "smtp relay %s listening on %s -> %s:%d "
            "(senders=%s, rcpt-domains=%s, max-bytes=%d, max-rcpt=%d)",
            self._cfg.name,
            self._cfg.listen,
            self._cfg.upstream_host,
            self._cfg.upstream_port,
            self._cfg.sender_allowlist or "(any — no policy)",
            self._cfg.recipient_domains or "(any — no policy)",
            self._cfg.max_message_bytes,
            self._cfg.max_recipients,
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        for task in list(self._sessions):
            task.cancel()
        for task in list(self._sessions):
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await self._server.wait_closed()
        self._server = None

    # ── Connection handling ──────────────────────────────

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._sessions.add(task)
            task.add_done_callback(self._sessions.discard)
        peer = client_writer.get_extra_info("peername") or ("?", 0)

        if not self._conn_limiter.take():
            log.warning(
                "smtp relay %s: connection rate limit, refusing %s:%d",
                self._cfg.name, peer[0], peer[1],
            )
            try:
                client_writer.write(b"421 connection rate limit\r\n")
                await client_writer.drain()
            except Exception:
                pass
            client_writer.close()
            return

        try:
            await self._smtp_session(client_reader, client_writer, peer)
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            log.error(
                "smtp relay %s: session error from %s:%d: %s",
                self._cfg.name, peer[0], peer[1], e,
            )
        finally:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    async def _readline_with_timeout(
        self, reader: asyncio.StreamReader,
    ) -> bytes:
        """`readline` with the configured idle timeout. Raises
        asyncio.TimeoutError on idle disconnect; the caller is expected
        to translate that into a 421 to the cage and close."""
        if self._cfg.idle_timeout_seconds <= 0:
            return await reader.readline()
        return await asyncio.wait_for(
            reader.readline(),
            timeout=self._cfg.idle_timeout_seconds,
        )

    async def _smtp_session(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        peer: tuple,
    ) -> None:
        """Drive one cage-side SMTP session.

        Lazily opens an upstream connection when the first transaction
        is committed (DATA accepted); reuses it for the rest of the
        session. Per-session txn state is carried in ``txn`` below.
        """
        self._write_line(client_writer, b"220 agentcage-smtp-relay ready")
        await client_writer.drain()

        helo_seen = False
        upstream: Optional[_UpstreamSmtp] = None
        txn = _Transaction()

        try:
            while True:
                try:
                    line = await self._readline_with_timeout(client_reader)
                except asyncio.TimeoutError:
                    log.info(
                        "smtp relay %s: cage idle for %ds, closing",
                        self._cfg.name, self._cfg.idle_timeout_seconds,
                    )
                    self._audit_log({
                        "kind": "smtp_session",
                        "relay": self._cfg.name,
                        "decision": "closed",
                        "reason": "cage idle timeout",
                    })
                    try:
                        self._write_line(
                            client_writer,
                            b"421 4.4.2 idle timeout, closing connection",
                        )
                        await client_writer.drain()
                    except Exception:
                        pass
                    return
                if not line:
                    return
                # SMTP commands are not case-sensitive; arguments may be.
                stripped = line.rstrip(b"\r\n")
                cmd_b, _, arg_b = stripped.partition(b" ")
                cmd = cmd_b.upper().decode("ascii", errors="replace")
                arg = arg_b.decode("utf-8", errors="replace")

                if cmd in ("EHLO", "HELO"):
                    helo_seen = True
                    txn = _Transaction()
                    self._send_ehlo_response(client_writer, cmd == "EHLO")
                    await client_writer.drain()
                    continue

                if not helo_seen:
                    self._write_line(client_writer, b"503 HELO/EHLO first")
                    await client_writer.drain()
                    continue

                if cmd in ("AUTH",):
                    # The relay handled upstream AUTH; forge success.
                    # If the client sends AUTH PLAIN <base64>, the
                    # base64 is consumed in arg. AUTH LOGIN sends two
                    # additional continuation lines we'd have to
                    # absorb — handle that case too.
                    self._audit_log({
                        "kind": "smtp_command",
                        "relay": self._cfg.name,
                        "command": "AUTH",
                        "decision": "intercepted",
                        "reason": "client AUTH on relay-authed connection",
                    })
                    if arg.upper().startswith("LOGIN"):
                        # Server normally responds 334 to ask for the
                        # username, then 334 for the password. We forge
                        # the dialog to 235 immediately. Continuation
                        # reads share the same idle timeout so a cage
                        # that goes silent mid-AUTH doesn't pin a slot.
                        self._write_line(client_writer, b"334 VXNlcm5hbWU6")
                        await client_writer.drain()
                        try:
                            await self._readline_with_timeout(client_reader)
                        except asyncio.TimeoutError:
                            return
                        self._write_line(client_writer, b"334 UGFzc3dvcmQ6")
                        await client_writer.drain()
                        try:
                            await self._readline_with_timeout(client_reader)
                        except asyncio.TimeoutError:
                            return
                    self._write_line(
                        client_writer,
                        b"235 2.7.0 already authenticated (relay)",
                    )
                    await client_writer.drain()
                    continue

                if cmd == "NOOP":
                    self._write_line(client_writer, b"250 OK")
                    await client_writer.drain()
                    continue

                if cmd == "RSET":
                    txn = _Transaction()
                    if upstream is not None:
                        await upstream.rset()
                    self._write_line(client_writer, b"250 OK")
                    await client_writer.drain()
                    continue

                if cmd == "QUIT":
                    self._write_line(
                        client_writer, b"221 2.0.0 agentcage signing off"
                    )
                    await client_writer.drain()
                    return

                if cmd == "VRFY":
                    self._write_line(
                        client_writer,
                        b"252 cannot VRFY user, but will accept for delivery",
                    )
                    await client_writer.drain()
                    continue

                if cmd == "MAIL":
                    if not arg.upper().startswith("FROM:"):
                        self._write_line(
                            client_writer,
                            b"501 syntax: MAIL FROM:<address>",
                        )
                        await client_writer.drain()
                        continue
                    sender = _extract_address(arg[5:].strip())
                    decision = self._sender_decision(sender)
                    if decision is not None:
                        reason = decision.encode()
                        self._write_line(
                            client_writer, b"550 " + reason,
                        )
                        await client_writer.drain()
                        continue
                    txn = _Transaction()
                    txn.sender = sender or ""
                    self._write_line(
                        client_writer, b"250 2.1.0 sender ok",
                    )
                    await client_writer.drain()
                    continue

                if cmd == "RCPT":
                    if not arg.upper().startswith("TO:"):
                        self._write_line(
                            client_writer,
                            b"501 syntax: RCPT TO:<address>",
                        )
                        await client_writer.drain()
                        continue
                    if not txn.sender:
                        self._write_line(
                            client_writer, b"503 MAIL FROM first",
                        )
                        await client_writer.drain()
                        continue
                    if len(txn.recipients) >= self._cfg.max_recipients:
                        self._audit_log({
                            "kind": "smtp_command",
                            "relay": self._cfg.name,
                            "command": "RCPT",
                            "decision": "blocked",
                            "reason": (
                                f"max_recipients ({self._cfg.max_recipients}) "
                                f"exceeded"
                            ),
                        })
                        self._write_line(
                            client_writer,
                            b"452 4.5.3 too many recipients",
                        )
                        await client_writer.drain()
                        continue
                    rcpt = _extract_address(arg[3:].strip())
                    decision = self._recipient_decision(rcpt)
                    if decision is not None:
                        self._write_line(
                            client_writer,
                            b"550 5.7.1 " + decision.encode(),
                        )
                        await client_writer.drain()
                        continue
                    txn.recipients.append(rcpt or "")
                    self._write_line(
                        client_writer,
                        b"250 2.1.5 recipient ok",
                    )
                    await client_writer.drain()
                    continue

                if cmd == "DATA":
                    if not txn.sender or not txn.recipients:
                        self._write_line(
                            client_writer,
                            b"503 need MAIL FROM and at least one RCPT TO",
                        )
                        await client_writer.drain()
                        continue
                    if not self._send_limiter.take():
                        self._audit_log({
                            "kind": "smtp_command",
                            "relay": self._cfg.name,
                            "command": "DATA",
                            "decision": "blocked",
                            "reason": "send_rate_limit exceeded",
                        })
                        self._write_line(
                            client_writer,
                            b"451 4.7.0 send rate limit exceeded",
                        )
                        await client_writer.drain()
                        continue
                    self._write_line(
                        client_writer,
                        b"354 end data with <CR><LF>.<CR><LF>",
                    )
                    await client_writer.drain()
                    try:
                        body, oversize = await self._read_data(
                            client_reader, self._cfg.max_message_bytes
                        )
                    except asyncio.TimeoutError:
                        self._audit_log({
                            "kind": "smtp_command",
                            "relay": self._cfg.name,
                            "command": "DATA",
                            "decision": "blocked",
                            "reason": "DATA reception idle timeout",
                        })
                        self._write_line(
                            client_writer,
                            b"451 4.4.2 DATA reception timed out",
                        )
                        await client_writer.drain()
                        txn = _Transaction()
                        continue
                    if oversize:
                        self._audit_log({
                            "kind": "smtp_command",
                            "relay": self._cfg.name,
                            "command": "DATA",
                            "decision": "blocked",
                            "reason": (
                                f"message exceeds max_message_bytes "
                                f"({self._cfg.max_message_bytes})"
                            ),
                            "size": len(body),
                        })
                        self._write_line(
                            client_writer,
                            b"552 5.3.4 message size exceeds limit",
                        )
                        await client_writer.drain()
                        txn = _Transaction()
                        continue
                    inspector_block = self._run_inspectors(body, txn)
                    if inspector_block is not None:
                        self._audit_log({
                            "kind": "smtp_data",
                            "relay": self._cfg.name,
                            "decision": "blocked",
                            "reason": inspector_block.reason,
                            "inspector": inspector_block.inspector,
                            "severity": inspector_block.severity,
                            "sender": txn.sender,
                            "recipients": list(txn.recipients),
                            "size": len(body),
                        })
                        self._write_line(
                            client_writer,
                            b"550 5.7.0 "
                            + inspector_block.reason.encode(
                                "utf-8", errors="replace"
                            ),
                        )
                        await client_writer.drain()
                        txn = _Transaction()
                        continue
                    # Open upstream lazily — no point burning a TLS
                    # handshake on a transaction that never makes it
                    # past policy. Both connect and deliver share the
                    # same upstream-error handling: 421 to the cage
                    # plus a structured audit entry.
                    try:
                        if upstream is None:
                            upstream = await self._connect_upstream()
                        upstream_status = await upstream.deliver(
                            txn.sender, list(txn.recipients), body
                        )
                    except Exception as e:
                        log.error(
                            "smtp relay %s: upstream delivery failed: %s",
                            self._cfg.name, e,
                        )
                        self._audit_log({
                            "kind": "smtp_data",
                            "relay": self._cfg.name,
                            "decision": "upstream_error",
                            "error": str(e),
                            "sender": txn.sender,
                            "recipients": list(txn.recipients),
                        })
                        # 451 (transient, channel stays open) rather than
                        # 421 (closing) — lets the cage's mailer retry
                        # the next message on the same session if the
                        # upstream comes back. We tear down our broken
                        # upstream connection so the next transaction
                        # opens a fresh one.
                        self._write_line(
                            client_writer,
                            b"451 4.4.0 upstream temporarily unavailable",
                        )
                        await client_writer.drain()
                        if upstream is not None:
                            try:
                                await upstream.close()
                            finally:
                                upstream = None
                        txn = _Transaction()
                        continue
                    self._audit_log({
                        "kind": "smtp_data",
                        "relay": self._cfg.name,
                        "decision": "allowed",
                        "sender": txn.sender,
                        "recipients": list(txn.recipients),
                        "size": len(body),
                        "upstream_status": upstream_status,
                    })
                    self._write_line(
                        client_writer,
                        f"250 2.0.0 ok ({upstream_status})".encode(),
                    )
                    await client_writer.drain()
                    txn = _Transaction()
                    continue

                # Unknown command — be permissive (some clients send
                # HELP, EXPN, etc.) but don't pass through.
                self._write_line(
                    client_writer, b"502 5.5.1 command not implemented",
                )
                await client_writer.drain()
        finally:
            if upstream is not None:
                await upstream.close()

    # ── Helpers ──────────────────────────────────────────

    def _send_ehlo_response(
        self, w: asyncio.StreamWriter, is_ehlo: bool
    ) -> None:
        # Don't advertise STARTTLS (we're plaintext on loopback) or
        # AUTH (relay handled it). Do advertise SIZE so clients can
        # bail early on oversized messages and 8BITMIME for utf-8 mail.
        if is_ehlo:
            lines = [
                b"agentcage-smtp-relay",
                b"8BITMIME",
                f"SIZE {self._cfg.max_message_bytes}".encode(),
                b"PIPELINING",
                b"ENHANCEDSTATUSCODES",
                b"SMTPUTF8",
            ]
            for i, payload in enumerate(lines):
                sep = b"-" if i < len(lines) - 1 else b" "
                w.write(b"250" + sep + payload + b"\r\n")
        else:
            w.write(b"250 agentcage-smtp-relay\r\n")

    def _write_line(self, w: asyncio.StreamWriter, line: bytes) -> None:
        if not line.endswith(b"\r\n"):
            line = line + b"\r\n"
        w.write(line)

    async def _read_data(
        self,
        reader: asyncio.StreamReader,
        max_bytes: int,
    ) -> tuple[bytes, bool]:
        """Read until the canonical end-of-data marker ``\\r\\n.\\r\\n``.

        Performs SMTP dot-unstuffing (RFC 5321 §4.5.2: a line that
        starts with ``..`` becomes ``.``). Returns (body, oversize).
        On oversize the body is truncated and the rest of the
        transaction is drained from the wire so the next command
        starts at a clean state.
        """
        body = bytearray()
        oversize = False
        while True:
            try:
                line = await self._readline_with_timeout(reader)
            except asyncio.TimeoutError:
                # Mid-DATA idle: treat like a truncated message and
                # let the caller surface the error to the cage.
                raise
            if not line:
                return bytes(body), oversize
            if line == b".\r\n" or line == b".\n":
                break
            if line.startswith(b".."):
                line = line[1:]
            if not oversize:
                body.extend(line)
                if len(body) > max_bytes:
                    oversize = True
                    # Drop excess; keep reading to consume the rest of
                    # the message so the SMTP framing stays in sync.
        return bytes(body), oversize

    def _sender_decision(self, sender: Optional[str]) -> Optional[str]:
        """Returns a denial reason (string) or None if allowed."""
        if not sender:
            self._audit_log({
                "kind": "smtp_command",
                "relay": self._cfg.name,
                "command": "MAIL",
                "decision": "blocked",
                "reason": "missing sender",
            })
            return "missing or malformed sender"
        if not self._cfg.sender_allowlist:
            return None  # no policy = allow
        if sender.lower() in self._cfg.sender_allowlist:
            return None
        self._audit_log({
            "kind": "smtp_command",
            "relay": self._cfg.name,
            "command": "MAIL",
            "decision": "blocked",
            "sender": sender,
            "reason": "sender not in sender_allowlist",
        })
        return f"sender {sender} not permitted"

    def _recipient_decision(self, rcpt: Optional[str]) -> Optional[str]:
        if not rcpt:
            self._audit_log({
                "kind": "smtp_command",
                "relay": self._cfg.name,
                "command": "RCPT",
                "decision": "blocked",
                "reason": "missing recipient",
            })
            return "missing or malformed recipient"
        addrs = self._cfg.recipient_addresses
        domains = self._cfg.recipient_domains
        if not addrs and not domains:
            return None  # no policy
        rl = rcpt.lower()
        if rl in addrs:
            return None
        domain = rl.rsplit("@", 1)[-1] if "@" in rl else ""
        for d in domains:
            if domain == d or domain.endswith("." + d):
                return None
        self._audit_log({
            "kind": "smtp_command",
            "relay": self._cfg.name,
            "command": "RCPT",
            "decision": "blocked",
            "recipient": rcpt,
            "reason": "recipient not in recipient_allowlist",
        })
        return f"recipient {rcpt} not permitted"

    def _run_inspectors(
        self, body: bytes, txn: "_Transaction"
    ) -> Optional[InspectionResult]:
        """Run the proxy's inspector chain on the assembled RFC822
        message. Returns the first ``block`` result, or None if all
        inspectors abstained (or returned only ``flag``).

        When the recipient allowlist is non-empty (so every recipient
        in the txn matched it — blocked recipients got 550 at RCPT
        time and never made it into ``txn.recipients``), inspectors
        named in ``bypass_inspectors_for_allowlisted`` are skipped.
        That lets legitimate user content (forwarded mail with API
        keys, base64 attachments, calendar invites) reach the trusted
        recipient instead of being blocked by a strict body filter.
        """
        if not self._inspectors:
            return None
        # "Allowlist matched" = there IS a recipient policy and every
        # surviving recipient passed it. With an empty allowlist
        # (no policy) we always run inspectors strictly.
        allowlisted = bool(
            self._cfg.recipient_addresses or self._cfg.recipient_domains
        )
        bypass = (
            self._cfg.bypass_inspectors_for_allowlisted
            if allowlisted else set()
        )
        try:
            msg = message_from_bytes(body, policy=_email_policy)
        except Exception:
            msg = None
        if msg is not None:
            content_type = msg.get_content_type() or ""
            headers: list[tuple[str, str]] = [
                (str(k), str(v)) for k, v in msg.items()
            ]
        else:
            content_type = ""
            headers = []
        ctx = InspectionContext(
            url="",
            host=self._cfg.upstream_host,
            method="SMTP_DATA",
            headers=headers,
            content_type=content_type,
            body_bytes=body,
            body_text=body.decode("utf-8", errors="replace"),
            body_size=len(body),
            body_entropy=shannon_entropy(body) if body else None,
        )
        flagged: list[InspectionResult] = []
        bypassed: list[str] = []
        for inspector in self._inspectors:
            if inspector.name in bypass:
                bypassed.append(inspector.name)
                continue
            result = inspector.inspect_request(ctx)
            if result is None:
                continue
            ctx.prior_results.append(result)
            if result.action == "block":
                return result
            if result.action == "flag":
                flagged.append(result)
        for r in flagged:
            self._audit_log({
                "kind": "smtp_data_flag",
                "relay": self._cfg.name,
                "inspector": r.inspector,
                "reason": r.reason,
                "severity": r.severity,
                "sender": txn.sender,
                "recipients": list(txn.recipients),
            })
        if bypassed:
            self._audit_log({
                "kind": "smtp_data_bypass",
                "relay": self._cfg.name,
                "bypassed": sorted(bypassed),
                "sender": txn.sender,
                "recipients": list(txn.recipients),
                "reason": "all recipients in allowlist",
            })
        return None

    async def _connect_upstream(self) -> "_UpstreamSmtp":
        ssl_ctx = (
            ssl.create_default_context() if self._cfg.upstream_tls else None
        )
        reader, writer = await asyncio.open_connection(
            self._cfg.upstream_host,
            self._cfg.upstream_port,
            ssl=ssl_ctx,
        )
        upstream = _UpstreamSmtp(
            reader, writer, self._cfg.name, self._user, self._password,
            idle_timeout_seconds=self._cfg.idle_timeout_seconds,
        )
        try:
            await upstream.handshake()
        except Exception:
            # Don't leak the socket if EHLO/AUTH fails. Otherwise the
            # upstream's handler keeps reading from a dead client and
            # `Server.wait_closed()` blocks until kernel TCP keepalive
            # detects the half-open connection (~60s).
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            raise
        return upstream


class _Transaction:
    """SMTP transaction state for one MAIL FROM ... DATA cycle."""

    __slots__ = ("sender", "recipients")

    def __init__(self) -> None:
        self.sender: str = ""
        self.recipients: list[str] = []


class _UpstreamSmtp:
    """Thin SMTP client wrapper for the upstream connection.

    Drives EHLO + AUTH PLAIN at handshake, then exposes ``deliver()``
    and ``rset()`` for transactions. Single-loop, no concurrency.

    Every readline shares the same idle timeout as the cage side: a
    silent upstream cannot pin our session indefinitely. TimeoutError
    is raised through to the relay's session loop, which translates
    it into a 451 to the cage.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        relay_name: str,
        user: str,
        password: str,
        idle_timeout_seconds: int = 0,
    ) -> None:
        self._r = reader
        self._w = writer
        self._relay_name = relay_name
        self._user = user
        self._password = password
        self._idle_timeout = idle_timeout_seconds

    async def _readline(self) -> bytes:
        if self._idle_timeout <= 0:
            return await self._r.readline()
        return await asyncio.wait_for(
            self._r.readline(), timeout=self._idle_timeout,
        )

    async def _read_response(self) -> tuple[int, str]:
        """Read a (possibly multi-line) SMTP response. Returns (code, text)."""
        text_parts: list[str] = []
        code = 0
        while True:
            line = await self._readline()
            if not line:
                raise ConnectionError("upstream closed")
            try:
                code = int(line[:3])
            except ValueError:
                raise ValueError(
                    f"malformed upstream response: {line!r}"
                )
            sep = line[3:4]
            text_parts.append(
                line[4:].decode("utf-8", errors="replace").rstrip("\r\n")
            )
            if sep != b"-":
                break
        return code, "\n".join(text_parts)

    async def _command(self, line: bytes) -> tuple[int, str]:
        if not line.endswith(b"\r\n"):
            line = line + b"\r\n"
        self._w.write(line)
        await self._w.drain()
        return await self._read_response()

    async def handshake(self) -> None:
        code, _ = await self._read_response()
        if not 200 <= code < 400:
            raise ConnectionError(f"upstream greeting code {code}")
        # Use FQDN-ish identifier; some MTAs reject empty/IP HELOs.
        ehlo_code, ehlo_text = await self._command(
            b"EHLO agentcage.local"
        )
        if ehlo_code != 250:
            raise ConnectionError(
                f"upstream EHLO rejected: {ehlo_code} {ehlo_text}"
            )
        # AUTH PLAIN: base64("\0user\0password").
        token = b64encode(
            b"\0" + self._user.encode() + b"\0" + self._password.encode()
        ).decode("ascii")
        auth_code, auth_text = await self._command(
            b"AUTH PLAIN " + token.encode("ascii"),
        )
        if auth_code not in (235,):
            raise ConnectionError(
                f"upstream AUTH failed: {auth_code} {auth_text}"
            )

    async def rset(self) -> None:
        try:
            await self._command(b"RSET")
        except Exception:
            pass

    async def deliver(
        self, sender: str, recipients: list[str], body: bytes,
    ) -> str:
        """Synthesize MAIL FROM / RCPT TO / DATA upstream."""
        code, txt = await self._command(
            f"MAIL FROM:<{sender}>".encode("utf-8"),
        )
        if code != 250:
            raise ConnectionError(f"upstream MAIL FROM rejected: {code} {txt}")
        accepted = 0
        for rcpt in recipients:
            code, txt = await self._command(
                f"RCPT TO:<{rcpt}>".encode("utf-8"),
            )
            if 200 <= code < 300:
                accepted += 1
            else:
                log.warning(
                    "smtp relay %s: upstream rejected RCPT %s: %d %s",
                    self._relay_name, rcpt, code, txt,
                )
        if accepted == 0:
            await self._command(b"RSET")
            raise ConnectionError("upstream rejected all recipients")
        code, txt = await self._command(b"DATA")
        if code != 354:
            raise ConnectionError(f"upstream DATA rejected: {code} {txt}")
        # Dot-stuff outgoing body: any line starting with `.` becomes `..`.
        stuffed = bytearray()
        for line in body.splitlines(keepends=True):
            if line.startswith(b"."):
                stuffed.append(ord("."))
            stuffed.extend(line)
        # Ensure final CRLF before the dot terminator.
        if not stuffed.endswith(b"\r\n"):
            stuffed.extend(b"\r\n")
        self._w.write(bytes(stuffed))
        self._w.write(b".\r\n")
        await self._w.drain()
        code, txt = await self._read_response()
        if not 200 <= code < 300:
            raise ConnectionError(f"upstream DATA body rejected: {code} {txt}")
        return f"upstream {code} {txt}"

    async def close(self) -> None:
        try:
            await self._command(b"QUIT")
        except Exception:
            pass
        try:
            self._w.close()
            await self._w.wait_closed()
        except Exception:
            pass
