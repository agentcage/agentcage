"""IMAP relay — stateful TCP proxy that injects LOGIN credentials and
enforces a command/folder allowlist.

Threat model: the cage container holds no IMAP credentials. It connects
to a localhost listener inside the proxy container, plaintext, no
client auth (the cage internal network is single-tenant). The relay
holds the upstream credentials in its own memory only, opens an
authenticated TLS connection to the real IMAP server, and bridges the
post-auth byte stream — applying policy on every command from the
client.

Hand-shake: the relay greets the client with ``* PREAUTH ...``, the
canonical IMAP signal that the connection is already authenticated and
the client should skip LOGIN. Any LOGIN/AUTHENTICATE the client tries
anyway is rejected with NO ("already authenticated") — it must never
reach upstream.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import ssl
import time
from typing import Callable, Optional

log = logging.getLogger("agentcage.relays.imap")


# IMAP commands that mutate mailbox state. Blocked when policy.readonly
# is true.
_DENY_COMMANDS_READONLY = frozenset({
    "APPEND",
    "DELETE",
    "STORE",
    "EXPUNGE",
    "CREATE",
    "RENAME",
    "MOVE",
    "SETMETADATA",
    "SETACL",
    "DELETEACL",
    "COPY",
})

# UID is a prefix that turns the next token into a UID-aware variant.
# UID FETCH and UID SEARCH are reads (and clients use them for everything
# because UIDs are stable across reconnects); the rest mutate state.
_UID_WRITE_SUBCOMMANDS = frozenset({
    "STORE",
    "COPY",
    "MOVE",
    "EXPUNGE",
})

# Capability tokens that break the relay's command-level visibility.
# COMPRESS=DEFLATE wraps subsequent traffic in a deflate stream; we
# can't policy-check what we can't read. Strip it from the forwarded
# CAPABILITY list so the client never tries.
_STRIPPED_CAPABILITIES = frozenset({"COMPRESS=DEFLATE"})

# Commands whose first argument is a mailbox name we want to filter
# against folder_allowlist. LIST/LSUB are intentionally excluded —
# they are metadata-only and the cage may reasonably need them to
# discover the allowlisted folders.
_MAILBOX_ARG_COMMANDS = frozenset({"SELECT", "EXAMINE", "STATUS"})


_RATE_LIMIT_RE = re.compile(r"^\s*(\d+)\s*/\s*(sec|s|min|m|hour|h)\s*$")
_RATE_UNIT_SECS = {"sec": 1, "s": 1, "min": 60, "m": 60, "hour": 3600, "h": 3600}


def _parse_rate_limit(spec: str) -> tuple[int, int]:
    """Parse '30/min' into (count, window_seconds)."""
    m = _RATE_LIMIT_RE.match(spec)
    if not m:
        raise ValueError(f"invalid conn_rate_limit: {spec!r}")
    return int(m.group(1)), _RATE_UNIT_SECS[m.group(2).lower()]


def _resolve_credential(source: str) -> str:
    """Read the credential value at relay startup.

    All four supported schemes (env:, cmd:, systemd-creds:, podman:)
    have already populated the proxy container's environment by the
    time relays start — quadlets handle the decryption at unit start.
    So at runtime we just read the env var named after the scheme arg
    (or, for env:VAR, after the colon).
    """
    scheme, _, arg = (source or "").partition(":")
    if scheme in ("env", "cmd", "systemd-creds", "podman", ""):
        if not arg:
            return ""
        return os.environ.get(arg, "")
    raise ValueError(f"unsupported relay credential source: {source!r}")


class _ConnRateLimiter:
    """Sliding-window rate limiter. Thread-unsafe — single asyncio loop."""

    def __init__(self, spec: str) -> None:
        self._max, self._window = _parse_rate_limit(spec)
        self._timestamps: list[float] = []

    def take(self) -> bool:
        now = time.monotonic()
        cutoff = now - self._window
        # Drop expired timestamps.
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        if len(self._timestamps) >= self._max:
            return False
        self._timestamps.append(now)
        return True


class _RelayConfig:
    """Minimal in-proxy view of a ``protocol_relays`` entry from YAML.

    Doesn't import from ``agentcage.config`` — the proxy ships in its
    own container without the CLI package on the path.
    """

    def __init__(self, entry: dict) -> None:
        self.name: str = str(entry.get("name") or "")
        self.listen: str = str(entry.get("listen") or "")
        upstream = entry.get("upstream") or {}
        self.upstream_host: str = str(upstream.get("host") or "")
        self.upstream_port: int = int(upstream.get("port") or 0)
        self.upstream_tls: bool = bool(upstream.get("tls", True))
        auth = entry.get("auth") or {}
        self.user_source: str = str(auth.get("user_source") or "")
        self.password_source: str = str(auth.get("password_source") or "")
        policy = entry.get("policy") or {}
        self.readonly: bool = bool(policy.get("readonly", False))
        self.folder_allowlist: list[str] = list(
            policy.get("folder_allowlist") or []
        )
        self.conn_rate_limit: str = str(
            policy.get("conn_rate_limit") or "30/min"
        )


class ImapRelay:
    """Single-relay instance: one listener, one upstream target."""

    def __init__(
        self,
        entry: dict,
        *,
        audit_log: Optional[Callable[[dict], None]] = None,
        log_allowed: bool = False,
        inspectors: Optional[list] = None,
    ) -> None:
        # ``inspectors`` is accepted for call-site symmetry with the
        # SMTP relay but is not used here — IMAP traffic is bridged
        # at the byte level and policy is per-command, not body-shape.
        self._cfg = _RelayConfig(entry)
        self._user = _resolve_credential(self._cfg.user_source)
        self._password = _resolve_credential(self._cfg.password_source)
        if not self._user or not self._password:
            raise ValueError(
                f"imap relay {self._cfg.name}: credentials not resolved "
                f"(user_source={self._cfg.user_source!r}, "
                f"password_source={self._cfg.password_source!r})"
            )
        self._rate_limiter = _ConnRateLimiter(self._cfg.conn_rate_limit)
        self._server: Optional[asyncio.AbstractServer] = None
        self._sessions: set[asyncio.Task] = set()
        # Per-decision audit sink. Defaults to a no-op so the relay is
        # usable in tests without wiring the proxy's pipeline.
        self._audit_log: Callable[[dict], None] = audit_log or (lambda _e: None)
        self._log_allowed = log_allowed
        # Filled in once during _authenticate_upstream so the PREAUTH
        # greeting can advertise the same features the upstream does.
        self._upstream_capabilities: list[str] = []

    async def start(self) -> None:
        host, _, port_s = self._cfg.listen.rpartition(":")
        if not port_s.isdigit():
            raise ValueError(f"invalid listen address: {self._cfg.listen!r}")
        self._server = await asyncio.start_server(
            self._handle_client, host or "0.0.0.0", int(port_s)
        )
        log.info(
            "imap relay %s listening on %s -> %s:%d (readonly=%s, "
            "folders=%s)",
            self._cfg.name,
            self._cfg.listen,
            self._cfg.upstream_host,
            self._cfg.upstream_port,
            self._cfg.readonly,
            self._cfg.folder_allowlist or "(any)",
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        # Cancel any in-flight client sessions so wait_closed() doesn't
        # block on long-lived IDLE connections.
        for task in list(self._sessions):
            task.cancel()
        for task in list(self._sessions):
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await self._server.wait_closed()
        self._server = None

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

        if not self._rate_limiter.take():
            log.warning(
                "imap relay %s: connection rate limit hit, refusing %s:%d",
                self._cfg.name, peer[0], peer[1],
            )
            try:
                client_writer.write(b"* BYE rate limit\r\n")
                await client_writer.drain()
            except Exception:
                pass
            client_writer.close()
            return

        try:
            await self._proxy_session(client_reader, client_writer)
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            log.error(
                "imap relay %s: session error from %s:%d: %s",
                self._cfg.name, peer[0], peer[1], e,
            )
        finally:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    async def _proxy_session(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        ssl_ctx = (
            ssl.create_default_context() if self._cfg.upstream_tls else None
        )
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self._cfg.upstream_host,
                self._cfg.upstream_port,
                ssl=ssl_ctx,
            )
        except (OSError, ssl.SSLError) as e:
            log.warning(
                "imap relay %s: upstream %s:%d unreachable: %s",
                self._cfg.name, self._cfg.upstream_host,
                self._cfg.upstream_port, e,
            )
            self._audit_log({
                "kind": "imap_upstream_unreachable",
                "relay": self._cfg.name,
                "upstream": f"{self._cfg.upstream_host}:{self._cfg.upstream_port}",
                "error": str(e),
            })
            try:
                client_writer.write(b"* BYE upstream unreachable\r\n")
                await client_writer.drain()
            except Exception:
                pass
            return
        try:
            ok = await self._authenticate_upstream(
                upstream_reader, upstream_writer, client_writer
            )
            if not ok:
                return

            caps = self._client_capability_string()
            client_writer.write(
                b"* PREAUTH [CAPABILITY " + caps.encode("ascii") + b"] "
                b"agentcage relay ready\r\n"
            )
            await client_writer.drain()

            # Run both pipes concurrently. When one finishes (typically
            # because the client disconnected), cancel the other so we
            # don't hang on a half-open upstream connection.
            t1 = asyncio.create_task(
                self._pipe_client_to_upstream(
                    client_reader, upstream_writer, client_writer,
                )
            )
            t2 = asyncio.create_task(
                self._pipe_upstream_to_client(
                    upstream_reader, client_writer
                )
            )
            done, pending = await asyncio.wait(
                {t1, t2}, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
        finally:
            try:
                upstream_writer.close()
                await upstream_writer.wait_closed()
            except Exception:
                pass

    async def _authenticate_upstream(
        self,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        client_writer: asyncio.StreamWriter,
    ) -> bool:
        # Consume upstream greeting. Many servers embed the CAPABILITY
        # list inline as `* OK [CAPABILITY ...] ready` — capture it so
        # we can forward equivalent capabilities to the client below.
        greeting = await upstream_reader.readline()
        if not greeting.startswith(b"* OK"):
            log.error(
                "imap relay %s: unexpected greeting: %r",
                self._cfg.name, greeting,
            )
            client_writer.write(b"* BYE upstream rejected\r\n")
            await client_writer.drain()
            return False
        self._capture_capabilities(greeting)

        login_tag = b"a001"
        upstream_writer.write(
            login_tag
            + b" LOGIN "
            + _quote(self._user)
            + b" "
            + _quote(self._password)
            + b"\r\n"
        )
        await upstream_writer.drain()

        while True:
            line = await upstream_reader.readline()
            if not line:
                client_writer.write(b"* BYE upstream closed\r\n")
                await client_writer.drain()
                return False
            if line.startswith(login_tag + b" "):
                rest = line[len(login_tag) + 1:].split(b" ", 1)
                status = rest[0].upper()
                if status == b"OK":
                    # The tagged OK response can also carry CAPABILITY
                    # in brackets — capture it if present, it overrides
                    # the greeting's list per RFC 3501 §6.2.3.
                    self._capture_capabilities(line)
                    log.info(
                        "imap relay %s: upstream authenticated as %s",
                        self._cfg.name, self._user,
                    )
                    if not self._upstream_capabilities:
                        await self._fetch_capabilities(
                            upstream_reader, upstream_writer
                        )
                    return True
                log.warning(
                    "imap relay %s: upstream LOGIN failed: %s",
                    self._cfg.name, line.rstrip().decode(errors="replace"),
                )
                client_writer.write(b"* BYE auth failed\r\n")
                await client_writer.drain()
                return False
            # Untagged response (e.g., `* CAPABILITY ...`) — capture if
            # it is a CAPABILITY response, otherwise discard.
            self._capture_capabilities(line)

    async def _fetch_capabilities(
        self,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        """Issue an explicit CAPABILITY command if neither the greeting
        nor the LOGIN OK response advertised one."""
        cap_tag = b"a002"
        upstream_writer.write(cap_tag + b" CAPABILITY\r\n")
        await upstream_writer.drain()
        while True:
            line = await upstream_reader.readline()
            if not line:
                return
            self._capture_capabilities(line)
            if line.startswith(cap_tag + b" "):
                return

    def _capture_capabilities(self, line: bytes) -> None:
        """Pull a CAPABILITY token list out of a server response line.

        Handles two shapes per RFC 3501:
          * ``* CAPABILITY IMAP4rev1 IDLE MOVE\\r\\n`` — untagged form.
          * ``... [CAPABILITY IMAP4rev1 IDLE] ready\\r\\n`` — bracketed
            response code, can appear in the OK greeting, the tagged
            LOGIN OK response, or any other status response.

        Tagged responses without brackets (e.g. ``a002 OK CAPABILITY
        completed``) are NOT a capability advertisement — the word
        "CAPABILITY" there is just human-readable text. Treat the
        bracketed form as the only authoritative source outside of
        the ``* CAPABILITY`` untagged form.
        """
        try:
            text = line.decode("ascii", errors="replace")
        except Exception:
            return
        # Bracketed response code: `[CAPABILITY ...]` anywhere in the
        # line. Authoritative.
        upper = text.upper()
        bracket_idx = upper.find("[CAPABILITY")
        if bracket_idx >= 0:
            after = text[bracket_idx + len("[CAPABILITY"):]
            end = after.find("]")
            if end < 0:
                return
            tokens = after[:end].split()
            if tokens:
                self._upstream_capabilities = tokens
            return
        # Untagged form: line starts with `* CAPABILITY ` (no brackets).
        stripped = text.lstrip()
        if stripped.upper().startswith("* CAPABILITY "):
            payload = stripped[len("* CAPABILITY "):]
            tokens = payload.replace("\r", " ").replace("\n", " ").split()
            if tokens:
                self._upstream_capabilities = tokens

    def _client_capability_string(self) -> str:
        """Build the CAPABILITY token list to advertise to the cage.

        Forwards upstream capabilities, removing any token in
        ``_STRIPPED_CAPABILITIES`` (currently COMPRESS=DEFLATE, which
        would prevent the relay from reading the byte stream and
        applying policy). Falls back to ``IMAP4rev1`` if the upstream
        never advertised anything we could parse.
        """
        if not self._upstream_capabilities:
            return "IMAP4rev1"
        out = [
            t for t in self._upstream_capabilities
            if t.upper() not in _STRIPPED_CAPABILITIES
        ]
        if not any(t.upper() == "IMAP4REV1" for t in out):
            out.insert(0, "IMAP4rev1")
        return " ".join(out)

    async def _pipe_client_to_upstream(
        self,
        client_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        while True:
            line = await client_reader.readline()
            if not line:
                return
            decision = self._policy_check(line)
            if decision is None:
                upstream_writer.write(line)
                await upstream_writer.drain()
                continue

            tag, reason, fake_status = decision
            client_writer.write(
                tag + b" " + fake_status + b" " + reason.encode() + b"\r\n"
            )
            await client_writer.drain()

    async def _pipe_upstream_to_client(
        self,
        upstream_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        while True:
            chunk = await upstream_reader.read(8192)
            if not chunk:
                return
            client_writer.write(chunk)
            await client_writer.drain()

    def _policy_check(
        self, line: bytes
    ) -> Optional[tuple[bytes, str, bytes]]:
        """Return (tag, reason, fake_status) if denied, else None.

        ``fake_status`` is the IMAP status word the relay forges back
        to the client: ``OK`` for "already authenticated" (semantic
        no-op for a PREAUTH'd connection), ``NO`` for actual policy
        denials.
        """
        parts = line.split(b" ", 2)
        if len(parts) < 2:
            return None
        tag = parts[0]
        cmd_b = parts[1].rstrip(b"\r\n").upper()
        cmd = cmd_b.decode("ascii", errors="replace")

        # Resolve UID prefix to its subcommand for policy purposes.
        # `UID FETCH`/`UID SEARCH` are reads (clients use them for
        # everything because UIDs are stable), the rest mutate state.
        # Bare `UID` blocking would break every modern IMAP client.
        effective_cmd = cmd
        if cmd == "UID":
            sub_b = b""
            if len(parts) >= 3:
                tail = parts[2].lstrip()
                sub_b = tail.split(b" ", 1)[0].rstrip(b"\r\n")
            sub = sub_b.upper().decode("ascii", errors="replace")
            effective_cmd = f"UID {sub}" if sub else "UID"

        if cmd in ("LOGIN", "AUTHENTICATE"):
            log.info(
                "imap relay %s: client sent %s on PREAUTH'd connection — "
                "responding OK no-op",
                self._cfg.name, cmd,
            )
            self._audit_log({
                "kind": "imap_command",
                "relay": self._cfg.name,
                "command": cmd,
                "decision": "intercepted",
                "reason": "client login on PREAUTH'd connection",
            })
            return (tag, "already authenticated (relay handled login)", b"OK")

        # Readonly policy.
        if self._cfg.readonly:
            denied = False
            if cmd in _DENY_COMMANDS_READONLY:
                denied = True
            elif cmd == "UID":
                sub = effective_cmd.split(" ", 1)[1] if " " in effective_cmd else ""
                if sub in _UID_WRITE_SUBCOMMANDS:
                    denied = True
            if denied:
                log.warning(
                    "imap relay %s: blocked %s (readonly policy)",
                    self._cfg.name, effective_cmd,
                )
                self._audit_log({
                    "kind": "imap_command",
                    "relay": self._cfg.name,
                    "command": effective_cmd,
                    "decision": "blocked",
                    "reason": "readonly policy",
                })
                return (
                    tag,
                    f"{effective_cmd} not permitted (readonly)",
                    b"NO",
                )

        if (
            cmd in _MAILBOX_ARG_COMMANDS
            and self._cfg.folder_allowlist
        ):
            args = parts[2] if len(parts) >= 3 else b""
            mailbox = _extract_mailbox(args)
            if mailbox is None:
                log.warning(
                    "imap relay %s: %s with unparseable mailbox: %r",
                    self._cfg.name, cmd, args,
                )
                self._audit_log({
                    "kind": "imap_command",
                    "relay": self._cfg.name,
                    "command": cmd,
                    "decision": "blocked",
                    "reason": "mailbox not parseable",
                })
                return (tag, f"{cmd} mailbox not parseable", b"NO")
            if not self._mailbox_allowed(mailbox):
                log.warning(
                    "imap relay %s: blocked %s on %s "
                    "(not in folder_allowlist)",
                    self._cfg.name, cmd, mailbox,
                )
                self._audit_log({
                    "kind": "imap_command",
                    "relay": self._cfg.name,
                    "command": cmd,
                    "mailbox": mailbox,
                    "decision": "blocked",
                    "reason": "not in folder_allowlist",
                })
                return (
                    tag,
                    f"{cmd} {mailbox} not in folder_allowlist",
                    b"NO",
                )

        # Allowed-command logging. Per-command volume can be high under
        # IDLE/sync flows, so default to DEBUG and only emit at INFO
        # plus an audit entry when the operator opted in via
        # `logging.allowed_requests: true` (mirrors the HTTP path).
        if self._log_allowed:
            log.info(
                "imap relay %s: allowed %s",
                self._cfg.name, effective_cmd,
            )
            self._audit_log({
                "kind": "imap_command",
                "relay": self._cfg.name,
                "command": effective_cmd,
                "decision": "allowed",
            })
        else:
            log.debug(
                "imap relay %s: allowed %s",
                self._cfg.name, effective_cmd,
            )
        return None

    def _mailbox_allowed(self, mailbox: str) -> bool:
        return mailbox in self._cfg.folder_allowlist


def _quote(value: str) -> bytes:
    """Quote an IMAP string literal-style (RFC 3501 §4.3 'quoted')."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return b'"' + escaped.encode() + b'"'


def _extract_mailbox(args: bytes) -> Optional[str]:
    """Pull the first IMAP atom/quoted-string from *args*."""
    s = args.lstrip().rstrip(b"\r\n")
    if not s:
        return None
    if s.startswith(b'"'):
        i = 1
        buf = bytearray()
        while i < len(s):
            c = s[i]
            if c == ord("\\") and i + 1 < len(s):
                buf.append(s[i + 1])
                i += 2
                continue
            if c == ord('"'):
                return buf.decode("utf-8", errors="replace")
            buf.append(c)
            i += 1
        return None
    if s.startswith(b"{"):
        # Literal — too complex for v1; deny by signalling unparseable.
        return None
    end = 0
    while end < len(s) and s[end] not in (ord(" "), ord("\t")):
        end += 1
    return s[:end].decode("utf-8", errors="replace")
