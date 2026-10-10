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
import re
import ssl
import time
from typing import Callable, Optional

from relays._tls import upstream_connect_kwargs
from relays._validate import RATE_LIMIT_RE, RATE_UNIT_SECS
from secret_lookup import resolve_credential

log = logging.getLogger("agentcage.relays.imap")


# IMAP commands that mutate mailbox state. Blocked when policy.readonly
# is true.
#
# CLOSE is here for the same reason it is denied in "organise" (see below):
# RFC 3501 §6.4.2 makes it expunge every \Deleted message in the selected
# mailbox. STORE being denied stops the relay from setting the flag, but not
# another client sharing the mailbox, so allowing CLOSE would let a readonly
# relay destroy mail.
#
# REPLACE is here because RFC 8508 defines it as an atomic APPEND of a new
# message plus an EXPUNGE of the old one, both of which this mode refuses.
#
# SETQUOTA (RFC 9208) changes the account's storage limits, and SETANNOTATION
# (the Cyrus command from draft-daboo-imap-annotatemore) writes mailbox
# annotations, the predecessor of SETMETADATA. RFC 5257 message annotations
# are written with STORE, which this mode already refuses whole.
_DENY_COMMANDS_READONLY = frozenset({
    "APPEND",
    "REPLACE",
    "DELETE",
    "STORE",
    "EXPUNGE",
    "CLOSE",
    "CREATE",
    "RENAME",
    "MOVE",
    "SETMETADATA",
    "SETANNOTATION",
    "SETQUOTA",
    "SETACL",
    "DELETEACL",
    "COPY",
})

# Commands denied in write_mode "organise": everything that destroys mail
# or restructures the mailbox. MOVE/COPY/STORE are deliberately absent —
# filing and flagging are the point of this mode.
#
# CLOSE is in here for a reason that is easy to miss: RFC 3501 §6.4.2 makes
# CLOSE expunge every \Deleted message in the selected mailbox as a side
# effect. Denying EXPUNGE while allowing CLOSE would leave the destructive
# path wide open behind an innocuous-looking verb.
#
# CREATE is deliberately NOT here. The line this mode draws is "refuse what
# destroys, permit what is recoverable", and making a folder is recoverable —
# you can delete it again. Filing mail into folders is most of what organising
# means, and requiring the mailbox owner to hand-create every destination
# first defeats the point of the mode.
#
# DELETE and RENAME stay denied, on the same test. DELETE removes a folder and
# whatever is filed in it. RENAME looks harmless but is not: server-side
# filters and rules refer to folders by name, so a rename can silently stop
# incoming mail being sorted, and nothing about the result looks broken.
#
# APPEND is denied because it injects new messages — the way you would
# fabricate mail in someone's mailbox.
#
# REPLACE (RFC 8508) is APPEND and EXPUNGE in one atomic command: it writes a
# new message and permanently removes the old one. Both halves are refused
# here on their own, so the combination is too.
#
# SETQUOTA, SETANNOTATION and SETMETADATA change account and mailbox settings
# rather than file or flag mail, so they are outside what this mode is for.
# The RFC 5257 form of an annotation write, STORE ... ANNOTATION, is refused
# separately by _store_writes_annotation().
_DENY_COMMANDS_ORGANISE = frozenset({
    "EXPUNGE",
    "CLOSE",
    "APPEND",
    "REPLACE",
    "DELETE",
    "RENAME",
    "SETMETADATA",
    "SETANNOTATION",
    "SETQUOTA",
    "SETACL",
    "DELETEACL",
})

# UID variants denied in "organise". UID STORE/COPY/MOVE stay allowed; the
# \Deleted flag is filtered separately by _store_adds_deleted(). UID REPLACE
# is the UID form of RFC 8508 REPLACE (append + expunge).
_UID_DENY_ORGANISE = frozenset({"EXPUNGE", "REPLACE"})

# UID is a prefix that turns the next token into a UID-aware variant.
# UID FETCH and UID SEARCH are reads (and clients use them for everything
# because UIDs are stable across reconnects); the rest mutate state.
_UID_WRITE_SUBCOMMANDS = frozenset({
    "STORE",
    "COPY",
    "MOVE",
    "EXPUNGE",
    "REPLACE",
})

# Commands refused in every write_mode, "full" included, because each one
# would take the byte stream out of the relay's sight, and every check the
# relay makes (write_mode, folders, audit) reads that stream as IMAP lines.
#
#   COMPRESS (RFC 4978) switches both directions to DEFLATE right after the
#     server's OK. From then on the relay sees compressed bytes: an EXPUNGE
#     in readonly, or a SELECT of a denied folder, would pass unseen.
#   STARTTLS (RFC 3501 §6.2.1) starts TLS on the existing connection. The
#     relay's own upstream leg is already TLS or deliberately plaintext;
#     forwarding the cage's STARTTLS would let it negotiate TLS end to end
#     with a plaintext upstream, leaving the relay relaying ciphertext. It is
#     only valid before authentication anyway, and the cage is PREAUTH'd.
#   UNAUTHENTICATE (RFC 8437) drops the upstream session back to the
#     not-authenticated state, the state where STARTTLS and AUTHENTICATE
#     with a SASL security layer are valid. The relay's session is meant to
#     stay authenticated as the relay's own user for its whole life.
#
# AUTHENTICATE (whose SASL security layer could also wrap the stream) and
# LOGIN never reach the upstream either: see the PREAUTH handling in
# _policy_check().
_REFUSED_COMMANDS = {
    "COMPRESS": "relay cannot inspect a compressed stream",
    "STARTTLS": "relay cannot inspect a TLS stream",
    "UNAUTHENTICATE": "relay session stays authenticated",
}

# Capability tokens never advertised to the cage, because the command they
# announce is in _REFUSED_COMMANDS. Hiding them keeps a well-behaved client
# from trying; the refusal above is what stops one that tries anyway.
_STRIPPED_CAPABILITIES = frozenset({"STARTTLS", "UNAUTHENTICATE"})

# Prefixes of capability tokens hidden the same way. COMPRESS=<algorithm>
# covers DEFLATE and any mechanism a server adds later.
_STRIPPED_CAPABILITY_PREFIXES = ("COMPRESS=",)

# Capability tokens also stripped when write_mode is "none" or "organise",
# because the command they advertise is refused there. REPLACE (RFC 8508) is
# APPEND + EXPUNGE; advertising it would only steer a client into a NO.
_STRIPPED_CAPABILITIES_RESTRICTED = frozenset({"REPLACE"})

# Commands whose first argument is a mailbox name we want to filter
# against folder_allowlist. LIST/LSUB are intentionally excluded —
# they are metadata-only and the cage may reasonably need them to
# discover the allowlisted folders.
_MAILBOX_ARG_COMMANDS = frozenset({"SELECT", "EXAMINE", "STATUS"})

# How much of one upstream response line _ResponseFilter holds back before
# it stops holding that line and streams the rest raw. It must be well above
# the longest line the cage can send (asyncio's StreamReader default limit,
# 64 KiB): the upstream echoes the cage's tag at the start of a tagged
# response and the [CAPABILITY ...] response code follows it, so a long tag
# must not push the code past the limit.
_HELD_LINE_LIMIT = 256 * 1024

# An IMAP literal announcement at the end of a response line: "{123}" CRLF,
# or the RFC 3516 literal8 "~{123}" CRLF (same tail). Looked for in the last
# _LITERAL_TAIL_BYTES of a line only.
_LITERAL_TAIL_RE = re.compile(rb"\{(\d+)\}\r?\n\Z")
_LITERAL_TAIL_BYTES = 64

# Status words of an untagged status response (RFC 3501 §7.1). Such a line
# carries free text, never a literal.
_STATUS_WORDS = frozenset({b"OK", b"NO", b"BAD", b"BYE", b"PREAUTH"})


def _capability_hidden(token: str, write_mode: str) -> bool:
    """True when *token* must not be advertised to the cage.

    One rule for the PREAUTH greeting and for every capability list the
    upstream sends later: always hide what _REFUSED_COMMANDS refuses, and
    unless write_mode is "full", hide what that mode refuses too.
    """
    t = token.upper()
    if t in _STRIPPED_CAPABILITIES or t.startswith(_STRIPPED_CAPABILITY_PREFIXES):
        return True
    return write_mode != "full" and t in _STRIPPED_CAPABILITIES_RESTRICTED


# One grammar for both relays and the validator — see relays._validate.
_RATE_LIMIT_RE = RATE_LIMIT_RE
_RATE_UNIT_SECS = RATE_UNIT_SECS


def _parse_rate_limit(spec: str) -> tuple[int, int]:
    """Parse '30/min' into (count, window_seconds)."""
    m = _RATE_LIMIT_RE.match(spec)
    if not m:
        raise ValueError(f"invalid conn_rate_limit: {spec!r}")
    return int(m.group(1)), _RATE_UNIT_SECS[m.group(2).lower()]


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
        # Pinned PEM + SNI/hostname override for upstreams no public CA
        # signs (private CA, Proton Mail Bridge). See relays._tls.
        self.upstream_ca_pem: str = str(upstream.get("ca_pem") or "")
        self.upstream_tls_servername: str = str(
            upstream.get("tls_servername") or ""
        )
        auth = entry.get("auth") or {}
        self.user_source: str = str(auth.get("user_source") or "")
        self.password_source: str = str(auth.get("password_source") or "")
        policy = entry.get("policy") or {}
        self.readonly: bool = bool(policy.get("readonly", False))
        # write_mode is the expressive form; readonly is the older boolean
        # and still works. An explicit write_mode wins; otherwise readonly
        # maps onto it, so existing configs behave exactly as before.
        #   none     - no writes at all (readonly: true)
        #   organise - file and flag mail, but never destroy it
        #   full     - no restrictions (readonly: false / absent)
        mode = str(policy.get("write_mode") or "").strip().lower()
        if not mode:
            mode = "none" if self.readonly else "full"
        self.write_mode: str = mode
        self.folder_allowlist: list[str] = list(
            policy.get("folder_allowlist") or []
        )
        # Denied outright, and denial wins over the allowlist. Useful for
        # carving one folder out of otherwise-full access — e.g. keeping an
        # agent out of Trash so that "delete" can only ever mean "move to
        # Trash" and never "purge what is already there".
        self.folder_denylist: list[str] = list(
            policy.get("folder_denylist") or []
        )
        self.conn_rate_limit: str = str(
            policy.get("conn_rate_limit") or "30/min"
        )
        # Per-readline idle timeout. Default 1800s = 30 min so RFC 2177
        # IDLE heartbeats (every ~29 min) don't trip a closure. 0
        # disables the timeout entirely (legacy behavior).
        self.idle_timeout_seconds: int = int(
            policy.get("idle_timeout_seconds", 1800)
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
        self._user = resolve_credential(self._cfg.user_source)
        self._password = resolve_credential(self._cfg.password_source)
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
            "imap relay %s listening on %s -> %s:%d (write=%s, "
            "folders=%s, denied=%s)",
            self._cfg.name,
            self._cfg.listen,
            self._cfg.upstream_host,
            self._cfg.upstream_port,
            self._cfg.write_mode,
            self._cfg.folder_allowlist or "(any)",
            self._cfg.folder_denylist or "(none)",
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
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self._cfg.upstream_host,
                self._cfg.upstream_port,
                **upstream_connect_kwargs(
                    tls=self._cfg.upstream_tls,
                    ca_pem=self._cfg.upstream_ca_pem,
                    tls_servername=self._cfg.upstream_tls_servername,
                ),
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

    async def _read_with_timeout(
        self, reader: asyncio.StreamReader,
    ) -> bytes:
        """`readline` with the configured idle timeout. Used during
        the auth phase only — once the bridge starts, IDLE sessions
        legitimately go quiet for ~29 minutes between heartbeats and
        we want to keep them open. Pre-auth timeouts catch the case
        where a cage connects but never speaks.
        """
        if self._cfg.idle_timeout_seconds <= 0:
            return await reader.readline()
        return await asyncio.wait_for(
            reader.readline(),
            timeout=self._cfg.idle_timeout_seconds,
        )

    async def _authenticate_upstream(
        self,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        client_writer: asyncio.StreamWriter,
    ) -> bool:
        # Consume upstream greeting. Many servers embed the CAPABILITY
        # list inline as `* OK [CAPABILITY ...] ready` — capture it so
        # we can forward equivalent capabilities to the client below.
        try:
            greeting = await self._read_with_timeout(upstream_reader)
        except asyncio.TimeoutError:
            log.warning(
                "imap relay %s: upstream silent for %ds, giving up",
                self._cfg.name, self._cfg.idle_timeout_seconds,
            )
            client_writer.write(b"* BYE upstream silent\r\n")
            await client_writer.drain()
            return False
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
            line = await self._read_with_timeout(upstream_reader)
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
            line = await self._read_with_timeout(upstream_reader)
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

        Forwards upstream capabilities minus what _capability_hidden()
        hides: COMPRESS=*, STARTTLS and UNAUTHENTICATE always (each would
        take the byte stream out of the relay's sight), and, unless
        write_mode is "full", commands the mode refuses. Falls back to
        ``IMAP4rev1`` if the upstream never advertised anything we could
        parse.
        """
        if not self._upstream_capabilities:
            return "IMAP4rev1"
        out = [
            t for t in self._upstream_capabilities
            if not _capability_hidden(t, self._cfg.write_mode)
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
        # The PREAUTH greeting is not the only place capabilities reach the
        # cage: the reply to a CAPABILITY command, and a [CAPABILITY ...]
        # code in any status response, carry the upstream's list too.
        # Filter them with the same rule as the greeting.
        filt = _ResponseFilter(
            lambda t: _capability_hidden(t, self._cfg.write_mode)
        )
        while True:
            chunk = await upstream_reader.read(8192)
            try:
                out = filt.feed(chunk) if chunk else filt.finish()
            except _UnfilterableResponse as e:
                log.warning(
                    "imap relay %s: closing session: %s", self._cfg.name, e,
                )
                self._audit_log({
                    "kind": "imap_response",
                    "relay": self._cfg.name,
                    "decision": "blocked",
                    "reason": str(e),
                })
                return
            if out:
                client_writer.write(out)
                await client_writer.drain()
            if not chunk:
                return

    def _policy_check(
        self, line: bytes
    ) -> Optional[tuple[bytes, str, bytes]]:
        """Return (tag, reason, fake_status) if denied, else None.

        ``fake_status`` is the IMAP status word the relay forges back
        to the client: ``OK`` for "already authenticated" (semantic
        no-op for a PREAUTH'd connection), ``NO`` for actual policy
        denials.
        """
        # Split on any run of whitespace, not single spaces. RFC 3501 says
        # exactly one SP, but an upstream lenient about tabs, doubled or
        # leading spaces would run `a1  EXPUNGE` as EXPUNGE, and a
        # single-space split would have seen command "" and let it through.
        parts = line.split(None, 2)
        if len(parts) < 2:
            return None
        tag = parts[0]
        cmd_b = parts[1].upper()
        cmd = cmd_b.decode("ascii", errors="replace")

        # Resolve UID prefix to its subcommand for policy purposes.
        # `UID FETCH`/`UID SEARCH` are reads (clients use them for
        # everything because UIDs are stable), the rest mutate state.
        # Bare `UID` blocking would break every modern IMAP client.
        effective_cmd = cmd
        if cmd == "UID":
            sub_b = b""
            if len(parts) >= 3:
                sub_b = (parts[2].split(None, 1) or [b""])[0]
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

        # Refused in every write_mode: past this point the relay could no
        # longer read the stream, so no other rule would hold either.
        why = _REFUSED_COMMANDS.get(cmd)
        if why is not None:
            log.warning(
                "imap relay %s: blocked %s (%s)", self._cfg.name, cmd, why,
            )
            self._audit_log({
                "kind": "imap_command",
                "relay": self._cfg.name,
                "command": cmd,
                "decision": "blocked",
                "reason": why,
            })
            return (tag, f"{cmd} not permitted ({why})", b"NO")

        # Write policy.
        if self._cfg.write_mode != "full":
            sub = (
                effective_cmd.split(" ", 1)[1]
                if cmd == "UID" and " " in effective_cmd
                else ""
            )
            denied = False
            reason = ""
            wire = "readonly" if self._cfg.write_mode == "none" else "write_mode organise"

            if self._cfg.write_mode == "none":
                if cmd in _DENY_COMMANDS_READONLY or sub in _UID_WRITE_SUBCOMMANDS:
                    denied, reason = True, "readonly policy"
            else:  # organise
                if cmd in _DENY_COMMANDS_ORGANISE or sub in _UID_DENY_ORGANISE:
                    denied, reason = True, "write_mode organise"
                elif cmd == "STORE" or sub == "STORE":
                    # Filing and flagging are allowed; marking mail deleted
                    # is not. Refusing the flag — rather than only the
                    # EXPUNGE that reaps it — means there is never anything
                    # for an expunge to destroy.
                    args = parts[2] if len(parts) >= 3 else b""
                    if _store_adds_deleted(args):
                        denied = True
                        reason = "write_mode organise (\\Deleted flag)"
                    elif _store_writes_annotation(args):
                        denied = True
                        reason = "write_mode organise (annotation)"

            if denied:
                log.warning(
                    "imap relay %s: blocked %s (%s)",
                    self._cfg.name, effective_cmd, reason,
                )
                self._audit_log({
                    "kind": "imap_command",
                    "relay": self._cfg.name,
                    "command": effective_cmd,
                    "decision": "blocked",
                    "reason": reason,
                })
                return (
                    tag,
                    f"{effective_cmd} not permitted ({wire})",
                    b"NO",
                )

        if cmd in _MAILBOX_ARG_COMMANDS and (
            self._cfg.folder_allowlist or self._cfg.folder_denylist
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
            reason = self._mailbox_denial_reason(mailbox)
            if reason is not None:
                log.warning(
                    "imap relay %s: blocked %s on %s (%s)",
                    self._cfg.name, cmd, mailbox, reason,
                )
                self._audit_log({
                    "kind": "imap_command",
                    "relay": self._cfg.name,
                    "command": cmd,
                    "mailbox": mailbox,
                    "decision": "blocked",
                    "reason": reason,
                })
                return (tag, f"{cmd} {mailbox} {reason}", b"NO")

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

    def _mailbox_denial_reason(self, mailbox: str) -> Optional[str]:
        """Why this mailbox may not be selected, or None if it may.

        Denial wins over the allowlist: a folder named in both is denied.
        Matching is case-insensitive because IMAP servers differ on the
        case they report for special-use mailboxes, and a denylist that
        misses ``trash`` because the server said ``Trash`` would fail
        open — the wrong direction for this list to be wrong in.
        """
        lowered = mailbox.lower()
        if any(lowered == d.lower() for d in self._cfg.folder_denylist):
            return "denied by folder_denylist"
        if (
            self._cfg.folder_allowlist
            and not any(
                lowered == a.lower() for a in self._cfg.folder_allowlist
            )
        ):
            return "not in folder_allowlist"
        return None


_STORE_OP_RE = re.compile(
    rb"(?P<op>[+-]?)FLAGS(?:\.SILENT)?(?P<flags>.*)$",
    re.IGNORECASE | re.DOTALL,
)


def _store_adds_deleted(args: bytes) -> bool:
    r"""True when a STORE would ADD the ``\Deleted`` flag.

    ``\Deleted`` is what makes a later EXPUNGE (or CLOSE) destroy mail, so
    in "organise" mode it is the flag to refuse rather than the commands
    that act on it. Refusing the flag means EXPUNGE and CLOSE have nothing
    to reap even if some other path reaches them.

    ``-FLAGS (\Deleted)`` *removes* the flag — that un-deletes a message
    and is always allowed. Only ``FLAGS`` (set exactly) and ``+FLAGS`` (add)
    can introduce it.
    """
    m = _STORE_OP_RE.search(args)
    if not m:
        return False
    if m.group("op") == b"-":
        return False
    return b"\\DELETED" in m.group("flags").upper()


def _store_writes_annotation(args: bytes) -> bool:
    """True when a STORE writes RFC 5257 message annotations.

    ``STORE 1 ANNOTATION (/comment (value.priv "x"))`` sets annotation data
    on a message rather than flags. Any ``ANNOTATION`` token in the
    arguments counts, wherever it sits, so CONDSTORE modifiers or odd
    spacing in front of it change nothing. A keyword flag literally named
    ANNOTATION is refused too; that costs nothing real and keeps the check
    simple enough to trust.
    """
    return b"ANNOTATION" in re.split(rb"[\s()]+", args.upper())


class _UnfilterableResponse(Exception):
    """An upstream line the relay must filter but will not hold to filter."""


class _ResponseFilter:
    """Remove hidden capabilities from the upstream -> client byte stream.

    Capability lists reach the cage in two shapes: an untagged
    ``* CAPABILITY ...`` response, and a ``[CAPABILITY ...]`` response code
    in a status response (``* OK [...]``, ``a1 OK [...]``). Both are single
    lines, so the filter works a line at a time. But the stream is not all
    lines: a message body arrives as an IMAP literal (``{n}`` CRLF, then n
    raw bytes), and that body may well contain a line reading
    ``* CAPABILITY ...``, which is mail, not a response, and must reach the
    cage byte-exact.

    So the filter tracks literals and passes their bytes through as they
    arrive, never buffering them: a large FETCH costs no extra memory and no
    extra latency. Outside literals it holds back only the current partial
    line until its LF arrives (normally in the same or the next read), then
    rewrites it if it carries capabilities and forwards it. A line longer
    than _HELD_LINE_LIMIT is flushed and the rest of it streamed raw, which
    keeps memory bounded for the occasional huge ``* SEARCH`` line; if that
    line is one the filter has to rewrite, it raises _UnfilterableResponse
    and the session is closed instead, rather than leak the list unfiltered.

    Literals are only honoured in untagged data responses (``* 12 FETCH``,
    ``* LIST`` ...), where the grammar puts strings in quotes or literals,
    so a ``{n}`` CRLF at the end of a line is always a literal. Status
    responses, tagged responses and ``+`` continuation requests carry free
    text, which may echo what the cage sent; a ``{n}`` at the end of one is
    text, and treating it as a literal would let the cage make the filter
    wave the next n bytes through unfiltered.
    """

    def __init__(self, hidden: Callable[[str], bool]) -> None:
        self._hidden = hidden
        self._held = bytearray()   # current line so far, not yet forwarded
        self._streaming = False    # current line overflowed: rest goes raw
        self._tail = b""           # last bytes of the line being streamed
        self._literal = 0          # literal bytes still to pass through
        self._continuing = False   # line continues a response after a literal
        self._data = False         # current response may carry literals

    def feed(self, chunk: bytes) -> bytes:
        out = bytearray()
        i, n = 0, len(chunk)
        while i < n:
            if self._literal:
                take = min(self._literal, n - i)
                out += chunk[i:i + take]
                self._literal -= take
                i += take
                continue
            nl = chunk.find(b"\n", i)
            end = n if nl < 0 else nl + 1
            piece = chunk[i:end]
            i = end
            if self._streaming:
                out += piece
                self._tail = (self._tail + piece)[-_LITERAL_TAIL_BYTES:]
                if nl >= 0:
                    self._streaming = False
                    self._end_line(self._tail)
                continue
            self._held += piece
            if nl >= 0:
                line = bytes(self._held)
                self._held.clear()
                out += self._rewrite(line, self._classify(line))
                self._end_line(line)
            elif len(self._held) > _HELD_LINE_LIMIT:
                line = bytes(self._held)
                self._held.clear()
                kind = self._classify(line)
                if kind == "capability" or (
                    kind == "status" and b"[CAPABILITY" in line.upper()
                ):
                    raise _UnfilterableResponse(
                        "upstream capability line longer than "
                        f"{_HELD_LINE_LIMIT} bytes"
                    )
                out += line
                self._streaming = True
                self._tail = line[-_LITERAL_TAIL_BYTES:]
        return bytes(out)

    def finish(self) -> bytes:
        """Flush a last line the upstream never terminated (at EOF)."""
        if self._streaming or not self._held:
            return b""
        line = bytes(self._held)
        self._held.clear()
        return self._rewrite(line, self._classify(line))

    def _classify(self, line: bytes) -> str:
        """``capability``, ``data`` or ``status``: the response this line
        is in. On a line that starts a response, also decides whether that
        response may carry literals."""
        if self._continuing:
            return "data"
        if line[:13].upper().rstrip(b"\r\n") in (
            b"* CAPABILITY", b"* CAPABILITY ",
        ):
            self._data = False
            return "capability"
        words = line.split(None, 2)
        self._data = (
            len(words) >= 2
            and words[0] == b"*"
            and words[1].upper() not in _STATUS_WORDS
        )
        return "data" if self._data else "status"

    def _end_line(self, tail: bytes) -> None:
        m = None
        if self._data:
            m = _LITERAL_TAIL_RE.search(tail[-_LITERAL_TAIL_BYTES:])
        if m:
            self._literal = int(m.group(1))
            self._continuing = True
        else:
            self._continuing = False
            self._data = False

    def _rewrite(self, line: bytes, kind: str) -> bytes:
        if kind == "data":
            return line
        body = line.rstrip(b"\r\n")
        eol = line[len(body):]
        if kind == "capability":
            start, close = len(b"* CAPABILITY"), len(body)
        else:
            idx = body.upper().find(b"[CAPABILITY")
            if idx < 0:
                return line
            start = idx + len(b"[CAPABILITY")
            if body[start:start + 1] not in (b" ", b"]"):
                return line  # another response code that merely starts alike
            close = body.find(b"]", start)
            if close < 0:
                close = len(body)
        kept = [
            t for t in body[start:close].split()
            if not self._hidden(t.decode("ascii", errors="replace"))
        ]
        return (
            body[:start] + b"".join(b" " + t for t in kept) + body[close:] + eol
        )


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
