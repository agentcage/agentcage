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
import base64
import binascii
import logging
import re
import ssl
import time
import unicodedata
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
#
# The destinations of COPY, MOVE and APPEND are deliberately not checked
# either. The folder lists say which folders the cage may read, and filing
# mail into a folder reads nothing. Checking them would also break the use
# the denylist exists for: denying Trash so that "delete" can only mean
# "move to Trash". What may be written where is write_mode's business.
_MAILBOX_ARG_COMMANDS = frozenset({"SELECT", "EXAMINE", "STATUS"})

# Longest mailbox name the relay reads ahead from a literal to check it
# against the folder lists. Longer names are refused as unparseable.
_MAX_MAILBOX_LITERAL = 1024

# Capabilities whose commands report on mailboxes other than the selected
# one, so the relay refuses them while a folder list is set (see
# _folder_side_door()): LIST-STATUS (RFC 5819) puts STATUS data in a LIST
# reply, MULTISEARCH (RFC 7377) searches several mailboxes at once, NOTIFY
# (RFC 5465) reports on mailboxes the cage names. Hidden like the others.
_STRIPPED_CAPABILITIES_FOLDERS = frozenset({"LIST-STATUS", "MULTISEARCH", "NOTIFY"})

# ENABLE arguments after which the upstream may read mailbox names as
# UTF-8 (RFC 6855 UTF8=ACCEPT, RFC 9051 IMAP4rev2) instead of modified
# UTF-7.
_UTF8_ENABLES = frozenset({b"UTF8=ACCEPT", b"IMAP4REV2"})

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

# Status words that complete a command in a tagged response (RFC 3501 §7.1).
_COMPLETION_WORDS = frozenset({b"OK", b"NO", b"BAD"})

# A literal announced at the end of a line from the cage (RFC 3501 §4.3):
# "{n}" (synchronising), "{n+}" (non-synchronising, RFC 7888 LITERAL+ and
# LITERAL-, which share the syntax), each optionally "~"-prefixed (RFC 3516
# literal8). The count is matched loosely here and range-checked by
# _client_literal(), so a 30-digit count is "too large", not "malformed".
_CLIENT_LITERAL_RE = re.compile(rb"(~?)\{(\d+)(\+?)\}\r?\n\Z")

# Anything else in braces at the end of a line ("{5-}", "{ 5}", "{}"). Not a
# literal in IMAP's grammar, but close enough that a lenient upstream might
# read one as a literal while the relay reads a complete command line, so the
# relay refuses it rather than guess. A brace can't end a line otherwise:
# atoms and tags can't contain "{", and a quoted string ends in '"'.
_LITERAL_LIKE_RE = re.compile(rb"\{[^{}\r\n]*\}\r?\n\Z")

# Largest literal the cage may send, in bytes. A literal is a message being
# uploaded (APPEND, REPLACE, CATENATE) or a string argument; the relay streams
# literal bytes through without holding them, so this bounds what one command
# can push at the upstream, not the relay's memory. 64 MiB is well above
# the message size most providers accept by default, so an ordinary upload
# meets the upstream's own limit first.
_MAX_LITERAL_BYTES = 64 * 1024 * 1024

# Bytes allowed in a command tag: RFC 3501 §9, tag = 1*<any ASTRING-CHAR
# except "+">, i.e. printable ASCII except "(", ")", "{", "%", "*", '"', "\"
# and "+". Refusing other tags keeps the relay's view of the stream and the
# upstream's in step: a "+" or "*" tag echoed back by the upstream would read
# as a continuation request or an untagged response.
_TAG_BYTES = frozenset(range(0x21, 0x7F)) - frozenset(b'(){%*"\\+')


class _Literal:
    """A literal announced at the end of one line from the cage."""

    __slots__ = ("size", "sync", "start")

    def __init__(self, size: int, sync: bool, start: int) -> None:
        self.size = size    # payload bytes that follow the line
        self.sync = sync    # synchronising: the cage waits for "+" first
        self.start = start  # offset of "{" in the line


class _MalformedLiteral(Exception):
    """A line ends in something brace-shaped that is not a literal."""


def _client_literal(line: bytes) -> Optional[_Literal]:
    """The literal *line* announces at its end, or None.

    Raises _MalformedLiteral for a brace-shaped tail that is not one; the
    size is not range-checked here (see _MAX_LITERAL_BYTES).
    """
    if not line.endswith(b"}\r\n") and not line.endswith(b"}\n"):
        return None
    # Neither form has a "{" inside it, so the last one on the line is
    # where the tail starts, however long the count.
    brace = line.rfind(b"{")
    if brace < 0:
        return None
    tail = line[max(0, brace - 1):]
    m = _CLIENT_LITERAL_RE.search(tail)
    if m is None:
        if _LITERAL_LIKE_RE.search(tail):
            raise _MalformedLiteral(tail)
        return None
    digits = m.group(2)
    # A count with more digits than any sane size is simply too large. Not
    # parsed, since int() refuses very long digit strings.
    size = int(digits) if len(digits) <= 18 else _MAX_LITERAL_BYTES + 1
    return _Literal(size, not m.group(3), brace)


def _synchronising(line: bytes, lit: _Literal) -> bytes:
    """*line* with its literal announced as synchronising ("{n+}" -> "{n}")."""
    if lit.sync:
        return line
    head = line[:lit.start]
    eol = b"\r\n" if line.endswith(b"\r\n") else b"\n"
    return head + b"{%d}" % lit.size + eol


def _valid_tag(tag: bytes) -> bool:
    return bool(tag) and all(b in _TAG_BYTES for b in tag)


def _capability_hidden(
    token: str, write_mode: str, folder_lists: bool = False,
) -> bool:
    """True when *token* must not be advertised to the cage.

    One rule for the PREAUTH greeting and for every capability list the
    upstream sends later: always hide what _REFUSED_COMMANDS refuses,
    unless write_mode is "full", hide what that mode refuses too, and while
    a folder list is set, what _folder_side_door() refuses.
    """
    t = token.upper()
    if t in _STRIPPED_CAPABILITIES or t.startswith(_STRIPPED_CAPABILITY_PREFIXES):
        return True
    if folder_lists and t in _STRIPPED_CAPABILITIES_FOLDERS:
        return True
    return write_mode != "full" and t in _STRIPPED_CAPABILITIES_RESTRICTED


# Modified BASE64 of RFC 3501 §5.1.3: "," stands in for "/".
_MB64_RE = re.compile(r"[A-Za-z0-9+,]*\Z")


def _mutf7_decode(name: str) -> Optional[str]:
    """Decode a modified UTF-7 mailbox name (RFC 3501 §5.1.3), or None if
    *name* is not valid modified UTF-7.

    Lenient where the RFC is strict but the meaning is clear (a shifted
    run that encodes plain ASCII, nonzero padding bits): the result is only
    ever used to find more names a deny entry should catch.
    """
    if not name.isascii():
        return None
    out: list[str] = []
    i = 0
    while i < len(name):
        amp = name.find("&", i)
        if amp < 0:
            out.append(name[i:])
            break
        out.append(name[i:amp])
        end = name.find("-", amp + 1)
        if end < 0:
            return None
        run = name[amp + 1:end]
        if not run:
            out.append("&")
        else:
            if not _MB64_RE.match(run) or len(run) % 4 == 1:
                return None
            try:
                raw = base64.b64decode(
                    run.replace(",", "/") + "=" * (-len(run) % 4),
                    validate=True,
                )
                if len(raw) % 2:
                    return None
                out.append(raw.decode("utf-16-be"))
            except (binascii.Error, UnicodeDecodeError, ValueError):
                return None
        i = end + 1
    return "".join(out)


def _fold(name: str) -> str:
    """The canonical form two spellings of one mailbox name compare in:
    NFC, case-folded (IMAP servers disagree on the case of special-use
    names, and RFC 3501 §5.1 makes INBOX case-insensitive), NFC again."""
    return unicodedata.normalize(
        "NFC", unicodedata.normalize("NFC", name).casefold(),
    )


def _name_forms(name: str) -> set[str]:
    """Every canonical name the upstream might take *name* for: as written
    (UTF-8, how a server reads it after ENABLE UTF8=ACCEPT) and, when it
    is valid modified UTF-7, decoded (how a server reads it otherwise)."""
    forms = {_fold(name)}
    decoded = _mutf7_decode(name)
    if decoded is not None:
        forms.add(_fold(decoded))
    return forms


def _server_reading(name: str) -> str:
    """The canonical name a server not reading UTF-8 names takes *name*
    for: decoded if it is valid modified UTF-7, as written otherwise."""
    decoded = _mutf7_decode(name)
    return _fold(name if decoded is None else decoded)


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
        # The folder lists in canonical form, every spelling of each entry
        # included (see _name_forms()).
        self._folder_lists = bool(
            self._cfg.folder_allowlist or self._cfg.folder_denylist
        )
        self._deny_forms: set[str] = set()
        for d in self._cfg.folder_denylist:
            self._deny_forms |= _name_forms(str(d))
        self._allow_forms: set[str] = set()
        for a in self._cfg.folder_allowlist:
            self._allow_forms |= _name_forms(str(a))

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
            #
            # Both pipes write to the cage: the upstream's responses, and
            # the relay's own replies. _ClientOutput keeps the second from
            # landing inside the first.
            #
            # The PREAUTH greeting is not the only place capabilities reach
            # the cage: the reply to a CAPABILITY command, and a
            # [CAPABILITY ...] code in any status response, carry the
            # upstream's list too, so responses are filtered with the same
            # rule as the greeting. The tracker sees every response, to
            # match continuation requests and completions to what the
            # client pipe forwarded.
            tracker = _CommandTracker()
            to_client = _ClientOutput(client_writer, _ResponseFilter(
                lambda t: _capability_hidden(
                    t, self._cfg.write_mode, self._folder_lists,
                ),
                tracker.observe,
            ))
            t1 = asyncio.create_task(
                self._pipe_client_to_upstream(
                    client_reader, upstream_writer, to_client, tracker,
                )
            )
            t2 = asyncio.create_task(
                self._pipe_upstream_to_client(upstream_reader, to_client)
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
            if not _capability_hidden(
                t, self._cfg.write_mode, self._folder_lists,
            )
        ]
        if not any(t.upper() == "IMAP4REV1" for t in out):
            out.insert(0, "IMAP4rev1")
        return " ".join(out)

    async def _pipe_client_to_upstream(
        self,
        client_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        to_client: _ClientOutput,
        tracker: _CommandTracker,
    ) -> None:
        # Whether the upstream may read mailbox names as UTF-8 rather than
        # modified UTF-7: from the start on a server that only speaks
        # IMAP4rev2 or UTF-8, else once the cage has asked it to.
        caps = {c.upper() for c in self._upstream_capabilities}
        state = _SessionState(
            utf8_names="UTF8=ONLY" in caps
            or ("IMAP4REV2" in caps and "IMAP4REV1" not in caps),
        )
        while True:
            line = await client_reader.readline()
            if not line:
                return
            if not await self._relay_command(
                line, client_reader, upstream_writer, to_client, tracker,
                state,
            ):
                return

    async def _relay_command(
        self,
        line: bytes,
        client_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        to_client: _ClientOutput,
        tracker: _CommandTracker,
        state: "_SessionState",
    ) -> bool:
        """Relay one command whose first line is *line*. False ends the
        session.

        A command is one line unless it carries literals (RFC 3501 §4.3):
        a line ending in ``{n}`` is followed by n bytes of payload and then
        the rest of the command, which may announce another literal, and so
        on. Payload is data, never commands: it is streamed through byte for
        byte and never policy-checked, while the line that starts a command
        always is, before anything of the command is forwarded.

        That only holds while the relay and the upstream agree on where each
        literal starts and ends, so every literal goes upstream as a
        synchronising one, and its payload is forwarded only after the
        upstream has answered that very line with ``+``:
          - ``{n}``: the cage itself waits for ``+``, which the relay passes
            on. A tagged response instead means the upstream refused the
            literal; the cage sends no payload, and the relay reads what
            follows as a new command, as the upstream does.
          - ``{n+}`` (LITERAL+/LITERAL-, RFC 7888): the cage sends the
            payload without waiting. The relay announces it upstream as
            ``{n}``, swallows the upstream's ``+``, then forwards it; if the
            upstream refuses instead, the relay drops the payload and the
            rest of the command, as a server would. Rewriting costs a round
            trip per literal, and buys this: the relay never has to predict
            whether the upstream would have parsed a non-synchronising
            literal where the cage put it (it may lack LITERAL+, or the
            ``{n+}`` may sit inside an unterminated quoted string), which
            is where a cage could otherwise get payload read as commands.
        A command the relay refuses itself never reaches the upstream. If it
        announced ``{n}``, the relay answers in place of the ``+`` and the
        cage, as RFC 3501 §7.5 requires, never sends the payload; if
        ``{n+}``, the relay reads and drops exactly the payload, and so on to
        the end of the command.

        A mailbox name the folder lists must judge may itself be a literal
        (``SELECT {5}``). The relay then reads it before deciding: for
        ``{n}`` it sends the cage the ``+`` itself, and swallows the
        upstream's later one. Such a literal is short (_MAX_MAILBOX_LITERAL)
        and the cage has sent it either way by the time the relay decides,
        so a refusal drops the rest of the command as for ``{n+}``.
        """
        try:
            lit = _client_literal(line)
        except _MalformedLiteral:
            lit = None  # _policy_check() refuses the line
        name: Optional[bytes] = None  # a literal mailbox name, read ahead
        if lit is not None and self._literal_mailbox(line, lit):
            await tracker.settle(0)
            if lit.sync:
                await to_client.from_relay(b"+ Ready for the mailbox name\r\n")
            try:
                name = await client_reader.readexactly(lit.size)
            except asyncio.IncompleteReadError:
                return False
        decision = self._policy_check(
            line, mailbox=name, utf8_names=state.utf8_names,
        )
        if decision is not None:
            await self._reply(to_client, decision)
            if name is not None:
                return await self._discard_rest(client_reader, to_client)
            return await self._discard_command(
                client_reader, to_client, lit,
            )
        if _enables_utf8_names(line):
            # Set before the upstream has agreed, which errs towards
            # checking both readings of a name for longer than needed.
            state.utf8_names = True

        tag = (line.split(None, 1) or [b""])[0]
        command = _command_name(line)
        counted = len(line.split(None, 2)) >= 2
        first = True
        while True:
            if lit is None:
                upstream_writer.write(line)
                await upstream_writer.drain()
                if first and counted:
                    tracker.sent(tag)
                return True
            if not first and lit.size > _MAX_LITERAL_BYTES:
                # Part of this command is already upstream, so there is no
                # refusing it cleanly any more.
                self._audit_literal_too_large(command)
                await self._bye(to_client, b"literal too large")
                return False
            # Make sure the next "+" or tagged response is this literal's:
            # no other command may be outstanding. A later literal of the
            # same command finds just this one outstanding, unless the
            # upstream has already answered it, which leaves the two sides
            # disagreeing about where the command ends.
            await tracker.settle(0 if first else 1)
            if not first and tracker.outstanding != 1:
                log.warning(
                    "imap relay %s: upstream completed a command before "
                    "its last literal, closing session", self._cfg.name,
                )
                await self._bye(to_client, b"protocol error")
                return False
            verdict = tracker.expect_continuation(
                tag, forward=lit.sync and name is None,
            )
            if first:
                tracker.sent(tag)
            upstream_writer.write(_synchronising(line, lit))
            await upstream_writer.drain()
            if not await verdict:
                # Refused upstream; its tagged response is on its way to
                # the cage.
                if name is not None:
                    return await self._discard_rest(client_reader, to_client)
                return await self._discard_command(
                    client_reader, to_client, lit,
                )
            if name is not None:
                upstream_writer.write(name)
                await upstream_writer.drain()
                name = None
            elif not await _copy_exactly(
                client_reader, upstream_writer, lit.size,
            ):
                return False
            line = await client_reader.readline()
            if not line:
                return False
            first = False
            try:
                lit = _client_literal(line)
            except _MalformedLiteral:
                log.warning(
                    "imap relay %s: malformed literal inside a command, "
                    "closing session", self._cfg.name,
                )
                self._audit_log({
                    "kind": "imap_command",
                    "relay": self._cfg.name,
                    "command": command,
                    "decision": "blocked",
                    "reason": "malformed literal",
                })
                await self._bye(to_client, b"malformed literal")
                return False

    async def _discard_rest(
        self,
        client_reader: asyncio.StreamReader,
        to_client: _ClientOutput,
    ) -> bool:
        """_discard_command() for a command whose literal the relay has
        already read: drop the line after it, and on from there."""
        line = await client_reader.readline()
        if not line:
            return False
        try:
            lit = _client_literal(line)
        except _MalformedLiteral:
            return True
        return await self._discard_command(client_reader, to_client, lit)

    def _literal_mailbox(self, line: bytes, lit: _Literal) -> bool:
        """True when *line* is a SELECT/EXAMINE/STATUS whose mailbox
        argument is the literal it announces, and the folder lists need
        to see that name."""
        if not self._folder_lists or lit.size > _MAX_MAILBOX_LITERAL:
            return False
        parts = line.split(None, 2)
        if len(parts) < 3 or not _valid_tag(parts[0]):
            return False
        if parts[1].upper().decode("ascii", "replace") \
                not in _MAILBOX_ARG_COMMANDS:
            return False
        # parts[2] runs to the end of the line, so this is where it starts.
        return lit.start == len(line) - len(parts[2])

    async def _discard_command(
        self,
        client_reader: asyncio.StreamReader,
        to_client: _ClientOutput,
        lit: Optional[_Literal],
    ) -> bool:
        """Drop the rest of a command that will not reach the upstream.

        Only payload the cage sends unasked needs dropping: a ``{n+}``
        literal, then the line after it, and so on while those lines end
        in ``{n+}`` too. At a ``{n}`` the cage waits for a ``+`` that never
        comes (it has its tagged response), so whatever follows is the
        cage's next command. False when the session must end: the payload
        is larger than the relay will read, or the cage hung up.
        """
        while lit is not None and not lit.sync:
            if lit.size > _MAX_LITERAL_BYTES:
                await self._bye(to_client, b"literal too large")
                return False
            if not await _copy_exactly(client_reader, None, lit.size):
                return False
            line = await client_reader.readline()
            if not line:
                return False
            try:
                lit = _client_literal(line)
            except _MalformedLiteral:
                return True
        return True

    async def _reply(
        self,
        to_client: _ClientOutput,
        decision: tuple[bytes, str, bytes],
    ) -> None:
        tag, reason, fake_status = decision
        await to_client.from_relay(
            tag + b" " + fake_status + b" " + reason.encode() + b"\r\n"
        )

    async def _bye(self, to_client: _ClientOutput, reason: bytes) -> None:
        """Say why the session is ending. Like any relay reply it is held
        back while an upstream response is half sent, and the session
        ends without it rather than wait."""
        try:
            await to_client.from_relay(b"* BYE " + reason + b"\r\n")
        except Exception:
            pass

    def _audit_literal_too_large(self, command: str) -> None:
        log.warning(
            "imap relay %s: blocked literal over %d bytes",
            self._cfg.name, _MAX_LITERAL_BYTES,
        )
        self._audit_log({
            "kind": "imap_command",
            "relay": self._cfg.name,
            "command": command,
            "decision": "blocked",
            "reason": "literal too large",
        })

    async def _pipe_upstream_to_client(
        self,
        upstream_reader: asyncio.StreamReader,
        to_client: _ClientOutput,
    ) -> None:
        while True:
            chunk = await upstream_reader.read(8192)
            try:
                await to_client.from_upstream(chunk)
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
            if not chunk:
                return

    def _policy_check(
        self,
        line: bytes,
        *,
        mailbox: Optional[bytes] = None,
        utf8_names: bool = False,
    ) -> Optional[tuple[bytes, str, bytes]]:
        """Return (tag, reason, fake_status) if denied, else None.

        ``fake_status`` is the IMAP status word the relay forges back
        to the client: ``OK`` for "already authenticated" (semantic
        no-op for a PREAUTH'd connection), ``NO`` for actual policy
        denials, ``BAD`` for a line the relay won't parse (an invalid
        tag, answered with tag ``*``, or a malformed literal).

        *mailbox* is a mailbox name the cage sent as a literal, read ahead
        by _relay_command(); *utf8_names* says whether the upstream may
        read mailbox names as UTF-8 (see _mailbox_denial_reason()).
        """
        # Split on any run of whitespace, not single spaces. RFC 3501 says
        # exactly one SP, but an upstream lenient about tabs, doubled or
        # leading spaces would run `a1  EXPUNGE` as EXPUNGE, and a
        # single-space split would have seen command "" and let it through.
        parts = line.split(None, 2)
        if not parts:
            return None
        tag = parts[0]
        if not _valid_tag(tag):
            # Answered untagged: echoing a "+" or "*" tag back would itself
            # read as a continuation request or an untagged response.
            log.warning(
                "imap relay %s: blocked line with invalid tag %r",
                self._cfg.name, tag[:32],
            )
            self._audit_log({
                "kind": "imap_command",
                "relay": self._cfg.name,
                "command": _command_name(line),
                "decision": "blocked",
                "reason": "invalid tag",
            })
            return (b"*", "invalid command tag", b"BAD")
        if len(parts) < 2:
            return None
        cmd_b = parts[1].upper()
        cmd = cmd_b.decode("ascii", errors="replace")

        # Resolve UID prefix to its subcommand for policy purposes.
        # `UID FETCH`/`UID SEARCH` are reads (clients use them for
        # everything because UIDs are stable), the rest mutate state.
        # Bare `UID` blocking would break every modern IMAP client.
        effective_cmd = _command_name(line)

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

        if self._folder_lists:
            why = _folder_side_door(cmd, parts[2] if len(parts) >= 3 else b"")
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

        if cmd in _MAILBOX_ARG_COMMANDS and self._folder_lists:
            args = parts[2] if len(parts) >= 3 else b""
            if mailbox is not None:
                mailbox = _decode_mailbox(mailbox)
            elif _announces_literal(line):
                # A literal the relay didn't read ahead: too long, or not
                # the mailbox argument (where these commands never take one).
                mailbox = None
            else:
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
            reason = self._mailbox_denial_reason(mailbox, utf8_names)
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

        # The literal this line announces, if any (see _relay_command).
        try:
            lit = _client_literal(line)
        except _MalformedLiteral:
            log.warning(
                "imap relay %s: blocked %s with malformed literal",
                self._cfg.name, effective_cmd,
            )
            self._audit_log({
                "kind": "imap_command",
                "relay": self._cfg.name,
                "command": effective_cmd,
                "decision": "blocked",
                "reason": "malformed literal",
            })
            return (tag, "malformed literal", b"BAD")
        if lit is not None and lit.size > _MAX_LITERAL_BYTES:
            self._audit_literal_too_large(effective_cmd)
            return (
                tag,
                f"[TOOBIG] literal larger than {_MAX_LITERAL_BYTES} bytes",
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

    def _mailbox_denial_reason(
        self, mailbox: str, utf8_names: bool = False,
    ) -> Optional[str]:
        """Why this mailbox may not be selected, or None if it may.

        Denial wins over the allowlist: a folder named in both is denied.
        Names compare in canonical form (_fold()): case-insensitive, because
        IMAP servers differ on the case they report for special-use
        mailboxes, and a denylist that misses ``trash`` because the server
        said ``Trash`` would fail open, the wrong direction for this list to
        be wrong in; and NFC-normalised, so a decomposed ``É`` is the same
        letter as a precomposed one.

        One folder has two spellings when its name is not ASCII: modified
        UTF-7 (RFC 3501 §5.1.3, ``&AMk-t&AOk-``) and, once the upstream
        reads names as UTF-8 (RFC 6855), UTF-8 (``Été``). Both the
        configured names and the cage's are compared in every spelling the
        upstream might read them in (_name_forms()). A deny entry matches if
        any reading of the name matches any reading of the entry. The
        allowlist admits a name only in the reading the upstream will use:
        decoded modified UTF-7 until UTF-8 names may be on, and then only
        if every reading is allowed, since the relay can't tell which one a
        given server picks.

        Matching is exact otherwise: no wildcards, no hierarchy. Denying
        ``Trash`` does not deny ``Trash/Old``; list each folder.
        """
        forms = _name_forms(mailbox)
        if forms & self._deny_forms:
            return "denied by folder_denylist"
        if self._cfg.folder_allowlist:
            if utf8_names:
                allowed = forms <= self._allow_forms
            else:
                allowed = _server_reading(mailbox) in self._allow_forms
            if not allowed:
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

    def __init__(
        self,
        hidden: Callable[[str], bool],
        observe: Optional[Callable[[bytes], bool]] = None,
    ) -> None:
        self._hidden = hidden
        # Shown the first line of every response (a whole line, or the first
        # _HELD_LINE_LIMIT bytes of a longer one); returns False to drop
        # that response instead of forwarding it. See _CommandTracker.
        self._observe = observe
        self._held = bytearray()   # current line so far, not yet forwarded
        self._streaming = False    # current line overflowed: rest goes raw
        self._tail = b""           # last bytes of the line being streamed
        self._literal = 0          # literal bytes still to pass through
        self._continuing = False   # line continues a response after a literal
        self._data = False         # current response may carry literals
        self._inserts = bytearray()  # relay replies waiting for a boundary

    @property
    def at_boundary(self) -> bool:
        """True when everything forwarded so far ends with a complete
        response, so bytes written to the cage now start a new one.

        A partial line held back in ``_held`` doesn't count against it:
        none of it has been forwarded yet, so it simply goes out after.
        """
        return not (self._streaming or self._literal or self._continuing)

    def insert(self, data: bytes) -> bytes:
        """Place relay-originated *data* (whole responses) in the stream.

        Returns it if it can be written to the cage now; otherwise keeps
        it, behind any it already keeps, and returns b"": feed() emits it
        as soon as the upstream's response in progress is complete.
        """
        if self._inserts or not self.at_boundary:
            self._inserts += data
            return b""
        return data

    def _flush_inserts(self, out: bytearray) -> None:
        if self._inserts and self.at_boundary:
            out += self._inserts
            self._inserts.clear()

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
                    self._flush_inserts(out)
                continue
            self._held += piece
            if nl >= 0:
                line = bytes(self._held)
                self._held.clear()
                starting = not self._continuing
                kind = self._classify(line)
                if not starting or self._observe is None or self._observe(line):
                    out += self._rewrite(line, kind)
                self._end_line(line)
                self._flush_inserts(out)
            elif len(self._held) > _HELD_LINE_LIMIT:
                line = bytes(self._held)
                self._held.clear()
                starting = not self._continuing
                kind = self._classify(line)
                if kind == "capability" or (
                    kind == "status" and b"[CAPABILITY" in line.upper()
                ):
                    raise _UnfilterableResponse(
                        "upstream capability line longer than "
                        f"{_HELD_LINE_LIMIT} bytes"
                    )
                if starting and self._observe is not None \
                        and not self._observe(line):
                    raise _UnfilterableResponse(
                        "upstream continuation request longer than "
                        f"{_HELD_LINE_LIMIT} bytes"
                    )
                out += line
                self._streaming = True
                self._tail = line[-_LITERAL_TAIL_BYTES:]
        return bytes(out)

    def finish(self) -> bytes:
        """Flush a last line the upstream never terminated (at EOF), and
        relay replies still held, if the stream ends where they fit."""
        out = bytearray()
        if not self._streaming and self._held:
            line = bytes(self._held)
            self._held.clear()
            out += self._rewrite(line, self._classify(line))
            self._end_line(line)
        self._flush_inserts(out)
        return bytes(out)

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


class _ClientOutput:
    """The one way bytes reach the cage once the session is bridged.

    Two tasks write to the cage: the upstream -> client pipe, with the
    upstream's responses, and the client -> upstream pipe, with the relay's
    own replies to the commands it refuses or answers itself (``NO``, the
    ``OK`` to a LOGIN, ``BAD``, ``BYE``). Commands are pipelined, so a reply
    can be ready while the upstream is half way through a response, say
    inside a FETCH literal; written there, it would become part of the
    message body and the client's parse of everything after it would be
    off.

    So a relay reply goes out only between complete upstream responses: at
    once when the stream is at such a boundary, otherwise held by the
    _ResponseFilter, which already tracks lines and literals, until the
    response in progress ends. Replies keep the order they were made in.
    Each one is the tagged completion of a command the upstream never saw,
    so it may come before the completion of a command the cage sent
    earlier, as from a server running pipelined commands concurrently,
    which RFC 3501 §5.5 allows and clients must expect.

    Feeding the filter and writing its output happen with no await in
    between, in either task, so what the filter believes has been sent is
    always what the transport has been given.
    """

    def __init__(
        self, writer: asyncio.StreamWriter, filt: _ResponseFilter,
    ) -> None:
        self._writer = writer
        self._filt = filt

    async def from_upstream(self, chunk: bytes) -> None:
        """Forward upstream bytes (b"" at EOF). May raise
        _UnfilterableResponse."""
        out = self._filt.feed(chunk) if chunk else self._filt.finish()
        if out:
            self._writer.write(out)
            await self._writer.drain()

    async def from_relay(self, data: bytes) -> None:
        """Send a reply the relay made itself, at the next boundary."""
        out = self._filt.insert(data)
        if out:
            self._writer.write(out)
            await self._writer.drain()


class _CommandTracker:
    """What the upstream still owes the relay, shared by the two pipes.

    The client -> upstream pipe needs to know, for each literal it forwards,
    whether the upstream answered the line announcing it with a ``+``
    continuation request (send the literal) or a tagged response (the
    command is over: no literal follows). Only the upstream -> client pipe
    sees responses, so it shows every response's first line to observe(),
    and the client pipe waits on the future expect_continuation() returns.

    A ``+`` carries no tag, so it is only unambiguous when nothing else the
    upstream is still working on could ask for one: an IDLE (RFC 2177),
    another command's literal, or an extension the relay doesn't know. So
    before forwarding a line that announces a literal, the client pipe waits
    (settle()) until every other command it has forwarded has had its
    tagged response. The relay never forwards AUTHENTICATE, the other
    command that asks for continuations.
    """

    def __init__(self) -> None:
        self._outstanding: dict[bytes, int] = {}
        self._count = 0
        self._changed = asyncio.Event()
        # (tag, future, forward the "+" to the cage)
        self._waiter: Optional[tuple[bytes, asyncio.Future, bool]] = None

    @property
    def outstanding(self) -> int:
        return self._count

    def sent(self, tag: bytes) -> None:
        """A command with *tag* was forwarded; the upstream owes a reply."""
        self._outstanding[tag] = self._outstanding.get(tag, 0) + 1
        self._count += 1

    async def settle(self, allowed: int) -> None:
        """Wait until at most *allowed* forwarded commands are unanswered."""
        while self._count > allowed:
            self._changed.clear()
            await self._changed.wait()

    def expect_continuation(self, tag: bytes, forward: bool) -> asyncio.Future:
        """A future for the upstream's answer to a literal of command *tag*:
        True for ``+`` (forwarded to the cage only when *forward*, i.e. the
        cage itself is waiting for it), False for the tagged response."""
        fut = asyncio.get_running_loop().create_future()
        self._waiter = (tag, fut, forward)
        return fut

    def observe(self, line: bytes) -> bool:
        """See the first line of an upstream response; False drops it."""
        waiter = self._waiter
        if line[:1] == b"+":
            if waiter is None:
                return True  # IDLE's, or one the cage asked for itself
            self._waiter = None
            waiter[1].set_result(True)
            return waiter[2]
        words = line.split(None, 2)
        if (
            len(words) < 2
            or words[0] == b"*"
            or words[1].upper() not in _COMPLETION_WORDS
        ):
            return True
        tag = words[0]
        n = self._outstanding.get(tag, 0)
        if n:
            if n == 1:
                del self._outstanding[tag]
            else:
                self._outstanding[tag] = n - 1
            self._count -= 1
            self._changed.set()
        if waiter is not None and waiter[0] == tag:
            self._waiter = None
            waiter[1].set_result(False)
        return True


def _command_name(line: bytes) -> str:
    """The command a line from the cage starts, as audit records name it:
    upper-cased, with ``UID`` resolved to its subcommand (``UID STORE``)."""
    parts = line.split(None, 2)
    if len(parts) < 2:
        return ""
    cmd = parts[1].upper().decode("ascii", errors="replace")
    if cmd == "UID":
        sub_b = (parts[2].split(None, 1) or [b""])[0] if len(parts) >= 3 else b""
        sub = sub_b.upper().decode("ascii", errors="replace")
        return f"UID {sub}" if sub else "UID"
    return cmd


async def _copy_exactly(
    reader: asyncio.StreamReader,
    writer: Optional[asyncio.StreamWriter],
    n: int,
) -> bool:
    """Move exactly *n* bytes from *reader* to *writer* (None drops them),
    a chunk at a time. False if the reader hits EOF first."""
    while n > 0:
        chunk = await reader.read(min(n, 65536))
        if not chunk:
            return False
        n -= len(chunk)
        if writer is not None:
            writer.write(chunk)
            await writer.drain()
    return True


def _quote(value: str) -> bytes:
    """Quote an IMAP string literal-style (RFC 3501 §4.3 'quoted')."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return b'"' + escaped.encode() + b'"'


class _SessionState:
    """What the client pipe remembers about one session's commands."""

    __slots__ = ("utf8_names",)

    def __init__(self, utf8_names: bool = False) -> None:
        self.utf8_names = utf8_names


def _enables_utf8_names(line: bytes) -> bool:
    """True for an ENABLE asking for UTF-8 mailbox names."""
    parts = line.split()
    return (
        len(parts) >= 3
        and parts[1].upper() == b"ENABLE"
        and any(p.upper() in _UTF8_ENABLES for p in parts[2:])
    )


def _announces_literal(line: bytes) -> bool:
    try:
        return _client_literal(line) is not None
    except _MalformedLiteral:
        return True


def _folder_side_door(cmd: str, args: bytes) -> Optional[str]:
    """Why *cmd* is refused while a folder list is set, or None.

    The folder lists are checked on the commands that open or report on
    one mailbox (_MAILBOX_ARG_COMMANDS). These report on others: a LIST
    with ``RETURN (STATUS ...)`` (RFC 5819) gives STATUS data for every
    folder it lists, ESEARCH (RFC 7377) searches the mailboxes it names,
    and NOTIFY SET (RFC 5465) watches them. Rather than parse their
    mailbox specifiers, the relay refuses them; the cage can still STATUS
    or SELECT each folder the lists allow.
    """
    if cmd in ("LIST", "LSUB"):
        words = re.split(rb"[\s()]+", args.upper())
        if b"RETURN" in words and \
                b"STATUS" in words[words.index(b"RETURN"):]:
            return "STATUS in LIST with folder lists set"
    elif cmd == "ESEARCH":
        return "multi-mailbox search with folder lists set"
    elif cmd == "NOTIFY":
        if (args.split(None, 1) or [b""])[0].upper() != b"NONE":
            return "NOTIFY with folder lists set"
    return None


def _decode_mailbox(raw: bytes) -> Optional[str]:
    """A mailbox name as sent, decoded; None unless it is valid UTF-8 (an
    upstream reading names as UTF-8 refuses anything else, and the relay
    won't guess what a lenient one makes of it)."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


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
                return _decode_mailbox(bytes(buf))
            buf.append(c)
            i += 1
        return None
    if s.startswith(b"{"):
        # Literal — too complex for v1; deny by signalling unparseable.
        return None
    end = 0
    while end < len(s) and s[end] not in (ord(" "), ord("\t")):
        end += 1
    return _decode_mailbox(s[:end])
