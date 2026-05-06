"""IMAP response parsers for the inbound message inspector.

Used by the IMAP relay when ``policy.require_authentication`` is on (and
later by ``from_allowlist``). The relay buffers SEARCH responses, side-
channel-fetches the headers of the returned UIDs, and filters out UIDs
that fail policy before forwarding the SEARCH response to the cage.

This module is stateless. It owns the parsing surface so ``imap.py``
doesn't grow yet another inline parser. Three things to parse:

    * ``* SEARCH 12 17 23`` — return the UID list, or ``None`` if the
      line isn't a SEARCH response.
    * A FETCH response containing ``BODY[HEADER.FIELDS (...)] {N}\r\n
      <N bytes of headers>`` — extract the literal payload for one
      requested UID. Multiple per response stream.
    * ``Authentication-Results: ... dkim=pass ... spf=pass ...
      dmarc=pass ...`` — return whether all three required methods
      have a verdict of ``pass``.

Robustness target: parse what Migadu and Dovecot actually emit. We do
not aim to be a complete IMAP grammar — anything we can't parse is
treated as policy-fail, so the caller drops the UID rather than
surfacing it.
"""

from __future__ import annotations

import re
from typing import Optional


# Authentication-Results syntax per RFC 8601 §2.2 is non-trivial — comments,
# pvalue tokens, multiple methods, optional reason fields. We don't need a
# full parser. The check is: for each required method, is there a
# ``method=pass`` token, with no later ``method=<other>`` overriding it?
# In practice all Migadu-stamped headers we've inspected use a single
# ``<method>=<result>`` token per method, separated by ``;`` or whitespace.
# We collapse multiline (RFC 5322 folded) headers before scanning.
_AUTHRES_TOKEN = re.compile(
    r"\b(dkim|spf|dmarc)\s*=\s*([a-z]+)",
    re.IGNORECASE,
)


def evaluate_authentication_results(
    header_value: str,
    *,
    required_methods: tuple[str, ...] = ("dkim", "spf", "dmarc"),
) -> bool:
    """Return True iff *header_value* shows ``=pass`` for every required method.

    Designed for the Migadu shape:

        Authentication-Results: m8i.io;
            dkim=pass header.d=luca.io;
            spf=pass smtp.mailfrom=luca@luca.io;
            dmarc=pass header.from=luca.io

    A method that appears multiple times (rare; happens when a relay
    re-stamps) is required to be ``pass`` on its FIRST occurrence —
    we treat earliest as authoritative since that's what the upstream
    receiver decided. Anything we can't parse fails closed.
    """
    if not header_value:
        return False
    # RFC 5322 folding: continuation lines start with whitespace. Collapse
    # so the regex sees one logical header value.
    flat = re.sub(r"\r?\n[ \t]+", " ", header_value)
    seen: dict[str, str] = {}
    for m in _AUTHRES_TOKEN.finditer(flat):
        method = m.group(1).lower()
        result = m.group(2).lower()
        # First occurrence wins — see docstring.
        seen.setdefault(method, result)
    for method in required_methods:
        if seen.get(method) != "pass":
            return False
    return True


# ── SEARCH response ─────────────────────────────────────


_SEARCH_RE = re.compile(rb"^\*\s+SEARCH\b(.*?)\r?\n$", re.IGNORECASE | re.DOTALL)


def parse_search_response_line(line: bytes) -> Optional[list[int]]:
    """If *line* is an untagged ``* SEARCH ...`` response, return the UID
    list. Otherwise return None.

    Empty result (``* SEARCH\r\n``) returns ``[]`` — the absence of
    matches, distinct from "not a SEARCH response."
    """
    m = _SEARCH_RE.match(line)
    if not m:
        return None
    payload = m.group(1).strip()
    if not payload:
        return []
    out: list[int] = []
    for tok in payload.split():
        try:
            out.append(int(tok))
        except ValueError:
            # Garbage in the UID list — treat the whole response as
            # unparseable so the caller fails closed.
            return None
    return out


def encode_search_response(uids: list[int]) -> bytes:
    """Re-emit a ``* SEARCH ...`` line for the given UID list.

    Empty list → ``* SEARCH\r\n`` (the well-formed "no matches" form).
    """
    if not uids:
        return b"* SEARCH\r\n"
    return b"* SEARCH " + b" ".join(str(u).encode() for u in uids) + b"\r\n"


# ── FETCH response with literal-string body ─────────────


# Match the start of an untagged FETCH response and capture the message
# sequence/UID and the body. We don't try to parse the inner field list
# structurally — we look for the BODY[...] section header followed by a
# literal-string size, then read the literal payload from the stream
# bytewise.
_FETCH_HEAD_RE = re.compile(
    rb"^\*\s+(\d+)\s+FETCH\s+\(",
    re.IGNORECASE,
)
_LITERAL_RE = re.compile(rb"\{(\d+)\}\r?\n")
_UID_PAIR_RE = re.compile(rb"\bUID\s+(\d+)", re.IGNORECASE)


class FetchResponseParser:
    """Streaming parser for ``UID FETCH ... (BODY.PEEK[HEADER.FIELDS (...)])``
    responses.

    Feed the raw bytes of upstream responses via :meth:`feed`. Yields
    ``(uid, header_blob)`` tuples as full FETCH responses are reassembled.
    Tagged status lines ("``a001 OK FETCH completed\\r\\n``") signal the
    end of the response stream — they are not yielded but cause
    :meth:`drain` to return them so the caller can detect completion.

    Why a streaming parser: literal-string framing means a single FETCH
    response can be tens of kilobytes, split across many TCP reads. We
    accumulate into a buffer and consume complete FETCH records in
    sequence.
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self._fetched: list[tuple[int, bytes]] = []
        self._tagged: Optional[bytes] = None

    def feed(self, chunk: bytes) -> None:
        if chunk:
            self._buf.extend(chunk)
        self._consume()

    def take_fetched(self) -> list[tuple[int, bytes]]:
        out = self._fetched
        self._fetched = []
        return out

    @property
    def tagged_response(self) -> Optional[bytes]:
        return self._tagged

    def _consume(self) -> None:
        while True:
            # Look for the next response line. If we don't have a complete
            # line yet, wait for more data.
            nl = self._buf.find(b"\n")
            if nl < 0:
                return
            line = bytes(self._buf[: nl + 1])

            # FETCH response with literal — must consume the literal payload
            # in addition to the header line.
            if _FETCH_HEAD_RE.match(line):
                consumed = self._try_consume_fetch_record()
                if consumed == 0:
                    # Need more data.
                    return
                # FetchRecord consumed — loop to handle next response.
                continue

            # Any non-FETCH line: if it's a tagged response (anything that
            # doesn't start with ``*``), record it and stop. Untagged lines
            # we don't care about (e.g. ``* OK ...``) are dropped — the
            # caller doesn't get the upstream stream verbatim through this
            # parser; only the FETCH content.
            del self._buf[: nl + 1]
            if not line.startswith(b"*"):
                self._tagged = line
                return
            # Untagged non-FETCH line: just discard.

    def _try_consume_fetch_record(self) -> int:
        """Parse one FETCH record (header + literal + closing paren).

        Returns the number of bytes consumed from ``self._buf``, or 0 if
        the record isn't fully buffered yet.
        """
        # We need the line header up to the literal marker, the literal
        # payload, then the trailing bytes up to the closing ``)\r\n``.
        # Approach: find the literal marker ``{N}\r\n``, advance past N
        # bytes, then find the end-of-record ``\r\n``.
        view = bytes(self._buf)
        head_match = _FETCH_HEAD_RE.match(view)
        if not head_match:
            return 0
        # Find the literal size in the header portion of the response —
        # may not be on the same line as the ``* N FETCH (`` opener if
        # the field list contains other items first. So search after the
        # opener for the first ``{N}\r\n``.
        lit_match = _LITERAL_RE.search(view, head_match.end())
        if not lit_match:
            # No literal — for our purposes (BODY[HEADER.FIELDS] always
            # comes back as a literal in practice), treat as malformed
            # and skip ahead one line so we don't loop forever.
            nl = view.find(b"\n")
            if nl < 0:
                return 0
            del self._buf[: nl + 1]
            return nl + 1

        lit_size = int(lit_match.group(1))
        lit_start = lit_match.end()
        lit_end = lit_start + lit_size
        if lit_end > len(view):
            # Literal not fully buffered yet.
            return 0

        # After the literal, look for the record's closing ``)`` and the
        # CRLF that terminates the FETCH untagged response.
        tail_start = lit_end
        end_nl = view.find(b"\n", tail_start)
        if end_nl < 0:
            return 0
        record_end = end_nl + 1

        # Pull the UID. Either the FETCH opener carries the UID directly
        # (common when the client sent UID FETCH) or the field list does
        # via ``UID <n>``.
        seq = int(head_match.group(1))
        uid_match = _UID_PAIR_RE.search(view, head_match.end(), tail_start)
        uid = int(uid_match.group(1)) if uid_match else seq

        header_blob = view[lit_start:lit_end]
        self._fetched.append((uid, header_blob))
        del self._buf[:record_end]
        return record_end


# ── Helpers for the side-channel header fetcher ─────────


def extract_authentication_results(header_blob: bytes) -> Optional[str]:
    """Pull the Authentication-Results header value out of a HEADER.FIELDS
    blob.

    The blob looks like::

        Authentication-Results: m8i.io;\r\n
            dkim=pass header.d=luca.io;\r\n
            ...\r\n
        \r\n

    Returns the value (with folding intact, as the evaluator handles it),
    or ``None`` if no Authentication-Results header is present.
    """
    try:
        text = header_blob.decode("ascii", errors="replace")
    except Exception:
        return None
    lines = text.splitlines()
    out: list[str] = []
    in_header = False
    for line in lines:
        if line[:1] in (" ", "\t") and in_header:
            out.append(line)
            continue
        if in_header:
            break
        if line.lower().startswith("authentication-results:"):
            value = line.split(":", 1)[1]
            out.append(value)
            in_header = True
    if not out:
        return None
    return "\n".join(out).strip()
