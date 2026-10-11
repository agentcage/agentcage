"""Record tests/fixtures/egress/imap.json from the Python IMAP relay.

    uv run python tests/fixtures/egress/gen/imap.py

Four sections, each a list of cases:

* ``literals``: a command line -> the literal it announces (or
  ``"malformed"`` / null).
* ``mutf7``: a mailbox name -> its modified-UTF-7 decoding (or null).
* ``policy``: (relay policy, command line, literal mailbox, UTF-8 names
  on) -> the relay's own reply (or null: forwarded) and the audit records
  the check wrote.
* ``filter``: the upstream -> client response filter, driven by a list
  of ``feed`` / ``insert`` / ``finish`` operations -> what each one
  returned (or the error that closed the session).
* ``sessions``: whole sessions. A scripted mock upstream (the one
  ``tests/test_protocol_relays.py`` uses) behind the relay, a scripted
  client in front of it, and the recording: the PREAUTH line, what the
  client read at each step, every command the upstream received, the
  upstream's raw byte log, and the audit records.

The Rust relay asserts the same file (``src/relays/imap_tests.rs``), with
an in-process mock upstream that behaves like the one here. Audit records
are stored without ``ts`` (the relay's audit writer stamps it).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src" / "agentcage" / "data" / "proxy"))

os.environ["TEST_IMAP_USER"] = "real-user@example.com"
os.environ["TEST_IMAP_PASS"] = "real-app-password"

from relays import imap as m  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "egress" / "imap.json"


# ── Byte encoding ────────────────────────────────────────


class Blob:
    """A long byte string stored as its recipe: ``[(piece, count), ...]``
    concatenated. Slices of it are stored as the recipe plus a range, so a
    corpus holding a megabyte line stays small."""

    def __init__(self, parts):
        self.parts = parts
        self.data = b"".join(p * n for p, n in parts)

    def __len__(self):
        return len(self.data)

    def slice(self, start, end):
        return BlobSlice(self, start, min(end, len(self.data)))


class BlobSlice:
    def __init__(self, blob, start, end):
        self.blob, self.start, self.end = blob, start, end
        self.data = blob.data[start:end]


def enc(data):
    if isinstance(data, BlobSlice):
        return {"blob": [[enc(p), n] for p, n in data.blob.parts],
                "start": data.start, "end": data.end}
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return {"b64": base64.b64encode(data).decode()}


def enc_out(data: bytes):
    """What a step or filter op returned: long outputs as a digest."""
    if len(data) > 4096:
        return {"sha256": hashlib.sha256(data).hexdigest(), "len": len(data)}
    return enc(data)


def dec(value) -> bytes:
    if isinstance(value, dict) and "blob" in value:
        whole = b"".join(dec(p) * n for p, n in value["blob"])
        return whole[value["start"]:value["end"]]
    if isinstance(value, dict):
        return base64.b64decode(value["b64"])
    return value.encode("utf-8")


def data_of(value) -> bytes:
    return value.data if isinstance(value, BlobSlice) else value


# ── Pure helpers ─────────────────────────────────────────


LITERAL_LINES = [
    b"a1 APPEND INBOX {5}\r\n",
    b"a1 APPEND INBOX {5+}\r\n",
    b"a1 APPEND INBOX ~{5}\r\n",
    b"a1 APPEND INBOX ~{5+}\n",
    b"a1 APPEND INBOX {0}\r\n",
    b"a1 APPEND INBOX {" + b"9" * 19 + b"}\r\n",
    b"a1 APPEND INBOX {" + b"9" * 18 + b"}\r\n",
    b"a1 SEARCH TEXT {5-}\r\n",
    b"a1 SEARCH TEXT { 5}\r\n",
    b"a1 SEARCH TEXT {}\r\n",
    b"a1 SEARCH TEXT {5+ }\r\n",
    b"a1 SEARCH TEXT {5}}\r\n",
    b"a1 SEARCH TEXT {5}\r}\n",
    b"a1 SEARCH TEXT {5}\r\r\n",
    b"a1 NOOP\r\n",
    b"a1 NOOP}\r\n",
    b"a1 {x{5}\r\n",
    b"{5}\r\n",
    b"a1 APPEND INBOX {5}",
]

MUTF7_NAMES = [
    "&AMk-t&AOk-", "&ZeVnLIqe-", "R&-D", "INBOX",
    "~peter/mail/&U,BTFw-/&ZeVnLIqe-",
    "&AMk", "&A-", "&AM!-", "Été", "&2D0-", "&AMl-", "&AMk-&AOk-",
    "", "&-", "&-&-", "a&", "&AAA-",
]


def literal_case(line: bytes):
    try:
        lit = m._client_literal(line)
    except m._MalformedLiteral:
        return "malformed"
    if lit is None:
        return None
    return {"size": lit.size, "sync": lit.sync, "start": lit.start}


# ── Policy checks ────────────────────────────────────────


def entry(policy: dict, port: int = 1) -> dict:
    return {
        "name": "test-imap",
        "type": "imap",
        "listen": "127.0.0.1:0",
        "upstream": {"host": "127.0.0.1", "port": port, "tls": False},
        "auth": {
            "type": "imap-login",
            "user_source": "env:TEST_IMAP_USER",
            "password_source": "env:TEST_IMAP_PASS",
        },
        "policy": {
            "readonly": False,
            "folder_allowlist": [],
            "conn_rate_limit": "30/min",
            **policy,
        },
    }


MODES = [
    {"write_mode": "none"},
    {"readonly": True},
    {"write_mode": "organise"},
    {"write_mode": "full"},
]

ETE_MUTF7 = b"&AMk-t&AOk-"
ETE_NFC = "Été".encode()
ETE_NFD = "Été".encode()

MODE_LINES = [
    b"a1 NOOP\r\n", b"a1 FETCH 1 (BODY[])\r\n", b"a1 UID FETCH 1:* FLAGS\r\n",
    b"a1 UID SEARCH ALL\r\n", b"a1 SELECT INBOX\r\n",
    b"a1 APPEND INBOX {5}\r\n", b"a1 APPEND INBOX {5+}\r\n",
    b"a1 DELETE Trash\r\n", b"a1 STORE 1 +FLAGS (\\Seen)\r\n",
    b"a1 STORE 1 FLAGS (\\Deleted)\r\n", b"a1 STORE 1 -FLAGS (\\Deleted)\r\n",
    b"a1 UID STORE 5 +FLAGS.SILENT (\\Deleted)\r\n",
    b"a1 UID STORE 5 +FLAGS.SILENT (\\Flagged)\r\n",
    b"a1 STORE 1 -FLAGS (\\Seen) +FLAGS (\\Deleted)\r\n",
    b"a1 EXPUNGE\r\n", b"a1 UID EXPUNGE 1:5\r\n", b"a1 CLOSE\r\n", b"a1 close\r\n",
    b"a1 CREATE Folders/X\r\n", b"a1 RENAME A B\r\n", b"a1 MOVE 1 Trash\r\n",
    b"a1 UID MOVE 5 Folders/Bills\r\n", b"a1 COPY 1 Archive\r\n",
    b"a1 UID COPY 1 Archive\r\n",
    b'a1 REPLACE 1 "Drafts" {12}\r\n', b'a1 UID REPLACE 5 "Drafts" {12}\r\n',
    b'a1 uid replace 5 "Drafts" {12}\r\n',
    b'a1 SETQUOTA "" (STORAGE 512)\r\n', b'a1 setquota "" (STORAGE 512)\r\n',
    b'a1 SETANNOTATION INBOX "/comment" ("value.shared" "x")\r\n',
    b'a1 STORE 1 ANNOTATION (/comment (value.priv "x"))\r\n',
    b'a1 UID STORE 5 annotation (/comment (value.priv "x"))\r\n',
    b"a1 STORE 1 (UNCHANGEDSINCE 12) ANNOTATION (/comment (value.priv \"x\"))\r\n",
    b"a1 SETMETADATA INBOX (/private/comment \"x\")\r\n",
    b"a1 SETACL INBOX bob lrs\r\n", b"a1 DELETEACL INBOX bob\r\n",
    b"a1 COMPRESS DEFLATE\r\n", b"a1 compress deflate\r\n",
    b"a1  COMPRESS DEFLATE\r\n", b"a1\tCOMPRESS DEFLATE\r\n",
    b" a1 COMPRESS DEFLATE\r\n", b"a1 STARTTLS\r\n", b"a1 unauthenticate\r\n",
    b'a1 LOGIN "u" "p"\r\n', b"a1 AUTHENTICATE PLAIN\r\n", b"a1 login {4+}\r\n",
    b"a1 UID\r\n", b"a1 uid\r\n", b"a1\r\n", b"\r\n", b"   \r\n",
    b"+ NOOP\r\n", b"* NOOP\r\n", b"a(1 NOOP\r\n", b"+\r\n",
    b"a1 SEARCH TEXT {5-}\r\n", b"a1 SEARCH TEXT {}\r\n",
    b"a1 APPEND INBOX {67108865}\r\n", b"a1 APPEND INBOX {67108864}\r\n",
    b"a1 APPEND INBOX {" + b"9" * 40 + b"+}\r\n",
    b"a1 NOOP\rb EXPUNGE\r\n", b"a1 NOOP\r\r\n", b"a1\rEXPUNGE\r\n",
    b"a1 NOOP\x00b EXPUNGE\r\n", b"a1\x00EXPUNGE\r\n", b"a1 NOOP\x00\n",
    b"a1 NOOP\n", b"a1 NOOP", b"a1 NOOP\r", b"a1 F\xc3\xa9TCH 1\r\n",
    b"a1 \xffSTORE 1 +FLAGS (\\Deleted)\r\n",
]

FOLDER_READS = [
    b"GETQUOTAROOT %s",
    b"GETMETADATA %s /private/comment",
    b"GETMETADATA (DEPTH 1 MAXSIZE 1024) %s (/private/comment /shared/x)",
    b'GETANNOTATION %s "/comment" "value.shared"',
    b"GETACL %s", b"MYRIGHTS %s", b"LISTRIGHTS %s anyone",
    b"DELETE %s", b"RENAME %s Elsewhere",
    b"SELECT %s", b"EXAMINE %s", b"STATUS %s (MESSAGES)",
    b"SUBSCRIBE %s", b"UNSUBSCRIBE %s",
]
FOLDER_WRITES = [
    b'SETMETADATA %s (/private/comment "x")',
    b'SETANNOTATION %s "/comment" ("value.shared" "x")',
    b"SETACL %s bob lrs", b"DELETEACL %s bob",
]

FOLDER_LINES = []
for _cmd in FOLDER_READS + FOLDER_WRITES:
    for _mb in [b"Trash", b'"trash"', ETE_MUTF7, b'"' + ETE_NFD + b'"',
                b'"' + ETE_NFC + b'"', b"inBox", b'"inbox"', b'"Trash/Old"',
                b"&AMk-T&AOk-"]:
        FOLDER_LINES.append(b"a1 " + _cmd % _mb + b"\r\n")
FOLDER_LINES += [
    b"a1 SELECT Trash\r\n", b'a1 SELECT "Tr\\ash"\r\n',
    b'a1 SELECT "\xc9t\xe9"\r\n', b'a1 SELECT "unterminated\r\n',
    b"a1 SELECT {5}\r\n", b"a1 SELECT {2000}\r\n", b"a1 SELECT INBOX {5}\r\n",
    b"a1 SELECT\r\n", b"a1 SELECT \r\n",
    b"a1 SETMETADATA Trash (/private/comment {3}\r\n",
    b"a1 SETMETADATA INBOX (/private/comment {3}\r\n",
    b"a1 SETACL Trash{3}\r\n", b'a1 SETACL "INBOX" {3}\r\n',
    b"a1 LISTRIGHTS INBOX {3+}\r\n", b"a1 RENAME INBOX/old {7}\r\n",
    b"a1 GETMETADATA (DEPTH 1 /private/comment\r\n",
    b'a1 GETMETADATA ("x) INBOX" ) Trash /private/comment\r\n',
    b"a1 GETMETADATA (DEPTH 1)Trash /private/comment\r\n",
    b"a1 GETMETADATA (DEPTH 1)\tINBOX /private/comment\r\n",
    b"a1 GETACL {2000}\r\n",
    b'a1 GETMETADATA "" /shared/comment\r\n',
    b'a1 GETMETADATA (DEPTH infinity) "" (/shared/comment)\r\n',
    b'a1 SETMETADATA "" (/shared/comment "x")\r\n',
    b'a1 GETANNOTATION "" "/comment" "value.shared"\r\n',
    b'a1 SELECT ""\r\n',
    b"a1 RENAME Archive Trash\r\n", b"a1 CREATE Trash\r\n", b'a1 GETQUOTA ""\r\n',
    b'a1 LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN))\r\n',
    b'a1 list "" "%" return (children status (messages))\r\n',
    b'a1 LSUB "" "*" RETURN (STATUS (MESSAGES))\r\n',
    b"a1 ESEARCH IN (mailboxes Trash) ALL\r\n",
    b"a1 NOTIFY SET (mailboxes Trash (MessageNew))\r\n",
    b'a1 LIST "" "*"\r\n', b'a1 LIST "" STATUS RETURN (CHILDREN)\r\n',
    b"a1 NOTIFY NONE\r\n", b"a1 notify none\r\n", b"a1 NOTIFY\r\n",
    b"a1 MOVE 1 Trash\r\n", b"a1 COPY 1 Trash\r\n",
    b"a1 ENABLE UTF8=ACCEPT\r\n",
]

FOLDER_POLICIES = [
    {"folder_denylist": ["Trash", "Été"]},
    {"folder_denylist": ["Été"]},
    {"folder_denylist": ["&AMk-t&AOk-"]},
    {"folder_allowlist": ["INBOX", "INBOX/old"]},
    {"folder_allowlist": ["Été"]},
    {"folder_denylist": ["Trash"], "folder_allowlist": ["INBOX"]},
    {"folder_denylist": ["Straße"], "write_mode": "full"},
    {},
]

LITERAL_MAILBOXES = [
    (b"a1 SELECT {5}\r\n", b"Trash"),
    (b"a1 SELECT {5}\r\n", b"INBOX"),
    (b"a1 SELECT {11}\r\n", ETE_MUTF7),
    (b"a1 SELECT {13}\r\n", b"x\r\n* BYE haha"),
    (b"a1 SELECT {2}\r\n", b"\xc9t"),
    (b"a1 GETACL {5}\r\n", b"trash"),
    (b"a1 GETMETADATA (DEPTH 1) {5+}\r\n", b"Trash"),
    (b"a1 SETMETADATA {0}\r\n", b""),
    (b"a1 SELECT {8}\r\n", b"STRASSE"),
]


def policy_cases():
    cases = []

    def run(policy, line, mailbox=None, utf8=False, log_allowed=False):
        audit = []
        relay = m.ImapRelay(entry(policy), audit_log=audit.append,
                            log_allowed=log_allowed)
        decision = relay._policy_check(line, mailbox=mailbox, utf8_names=utf8)
        cases.append({
            "policy": policy,
            "log_allowed": log_allowed,
            "line": enc(line),
            "mailbox": None if mailbox is None else enc(mailbox),
            "utf8_names": utf8,
            "decision": None if decision is None else {
                "tag": enc(decision[0]),
                "reason": decision[1],
                "status": decision[2].decode(),
            },
            "audit": audit,
        })

    for policy in MODES:
        for line in MODE_LINES:
            run(policy, line)
    for line in MODE_LINES[:8]:
        run({"write_mode": "full"}, line, log_allowed=True)
    for policy in FOLDER_POLICIES:
        for line in FOLDER_LINES:
            run(policy, line)
            run(policy, line, utf8=True)
        for line, name in LITERAL_MAILBOXES:
            run(policy, line, mailbox=name)
            run(policy, line, mailbox=name, utf8=True)
    return cases


# ── Response filter ──────────────────────────────────────

FILTER_STREAM = (
    b"* CAPABILITY IMAP4rev1 COMPRESS=DEFLATE IDLE REPLACE\r\n"
    b"a1 OK CAPABILITY completed\r\n"
    b"* 1 FETCH (BODY[] {54}\r\n"
    b"* CAPABILITY IMAP4rev1 COMPRESS=DEFLATE IDLE REPLACE\r\n"
    b" BODY[HEADER] ~{9}\r\n* OK [CA)\r\n"
    b"a2 OK FETCH completed\r\n"
    b"a3 BAD unknown command {20}\r\n"
    b"* OK [CAPABILITY IMAP4rev1 COMPRESS=DEFLATE] hi\r\n"
    b"+ go ahead {3}\r\n"
    b"a4 OK [CAPABILITY COMPRESS=DEFLATE REPLACE IDLE] done\r\n"
    b"a5 OK [CAPABILITYX COMPRESS=DEFLATE] other code\r\n"
)
ENDINGS_STREAM = (
    b"* 1 FETCH (BODY[] {5}\n" + b"a\nb\rc" + b" FLAGS ()\r)\n"
    b"a1 NO x\r* 2 FETCH (BODY[] {4}\r\n"
    b"* 3 FETCH (BODY[] {2}\r\r\n"
    b"a2 OK done\r\n"
)
REPLY_RESPONSES = [
    b"* 1 FETCH (UID 7 BODY[] {23}\r\nline one\r\na2 NO fake\r\n"
    b" FLAGS (\\Seen))\r\n",
    b"* 2 FETCH (BODY[HEADER] ~{4}\r\nab\r\n BODY[TEXT] {0}\r\n)\r\n",
    b"a1 OK FETCH completed\r\n",
    b"+ go ahead {3}\r\n",
    b"* OK still here {4}\r\n",
    b"a3 BAD no {2}\r\n",
    b"* 3 EXISTS\r\n",
]
REPLY = b"a9 NO APPEND not permitted (readonly)\r\n"


def filter_cases():
    cases = []

    def run(name, ops, mode="none", folder_lists=False, exhaustive=False):
        f = m._ResponseFilter(
            lambda t: m._capability_hidden(t, mode, folder_lists)
        )
        outs = []
        error = None
        for op in ops:
            try:
                if op[0] == "feed":
                    outs.append(enc_out(f.feed(data_of(op[1]))))
                elif op[0] == "insert":
                    outs.append(enc_out(f.insert(data_of(op[1]))))
                else:
                    outs.append(enc_out(f.finish()))
            except m._UnfilterableResponse as e:
                error = str(e)
                break
        cases.append({
            "name": name, "mode": mode, "folder_lists": folder_lists,
            "held_limit": m._HELD_LINE_LIMIT, "exhaustive": exhaustive,
            "ops": [[op[0]] + ([enc(op[1])] if len(op) > 1 else [])
                    for op in ops],
            "outputs": outs, "error": error,
        })

    run("stream", [("feed", FILTER_STREAM), ("finish",)], exhaustive=True)
    run("stream-full", [("feed", FILTER_STREAM), ("finish",)], mode="full")
    run("stream-folders", [
        ("feed", b"* CAPABILITY IMAP4rev1 LIST-STATUS MULTISEARCH NOTIFY IDLE\r\n"),
        ("finish",)], folder_lists=True)
    run("full-keeps-replace",
        [("feed", b"* CAPABILITY IMAP4rev1 compress=deflate REPLACE\r\n")],
        mode="full")
    run("partial-line", [("feed", b"* CAPABILITY IMAP4rev1 COMPRESS=DEF"),
                         ("feed", b"LATE\r\n")])
    run("endings", [("feed", ENDINGS_STREAM), ("finish",)], exhaustive=True)
    for raw in [
        b"a1 NO no such mailbox x\r* 1 FETCH (BODY[] {9}\r\n",
        b"* 1 FETCH (BODY[] {5}\rXYZ)\r\n",
        b"* 1 FETCH (BODY[] {5}\r\r\n",
        b"* OK [CAPABILITY IMAP4rev1]\r* CAPABILITY COMPRESS=DEFLATE\r\n",
        b"a1 OK done\n",
        b"* CAPABILITY\r\n",
        b"* capability imap4rev1 starttls\r\n",
        b"* CAPABILITYX STARTTLS\r\n",
        b"a1 OK [CAPABILITY STARTTLS\r\n",
        b"* OK [CAPABILITY\xff STARTTLS] x\r\n",
        b"* 1 FETCH (BODY[] {" + b"9" * 70 + b"}\r\n",
    ]:
        run("line", [("feed", raw), ("insert", b"a9 NO refused\r\n")])
    run("literal-bytes", [("feed",
        b"* 1 FETCH (BODY[] {5}\n" + b"a\nb\rc" + b")\n"
        b"* 2 FETCH (BODY[] {6}\r\n" + b"\r\r\n\n\r\n" + b")\r\n"
        b"a1 OK done\n"), ("finish",)])
    run("eof-cr", [("feed", b"* BYE gone\r"), ("finish",)])
    run("eof-partial", [("feed", b"* CAPABILITY X STARTTLS"), ("finish",)])
    stream = b"".join(REPLY_RESPONSES)
    run("reply-boundaries", [("feed", stream), ("finish",)], exhaustive=True)
    for cut in range(0, len(stream) + 1, 7):
        run("reply-cut", [("feed", stream[:cut]), ("insert", REPLY),
                          ("feed", stream[cut:]), ("finish",)])
    cut = stream.index(b"line one")
    run("reply-order", [("feed", stream[:cut]), ("insert", b"a0 NO x\r\n"),
                        ("insert", b"a1 NO x\r\n"), ("insert", b"a2 NO x\r\n"),
                        ("feed", stream[cut:])])
    limit = m._HELD_LINE_LIMIT
    long_line = Blob([(b"* SEARCH", 1), (b" 12345", limit // 3), (b"\r\n", 1)])
    chunks = [long_line.slice(i, i + 8192) for i in range(0, len(long_line), 8192)]
    run("overlong-search", [("feed", c) for c in chunks]
        + [("feed", b"* CAPABILITY X COMPRESS=DEFLATE\r\n")])
    run("overlong-reply", [("feed", long_line.slice(0, limit + 100)),
                           ("insert", REPLY),
                           ("feed", long_line.slice(limit + 100, len(long_line)))])
    cr_line = Blob([(b"* SEARCH", 1), (b" 1\r2", limit // 3), (b"\r\n", 1)])
    for back in (0, 1, 2):
        cut = len(cr_line) - back
        ops = [("feed", cr_line.slice(i, min(i + 8192, cut)))
               for i in range(0, cut, 8192)]
        run("overlong-cr", ops + [("feed", cr_line.slice(cut, len(cr_line))),
                                  ("insert", REPLY)])
    filler = Blob([(b"A", 8192)]).slice(0, 8192)
    run("overlong-capability",
        [("feed", b"a1 OK [CAPABILITY COMPRESS=DEFLATE")]
        + [("feed", filler)] * (limit // 8192 + 2))
    run("overlong-capability-untagged",
        [("feed", b"* CAPABILITY ")] + [("feed", filler)] * (limit // 8192 + 2))
    return cases


# ── Sessions ─────────────────────────────────────────────

_UPSTREAM_LITERAL_RE = re.compile(rb"~?\{(\d+)(\+?)\}\r\n\Z")
DEFAULT_GREETING = b"* OK [CAPABILITY IMAP4rev1] fake upstream ready\r\n"


class Recorder:
    def __init__(self):
        self.commands: list[bytes] = []
        self.raw = bytearray()


async def _read_upstream_command(reader, writer, rec, refuse):
    cmd = b""
    while True:
        line = await reader.readline()
        rec.raw += line
        cmd += line
        if not line:
            return cmd, False
        mt = _UPSTREAM_LITERAL_RE.search(line)
        if mt is None:
            return cmd, False
        if not mt.group(2):
            name = cmd.split(None, 2)[1].upper()
            if name in refuse:
                tag = cmd.split(None, 1)[0]
                writer.write(tag + b" NO [TRYCREATE] no such mailbox\r\n")
                await writer.drain()
                return cmd, True
            writer.write(b"+ go ahead\r\n")
            await writer.drain()
        payload = await reader.readexactly(int(mt.group(1)))
        rec.raw += payload
        cmd += payload


async def start_upstream(rec: Recorder, up: dict):
    """The mock upstream, configured by the case's ``upstream`` dict."""
    greeting = dec(up["greeting"]) if "greeting" in up else DEFAULT_GREETING
    literals = up.get("literals", False)
    refuse = frozenset(s.encode() for s in up.get("refuse_literal", []))
    scripted = {k.encode(): [dec(c) for c in v]
                for k, v in up.get("scripted", {}).items()}
    login_ok = dec(up["login_ok"]) if "login_ok" in up else b"<TAG> OK LOGIN completed\r\n"

    async def handle(reader, writer):
        try:
            if up.get("silent"):
                await reader.read()
                return
            writer.write(greeting)
            await writer.drain()
            line = await reader.readline()
            if not line:
                return
            rec.commands.append(line)
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
            if (up.get("fail_login") or user != "real-user@example.com"
                    or pwd != "real-app-password"):
                if up.get("echo_login"):
                    writer.write(tag + b" NO [AUTHENTICATIONFAILED] rejected: "
                                 + line.rstrip(b"\r\n") + b"\r\n")
                else:
                    writer.write(tag + b" NO bad credentials\r\n")
                await writer.drain()
                return
            writer.write(login_ok.replace(b"<TAG>", tag))
            await writer.drain()
            while True:
                if literals:
                    line, refused = await _read_upstream_command(
                        reader, writer, rec, refuse)
                else:
                    line, refused = await reader.readline(), False
                if not line:
                    return
                rec.commands.append(line)
                if refused:
                    continue
                parts = line.split(b" ", 2)
                tag = parts[0]
                cmd = parts[1].rstrip(b"\r\n").upper() if len(parts) > 1 else b""
                if literals and cmd == b"IDLE":
                    writer.write(b"+ idling\r\n")
                    await writer.drain()
                    done = await reader.readline()
                    rec.raw += done
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
                if cmd in scripted:
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

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def send_command(reader, writer, pieces):
    """Send one command as a compliant client would (see the IMAP tests'
    ``_send_command``): wait for ``+`` before a synchronising literal's
    payload; a tagged response ends the command."""
    tag = pieces[0].split(None, 1)[0]
    got = []

    async def line():
        ln = await asyncio.wait_for(reader.readline(), 5)
        if not ln:
            raise EOFError(got)
        got.append(ln)
        return ln

    for i in range(0, len(pieces), 2):
        writer.write(pieces[i])
        await writer.drain()
        if i + 1 == len(pieces):
            break
        if not pieces[i].rstrip(b"\r\n").endswith(b"+}"):
            while True:
                ln = await line()
                if ln.startswith(b"+"):
                    break
                if ln.startswith(tag + b" "):
                    return got
        writer.write(pieces[i + 1])
        await writer.drain()
    while not (await line()).startswith(tag + b" "):
        pass
    return got


async def run_step(step, reader, writer, port):
    op = step["op"]
    if op == "command":
        return [enc(x) for x in await send_command(
            reader, writer, [dec(p) for p in step["pieces"]])]
    if op == "until_closed":
        try:
            got = await send_command(reader, writer,
                                     [dec(p) for p in step["pieces"]])
        except EOFError as e:
            got = e.args[0]
        return [enc(x) for x in got]
    if op == "line":
        writer.write(dec(step["send"]))
        await writer.drain()
        return [enc(await asyncio.wait_for(reader.readline(), 5))]
    if op == "send":
        writer.write(dec(step["send"]))
        await writer.drain()
        return None
    if op == "until_tag":
        tag = step["tag"].encode()
        got = []
        while True:
            ln = await asyncio.wait_for(reader.readline(), 5)
            if not ln:
                raise EOFError(got)
            got.append(ln)
            if ln.startswith(tag + b" "):
                return [enc(x) for x in got]
    if op == "read_all":
        return enc(await asyncio.wait_for(reader.read(), 5))
    if op == "read_exact":
        return enc_out(await asyncio.wait_for(reader.readexactly(step["n"]), 10))
    if op == "sleep":
        await asyncio.sleep(step["seconds"])
        return None
    if op == "new_client":
        r2, w2 = await asyncio.open_connection("127.0.0.1", port)
        try:
            return [enc(await asyncio.wait_for(r2.readline(), 5))]
        finally:
            w2.close()
    raise ValueError(op)


async def run_session(case: dict) -> dict:
    rec = Recorder()
    up = case.get("upstream", {})
    if up.get("unreachable"):
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        up_port = s.getsockname()[1]
        s.close()
        server = None
    else:
        server, up_port = await start_upstream(rec, up)
    audit: list[dict] = []
    results = []
    greeting = None
    try:
        relay = m.ImapRelay(entry(case.get("policy", {}), up_port),
                            audit_log=audit.append,
                            log_allowed=case.get("log_allowed", False))
        await relay.start()
        try:
            port = relay._server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                greeting = enc(await asyncio.wait_for(reader.readline(), 5))
                for step in case["steps"]:
                    results.append(await run_step(step, reader, writer, port))
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            await asyncio.sleep(0.1)
        finally:
            await relay.stop()
    finally:
        if server is not None:
            server.close()
            await server.wait_closed()
    for e in audit:
        if case.get("mask_error"):
            # The OS's words, and an ephemeral port: not portable.
            for key in ("error", "upstream"):
                if key in e:
                    e[key] = "<masked>"
    return {
        "greeting": greeting,
        "steps": results,
        "upstream": [enc(c) for c in rec.commands],
        "upstream_raw": enc(bytes(rec.raw)),
        "audit": audit,
    }


TRICKY_BODY = (
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


def cmd(*pieces):
    return {"op": "command", "pieces": [enc(p) for p in pieces]}


def session_cases():
    lit = {"literals": True}
    caps6 = b"IMAP4rev1 IDLE REPLACE MOVE COMPRESS=DEFLATE STARTTLS"
    cases = [
        {"name": "login-injected-and-select", "steps": [cmd(b"a1 SELECT INBOX\r\n"),
                                                        cmd(b"a2 LOGOUT\r\n")]},
        {"name": "cage-login-intercepted", "steps": [
            cmd(b'a1 LOGIN "cage" "pw"\r\n'), cmd(b"a2 AUTHENTICATE PLAIN\r\n"),
            cmd(b"a3 NOOP\r\n")]},
        {"name": "readonly-append", "policy": {"readonly": True},
         "steps": [cmd(b"a1 APPEND INBOX {3}\r\n"), cmd(b"a2 SELECT INBOX\r\n")]},
        {"name": "close-refused-none", "policy": {"write_mode": "none"},
         "steps": [cmd(b"a1 CLOSE\r\n"), cmd(b"a2 NOOP\r\n")]},
        {"name": "close-refused-organise", "policy": {"write_mode": "organise"},
         "steps": [cmd(b"a1 CLOSE\r\n"), cmd(b"a2 STORE 1 +FLAGS (\\Deleted)\r\n"),
                   cmd(b'a3 MOVE 1 "Trash"\r\n')]},
        {"name": "allowlist", "policy": {"folder_allowlist": ["INBOX"]},
         "steps": [cmd(b"a1 SELECT Trash\r\n"), cmd(b"a2 EXAMINE Spam\r\n"),
                   cmd(b"a3 SELECT INBOX\r\n"), cmd(b'a4 LIST "" "*"\r\n')]},
        {"name": "log-allowed", "log_allowed": True,
         "steps": [cmd(b"a1 NOOP\r\n"), cmd(b"a2 UID FETCH 1 FLAGS\r\n")]},
        {"name": "capability-forwarded", "upstream": {
            "greeting": b"* OK [CAPABILITY IMAP4rev1 IDLE MOVE] ready\r\n"},
         "steps": []},
        {"name": "compress-stripped", "upstream": {
            "greeting": b"* OK [CAPABILITY IMAP4rev1 IDLE COMPRESS=DEFLATE STARTTLS UNAUTHENTICATE REPLACE] ready\r\n"},
         "policy": {"write_mode": "none"}, "steps": []},
        {"name": "replace-kept-in-full", "upstream": {
            "greeting": b"* OK [CAPABILITY IMAP4rev1 REPLACE COMPRESS=DEFLATE] ready\r\n"},
         "policy": {"write_mode": "full"}, "steps": []},
        {"name": "no-capability-falls-back", "upstream": {
            "greeting": b"* OK ready\r\n"}, "steps": [cmd(b"a1 NOOP\r\n")]},
        {"name": "capability-fetched", "upstream": {
            "greeting": b"* OK ready\r\n",
            "scripted": {"CAPABILITY": [b"* CAPABILITY IMAP4 IDLE\r\n<TAG> OK done\r\n"]}},
         "steps": [cmd(b"a1 NOOP\r\n")]},
        {"name": "capability-from-login-ok", "upstream": {
            "login_ok": b"<TAG> OK [CAPABILITY IMAP4rev2 MOVE] logged in\r\n"},
         "steps": []},
        {"name": "imap4rev2-only-utf8-names", "policy": {"folder_allowlist": ["Été"]},
         "upstream": {"login_ok": b"<TAG> OK [CAPABILITY IMAP4rev2] in\r\n"},
         "steps": [cmd(b"a1 SELECT " + ETE_MUTF7 + b"\r\n"),
                   cmd(b'a2 SELECT "' + ETE_NFC + b'"\r\n')]},
        {"name": "side-door-caps-hidden", "policy": {"folder_denylist": ["Trash"]},
         "upstream": {"greeting": b"* OK [CAPABILITY IMAP4rev1 IDLE LIST-STATUS MULTISEARCH NOTIFY] hi\r\n"},
         "steps": []},
        {"name": "login-failure", "upstream": {"fail_login": True}, "steps": []},
        {"name": "login-failure-echo", "upstream": {"fail_login": True, "echo_login": True},
         "steps": []},
        {"name": "rejected-greeting", "upstream": {"greeting": b"* NO go away\r\n"},
         "steps": []},
        {"name": "silent-upstream", "upstream": {"silent": True},
         "policy": {"idle_timeout_seconds": 1}, "steps": []},
        {"name": "unreachable", "upstream": {"unreachable": True}, "mask_error": True,
         "steps": []},
        {"name": "rate-limit", "policy": {"conn_rate_limit": "2/min"},
         "steps": [{"op": "new_client"}, {"op": "new_client"}]},
    ]
    for policy in MODES:
        name = "-".join(f"{k}={v}" for k, v in policy.items())
        cases.append({"name": f"untagged-capability-filtered-{name}", "policy": policy,
                      "upstream": {"scripted": {"CAPABILITY": [
                          b"* CAPABILITY " + caps6 + b"\r\n<TAG> OK CAPABILITY completed\r\n"]}},
                      "steps": [cmd(b"a1 CAPABILITY\r\n")]})
        cases.append({"name": f"split-capability-filtered-{name}", "policy": policy,
                      "upstream": {"scripted": {"CAPABILITY": [
                          b"* CAPABILITY IMAP4rev1 IDLE REPLACE MOVE COMPR",
                          b"ESS=DEFLATE STARTTLS\r\n<TAG> OK CAPABILITY completed\r\n"]}},
                      "steps": [cmd(b"a1 CAPABILITY\r\n")]})
        cases.append({"name": f"tagged-capability-code-{name}", "policy": policy,
                      "upstream": {"scripted": {"NOOP": [
                          b"<TAG> OK [CAPABILITY " + caps6 + b"] NOOP completed\r\n"]}},
                      "steps": [cmd(b"a1 NOOP\r\n")]})
        cases.append({"name": f"untagged-capability-code-{name}", "policy": policy,
                      "upstream": {"scripted": {"NOOP": [
                          b"* OK [CAPABILITY " + caps6 + b"] still here\r\n",
                          b"<TAG> OK NOOP completed\r\n"]}},
                      "steps": [cmd(b"a1 NOOP\r\n")]})
        cases.append({"name": f"compress-refused-{name}", "policy": policy,
                      "steps": [cmd(b"a1 COMPRESS DEFLATE\r\n"), cmd(b"a2 NOOP\r\n")]})
        cases.append({"name": f"starttls-refused-{name}", "policy": policy,
                      "steps": [cmd(b"a1 STARTTLS\r\n"), cmd(b"a2 unauthenticate\r\n")]})

    # Large FETCH literal passes byte-exact: bigger than the relay's read
    # size and the held-line limit, with a line longer than that limit and
    # lines that look like capability responses and literals, all mail.
    head = (b"Subject: hi\r\n\r\n"
            b"* CAPABILITY IMAP4rev1 COMPRESS=DEFLATE REPLACE\r\n"
            b"a1 OK [CAPABILITY COMPRESS=DEFLATE] fake\r\n"
            b"* 2 FETCH (BODY[] {99999}\r\n")
    tail = b"\r\n* CAPABILITY COMPRESS=DEFLATE\r\n"
    body_len = len(head) + 300 * 1024 + 2 + 256 * 80 + len(tail)
    reply = Blob([
        (b"* 1 FETCH (UID 7 BODY[] {%d}\r\n" % body_len, 1), (head, 1),
        (b"x", 300 * 1024), (b"\r\n", 1), (bytes(range(256)), 80), (tail, 1),
        (b" FLAGS (\\Seen))\r\n<TAG> OK FETCH completed\r\n", 1),
    ])
    expected_len = len(reply) - len(b"<TAG>") + len(b"a1")
    chunks = [reply.slice(i, i + 70001) for i in range(0, len(reply), 70001)]
    cases.append({"name": "large-fetch-literal", "policy": {"write_mode": "none"},
                  "upstream": {"scripted": {"FETCH": chunks}},
                  "steps": [{"op": "send", "send": b"a1 FETCH 1 (UID BODY[] FLAGS)\r\n"},
                            {"op": "read_exact", "n": expected_len}]})

    # Client literals.
    for marker in (b"{%d}", b"{%d+}", b"~{%d}"):
        bd = TRICKY_BODY + (b"\x00\xff\r\n" if b"~" in marker else b"")
        cases.append({"name": "append-byte-exact-" + marker.decode(), "upstream": lit,
                      "log_allowed": True, "policy": {"write_mode": "full"},
                      "steps": [cmd(b"a1 APPEND INBOX (\\Seen) " + marker % len(bd) + b"\r\n",
                                    bd, b"\r\n"),
                                cmd(b"a2 NOOP\r\n")]})
    for policy in ({"write_mode": "none"}, {"write_mode": "organise"}):
        mode = policy["write_mode"]
        cases.append({"name": f"refused-sync-literal-{mode}", "upstream": lit, "policy": policy,
                      "steps": [cmd(b"a1 APPEND INBOX {%d}\r\n" % len(TRICKY_BODY),
                                    TRICKY_BODY, b"\r\n"),
                                cmd(b"a2 EXPUNGE\r\n"), cmd(b"a3 NOOP\r\n")]})
        payload = b"b NOOP\r\nc SELECT INBOX\r\nd EXAMINE x"
        second = b"e STATUS INBOX (MESSAGES)\r\n"
        cases.append({"name": f"refused-non-sync-literal-{mode}", "upstream": lit,
                      "policy": policy,
                      "steps": [cmd(b"a1 APPEND INBOX {%d+}\r\n" % len(payload), payload,
                                    b" (\\Seen) {%d+}\r\n" % len(second), second, b"\r\n"),
                                cmd(b"a2 EXPUNGE\r\n"), cmd(b"a3 NOOP\r\n")]})
    cases.append({"name": "upstream-refuses-sync-literal",
                  "upstream": {**lit, "refuse_literal": ["APPEND"]},
                  "steps": [cmd(b"a1 APPEND Nope {%d}\r\n" % len(TRICKY_BODY), TRICKY_BODY,
                                b"\r\n"), cmd(b"a2 NOOP\r\n")]})
    payload = b"b COMPRESS DEFLATE\r\nc NOOP\r\n"
    cases.append({"name": "upstream-refuses-non-sync-literal",
                  "upstream": {**lit, "refuse_literal": ["APPEND"]},
                  "steps": [cmd(b"a1 APPEND Nope {%d+}\r\n" % len(payload), payload, b"\r\n"),
                            cmd(b"a2 NOOP\r\n")]})
    m2 = b"Subject: two\r\n\r\nq LOGIN a b\r\nr compress deflate\r\n"
    for second in (b"{%d}", b"{%d+}"):
        cases.append({"name": "multiappend-" + second.decode(), "upstream": lit,
                      "steps": [cmd(b"a1 APPEND INBOX (\\Seen) {%d}\r\n" % len(TRICKY_BODY),
                                    TRICKY_BODY,
                                    b' (\\Flagged) "10-Oct-2026 10:00:00 +0000" '
                                    + second % len(m2) + b"\r\n", m2, b"\r\n")]})
    cases.append({"name": "oversized-sync-literal", "upstream": lit,
                  "steps": [cmd(b"a1 APPEND INBOX {%d}\r\n" % (m._MAX_LITERAL_BYTES + 1)),
                            cmd(b"a2 NOOP\r\n")]})
    for count in (b"%d+" % (64 * 1024 * 1024 + 1), b"9" * 40 + b"+"):
        cases.append({"name": "oversized-non-sync-literal", "upstream": lit,
                      "steps": [{"op": "send", "send": b"a1 APPEND INBOX {" + count
                                 + b"}\r\nb COMPRESS DEFLATE\r\n"},
                                {"op": "read_all"}]})
    cases.append({"name": "oversized-literal-mid-command", "upstream": lit,
                  "steps": [{"op": "until_closed", "pieces": [
                      enc(b"a1 APPEND INBOX {3}\r\n"), "abc",
                      enc(b" {67108865}\r\n")]}]})
    for line in (b"+ NOOP\r\n", b"* NOOP\r\n", b"a(1 NOOP\r\n", b"+\r\n"):
        cases.append({"name": "invalid-tag", "upstream": lit,
                      "steps": [{"op": "line", "send": line}, cmd(b"a2 NOOP\r\n")]})
    for marker in (b"{5-}", b"{ 5}", b"{}", b"{5+ }"):
        cases.append({"name": "malformed-literal", "upstream": lit,
                      "steps": [cmd(b"a1 SEARCH TEXT " + marker + b"\r\n"),
                                cmd(b"a2 NOOP\r\n")]})
    cases.append({"name": "idle-then-done", "upstream": lit, "policy": {"write_mode": "none"},
                  "steps": [{"op": "line", "send": b"a1 IDLE\r\n"},
                            {"op": "send", "send": b"DONE\r\n"},
                            {"op": "until_tag", "tag": "a1"}]})
    payload = b"b COMPRESS DEFLATE\r\n"
    cases.append({"name": "idle-plus-not-a-literal-go-ahead", "upstream": lit,
                  "steps": [{"op": "line", "send": b"a1 IDLE\r\na2 SEARCH TEXT {%d+}\r\n"
                             % len(payload) + payload + b"\r\n"},
                            {"op": "sleep", "seconds": 0.3}]})
    cases.append({"name": "literal-waits-for-pipelined", "upstream": lit,
                  "steps": [{"op": "send", "send": b"a1 NOOP\r\na2 SELECT INBOX\r\n"
                             b"a3 APPEND INBOX {%d+}\r\n" % len(TRICKY_BODY)
                             + TRICKY_BODY + b"\r\na4 NOOP\r\n"},
                            {"op": "until_tag", "tag": "a4"}]})
    cases.append({"name": "login-literal-dropped", "upstream": lit,
                  "policy": {"write_mode": "none"},
                  "steps": [cmd(b"a1 LOGIN {4+}\r\n", b"user", b" {13+}\r\n",
                                b"x EXPUNGE\r\n\r\n", b"\r\n"),
                            cmd(b"a2 NOOP\r\n")]})
    # Bare CR / NUL / LF.
    for line in (b"a1 NOOP\rb EXPUNGE\r\n", b"a1 NOOP\r\rb EXPUNGE\r\n", b"a1 NOOP\r\r\n",
                 b"a1\rEXPUNGE\r\n", b"a1 SELECT INBOX\rb DELETE Trash\r\n",
                 b"a1 NOOP\rb EXPUNGE\n", b"a1 NOOP\x00b EXPUNGE\r\n",
                 b"a1 SELECT INBOX\x00\r\n", b"a1\x00EXPUNGE\r\n",
                 b'a1 SELECT "IN\x00BOX"\r\n', b"a1 NOOP\x00\n"):
        cases.append({"name": "line-fault", "upstream": lit, "policy": {"write_mode": "none"},
                      "steps": [{"op": "line", "send": line}, cmd(b"a2 NOOP\r\n")]})
    for bad in (b"\r", b"\x00"):
        cases.append({"name": "line-fault-drops-non-sync-literal", "upstream": lit,
                      "steps": [cmd(b"a1 NOOP" + bad + b"b APPEND INBOX {6+}\r\n",
                                    b"c NOOP", b"\r\n"), cmd(b"a2 NOOP\r\n")]})
        cases.append({"name": "line-fault-after-literal", "upstream": lit,
                      "steps": [{"op": "until_closed", "pieces": [
                          enc(b"a1 SEARCH CHARSET UTF-8 TEXT {5}\r\n"), "hello",
                          enc(b" " + bad + b"b EXPUNGE\r\n")]}]})
    for marker in (b"{%d}", b"{%d+}"):
        bd = b"one\rtwo\x00three\r\n"
        cases.append({"name": "cr-nul-inside-literal", "upstream": lit,
                      "steps": [cmd(b"a1 APPEND INBOX " + marker % len(bd) + b"\r\n",
                                    bd, b"\r\n")]})
    cases.append({"name": "bare-lf-forwarded-with-crlf", "upstream": lit,
                  "steps": [cmd(b"a1 NOOP\n"), cmd(b"a2 APPEND INBOX {5}\n", b"hello", b"\n")]})
    # Folder lists end to end.
    deny = {"folder_denylist": ["Trash", "Été"]}
    for pieces in ([b"a1 SELECT Trash\r\n"], [b'a1 SELECT "Tr\\ash"\r\n'],
                   [b"a1 SELECT {5}\r\n", b"Trash", b"\r\n"],
                   [b"a1 SELECT {5+}\r\n", b"Trash", b"\r\n"],
                   [b"a1 STATUS {5}\r\n", b"trash", b" (MESSAGES)\r\n"],
                   [b"a1 EXAMINE {11+}\r\n", ETE_MUTF7, b" (CONDSTORE)\r\n"],
                   [b"a1 GETACL {5}\r\n", b"Trash", b"\r\n"],
                   [b"a1 MYRIGHTS {5+}\r\n", b"trash", b"\r\n"],
                   [b"a1 GETMETADATA (DEPTH 1) {5+}\r\n", b"Trash", b" /private/comment\r\n"],
                   [b"a1 SUBSCRIBE {11}\r\n", ETE_MUTF7, b"\r\n"],
                   [b"a1 SETMETADATA {5}\r\n", b"Trash", b" (/private/comment {3}\r\n",
                    b"abc", b")\r\n"]):
        cases.append({"name": "denied-form", "upstream": lit, "policy": deny,
                      "steps": [cmd(*pieces), cmd(b"a2 NOOP\r\n")]})
    allow = {"folder_allowlist": ["INBOX", "INBOX/old"]}
    for pieces in ([b"a1 SELECT {5}\r\n", b"INBOX", b"\r\n"],
                   [b"a1 SELECT {5+}\r\n", b"INBOX", b"\r\n"],
                   [b"a1 STATUS {5}\r\n", b"inbox", b" (MESSAGES UNSEEN)\r\n"],
                   [b"a1 SETMETADATA INBOX (/private/comment {3}\r\n", b"abc", b")\r\n"],
                   [b"a1 SETMETADATA {5}\r\n", b"INBOX", b" (/private/comment {3}\r\n",
                    b"abc", b")\r\n"],
                   [b"a1 LISTRIGHTS INBOX {3+}\r\n", b"bob", b"\r\n"],
                   [b'a1 SETACL "INBOX" {3}\r\n', b"bob", b" lrs\r\n"],
                   [b"a1 RENAME INBOX/old {7}\r\n", b"Archive", b"\r\n"]):
        cases.append({"name": "allowed-literal-form", "upstream": lit, "policy": allow,
                      "steps": [cmd(*pieces)]})
    cases.append({"name": "upstream-refuses-literal-name",
                  "upstream": {**lit, "refuse_literal": ["SELECT"]},
                  "policy": {"folder_allowlist": ["INBOX"]},
                  "steps": [cmd(b"a1 SELECT {5}\r\n", b"INBOX", b" (CONDSTORE)\r\n"),
                            cmd(b"a2 NOOP\r\n")]})
    name = b"x\r\n* BYE haha"
    cases.append({"name": "literal-name-kept-on-one-line", "upstream": lit,
                  "policy": {"folder_allowlist": ["INBOX"]},
                  "steps": [cmd(b"a1 SELECT {%d}\r\n" % len(name), name, b"\r\n"),
                            cmd(b"a2 NOOP\r\n")]})
    for enable in (b"a0 ENABLE UTF8=ACCEPT\r\n", b"a0 enable imap4rev2\r\n"):
        cases.append({"name": "enable-switches-reading", "upstream": lit,
                      "policy": {"folder_allowlist": ["Été"]},
                      "steps": [cmd(enable), cmd(b"a1 SELECT " + ETE_MUTF7 + b"\r\n"),
                                cmd(b'a2 SELECT "' + ETE_NFC + b'"\r\n')]})
    return cases


def encode(value):
    """`value` with every `bytes` in it stored as JSON (see :func:`enc`)."""
    if isinstance(value, (bytes, BlobSlice)):
        return enc(value)
    if isinstance(value, dict):
        return {k: encode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [encode(v) for v in value]
    return value


def stored_case(case: dict) -> dict:
    """A session case as the corpus stores it, minus `expect`."""
    return {
        "name": case["name"],
        "policy": case.get("policy", {}),
        "log_allowed": case.get("log_allowed", False),
        "upstream": encode(case.get("upstream", {})),
        "mask_error": case.get("mask_error", False),
        "steps": encode(case["steps"]),
    }


def main() -> None:
    sessions = []
    for case in session_cases():
        stored = stored_case(case)
        stored["expect"] = asyncio.run(run_session(stored))
        sessions.append(stored)
    corpus = {
        "_comment": "IMAP relay oracle, recorded from the Python egress by "
                    "tests/fixtures/egress/gen/imap.py; see its docstring.",
        "literals": [{"line": enc(x), "literal": literal_case(x)} for x in LITERAL_LINES],
        "mutf7": [{"name": n, "decoded": m._mutf7_decode(n)} for n in MUTF7_NAMES],
        "policy": policy_cases(),
        "filter": filter_cases(),
        "sessions": sessions,
    }
    OUT.write_text(json.dumps(corpus, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
