"""Record tests/fixtures/egress/smtp.json from the Python SMTP relay.

    uv run python tests/fixtures/egress/gen/smtp.py

Sections:

* ``headers``: a message body -> the content type and header list the
  relay's inspector context carries (Python's ``email`` package, policy
  ``compat32``).
* ``addresses``: a ``MAIL FROM:`` / ``RCPT TO:`` argument -> the address.
* ``sessions``: whole sessions against the mock submission host of
  ``tests/test_protocol_relays_smtp.py``. Each step sends bytes and reads
  a number of (possibly multi-line) replies. Recorded: every reply, what
  the upstream saw (command lines, AUTH credentials, delivered
  transactions), the audit records, and the context every inspector call
  saw. Inspectors are test inspectors described in the case: a
  ``marker`` inspector returns ``action`` with reason
  ``"<action>: <marker>"`` when its marker is in the body text, a
  ``recorder`` records the context and abstains.

Audit records are stored without ``ts`` (the audit writer stamps it).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src" / "agentcage" / "data" / "proxy"))

os.environ["TEST_SMTP_USER"] = "agent@example.com"
os.environ["TEST_SMTP_PASS"] = "real-app-password"

from inspectors.base import InspectionResult, Inspector  # noqa: E402
from relays import smtp as m  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "egress" / "smtp.json"
USER, PASS = "agent@example.com", "real-app-password"


def enc(data: bytes):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return {"b64": base64.b64encode(data).decode()}


def dec(value) -> bytes:
    if isinstance(value, dict):
        return base64.b64decode(value["b64"])
    return value.encode("utf-8")


def encode(value):
    if isinstance(value, bytes):
        return enc(value)
    if isinstance(value, dict):
        return {k: encode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [encode(v) for v in value]
    return value


# ── Pure helpers ─────────────────────────────────────────

HEADER_BODIES = [
    b"From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nbody\r\n",
    b"Content-Type: TEXT/HTML; charset=utf-8\r\n\r\n<b>x</b>\r\n",
    b"Content-Type: multipart/mixed;\r\n boundary=\"xyz\"\r\n\r\n--xyz--\r\n",
    b"content-type: application/octet-stream\r\n\r\n\x00\x01",
    b"Content-Type: nonsense\r\n\r\n",
    b"Content-Type: a/b/c\r\n\r\n",
    b"Content-Type:   image/png  ; name=x.png\r\n\r\n",
    b"Content-Type: \r\n\r\n",
    b"Subject: caf\xc3\xa9 \xff\r\n\r\n",
    b"Subject: folded\r\n\tcontinuation\r\n  more\r\nX: y\r\n\r\n",
    b"From someone@example.com Mon Jan  1 00:00:00 2026\r\nSubject: unix from\r\n\r\nx",
    b"Subject: a\r\nFrom misplaced\r\nX: y\r\n\r\n",
    b"Subject: a\r\nFrom last line\r\n",
    b" leading continuation\r\nSubject: a\r\n\r\n",
    b":nameless\r\nSubject: a\r\n\r\n",
    b"Subject: a\rX-CR: only\rTo: z\r\n\r\n",
    b"Subject: a\nX-LF: only\n\nbody",
    b"No header here, just text\r\nSubject: not a header\r\n",
    b"Subject: no body separator\r\nthis line is body\r\n",
    b"",
    b"Subject:\r\n\r\n",
    b"Subject:   \r\n   \r\n\r\n",
    b"X-Weird_Name!: v\r\n\r\n",
    b"Bad Name: v\r\n\r\n",
    b"Subject: no newline at end",
    b"Subject: crlf at end\r",
    b"Content-Type: text/plain\r\nContent-Type: text/html\r\n\r\n",
]

ADDRESS_ARGS = [
    "<luca@example.com>", "<luca@example.com> SIZE=100", "luca@example.com",
    "", "   ", "<>", "<> <real@example.com>", "noat", "<a<b@example.com>",
    "  < spaced@example.com >  ", "<unterminated@example.com", "x <y@z> <w@v>",
]


def header_case(body: bytes) -> dict:
    from email import message_from_bytes
    from email.policy import compat32
    msg = message_from_bytes(body, policy=compat32)
    return {
        "content_type": msg.get_content_type() or "",
        "headers": [[str(k), str(v)] for k, v in msg.items()],
    }


# ── Inspectors ───────────────────────────────────────────


class MarkerInspector(Inspector):
    def __init__(self, spec, contexts):
        self.name = spec["name"]
        self.spec = spec
        self.contexts = contexts

    def configure(self, config):
        pass

    def inspect_request(self, ctx):
        if self.spec["kind"] == "recorder":
            self.contexts.append({
                "inspector": self.name,
                "url": ctx.url, "host": ctx.host, "method": ctx.method,
                "headers": [[k, v] for k, v in ctx.headers],
                "content_type": ctx.content_type,
                "body_text": ctx.body_text, "body_size": ctx.body_size,
                "body_entropy": ctx.body_entropy,
                "prior": [r.inspector for r in ctx.prior_results],
            })
            return None
        marker = self.spec["marker"]
        if ctx.body_text and marker in ctx.body_text:
            action = self.spec["action"]
            return InspectionResult(
                inspector=self.name, action=action,
                reason=f"{action}: {marker}",
                severity=self.spec.get("severity", "warning"),
            )
        return None


# ── Mock upstream ────────────────────────────────────────


async def start_upstream(rec: dict, up: dict):
    reject = set(up.get("reject_rcpts", []))

    async def handle(reader, writer):
        try:
            if up.get("silent"):
                await reader.read()
                return
            writer.write(b"220 fake.upstream ESMTP\r\n")
            await writer.drain()
            txn = {"sender": "", "recipients": [], "data": b""}
            while True:
                line = await reader.readline()
                if not line:
                    return
                rec["commands"].append(enc(line))
                upper = line.upper()
                if upper.startswith(b"EHLO") or upper.startswith(b"HELO"):
                    writer.write(b"250-fake.upstream\r\n250-AUTH PLAIN LOGIN\r\n"
                                 b"250-SIZE 10485760\r\n250 8BITMIME\r\n")
                elif upper.startswith(b"AUTH PLAIN"):
                    token = line[len(b"AUTH PLAIN "):].strip()
                    try:
                        decoded = base64.b64decode(token).split(b"\0")
                        user, pwd = decoded[1].decode(), decoded[2].decode()
                    except Exception:
                        writer.write(b"535 5.7.8 bad auth\r\n")
                        await writer.drain()
                        continue
                    rec["auth_seen"] = [user, pwd]
                    if up.get("echo_auth"):
                        writer.write(b"535-5.7.8 rejected: " + line.rstrip(b"\r\n")
                                     + b"\r\n535 5.7.8 password " + pwd.encode()
                                     + b" is wrong\r\n")
                    elif up.get("fail_auth") or user != USER or pwd != PASS:
                        writer.write(b"535 5.7.8 bad credentials\r\n")
                    else:
                        writer.write(b"235 2.7.0 authenticated\r\n")
                elif upper.startswith(b"MAIL FROM"):
                    mt = re.search(rb"<([^>]+)>", line)
                    txn = {"sender": mt.group(1).decode() if mt else "",
                           "recipients": [], "data": b""}
                    writer.write(b"250 2.1.0 ok\r\n")
                elif upper.startswith(b"RCPT TO"):
                    mt = re.search(rb"<([^>]+)>", line)
                    rcpt = mt.group(1).decode() if mt else ""
                    if rcpt in reject:
                        writer.write(b"550 5.7.1 upstream-reject\r\n")
                    else:
                        txn["recipients"].append(rcpt)
                        writer.write(b"250 2.1.5 ok\r\n")
                elif upper.startswith(b"DATA"):
                    if up.get("reject_data"):
                        writer.write(b"554 5.7.0 no data today\r\n")
                        await writer.drain()
                        continue
                    writer.write(b"354 end with .\r\n")
                    await writer.drain()
                    body = bytearray()
                    while True:
                        ln = await reader.readline()
                        if ln in (b".\r\n", b".\n") or not ln:
                            break
                        if ln.startswith(b".."):
                            ln = ln[1:]
                        body.extend(ln)
                    txn["data"] = enc(bytes(body))
                    rec["transactions"].append(dict(txn))
                    writer.write(b"250 2.0.0 queued as ABC123\r\n")
                elif upper.startswith(b"RSET"):
                    txn = {"sender": "", "recipients": [], "data": b""}
                    writer.write(b"250 2.0.0 ok\r\n")
                elif upper.startswith(b"QUIT"):
                    writer.write(b"221 2.0.0 bye\r\n")
                    await writer.drain()
                    return
                elif upper.startswith(b"NOOP"):
                    writer.write(b"250 2.0.0 ok\r\n")
                else:
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

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def entry(policy: dict, port: int) -> dict:
    return {
        "name": "test-smtp", "type": "smtp", "listen": "127.0.0.1:0",
        "upstream": {"host": "127.0.0.1", "port": port, "tls": False},
        "auth": {"type": "smtp-plain", "user_source": "env:TEST_SMTP_USER",
                 "password_source": "env:TEST_SMTP_PASS"},
        "policy": {
            "sender_allowlist": [],
            "recipient_allowlist": {"addresses": [], "domains": []},
            "max_message_bytes": 5_242_880, "max_recipients": 10,
            "send_rate_limit": "100/min", "conn_rate_limit": "100/min",
            **policy,
        },
    }


async def read_response(reader) -> list[str]:
    lines = []
    while True:
        ln = await asyncio.wait_for(reader.readline(), 5)
        if not ln:
            lines.append("<eof>")
            return lines
        lines.append(enc(ln))
        if ln[3:4] != b"-":
            return lines


async def run_session(case: dict) -> dict:
    rec = {"commands": [], "auth_seen": None, "transactions": []}
    up = case["upstream"]
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
    contexts: list[dict] = []
    inspectors = [MarkerInspector(spec, contexts) for spec in case["inspectors"]]
    results = []
    try:
        relay = m.SmtpRelay(entry(case["policy"], up_port), audit_log=audit.append,
                            log_allowed=case["log_allowed"], inspectors=inspectors)
        await relay.start()
        try:
            port = relay._server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                greeting = await read_response(reader)
                for step in case["steps"]:
                    if "sleep" in step:
                        await asyncio.sleep(step["sleep"])
                    if "send" in step:
                        writer.write(dec(step["send"]))
                        await writer.drain()
                    if step.get("new_client"):
                        r2, w2 = await asyncio.open_connection("127.0.0.1", port)
                        results.append([await read_response(r2)])
                        w2.close()
                        continue
                    got = []
                    for _ in range(step.get("responses", 1)):
                        got.append(await read_response(reader))
                    results.append(got)
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
    if case.get("mask_error"):
        for e in audit:
            if "error" in e:
                e["error"] = "<masked>"
    return {"greeting": greeting, "steps": results, "upstream": rec,
            "audit": audit, "contexts": contexts}


# ── Cases ────────────────────────────────────────────────

def send(data: bytes, responses: int = 1) -> dict:
    return {"send": data, "responses": responses}


HELLO = [send(b"EHLO cage.local\r\n")]
TXN = HELLO + [send(b"MAIL FROM:<agent@example.com>\r\n"),
               send(b"RCPT TO:<friend@example.com>\r\n"), send(b"DATA\r\n")]
MSG = b"From: agent@example.com\r\nTo: friend@example.com\r\nSubject: hi\r\n\r\nHello there.\r\n.\r\n"

BLOCK = {"kind": "marker", "name": "marker", "action": "block",
         "marker": "EXFIL_MARKER_99", "severity": "critical"}
FLAG = {"kind": "marker", "name": "marker-flag", "action": "flag",
        "marker": "FLAG_MARKER_42", "severity": "warning"}
REC = {"kind": "recorder", "name": "recorder"}
SECRETS = {"kind": "marker", "name": "secrets", "action": "block",
           "marker": "sk-ant-api03", "severity": "critical"}
ENTROPY = {"kind": "marker", "name": "entropy", "action": "flag",
           "marker": "QUJDREVGR0g", "severity": "warning"}
BODYSIZE = {"kind": "marker", "name": "body-size", "action": "block",
            "marker": "HUGE", "severity": "error"}


def case(name, steps, **kw):
    return {"name": name, "steps": steps, "policy": kw.get("policy", {}),
            "log_allowed": kw.get("log_allowed", False),
            "upstream": kw.get("upstream", {}), "inspectors": kw.get("inspectors", []),
            "mask_error": kw.get("mask_error", False)}


def session_cases():
    rcpt_allow = {"recipient_allowlist": {"addresses": ["friend@example.com"], "domains": []}}
    cases = [
        case("round-trip", TXN + [send(MSG), send(b"QUIT\r\n")]),
        case("round-trip-logged", TXN + [send(MSG)], log_allowed=True),
        case("helo", [send(b"HELO cage\r\n"), send(b"NOOP\r\n")]),
        case("before-helo", [send(b"MAIL FROM:<a@b>\r\n"), send(b"NOOP\r\n")]),
        case("misc-commands", HELLO + [send(b"NOOP\r\n"), send(b"VRFY bob\r\n"),
                                       send(b"HELP\r\n"), send(b"EXPN list\r\n"),
                                       send(b"RSET\r\n"), send(b"noop\r\n"),
                                       send(b"QUIT\r\n")]),
        case("syntax", HELLO + [send(b"MAIL TO:<a@b>\r\n"), send(b"MAIL\r\n"),
                                send(b"RCPT FROM:<a@b>\r\n"), send(b"RCPT TO:<a@b>\r\n"),
                                send(b"DATA\r\n")]),
        case("mail-forms", HELLO + [send(b"MAIL FROM:<>\r\n"), send(b"MAIL FROM:noat\r\n"),
                                    send(b"mail from: bare@example.com\r\n"),
                                    send(b"MAIL FROM:<x@y> SIZE=10\r\n")]),
        case("rcpt-mixed", HELLO + [send(b"MAIL FROM:<agent@example.com>\r\n"),
                                    send(b"RCPT TO:<friend@example.com>\r\n"),
                                    send(b"RCPT TO:<evil@attacker.com>\r\n"),
                                    send(b"RCPT TO:<>\r\n"),
                                    send(b"DATA\r\n"), send(MSG)],
             policy=rcpt_allow),
        case("rcpt-domains", HELLO + [send(b"MAIL FROM:<a@example.com>\r\n"),
                                      send(b"RCPT TO:<x@sub.example.com>\r\n"),
                                      send(b"RCPT TO:<x@EXAMPLE.com>\r\n"),
                                      send(b"RCPT TO:<x@badexample.com>\r\n")],
             policy={"recipient_allowlist": {"addresses": [], "domains": ["example.com"]}}),
        case("rcpt-list-shorthand", HELLO + [send(b"MAIL FROM:<a@example.com>\r\n"),
                                             send(b"RCPT TO:<Friend@Example.com>\r\n"),
                                             send(b"RCPT TO:<x@example.com>\r\n")],
             policy={"recipient_allowlist": ["friend@example.com"]}),
        case("sender-allowlist", HELLO + [send(b"MAIL FROM:<evil@example.com>\r\n"),
                                          send(b"MAIL FROM:<Agent@Example.COM>\r\n")],
             policy={"sender_allowlist": ["agent@example.com"]}),
        case("max-recipients", HELLO + [send(b"MAIL FROM:<a@example.com>\r\n")]
             + [send(b"RCPT TO:<r%d@example.com>\r\n" % i) for i in range(4)],
             policy={"max_recipients": 2}),
        case("max-message-bytes", TXN + [send(b"Subject: x\r\n\r\n" + b"y" * 200 + b"\r\n.\r\n"),
                                         send(b"NOOP\r\n")],
             policy={"max_message_bytes": 50}),
        case("send-rate-limit", TXN + [send(MSG), send(b"MAIL FROM:<agent@example.com>\r\n"),
                                       send(b"RCPT TO:<friend@example.com>\r\n"),
                                       send(b"DATA\r\n")],
             policy={"send_rate_limit": "1/hour"}),
        case("blocked-does-not-burn-slot", TXN + [
            send(b"Subject: x\r\n\r\nEXFIL_MARKER_99\r\n.\r\n"),
            send(b"MAIL FROM:<agent@example.com>\r\n"), send(b"RCPT TO:<friend@example.com>\r\n"),
            send(b"DATA\r\n"), send(MSG)],
             policy={"send_rate_limit": "1/hour"}, inspectors=[BLOCK]),
        case("oversize-does-not-burn-slot", TXN + [
            send(b"Subject: x\r\n\r\n" + b"y" * 200 + b"\r\n.\r\n"),
            send(b"MAIL FROM:<agent@example.com>\r\n"), send(b"RCPT TO:<friend@example.com>\r\n"),
            send(b"DATA\r\n"), send(b"short\r\n.\r\n")],
             policy={"send_rate_limit": "1/hour", "max_message_bytes": 100}),
        case("conn-rate-limit", [{"new_client": True}, {"new_client": True}],
             policy={"conn_rate_limit": "2/min"}),
        case("auth-plain-inline", HELLO + [send(b"AUTH PLAIN AGNhZ2UAcHc=\r\n"), send(b"NOOP\r\n")]),
        case("auth-plain-continuation", HELLO + [send(b"AUTH PLAIN\r\n"),
                                                 send(b"AGNhZ2UAcHc=\r\n"), send(b"NOOP\r\n")]),
        case("auth-plain-lowercase", HELLO + [send(b"auth plain\r\n"),
                                              send(b"AGNhZ2UAcHc=\r\n")]),
        case("auth-login", HELLO + [send(b"AUTH LOGIN\r\n"), send(b"Y2FnZQ==\r\n"),
                                    send(b"cHc=\r\n"), send(b"NOOP\r\n")]),
        case("auth-login-inline-user", HELLO + [send(b"AUTH LOGIN Y2FnZQ==\r\n"),
                                                send(b"Y2FnZQ==\r\n"), send(b"cHc=\r\n")]),
        case("auth-other", HELLO + [send(b"AUTH CRAM-MD5\r\n")]),
        case("inspector-block", TXN + [send(b"Subject: x\r\n\r\nleak EXFIL_MARKER_99\r\n.\r\n"),
                                       send(b"NOOP\r\n")], inspectors=[BLOCK, REC]),
        case("inspector-pass", TXN + [send(MSG)], inspectors=[REC, BLOCK]),
        case("inspector-flag", TXN + [send(b"Subject: x\r\n\r\nFLAG_MARKER_42\r\n.\r\n")],
             inspectors=[FLAG, REC]),
        case("inspector-flag-then-block", TXN + [
            send(b"Subject: x\r\n\r\nFLAG_MARKER_42 EXFIL_MARKER_99\r\n.\r\n")],
             inspectors=[FLAG, BLOCK, REC]),
        case("context", TXN + [send(b"From: a@example.com\r\nContent-Type: Text/Plain; charset=x\r\n"
                                    b"Subject: caf\xc3\xa9\r\n\r\nbody \xff bytes\r\n..dot\r\n.\r\n")],
             inspectors=[REC]),
        case("default-bypass", TXN + [send(b"Subject: x\r\n\r\nkey sk-ant-api03-XXXX QUJDREVGR0g\r\n.\r\n")],
             policy=rcpt_allow, inspectors=[SECRETS, ENTROPY, REC]),
        case("explicit-empty-bypass", TXN + [send(b"Subject: x\r\n\r\nkey sk-ant-api03-XXXX\r\n.\r\n")],
             policy={**rcpt_allow, "bypass_inspectors_for_allowlisted": []},
             inspectors=[SECRETS]),
        case("no-allowlist-no-bypass", TXN + [send(b"Subject: x\r\n\r\nkey sk-ant-api03-XXXX\r\n.\r\n")],
             inspectors=[SECRETS]),
        case("bypass-keeps-body-size", TXN + [send(b"Subject: x\r\n\r\nHUGE\r\n.\r\n")],
             policy=rcpt_allow, inspectors=[BODYSIZE, SECRETS]),
        case("custom-bypass", TXN + [send(b"Subject: x\r\n\r\nHUGE sk-ant-api03\r\n.\r\n")],
             policy={**rcpt_allow, "bypass_inspectors_for_allowlisted": ["body-size", "secrets"]},
             inspectors=[SECRETS, BODYSIZE, REC]),
        case("flag-logged-when-off", TXN + [send(b"Subject: x\r\n\r\nQUJDREVGR0g\r\n.\r\n")],
             inspectors=[ENTROPY]),
        case("dot-stuffing", TXN + [send(b"Subject: dots\r\n\r\n..leading dot\r\n...two\r\n"
                                         b"middle . dot\r\n.\r\n")]),
        case("bare-lf-message", TXN + [send(b"Subject: lf\n\n.x\nno crlf\n.\n")]),
        case("rcpt-rejected-upstream", HELLO + [
            send(b"MAIL FROM:<agent@example.com>\r\n"), send(b"RCPT TO:<friend@example.com>\r\n"),
            send(b"RCPT TO:<bounce@example.com>\r\n"), send(b"DATA\r\n"), send(MSG)],
             upstream={"reject_rcpts": ["bounce@example.com"]}, log_allowed=True),
        case("all-rcpts-rejected-upstream", TXN + [send(MSG), send(b"NOOP\r\n")],
             upstream={"reject_rcpts": ["friend@example.com"]}),
        case("upstream-auth-rejected", TXN + [send(MSG), send(b"RSET\r\n")],
             upstream={"fail_auth": True}),
        case("upstream-auth-echoed", TXN + [send(MSG)], upstream={"echo_auth": True}),
        case("upstream-data-rejected", TXN + [send(MSG)], upstream={"reject_data": True}),
        case("upstream-unreachable", TXN + [send(MSG), send(b"NOOP\r\n")],
             upstream={"unreachable": True}, mask_error=True),
        case("upstream-reused", TXN + [send(MSG), send(b"RSET\r\n"),
                                       send(b"MAIL FROM:<agent@example.com>\r\n"),
                                       send(b"RCPT TO:<friend@example.com>\r\n"),
                                       send(b"DATA\r\n"), send(MSG)]),
        case("cage-idle", [{"sleep": 1.5, "responses": 1}], policy={"idle_timeout_seconds": 1}),
        case("data-idle", TXN + [{"send": b"Subject: x\r\n", "sleep": 0, "responses": 0},
                                 {"sleep": 1.5, "responses": 1}, send(b"NOOP\r\n")],
             policy={"idle_timeout_seconds": 1}),
        case("upstream-silent", TXN + [send(MSG)], upstream={"silent": True},
             policy={"idle_timeout_seconds": 1}),
        case("rset-clears", HELLO + [send(b"MAIL FROM:<agent@example.com>\r\n"),
                                     send(b"RCPT TO:<friend@example.com>\r\n"),
                                     send(b"RSET\r\n"), send(b"DATA\r\n")]),
        case("ehlo-resets", HELLO + [send(b"MAIL FROM:<agent@example.com>\r\n"),
                                     send(b"EHLO again\r\n"), send(b"RCPT TO:<x@y.z>\r\n")]),
        case("ehlo-size", HELLO, policy={"max_message_bytes": 1234}),
        case("pipelined", [send(b"EHLO a\r\nMAIL FROM:<agent@example.com>\r\n"
                                b"RCPT TO:<friend@example.com>\r\nDATA\r\n", 4),
                           send(MSG)]),
        case("non-ascii-command", HELLO + [send(b"M\xc3\x80IL FROM:<a@b.c>\r\n"),
                                           send(b"MAIL FROM:<\xc3\xa9@example.com>\r\n")]),
    ]
    return cases


def stored(c: dict) -> dict:
    return encode(c)


def main() -> None:
    sessions = []
    for c in session_cases():
        s = stored(c)
        s["expect"] = asyncio.run(run_session(s))
        sessions.append(s)
    corpus = {
        "_comment": "SMTP relay oracle, recorded from the Python egress by "
                    "tests/fixtures/egress/gen/smtp.py; see its docstring.",
        "headers": [{"body": enc(b), **header_case(b)} for b in HEADER_BODIES],
        "addresses": [{"arg": a, "address": m._extract_address(a)} for a in ADDRESS_ARGS],
        "sessions": sessions,
    }
    OUT.write_text(json.dumps(corpus, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
