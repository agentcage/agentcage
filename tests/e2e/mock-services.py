"""Mock upstreams for the egress-feature e2e phase (phase 9).

One stdlib-only process serving four stand-ins, each on its own thread:

  * IMAP   127.0.0.1:3143  plaintext, the protocol relay's upstream
  * SMTP   127.0.0.1:3025  plaintext, the protocol relay's upstream
  * LLM    127.0.0.1:18089 plain HTTP, answers the Anthropic /v1/messages
                           forced-tool-call shape for the decider ("decide")
                           and the traffic watcher ("review")
  * TLS    0.0.0.0:443     a TLS server with its own self-signed
                           certificate, the upstream of a passthrough domain

Like mock-httpbin.py it runs in its own container that shares the egress
container's network namespace (see ``start_services`` in
phase9_egress_features.sh), so the loopback listeners are reachable from
the egress only, never from the cage. The TLS listener binds every
interface because a passthrough splice dials the cage's ORIGINAL
destination, which the phase points at the egress's own cage-network
address.

Everything a test needs to assert on is appended to files under
/tmp/mock-log (read back with ``podman exec ... cat``):

  imap.log      every command line the relay forwarded upstream
  smtp.jsonl    one JSON object per message accepted with a final "."
  smtp.log      every SMTP command line received
  llm.jsonl     one JSON object per LLM call: tool name, x-api-key, domain

Usage: mock-services.py CERT_PEM KEY_PEM
"""

import json
import os
import socket
import socketserver
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_DIR = "/tmp/mock-log"
_log_lock = threading.Lock()


def _append(name, line):
    with _log_lock:
        with open(os.path.join(LOG_DIR, name), "a", encoding="utf-8") as fh:
            fh.write(line.rstrip("\r\n") + "\n")


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ── IMAP ─────────────────────────────────────────────────────────────

_MESSAGE = (
    "From: sender@example.com\r\n"
    "To: agent@example.com\r\n"
    "Subject: e2e mock message\r\n"
    "\r\n"
    "hello from the mock imap server\r\n"
)


class ImapHandler(socketserver.StreamRequestHandler):
    def _send(self, text):
        self.wfile.write(text.encode())
        self.wfile.flush()

    def handle(self):
        self._send("* OK mock IMAP ready\r\n")
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            _append("imap.log", line)
            parts = line.split(" ", 2)
            if len(parts) < 2:
                self._send("* BAD missing command\r\n")
                continue
            tag, cmd = parts[0], parts[1].upper()
            args = parts[2] if len(parts) > 2 else ""
            if cmd == "UID" and args:
                sub = args.split(" ", 1)
                cmd = "UID " + sub[0].upper()
            if cmd == "CAPABILITY":
                self._send("* CAPABILITY IMAP4rev1 IDLE UIDPLUS\r\n"
                           f"{tag} OK CAPABILITY completed\r\n")
            elif cmd in ("SELECT", "EXAMINE"):
                self._send("* FLAGS (\\Seen \\Deleted)\r\n"
                           "* 1 EXISTS\r\n"
                           "* OK [UIDVALIDITY 1] ok\r\n"
                           f"{tag} OK [READ-WRITE] {cmd} completed\r\n")
            elif cmd in ("FETCH", "UID FETCH"):
                body = _MESSAGE.encode()
                self._send(f"* 1 FETCH (UID 1 BODY[] {{{len(body)}}}\r\n")
                self.wfile.write(body)
                self._send(f")\r\n{tag} OK FETCH completed\r\n")
            elif cmd == "LIST":
                self._send('* LIST () "/" INBOX\r\n'
                           '* LIST () "/" Trash\r\n'
                           f"{tag} OK LIST completed\r\n")
            elif cmd == "STORE" or cmd == "UID STORE":
                self._send(f"* 1 FETCH (FLAGS (\\Seen))\r\n"
                           f"{tag} OK STORE completed\r\n")
            elif cmd == "LOGOUT":
                self._send(f"* BYE bye\r\n{tag} OK LOGOUT completed\r\n")
                return
            else:
                self._send(f"{tag} OK {cmd} completed\r\n")


# ── SMTP ─────────────────────────────────────────────────────────────


class SmtpHandler(socketserver.StreamRequestHandler):
    def _send(self, text):
        self.wfile.write(text.encode())
        self.wfile.flush()

    def handle(self):
        self._send("220 mock ESMTP ready\r\n")
        sender, rcpts = "", []
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            _append("smtp.log", line)
            verb = line.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                self._send("250-mock\r\n250-AUTH PLAIN LOGIN\r\n"
                           "250-8BITMIME\r\n250 SIZE 10485760\r\n")
            elif verb == "AUTH":
                self._send("235 2.7.0 accepted\r\n")
            elif verb == "MAIL":
                sender, rcpts = line[10:].strip(), []
                self._send("250 2.1.0 ok\r\n")
            elif verb == "RCPT":
                rcpts.append(line[8:].strip())
                self._send("250 2.1.5 ok\r\n")
            elif verb == "DATA":
                self._send("354 go ahead\r\n")
                lines = []
                complete = False
                while True:
                    data = self.rfile.readline()
                    if not data:
                        break
                    text = data.decode("utf-8", "replace").rstrip("\r\n")
                    if text == ".":
                        complete = True
                        break
                    lines.append(text[1:] if text.startswith("..") else text)
                if not complete:
                    # The client went away mid-DATA: nothing was
                    # delivered, so nothing is recorded.
                    return
                body = "\n".join(lines)
                _append("smtp.jsonl", json.dumps(
                    {"from": sender, "to": rcpts, "body": body}))
                self._send("250 2.0.0 queued\r\n")
            elif verb in ("RSET", "NOOP"):
                self._send("250 2.0.0 ok\r\n")
            elif verb == "QUIT":
                self._send("221 2.0.0 bye\r\n")
                return
            else:
                self._send("502 5.5.2 unknown\r\n")


# ── LLM stub ─────────────────────────────────────────────────────────


class LlmHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw)
        except ValueError:
            req = {}
        tool = ((req.get("tool_choice") or {}).get("name")) or ""
        domain = ""
        try:
            content = req["messages"][0]["content"]
            domain = json.loads(content).get("domain_requested", "")
        except (KeyError, IndexError, TypeError, ValueError):
            pass
        _append("llm.jsonl", json.dumps({
            "path": self.path,
            "tool": tool,
            "x_api_key": self.headers.get("x-api-key", ""),
            "domain": domain,
        }))
        if tool == "decide":
            if "deny" in domain:
                args = {"decision": "deny",
                        "reason": f"stub denies {domain}"}
            else:
                args = {"decision": "grant",
                        "reason": f"stub grants {domain}",
                        "ttl_seconds": 600}
        elif tool == "review":
            args = {
                "findings": [{
                    "severity": "low",
                    "title": "e2e stub finding",
                    "detail": "the e2e stub LLM reviewed this window",
                    "recommendation": "none, this is a test",
                }],
                "allowlist_removals": [],
                "baseline_recommendations": [],
            }
        else:
            args = {}
        body = json.dumps({
            "id": "msg_e2e",
            "type": "message",
            "role": "assistant",
            "model": req.get("model", ""),
            "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "id": "toolu_e2e",
                         "name": tool, "input": args}],
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


# ── TLS (passthrough upstream) ───────────────────────────────────────


def serve_tls(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["http/1.1"])
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("0.0.0.0", 443))
    lsock.listen(16)

    def one(conn):
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(10)
                tls.recv(65536)
                body = json.dumps({"passthrough": True}).encode()
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            b"Content-Length: " + str(len(body)).encode()
                            + b"\r\nConnection: close\r\n\r\n" + body)
        except (OSError, ssl.SSLError):
            pass

    while True:
        conn, _ = lsock.accept()
        threading.Thread(target=one, args=(conn,), daemon=True).start()


def main():
    cert, key = sys.argv[1], sys.argv[2]
    os.makedirs(LOG_DIR, exist_ok=True)
    servers = [
        _Server(("127.0.0.1", 3143), ImapHandler),
        _Server(("127.0.0.1", 3025), SmtpHandler),
        ThreadingHTTPServer(("127.0.0.1", 18089), LlmHandler),
    ]
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    serve_tls(cert, key)


if __name__ == "__main__":
    main()
