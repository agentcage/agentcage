"""Minimal HTTP server that returns 200 JSON for any request.

Used by E2E tests as a stand-in for httpbin.org / example.com so tests
don't depend on external network access.

``GET /ws`` with ``Upgrade: websocket`` is a WebSocket echo instead: each
text message is answered with ``{"echo": <text>, "sha256": <hex>}``, the
digest taken over the bytes as they ARRIVED. The egress redacts a real
secret value back to its placeholder on the way into the cage, so the echo
field alone cannot show that a placeholder was injected on the way out;
the digest (which redaction cannot touch) can.

Stdlib only, so it runs in any stock python image. The harness starts it
in its own container that shares the egress's network namespace and
passes ``127.0.0.1`` as the bind address (see ``start_mock`` in lib.sh).

Usage: mock-httpbin.py [BIND_ADDR]   (default 0.0.0.0; port is always 80)
"""

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import base64
import hashlib
import json
import struct
import sys

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_read_frame(rfile):
    """One client frame: (opcode, payload), or None at EOF."""
    head = rfile.read(2)
    if len(head) < 2:
        return None
    opcode = head[0] & 0x0F
    masked = head[1] & 0x80
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", rfile.read(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", rfile.read(8))[0]
    mask = rfile.read(4) if masked else b"\0\0\0\0"
    data = bytearray(rfile.read(length))
    for i in range(len(data)):
        data[i] ^= mask[i % 4]
    return opcode, bytes(data)


def _ws_frame(opcode, payload):
    """One unmasked server frame (FIN set)."""
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + struct.pack("!H", n)
    else:
        head += bytes([127]) + struct.pack("!Q", n)
    return head + payload


class Handler(BaseHTTPRequestHandler):
    def _respond(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        body = json.dumps(
            {"ok": True, "path": self.path, "method": self.command}
        )
        self.wfile.write(body.encode())

    def _websocket(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode()).digest()
        ).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()
        while True:
            frame = _ws_read_frame(self.rfile)
            if frame is None:
                return
            opcode, payload = frame
            if opcode == 0x8:  # close: answer it and stop
                self.wfile.write(_ws_frame(0x8, payload[:2]))
                self.wfile.flush()
                return
            if opcode == 0x9:  # ping
                self.wfile.write(_ws_frame(0xA, payload))
            elif opcode in (0x1, 0x2):
                reply = json.dumps({
                    "echo": payload.decode("utf-8", "replace"),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }).encode()
                self.wfile.write(_ws_frame(0x1, reply))
            self.wfile.flush()

    def do_GET(self):
        if (self.path.split("?", 1)[0] == "/ws"
                and self.headers.get("Upgrade", "").lower() == "websocket"):
            self.close_connection = True
            self._websocket()
            return
        self._respond()

    def do_POST(self):
        self._respond()

    def do_PUT(self):
        self._respond()

    def log_message(self, *args):
        pass  # suppress request logging


class Server(ThreadingHTTPServer):
    # Threaded so an open WebSocket does not stall every other request;
    # daemon threads so a lingering socket never blocks shutdown.
    daemon_threads = True


if __name__ == "__main__":
    bind = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    Server((bind, 80), Handler).serve_forever()
