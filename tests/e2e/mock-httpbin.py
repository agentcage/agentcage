"""Minimal HTTP server that returns 200 JSON for any request.

Used by E2E tests as a stand-in for httpbin.org / example.com so tests
don't depend on external network access.

Stdlib only, so it runs in any stock python image. The harness starts it
in its own container that shares the egress's network namespace and
passes ``127.0.0.1`` as the bind address (see ``start_mock`` in lib.sh).

Usage: mock-httpbin.py [BIND_ADDR]   (default 0.0.0.0; port is always 80)
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys


class Handler(BaseHTTPRequestHandler):
    def _respond(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        body = json.dumps(
            {"ok": True, "path": self.path, "method": self.command}
        )
        self.wfile.write(body.encode())

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def do_PUT(self):
        self._respond()

    def log_message(self, *args):
        pass  # suppress request logging


if __name__ == "__main__":
    bind = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    HTTPServer((bind, 80), Handler).serve_forever()
