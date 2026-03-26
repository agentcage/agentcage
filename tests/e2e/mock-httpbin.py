"""Minimal HTTP server that returns 200 JSON for any request.

Used by E2E tests as a stand-in for httpbin.org / example.com so tests
don't depend on external network access.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json


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
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
