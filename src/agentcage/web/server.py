"""The `agentcage web` HTTP server — stdlib-only, read-only.

A threaded ``http.server`` serving two things on one port:

- ``/api/v1/*`` — JSON panels backed by :mod:`agentcage.web.providers`;
- ``/`` — the single-file static dashboard shipped in ``web/static/``.

Deliberately not a framework: the whole surface is six GET routes, the
project carries no web dependency, and every handler is a two-line glue
between a parsed path and a provider. Extensibility is the panel registry
in ``providers.PANELS`` — the server serves whatever is registered there.

Security posture:

- **Loopback by default.** ``--host 0.0.0.0`` is a deliberate operator
  choice; the CLI warns before serving on a non-loopback interface because
  the API exposes cage inventory (names, domains, traffic metadata).
- **No secret values.** The providers never emit them; this module adds
  `Cache-Control: no-store` + `X-Content-Type-Options: nosniff` so no
  intermediary or browser caches a panel or sniffs it into script.
- **Cage names are regex-validated** inside the providers before any
  filesystem use; a URL like ``/api/v1/cages/../x/secrets`` is rejected
  as a 404 (no traversal surface).
- **GET only.** The web interface is read-only; writes stay in the CLI
  where they are reviewed, audited commands.
"""

from __future__ import annotations

import json
import queue
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import providers

_STATIC_DIR = Path(__file__).parent / "static"

# /api/v1/cages/<name>[/panel] — the name is constrained to the same charset
# the CLI accepts at create time; providers re-validate against state.
_CAGE_ROUTE = re.compile(r"^/api/v1/cages/([a-z0-9][a-z0-9-]{0,62})(?:/(\w+))?$")

# Live variants (SSE) and the HAR download need their own patterns — two
# segments after the name, which _CAGE_ROUTE deliberately doesn't match.
_CAGE_STREAM = re.compile(
    r"^/api/v1/cages/([a-z0-9][a-z0-9-]{0,62})/(traffic|logs)/stream$"
)
_CAGE_HAR = re.compile(
    r"^/api/v1/cages/([a-z0-9][a-z0-9-]{0,62})/capture/har$"
)

_MAX_QUERY_ITEMS = 32  # per repeated query param — a guard, not a feature
_MAX_LIMIT = 1000       # traffic/logs cap; the CLI is unlimited, the API is not
_MAX_HAR_ENTRIES = 5000  # HAR download cap — a full cage export can be huge
_HEARTBEAT_S = 15       # SSE keepalive: detects dead clients, survives proxies

# Panel key → provider function name. Built from PANELS so an
# unregistered panel can never be routed; then "cage" (the detail panel)
# is remapped to cage_detail() — the comprehension would name it
# cage_cage, which doesn't exist.
_PANEL_FN: dict[str, str] = {
    p.key: f"cage_{p.key}" for p in providers.PANELS if p.cage_scoped
}
_PANEL_FN["cage"] = "cage_detail"


class ApiError(Exception):
    """An error with its HTTP status code, raised by routing glue."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class _Handler(BaseHTTPRequestHandler):
    """Routes GET requests; everything else is a 405."""

    # Class-level injection point set by make_server(); keeps the handler
    # pickle-free and lets tests spawn a server against patched providers.
    server_version = "agentcage-web"

    def log_message(self, fmt, *args):  # noqa: N802 — stdlib signature
        # One concise line per request to stderr (matches `run.py`'s
        # monitor style); no default address double-log noise.
        print(f"[web] {self.address_string()} {fmt % args}", flush=True)

    # ── responses ──────────────────────────────────────────

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: dict | list) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    # ── methods ───────────────────────────────────────────

    def do_GET(self):  # noqa: N802 — stdlib signature
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if path.startswith("/api/"):
                self._handle_api(path, parse_qs(parsed.query))
            elif path in ("/", "/index.html"):
                self._handle_static()
            else:
                raise ApiError(404, f"not found: {path}")
        except ApiError as exc:
            self._send_error_json(exc.status, exc.message)
        except providers.CageNotFound as exc:
            self._send_error_json(404, str(exc))
        except providers.LegacyCageError as exc:
            self._send_error_json(409, str(exc))
        except providers.ProviderError as exc:
            self._send_error_json(503, str(exc))
        except Exception as exc:  # noqa: BLE001 — one cage panel must not
            self._send_error_json(500, f"{type(exc).__name__}: {exc}")  # kill the server

    def do_POST(self):  # noqa: N802
        self._send_error_json(405, "the web interface is read-only; "
                            "use the CLI for changes")

    # PUT / DELETE / PATCH / HEAD fall through to the stdlib's 501.

    # ── handlers ──────────────────────────────────────────

    def _handle_static(self) -> None:
        index = _STATIC_DIR / "index.html"
        try:
            body = index.read_bytes()
        except OSError as exc:
            raise ApiError(500, f"dashboard asset missing: {exc}") from exc
        self._send(200, body, "text/html; charset=utf-8")

    def _handle_api(self, path: str, query: dict[str, list[str]]) -> None:
        if path == "/api/v1/health":
            self._send_json(200, {"status": "ok"})
        elif path == "/api/v1/manifest":
            self._send_json(200, {"panels": providers.manifest()})
        elif path == "/api/v1/overview":
            self._send_json(200, providers.overview())
        elif path == "/api/v1/doctor":
            self._send_json(200, providers.doctor())
        else:
            m = _CAGE_HAR.match(path)
            if m:
                self._handle_har_download(m.group(1), query)
                return
            m = _CAGE_STREAM.match(path)
            if m:
                self._handle_stream(m.group(1), m.group(2), query)
                return
            m = _CAGE_ROUTE.match(path)
            if not m:
                raise ApiError(404, f"not found: {path}")
            name, panel = m.group(1), m.group(2)
            self._handle_cage_panel(name, panel or "cage", query)

    def _handle_cage_panel(
        self, name: str, panel: str, query: dict[str, list[str]]
    ) -> None:
        fn_name = _PANEL_FN.get(panel)
        fn = getattr(providers, fn_name, None) if fn_name else None
        if fn is None:
            raise ApiError(404, f"unknown panel: {panel}")

        if panel in ("cage", "secrets", "allowlist", "dns"):
            self._send_json(200, fn(name))
        elif panel == "capture":
            self._send_json(200, fn(
                name,
                limit=self._int_query(query, "limit", default=100,
                                      maximum=_MAX_LIMIT),
            ))
        elif panel == "traffic":
            self._send_json(200, fn(
                name,
                limit=self._int_query(query, "limit", default=100,
                                      maximum=_MAX_LIMIT),
                decisions=self._list_query(query, "decision"),
                hosts=self._list_query(query, "host"),
                methods=self._list_query(query, "method"),
                since=self._one_query(query, "since"),
            ))
        elif panel == "logs":
            services = self._list_query(query, "service")
            unknown = [s for s in services if not re.match(r"^\w+$", s)]
            if unknown:
                raise ApiError(400, f"invalid service: {unknown[0]!r}")
            self._send_json(200, fn(
                name,
                services=services,
                lines=self._int_query(query, "lines", default=50,
                                      maximum=_MAX_LIMIT),
            ))
        else:  # pragma: no cover — guarded by _PANEL_FN
            raise ApiError(404, f"unknown panel: {panel}")

    # ── live streams + HAR download ───────────────────────

    def _handle_stream(
        self, name: str, kind: str, query: dict[str, list[str]]
    ) -> None:
        """SSE live tail — the web twin of `cage audit -f` / `cage logs -f`.

        Providers are resolved BEFORE headers are written, so unknown
        cages / panels still get a clean JSON error; once the event stream
        opens, failures become ``event: error`` frames and the stream ends.
        """
        if kind == "traffic":
            live = providers.follow_traffic(
                name,
                decisions=self._list_query(query, "decision"),
                hosts=self._list_query(query, "host"),
                methods=self._list_query(query, "method"),
            )
        else:
            services = self._list_query(query, "service")
            unknown = [s for s in services if not re.match(r"^\w+$", s)]
            if unknown:
                raise ApiError(400, f"invalid service: {unknown[0]!r}")
            live = providers.follow_logs(
                name,
                services=services,
                lines=self._int_query(query, "lines", default=50,
                                      maximum=_MAX_LIMIT),
            )
        self._stream_sse(live)

    def _stream_sse(self, live: "providers.LiveStream") -> None:
        """Write a LiveStream as text/event-stream until it ends or the
        client disconnects.

        A producer thread iterates the reader subprocess (blocked in
        readline most of the time) and pushes items onto a queue; the
        request thread drains the queue with a timeout so it can emit a
        heartbeat even when the cage is idle — the heartbeat is what
        both keeps proxies from reaping the connection and turns a dead
        client into a write error within one interval. On disconnect the
        request thread closes the LiveStream (terminating the subprocess,
        which is what unblocks the producer) instead of leaking a tail.
        """
        items: "queue.Queue[dict | None]" = queue.Queue()

        def produce() -> None:
            try:
                for item in live:
                    items.put(item)
            except Exception as exc:  # noqa: BLE001 — surface in-stream
                items.put({"event": "error", "message": f"{exc}"})
            finally:
                items.put(None)  # sentinel: reader exited

        producer = threading.Thread(target=produce, daemon=True)
        producer.start()

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        # Bound every write so a wedged client cannot pin a server thread.
        self.connection.settimeout(_HEARTBEAT_S + 5)

        try:
            while True:
                try:
                    item = items.get(timeout=_HEARTBEAT_S)
                except queue.Empty:
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
                    continue
                if item is None:
                    break
                if item.get("event") == "error":
                    self.wfile.write(
                        b"event: error\ndata: "
                        + json.dumps(item).encode("utf-8") + b"\n\n"
                    )
                    break
                self.wfile.write(
                    b"data: " + json.dumps(item).encode("utf-8") + b"\n\n"
                )
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            pass  # client went away — that IS the disconnect path
        finally:
            live.close()
            producer.join(timeout=5)

    def _handle_har_download(
        self, name: str, query: dict[str, list[str]]
    ) -> None:
        """Inbound-view HAR download — the web twin of `cage har`'s default.

        Served as an attachment; the outbound (wire) perspective is not
        reachable here by construction — the provider has no view knob.
        """
        har = providers.cage_har(
            name,
            limit=self._int_query(query, "limit", default=0,
                                  maximum=_MAX_HAR_ENTRIES),
        )
        body = json.dumps(har, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{name}-inbound.har"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    # ── query parsing ─────────────────────────────────────

    @staticmethod
    def _one_query(query: dict[str, list[str]], key: str) -> str | None:
        values = query.get(key) or []
        if len(values) > 1:
            raise ApiError(400, f"repeat ?{key}= is not supported")
        return values[0] if values else None

    @staticmethod
    def _list_query(query: dict[str, list[str]], key: str) -> list[str]:
        values = query.get(key) or []
        if len(values) > _MAX_QUERY_ITEMS:
            raise ApiError(400, f"too many ?{key}= values (max "
                                f"{_MAX_QUERY_ITEMS})")
        return values

    @staticmethod
    def _int_query(
        query: dict[str, list[str]], key: str, *, default: int, maximum: int,
    ) -> int:
        raw = _Handler._one_query(query, key)
        if raw is None:
            return default
        try:
            value = int(raw)
        except ValueError:
            raise ApiError(400, f"?{key}= must be an integer") from None
        if value < 0:
            raise ApiError(400, f"?{key}= must be >= 0")
        return min(value, maximum)


class _ThreadingServer(ThreadingHTTPServer):
    """Threaded server: one cage panel taking seconds (a slow VM grants
    round-trip, a cold journal) must not stall the dashboard's other
    requests. ThreadingHTTPServer already mixes in ThreadingMixIn."""

    daemon_threads = True
    allow_reuse_address = True


def make_server(host: str, port: int) -> _ThreadingServer:
    """Build (without starting) the dashboard server on host:port."""
    return _ThreadingServer((host, port), _Handler)


def serve(host: str, port: int, *, open_browser: bool = False) -> None:
    """Start the dashboard and serve until interrupted.

    Called by `agentcage web`; also usable directly from Python. Binds,
    prints the URL, optionally opens a browser, then blocks.
    """
    server = make_server(host, port)
    bound_host, bound_port = server.server_address[:2]

    # A non-loopback bind exposes cage inventory on the network — say so
    # before the first request, not after something unexpected connects.
    if bound_host not in ("127.0.0.1", "::1", "localhost"):
        print(
            f"[web] WARNING: serving on {bound_host} — the dashboard shows "
            f"cage names, domains, and traffic metadata to anyone who can "
            f"reach {bound_host}:{bound_port}. Prefer 127.0.0.1.",
            flush=True,
        )

    url = f"http://{'localhost' if bound_host in ('::1',) else bound_host}:{bound_port}/"
    print(f"[web] agentcage dashboard listening on {url}", flush=True)
    print("[web] read-only; press Ctrl-C to stop", flush=True)

    if open_browser:
        import webbrowser
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
