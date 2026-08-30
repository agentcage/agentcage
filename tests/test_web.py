"""Tests for the web interface: providers, server, and CLI parity.

The web interface's contract is that it is a *view*, never a capability:
every panel has a CLI twin. These tests pin that contract from three
sides — the provider data layer, the HTTP surface, and the CLI commands
(`overview`, `web`) that mirror the API.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest
from click.testing import CliRunner

import agentcage.state as state
import agentcage.web.providers as providers
from agentcage.cli import main


# ── fixtures ─────────────────────────────────────────────────


CAGE_YAML = """\
name: demo
container:
  image: localhost/demo:latest
domains:
  allow:
    - api.example.com
    - cdn.example.com
  passthrough:
    - relay.example.com
  expires:
    cdn.example.com: 2099-01-01T00:00:00+00:00
secret_injection:
  - env: API_KEY
    placeholder: agentcage:secret:API_KEY:00000000000000000000000000000000
    inject_to: [api.example.com]
"""


class FakeBackend:
    """A Backend-protocol stand-in with canned, assertable answers."""

    def __init__(self, running: dict[str, bool] | None = None):
        self._running = running if running is not None else {
            "cage": True, "egress": True,
        }

    def service_names(self, name):
        return ["cage", "egress"]

    def is_running(self, name, service):
        return self._running.get(service, False)

    def audit_argv(self, name, *, since=None, follow=False):
        return ["audit-reader", name]

    def logs_argv(self, name, services, *, follow=False, lines=0, **kw):
        return ["logs-reader", name, *services, str(lines)]


@pytest.fixture
def demo_cage(patch_state_dirs, tmp_path):
    """One well-formed deployment named 'demo' in redirected state dirs."""
    cfg_path = tmp_path / "demo-cage.yaml"
    cfg_path.write_text(CAGE_YAML)
    state.save_deployment("demo", str(cfg_path))
    state.save_metadata("demo", {
        "agentcage_version": "0.34.0",
        "lifecycle": "service",
        "scaffold": "openclaw",
    })
    state.save_grants("demo", [{
        "domain": "api.granted.example",
        "granted_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2026-02-01T00:00:00+00:00",
        "reason": "one-off fetch",
        "source": "policy-api",
    }])
    return "demo"


@pytest.fixture
def web_env(monkeypatch, demo_cage):
    """demo_cage + fully stubbed backend readers and secret presence.

    Network-touching surfaces (podman, journalctl) are stubbed so the
    suite runs on a bare CI host; the stubbed seams are exactly the ones
    the Backend protocol and Podman wrapper define, so the assertions
    still exercise the real provider logic around them.
    """
    audit_lines = [
        {"ts": "2026-01-01T00:00:01+00:00", "direction": "outbound",
         "method": "GET", "host": "api.example.com", "path": "/v1/things",
         "decision": "allowed", "reason": "", "inspectors": []},
        {"ts": "2026-01-01T00:00:02+00:00", "direction": "outbound",
         "method": "POST", "host": "evil.example", "path": "/",
         "decision": "blocked", "reason": "not in allowlist",
         "inspectors": [{"name": "domain", "severity": "error"}]},
    ]
    monkeypatch.setattr(providers, "get_backend",
                        lambda cfg: FakeBackend())
    monkeypatch.setattr(
        providers, "_secret_names_present",
        lambda name, cfg: {"API_KEY"},
    )
    monkeypatch.setattr(
        providers, "_run_capture",
        lambda argv, **kw: "\n".join(json.dumps(e) for e in audit_lines),
    )
    return {"audit_lines": audit_lines}


def _make_client():
    """Start a real dashboard server on an ephemeral loopback port.

    Returns a getter ``get(path, method="GET", data=None)`` yielding
    ``(status, body_text, headers)`` — including for error statuses, so
    4xx/5xx responses are assertable like any other.
    """
    from agentcage.web import server as web_server

    httpd = web_server.make_server("127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def get(path: str, *, method: str = "GET", data: bytes | None = None):
        req = urllib.request.Request(base + path, data=data, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as res:
                return res.status, res.read().decode(), dict(res.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), dict(exc.headers)

    return get, httpd


# ── providers ─────────────────────────────────────────────────


class TestProviders:
    def test_manifest_lists_cli_twin_for_every_panel(self):
        for panel in providers.manifest():
            assert panel["cli"].startswith("agentcage "), (
                f"panel {panel['key']!r} must declare a CLI twin"
            )

    def test_overview_running_cage(self, web_env):
        data = providers.overview()
        assert len(data["cages"]) == 1
        row = data["cages"][0]
        assert row["name"] == "demo"
        assert row["status"] == "running (2/2)"
        assert row["isolation"] in ("container", "vm", "apple-container")
        assert row["secrets"] == {"expected": 1, "present": 1, "missing": 0}
        assert row["domains"] == {"mode": "allowlist", "domains": 2}
        assert row["scaffold"] == "openclaw"

    def test_overview_stopped_and_degraded(self, web_env, monkeypatch):
        stopped = FakeBackend(running={"cage": False, "egress": False})
        degraded = FakeBackend(running={"cage": True, "egress": False})
        monkeypatch.setattr(providers, "get_backend", lambda cfg: stopped)
        assert providers.overview()["cages"][0]["status"] == "stopped (0/2)"

        monkeypatch.setattr(providers, "get_backend", lambda cfg: degraded)
        assert providers.overview()["cages"][0]["status"] == "degraded (1/2)"

    def test_overview_broken_config_is_a_row_not_a_crash(
        self, patch_state_dirs, tmp_path,
    ):
        bad = patch_state_dirs._DEPLOYMENTS_DIR / "broken"
        bad.mkdir(parents=True)
        (bad / "cage.yaml").write_text("name: [")
        data = providers.overview()
        assert data["cages"][0]["status"] == "config error"

    def test_overview_legacy_cage_annotated(self, web_env):
        state.save_metadata("demo", {"agentcage_version": "0.21.0"})
        row = providers.overview()["cages"][0]
        assert row["status"] == "legacy v0.21"
        assert row["services"] == []

    def test_cage_detail(self, web_env):
        detail = providers.cage_detail("demo")
        assert detail["name"] == "demo"
        assert detail["status"] == "running (2/2)"
        assert detail["services"] == [
            {"service": "cage", "running": True},
            {"service": "egress", "running": True},
        ]
        assert detail["image"] == "localhost/demo:latest"
        assert detail["ports"] == []

    def test_cage_detail_requires_existing_cage(self, web_env):
        with pytest.raises(providers.CageNotFound):
            providers.cage_detail("nope")

    def test_cage_detail_rejects_bad_name(self, web_env):
        # a traversal-ish name never reaches a filesystem join
        with pytest.raises(providers.CageNotFound):
            providers.cage_detail("../demo")

    def test_legacy_cage_raises(self, web_env):
        state.save_metadata("demo", {"agentcage_version": "0.21.0"})
        with pytest.raises(providers.LegacyCageError):
            providers.cage_detail("demo")

    def test_secrets_names_only(self, web_env):
        data = providers.cage_secrets("demo")
        assert data["expected"] == 1
        assert data["missing"] == 0
        entry = data["secrets"][0]
        assert entry == {"name": "API_KEY", "present": True,
                         "inject_to": ["api.example.com"]}
        # the placeholder must not be in the payload
        assert "placeholder" not in json.dumps(data)
        assert "00000000" not in json.dumps(data)

    def test_secrets_reports_missing(self, web_env, monkeypatch):
        monkeypatch.setattr(providers, "_secret_names_present",
                            lambda name, cfg: set())
        data = providers.cage_secrets("demo")
        assert data["missing"] == 1
        assert data["secrets"][0]["present"] is False

    def test_secrets_fail_soft_when_store_unreachable(self, web_env, monkeypatch):
        def boom(name, cfg):
            raise RuntimeError("no podman on PATH")

        monkeypatch.setattr(providers, "_secret_names_present", boom)
        data = providers.cage_secrets("demo")
        assert data["error"].startswith("secret store unavailable:")
        assert data["secrets"][0] == {"name": "API_KEY", "present": None}

    def test_cage_detail_fail_soft_when_backend_tooling_missing(
        self, web_env, monkeypatch,
    ):
        def boom(cfg):
            raise FileNotFoundError("podman")

        monkeypatch.setattr(providers, "get_backend", boom)
        detail = providers.cage_detail("demo")
        assert detail["status"] == "unknown"
        assert "podman" in detail["detail"]
        assert detail["services"] == []

    def test_allowlist_fail_soft_when_grants_unreadable(
        self, web_env, monkeypatch,
    ):
        def boom(name, cfg):
            raise RuntimeError("limactl failed")

        monkeypatch.setattr(providers, "_grants_overlay", boom)
        data = providers.cage_allowlist("demo")
        assert data["grants"] == []
        assert "grants unavailable" in data["grants_note"]

    def test_allowlist(self, web_env):
        data = providers.cage_allowlist("demo")
        assert data["mode"] == "allowlist"
        assert data["baseline"] == ["api.example.com", "cdn.example.com"]
        by_name = {d["domain"]: d for d in data["domains"]}
        assert by_name["relay.example.com"]["passthrough"] is True
        assert by_name["cdn.example.com"]["expires"] == \
            "2099-01-01T00:00:00+00:00"
        assert by_name["api.example.com"]["expires"] is None
        assert data["grants"][0]["domain"] == "api.granted.example"

    def test_traffic_entries_and_summary(self, web_env):
        data = providers.cage_traffic("demo")
        assert data["count"] == 2
        assert data["summary"]["total"] == 2
        assert data["summary"]["decisions"] == {"allowed": 1, "blocked": 1}
        assert "evil.example" in data["summary"]["top_blocked_hosts"]
        assert data["entries"][0]["host"] == "api.example.com"

    def test_traffic_filters_and_limit(self, web_env):
        data = providers.cage_traffic("demo", decisions=["blocked"])
        assert data["count"] == 1
        assert data["entries"][0]["host"] == "evil.example"
        assert providers.cage_traffic("demo", limit=1)["count"] == 1

    def test_traffic_summary_spans_beyond_limit(self, web_env):
        """?limit= trims displayed entries, never the aggregates —
        `cage audit --summary` counts every matching entry."""
        data = providers.cage_traffic("demo", limit=1)
        assert data["count"] == 1
        assert data["summary"]["total"] == 2
        assert data["summary"]["decisions"] == {"allowed": 1, "blocked": 1}

    def test_traffic_invalid_since(self, web_env):
        with pytest.raises(providers.ProviderError):
            providers.cage_traffic("demo", since="not-a-window")

    def test_logs_tail_and_service_filter(self, web_env, monkeypatch):
        seen = {}

        def fake_run(argv, **kw):
            seen["argv"] = argv
            return "\n".join(f"line-{i}" for i in range(100))

        monkeypatch.setattr(providers, "_run_capture", fake_run)
        data = providers.cage_logs("demo", lines=10)
        assert data["services"] == ["cage", "egress"]
        assert data["lines"] == [f"line-{i}" for i in range(90, 100)]

        providers.cage_logs("demo", services=["egress"], lines=5)
        assert seen["argv"] == ["logs-reader", "demo", "egress", "5"]

    def test_logs_rejects_unknown_service(self, web_env):
        data = providers.cage_logs("demo", services=["bogus"], lines=5)
        assert data["services"] == ["cage", "egress"]  # fell back to all


# ── server ────────────────────────────────────────────────────


class TestServer:
    @pytest.fixture
    def client(self, web_env):
        """A live server + getter; web_env stubs the providers it serves."""
        get, httpd = _make_client()
        yield get
        httpd.shutdown()
        httpd.server_close()

    def test_index_serves_dashboard(self, client):
        status, body, _ = client("/")
        assert status == 200
        assert "<!DOCTYPE html>" in body
        assert "agentcage" in body

    def test_health(self, client):
        status, body, _ = client("/api/v1/health")
        assert status == 200
        assert json.loads(body)["status"] == "ok"

    def test_manifest(self, client):
        status, body, _ = client("/api/v1/manifest")
        panels = json.loads(body)["panels"]
        keys = {p["key"] for p in panels}
        assert keys == {"overview", "cage", "secrets", "allowlist",
                        "traffic", "logs"}

    def test_overview_endpoint(self, client):
        status, body, _ = client("/api/v1/overview")
        assert status == 200
        assert json.loads(body)["cages"][0]["name"] == "demo"

    def test_cage_panel_routes(self, client):
        for panel in ("", "/secrets", "/allowlist", "/traffic", "/logs"):
            status, body, _ = client(f"/api/v1/cages/demo{panel}")
            assert status == 200, panel
            assert json.loads(body)["name"] == "demo"

    def test_traffic_query_params(self, client):
        status, body, _ = client(
            "/api/v1/cages/demo/traffic?decision=blocked&limit=5"
        )
        assert status == 200
        assert json.loads(body)["count"] == 1

    def test_unknown_cage_is_404(self, client):
        status, body, _ = client("/api/v1/cages/nope")
        assert status == 404
        assert "does not exist" in json.loads(body)["error"]

    def test_traversal_name_is_404(self, client):
        # %2F decodes to '/', so this asks for cage '..' — rejected by the
        # name regex before any filesystem use
        status, _, _ = client("/api/v1/cages/..%2Fx")
        assert status == 404

    def test_unknown_panel_is_404(self, client):
        status, body, _ = client("/api/v1/cages/demo/exec")
        assert status == 404

    def test_bad_query_is_400(self, client):
        status, _, _ = client("/api/v1/cages/demo/traffic?limit=abc")
        assert status == 400
        status, _, _ = client("/api/v1/cages/demo/logs?service=bad--name")
        assert status == 400

    def test_write_methods_rejected(self, client):
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            status, body, _ = client("/api/v1/overview",
                                     method=method, data=b"{}")
            assert status in (405, 501), method
        status, body, _ = client("/api/v1/overview", method="POST",
                                 data=b"{}")
        assert "read-only" in json.loads(body)["error"]

    def test_api_responses_are_nostore_and_nosniff(self, client):
        _, _, headers = client("/api/v1/health")
        assert headers["Cache-Control"] == "no-store"
        assert headers["X-Content-Type-Options"] == "nosniff"

    def test_content_types(self, client):
        _, _, api_headers = client("/api/v1/health")
        _, _, html_headers = client("/")
        assert api_headers["Content-Type"].startswith("application/json")
        assert html_headers["Content-Type"].startswith("text/html")

    def test_legacy_cage_is_409(self, client):
        state.save_metadata("demo", {"agentcage_version": "0.21.0"})
        status, body, _ = client("/api/v1/cages/demo")
        assert status == 409
        state.save_metadata("demo", {"agentcage_version": "0.34.0"})


# ── CLI parity ───────────────────────────────────────────────


class TestCliParity:
    def test_overview_human_output(self, web_env):
        result = CliRunner().invoke(main, ["overview"])
        assert result.exit_code == 0
        assert "demo" in result.output
        assert "running" in result.output
        assert "1/1" in result.output          # secrets present/expected

    def test_overview_json_matches_api_payload(self, web_env):
        runner = CliRunner()
        result = runner.invoke(main, ["overview", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload == providers.overview()  # byte-parity with the API

    def test_overview_empty(self, patch_state_dirs):
        result = CliRunner().invoke(main, ["overview"])
        assert result.exit_code == 0
        assert "No cages found" in result.output

    def test_web_help_lists_parity_commands(self):
        result = CliRunner().invoke(main, ["web", "--help"])
        assert result.exit_code == 0
        assert "read-only" in result.output

    def test_web_bad_host_exits(self, monkeypatch):
        result = CliRunner().invoke(
            main, ["web", "--host", "256.256.256.256", "--no-browser"],
        )
        assert result.exit_code == 1
        assert "error" in result.output
