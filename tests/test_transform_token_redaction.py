"""Tokens a transform mints are secrets wherever real values are.

A rule with ``transform: google-jwt-bearer`` holds a service-account JSON
as its secret, but what goes on the wire is a short-lived access token
the transform mints from it (``ya29.…``). Redaction used to swap only
each rule's ``real_value`` (the SA JSON) back to the placeholder, so the
minted token stayed in the outbound request snapshot in
``capture.jsonl``, a server echoing it reached the cage and the capture
unredacted, and a cage holding it could send it anywhere.

The contract these tests pin, end to end through the addon with the real
transform (only the token endpoint is mocked):

* the minted token never reaches ``capture.jsonl`` (HTTP request and
  response sides, WebSocket frames): it is replaced by the rule's
  placeholder, as a real value is;
* a server echo of the token is redacted in what the cage receives;
* the token in an outbound request to a host outside ``inject_to`` is
  blocked like a literal real value (to an ``inject_to`` host it is the
  credential the proxy puts there anyway, and passes);
* after a refresh the old token stays redacted while a flow may still
  carry it, and is forgotten once it expires; a config reload neither
  loses the tracked tokens nor re-mints.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import types
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


_PH = "{{GOOGLE_BEARER}}"
_HOST = "gmail.googleapis.com"
_URLOPEN = "transforms.google_jwt_bearer.urllib.request.urlopen"
_TOKEN_A = "ya29.FAKE-MINTED-ACCESS-TOKEN-AAAAAAAAAAAAAAAAAAAA"
_TOKEN_B = "ya29.FAKE-MINTED-ACCESS-TOKEN-BBBBBBBBBBBBBBBBBBBB"


class _StubReverseMode:
    """Real class so ``isinstance(..., ReverseMode)`` works (conftest
    stubs it as a MagicMock instance). No flow here is reverse-mode."""


class _Headers(dict):
    """dict with the Headers methods the addon and the writer use."""

    def items(self, multi=False):  # noqa: ARG002
        return list(super().items())

    def get(self, key, default=None):  # type: ignore[override]
        kl = key.lower()
        for k, v in super().items():
            if k.lower() == kl:
                return v
        return default

    def keys(self):  # type: ignore[override]
        return list(super().keys())


def _sa_json() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return json.dumps({
        "type": "service_account",
        "client_email": "agent@test.iam.gserviceaccount.com",
        "private_key": pem,
    })


@pytest.fixture(scope="module")
def sa_keys() -> tuple[str, str]:
    """Two distinct service-account keys (the second for a re-staged secret)."""
    return _sa_json(), _sa_json()


def _oauth(token: str, expires_in: int = 3600):
    body = json.dumps({"access_token": token, "expires_in": expires_in}).encode()

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return body

    return _Resp()


@pytest.fixture
def clock(monkeypatch):
    """Drive the transform's wall clock (expiry) by hand."""
    import transforms.google_jwt_bearer as gjb

    now = [1_000_000.0]
    fake = types.SimpleNamespace(time=lambda: now[0], monotonic=time.monotonic)
    monkeypatch.setattr(gjb, "time", fake)
    return now


@pytest.fixture
def addon_mod(monkeypatch):
    from agentcage.data.proxy import addon as mod
    monkeypatch.setattr(mod, "ReverseMode", _StubReverseMode)
    return mod


def _rule_cfg(**kw):
    cfg = {
        "env": "GOOGLE_SA_KEY",
        "placeholder": _PH,
        "inject_to": ["googleapis.com"],
        "transform": "google-jwt-bearer",
        "transform_config": {
            "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
        },
    }
    cfg.update(kw)
    return cfg


def _injector(addon_mod, monkeypatch, tmp_path, sa: str, **kw):
    monkeypatch.setenv("AGENTCAGE_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("GOOGLE_SA_KEY", sa)
    inj = addon_mod.SecretInjector()
    inj.configure([_rule_cfg(**kw)])
    assert len(inj.rules) == 1
    return inj


def _addon(addon_mod, injector, tmp_path):
    from capture import CaptureWriter
    addon = addon_mod.Agentcage()
    addon.cfg = {}
    addon.log_allowed = False
    addon.inspectors = []
    addon._rl_rate = 0.0
    addon._rl_burst = 0
    addon._rl_buckets = {}
    addon._audit_file = None
    addon._cap_pending = {}
    addon.injector = injector
    addon._capture = CaptureWriter(
        {"max_body_size": 10485760}, str(tmp_path / "capture.jsonl"))
    return addon


def _flow(*, host=_HOST, path="/gmail/v1/users/me/profile", method="GET",
          headers=None, body=b"", flow_id="flow-1"):
    flow = MagicMock()
    flow.id = flow_id
    flow.metadata = {}
    flow.request.url = f"https://{host}{path}"
    flow.request.host = host
    flow.request.pretty_host = host
    flow.request.host_header = host
    flow.request.path = path
    flow.request.port = 443
    flow.request.method = method
    flow.request.http_version = "HTTP/1.1"
    flow.request.headers = _Headers(dict(headers or {}))
    flow.request.content = body
    flow.request.get_text.side_effect = (
        lambda strict=False: flow.request.content.decode("utf-8", "replace"))
    flow.client_conn.proxy_mode = MagicMock()
    flow.client_conn.sni = host
    flow.client_conn.tls_established = True
    flow.client_conn.address = ("127.0.0.1", 12345)
    flow.response = None
    flow.websocket = None
    return flow


def _respond(flow, *, body=b'{"ok": true}', headers=None, status=200):
    flow.response = MagicMock()
    flow.response.status_code = status
    flow.response.reason = "OK"
    flow.response.http_version = "HTTP/1.1"
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    flow.response.headers = _Headers(h)
    flow.response.content = body
    flow.response.get_text.side_effect = (
        lambda strict=False: flow.response.content.decode("utf-8", "replace"))


def _capture_text(tmp_path) -> str:
    path = tmp_path / "capture.jsonl"
    return path.read_text() if path.exists() else ""


def _entries(tmp_path) -> list[dict]:
    return [json.loads(line) for line in _capture_text(tmp_path).splitlines()]


def _header(snapshot: dict, name: str) -> str:
    return next(v for k, v in snapshot["headers"] if k.lower() == name)


# ── HTTP capture ─────────────────────────────────────────


class TestHttpCapture:
    def test_minted_token_not_in_outbound_request_snapshot(
            self, addon_mod, monkeypatch, tmp_path, sa_keys):
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        addon = _addon(addon_mod, inj, tmp_path)
        flow = _flow(headers={"Authorization": f"Bearer {_PH}"})
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_A)):
            asyncio.run(addon.request(flow))
        # The upstream got the minted token...
        assert flow.request.headers["Authorization"] == f"Bearer {_TOKEN_A}"
        _respond(flow)
        asyncio.run(addon.response(flow))

        # ...the capture only the placeholder, on both perspectives.
        assert _TOKEN_A not in _capture_text(tmp_path)
        [entry] = _entries(tmp_path)
        assert _header(entry["outbound"]["request"], "authorization") == (
            f"Bearer {_PH}")
        assert _header(entry["inbound"]["request"], "authorization") == (
            f"Bearer {_PH}")

    def test_server_echo_of_minted_token_is_redacted(
            self, addon_mod, monkeypatch, tmp_path, sa_keys):
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        addon = _addon(addon_mod, inj, tmp_path)
        flow = _flow(headers={"Authorization": f"Bearer {_PH}"})
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_A)):
            asyncio.run(addon.request(flow))
        _respond(
            flow,
            body=json.dumps({"debug": {"token": _TOKEN_A}}).encode(),
            headers={"X-Echo-Authorization": f"Bearer {_TOKEN_A}"},
        )
        asyncio.run(addon.response(flow))

        # What the cage receives carries the placeholder.
        assert _TOKEN_A.encode() not in flow.response.content
        assert _PH.encode() in flow.response.content
        assert flow.response.headers["X-Echo-Authorization"] == f"Bearer {_PH}"
        # And neither response perspective in the capture holds the token.
        assert _TOKEN_A not in _capture_text(tmp_path)
        [entry] = _entries(tmp_path)
        for side in ("inbound", "outbound"):
            resp = entry[side]["response"]
            assert _PH in resp["body"]
            assert _header(resp, "x-echo-authorization") == f"Bearer {_PH}"

    def test_server_echo_of_real_value_not_in_outbound_response(
            self, addon_mod, tmp_path):
        """The outbound response snapshot was taken before redaction, so a
        server echo of a static rule's real value landed in capture.jsonl
        too (the cage-bound response was redacted, the file was not)."""
        real = "sk-FAKE-STATIC-SECRET-ECHOED-BY-THE-SERVER-0123456789"
        rule_cls = sys.modules[addon_mod.SecretInjector.__module__].InjectionRule
        inj = addon_mod.SecretInjector()
        inj.rules = [rule_cls("API_KEY", "{{API_KEY}}", real,
                              inject_to=["api.example.com"])]
        addon = _addon(addon_mod, inj, tmp_path)
        flow = _flow(host="api.example.com",
                     headers={"Authorization": "Bearer {{API_KEY}}"})
        asyncio.run(addon.request(flow))
        _respond(flow, body=f'{{"you_sent": "{real}"}}'.encode())
        asyncio.run(addon.response(flow))
        assert real not in _capture_text(tmp_path)
        [entry] = _entries(tmp_path)
        assert "{{API_KEY}}" in entry["outbound"]["response"]["body"]


# ── WebSocket capture ────────────────────────────────────


def _ws_flow(**kw):
    kw.setdefault("path", "/socket")
    headers = {"Upgrade": "websocket", "Connection": "Upgrade",
               "Sec-WebSocket-Version": "13"}
    headers.update(kw.pop("headers", {}))
    return _flow(headers=headers, **kw)


def _ws_upgrade(addon, flow, token=_TOKEN_A):
    with patch(_URLOPEN, return_value=_oauth(token)):
        asyncio.run(addon.request(flow))
    _respond(flow, body=b"", status=101, headers={"Upgrade": "websocket"})
    flow.websocket = MagicMock()
    flow.websocket.messages = []
    asyncio.run(addon.response(flow))


def _frame(addon, flow, content: bytes, *, from_client: bool):
    msg = MagicMock()
    msg.content = content
    msg.from_client = from_client
    msg.is_text = True
    flow.websocket.messages.append(msg)
    asyncio.run(addon.websocket_message(flow))
    return msg


class TestWebSocketCapture:
    def test_echoed_minted_token_redacted_in_frame_and_capture(
            self, addon_mod, monkeypatch, tmp_path, sa_keys):
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        addon = _addon(addon_mod, inj, tmp_path)
        flow = _ws_flow(headers={"Authorization": f"Bearer {_PH}"})
        _ws_upgrade(addon, flow)
        got = _frame(addon, flow, f"hello {_TOKEN_A}".encode(),
                     from_client=False)
        # The cage-bound frame is redacted...
        assert got.content == f"hello {_PH}".encode()
        addon.websocket_end(flow)
        # ...and so is everything recorded: the upgrade request's header
        # and the frame.
        assert _TOKEN_A not in _capture_text(tmp_path)
        [entry] = _entries(tmp_path)
        assert entry["ws_messages"][0]["data"] == f"hello {_PH}"
        assert _header(entry["outbound"]["request"], "authorization") == (
            f"Bearer {_PH}")

    def test_minted_token_in_frame_to_foreign_host_blocked(
            self, addon_mod, monkeypatch, tmp_path, sa_keys):
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_A)):
            assert inj.rules[0].transform_fn() == _TOKEN_A
        addon = _addon(addon_mod, inj, tmp_path)
        flow = _ws_flow(host="ws.attacker.example")
        _ws_upgrade(addon, flow)
        sent = _frame(addon, flow, f"exfil {_TOKEN_A}".encode(),
                      from_client=True)
        assert sent.drop.called
        addon.websocket_end(flow)
        assert _TOKEN_A not in _capture_text(tmp_path)
        [entry] = _entries(tmp_path)
        assert entry["decision"] == "blocked"
        assert entry["ws_messages"][0]["data"] == f"exfil {_PH}"


# ── Injection policy ─────────────────────────────────────


class TestPolicy:
    def test_minted_token_to_foreign_host_blocked(
            self, addon_mod, monkeypatch, tmp_path, sa_keys):
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_A)):
            inj.rules[0].transform_fn()
        addon = _addon(addon_mod, inj, tmp_path)
        # The 403 is a stub here (http.Response.make), not serializable.
        addon._capture = None
        flow = _flow(host="collector.attacker.example", method="POST",
                     body=f'{{"stolen": "{_TOKEN_A}"}}'.encode())
        asyncio.run(addon.request(flow))
        assert flow.metadata.get("agentcage_blocked") is True
        result = inj.check_injection_policy(flow)
        assert result.action == "block"
        assert result.severity == "critical"
        assert "GOOGLE_SA_KEY" in result.reason

    def test_blocked_minted_token_not_in_capture(
            self, addon_mod, monkeypatch, tmp_path, sa_keys):
        # The blocked request is captured (both views alike), with the
        # rule's placeholder in place of the token the cage sent.
        def make(status, content=b"", headers=None):
            resp = MagicMock()
            resp.status_code = status
            resp.reason = "Forbidden"
            resp.http_version = "HTTP/1.1"
            resp.headers = _Headers(dict(headers or {}))
            resp.content = content
            return resp

        monkeypatch.setattr(addon_mod.http.Response, "make", make)
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_A)):
            inj.rules[0].transform_fn()
        addon = _addon(addon_mod, inj, tmp_path)
        flow = _flow(host="collector.attacker.example", method="POST",
                     headers={"Authorization": f"Bearer {_TOKEN_A}"},
                     body=f'{{"stolen": "{_TOKEN_A}"}}'.encode())
        asyncio.run(addon.request(flow))
        assert flow.metadata.get("agentcage_blocked") is True

        assert _TOKEN_A not in _capture_text(tmp_path)
        [entry] = _entries(tmp_path)
        assert entry["decision"] == "blocked"
        for view in ("inbound", "outbound"):
            req = entry[view]["request"]
            assert _header(req, "authorization") == f"Bearer {_PH}"
            assert req["body"] == f'{{"stolen": "{_PH}"}}'

    def test_minted_token_in_header_to_foreign_host_blocked(
            self, addon_mod, monkeypatch, tmp_path, sa_keys):
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_A)):
            inj.rules[0].transform_fn()
        flow = _flow(host="evil.example",
                     headers={"Authorization": f"Bearer {_TOKEN_A}"})
        result = inj.check_injection_policy(flow)
        assert result is not None and result.action == "block"

    def test_minted_token_to_inject_to_host_passes(
            self, addon_mod, monkeypatch, tmp_path, sa_keys):
        # The token is the credential the proxy puts on requests to this
        # host anyway; sending it there leaks nothing new.
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_A)):
            inj.rules[0].transform_fn()
        flow = _flow(headers={"Authorization": f"Bearer {_TOKEN_A}"})
        assert inj.check_injection_policy(flow) is None
        assert inj.check_ws_injection_policy(
            _TOKEN_A.encode(), _HOST) is None

    def test_ws_minted_token_to_foreign_host_blocked(
            self, addon_mod, monkeypatch, tmp_path, sa_keys):
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_A)):
            inj.rules[0].transform_fn()
        result = inj.check_ws_injection_policy(
            f"t={_TOKEN_A}".encode(), "evil.example")
        assert result is not None
        assert result.action == "block"
        assert result.severity == "critical"

    def test_redact_to_host_gets_token_redacted_not_blocked(
            self, addon_mod, monkeypatch, tmp_path, sa_keys):
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        inj.redact_to = ["logs.example"]
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_A)):
            inj.rules[0].transform_fn()
        flow = _flow(host="logs.example", method="POST",
                     body=f"token {_TOKEN_A}".encode())
        assert inj.check_injection_policy(flow) is None
        assert inj.inject_request(flow) == ["GOOGLE_SA_KEY"]
        assert flow.request.content == f"token {_PH}".encode()


# ── Refresh, expiry and reload ───────────────────────────


def _response_flow(body: str):
    flow = _flow()
    _respond(flow, body=body.encode())
    return flow


class TestLifetime:
    def test_refresh_redacts_old_and_new_then_drops_old_after_expiry(
            self, addon_mod, monkeypatch, tmp_path, sa_keys, clock):
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        rule = inj.rules[0]
        with patch(_URLOPEN, side_effect=[_oauth(_TOKEN_A, 3600),
                                          _oauth(_TOKEN_B, 3600)]):
            # A flow takes token A just before the refresh window...
            assert rule.transform_fn() == _TOKEN_A
            in_flight = _flow(headers={"Authorization": f"Bearer {_PH}"})
            clock[0] += 3200
            inj.inject_request(in_flight)
            assert in_flight.request.headers["Authorization"] == (
                f"Bearer {_TOKEN_A}")
            # ...and the next one refreshes (300 s margin) to token B.
            clock[0] += 200
            assert rule.transform_fn() == _TOKEN_B

        # Both are still redacted: the in-flight request still carries A.
        assert inj.redact_request(in_flight) == ["GOOGLE_SA_KEY"]
        assert in_flight.request.headers["Authorization"] == f"Bearer {_PH}"
        flow = _response_flow(f"{_TOKEN_A} {_TOKEN_B}")
        inj.redact_response(flow)
        assert flow.response.content == f"{_PH} {_PH}".encode()
        assert inj.redact_ws_content(_TOKEN_A.encode())[0] == _PH.encode()

        # Once A has expired it is forgotten; B is still a secret.
        clock[0] += 201
        flow = _response_flow(f"{_TOKEN_A} {_TOKEN_B}")
        inj.redact_response(flow)
        assert flow.response.content == f"{_TOKEN_A} {_PH}".encode()
        assert inj.check_ws_injection_policy(
            _TOKEN_A.encode(), "evil.example") is None

        # And B goes too once it expires.
        clock[0] += 3600
        flow = _response_flow(_TOKEN_B)
        inj.redact_response(flow)
        assert flow.response.content == _TOKEN_B.encode()

    def test_reload_keeps_transform_and_its_tokens(
            self, addon_mod, monkeypatch, tmp_path, sa_keys, clock):
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_A)) as m:
            assert inj.rules[0].transform_fn() == _TOKEN_A
            # An unchanged rule keeps its transform across a reload: the
            # cached token is still served (no re-mint) and redacted.
            inj.configure([_rule_cfg()])
            assert inj.rules[0].transform_fn() == _TOKEN_A
            assert m.call_count == 1
        assert inj.redact_ws_content(_TOKEN_A.encode())[0] == _PH.encode()

    def test_reload_with_new_secret_keeps_old_token_redacted_until_expiry(
            self, addon_mod, monkeypatch, tmp_path, sa_keys, clock):
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_A, 3600)):
            inj.rules[0].transform_fn()
        # `secret set` re-stages a different SA key: the rule gets a new
        # transform, but token A is still live at the provider and may be
        # in flight, so it stays a secret until it expires.
        monkeypatch.setenv("GOOGLE_SA_KEY", sa_keys[1])
        inj.configure([_rule_cfg()])
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_B, 3600)):
            assert inj.rules[0].transform_fn() == _TOKEN_B
        content, names = inj.redact_ws_content(
            f"{_TOKEN_A} {_TOKEN_B}".encode())
        assert content == f"{_PH} {_PH}".encode()
        assert names == ["GOOGLE_SA_KEY"]
        assert inj.check_ws_injection_policy(
            _TOKEN_A.encode(), "evil.example").action == "block"

        clock[0] += 3601
        inj.configure([_rule_cfg()])  # a later reload prunes it
        content, _ = inj.redact_ws_content(_TOKEN_A.encode())
        assert content == _TOKEN_A.encode()
        assert inj._retired == []

    def test_removed_rule_keeps_its_live_token_redacted(
            self, addon_mod, monkeypatch, tmp_path, sa_keys, clock):
        inj = _injector(addon_mod, monkeypatch, tmp_path, sa_keys[0])
        with patch(_URLOPEN, return_value=_oauth(_TOKEN_A, 3600)):
            inj.rules[0].transform_fn()
        inj.configure([])
        assert inj.rules == []
        flow = _response_flow(f"echo {_TOKEN_A}")
        assert inj.redact_response(flow) == ["GOOGLE_SA_KEY"]
        assert flow.response.content == f"echo {_PH}".encode()
        clock[0] += 3601
        flow = _response_flow(f"echo {_TOKEN_A}")
        assert inj.redact_response(flow) == []
