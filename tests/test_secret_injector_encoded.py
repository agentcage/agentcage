"""Encoded forms of a secret are redacted and policy-checked like its
literal bytes (Phase 0a fix 0a.32).

Redaction swapped each secret's literal bytes for its placeholder and the
policy check looked for those bytes only. A secret reaches the cage, the
capture or the audit log in other spellings, though, each produced by an
ordinary encoder:

- percent-encoded: a server echoing a URL it was sent (an error body, a
  ``Location`` header) quotes it with upper- or lower-case hex, ``+`` for
  a space in a query or form, and leaves different characters alone
  depending on the encoder (Python ``quote`` keeps ``/``, JavaScript
  ``encodeURIComponent`` keeps ``!~*'()``);
- JSON-escaped: PHP's ``json_encode`` writes ``/`` as ``\\/``, Go's
  ``encoding/json`` writes ``&`` as ``\\u0026``, Python's ``json.dumps``
  writes non-ASCII as ``\\uXXXX``;
- base64: an echo service returns the request's ``Authorization: Basic``
  header in its body, and a token can ride in a base64 blob.

None of these spellings matched, so the real value reached the cage (the
whole point of the placeholder is that it never does), ``capture.jsonl``
and the audit sinks, and a cage holding a real value could send it to any
host percent-encoded.
"""

from __future__ import annotations

import base64
import json
import re
from unittest.mock import MagicMock
from urllib.parse import quote, quote_plus, unquote, unquote_plus

import pytest

from secret_injector import InjectionRule, SecretInjector


# A secret with characters each encoder treats differently: base64-ish
# `+ / =`, a query separator `&` and `~`, which some encoders escape.
_REAL = "sk+FAKE/enc=0123456789&abcdef~ghij"
_PH = "{{API_KEY}}"
_HOST = "api.example.com"


def _injector(real: str = _REAL, *, inject_to=(_HOST,), **kw) -> SecretInjector:
    inj = SecretInjector()
    inj.rules = [InjectionRule("API_KEY", _PH, real, inject_to=list(inject_to),
                               **kw)]
    return inj


def _lower_hex(text: str) -> str:
    """*text* with its percent escapes in lower-case hex."""
    return re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), text)


def _php_json(value: str) -> str:
    """The JSON string body PHP's ``json_encode`` writes (``/`` escaped)."""
    return json.dumps(value)[1:-1].replace("/", "\\/")


def _go_json(value: str) -> str:
    """The JSON string body Go's ``encoding/json`` writes (HTML-safe:
    ``&``, ``<`` and ``>`` as ``\\u00XX``)."""
    return (json.dumps(value)[1:-1].replace("&", "\\u0026")
            .replace("<", "\\u003c").replace(">", "\\u003e"))


# (id, encoded form) for every spelling an ordinary encoder produces.
_ENCODED = [
    ("quote-upper", quote(_REAL, safe="")),
    ("quote-lower", _lower_hex(quote(_REAL, safe=""))),
    ("quote-plus", quote_plus(_REAL, safe="")),
    ("quote-keeps-slash", quote(_REAL)),
    ("encodeURIComponent", quote(_REAL, safe="!~*'()")),
    ("php-json", _php_json(_REAL)),
    ("go-json", _go_json(_REAL)),
]


def _recoverable(text: str, secret: str = _REAL) -> bool:
    """Whether *secret* can be read back out of *text* by undoing one of
    the encodings."""
    candidates = [text, unquote(text), unquote_plus(text)]
    # JSON string escapes, \/ included (unicode_escape keeps it).
    candidates.append(
        text.replace("\\/", "/").encode("ascii", "backslashreplace")
        .decode("unicode_escape"))
    return any(secret in c for c in candidates)


def _response_flow(body: bytes = b"", headers=None):
    flow = MagicMock()
    flow.request.url = f"https://{_HOST}/v1/data"
    flow.request.host = _HOST
    flow.request.headers = {}
    flow.request.content = b""
    flow.response = MagicMock()
    flow.response.headers = dict(headers or {})
    flow.response.content = body
    return flow


def _request_flow(url: str, *, host: str = _HOST, headers=None,
                  body: bytes = b""):
    flow = MagicMock()
    flow.request.url = url
    flow.request.host = host
    flow.request.headers = dict(headers or {})
    flow.request.content = body
    flow.response = None
    return flow


# ── Responses to the cage ────────────────────────────────


class TestResponseRedaction:
    @pytest.mark.parametrize("encoded", [e for _, e in _ENCODED],
                             ids=[i for i, _ in _ENCODED])
    def test_encoded_echo_in_body(self, encoded):
        inj = _injector()
        assert encoded != _REAL
        flow = _response_flow(f'{{"error": "bad key", "got": "{encoded}"}}'
                              .encode())
        names = inj.redact_response(flow)
        body = flow.response.content.decode()
        assert names == ["API_KEY"]
        assert not _recoverable(body), body

    @pytest.mark.parametrize("encoded", [e for _, e in _ENCODED],
                             ids=[i for i, _ in _ENCODED])
    def test_encoded_echo_in_header(self, encoded):
        inj = _injector()
        flow = _response_flow(headers={
            "Location": f"https://{_HOST}/v2/data?key={encoded}&q=1"})
        names = inj.redact_response(flow)
        location = flow.response.headers["Location"]
        assert names == ["API_KEY"]
        assert not _recoverable(location), location
        assert location.endswith("&q=1")

    def test_percent_encoded_placeholder_keeps_the_url_valid(self):
        """A percent-encoded secret becomes the placeholder percent-encoded
        the same way (same hex case), so the URL stays a URL and decodes
        to the placeholder."""
        inj = _injector()
        for encoded, ph in (
            (quote(_REAL, safe=""), "%7B%7BAPI_KEY%7D%7D"),
            (_lower_hex(quote(_REAL, safe="")), "%7b%7bAPI_KEY%7d%7d"),
        ):
            flow = _response_flow(headers={
                "Location": f"https://{_HOST}/v2?key={encoded}&q=1"})
            inj.redact_response(flow)
            assert flow.response.headers["Location"] == (
                f"https://{_HOST}/v2?key={ph}&q=1")
            assert unquote(ph) == _PH

    def test_json_escaped_placeholder_keeps_the_json_valid(self):
        inj = _injector()
        body = json.dumps({"got": _REAL}).replace("/", "\\/").encode()
        flow = _response_flow(body)
        inj.redact_response(flow)
        assert json.loads(flow.response.content) == {"got": _PH}

    def test_space_as_plus_in_a_form_body(self):
        real = "pass phrase with spaces+plus"
        inj = _injector(real)
        flow = _response_flow(
            f"user=a&secret={quote_plus(real, safe='')}&x=1".encode())
        inj.redact_response(flow)
        body = flow.response.content.decode()
        assert not _recoverable(body, real), body
        assert body == "user=a&secret=%7B%7BAPI_KEY%7D%7D&x=1"

    def test_non_ascii_json_escape(self):
        """Python's json.dumps writes non-ASCII as \\uXXXX (a surrogate
        pair past the BMP)."""
        real = "clé-secrète-🔑-0123456789"
        inj = _injector(real)
        body = json.dumps({"got": real}).encode()
        assert real.encode() not in body
        flow = _response_flow(body)
        inj.redact_response(flow)
        assert json.loads(flow.response.content) == {"got": _PH}

    def test_basic_credential_echoed_in_body(self):
        """An echo service (``/headers``, ``/anything``) returns the
        injected ``Authorization: Basic`` header in its JSON body; the
        literal match never saw the base64."""
        inj = _injector()
        basic = base64.b64encode(f"x-access-token:{_REAL}".encode()).decode()
        flow = _response_flow(json.dumps(
            {"headers": {"Authorization": f"Basic {basic}"}}).encode())
        inj.redact_response(flow)
        got = json.loads(flow.response.content)["headers"]["Authorization"]
        assert got.startswith("Basic ")
        assert base64.b64decode(got[6:]).decode() == f"x-access-token:{_PH}"

    @pytest.mark.parametrize("prefix", [b"", b"a", b"ab"],
                             ids=["aligned", "shift-1", "shift-2"])
    def test_base64_blob_any_alignment(self, prefix):
        """The secret at any byte offset of a base64 blob, standard or
        URL-safe alphabet, padded or not."""
        inj = _injector()
        raw = prefix + _REAL.encode() + b"-tail"
        for blob in (base64.b64encode(raw),
                     base64.urlsafe_b64encode(raw).rstrip(b"=")):
            flow = _response_flow(b'{"token": "' + blob + b'"}')
            inj.redact_response(flow)
            got = json.loads(flow.response.content)["token"].encode()
            got += b"=" * (-len(got) % 4)
            decoded = base64.urlsafe_b64decode(
                got.replace(b"+", b"-").replace(b"/", b"_"))
            assert decoded == prefix + _PH.encode() + b"-tail"

    def test_unrelated_content_untouched(self):
        inj = _injector()
        body = json.dumps({
            "near": quote(_REAL[:-1], safe=""),
            "blob": base64.b64encode(b"nothing secret in here at all").decode(),
        }).encode()
        flow = _response_flow(body)
        assert inj.redact_response(flow) == []
        assert flow.response.content == body

    def test_minted_token_encoded_echo(self):
        """A token a transform minted is a secret too: its encoded forms
        are redacted like a real value's."""
        token = "ya29.minted/token+value=="
        inj = SecretInjector()
        inj.rules = [InjectionRule(
            "SA", _PH, "underlying-service-account-key", inject_to=[_HOST],
            transform="t", transform_fn=lambda: token,
            transform_values_fn=lambda: [token],
        )]
        flow = _response_flow(
            f'{{"echo": "{quote(token, safe="")}"}}'.encode())
        inj.redact_response(flow)
        assert not _recoverable(flow.response.content.decode(), token)


# ── Requests (capture, redact_to) ────────────────────────


class TestRequestRedaction:
    @pytest.mark.parametrize("encoded", [e for _, e in _ENCODED],
                             ids=[i for i, _ in _ENCODED])
    def test_encoded_value_in_url_and_body(self, encoded):
        inj = _injector()
        flow = _request_flow(f"https://{_HOST}/v1?key={encoded}",
                             body=f"key={encoded}".encode())
        names = inj.redact_request(flow)
        assert names == ["API_KEY"]
        assert not _recoverable(flow.request.url), flow.request.url
        assert not _recoverable(flow.request.content.decode())

    def test_encoded_value_in_header(self):
        inj = _injector()
        flow = _request_flow(f"https://{_HOST}/v1", headers={
            "Referer": f"https://app.example/?k={quote(_REAL, safe='')}"})
        inj.redact_request(flow)
        assert not _recoverable(flow.request.headers["Referer"])


# ── WebSocket frames ─────────────────────────────────────


class TestWebSocketRedaction:
    @pytest.mark.parametrize("encoded", [e for _, e in _ENCODED],
                             ids=[i for i, _ in _ENCODED])
    def test_encoded_echo_in_frame(self, encoded):
        inj = _injector()
        content, names = inj.redact_ws_content(
            f'{{"type": "echo", "data": "{encoded}"}}'.encode())
        assert names == ["API_KEY"]
        assert not _recoverable(content.decode()), content


# ── Audit records ────────────────────────────────────────


class TestRecordRedaction:
    @pytest.mark.parametrize("encoded", [e for _, e in _ENCODED],
                             ids=[i for i, _ in _ENCODED])
    def test_encoded_value_in_record(self, encoded):
        inj = _injector()
        record = inj.redact_record({
            "url": f"https://{_HOST}/v1?key={encoded}",
            "reason": f"suspicious body: {encoded}",
        })
        assert not _recoverable(json.dumps(record)), record
        for value in record.values():
            assert not _recoverable(value), value


# ── Policy: an encoded real value outside inject_to ──────


class TestPolicy:
    @pytest.mark.parametrize("encoded", [e for _, e in _ENCODED],
                             ids=[i for i, _ in _ENCODED])
    def test_encoded_value_in_url_blocked(self, encoded):
        inj = _injector()
        flow = _request_flow(f"https://collector.example/x?d={encoded}",
                             host="collector.example")
        result = inj.check_injection_policy(flow)
        assert result is not None and result.action == "block"
        assert "API_KEY" in result.reason

    @pytest.mark.parametrize("encoded", [e for _, e in _ENCODED],
                             ids=[i for i, _ in _ENCODED])
    def test_encoded_value_in_body_blocked(self, encoded):
        inj = _injector()
        flow = _request_flow("https://collector.example/x",
                             host="collector.example",
                             body=f'{{"d": "{encoded}"}}'.encode())
        result = inj.check_injection_policy(flow)
        assert result is not None and result.action == "block"

    def test_basic_credential_blocked(self):
        inj = _injector()
        basic = base64.b64encode(f"u:{_REAL}".encode()).decode()
        flow = _request_flow("https://collector.example/x",
                             host="collector.example",
                             headers={"Authorization": f"Basic {basic}"})
        result = inj.check_injection_policy(flow)
        assert result is not None and result.action == "block"

    def test_base64_in_body_blocked(self):
        inj = _injector()
        flow = _request_flow(
            "https://collector.example/x", host="collector.example",
            body=b"blob=" + base64.urlsafe_b64encode(b"x" + _REAL.encode()))
        result = inj.check_injection_policy(flow)
        assert result is not None and result.action == "block"

    def test_encoded_value_to_inject_to_host_allowed(self):
        """Like the literal: to a host in inject_to it is the credential
        the egress would inject there anyway."""
        inj = _injector()
        flow = _request_flow(f"https://{_HOST}/v1?key={quote(_REAL, safe='')}")
        assert inj.check_injection_policy(flow) is None

    def test_encoded_value_in_ws_frame_blocked(self):
        inj = _injector()
        result = inj.check_ws_injection_policy(
            f'{{"d": "{quote(_REAL, safe="")}"}}'.encode(), "collector.example")
        assert result is not None and result.action == "block"

    def test_encoded_minted_token_blocked(self):
        token = "ya29.minted/token+value=="
        inj = SecretInjector()
        inj.rules = [InjectionRule(
            "SA", _PH, "underlying-service-account-key", inject_to=[_HOST],
            transform="t", transform_fn=lambda: token,
            transform_values_fn=lambda: [token],
        )]
        flow = _request_flow(
            f"https://collector.example/x?t={quote(token, safe='')}",
            host="collector.example")
        result = inj.check_injection_policy(flow)
        assert result is not None and result.action == "block"
