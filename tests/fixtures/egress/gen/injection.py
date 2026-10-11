"""Record ``tests/fixtures/egress/injection.json``.

Runs the Python egress's ``SecretInjector`` (``secret_injector.py``) and
``google-jwt-bearer`` transform on recorded inputs::

    uv run python tests/fixtures/egress/gen/injection.py

The injector works on HTTP flows of the library the Python egress runs
inside; ``FakeRequest`` / ``FakeResponse`` / ``FakeHeaders`` below give it
the same surface with that library's semantics (read from its source at
the pinned version): one value per distinct header name with duplicates
folded by ``", "``, assignment collapsing duplicates at the first
occurrence, URL assignment re-parsing scheme/host/port/path and
rewriting a ``Host`` header, ``content`` decoding the Content-Encoding
(``gen/get_text.py``). One deliberate difference, from the port plan
(§5.3): a rewritten body is stored identity-encoded with
``Content-Encoding`` removed (the library re-compressed it).

Sections: ``cases`` (one injector operation each), ``configure`` (config
plus staged secrets → resolved rules) and ``transform`` (the JWT-bearer
transform's config errors and its exact token request for a fixed key
and clock).
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import random
import re
import sys
import tempfile
import time
import types
import urllib.parse
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(ROOT), str(ROOT / "src"),
                str(ROOT / "src" / "agentcage" / "data" / "proxy")]
import tests.conftest  # noqa: E402,F401  (stubs the proxy library)

import yaml  # noqa: E402

from secret_injector import InjectionRule, SecretInjector  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "egress_gen_get_text", Path(__file__).with_name("get_text.py"))
get_text = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(get_text)

OUT = Path(__file__).resolve().parent.parent / "injection.json"
enc_bytes, dec_bytes = get_text.enc_bytes, get_text.dec_bytes


# ── The flow surface ─────────────────────────────────────


class FakeHeaders:
    def __init__(self, fields):
        self.fields = [(k, v) for k, v in fields]

    def _all(self, key):
        return [v for k, v in self.fields if k.lower() == key.lower()]

    def keys(self):
        seen, out = set(), []
        for k, _ in self.fields:
            if k.lower() not in seen:
                seen.add(k.lower())
                out.append(k)
        return out

    def values(self):
        return [self[k] for k in self.keys()]

    def __iter__(self):
        return iter(self.keys())

    def __contains__(self, key):
        return bool(self._all(key))

    def __getitem__(self, key):
        values = self._all(key)
        if not values:
            raise KeyError(key)
        return ", ".join(values)

    def get(self, key, default=None):
        return self[key] if key in self else default

    def __setitem__(self, key, value):
        out, done = [], False
        for k, v in self.fields:
            if k.lower() == key.lower():
                if not done:
                    out.append((k, value))
                    done = True
            else:
                out.append((k, v))
        if not done:
            out.append((key, value))
        self.fields = out

    def pop(self, key, default=None):
        value = self.get(key, default)
        self.fields = [(k, v) for k, v in self.fields if k.lower() != key.lower()]
        return value


class _Message:
    def __init__(self, headers, body: bytes):
        self.headers = FakeHeaders(headers)
        self.raw_content = body

    @property
    def content(self) -> bytes:
        return get_text.get_content(self.headers.fields, self.raw_content,
                                    strict=True)

    @content.setter
    def content(self, value: bytes) -> None:
        self.headers.pop("content-encoding")
        self.raw_content = value
        if "transfer-encoding" not in self.headers:
            self.headers["content-length"] = str(len(value))


def _hostport(scheme, host, port):
    default = {"http": 80, "https": 443}.get(scheme)
    return host if default == port else f"{host}:{port}"


_LABEL = re.compile(r"[A-Z\d\-_]{1,63}$", re.IGNORECASE)


def _valid_host(host: str) -> bool:
    if not host or len(host) > 255 or not host.isascii():
        return False
    trimmed = host[:-1] if host.endswith(".") else host
    return all(_LABEL.match(x) for x in trimmed.split("."))


class FakeRequest(_Message):
    def __init__(self, method, scheme, host, port, path, headers, body):
        super().__init__(headers, body)
        self.method, self.scheme = method, scheme
        self._host, self.port, self.path = host, port, path

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, value):
        self._host = value
        if "Host" in self.headers:
            self.headers["Host"] = _hostport(self.scheme, self._host, self.port)

    @property
    def url(self):
        return f"{self.scheme}://{_hostport(self.scheme, self.host, self.port)}{self.path}"

    @url.setter
    def url(self, value):
        # The library's url.parse.
        parsed = urllib.parse.urlparse(value)
        if not parsed.hostname:
            raise ValueError("No hostname given")
        host = parsed.hostname.encode("idna").decode()
        parsed_b = parsed.encode("ascii")
        port = parsed_b.port or (443 if parsed_b.scheme == b"https" else 80)
        full = urllib.parse.urlunparse(
            (b"", b"", parsed_b.path, parsed_b.params, parsed_b.query,
             parsed_b.fragment))
        if not full.startswith(b"/"):
            full = b"/" + full
        if not _valid_host(host):
            raise ValueError("Invalid Host")
        self.scheme = parsed_b.scheme.decode()
        self.host = host
        self.port = port
        self.host = host  # the port setter refreshes Host the same way
        self.path = full.decode()

    def dump(self):
        return {
            "method": self.method, "scheme": self.scheme, "host": self.host,
            "port": self.port, "path": self.path,
            "headers": [list(f) for f in self.headers.fields],
            "body": enc_bytes(self.raw_content),
        }


class FakeResponse(_Message):
    def __init__(self, status, headers, body):
        super().__init__(headers, body)
        self.status = status

    def dump(self):
        return {"status": self.status,
                "headers": [list(f) for f in self.headers.fields],
                "body": enc_bytes(self.raw_content)}


class FakeFlow:
    def __init__(self, request, response=None):
        self.request, self.response = request, response


def make_request(spec) -> FakeRequest:
    return FakeRequest(spec.get("method", "GET"), spec.get("scheme", "https"),
                       spec["host"], spec.get("port", 443),
                       spec.get("path", "/"), spec.get("headers", []),
                       dec_bytes(spec.get("body", "")))


# ── Rules ────────────────────────────────────────────────


def make_rule(spec) -> InjectionRule:
    kw = dict(
        name=spec["name"], placeholder=spec["placeholder"],
        real_value=spec["real_value"],
        inject_to=list(spec.get("inject_to", [])),
        inject_body=spec.get("inject_body", False),
        inject_headers=list(spec.get("inject_headers", [])),
    )
    t = spec.get("transform")
    if t:
        def value(t=t):
            if t.get("fails"):
                raise RuntimeError("transform failed")
            return t["value"]
        kw.update(transform=t["name"], transform_fn=value)
        if t.get("active") is not None:
            kw["transform_values_fn"] = lambda t=t: list(t["active"])
    return InjectionRule(**kw)


def run(case) -> dict:
    inj = SecretInjector()
    inj.rules = [make_rule(r) for r in case["rules"]]
    inj.redact_to = [d.lower() for d in case.get("redact_to", [])]
    op = case["op"]
    out = dict(case)
    try:
        if op == "policy":
            r = inj.check_injection_policy(FakeFlow(make_request(case["request"])))
            out["expect"] = {"verdict": _verdict(r)}
        elif op in ("inject", "redact_request"):
            flow = FakeFlow(make_request(case["request"]))
            fn = inj.inject_request if op == "inject" else inj.redact_request
            names = fn(flow)
            out["expect"] = {"names": names, "request": flow.request.dump()}
        elif op == "redact_response":
            spec = case["response"]
            resp = FakeResponse(spec.get("status", 200), spec.get("headers", []),
                                dec_bytes(spec.get("body", "")))
            flow = FakeFlow(make_request({"host": "api.example.com"}), resp)
            names = inj.redact_response(flow)
            out["expect"] = {"names": names, "response": resp.dump()}
        elif op == "ws_policy":
            r = inj.check_ws_injection_policy(dec_bytes(case["content"]),
                                              case["host"])
            out["expect"] = {"verdict": _verdict(r)}
        elif op == "ws_inject":
            content, names = inj.inject_ws_content(dec_bytes(case["content"]),
                                                   case["host"])
            out["expect"] = {"content": enc_bytes(content), "names": names}
        elif op == "ws_redact":
            content, names = inj.redact_ws_content(dec_bytes(case["content"]))
            out["expect"] = {"content": enc_bytes(content), "names": names}
        elif op == "redact_text":
            text, names = inj.redact_text(case["text"])
            out["expect"] = {"text": text, "names": names}
        elif op == "redact_record":
            out["expect"] = {"record": inj.redact_record(case["record"])}
        elif op == "basic":
            import secret_injector
            value, changed = secret_injector._rewrite_basic_auth(
                case["value"], case["find"], case["replace"])
            out["expect"] = {"value": value if changed else None}
        else:
            raise AssertionError(op)
    except ValueError as e:
        out["expect"] = {"error": type(e).__name__}
    return out


def _verdict(r):
    if r is None:
        return None
    return {"inspector": r.inspector, "action": r.action, "reason": r.reason,
            "severity": r.severity}


# ── Handwritten cases ────────────────────────────────────

H = "api.anthropic.com"
PH = "{{KEY}}"


def rule(name="KEY", ph=PH, real="real-secret", inject_to=("anthropic.com",),
         **kw):
    return {"name": name, "placeholder": ph, "real_value": real,
            "inject_to": list(inject_to), **kw}


def req(host=H, path="/v1/messages", headers=(), body="", **kw):
    if isinstance(body, bytes):
        body = enc_bytes(body)
    return {"host": host, "path": path, "headers": [list(h) for h in headers],
            "body": body, "method": kw.get("method", "POST"),
            "scheme": kw.get("scheme", "https"), "port": kw.get("port", 443)}


SURVEY = [
    "Authorization", "X-Api-Key", "api-key", "apikey", "x-goog-api-key",
    "private-token", "x-auth-token", "x-auth-key", "x-subscription-token",
    "ocp-apim-subscription-key", "dd-api-key", "circle-token",
    "x-algolia-api-key", "fastly-key", "x-figma-token",
    "x-postmark-server-token", "x-shopify-access-token", "X-Honeycomb-Team",
    "X-Custom-Trace", "Cookie", "AUTHORIZATION",
]


def handwritten():
    c = []
    add = c.append
    # Strict injection and the header heuristic.
    for header in SURVEY:
        add({"name": f"inject/strict-header/{header}", "op": "inject",
             "rules": [rule()],
             "request": req(headers=[(header, f"Bearer {PH}")])})
    add({"name": "inject/strict-leaves-url-body-and-plain-headers",
         "op": "inject", "rules": [rule()],
         "request": req(path=f"/v1?key={PH}",
                        headers=[("Authorization", f"Bearer {PH}"),
                                 ("X-Api-Key", PH), ("X-Custom-Trace", PH)],
                        body=f"body with {PH} here")})
    add({"name": "inject/inject-headers-keywordless", "op": "inject",
         "rules": [rule(inject_headers=[" x-honeycomb-team "])],
         "request": req(headers=[("X-Honeycomb-Team", PH)])})
    add({"name": "inject/inject-headers-exact-not-substring", "op": "inject",
         "rules": [rule(inject_headers=["x-honeycomb"])],
         "request": req(headers=[("X-Honeycomb-Team", PH)])})
    add({"name": "inject/unauthorized-domain", "op": "inject",
         "rules": [rule()],
         "request": req(host="evil.example.com",
                        headers=[("Authorization", f"Bearer {PH}")])})
    add({"name": "inject/no-inject-to", "op": "inject",
         "rules": [rule(inject_to=())],
         "request": req(headers=[("Authorization", f"Bearer {PH}")])})
    add({"name": "inject/subdomain", "op": "inject",
         "rules": [rule(inject_to=("ANTHROPIC.com",))],
         "request": req(host="Deep.API.Anthropic.com",
                        headers=[("Authorization", f"Bearer {PH}")])})
    add({"name": "inject/not-a-suffix-label", "op": "inject",
         "rules": [rule(inject_to=("example.com",))],
         "request": req(host="notexample.com",
                        headers=[("Authorization", f"Bearer {PH}")])})
    add({"name": "inject/mixed-rules", "op": "inject",
         "rules": [rule(), rule("OTHER", "{{OTHER}}", "other-secret",
                                ("other.com",))],
         "request": req(headers=[("Authorization", f"Bearer {PH}"),
                                 ("X-Other-Key", "{{OTHER}}")])})
    add({"name": "inject/duplicate-headers-collapse", "op": "inject",
         "rules": [rule()],
         "request": req(headers=[("Authorization", f"Bearer {PH}"),
                                 ("Accept", "a"),
                                 ("authorization", "Basic xyz")])})
    add({"name": "inject/no-rules", "op": "inject", "rules": [],
         "request": req(headers=[("Authorization", f"Bearer {PH}")])})
    # Loose (inject_body) mode.
    add({"name": "inject/body-url-headers", "op": "inject",
         "rules": [rule(inject_body=True)],
         "request": req(path=f"/v1?key={PH}&x=1",
                        headers=[("Host", H), ("X-Custom-Trace", PH)],
                        body=f"body with {PH} here")})
    add({"name": "inject/body-gzip-identity", "op": "inject",
         "rules": [rule(inject_body=True)],
         "request": req(headers=[("Content-Encoding", "gzip"),
                                 ("Content-Length", "99")],
                        body=get_text._gzip(f'{{"k": "{PH}"}}'.encode()))})
    add({"name": "inject/body-chunked-keeps-no-length", "op": "inject",
         "rules": [rule(inject_body=True)],
         "request": req(headers=[("Transfer-Encoding", "chunked")],
                        body=f"x={PH}")})
    add({"name": "inject/body-bad-encoding", "op": "inject",
         "rules": [rule(inject_body=True)],
         "request": req(headers=[("Content-Encoding", "bogus")],
                        body=f"x={PH}")})
    add({"name": "inject/host-placeholder-retargets", "op": "inject",
         "rules": [rule("TENANT", "{{tenant}}", "tenant0a1b2c3d4e5f",
                        ("example.com",), inject_body=True)],
         "request": req(host="{{tenant}}.example.com", path="/v1/data",
                        headers=[("Host", "{{tenant}}.example.com")])})
    add({"name": "inject/host-placeholder-outside-inject-to", "op": "inject",
         "rules": [rule("TENANT", "{{tenant}}", "tenant0a1b2c3d4e5f",
                        ("example.com",), inject_body=True)],
         "request": req(host="{{tenant}}.example.net", path="/v1/data")})
    add({"name": "inject/url-nondefault-port-host-header", "op": "inject",
         "rules": [rule(inject_body=True)],
         "request": req(port=8443, path=f"/x;p?k={PH}#frag",
                        headers=[("Host", f"{H}:8443")])})
    add({"name": "inject/url-empty-query-dropped", "op": "inject",
         "rules": [rule(real="v", inject_body=True)],
         "request": req(path=f"/a;?{PH}=#")})
    add({"name": "inject/url-invalid-after-injection", "op": "inject",
         "rules": [rule("T", "{{t}}", "bad host!", ("example.com",),
                        inject_body=True)],
         "request": req(host="{{t}}.example.com")})
    # Basic auth.
    basic = base64.b64encode(f"x-access-token:{PH}".encode()).decode()
    add({"name": "inject/basic-auth", "op": "inject", "rules": [rule()],
         "request": req(headers=[("Authorization", f"Basic {basic}")])})
    add({"name": "inject/basic-auth-unauthorized", "op": "inject",
         "rules": [rule()],
         "request": req(host="github.com",
                        headers=[("Authorization", f"Basic {basic}")])})
    add({"name": "inject/basic-scheme-case", "op": "inject", "rules": [rule()],
         "request": req(headers=[("Authorization", f"bAsIc  {basic} ")])})
    # Transforms.
    tr = {"name": "google-jwt-bearer", "value": "ya29.minted", "active": None}
    add({"name": "inject/transform-value", "op": "inject",
         "rules": [rule(real='{"sa": "json"}', transform=tr)],
         "request": req(headers=[("Authorization", f"Bearer {PH}")])})
    add({"name": "inject/transform-fails-leaves-placeholder", "op": "inject",
         "rules": [rule(transform=dict(tr, fails=True))],
         "request": req(headers=[("Authorization", f"Bearer {PH}")])})
    # redact_to.
    add({"name": "inject/redact-to-redacts", "op": "inject",
         "rules": [rule(real="user@example.org", inject_to=("api.com",))],
         "redact_to": ["Anthropic.com"],
         "request": req(path="/send?to=user%40example.org",
                        headers=[("X-Trace", "user@example.org")],
                        body="mail user@example.org")})
    add({"name": "inject/redact-to-priority", "op": "inject",
         "rules": [rule()], "redact_to": ["anthropic.com"],
         "request": req(headers=[("Authorization", f"Bearer {PH}")])})

    # Policy.
    add({"name": "policy/placeholder-unauthorized", "op": "policy",
         "rules": [rule()],
         "request": req(host="evil.com",
                        headers=[("Authorization", f"Bearer {PH}")])})
    add({"name": "policy/placeholder-no-inject-to", "op": "policy",
         "rules": [rule(inject_to=())],
         "request": req(headers=[("X-Api-Key", PH)])})
    add({"name": "policy/placeholder-in-basic", "op": "policy",
         "rules": [rule()],
         "request": req(host="github.com",
                        headers=[("Authorization", f"Basic {basic}")])})
    add({"name": "policy/placeholder-in-body", "op": "policy",
         "rules": [rule()], "request": req(host="x.com", body=f"k={PH}")})
    add({"name": "policy/ok-authorized", "op": "policy", "rules": [rule()],
         "request": req(headers=[("Authorization", f"Bearer {PH}")])})
    for where, r in (
        ("body", req(host="evil.com", body="leak real-secret now")),
        ("header", req(host="evil.com", headers=[("X-Data", "real-secret")])),
        ("url", req(host="evil.com", path="/?q=real-secret")),
        ("basic", req(host="evil.com", headers=[(
            "Authorization",
            "Basic " + base64.b64encode(b"u:real-secret").decode())])),
        ("gzip-body", req(host="evil.com",
                          headers=[("Content-Encoding", "gzip")],
                          body=get_text._gzip(b"real-secret"))),
    ):
        add({"name": f"policy/literal-in-{where}", "op": "policy",
             "rules": [rule()], "request": r})
    add({"name": "policy/literal-to-inject-to-allowed", "op": "policy",
         "rules": [rule()], "request": req(body="real-secret")})
    add({"name": "policy/literal-beats-placeholder", "op": "policy",
         "rules": [rule()],
         "request": req(host="evil.com", body=f"real-secret {PH}")})
    add({"name": "policy/redact-to-skips", "op": "policy",
         "rules": [rule()], "redact_to": ["evil.com"],
         "request": req(host="evil.com", body=f"real-secret {PH}")})
    add({"name": "policy/transform-raw-secret-blocked-everywhere",
         "op": "policy", "rules": [rule(real="RAW-SA-KEY-123", transform=tr)],
         "request": req(body="RAW-SA-KEY-123")})
    trm = dict(tr, active=["ya29.minted-token-value"])
    add({"name": "policy/minted-token-foreign-host", "op": "policy",
         "rules": [rule(real="sa-json-0123456789", transform=trm)],
         "request": req(host="evil.com",
                        headers=[("Authorization", "Bearer ya29.minted-token-value")])})
    add({"name": "policy/minted-token-inject-to", "op": "policy",
         "rules": [rule(real="sa-json-0123456789", transform=trm)],
         "request": req(headers=[("Authorization", "Bearer ya29.minted-token-value")])})
    add({"name": "policy/minted-token-percent-encoded", "op": "policy",
         "rules": [rule(real="sa-json-0123456789", transform=dict(
             tr, active=["ya29.minted/token+value=="]))],
         "request": req(host="evil.com",
                        path="/?t=ya29.minted%2Ftoken%2Bvalue%3D%3D")})
    add({"name": "policy/bad-body-encoding", "op": "policy",
         "rules": [rule()],
         "request": req(host="evil.com", headers=[("Content-Encoding", "x")],
                        body="zz")})
    add({"name": "policy/no-rules", "op": "policy", "rules": [],
         "request": req(host="evil.com", body="real-secret")})

    # Request redaction (capture).
    add({"name": "redact_request/everywhere", "op": "redact_request",
         "rules": [rule(real="sk-real-value-1234")],
         "request": req(path="/v1?key=sk-real-value-1234",
                        headers=[("Authorization", "Bearer sk-real-value-1234"),
                                 ("Host", H)],
                        body="x sk-real-value-1234 y")})
    add({"name": "redact_request/basic", "op": "redact_request",
         "rules": [rule()],
         "request": req(headers=[("Authorization", "Basic " + base64.b64encode(
             b"x-access-token:real-secret").decode())])})
    add({"name": "redact_request/longest-first", "op": "redact_request",
         "rules": [rule("SHORT", "{{S}}", "abc"),
                   rule("LONG", "{{L}}", "abcdef")],
         "request": req(body="abcdef abc")})
    add({"name": "redact_request/minted-token", "op": "redact_request",
         "rules": [rule(real="sa-json-0123456789", transform=trm)],
         "request": req(headers=[("Authorization", "Bearer ya29.minted-token-value")])})
    add({"name": "redact_request/placeholder-untouched", "op": "redact_request",
         "rules": [rule()],
         "request": req(headers=[("Authorization", f"Bearer {PH}")])})
    add({"name": "redact_request/gzip-body", "op": "redact_request",
         "rules": [rule()],
         "request": req(headers=[("Content-Encoding", "gzip")],
                        body=get_text._gzip(b"real-secret"))})
    add({"name": "redact_request/gzip-body-untouched", "op": "redact_request",
         "rules": [rule()],
         "request": req(headers=[("Content-Encoding", "gzip")],
                        body=get_text._gzip(b"nothing here"))})

    # Response redaction.
    add({"name": "redact_response/body-and-headers", "op": "redact_response",
         "rules": [rule()],
         "response": {"headers": [["X-Echo", "real-secret"],
                                  ["Location", "https://x/?k=real-secret"]],
                      "body": "echo real-secret"}})
    add({"name": "redact_response/regardless-of-domain",
         "op": "redact_response", "rules": [rule(inject_to=())],
         "response": {"body": "real-secret"}})
    add({"name": "redact_response/no-rules-bad-encoding",
         "op": "redact_response", "rules": [],
         "response": {"headers": [["Content-Encoding", "bogus"]],
                      "body": "real-secret"}})
    add({"name": "redact_response/bad-encoding", "op": "redact_response",
         "rules": [rule()],
         "response": {"headers": [["Content-Encoding", "bogus"]],
                      "body": "real-secret"}})
    add({"name": "redact_response/br-unsupported-stacked",
         "op": "redact_response", "rules": [rule()],
         "response": {"headers": [["Content-Encoding", "gzip"],
                                  ["Content-Encoding", "gzip"]],
                      "body": "x"}})

    # WebSocket.
    add({"name": "ws_inject/authorized", "op": "ws_inject",
         "rules": [rule(inject_body=True)], "host": H,
         "content": f'{{"auth": "{PH}"}}'})
    add({"name": "ws_inject/strict-leaves", "op": "ws_inject",
         "rules": [rule()], "host": H, "content": PH})
    add({"name": "ws_inject/unauthorized", "op": "ws_inject",
         "rules": [rule(inject_body=True)], "host": "evil.com", "content": PH})
    add({"name": "ws_inject/redact-to", "op": "ws_inject",
         "rules": [rule(inject_body=True)], "redact_to": [H],
         "host": H, "content": f"real-secret {PH}"})
    add({"name": "ws_inject/transform", "op": "ws_inject",
         "rules": [rule(inject_body=True, transform=tr)], "host": H,
         "content": PH})
    add({"name": "ws_policy/placeholder-flag", "op": "ws_policy",
         "rules": [rule()], "host": "evil.com", "content": PH})
    add({"name": "ws_policy/literal-block", "op": "ws_policy",
         "rules": [rule()], "host": "evil.com", "content": "real-secret"})
    add({"name": "ws_policy/literal-allowed", "op": "ws_policy",
         "rules": [rule()], "host": H, "content": "real-secret"})
    add({"name": "ws_policy/transform-raw", "op": "ws_policy",
         "rules": [rule(transform=tr)], "host": H, "content": "real-secret"})
    add({"name": "ws_policy/minted", "op": "ws_policy",
         "rules": [rule(real="sa-json-0123456789", transform=trm)],
         "host": "evil.com", "content": "ya29.minted-token-value"})
    add({"name": "ws_policy/redact-to", "op": "ws_policy",
         "rules": [rule()], "redact_to": ["evil.com"], "host": "evil.com",
         "content": "real-secret"})
    add({"name": "ws_redact/longest-first", "op": "ws_redact",
         "rules": [rule("SHORT", "{{S}}", "abc"),
                   rule("LONG", "{{L}}", "abcdef")],
         "content": "abcdef abc"})

    # Records and text.
    add({"name": "redact_record/nested", "op": "redact_record",
         "rules": [rule()],
         "record": {"url": "https://x/?k=real-secret", "n": 3, "ok": True,
                    "none": None, "real-secret": "key stays",
                    "inspectors": [{"reason": "saw real-secret"}],
                    "list": ["real%2Dsecret", "cmVhbC1zZWNyZXQ="]}})
    add({"name": "redact_record/no-rules", "op": "redact_record", "rules": [],
         "record": {"a": "real-secret"}})
    add({"name": "redact_text/names", "op": "redact_text",
         "rules": [rule(), rule("B", "{{B}}", "bbbbbbbb")],
         "text": "real-secret and bbbbbbbb and real-secret"})

    # Basic helper.
    b = base64.b64encode(b"user:secret").decode()
    for name, value, find, replace in (
        ("substitutes", f"Basic {b}", "secret", "XX"),
        ("non-basic", "Bearer abc", "abc", "x"),
        ("invalid-base64", "Basic !!!", "x", "y"),
        ("absent", f"Basic {b}", "nope", "y"),
        ("no-padding", "Basic " + b.rstrip("="), "secret", "XX"),
        ("not-utf8", "Basic " + base64.b64encode(b"\xff:secret").decode(),
         "secret", "x"),
        ("no-space", "Basic", "a", "b"),
        ("whitespace", f"basic \t{b}\x1c ", "user", "u"),
    ):
        add({"name": f"basic/{name}", "op": "basic", "rules": [],
             "value": value, "find": find, "replace": replace})
    return c


# ── Encoded forms ────────────────────────────────────────

_REAL = "sk+FAKE/enc=0123456789&abcdef~ghij"


def _lower_hex(text):
    return re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), text)


def _encodings(value, rng=None):
    q = urllib.parse.quote
    forms = [
        ("literal", value),
        ("quote-upper", q(value, safe="")),
        ("quote-lower", _lower_hex(q(value, safe=""))),
        ("quote-plus", urllib.parse.quote_plus(value, safe="")),
        ("quote-keeps-slash", q(value)),
        ("encodeURIComponent", q(value, safe="!~*'()")),
        ("json", json.dumps(value)[1:-1]),
        ("json-unicode", json.dumps(value, ensure_ascii=True)[1:-1]),
        ("php-json", json.dumps(value)[1:-1].replace("/", "\\/")),
        ("go-json", json.dumps(value)[1:-1].replace("&", "\\u0026")
         .replace("<", "\\u003c").replace(">", "\\u003e")),
        ("json-upper-u", re.sub(r"\\u([0-9a-f]{4})",
                                lambda m: "\\u" + m.group(1).upper(),
                                json.dumps(value)[1:-1])),
    ]
    raw = value.encode()
    for prefix in (b"", b"a", b"ab", b"abc"):
        blob = prefix + raw + b"-tail"
        forms.append((f"b64-std-{len(prefix)}", base64.b64encode(blob).decode()))
        forms.append((f"b64-url-{len(prefix)}",
                      base64.urlsafe_b64encode(blob).decode().rstrip("=")))
        forms.append((f"b64-url-padded-{len(prefix)}",
                      base64.urlsafe_b64encode(blob).decode()))
        forms.append((f"b64-std-unpadded-{len(prefix)}",
                      base64.b64encode(blob).decode().rstrip("=")))
    if rng is not None:
        # A random per-character mix of the escapes.
        chars = []
        for ch in value:
            r = rng.random()
            if ch.isascii() and (ch.isalnum() or ch in "-._"):
                chars.append(ch)
            elif r < 0.3:
                chars.append(q(ch, safe=""))
            elif r < 0.5:
                chars.append(_lower_hex(q(ch, safe="")))
            elif r < 0.7:
                chars.append(json.dumps(ch, ensure_ascii=True)[1:-1])
            else:
                chars.append(ch)
        forms.append(("mixed", "".join(chars)))
    return forms


ALPHABET = ("abcdefXYZ0189-._~+/=&%?# \"\\'!*()<>:;@é日🔑\n\t" + "AAAAaaaa0000")


def encoded_cases():
    c = []
    for form, encoded in _encodings(_REAL):
        for op in ("ws_redact", "redact_text"):
            body = f'{{"echo": "{encoded}", "q": 1}}'
            case = {"name": f"encoded/{op}/{form}", "op": op,
                    "rules": [rule("API_KEY", "{{API_KEY}}", _REAL,
                                   ("api.example.com",))]}
            if op == "ws_redact":
                case["content"] = body
            else:
                case["text"] = body
            c.append(case)
        c.append({"name": f"encoded/policy/{form}", "op": "policy",
                  "rules": [rule("API_KEY", "{{API_KEY}}", _REAL,
                                 ("api.example.com",))],
                  "request": req(host="evil.example.com",
                                 path=f"/x?d={urllib.parse.quote(encoded)}",
                                 body=encoded)})
    for ph in ("{{API_KEY}}", "agentcage:secret:API_KEY:0123456789abcdef0123456789abcdef"):
        c.append({"name": f"encoded/space-plus/{ph[:5]}", "op": "ws_redact",
                  "rules": [rule("API_KEY", ph, "pass phrase with spaces+plus")],
                  "content": "user=a&secret=pass+phrase+with+spaces%2Bplus&x=1"})
    rng = random.Random(20261010)
    for i in range(160):
        n = rng.randint(1, 24)
        value = "".join(rng.choice(ALPHABET) for _ in range(n))
        if not value.strip():
            value = "x" + value
        ph = rng.choice(["{{S}}", "agentcage:secret:S:" + "%032x" % rng.getrandbits(128),
                         "{{a b/c}}"])
        forms = _encodings(value, rng)
        picks = rng.sample(forms, k=min(3, len(forms)))
        filler = ["", "x", "==", "&q=", " ", "AAAA", '"', "ab+/"]
        content = "".join(rng.choice(filler) + e for _, e in picks) + rng.choice(filler)
        rules = [rule("S", ph, value, ("api.example.com",))]
        if rng.random() < 0.3 and len(value) > 2:
            rules.append(rule("T", "{{T}}", value[1:], ("api.example.com",)))
        op = rng.choice(["ws_redact", "redact_text", "ws_policy"])
        case = {"name": f"fuzz/{i:03d}/{op}", "op": op, "rules": rules}
        if op == "redact_text":
            case["text"] = content
        else:
            case["content"] = content
            case["host"] = rng.choice(["api.example.com", "evil.example.com"])
        c.append(case)
    return c


# ── configure ────────────────────────────────────────────


CONFIGURE = [
    ("list-form", """
- env: API_KEY
  placeholder: "{{API_KEY}}"
  inject_to: [Example.COM, api.other.org]
""", {"API_KEY": ("file", "staged-value\n\n")}),
    ("dict-form", """
rules:
  - env: A
    placeholder: "{{A}}"
    inject_body: yes
    inject_headers: [" X-Honeycomb-Team ", 42]
  - env: B
    placeholder: ""
  - env: C
    placeholder: "{{C}}"
  - env: D
    placeholder: "{{D}}"
redact_to: [Mail.Example.org]
""", {"A": ("env", "from-env"), "C": ("file", ""), "D": ("both", "file-wins")}),
    ("empty", "", {}),
    ("unknown-transform", """
- env: SA
  placeholder: "{{SA}}"
  transform: no-such-transform
- env: K
  placeholder: "{{K}}"
  inject_to: [k.example]
""", {"SA": ("file", "{}"), "K": ("file", "kv")}),
]


def configure_cases():
    out = []
    for name, text, secrets in CONFIGURE:
        with tempfile.TemporaryDirectory() as d:
            env = {}
            for key, (where, value) in secrets.items():
                if where in ("file", "both"):
                    Path(d, key).write_text(value)
                if where in ("env", "both"):
                    env[key] = "env-loses" if where == "both" else value
            old = dict(os.environ)
            os.environ.update(env)
            os.environ["AGENTCAGE_SECRETS_DIR"] = d
            try:
                inj = SecretInjector()
                inj.configure(yaml.safe_load(text) or [])
            finally:
                os.environ.clear()
                os.environ.update(old)
        out.append({
            "name": name, "config_yaml": text,
            "staged": {k: v for k, (w, v) in secrets.items() if w != "env"},
            "env": {k: ("env-loses" if w == "both" else v)
                    for k, (w, v) in secrets.items() if w in ("env", "both")},
            "rules": [{
                "name": r.name, "placeholder": r.placeholder,
                "real_value": r.real_value, "inject_to": r.inject_to,
                "inject_body": r.inject_body,
                "inject_headers": r.inject_headers, "transform": r.transform,
            } for r in inj.rules],
            "redact_to": inj.redact_to,
        })
    return out


# ── google-jwt-bearer ────────────────────────────────────


def _key_pem() -> str:
    if OUT.exists():
        old = json.loads(OUT.read_text())
        if "transform" in old:
            return old["transform"]["private_key"]
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()).decode()


def transform_section():
    import transforms.google_jwt_bearer as gjb

    pem = _key_pem()
    email = "agent@test.iam.gserviceaccount.com"
    sa = json.dumps({"type": "service_account", "client_email": email,
                     "private_key": pem})
    errors = []
    for secret, cfg in (
        ("<valid>", "{}"),
        ("<valid>", "scopes: []"),
        ("<valid>", "scopes: [a]"),
        ("<valid>", "scopes: [a]\naudience: http://oauth2.googleapis.com/token"),
        ("<valid>", "scopes: [a]\naudience: https://attacker.example/token"),
        ("<valid>", "scopes: [a]\naudience: https://evil-oauth2.googleapis.com/t"),
        ("<valid>", "scopes: [a]\naudience: https://x.accounts.google.com/t"),
        ("<valid>", "scopes: [a]\naudience: HTTPS://OAUTH2.GOOGLEAPIS.COM/token"),
        ("<valid>", "scopes: [a]\nrefresh_margin: soon"),
        ("<valid>", "scopes: [a]\nmint_rate_per_hour: '7'"),
        ("not json", "scopes: [a]"),
        (json.dumps({"client_email": "x@example.com"}), "scopes: [a]"),
        (json.dumps({"private_key": pem}), "scopes: [a]"),
    ):
        secret_value = sa if secret == "<valid>" else secret
        try:
            gjb.GoogleJwtBearer(secret_value, yaml.safe_load(cfg) or {})
            error = None
        except gjb.TransformError as e:
            error = str(e)
            if error.startswith("google-jwt-bearer: SA key is not valid JSON"):
                error = "google-jwt-bearer: SA key is not valid JSON"
        except Exception:  # noqa: BLE001
            error = ""
        errors.append({"secret": secret, "config_yaml": cfg, "error": error})

    mints = []
    for cfg, now in (
        ("scopes: [https://www.googleapis.com/auth/gmail.readonly]", 1_700_000_000.75),
        ("scopes: [s1, 's two', 'é']\naudience: https://accounts.google.com/o/oauth2/token",
         1_234_567_890.0),
    ):
        t = gjb.GoogleJwtBearer(sa, yaml.safe_load(cfg))
        captured = {}
        body = json.dumps({"access_token": "ya29.minted", "expires_in": 3600}).encode()

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return body

        def fake_urlopen(request, timeout):
            captured.update(url=request.full_url, body=request.data.decode(),
                            timeout=timeout)
            return _Resp()

        clock = types.SimpleNamespace(time=lambda: now, monotonic=time.monotonic)
        with patch.object(gjb, "time", clock), \
                patch.object(gjb.urllib.request, "urlopen", fake_urlopen):
            assert t.get_value() == "ya29.minted"
        assert captured["timeout"] == 10
        mints.append({"config_yaml": cfg, "now": now, "url": captured["url"],
                      "body": captured["body"]})
    return {"client_email": email, "private_key": pem, "config_errors": errors,
            "mints": mints}


def build():
    return {
        "_comment": (
            "SecretInjector and google-jwt-bearer behaviour, recorded from "
            "the Python egress by gen/injection.py; do not edit by hand. "
            "The private key is a throwaway generated for this corpus."
        ),
        "cases": [run(c) for c in handwritten() + encoded_cases()],
        "configure": configure_cases(),
        "transform": transform_section(),
    }


def main() -> int:
    data = build()
    OUT.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT} ({len(data['cases'])} cases)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
