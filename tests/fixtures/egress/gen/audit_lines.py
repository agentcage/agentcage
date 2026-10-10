"""Record ``tests/fixtures/egress/audit_lines.json`` from the Python egress.

Every case runs through the live addon's audit funnel (``_log``,
``_audit_write``, ``tcp_start``, ``_refuse_peer``) with the clock pinned,
and records the exact line each sink received: stderr, ``audit.jsonl``
and the traffic watcher's ring. The Rust port (``agentcage-egress``,
``src/audit/``) asserts the same file byte for byte.

    uv run python tests/fixtures/egress/gen/audit_lines.py

``tests/test_egress_corpus_audit_lines.py`` re-runs every case against
the Python through :func:`run_case`, so the file cannot drift from the
implementation it was recorded from.
"""

from __future__ import annotations

import collections
import contextlib
import io
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

_ROOT = Path(__file__).resolve().parents[4]
OUT = _ROOT / "tests" / "fixtures" / "egress" / "audit_lines.json"

for _p in (_ROOT / "src", _ROOT / "src" / "agentcage" / "data" / "proxy",
           _ROOT / "tests"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# The test suite's stub of the proxy framework the addon imports at the
# top: the generator runs on the host, without the egress image's deps.
import conftest  # noqa: E402,F401

from agentcage.data.proxy import addon as addon_mod  # noqa: E402
from inspectors.base import InspectionResult  # noqa: E402


def _fixed_clock(parts):
    moment = datetime(*parts, tzinfo=timezone.utc)

    class _Fixed(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ARG003
            return moment

    return _Fixed


def _injector(rules):
    """A real SecretInjector holding *rules* (name, placeholder, value)."""
    inj = addon_mod.SecretInjector()
    rule_cls = sys.modules[addon_mod.SecretInjector.__module__].InjectionRule
    inj.rules = [rule_cls(name=r["name"], placeholder=r["placeholder"],
                          real_value=r["real_value"], inject_to=[])
                 for r in rules]
    inj.redact_to = []
    return inj


def run_case(case: dict) -> dict:
    """Run one case's input through the Python funnel; return what each
    sink received."""
    inp = case["input"]
    kind = case["kind"]
    if kind == "isoformat":
        return {"isoformat": datetime(*inp["parts"],
                                      tzinfo=timezone.utc).isoformat()}

    with tempfile.TemporaryDirectory() as tmp:
        addon = addon_mod.Agentcage()
        ring: collections.deque = collections.deque(maxlen=5000)
        addon._watcher_ring = ring
        addon.log_allowed = bool(inp.get("log_allowed", False))
        audit_path = os.path.join(tmp, "audit.jsonl")
        addon._audit_file = open(audit_path, "a")
        addon._audit_capped = False
        if inp.get("rules"):
            addon.injector = _injector(inp["rules"])
        stderr = io.StringIO()
        saved = addon_mod.datetime
        addon_mod.datetime = _fixed_clock(inp["ts"])
        try:
            with contextlib.redirect_stderr(stderr):
                _emit(addon, kind, inp)
        finally:
            addon_mod.datetime = saved
            addon._audit_file.close()
        with open(audit_path) as f:
            file_lines = f.read().splitlines()
    return {
        "stderr": stderr.getvalue().splitlines(),
        "file": file_lines,
        "ring": [json.dumps(e) for e in ring],
    }


def _emit(addon, kind: str, inp: dict) -> None:
    if kind == "http":
        req = SimpleNamespace(method=inp["method"], host=inp["host"],
                              port=inp["port"], path=inp["path"],
                              url=inp["url"])
        results = [InspectionResult(inspector=r["name"], action=r["action"],
                                    reason=r["reason"],
                                    severity=r["severity"])
                   for r in inp.get("inspectors", [])]
        addon._log(
            SimpleNamespace(request=req), inp["decision"], inp.get("reason"),
            results, direction=inp.get("direction", "outbound"),
            source=inp.get("source", ""),
            secrets_injected=inp.get("secrets_injected") or None,
            secrets_redacted=inp.get("secrets_redacted") or None,
        )
    elif kind == "tcp_bypass_blocked":
        addon._tcp_flow_target = lambda flow: inp["target"]
        addon.tcp_start(SimpleNamespace(server_conn=None, killable=False))
    elif kind == "private_peer_blocked":
        addon._poisoned_peers = set()
        addon._refuse_peer(SimpleNamespace(), inp["host"], inp["peer_ip"],
                           inp["phase"])
    elif kind == "raw":
        addon._audit_write(json.loads(json.dumps(inp["entry"])))
    elif kind == "tcp_target":
        raise AssertionError("tcp_target cases are pure; see run_target")
    else:
        raise AssertionError(f"unknown kind {kind!r}")


def run_target(inp: dict) -> str:
    """``_tcp_flow_target`` for one (sni, peername, address) triple."""
    def addr(v):
        return tuple(v) if v is not None else None
    flow = SimpleNamespace(
        client_conn=SimpleNamespace(sni=inp.get("sni")),
        server_conn=SimpleNamespace(peername=addr(inp.get("peername")),
                                    address=addr(inp.get("address"))),
    )
    return addon_mod.Agentcage._tcp_flow_target(None, flow)


def run(case: dict) -> dict:
    if case["kind"] == "tcp_target":
        return {"target": run_target(case["input"])}
    return run_case(case)


# ── The cases ────────────────────────────────────────────

_TS = [2026, 10, 10, 12, 34, 56, 0]
_TS_US = [2026, 10, 10, 12, 34, 56, 123456]


def _http(cid, **over):
    inp = {
        "ts": _TS,
        "direction": "outbound",
        "method": "GET",
        "host": "api.example.com",
        "port": 443,
        "path": "/v1/models?limit=2",
        "url": "https://api.example.com/v1/models?limit=2",
        "decision": "allowed",
        "reason": None,
        "source": "",
        "secrets_injected": [],
        "secrets_redacted": [],
        "inspectors": [],
        "log_allowed": False,
    }
    inp.update(over)
    return {"id": cid, "kind": "http", "input": inp}


_FLAG = {"name": "secrets", "action": "flag",
         "reason": "possible secret: AWS access key", "severity": "warning"}
_BLOCK = {"name": "domain", "action": "block",
          "reason": "domain not in allowlist: evil.example",
          "severity": "error"}
_REAL = "sk-FAKE-AUDIT-CORPUS-0123456789abcdef"
_PH = "agentcage:secret:API_KEY:0123456789abcdef0123456789abcdef"


def cases() -> list[dict]:
    out: list[dict] = []
    for i, parts in enumerate([
        [2026, 10, 10, 0, 0, 0, 0],
        [2026, 10, 10, 12, 34, 56, 1],
        [2026, 10, 10, 12, 34, 56, 123456],
        [2026, 10, 10, 12, 34, 56, 999999],
        [2024, 2, 29, 23, 59, 59, 500000],
        [1999, 12, 31, 23, 59, 59, 0],
        [2026, 1, 1, 0, 0, 0, 10],
    ]):
        out.append({"id": f"isoformat-{i}", "kind": "isoformat",
                    "input": {"parts": parts}})

    out += [
        _http("allowed-suppressed-goes-to-the-ring-only"),
        _http("allowed-logged-when-log-allowed", log_allowed=True),
        _http("allowed-with-secret-injected-is-always-durable",
              secrets_injected=["API_KEY", "OTHER"]),
        _http("allowed-with-secret-redacted-is-always-durable",
              secrets_redacted=["API_KEY"]),
        _http("flagged-joined-reasons",
              decision="flagged",
              reason="possible secret: AWS access key; high entropy body",
              inspectors=[_FLAG, {**_FLAG, "name": "entropy",
                                  "reason": "high entropy body"}],
              secrets_injected=["API_KEY"]),
        _http("blocked-with-inspectors", decision="blocked",
              host="evil.example", url="https://evil.example/x",
              path="/x", reason=_BLOCK["reason"],
              inspectors=[_FLAG, _BLOCK], ts=_TS_US),
        _http("blocked-without-inspectors", decision="blocked",
              reason="rate limit exceeded"),
        _http("inbound-with-source", direction="inbound", method="POST",
              host="10.89.0.2", port=18789, url="http://10.89.0.2:18789/hook",
              path="/hook", source="10.89.0.1", log_allowed=True),
        _http("inbound-blocked-with-source-and-inspectors",
              direction="inbound", decision="blocked",
              reason="possible secret", source="192.0.2.7",
              inspectors=[{**_FLAG, "action": "block"}]),
        _http("non-ascii-and-escapes", decision="flagged",
              host="xn--caf-dma.example", path="/café?q=\"x\"\\y",
              url="https://xn--caf-dma.example/café?q=\"x\"\\y",
              reason="tab\there, newline\nthere, nul\x00, emoji \U0001f600, "
                     "bmp ☃, del \x7f",
              inspectors=[{**_FLAG, "reason": "snowman ☃"}]),
        _http("ipv6-host", host="2001:db8::1", port=8443,
              url="https://[2001:db8::1]:8443/", path="/",
              decision="blocked", reason="nope"),
        _http("websocket-allowed-reason", method="GET",
              decision="allowed", reason="websocket", log_allowed=True),
        _http("empty-reason-string-and-severities", decision="flagged",
              reason="",
              inspectors=[{**_FLAG, "severity": s} for s in
                          ("debug", "info", "warning", "error", "critical")]),
        _http("redacted-before-every-sink", decision="flagged",
              path=f"/v1?key={_REAL}",
              url=f"https://api.example.com/v1?key={_REAL}",
              reason=f"saw {_REAL} twice: {_REAL}",
              inspectors=[{**_FLAG, "reason": f"echo {_REAL}"}],
              secrets_injected=["API_KEY"],
              rules=[{"name": "API_KEY", "placeholder": _PH,
                      "real_value": _REAL}]),
        _http("redacted-in-the-ring-only-copy",
              path=f"/v1?key={_REAL}",
              url=f"https://api.example.com/v1?key={_REAL}",
              rules=[{"name": "API_KEY", "placeholder": _PH,
                      "real_value": _REAL}]),
    ]

    out += [
        {"id": "tcp-bypass-sni", "kind": "tcp_bypass_blocked",
         "input": {"ts": _TS, "target": "exfil.example"}},
        {"id": "tcp-bypass-addr", "kind": "tcp_bypass_blocked",
         "input": {"ts": _TS_US, "target": "1.1.1.1:443"}},
        {"id": "tcp-bypass-unknown", "kind": "tcp_bypass_blocked",
         "input": {"ts": _TS, "target": "<unknown>"}},
        {"id": "private-peer-connect", "kind": "private_peer_blocked",
         "input": {"ts": _TS, "host": "granted.example",
                   "peer_ip": "169.254.169.254", "phase": "connect"}},
        {"id": "private-peer-connected", "kind": "private_peer_blocked",
         "input": {"ts": _TS_US, "host": "localtest.me",
                   "peer_ip": "::ffff:127.0.0.1", "phase": "connected"}},
    ]

    for i, (sni, peer, addr) in enumerate([
        ("exfil.example", ["1.1.1.1", 443], ["1.1.1.1", 443]),
        (None, ["203.0.113.9", 8443], ["198.51.100.1", 443]),
        ("", None, ["198.51.100.1", 443]),
        (None, None, ["2001:db8::1", 443]),
        (None, None, None),
        (None, ["", 443], None),
    ]):
        out.append({"id": f"tcp-target-{i}", "kind": "tcp_target",
                    "input": {"sni": sni, "peername": peer, "address": addr}})

    out += [
        {"id": "raw-relay-record-gets-ts-appended", "kind": "raw",
         "input": {"ts": _TS_US, "entry": {
             "kind": "relay_start_failed", "relay": "mail",
             "error": "[Errno 98] Address in use"}}},
        {"id": "raw-record-keeps-its-own-ts", "kind": "raw",
         "input": {"ts": _TS, "entry": {
             "ts": "2020-01-01T00:00:00+00:00", "kind": "policy_grant",
             "domain": "example.org", "ttl_seconds": 3600,
             "ratio": 0.5, "big": 12345678901234567890,
             "flag": True, "none": None, "nested": {"a": [1, 2.5, "x"]}}}},
        {"id": "raw-record-redacted-at-any-depth-keys-untouched",
         "kind": "raw",
         "input": {"ts": _TS, "rules": [
             {"name": "API_KEY", "placeholder": _PH, "real_value": _REAL}],
             "entry": {"kind": "relay_upstream_error", "relay": "mail",
                       _REAL: "key stays",
                       "error": f"login failed for {_REAL}",
                       "nested": [{"deep": [f"x{_REAL}y"]}], "n": 3}}},
    ]
    return out


def main() -> None:
    recorded = []
    for case in cases():
        recorded.append({**case, "expected": run(case)})
    doc = {
        "_comment": (
            "Audit lines as the Python egress wrote them: for each case, "
            "the exact line on stderr, in audit.jsonl and in the watcher "
            "ring (json.dumps of the ring entry). Generated by "
            "tests/fixtures/egress/gen/audit_lines.py; asserted by "
            "tests/test_egress_corpus_audit_lines.py and by "
            "rust/agentcage-egress/src/audit/ (corpus test)."
        ),
        "cases": recorded,
    }
    OUT.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {OUT} ({len(recorded)} cases)")


if __name__ == "__main__":
    main()
