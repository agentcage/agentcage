"""Record the traffic watcher's pure behaviour as a language-neutral corpus.

Writes ``tests/fixtures/egress/watcher.json``: config parsing, the capture
sample reduction, ``dedup_samples``, ``build_digest``, ``_fit_to_budget``,
the token estimate, finding normalisation, the never-revoke floor, the
prompts and tool schema, and scripted capture-tail scenarios. Everything
runs with no RNG (the stride/head-only mode), because the Rust egress uses
a different generator and only the deterministic mode can be compared.

Run: ``uv run python tests/fixtures/egress/gen/watcher.py``.
``tests/test_egress_corpus_watcher.py`` re-checks every case against the
Python with :func:`compute`.
"""

from __future__ import annotations

import base64
import copy
import importlib.abc
import importlib.machinery
import json
import os
import sys
import tempfile
import types
from datetime import datetime
from pathlib import Path

_REPO = Path(__file__).resolve().parents[4]
_PROXY_DIR = _REPO / "src" / "agentcage" / "data" / "proxy"
OUT = _REPO / "tests" / "fixtures" / "egress" / "watcher.json"


class _StubMissing(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Hand an empty module to any import nothing else can satisfy.

    The proxy modules import the interception framework they ran under,
    which is not installed in the test environment; the watcher's pure
    functions never touch it. Installed last on ``sys.meta_path`` so it
    only ever answers for a module that is genuinely absent.
    """

    def find_spec(self, name, path, target=None):
        # Never stand in for the standard library: it probes optional
        # platform modules with try/except ImportError.
        if name.partition(".")[0] in sys.stdlib_module_names:
            return None
        return importlib.machinery.ModuleSpec(name, self, is_package=True)

    def create_module(self, spec):
        mod = types.ModuleType(spec.name)
        mod.__path__ = []
        return mod

    def exec_module(self, module):
        return None


def _import_watcher():
    if str(_PROXY_DIR) not in sys.path:
        sys.path.insert(0, str(_PROXY_DIR))
    # Import in isolation and then forget every module that import added:
    # the pytest run shares sys.modules with suites that install their own
    # stand-ins under the same bare names (``policy_api``, ``watcher``), and
    # must not find these cached ones.
    before = set(sys.modules)
    finder = _StubMissing()
    sys.meta_path.append(finder)
    try:
        import watcher  # noqa: PLC0415  (bare name: the egress convention)
    finally:
        sys.meta_path.remove(finder)
        for name in set(sys.modules) - before:
            del sys.modules[name]
    return watcher


wmod = _import_watcher()


class _Log:
    def __init__(self):
        self.warnings: list[str] = []

    def warn(self, msg):
        self.warnings.append(str(msg))


# ── byte strings in the corpus ─────────────────────────────────────

def _enc_bytes(data: bytes):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return {"b64": base64.b64encode(data).decode("ascii")}


def _dec_bytes(value) -> bytes:
    if isinstance(value, dict):
        return base64.b64decode(value["b64"])
    return value.encode("utf-8")


# ── compute: one case → its expected value ─────────────────────────

def _watcher(proxy_cfg, log=None):
    return wmod.Watcher(proxy_cfg, None, None, lambda e: None,
                        log or _Log(), None, "")


def _config(inp):
    log = _Log()
    w = _watcher(inp["proxy_cfg"], log)
    return {
        "interval_seconds": w._interval,
        "window_seconds": w._window,
        "max_flows": w._max_flows,
        "auto_revoke": w._auto_revoke,
        "dedup_samples": w._dedup,
        "max_digest_tokens": w._max_digest_tokens,
        "context": w._context,
        "provider": w._provider,
        "model": w._model,
        "api_key": str(w.cfg.get("api_key", "") or ""),
        "timeout_seconds": w._timeout,
        "max_tokens": w._llm_max_tokens,
        "base_url": w._llm_base_url,
        "line_cap": w._line_cap,
        "warnings": log.warnings,
    }


def _tail(inp):
    """Replay a scripted sequence of capture-file edits and tail reads."""
    saved = (wmod._CAP_READ_CHUNK, wmod._MAX_CATCHUP_BYTES)
    wmod._CAP_READ_CHUNK = inp["chunk"]
    wmod._MAX_CATCHUP_BYTES = inp["max_catchup"]
    out = []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            cap = os.path.join(tmp, "capture.jsonl")
            log = _Log()
            w = _watcher({"agents": {"watcher": {
                "max_flows": inp["max_flows"],
                "window_seconds": inp["window_seconds"]}}}, log)
            w._capture_path = cap
            w._line_cap = inp["line_cap"]
            now = datetime.fromisoformat(inp["now"])
            for n, step in enumerate(inp["steps"]):
                op = step["op"]
                if op == "write":
                    with open(cap, "wb") as f:
                        f.write(_dec_bytes(step["data"]))
                elif op == "append":
                    with open(cap, "ab") as f:
                        f.write(_dec_bytes(step["data"]))
                elif op == "replace":
                    other = os.path.join(tmp, f"next-{n}.jsonl")
                    with open(other, "wb") as f:
                        f.write(_dec_bytes(step["data"]))
                    os.replace(other, cap)
                elif op == "remove":
                    os.remove(cap)
                elif op == "read":
                    log.warnings.clear()
                    samples, off, fid = w._read_capture(now)
                    batch = {"cap_offset": off, "cap_file_id": fid}
                    if step.get("commit"):
                        w._commit_capture(batch)
                    out.append({
                        "samples": samples,
                        "offset": off,
                        "skipped": w._cap_skipped,
                        "warnings": list(log.warnings),
                    })
                else:  # pragma: no cover — corpus authoring error
                    raise ValueError(op)
    finally:
        wmod._CAP_READ_CHUNK, wmod._MAX_CATCHUP_BYTES = saved
    return out


def compute(case):
    kind, inp = case["kind"], copy.deepcopy(case["input"])
    if kind == "config":
        return _config(inp)
    if kind == "redact_headers":
        return wmod._redact_headers(inp["headers"])
    if kind == "excerpt_body":
        return wmod._excerpt_body(inp["body"], inp["encoding"])
    if kind == "sample_capture":
        return wmod._sample_capture(inp["entry"], inp.get("host_hint", ""))
    if kind == "template_path":
        return wmod._template_path(inp["path"])
    if kind == "dedup_samples":
        return wmod.dedup_samples(inp["samples"], inp["max_bodies"])
    if kind == "est_tokens":
        return wmod._est_tokens(inp["obj"])
    if kind == "fit_to_budget":
        return wmod._fit_to_budget(inp["samples"], inp["budget"],
                                   inp["overhead"])
    if kind == "build_digest":
        return wmod.build_digest(**inp)
    if kind == "norm_finding":
        return wmod.Watcher._norm_finding(inp["finding"])
    if kind == "is_never_revoke":
        return wmod.Watcher._is_never_revoke(None, inp["domain"])
    if kind == "system_prompt":
        return _watcher({"agents": {"watcher": {
            "context": inp["context"]}}})._watcher_system_prompt()
    if kind == "review_tool":
        return wmod._REVIEW_TOOL
    if kind == "tail":
        return _tail(inp)
    raise ValueError(kind)  # pragma: no cover


# ── the cases ──────────────────────────────────────────────────────

def _s(host="api.example.com", method="GET", path="/", ts="t",
       decision="allowed", status=200, body=None, size=0, **extra):
    d = {"ts": ts, "host": host, "method": method, "path": path,
         "decision": decision, "response_status": status,
         "request_body_size": size, "direction": "outbound",
         "inspectors": []}
    if body is not None:
        d["request_body_excerpt"] = body
    d.update(extra)
    return d


def _cap_entry(host, ts, body="", encoding=None, **over):
    e = {
        "ts": ts, "flow_id": "f-" + host, "direction": "outbound",
        "decision": "allowed", "host": host, "method": "POST",
        "path": "/v1/x?key=agentcage:secret:K:ab", "inspectors": [],
        "inbound": {
            "request": {"method": "POST",
                        "url": f"https://{host}/v1/x?key=agentcage:secret:K:ab",
                        "headers": [["Content-Type", "application/json"]],
                        "body": body, "bodyEncoding": encoding,
                        "bodySize": len(body)},
            "response": {"status": 200,
                         "headers": [["Set-Cookie", "s=1"], ["Server", "x"]],
                         "body": "ok", "bodySize": 2},
        },
        "outbound": {"request": {"body": "real-secret-on-the-wire",
                                 "bodySize": 23},
                     "response": {}},
    }
    e.update(over)
    return e


def _line(obj) -> str:
    return json.dumps(obj) + "\n"


def cases():
    out = []

    def add(kind, name, **inp):
        out.append({"kind": kind, "name": name, "input": inp})

    # config
    base = {"enable": True, "provider": "openai", "model": "m",
            "api_key": "env:WATCHKEY"}
    add("config", "defaults", proxy_cfg={"agents": {"watcher": dict(base)}})
    add("config", "empty_document", proxy_cfg={})
    add("config", "explicit_values", proxy_cfg={
        "agents": {"watcher": {**base, "interval_seconds": 120,
                               "window_seconds": 600, "max_flows": 50,
                               "auto_revoke": False, "dedup_samples": False,
                               "max_digest_tokens": 2000,
                               "context": "  runs the test suite  \n",
                               "timeout_seconds": 12.5, "max_tokens": 1024,
                               "base_url": "https://llm.example/v1///"}},
        "capture": {"max_body_size": 50 * 1024 * 1024}})
    add("config", "floors_and_ceilings", proxy_cfg={
        "agents": {"watcher": {**base, "interval_seconds": 5,
                               "window_seconds": 999999, "max_flows": 3,
                               "max_digest_tokens": -5}},
        "capture": {"max_body_size": 1024}})
    add("config", "window_floor", proxy_cfg={
        "agents": {"watcher": {"window_seconds": 0.25}}})
    add("config", "numeric_strings_and_bools", proxy_cfg={
        "agents": {"watcher": {"interval_seconds": "600",
                               "max_flows": "75.9", "window_seconds": True,
                               "timeout_seconds": " 7 ",
                               "max_digest_tokens": 1234.9}},
        "capture": {"max_body_size": "2048"}})
    add("config", "non_numbers_warn", proxy_cfg={
        "agents": {"watcher": {"interval_seconds": "abc",
                               "max_flows": [1], "window_seconds": {"a": 1},
                               "timeout_seconds": "", "max_tokens": None}},
        "capture": {"max_body_size": "big"}})
    add("config", "non_bool_flags_warn", proxy_cfg={
        "agents": {"watcher": {"auto_revoke": "false",
                               "dedup_samples": 0}}})
    add("config", "non_string_context", proxy_cfg={
        "agents": {"watcher": {"context": ["a", "b"]}}})
    add("config", "long_context_cut", proxy_cfg={
        "agents": {"watcher": {"context": "é" * 5000}}})
    add("config", "scalar_llm_fields_are_stringified", proxy_cfg={
        "agents": {"watcher": {"provider": "OpenAI", "model": 4,
                               "api_key": False, "base_url": 0}}})
    add("config", "capture_null_body", proxy_cfg={
        "capture": {"max_body_size": None}})
    add("config", "capture_float_body", proxy_cfg={
        "capture": {"max_body_size": 12000000.7}})

    # redact_headers
    add("redact_headers", "by_name", headers=[
        ["Authorization", "Bearer x"], ["content-type", "application/json"],
        ["Cookie", "a=b"], ["X-Api-Key", "k"], ["x-amz-security-token", "t"],
        ["X-Authorization-Hint", "keep"], ["Private-Token", "p"]])
    add("redact_headers", "malformed_items_skipped", headers=[
        ["only-name"], "str", None, ["A", 1, "extra"], [2, None]])
    add("redact_headers", "none", headers=None)

    # excerpt_body
    add("excerpt_body", "empty", body="", encoding=None)
    add("excerpt_body", "null", body=None, encoding=None)
    add("excerpt_body", "short", body="hello", encoding=None)
    add("excerpt_body", "exactly_cap", body="a" * 512, encoding=None)
    add("excerpt_body", "over_cap", body="b" * 513, encoding=None)
    add("excerpt_body", "code_points_not_bytes", body="é" * 600,
        encoding=None)
    add("excerpt_body", "astral", body="\U0001F600" * 520, encoding=None)
    add("excerpt_body", "base64", body="c2stcmVhbC1zZWNyZXQ=",
        encoding="base64")
    add("excerpt_body", "non_string_body", body={"a": [1, 2.5, None]},
        encoding="utf-8")
    add("excerpt_body", "zero_is_falsy", body=0, encoding=None)

    # template_path
    for name, p in [("plain", "/v1/x"), ("ids", "/repos/x/1234/y/56"),
                    ("hash", "/objects/deadbeefcafe1234"),
                    ("hash_upper", "/o/DEADBEEFCAFE/z"),
                    ("short_hex_is_number", "/o/abc123/z"),
                    ("hex_in_word", "/o/xdeadbeefcafe1/z"),
                    ("mixed", "/a1b2c3d4e5/9"), ("none", None),
                    ("long", "/p" * 200), ("unicode_digits", "/x/٣٤")]:
        add("template_path", name, path=p)

    # sample_capture
    add("sample_capture", "full_entry", entry=_cap_entry(
        "api.example.com", "2026-01-01T00:00:00+00:00",
        body='{"token": "agentcage:secret:API_TOKEN:abcd"}',
        inspectors=[{"name": "secrets", "severity": "warning",
                     "reason": "r" * 300, "action": "flag"}, "junk"]))
    add("sample_capture", "base64_body", entry=_cap_entry(
        "h.example", "t", body="c2stcmVhbC1zZWNyZXQ=", encoding="base64"))
    add("sample_capture", "long_body", entry=_cap_entry(
        "h.example", "t", body="z" * 900))
    add("sample_capture", "no_inbound_url_strips_query", entry={
        "ts": "t", "host": "h", "path": "/search?key=sk-real",
        "method": "GET", "inbound": {"request": {}, "response": {}}})
    add("sample_capture", "bare_entry_with_hint", entry={},
        host_hint="hint.example")
    add("sample_capture", "method_from_inbound", entry={
        "inbound": {"request": {"method": "PUT", "url": "/rel?x=1#frag"}}})
    add("sample_capture", "url_shapes", entry={
        "inbound": {"request": {"url": "https://h.example:8443/a/b;p?q=1&r=2#f"}}})
    add("sample_capture", "url_without_scheme", entry={
        "inbound": {"request": {"url": "h.example/a?b"}}})
    add("sample_capture", "url_bad_ipv6_falls_back", entry={
        "path": "/fallback?secret=1",
        "inbound": {"request": {"url": "https://[::1/x?y"}}})
    add("sample_capture", "url_bracketed_ipv4_falls_back", entry={
        "path": "/fb?q",
        "inbound": {"request": {"url": "http://[127.0.0.1]/x?y"}}})
    add("sample_capture", "url_bracketed_ipv6_ok", entry={
        "inbound": {"request": {"url": "http://[::1]:80/x?y"}}})
    add("sample_capture", "url_controls_stripped", entry={
        "inbound": {"request": {"url": " \x01https://h/a\tb\n?c\r=d"}}})
    add("sample_capture", "url_long_path_cut", entry={
        "inbound": {"request": {"url": "https://h/" + "p" * 300}}})
    add("sample_capture", "non_string_fields", entry={
        "ts": 5, "method": 7, "host": None, "decision": None,
        "inspectors": [{"name": None, "reason": None}, {"reason": 5}],
        "inbound": {"request": {"bodySize": "12"},
                    "response": {"status": "200", "headers": [["a", "b"]] * 20}},
        "outbound": None})
    add("sample_capture", "response_body_excerpt", entry={
        "inbound": {"response": {"body": "y" * 700, "bodyEncoding": None}}})

    # dedup_samples
    add("dedup_samples", "identical_collapse",
        samples=[_s(ts=f"t{i}", size=i) for i in range(5)], max_bodies=3)
    add("dedup_samples", "distinct_shapes", samples=[
        _s(host="a.example"), _s(host="b.example"), _s(method="POST"),
        _s(decision="blocked"), _s(status=404)], max_bodies=3)
    add("dedup_samples", "ids_share_a_shape",
        samples=[_s(path=f"/repos/x/{i}", ts=f"t{i}") for i in range(4)],
        max_bodies=3)
    add("dedup_samples", "status_int_float_equal", samples=[
        _s(status=200), _s(status=200.0), _s(status=True), _s(status=1)],
        max_bodies=3)
    flows = []
    for seq in (1, 2, 3):
        for _ in range(2):
            flows.append(_s(method="POST", path="/graphql",
                            body='{"query":"{viewer}","seq":%d}' % seq))
    flows.append(_s(method="POST", path="/graphql",
                    body='{"exfil_batch":1,"env_dump":{"AWS_KEY":"x"}}'))
    add("dedup_samples", "rarity_keeps_the_late_body", samples=flows,
        max_bodies=3)
    add("dedup_samples", "modal_kept", samples=(
        [_s(method="POST", body='{"ping":1}') for _ in range(6)]
        + [_s(method="POST", body='{"odd":%d}' % i) for i in range(5)]),
        max_bodies=3)
    add("dedup_samples", "identical_bodies_single_field", samples=[
        _s(method="POST", body="same") for _ in range(4)], max_bodies=3)
    add("dedup_samples", "bodies_bounded", samples=[
        _s(method="POST", body=f"b{i}") for i in range(8)], max_bodies=3)
    add("dedup_samples", "zero_max_bodies", samples=[
        _s(body="a"), _s(body="b")], max_bodies=0)
    add("dedup_samples", "falsy_bodies_ignored", samples=[
        _s(body=""), _s(body="x"), _s(), _s(body="y"), _s(body="x")],
        max_bodies=5)
    add("dedup_samples", "missing_keys_and_non_dicts", samples=[
        {}, {"ts": "a"}, "junk", None, {"request_body_size": "7"},
        {"request_body_size": None, "ts": "b"}], max_bodies=3)
    add("dedup_samples", "existing_repeated_key_keeps_position", samples=[
        {"repeated": 9, "ts": "a", "host": "h"}, {"ts": "b", "host": "h"}],
        max_bodies=3)

    # est_tokens
    add("est_tokens", "empty", obj={})
    add("est_tokens", "nested", obj={"a": [1, 2.5, None, True], "b": "x"})
    add("est_tokens", "non_ascii_escaped", obj={"k": "é\U0001F600"})
    add("est_tokens", "list", obj=[_s(), _s(body="abc")])

    # fit_to_budget (stride mode)
    def _b(i, decision="allowed", body=None):
        d = {"ts": f"t{i}", "host": f"h{i}.example", "method": "GET",
             "path": f"/p{i}", "decision": decision, "response_status": 200,
             "request_body_size": 0, "inspectors": []}
        if body:
            d["request_body_excerpt"] = body
        return d

    items = [{"i": i, "decision": "allowed", "pad": "x" * 100}
             for i in range(100)]
    add("fit_to_budget", "spread", samples=items, budget=400, overhead=0)
    add("fit_to_budget", "fits_untouched", samples=items[:3], budget=4000,
        overhead=10)
    add("fit_to_budget", "zero_budget", samples=items[:5], budget=0,
        overhead=0)
    add("fit_to_budget", "pathological_overhead", samples=items[:40],
        budget=300, overhead=500)
    mixed = [_b(i, body="y" * 150) for i in range(60)]
    mixed.insert(20, _b(999, decision="blocked"))
    mixed.insert(40, _b(998, decision="flagged"))
    add("fit_to_budget", "notable_kept", samples=mixed, budget=900,
        overhead=50)
    add("fit_to_budget", "notable_alone_over", samples=[
        _b(i, decision="blocked", body="q" * 200) for i in range(10)],
        budget=200, overhead=0)
    add("fit_to_budget", "one_left", samples=[
        _b(0, decision="blocked", body="q" * 900)], budget=10, overhead=0)
    add("fit_to_budget", "missing_decision_is_notable", samples=[
        {"x": "a" * 100}, {"decision": "allowed", "x": "b" * 100},
        {"decision": "allowed", "x": "c" * 100}], budget=60, overhead=0)

    # build_digest
    entries = [
        {"ts": "2026-01-01T00:00:01+00:00", "decision": "allowed",
         "host": "registry.npmjs.org", "method": "GET",
         "inspectors": [{"name": "entropy"}, {"name": ""}, "x"],
         "secrets_injected": ["API_TOKEN"], "secrets_redacted": ["AWS_KEY"]},
        {"ts": "2026-01-01T00:00:02+00:00", "decision": "blocked",
         "host": "evil.example", "method": "POST",
         "inspectors": [{"name": "entropy"}]},
        {"kind": "policy_introspect", "ts": "t2", "path": "/v1/allowlist"},
        {"kind": "policy_request", "ts": "t3", "domain": "x.example",
         "decision": "denied", "reason": "r" * 400, "decided_by": "decider"},
        {"kind": "watcher_finding", "decision": "flagged"},
        {"kind": "imap_command", "relay": "r", "decision": "allowed"},
        {"kind": "smtp_command", "decision": "blocked", "host": None},
        {"decision": "", "method": "", "host": ""},
        {"decision": "blocked"},
        {"secrets_injected": "AB", "secrets_redacted": {"K": 1}},
    ]
    add("build_digest", "aggregates", audit_entries=entries,
        capture_samples=[], policy_events=[e for e in entries
                                           if str(e.get("kind", "")).startswith("policy_")],
        granted=["b.example", "a.example"], baseline=["z.com", "a.com"],
        max_flows=10)
    hosts = [{"decision": "allowed", "host": f"h{i % 30}.example",
              "method": "GET"} for i in range(200)]
    add("build_digest", "top_hosts_capped_stable_ties", audit_entries=hosts,
        capture_samples=[], policy_events=[], granted=[], baseline=[],
        max_flows=10)
    add("build_digest", "policy_events_capped", audit_entries=[],
        capture_samples=[], policy_events=[{"kind": "policy_request",
                                            "domain": f"d{i}"}
                                           for i in range(205)],
        granted=[], baseline=[], max_flows=10)
    add("build_digest", "samples_newest_keep", audit_entries=[],
        capture_samples=[{"host": f"h{i}"} for i in range(10)],
        policy_events=[], granted=[], baseline=[], max_flows=3)
    add("build_digest", "max_flows_zero_keeps_all", audit_entries=[],
        capture_samples=[{"host": f"h{i}"} for i in range(4)],
        policy_events=[], granted=[], baseline=[], max_flows=0)
    add("build_digest", "dedup_off", audit_entries=[],
        capture_samples=[_s(ts=f"t{i}") for i in range(5)],
        policy_events=[], granted=[], baseline=[], max_flows=200,
        dedup=False)
    add("build_digest", "dedup_on", audit_entries=[],
        capture_samples=[_s(ts=f"t{i}") for i in range(5)],
        policy_events=[], granted=[], baseline=[], max_flows=200)

    def _ev(host, body="x", enc=None):
        return {"ts": "t", "host": host, "method": "POST", "path": "/up",
                "decision": "allowed", "response_status": 200,
                "request_body_size": len(body), "inspectors": [],
                "request_body_binary": enc == "base64",
                "request_body_exceeds_excerpt": len(body) > 512,
                **({"request_body_excerpt": body} if enc != "base64" else {})}

    add("build_digest", "evasion_indicators", audit_entries=[],
        capture_samples=[_ev("files.drop.example", "QUJD", "base64"),
                         _ev("ok.example", "QUJD", "base64"),
                         _ev("DROP.example.", "QUJE", "base64"),
                         _ev("a.example", "p" * 900),
                         _ev("b.example", "short")],
        policy_events=[], granted=["drop.example.", "Other.Example"],
        baseline=["ok.example"], max_flows=200, ring_saturated=True)
    add("build_digest", "distinct_bodies_indicator", audit_entries=[],
        capture_samples=[_s(method="POST", body=f"b{i}") for i in range(6)],
        policy_events=[], granted=[], baseline=[], max_flows=200)
    add("build_digest", "budget_trims", audit_entries=entries[:2],
        capture_samples=[_b(i, body="x" * 200) for i in range(120)],
        policy_events=[], granted=[], baseline=[], max_flows=2000,
        max_digest_tokens=2000)
    flood = [_ev(f"h{i}.example", "q" * 200) for i in range(150)]
    flood.insert(70, {**_b(500, decision="blocked")})
    add("build_digest", "budget_flood_counted_first", audit_entries=[],
        capture_samples=flood, policy_events=[], granted=[], baseline=[],
        max_flows=2000, max_digest_tokens=3000)
    add("build_digest", "budget_fits", audit_entries=[],
        capture_samples=[_b(i) for i in range(3)], policy_events=[],
        granted=[], baseline=[], max_flows=200, max_digest_tokens=8000)

    # norm_finding
    for name, f in [
        ("full", {"severity": "HIGH", "title": "t", "detail": "d",
                  "recommendation": "r", "domain": "x.example"}),
        ("defaults", {}),
        ("bad_severity", {"severity": "urgent"}),
        ("null_severity", {"severity": None, "title": None}),
        ("long_fields", {"title": "t" * 300, "detail": "d" * 3000,
                         "recommendation": "r" * 1500, "domain": "x" * 300}),
        ("non_strings", {"severity": 3, "title": 0, "detail": [1, "a"],
                         "recommendation": {"k": "v"}, "domain": True}),
        ("float_and_none_values", {"title": 1.5, "detail": None,
                                   "recommendation": False}),
    ]:
        add("norm_finding", name, finding=f)

    # is_never_revoke
    for d in ["metadata.google.internal", "x.local", "localhost",
              "metadata.goog", "a.metadata.goog", "Foo.LOCAL.",
              "169-254-169-254.nip.io", "10.0.0.1.sslip.io",
              "93-184-216-34.nip.io", "g.example", "internal.example",
              "10-years.example.com", "localhost.example"]:
        add("is_never_revoke", d, domain=d)

    # prompts and the tool
    add("system_prompt", "no_context", context="")
    add("system_prompt", "with_context", context="payments recon suite")
    add("system_prompt", "whitespace_context", context="  \n ")
    add("review_tool", "review")

    # capture tail scenarios
    now = "2026-01-01T12:00:00+00:00"
    old = "2026-01-01T06:00:00+00:00"
    recent = "2026-01-01T11:59:00+00:00"

    def cl(host, ts=recent, **kw):
        return _line({"ts": ts, "host": host, "direction": "outbound",
                      "decision": "allowed", "method": "GET", "path": "/",
                      "inspectors": [],
                      "inbound": {"request": {"body": "", "bodySize": 1},
                                  "response": {"status": 200, "bodySize": 2}},
                      "outbound": {"request": {}, "response": {}}, **kw})

    def tail(name, steps, *, chunk=8 * 1024 * 1024,
             max_catchup=16 * 8 * 1024 * 1024, line_cap=32 * 1024 * 1024,
             max_flows=100, window=3600):
        add("tail", name, now=now, chunk=chunk, max_catchup=max_catchup,
            line_cap=line_cap, max_flows=max_flows, window_seconds=window,
            steps=steps)

    tail("missing_file", [{"op": "read", "commit": True}])
    tail("first_scan_windows_then_increments", [
        {"op": "write", "data": cl("old.example", old) + cl("new.example")},
        {"op": "read", "commit": True},
        {"op": "append", "data": cl("newer.example", old)},
        {"op": "read", "commit": True},
        {"op": "read", "commit": True},
    ])
    tail("unparseable_and_naive_ts_in_window", [
        {"op": "write", "data": cl("bad.example", "garbage")
         + cl("naive.example", "2026-01-01T11:30:00")
         + cl("nots.example", "") + cl("z.example", "2026-01-01T13:00:00+01:00")},
        {"op": "read", "commit": True},
    ])
    tail("truncation_resets", [
        {"op": "write", "data": cl("a.example") + cl("b.example")},
        {"op": "read", "commit": True},
        {"op": "write", "data": cl("c.example")},
        {"op": "read", "commit": True},
    ])
    first = cl("a.example")
    tail("rotation_by_identity_resets", [
        {"op": "write", "data": first},
        {"op": "read", "commit": True},
        {"op": "replace", "data": cl("b.example")},
        {"op": "read", "commit": True},
    ])
    full = cl("torn.example")
    tail("torn_tail_not_consumed", [
        {"op": "write", "data": full[: len(full) // 2]},
        {"op": "read", "commit": True},
        {"op": "write", "data": full},
        {"op": "read", "commit": True},
    ])
    tail("uncommitted_read_rereads", [
        {"op": "write", "data": cl("a.example") + cl("b.example")},
        {"op": "read", "commit": False},
        {"op": "append", "data": cl("c.example")},
        {"op": "read", "commit": True},
    ])
    tail("window_filter_across_reset_chunks", [
        {"op": "write", "data": "".join(cl(f"old{i}.example", old)
                                        for i in range(20)) + cl("new.example")},
        *[{"op": "read", "commit": True} for _ in range(25)],
    ], chunk=300)
    tail("reset_filter_survives_failed_scan", [
        {"op": "write", "data": "".join(cl(f"old{i}.example", old)
                                        for i in range(4))},
        {"op": "read", "commit": False},
        {"op": "read", "commit": False},
    ])
    huge = json.loads(cl("huge.example"))
    huge["inbound"]["request"]["body"] = "x" * 5000
    tail("oversized_line_dropped", [
        {"op": "write", "data": json.dumps(huge)},
        {"op": "read", "commit": True},
        {"op": "append", "data": "\n" + cl("fresh.example")},
        {"op": "read", "commit": True},
    ], line_cap=500)
    tail("large_backlog_loses_nothing", [
        {"op": "write", "data": "".join(cl(f"h{i:03d}.example")
                                        for i in range(30))},
        *[{"op": "read", "commit": True} for _ in range(40)],
    ], chunk=300, line_cap=1200, max_flows=2000)
    tail("catchup_skip", [
        {"op": "write", "data": "".join(cl(f"h{i:03d}.example")
                                        for i in range(60))},
        {"op": "read", "commit": False},
        {"op": "read", "commit": True},
        {"op": "read", "commit": True},
    ], chunk=2000, max_catchup=8000)
    tail("samples_capped_at_max_flows", [
        {"op": "write", "data": "".join(cl(f"h{i}.example")
                                        for i in range(15))},
        {"op": "read", "commit": True},
    ], max_flows=12)
    tail("corrupt_and_non_object_lines", [
        {"op": "write", "data": "{not json\n[1,2]\n\n   \n\"s\"\n"
         + cl("ok.example")},
        {"op": "read", "commit": True},
    ])
    tail("invalid_utf8_replaced", [
        {"op": "write", "data": {"b64": base64.b64encode(
            cl("u.example", path="/é").replace("\\u00e9", "é")
            .encode("utf-8").replace(b"\xc3\xa9", b"\xff")).decode()}},
        {"op": "read", "commit": True},
    ])
    tail("removed_file_keeps_cursor", [
        {"op": "write", "data": cl("a.example")},
        {"op": "read", "commit": True},
        {"op": "remove"},
        {"op": "read", "commit": True},
    ])
    tail("growth_past_chunk_chases_single_line", [
        {"op": "write", "data": cl("long.example",
                                   inbound={"request": {"body": "b" * 900}})},
        {"op": "read", "commit": True},
    ], chunk=200, line_cap=5000)
    return out


def main():
    corpus = {
        "_comment": "Recorded from src/agentcage/data/proxy/watcher.py by "
                    "tests/fixtures/egress/gen/watcher.py. Deterministic "
                    "(no-RNG) mode only. Asserted by "
                    "tests/test_egress_corpus_watcher.py and by the Rust "
                    "watcher's corpus test.",
        "cases": [],
    }
    for case in cases():
        case["expected"] = compute(case)
        corpus["cases"].append(case)
    OUT.write_text(json.dumps(corpus, indent=1) + "\n")
    print(f"wrote {len(corpus['cases'])} cases to {OUT.relative_to(_REPO)}")


if __name__ == "__main__":
    main()
