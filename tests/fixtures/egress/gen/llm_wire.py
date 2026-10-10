"""Record ``tests/fixtures/egress/llm_wire.json`` from the Python egress.

Two kinds of case, both driven through the live ``policy_api`` module:

* ``request``: the arguments of one ``llm_tool_call`` → the URL, the
  headers and the exact body bytes it handed to ``urllib`` (``urlopen``
  is replaced by a recorder, so nothing leaves the machine).
* ``parse``: a provider reply → what ``parse_tool_args`` extracted. A
  reply on which the Python *raised* instead of returning ``{}`` is
  recorded as ``{"raises": "<exception type>"}``; the Rust port returns
  ``{}`` there (every caller already fails closed on both), and asserts
  that.

    uv run python tests/fixtures/egress/gen/llm_wire.py

``tests/test_egress_corpus_llm_wire.py`` re-runs every case against the
Python through :func:`run`; ``rust/agentcage-egress/src/llm/tests.rs``
asserts the same file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parents[4]
OUT = _ROOT / "tests" / "fixtures" / "egress" / "llm_wire.json"

for _p in (_ROOT / "src" / "agentcage" / "data" / "proxy", _ROOT / "tests"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# The test suite's stub of the proxy framework the egress modules import
# at the top: the generator runs on the host, without the image's deps.
import conftest  # noqa: E402,F401

import policy_api  # noqa: E402

_DECIDE = policy_api._DECIDE_TOOL

_REVIEW = {
    "name": "review",
    "description": "Report findings — naïve “quotes” and a ☃.",
    "parameters": {
        "type": "object",
        "properties": {"findings": {"type": "array",
                                    "items": {"type": "object"}},
                       "ratio": {"type": "number", "minimum": 0.5}},
        "required": ["findings"],
    },
}


class _Recorder:
    def __init__(self):
        self.request = None

    def __call__(self, req, timeout=None):  # noqa: ARG002
        self.request = req
        resp = mock.MagicMock()
        resp.read.return_value = b"{}"
        resp.__enter__ = lambda s: s
        resp.__exit__ = lambda s, *a: False
        return resp


def _run_request(inp: dict) -> dict:
    rec = _Recorder()
    with mock.patch.object(policy_api.urllib.request, "urlopen", rec):
        policy_api.llm_tool_call(
            provider=inp["provider"], model=inp["model"],
            api_key=inp["api_key"], base_url=inp["base_url"],
            system=inp["system"], user_content=inp["user_content"],
            tool=inp["tool"], timeout=5.0, max_tokens=inp["max_tokens"])
    req = rec.request
    return {
        "method": req.get_method(),
        "url": req.full_url,
        # urllib stores names ``str.capitalize()``d; the port compares
        # them case-insensitively, in order.
        "headers": [[k, v] for k, v in req.header_items()],
        "body": req.data.decode("ascii"),
    }


def _run_parse(inp: dict) -> dict:
    try:
        return {"args": policy_api.parse_tool_args(
            inp["raw"], inp["provider"], inp["tool_name"])}
    except Exception as e:  # noqa: BLE001 — recorded, not hidden
        return {"raises": type(e).__name__}


def run(case: dict) -> dict:
    if case["kind"] == "request":
        return _run_request(case["input"])
    return _run_parse(case["input"])


def _req(cid, provider, base_url, **over):
    inp = {
        "provider": provider, "model": "model-x", "api_key": "sk-test-123",
        "base_url": base_url,
        "system": "You decide.\n\nLine two with a \"quote\" and a \\ slash.",
        "user_content": json.dumps({"domain_requested": "pypi.org",
                                    "agent_justification": "pip install"}),
        "tool": _DECIDE, "max_tokens": 8192,
    }
    inp.update(over)
    return {"id": cid, "kind": "request", "input": inp}


def _parse(cid, provider, raw, tool_name="decide"):
    return {"id": cid, "kind": "parse",
            "input": {"provider": provider, "tool_name": tool_name,
                      "raw": raw}}


def _oa(*tool_calls, message_extra=None):
    msg = {"role": "assistant", "content": None, "tool_calls": list(tool_calls)}
    if message_extra:
        msg.update(message_extra)
    return {"choices": [{"message": msg, "finish_reason": "tool_calls"}]}


def _fn(name, arguments):
    return {"id": "call_1", "type": "function",
            "function": {"name": name, "arguments": arguments}}


_GRANT = json.dumps({"decision": "grant", "reason": "registry",
                     "ttl_seconds": 600})


def cases() -> list[dict]:
    out = [
        _req("anthropic-default-base", "anthropic",
             "https://api.anthropic.com"),
        _req("openai-default-base", "openai", "https://api.openai.com"),
        _req("openrouter-default-base", "openrouter",
             "https://openrouter.ai/api/v1"),
        _req("openrouter-custom-base", "openrouter",
             "https://llm.example.net/api/v1", model="z-ai/glm-5.3-flash",
             max_tokens=16384),
        _req("unknown-provider-is-chat-completions", "gemini",
             "https://gw.example.net", max_tokens=1024),
        _req("anthropic-non-ascii-and-review-tool", "anthropic",
             "https://api.anthropic.com",
             system="Système: «règles» — ☃ \U0001F600 end",
             user_content=json.dumps({"samples": ["é", " ", "\x00"]},
                                     ensure_ascii=False),
             tool=_REVIEW, max_tokens=4096),
        _req("openai-non-ascii-and-review-tool", "openai",
             "http://127.0.0.1:11434",
             system="Système: «règles» — ☃ \U0001F600 end",
             user_content="plain text, not json\twith a tab",
             tool=_REVIEW, max_tokens=1),
        _req("empty-key-and-system", "openrouter",
             "https://openrouter.ai/api/v1", api_key="", system=""),

        # ── anthropic replies ──
        _parse("anthropic-tool-use", "anthropic", {
            "content": [{"type": "text", "text": "thinking"},
                        {"type": "tool_use", "id": "t1", "name": "decide",
                         "input": {"decision": "grant", "reason": "ok",
                                   "ttl_seconds": 3600}}]}),
        _parse("anthropic-wrong-tool-name-ignored", "anthropic", {
            "content": [{"type": "tool_use", "name": "other",
                         "input": {"decision": "grant"}}]}),
        _parse("anthropic-first-matching-block-wins", "anthropic", {
            "content": [{"type": "tool_use", "name": "other",
                         "input": {"decision": "grant"}},
                        {"type": "tool_use", "name": "decide",
                         "input": {"decision": "deny", "reason": "no"}},
                        {"type": "tool_use", "name": "decide",
                         "input": {"decision": "grant"}}]}),
        _parse("anthropic-null-input-is-empty", "anthropic", {
            "content": [{"type": "tool_use", "name": "decide",
                         "input": None}]}),
        _parse("anthropic-list-input-is-empty", "anthropic", {
            "content": [{"type": "tool_use", "name": "decide",
                         "input": [1, 2]}]}),
        _parse("anthropic-non-dict-blocks-skipped", "anthropic", {
            "content": ["tool_use", 3, None,
                        {"type": "tool_use", "name": "decide",
                         "input": {"decision": "deny"}}]}),
        _parse("anthropic-no-content", "anthropic", {"stop_reason": "max_tokens"}),
        _parse("anthropic-null-content", "anthropic", {"content": None}),
        _parse("anthropic-string-content", "anthropic", {"content": "tool_use"}),
        _parse("anthropic-int-content", "anthropic", {"content": 5}),
        _parse("anthropic-reply-in-openai-shape", "anthropic",
               _oa(_fn("decide", _GRANT))),
        _parse("anthropic-not-an-object-raises", "anthropic", ["content"]),
        _parse("anthropic-review-tool", "anthropic", {
            "content": [{"type": "tool_use", "name": "review",
                         "input": {"findings": [], "summary": "quiet"}}]},
               tool_name="review"),

        # ── chat-completions replies ──
        _parse("openai-tool-call", "openai", _oa(_fn("decide", _GRANT))),
        _parse("openrouter-tool-call", "openrouter",
               _oa(_fn("decide", _GRANT))),
        _parse("unknown-provider-parses-as-chat-completions", "gemini",
               _oa(_fn("decide", _GRANT))),
        _parse("openai-wrong-name-skipped-then-match", "openrouter",
               _oa(_fn("other", json.dumps({"decision": "grant"})),
                   _fn("decide", json.dumps({"decision": "deny",
                                             "reason": "x"})))),
        _parse("openai-only-wrong-name", "openrouter",
               _oa(_fn("other", _GRANT))),
        _parse("openai-unparseable-arguments", "openai",
               _oa(_fn("decide", "{not json"))),
        _parse("openai-arguments-not-an-object", "openai",
               _oa(_fn("decide", "[1, 2]"))),
        _parse("openai-arguments-missing", "openai",
               _oa({"function": {"name": "decide"}})),
        _parse("openai-arguments-null", "openai",
               _oa({"function": {"name": "decide", "arguments": None}})),
        _parse("openai-arguments-already-an-object", "openai",
               _oa({"function": {"name": "decide",
                                 "arguments": {"decision": "grant"}}})),
        _parse("openai-arguments-with-nan", "openai",
               _oa(_fn("decide", '{"decision": "deny", "x": NaN}'))),
        _parse("openai-falsy-entries-skipped", "openai",
               _oa(None, 0, "", {}, {"function": None},
                   _fn("decide", _GRANT))),
        _parse("openai-truthy-non-object-entry-raises", "openai",
               _oa("call", _fn("decide", _GRANT))),
        _parse("openai-truthy-non-object-function-raises", "openai",
               _oa({"function": "decide"}, _fn("decide", _GRANT))),
        _parse("openai-no-tool-calls", "openai",
               {"choices": [{"message": {"content": "prose answer"},
                             "finish_reason": "length"}]}),
        _parse("openai-tool-calls-string-raises", "openai",
               {"choices": [{"message": {"tool_calls": "decide"}}]}),
        _parse("openai-empty-choices", "openai", {"choices": []}),
        _parse("openai-no-choices", "openai", {"error": {"message": "x"}}),
        _parse("openai-choices-object", "openai",
               {"choices": {"0": {}}}),
        _parse("openai-choices-string-raises", "openai", {"choices": "abc"}),
        _parse("openai-choice-not-object-raises", "openai", {"choices": [7]}),
        _parse("openai-message-not-object-raises", "openai",
               {"choices": [{"message": "hi"}]}),
        _parse("openai-only-first-choice-counts", "openai", {
            "choices": [{"message": {"content": "x"}},
                        {"message": {"tool_calls": [_fn("decide", _GRANT)]}}]}),
        _parse("openai-reply-in-anthropic-shape", "openai", {
            "content": [{"type": "tool_use", "name": "decide",
                         "input": {"decision": "grant"}}]}),
        _parse("openai-not-an-object-raises", "openai", "choices"),
        _parse("openai-review-tool-unicode-args", "openrouter",
               _oa(_fn("review", json.dumps(
                   {"findings": [{"title": "naïve ☃"}]}))),
               tool_name="review"),
    ]
    return out


def main() -> None:
    recorded = [{**case, "expected": run(case)} for case in cases()]
    doc = {
        "_comment": (
            "LLM wire client: request cases record the URL, headers and "
            "exact body bytes llm_tool_call sent; parse cases record what "
            "parse_tool_args extracted from a reply ({\"raises\": T} where "
            "the Python raised; the Rust port returns {} there). Generated "
            "by tests/fixtures/egress/gen/llm_wire.py; asserted by "
            "tests/test_egress_corpus_llm_wire.py and by "
            "rust/agentcage-egress/src/llm/tests.rs."
        ),
        "cases": recorded,
    }
    OUT.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {OUT} ({len(recorded)} cases)")


if __name__ == "__main__":
    main()
