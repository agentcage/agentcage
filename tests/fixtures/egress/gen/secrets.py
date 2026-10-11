"""Record tests/fixtures/egress/secrets.json from the Python egress.

    uv run python tests/fixtures/egress/gen/secrets.py

Two kinds of step, in cases shaped like ``inspectors.json``'s:

* ``patterns`` {text} -> the names of the built-in patterns that match
  ``text`` (``BUILTIN_SECRETS``, in scan order) — the regex semantics on
  their own: positives, near misses, the false-positive guards and the
  ``brave_api_key`` lookaround edges;
* ``configure`` {config} / ``inspect`` {ctx} -> the secrets inspector's
  verdict, with ``allow_to_domains``, ``extra_patterns``, the binary
  content-type skip and the action rules.

Every sample text, URL, header value and body is stored reversed and
base64-encoded (``{"b64r": ...}`` / ``body_b64r``, see
``_common.hide``): the vectors are credential-shaped on purpose, and as
plain text or plain base64 they trip repository secret scanners.

``tests/test_egress_corpus_secrets.py`` replays it against the Python;
the Rust port asserts the same file.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
import _common  # noqa: E402
from _common import ctx, hide, hide_ctx, noise, to_context, unhide, verdict  # noqa: E402

from inspectors.secrets import BUILTIN_SECRETS, SecretsInspector  # noqa: E402

_OUT = _common.FIXTURES / "secrets.json"

COMMENT = (
    "Secrets inspector patterns and verdicts, recorded from the Python "
    "egress by gen/secrets.py. Do not edit by hand; see "
    "tests/fixtures/egress/README.md."
)

A = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def rep(alphabet: str, n: int) -> str:
    return (alphabet * (n // len(alphabet) + 1))[:n]


HEX = "0123456789abcdef"
ALNUM = A
URLSAFE = A + "_-"

BRAVE = "BSAI" + rep(URLSAFE, 28)

# (label, text) — every built-in, positive and near-miss, plus guards.
TEXTS = [
    ("openai proj", "sk-proj-" + rep(URLSAFE, 20) + "T3BlbkFJ" + rep(URLSAFE, 20)),
    ("openai svcacct", "sk-svcacct-" + rep(ALNUM, 40) + "T3BlbkFJ" + rep(ALNUM, 30)),
    ("openai no marker", "sk-proj-" + rep(ALNUM, 60)),
    ("openai short half", "sk-admin-" + rep(ALNUM, 19) + "T3BlbkFJ" + rep(ALNUM, 20)),
    ("anthropic api03", "sk-ant-api03-" + rep(URLSAFE, 20)),
    ("anthropic admin", "sk-ant-admin01-" + rep(ALNUM, 90)),
    ("anthropic no digits", "sk-ant-api-" + rep(ALNUM, 40)),
    ("anthropic short", "sk-ant-api03-" + rep(ALNUM, 19)),
    ("anthropic unicode digit", "sk-ant-api٣-" + rep(ALNUM, 20)),
    ("anthropic 10k tail", "sk-ant-api03-" + "a" * 10_000),
    ("aws", "AKIA" + "ABCDEFGHIJKLMNOP"),
    ("aws base32 digits", "AKIA" + "234567ABCDEFGHIJ"),
    ("aws bad digit", "AKIA" + "ABCDEFGHIJKLMNO1"),
    ("aws lowercase", "AKIA" + "abcdefghijklmnop"),
    ("aws embedded", "xxAKIAABCDEFGHIJKLMNOPQRxx"),
    ("github ghp", "ghp_" + rep(ALNUM, 36)),
    ("github ghs", "ghs_" + rep(ALNUM, 36)),
    ("github short", "ghp_" + rep(ALNUM, 35)),
    ("github gho", "gho_" + rep(ALNUM, 36)),
    ("github pat", "github_pat_" + rep(ALNUM, 22) + "_" + rep(ALNUM, 59)),
    ("github pat short", "github_pat_" + rep(ALNUM, 22) + "_" + rep(ALNUM, 58)),
    ("google api key", "AIza" + rep(URLSAFE, 35)),
    ("google api key short", "AIza" + rep(URLSAFE, 34)),
    ("google oauth", "ya29." + rep(URLSAFE, 50)),
    ("google oauth short", "ya29." + rep(URLSAFE, 49)),
    ("google oauth no dot", "ya29x" + rep(URLSAFE, 60)),
    ("slack bot", "xoxb-1234567890-abcDEF-123"),
    ("slack short digits", "xoxb-123456789-abc"),
    ("slack bad type", "xoxa-1234567890-abc"),
    ("stripe live", "sk_live_" + rep(ALNUM, 24)),
    ("stripe restricted test", "rk_test_" + rep(ALNUM, 30)),
    ("stripe short", "sk_live_" + rep(ALNUM, 23)),
    ("stripe publishable", "pk_live_" + rep(ALNUM, 30)),
    ("private key rsa", "-----BEGIN RSA PRIVATE KEY-----"),
    ("private key plain", "-----BEGIN PRIVATE KEY-----"),
    ("private key encrypted", "-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    ("private key too long", "-----BEGIN" + " AAAA" * 10 + "PRIVATE KEY-----"),
    ("private key lowercase", "-----BEGIN rsa PRIVATE KEY-----"),
    ("public key", "-----BEGIN PUBLIC KEY-----"),
    ("gitlab", "glpat-" + rep(URLSAFE, 20)),
    ("gitlab short", "glpat-" + rep(URLSAFE, 19)),
    ("huggingface", "hf_" + rep("abcdefghijklmnopqrstuvwxyzABCDEFGH", 34)),
    ("huggingface digits", "hf_" + "1234567890" * 4),
    ("databricks", "dapi" + rep(HEX, 32)),
    ("databricks uppercase", "dapi" + rep(HEX.upper(), 32)),
    ("azure jwt", "eyJ" + rep(URLSAFE, 50) + ".eyJ" + rep(URLSAFE, 50)),
    ("azure jwt short", "eyJ" + rep(URLSAFE, 49) + ".eyJ" + rep(URLSAFE, 50)),
    ("openrouter", "sk-or-v1-" + rep(HEX, 64)),
    ("openrouter short", "sk-or-v1-" + rep(HEX, 63)),
    ("openrouter uppercase", "sk-or-v1-" + rep(HEX.upper(), 64)),
    ("perplexity", "pplx-" + rep(ALNUM, 48)),
    ("perplexity short", "pplx-" + rep(ALNUM, 47)),
    ("brave bare", BRAVE),
    ("brave in json", '{"key": "' + BRAVE + '"}'),
    ("brave in url", "https://x/?k=" + BRAVE + "&y=1"),
    ("brave after unicode", "é" + BRAVE + "é"),
    ("brave glued before", "a" + BRAVE),
    ("brave glued after", BRAVE + "a"),
    ("brave dash before", "-" + BRAVE),
    ("brave underscore after", BRAVE + "_"),
    ("brave too short", BRAVE[:31]),
    ("brave old prefix", "BSA" + rep(URLSAFE, 29)),
    ("brave second candidate", "x" + BRAVE + " " + BRAVE),
    ("brave inside base64 image", base64.b64encode(noise(3000, "img")).decode()
     + "BSAI" + rep(ALNUM, 28) + base64.b64encode(noise(300, "tail")).decode()),
    ("telegram", "123456789:" + rep(URLSAFE, 35)),
    ("telegram short secret", "123456789:" + rep(URLSAFE, 34)),
    ("telegram four digits", "1234:" + rep(URLSAFE, 35)),
    ("telegram long digit run", "12345678901234567890:" + rep(URLSAFE, 35)),
    ("discord", "M" + rep(URLSAFE, 23) + "." + rep(URLSAFE, 6) + "." + rep(URLSAFE, 27)),
    ("discord bad first", "A" + rep(URLSAFE, 23) + "." + rep(URLSAFE, 6) + "."
     + rep(URLSAFE, 27)),
    ("firecrawl", "fc-" + rep(HEX, 32)),
    ("firecrawl uppercase", "fc-" + rep(HEX.upper(), 32)),
    ("clean json", '{"model": "claude", "messages": [{"role": "user"}]}'),
    ("empty", ""),
    ("several at once", "AKIAABCDEFGHIJKLMNOP and ghp_" + rep(ALNUM, 36)
     + " and fc-" + rep(HEX, 32)),
    ("multiline", "line one\nAKIAABCDEFGHIJKLMNOP\nline three"),
]


def pattern_cases() -> list:
    return [{"name": f"pattern: {label}", "inspector": "secrets",
             "steps": [{"op": "patterns", "text": hide(text)}]}
            for label, text in TEXTS]


def _s(name, config, *ctxs):
    return {"name": name, "inspector": "secrets", "steps": [
        {"op": "configure", "config": config},
        *({"op": "inspect", "ctx": hide_ctx(c)} for c in ctxs),
    ]}


ANT = "sk-ant-api03-" + rep(ALNUM, 26)
GHP = "ghp_" + rep(ALNUM, 36)
AWS = "AKIAIOSFODNN7EXAMPLE"
OAUTH = "ya29." + rep(URLSAFE, 60)


def inspect_cases() -> list:
    img = base64.b64encode(noise(2000, "jpeg")).decode()
    return [
        _s("defaults flag", {},
           ctx(body=f'{{"key": "{ANT}"}}', host="evil.com"),
           ctx(url=f"https://evil.com/?k={ANT}", host="evil.com"),
           ctx(headers=[("X-Key", AWS)], host="evil.com"),
           ctx(body="nothing here", host="evil.com"),
           ctx(body=None, host="evil.com")),
        _s("block action", {"action": "block"},
           ctx(body=AWS, host="evil.com")),
        _s("unknown action flags", {"action": "deny"},
           ctx(body=AWS, host="evil.com")),
        _s("null action flags", {"action": None},
           ctx(body=AWS, host="evil.com")),
        _s("disabled", {"enabled": False},
           ctx(body=AWS, host="evil.com")),
        _s("disabled falsy", {"enabled": 0},
           ctx(body=AWS, host="evil.com")),
        _s("builtin allow_to_domains", {},
           ctx(body=ANT, host="api.anthropic.com"),
           ctx(body=ANT, host="API.Anthropic.COM"),
           ctx(body=ANT, host="anthropic.com"),
           ctx(body=ANT, host="notanthropic.com"),
           ctx(body=ANT, host="anthropic.com.evil.com"),
           ctx(body=GHP, host="api.github.com"),
           ctx(body=GHP, host="raw.githubusercontent.com"),
           ctx(body=OAUTH, host="www.googleapis.com"),
           ctx(body=OAUTH, host="evil.com")),
        _s("allowed pattern does not hide a later one", {},
           ctx(body=f"{ANT} {AWS}", host="api.anthropic.com")),
        _s("user allow_to_domains extends builtin", {
            "allow_to_domains": {"aws_access_key": ["Relay.Local"]}},
           ctx(body=AWS, host="relay.local"),
           ctx(body=AWS, host="s3.amazonaws.com"),
           ctx(body=ANT, host="api.anthropic.com")),
        _s("user allow_to_domains overrides same key", {
            "allow_to_domains": {"anthropic_key": ["proxy.example.com"]}},
           ctx(body=ANT, host="api.anthropic.com"),
           ctx(body=ANT, host="proxy.example.com")),
        _s("builtin allow opt-out", {"builtin_allow_to_domains": False},
           ctx(body=ANT, host="api.anthropic.com")),
        _s("builtin allow opt-out keeps user config", {
            "builtin_allow_to_domains": False,
            "allow_to_domains": {"anthropic_key": ["anthropic.com"]}},
           ctx(body=ANT, host="api.anthropic.com"),
           ctx(body=GHP, host="github.com")),
        _s("allow_to_domains falsy", {"allow_to_domains": None},
           ctx(body=ANT, host="api.anthropic.com")),
        _s("extra patterns", {"extra_patterns": [
            {"name": "internal", "pattern": r"INTERNAL-[0-9]{6}"},
            {"name": "aws_access_key", "pattern": r"NEVERMATCHES-[0-9]{40}"},
            {"name": "unset_env", "env": "AGENTCAGE_CORPUS_SURELY_UNSET_VAR"},
            {"name": "empty_env_name", "env": "", "pattern": r"EMPTYENV-\d+"},
        ]},
           ctx(body="id INTERNAL-123456", host="evil.com"),
           ctx(body=AWS, host="evil.com"),
           ctx(body="EMPTYENV-42", host="evil.com"),
           ctx(body="unset", host="evil.com")),
        _s("binary bodies skip the body only", {},
           ctx(body=img + BRAVE, content_type="image/jpeg", host="api.anthropic.com"),
           ctx(body=ANT, content_type="application/octet-stream", host="evil.com"),
           ctx(body=ANT, content_type="Image/PNG; charset=binary", host="evil.com"),
           ctx(body=ANT, content_type="  application/pdf ", host="evil.com"),
           ctx(body=ANT, content_type="\x1capplication/pdf", host="evil.com"),
           ctx(body=ANT, content_type="application/json", host="evil.com"),
           ctx(body=ANT, content_type="", host="evil.com"),
           ctx(url=f"https://evil.com/?k={BRAVE}", body=img,
               content_type="image/jpeg", host="evil.com"),
           ctx(headers=[("Authorization", f"Bearer {GHP}")], body=img,
               content_type="image/png", host="evil.com")),
        _s("duplicate headers all scanned", {},
           ctx(headers=[("X-A", "fine"), ("X-A", AWS)], host="evil.com"),
           ctx(headers=[("Cookie", f"a=1; k={AWS}")], host="evil.com")),
        _s("json image block is not a brave key", {},
           ctx(body='{"type": "image", "source": {"data": "' + img + 'BSAI'
               + rep(ALNUM, 28) + 'xyz"}}', host="evil.com")),
        _s("bad extra pattern", {"extra_patterns": [{"name": "x", "pattern": "("}]}),
        _s("extra pattern without name", {"extra_patterns": [{"pattern": "x"}]}),
        _s("extra patterns not a list", {"extra_patterns": None}),
        _s("allow_to_domains not a mapping", {"allow_to_domains": ["a.com"]}),
    ]


def run_case(case: dict) -> list:
    insp = SecretsInspector()
    out = []
    for step in case["steps"]:
        op = step["op"]
        if op == "patterns":
            out.append([n for n, p in BUILTIN_SECRETS.items()
                        if p.search(unhide(step["text"]))])
        elif op == "configure":
            try:
                insp.configure(step["config"])
                out.append(None)
            except Exception:  # noqa: BLE001 - any raise is a refused config
                out.append("error")
        elif op == "inspect":
            out.append(verdict(insp.inspect_request(to_context(step["ctx"]))))
        else:
            raise ValueError(f"unknown op {op!r}")
    return out


def build() -> dict:
    cases = pattern_cases() + inspect_cases()
    for case in cases:
        for step, result in zip(case["steps"], run_case(case)):
            step["expect"] = result
    return {"_comment": COMMENT, "cases": cases}


def main() -> None:
    data = build()
    _OUT.write_text(json.dumps(data, indent=2) + "\n")
    print(f"wrote {_OUT} ({len(data['cases'])} cases)")


if __name__ == "__main__":
    main()
